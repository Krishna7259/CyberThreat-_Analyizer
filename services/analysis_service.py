import time
import json
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from database.db_models import db, Dataset, Analysis, SecurityEvent, Prediction
from ml.preprocessing import validate_dataset_schema
from ml.predict import CyberShieldPredictor
from services.alert_service import AlertService
from config import Config

class AnalysisService:
    def __init__(self):
        self.predictor = CyberShieldPredictor()

    def run_analysis(self, dataset_id: int, user_id: int, limit: int = None):
        """
        Executes complete threat analysis on an uploaded dataset.
        Stores results, predictions, and alerts in the SQLite database.
        """
        dataset = Dataset.query.get(dataset_id)
        if not dataset:
            raise ValueError(f"Dataset with ID {dataset_id} does not exist.")

        file_path = Path(dataset.stored_filename)
        if not file_path.exists():
            raise FileNotFoundError(f"Dataset file '{file_path}' not found on disk.")

        df = pd.read_csv(file_path)
        is_valid, missing, msg = validate_dataset_schema(df)
        if not is_valid:
            dataset.validation_status = 'invalid'
            db.session.commit()
            raise ValueError(f"Dataset schema invalid: {msg}")

        dataset.validation_status = 'valid'
        dataset.record_count = len(df)
        db.session.commit()

        if limit and limit > 0:
            df = df.head(limit)

        # Create Analysis Record
        start_time = time.time()
        analysis = Analysis(
            dataset_id=dataset.id,
            model_version=Config.MODEL_VERSION,
            started_at=datetime.now(timezone.utc),
            status='processing'
        )
        db.session.add(analysis)
        db.session.flush()

        # Run Predictions
        predictions = self.predictor.predict_dataframe(df)

        normal_count = 0
        suspicious_count = 0
        high_risk_count = 0
        med_risk_count = 0
        low_risk_count = 0

        for pred in predictions:
            if pred['predicted_label'] == 'Suspicious':
                suspicious_count += 1
            else:
                normal_count += 1

            sev = pred['severity']
            if sev == 'High':
                high_risk_count += 1
            elif sev == 'Medium':
                med_risk_count += 1
            else:
                low_risk_count += 1

            # Save SecurityEvent
            sec_event = SecurityEvent(
                analysis_id=analysis.id,
                event_index=pred['event_index'],
                event_data=json.dumps(pred['raw_features']),
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(sec_event)
            db.session.flush()

            # Save Prediction
            db_pred = Prediction(
                event_id=sec_event.id,
                predicted_label=pred['predicted_label'],
                prediction_probability=pred['prediction_probability'],
                anomaly_score=pred['anomaly_score'],
                risk_score=pred['risk_score'],
                severity=pred['severity']
            )
            db.session.add(db_pred)

            # Auto-generate Alert if criteria met
            AlertService.create_alert_from_prediction(sec_event.id, pred)

        duration = time.time() - start_time
        analysis.completed_at = datetime.now(timezone.utc)
        analysis.total_events = len(predictions)
        analysis.normal_events = normal_count
        analysis.suspicious_events = suspicious_count
        analysis.high_risk_events = high_risk_count
        analysis.medium_risk_events = med_risk_count
        analysis.low_risk_events = low_risk_count
        analysis.processing_time = duration
        analysis.status = 'completed'

        db.session.commit()
        return analysis
