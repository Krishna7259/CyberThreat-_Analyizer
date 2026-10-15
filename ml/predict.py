from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from config import Config
from ml.preprocessing import clean_and_prepare_df
from ml.anomaly_detection import compute_anomaly_scores
from ml.risk_scoring import compute_risk_score, get_severity_level

class CyberShieldPredictor:
    def __init__(self, models_dir: Path = Config.MODELS_FOLDER):
        self.models_dir = Path(models_dir)
        self.preprocessor = None
        self.rf_model = None
        self.iso_forest = None
        self._load_models()

    def _load_models(self):
        preprocessor_path = self.models_dir / 'preprocessor.joblib'
        rf_path = self.models_dir / 'random_forest.joblib'
        iso_path = self.models_dir / 'isolation_forest.joblib'

        if not (preprocessor_path.exists() and rf_path.exists() and iso_path.exists()):
            raise FileNotFoundError(
                f"Trained model artifacts not found in {self.models_dir}. "
                "Please run `python ml/train_model.py` first."
            )

        self.preprocessor = joblib.load(preprocessor_path)
        self.rf_model = joblib.load(rf_path)
        self.iso_forest = joblib.load(iso_path)

    def predict_dataframe(self, df: pd.DataFrame):
        """
        Runs complete threat classification, anomaly detection, and risk scoring
        over a DataFrame of security events.
        """
        if df.empty:
            return []

        df_clean = clean_and_prepare_df(df)
        X_trans = self.preprocessor.transform(df_clean)

        # 1. Random Forest Predictions & Probabilities
        rf_preds = self.rf_model.predict(X_trans)
        if hasattr(self.rf_model, "predict_proba"):
            probs = self.rf_model.predict_proba(X_trans)
            # Probability of Class 1 (Attack/Suspicious)
            threat_probs = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
        else:
            threat_probs = rf_preds.astype(float)

        # 2. Isolation Forest Anomaly Scoring
        anomaly_scores, is_anomalies = compute_anomaly_scores(self.iso_forest, X_trans)

        results = []
        for i in range(len(df)):
            row_dict = df.iloc[i].to_dict()
            prob = float(threat_probs[i])
            anom_score = float(anomaly_scores[i])
            is_anomaly = bool(is_anomalies[i])
            is_attack = bool(rf_preds[i] == 1)

            # Determine predicted label and category
            attack_cat = row_dict.get('attack_cat', None)
            if is_attack:
                label = 'Suspicious'
                category = str(attack_cat) if (attack_cat and str(attack_cat).strip() != '-' and str(attack_cat).lower() != 'normal') else 'Malicious Activity'
            else:
                label = 'Normal'
                category = 'Normal'

            # Risk calculation
            risk = compute_risk_score(prob, anom_score, row_dict)
            severity = get_severity_level(risk)

            results.append({
                'event_index': i + 1,
                'predicted_label': label,
                'threat_category': category,
                'prediction_probability': round(prob, 4),
                'anomaly_score': round(anom_score, 4),
                'is_anomaly': is_anomaly,
                'risk_score': risk,
                'severity': severity,
                'raw_features': row_dict
            })

        return results

    def predict_single_event(self, event_dict: dict):
        df = pd.DataFrame([event_dict])
        results = self.predict_dataframe(df)
        return results[0] if results else None
