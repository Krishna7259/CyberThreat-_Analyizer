import threading
import time
from pathlib import Path
import pandas as pd
from ml.predict import CyberShieldPredictor
from config import Config

class SimulationService:
    """
    Manages active event-replay simulation sessions.
    Simulates real-time security monitoring by streaming events sequentially
    from an authorized dataset with actual ML inference.
    """
    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()
        self.predictor = CyberShieldPredictor()

    def get_or_create_session(self, user_id: int, dataset_path: str = None, speed: float = 1.0):
        with self._lock:
            if user_id not in self._sessions:
                if not dataset_path:
                    dataset_path = str(Config.DATASETS_FOLDER / 'test_stream.csv')
                
                df = pd.read_csv(dataset_path)
                self._sessions[user_id] = {
                    'dataset_path': dataset_path,
                    'dataframe': df,
                    'total_records': len(df),
                    'current_index': 0,
                    'status': 'stopped',  # 'running', 'paused', 'stopped'
                    'speed': speed,       # events per poll or delay
                    'processed_events': [],
                    'stats': {
                        'total_processed': 0,
                        'normal_count': 0,
                        'suspicious_count': 0,
                        'high_risk_count': 0,
                        'medium_risk_count': 0,
                        'low_risk_count': 0,
                        'anomalies_count': 0
                    }
                }
            return self._sessions[user_id]

    def start_simulation(self, user_id: int, dataset_path: str = None, speed: float = 1.0):
        session = self.get_or_create_session(user_id, dataset_path, speed)
        session['status'] = 'running'
        session['speed'] = speed
        return self.get_status(user_id)

    def pause_simulation(self, user_id: int):
        session = self.get_or_create_session(user_id)
        session['status'] = 'paused'
        return self.get_status(user_id)

    def resume_simulation(self, user_id: int):
        session = self.get_or_create_session(user_id)
        session['status'] = 'running'
        return self.get_status(user_id)

    def stop_simulation(self, user_id: int):
        with self._lock:
            if user_id in self._sessions:
                session = self._sessions[user_id]
                session['status'] = 'stopped'
                session['current_index'] = 0
                session['processed_events'] = []
                session['stats'] = {
                    'total_processed': 0,
                    'normal_count': 0,
                    'suspicious_count': 0,
                    'high_risk_count': 0,
                    'medium_risk_count': 0,
                    'low_risk_count': 0,
                    'anomalies_count': 0
                }
        return self.get_status(user_id)

    def step_events(self, user_id: int, batch_size: int = 1):
        """
        Advances the replay simulation by batch_size events and runs actual ML inference.
        """
        session = self.get_or_create_session(user_id)
        if session['status'] != 'running':
            return {'new_events': [], 'stats': session['stats'], 'status': session['status']}

        df = session['dataframe']
        curr = session['current_index']
        total = session['total_records']

        if curr >= total:
            session['status'] = 'completed'
            return {'new_events': [], 'stats': session['stats'], 'status': 'completed'}

        end = min(curr + batch_size, total)
        slice_df = df.iloc[curr:end]
        session['current_index'] = end

        # Run real ML predictions on this replay batch
        predictions = self.predictor.predict_dataframe(slice_df)

        for pred in predictions:
            pred['stream_index'] = curr + 1
            curr += 1
            session['stats']['total_processed'] += 1
            if pred['predicted_label'] == 'Suspicious':
                session['stats']['suspicious_count'] += 1
            else:
                session['stats']['normal_count'] += 1

            sev = pred['severity']
            if sev == 'High':
                session['stats']['high_risk_count'] += 1
            elif sev == 'Medium':
                session['stats']['medium_risk_count'] += 1
            else:
                session['stats']['low_risk_count'] += 1

            if pred.get('is_anomaly'):
                session['stats']['anomalies_count'] += 1

            # Keep recent 100 events in memory
            session['processed_events'].append(pred)
            if len(session['processed_events']) > 100:
                session['processed_events'].pop(0)

        return {
            'new_events': predictions,
            'stats': session['stats'],
            'status': session['status'],
            'progress': round((session['current_index'] / total) * 100, 1)
        }

    def get_status(self, user_id: int):
        session = self.get_or_create_session(user_id)
        total = session['total_records']
        curr = session['current_index']
        return {
            'status': session['status'],
            'speed': session['speed'],
            'current_index': curr,
            'total_records': total,
            'progress': round((curr / total) * 100, 1) if total > 0 else 0,
            'stats': session['stats']
        }

simulation_service = SimulationService()
