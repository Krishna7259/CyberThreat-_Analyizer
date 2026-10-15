from datetime import datetime, timezone
from database.db_models import db, Alert, SecurityEvent

class AlertService:
    @staticmethod
    def create_alert_from_prediction(security_event_id: int, prediction_data: dict):
        """
        Generates a security alert if the event exceeds severity or anomaly thresholds.
        High and Medium risk events, or strong anomalies automatically spawn an alert.
        """
        severity = prediction_data.get('severity', 'Low')
        is_suspicious = (prediction_data.get('predicted_label') == 'Suspicious')
        is_anomaly = prediction_data.get('is_anomaly', False)
        risk_score = prediction_data.get('risk_score', 0.0)
        threat_cat = prediction_data.get('threat_category', 'Suspicious Activity')

        # Trigger alert for High/Medium risk or anomalous events
        if severity in ['High', 'Medium'] or is_anomaly or is_suspicious:
            desc = (
                f"Detected {severity}-severity {threat_cat} pattern. "
                f"Risk Score: {risk_score:.1f}, Threat Probability: {prediction_data.get('prediction_probability', 0.0):.2%}, "
                f"Anomaly Score: {prediction_data.get('anomaly_score', 0.0):.2f}."
            )
            
            alert = Alert(
                event_id=security_event_id,
                severity=severity,
                description=desc,
                status='New',
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(alert)
            return alert
        return None

    @staticmethod
    def update_alert_status(alert_id: int, status: str, user_id: int, analyst_notes: str = None):
        alert = Alert.query.get(alert_id)
        if not alert:
            return None, "Alert not found."

        valid_statuses = {'New', 'Under Review', 'Reviewed', 'False Positive'}
        if status not in valid_statuses:
            return None, f"Invalid status. Must be one of: {', '.join(valid_statuses)}"

        alert.status = status
        alert.reviewed_by = user_id
        if analyst_notes is not None:
            alert.analyst_notes = analyst_notes

        db.session.commit()
        return alert, "Alert status updated successfully."

    @staticmethod
    def get_filtered_alerts(severity=None, status=None, search=None, page=1, per_page=20):
        query = Alert.query

        if severity and severity.lower() != 'all':
            query = query.filter(Alert.severity.ilike(severity))

        if status and status.lower() != 'all':
            query = query.filter(Alert.status.ilike(status))

        if search:
            query = query.filter(
                (Alert.description.ilike(f"%{search}%")) |
                (Alert.analyst_notes.ilike(f"%{search}%"))
            )

        query = query.order_by(Alert.created_at.desc())
        paginated = query.paginate(page=page, per_page=per_page, error_out=False)
        return paginated
