from datetime import datetime, timezone
import json
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='analyst')  # 'admin' or 'analyst'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    datasets = db.relationship('Dataset', backref='uploader', lazy=True)
    reviewed_alerts = db.relationship('Alert', backref='reviewer', foreign_keys='Alert.reviewed_by', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Dataset(db.Model):
    __tablename__ = 'datasets'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    record_count = db.Column(db.Integer, default=0)
    validation_status = db.Column(db.String(50), default='valid')  # 'valid', 'invalid'

    analyses = db.relationship('Analysis', backref='dataset', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'stored_filename': self.stored_filename,
            'uploaded_by': self.uploaded_by,
            'uploader_name': self.uploader.username if self.uploader else 'Unknown',
            'uploaded_at': self.uploaded_at.isoformat() if self.uploaded_at else None,
            'record_count': self.record_count,
            'validation_status': self.validation_status
        }


class Analysis(db.Model):
    __tablename__ = 'analyses'

    id = db.Column(db.Integer, primary_key=True)
    dataset_id = db.Column(db.Integer, db.ForeignKey('datasets.id'), nullable=False)
    model_version = db.Column(db.String(50), nullable=False)
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)
    total_events = db.Column(db.Integer, default=0)
    suspicious_events = db.Column(db.Integer, default=0)
    normal_events = db.Column(db.Integer, default=0)
    high_risk_events = db.Column(db.Integer, default=0)
    medium_risk_events = db.Column(db.Integer, default=0)
    low_risk_events = db.Column(db.Integer, default=0)
    processing_time = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(50), default='completed')

    events = db.relationship('SecurityEvent', backref='analysis', cascade='all, delete-orphan', lazy=True)
    reports = db.relationship('Report', backref='analysis', cascade='all, delete-orphan', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'dataset_id': self.dataset_id,
            'dataset_name': self.dataset.filename if self.dataset else 'Unknown',
            'model_version': self.model_version,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_events': self.total_events,
            'suspicious_events': self.suspicious_events,
            'normal_events': self.normal_events,
            'high_risk_events': self.high_risk_events,
            'medium_risk_events': self.medium_risk_events,
            'low_risk_events': self.low_risk_events,
            'processing_time': round(self.processing_time, 3),
            'status': self.status
        }


class SecurityEvent(db.Model):
    __tablename__ = 'security_events'

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False, index=True)
    event_index = db.Column(db.Integer, nullable=False)
    event_data = db.Column(db.Text, nullable=False)  # JSON serialized dictionary of features
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    prediction = db.relationship('Prediction', backref='event', uselist=False, cascade='all, delete-orphan', lazy=True)
    alerts = db.relationship('Alert', backref='event', cascade='all, delete-orphan', lazy=True)

    def get_data(self):
        try:
            return json.loads(self.event_data)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'analysis_id': self.analysis_id,
            'event_index': self.event_index,
            'event_data': self.get_data(),
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'prediction': self.prediction.to_dict() if self.prediction else None
        }


class Prediction(db.Model):
    __tablename__ = 'predictions'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('security_events.id'), nullable=False, unique=True, index=True)
    predicted_label = db.Column(db.String(50), nullable=False)  # 'Normal', 'Suspicious', or attack category
    prediction_probability = db.Column(db.Float, nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # 'Low', 'Medium', 'High'

    def to_dict(self):
        return {
            'id': self.id,
            'event_id': self.event_id,
            'predicted_label': self.predicted_label,
            'prediction_probability': round(self.prediction_probability, 4),
            'anomaly_score': round(self.anomaly_score, 4),
            'risk_score': round(self.risk_score, 2),
            'severity': self.severity
        }


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('security_events.id'), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # 'Low', 'Medium', 'High'
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), default='New', index=True)  # 'New', 'Under Review', 'Reviewed', 'False Positive'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    analyst_notes = db.Column(db.Text, nullable=True)

    def to_dict(self):
        event_dict = None
        analysis_id = None
        if self.event:
            event_dict = self.event.get_data()
            analysis_id = self.event.analysis_id
        return {
            'id': self.id,
            'event_id': self.event_id,
            'analysis_id': analysis_id,
            'severity': self.severity,
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'reviewed_by': self.reviewed_by,
            'reviewer_name': self.reviewer.username if self.reviewer else None,
            'analyst_notes': self.analyst_notes or '',
            'event_data': event_dict
        }


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False, index=True)
    report_type = db.Column(db.String(20), nullable=False)  # 'PDF', 'CSV'
    file_path = db.Column(db.String(255), nullable=False)
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'analysis_id': self.analysis_id,
            'report_type': self.report_type,
            'file_path': self.file_path,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None
        }


class ModelVersion(db.Model):
    __tablename__ = 'model_versions'

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(50), unique=True, nullable=False)
    algorithm = db.Column(db.String(100), nullable=False)
    dataset_name = db.Column(db.String(100), nullable=False)
    training_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    evaluation_metrics = db.Column(db.Text, nullable=False)  # JSON string

    def get_metrics(self):
        try:
            return json.loads(self.evaluation_metrics)
        except Exception:
            return {}

    def to_dict(self):
        return {
            'id': self.id,
            'version': self.version,
            'algorithm': self.algorithm,
            'dataset_name': self.dataset_name,
            'training_date': self.training_date.isoformat() if self.training_date else None,
            'evaluation_metrics': self.get_metrics()
        }
