from flask import Blueprint, jsonify, render_template
from flask_login import login_required, current_user
from database.db_models import db, Analysis, Alert, Dataset, SecurityEvent, Prediction
from sqlalchemy import func

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def dashboard_page():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard/summary')
@login_required
def api_summary():
    total_events = db.session.query(func.sum(Analysis.total_events)).scalar() or 0
    normal_events = db.session.query(func.sum(Analysis.normal_events)).scalar() or 0
    suspicious_events = db.session.query(func.sum(Analysis.suspicious_events)).scalar() or 0
    high_risk = db.session.query(func.sum(Analysis.high_risk_events)).scalar() or 0
    med_risk = db.session.query(func.sum(Analysis.medium_risk_events)).scalar() or 0
    low_risk = db.session.query(func.sum(Analysis.low_risk_events)).scalar() or 0
    total_alerts = Alert.query.count()
    total_datasets = Dataset.query.count()
    total_analyses = Analysis.query.count()

    recent_alerts = (Alert.query
                     .filter(Alert.status == 'New')
                     .order_by(Alert.created_at.desc())
                     .limit(5)
                     .all())

    recent_datasets = (Dataset.query
                       .order_by(Dataset.uploaded_at.desc())
                       .limit(5)
                       .all())

    recent_analyses = (Analysis.query
                       .order_by(Analysis.started_at.desc())
                       .limit(5)
                       .all())

    return jsonify({
        'stats': {
            'total_events': int(total_events),
            'normal_events': int(normal_events),
            'suspicious_events': int(suspicious_events),
            'high_risk_events': int(high_risk),
            'medium_risk_events': int(med_risk),
            'low_risk_events': int(low_risk),
            'total_alerts': total_alerts,
            'total_datasets': total_datasets,
            'total_analyses': total_analyses
        },
        'recent_alerts': [a.to_dict() for a in recent_alerts],
        'recent_datasets': [d.to_dict() for d in recent_datasets],
        'recent_analyses': [a.to_dict() for a in recent_analyses]
    })

@dashboard_bp.route('/api/dashboard/charts')
@login_required
def api_charts():
    # Severity distribution
    sev_data = (db.session.query(Prediction.severity, func.count(Prediction.id))
                .group_by(Prediction.severity).all())
    severity_chart = {row[0]: row[1] for row in sev_data}

    # Label distribution
    label_data = (db.session.query(Prediction.predicted_label, func.count(Prediction.id))
                  .group_by(Prediction.predicted_label).all())
    label_chart = {row[0]: row[1] for row in label_data}

    # Timeline: analyses per day (last 14)
    analyses = (Analysis.query
                .order_by(Analysis.started_at.asc())
                .limit(14)
                .all())
    timeline = [
        {
            'date': a.started_at.strftime('%m/%d') if a.started_at else '',
            'suspicious': a.suspicious_events,
            'normal': a.normal_events
        }
        for a in analyses
    ]

    return jsonify({
        'severity_distribution': severity_chart,
        'label_distribution': label_chart,
        'timeline': timeline
    })
