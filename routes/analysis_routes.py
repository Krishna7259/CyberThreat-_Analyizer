from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from database.db_models import db, Analysis, SecurityEvent, Prediction, ModelVersion
from services.analysis_service import AnalysisService
from ml.explainability import CyberShieldExplainer
from ml.predict import CyberShieldPredictor
import joblib
from config import Config

analysis_bp = Blueprint('analysis', __name__)

def get_explainer():
    preprocessor = joblib.load(Config.MODELS_FOLDER / 'preprocessor.joblib')
    rf_model = joblib.load(Config.MODELS_FOLDER / 'random_forest.joblib')
    return CyberShieldExplainer(rf_model, preprocessor)

@analysis_bp.route('/detection')
@login_required
def detection_page():
    from database.db_models import Dataset
    datasets = Dataset.query.filter_by(validation_status='valid').order_by(Dataset.uploaded_at.desc()).all()
    return render_template('detection.html', datasets=datasets)

@analysis_bp.route('/anomalies')
@login_required
def anomalies_page():
    return render_template('anomalies.html')

@analysis_bp.route('/explainability')
@login_required
def explainability_page():
    return render_template('explainability.html')

@analysis_bp.route('/api/analysis/run', methods=['POST'])
@login_required
def run_analysis():
    data = request.get_json() or {}
    dataset_id = data.get('dataset_id')
    if not dataset_id:
        return jsonify({'success': False, 'error': 'dataset_id is required.'}), 400

    try:
        service = AnalysisService()
        analysis = service.run_analysis(int(dataset_id), current_user.id)
        return jsonify({'success': True, 'analysis': analysis.to_dict()})
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 422
    except Exception as e:
        return jsonify({'success': False, 'error': f'Analysis failed: {str(e)}'}), 500

@analysis_bp.route('/api/analysis/<int:analysis_id>')
@login_required
def get_analysis(analysis_id):
    analysis = Analysis.query.get_or_404(analysis_id)
    events = SecurityEvent.query.filter_by(analysis_id=analysis_id).order_by(SecurityEvent.event_index).limit(200).all()
    return jsonify({
        'analysis': analysis.to_dict(),
        'events': [e.to_dict() for e in events]
    })

@analysis_bp.route('/api/analysis/history')
@login_required
def analysis_history():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    paginated = Analysis.query.order_by(Analysis.started_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'analyses': [a.to_dict() for a in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page
    })

@analysis_bp.route('/api/analysis/anomalies/<int:analysis_id>')
@login_required
def get_anomalies(analysis_id):
    anomalies = (SecurityEvent.query
                 .join(Prediction)
                 .filter(SecurityEvent.analysis_id == analysis_id, Prediction.anomaly_score >= 0.55)
                 .order_by(Prediction.anomaly_score.desc())
                 .limit(100)
                 .all())
    return jsonify({'anomalies': [e.to_dict() for e in anomalies], 'count': len(anomalies)})

@analysis_bp.route('/api/explanations/<int:event_id>')
@login_required
def explain_event(event_id):
    event = SecurityEvent.query.get_or_404(event_id)
    try:
        explainer = get_explainer()
        result = explainer.explain_instance(event.get_data())
        return jsonify({'success': True, 'explanation': result, 'event_id': event_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@analysis_bp.route('/api/models/status')
@login_required
def model_status():
    preprocessor_exists = (Config.MODELS_FOLDER / 'preprocessor.joblib').exists()
    rf_exists = (Config.MODELS_FOLDER / 'random_forest.joblib').exists()
    iso_exists = (Config.MODELS_FOLDER / 'isolation_forest.joblib').exists()
    is_ready = preprocessor_exists and rf_exists and iso_exists

    latest = ModelVersion.query.order_by(ModelVersion.training_date.desc()).first()
    return jsonify({
        'models_ready': is_ready,
        'preprocessor': preprocessor_exists,
        'random_forest': rf_exists,
        'isolation_forest': iso_exists,
        'latest_version': latest.to_dict() if latest else None
    })

@analysis_bp.route('/api/models/metrics')
@login_required
def model_metrics():
    versions = ModelVersion.query.order_by(ModelVersion.training_date.desc()).all()
    return jsonify({'model_versions': [v.to_dict() for v in versions]})
