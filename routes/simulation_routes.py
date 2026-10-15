from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from services.simulation_service import simulation_service
from database.db_models import Dataset
from config import Config

simulation_bp = Blueprint('simulation', __name__)

@simulation_bp.route('/simulation')
@login_required
def simulation_page():
    datasets = Dataset.query.filter_by(validation_status='valid').order_by(Dataset.uploaded_at.desc()).all()
    return render_template('simulation.html', datasets=datasets)

@simulation_bp.route('/api/simulation/start', methods=['POST'])
@login_required
def start_simulation():
    data = request.get_json() or {}
    speed = float(data.get('speed', 1.0))
    dataset_id = data.get('dataset_id')

    dataset_path = None
    if dataset_id:
        ds = Dataset.query.get(int(dataset_id))
        if ds:
            dataset_path = ds.stored_filename

    if not dataset_path:
        dataset_path = str(Config.DATASETS_FOLDER / 'test_stream.csv')

    # Reset and start fresh
    simulation_service.stop_simulation(current_user.id)
    status = simulation_service.start_simulation(current_user.id, dataset_path=dataset_path, speed=speed)
    return jsonify({'success': True, 'status': status})

@simulation_bp.route('/api/simulation/pause', methods=['POST'])
@login_required
def pause_simulation():
    status = simulation_service.pause_simulation(current_user.id)
    return jsonify({'success': True, 'status': status})

@simulation_bp.route('/api/simulation/resume', methods=['POST'])
@login_required
def resume_simulation():
    status = simulation_service.resume_simulation(current_user.id)
    return jsonify({'success': True, 'status': status})

@simulation_bp.route('/api/simulation/stop', methods=['POST'])
@login_required
def stop_simulation():
    status = simulation_service.stop_simulation(current_user.id)
    return jsonify({'success': True, 'status': status})

@simulation_bp.route('/api/simulation/status')
@login_required
def get_status():
    status = simulation_service.get_status(current_user.id)
    return jsonify({'status': status})

@simulation_bp.route('/api/simulation/events')
@login_required
def get_events():
    batch_size = request.args.get('batch', 2, type=int)
    result = simulation_service.step_events(current_user.id, batch_size=batch_size)
    return jsonify(result)
