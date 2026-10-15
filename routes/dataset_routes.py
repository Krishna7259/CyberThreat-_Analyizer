import uuid
from pathlib import Path
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import pandas as pd
from database.db_models import db, Dataset
from ml.preprocessing import validate_dataset_schema
from config import Config

dataset_bp = Blueprint('datasets', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@dataset_bp.route('/upload')
@login_required
def upload_page():
    return render_template('upload.html')

@dataset_bp.route('/api/datasets/upload', methods=['POST'])
@login_required
def upload_dataset():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part in request.'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected.'}), 400

    if not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'Only CSV files are allowed.'}), 400

    original_name = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    upload_dir = Path(Config.UPLOAD_FOLDER)
    upload_dir.mkdir(parents=True, exist_ok=True)
    save_path = upload_dir / unique_name

    file.save(str(save_path))

    # Validate schema
    try:
        df = pd.read_csv(str(save_path), nrows=500)
        is_valid, missing, msg = validate_dataset_schema(df)
        record_count = len(pd.read_csv(str(save_path)))
    except Exception as e:
        save_path.unlink(missing_ok=True)
        return jsonify({'success': False, 'error': f'Failed to parse CSV: {str(e)}'}), 400

    validation_status = 'valid' if is_valid else 'invalid'

    dataset = Dataset(
        filename=original_name,
        stored_filename=str(save_path),
        uploaded_by=current_user.id,
        record_count=record_count,
        validation_status=validation_status
    )
    db.session.add(dataset)
    db.session.commit()

    # Preview first 10 rows
    preview_df = pd.read_csv(str(save_path), nrows=10)
    preview_columns = list(preview_df.columns)
    preview_rows = preview_df.fillna('').values.tolist()

    return jsonify({
        'success': True,
        'dataset': dataset.to_dict(),
        'validation': {
            'is_valid': is_valid,
            'missing_columns': missing,
            'message': msg
        },
        'preview': {
            'columns': preview_columns,
            'rows': preview_rows
        }
    })

@dataset_bp.route('/api/datasets')
@login_required
def list_datasets():
    datasets = Dataset.query.order_by(Dataset.uploaded_at.desc()).all()
    return jsonify({'datasets': [d.to_dict() for d in datasets]})

@dataset_bp.route('/api/datasets/<int:dataset_id>')
@login_required
def get_dataset(dataset_id):
    d = Dataset.query.get_or_404(dataset_id)
    return jsonify({'dataset': d.to_dict()})
