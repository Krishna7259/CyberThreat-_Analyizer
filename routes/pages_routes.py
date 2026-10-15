from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user
from database.db_models import User, Dataset, Analysis, Alert
from functools import wraps

pages_bp = Blueprint('pages', __name__)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('dashboard.dashboard_page'))
        return f(*args, **kwargs)
    return decorated

@pages_bp.route('/')
def index():
    return render_template('index.html')

@pages_bp.route('/history')
@login_required
def history_page():
    return render_template('history.html')

@pages_bp.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html')

@pages_bp.route('/admin')
@login_required
@admin_required
def admin_page():
    users = User.query.order_by(User.created_at.desc()).all()
    datasets = Dataset.query.order_by(Dataset.uploaded_at.desc()).all()
    analyses = Analysis.query.order_by(Analysis.started_at.desc()).limit(20).all()
    return render_template('admin.html', users=users, datasets=datasets, analyses=analyses)

# Admin API: toggle user role
@pages_bp.route('/api/admin/users/<int:user_id>/role', methods=['PATCH'])
@login_required
@admin_required
def toggle_user_role(user_id):
    from flask import jsonify, request
    from database.db_models import db
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot modify your own role.'}), 400
    data = request.get_json() or {}
    new_role = data.get('role', 'analyst')
    if new_role not in ('admin', 'analyst'):
        return jsonify({'success': False, 'error': 'Invalid role.'}), 400
    user.role = new_role
    db.session.commit()
    return jsonify({'success': True, 'user': user.to_dict()})
