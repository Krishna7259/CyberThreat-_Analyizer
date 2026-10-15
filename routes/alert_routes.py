from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user
from database.db_models import Alert
from services.alert_service import AlertService

alert_bp = Blueprint('alerts', __name__)

@alert_bp.route('/alerts')
@login_required
def alerts_page():
    return render_template('alerts.html')

@alert_bp.route('/api/alerts')
@login_required
def list_alerts():
    severity = request.args.get('severity', 'all')
    status = request.args.get('status', 'all')
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    paginated = AlertService.get_filtered_alerts(
        severity=severity, status=status, search=search,
        page=page, per_page=per_page
    )
    return jsonify({
        'alerts': [a.to_dict() for a in paginated.items],
        'total': paginated.total,
        'pages': paginated.pages,
        'current_page': page
    })

@alert_bp.route('/api/alerts/<int:alert_id>')
@login_required
def get_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    return jsonify({'alert': alert.to_dict()})

@alert_bp.route('/api/alerts/<int:alert_id>', methods=['PATCH'])
@login_required
def update_alert(alert_id):
    data = request.get_json() or {}
    status = data.get('status')
    notes = data.get('analyst_notes')

    alert, msg = AlertService.update_alert_status(alert_id, status, current_user.id, notes)
    if not alert:
        return jsonify({'success': False, 'error': msg}), 400
    return jsonify({'success': True, 'alert': alert.to_dict(), 'message': msg})
