from flask import Blueprint, send_file, jsonify
from flask_login import login_required
from services.report_service import ReportService

report_bp = Blueprint('reports', __name__)

@report_bp.route('/reports')
@login_required
def reports_page():
    from flask import render_template
    from database.db_models import Analysis
    analyses = Analysis.query.filter_by(status='completed').order_by(Analysis.started_at.desc()).all()
    return render_template('reports.html', analyses=analyses)

@report_bp.route('/api/reports/<int:analysis_id>/pdf')
@login_required
def download_pdf(analysis_id):
    try:
        pdf_path = ReportService.generate_pdf_report(analysis_id)
        return send_file(pdf_path, as_attachment=True,
                         download_name=f'cybershield_report_{analysis_id}.pdf',
                         mimetype='application/pdf')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@report_bp.route('/api/reports/<int:analysis_id>/csv')
@login_required
def download_csv(analysis_id):
    try:
        csv_path = ReportService.generate_csv_report(analysis_id)
        return send_file(csv_path, as_attachment=True,
                         download_name=f'cybershield_events_{analysis_id}.csv',
                         mimetype='text/csv')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
