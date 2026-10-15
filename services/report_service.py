import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from database.db_models import db, Analysis, SecurityEvent, Prediction, Report, ModelVersion
from config import Config

class ReportService:
    @staticmethod
    def generate_csv_report(analysis_id: int) -> str:
        analysis = Analysis.query.get(analysis_id)
        if not analysis:
            raise ValueError(f"Analysis with ID {analysis_id} not found.")

        reports_dir = Config.REPORTS_FOLDER
        reports_dir.mkdir(parents=True, exist_ok=True)
        csv_filename = f"cybershield_analysis_{analysis_id}.csv"
        csv_path = reports_dir / csv_filename

        events = SecurityEvent.query.filter_by(analysis_id=analysis_id).order_by(SecurityEvent.event_index).all()

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            header = [
                'Event ID', 'Event Index', 'Timestamp', 'Predicted Label',
                'Prediction Probability', 'Anomaly Score', 'Risk Score', 'Severity',
                'Raw Event Features (JSON)'
            ]
            writer.writerow(header)

            for ev in events:
                pred = ev.prediction
                writer.writerow([
                    ev.id,
                    ev.event_index,
                    ev.timestamp.isoformat() if ev.timestamp else '',
                    pred.predicted_label if pred else 'N/A',
                    pred.prediction_probability if pred else 0.0,
                    pred.anomaly_score if pred else 0.0,
                    pred.risk_score if pred else 0.0,
                    pred.severity if pred else 'N/A',
                    ev.event_data
                ])

        # Record in DB
        report = Report.query.filter_by(analysis_id=analysis_id, report_type='CSV').first()
        if not report:
            report = Report(
                analysis_id=analysis_id,
                report_type='CSV',
                file_path=str(csv_path),
                generated_at=datetime.now(timezone.utc)
            )
            db.session.add(report)
        else:
            report.file_path = str(csv_path)
            report.generated_at = datetime.now(timezone.utc)
        db.session.commit()

        return str(csv_path)

    @staticmethod
    def generate_pdf_report(analysis_id: int) -> str:
        analysis = Analysis.query.get(analysis_id)
        if not analysis:
            raise ValueError(f"Analysis with ID {analysis_id} not found.")

        reports_dir = Config.REPORTS_FOLDER
        reports_dir.mkdir(parents=True, exist_ok=True)
        pdf_filename = f"cybershield_analysis_{analysis_id}.pdf"
        pdf_path = reports_dir / pdf_filename

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CyberTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#08111F'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'CyberSubtitle',
            parent=styles['Normal'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#2563EB'),
            spaceAfter=14
        )
        h2_style = ParagraphStyle(
            'CyberH2',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#101C2E'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'CyberBody',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#334155'),
            spaceAfter=8
        )

        elements = []

        # Header Title
        elements.append(Paragraph("CyberShield AI — Threat Analytics Report", title_style))
        elements.append(Paragraph("Intelligent Cyber Threat Detection and Security Analytics Platform", subtitle_style))
        elements.append(Spacer(1, 10))

        # Metadata Table
        dataset_name = analysis.dataset.filename if analysis.dataset else "Dataset"
        meta_data = [
            [Paragraph("<b>Analysis ID:</b>", body_style), Paragraph(str(analysis.id), body_style),
             Paragraph("<b>Dataset:</b>", body_style), Paragraph(dataset_name, body_style)],
            [Paragraph("<b>Model Version:</b>", body_style), Paragraph(analysis.model_version, body_style),
             Paragraph("<b>Execution Date:</b>", body_style), Paragraph(analysis.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if analysis.started_at else "N/A", body_style)],
            [Paragraph("<b>Processing Duration:</b>", body_style), Paragraph(f"{analysis.processing_time:.2f} seconds", body_style),
             Paragraph("<b>Status:</b>", body_style), Paragraph(analysis.status.upper(), body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[120, 150, 110, 160])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 15))

        # Executive Summary Section
        elements.append(Paragraph("Executive Summary", h2_style))
        suspicious_pct = (analysis.suspicious_events / max(analysis.total_events, 1)) * 100
        summary_text = (
            f"During this security analysis session, a total of <b>{analysis.total_events}</b> network traffic events "
            f"were evaluated using the CyberShield AI supervised Random Forest and unsupervised Isolation Forest engines. "
            f"<b>{analysis.suspicious_events}</b> events ({suspicious_pct:.1f}%) were classified as suspicious or malicious, "
            f"with <b>{analysis.high_risk_events}</b> classified as High Risk requiring immediate security team investigation."
        )
        elements.append(Paragraph(summary_text, body_style))

        # Summary Metric Cards Table
        summary_data = [
            ["Total Events", "Normal Events", "Suspicious Events", "High Risk", "Medium Risk", "Low Risk"],
            [str(analysis.total_events), str(analysis.normal_events), str(analysis.suspicious_events),
             str(analysis.high_risk_events), str(analysis.medium_risk_events), str(analysis.low_risk_events)]
        ]
        sum_table = Table(summary_data, colWidths=[90, 90, 90, 90, 90, 90])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#101C2E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#F8FAFC')),
            ('FONTSIZE', (0, 1), (-1, 1), 12),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        elements.append(sum_table)
        elements.append(Spacer(1, 15))

        # Model Evaluation Metrics (from ModelVersion)
        m_version = ModelVersion.query.filter_by(version=analysis.model_version).first()
        if m_version:
            elements.append(Paragraph("Model Validation Metrics (Test Benchmark)", h2_style))
            metrics = m_version.get_metrics()
            acc = metrics.get('accuracy', 0.0) * 100
            prec = metrics.get('precision', 0.0) * 100
            rec = metrics.get('recall', 0.0) * 100
            f1 = metrics.get('f1_score', 0.0) * 100
            fpr = metrics.get('false_positive_rate', 0.0) * 100

            metrics_data = [
                ["Evaluation Metric", "Score (%)", "Evaluation Metric", "Score (%)"],
                ["Classification Accuracy", f"{acc:.2f}%", "Precision", f"{prec:.2f}%"],
                ["Sensitivity / Recall", f"{rec:.2f}%", "F1-Score", f"{f1:.2f}%"],
                ["False Positive Rate (FPR)", f"{fpr:.2f}%", "Architecture", "Random Forest + Isolation Forest"]
            ]
            m_table = Table(metrics_data, colWidths=[150, 120, 150, 120])
            m_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563EB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ]))
            elements.append(m_table)
            elements.append(Spacer(1, 15))

        # Critical Security Incidents (Top High / Medium Risk Events)
        elements.append(Paragraph("Critical Security Incidents Sample", h2_style))
        high_events = (
            SecurityEvent.query
            .join(Prediction)
            .filter(SecurityEvent.analysis_id == analysis.id)
            .order_by(Prediction.risk_score.desc())
            .limit(10)
            .all()
        )

        incidents_data = [["Event #", "Classification", "Anomaly Score", "Risk Score", "Severity Level"]]
        for ev in high_events:
            p = ev.prediction
            incidents_data.append([
                str(ev.event_index),
                p.predicted_label,
                f"{p.anomaly_score:.3f}",
                f"{p.risk_score:.1f}",
                p.severity
            ])

        inc_table = Table(incidents_data, colWidths=[60, 120, 120, 120, 120])
        inc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ]))
        elements.append(inc_table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("<i>Report generated automatically by CyberShield AI Security Analytics Platform.</i>", body_style))

        doc.build(elements)

        # Record in DB
        report = Report.query.filter_by(analysis_id=analysis_id, report_type='PDF').first()
        if not report:
            report = Report(
                analysis_id=analysis_id,
                report_type='PDF',
                file_path=str(pdf_path),
                generated_at=datetime.now(timezone.utc)
            )
            db.session.add(report)
        else:
            report.file_path = str(pdf_path)
            report.generated_at = datetime.now(timezone.utc)
        db.session.commit()

        return str(pdf_path)
