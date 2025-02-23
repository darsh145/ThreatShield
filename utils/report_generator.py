from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )

    def generate_pdf_report(self, stats, anomaly_details):
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph("Cybersecurity Analysis Report", self.title_style))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles["Normal"]))
        story.append(Spacer(1, 20))

        # Basic Statistics
        story.append(Paragraph("Basic Statistics", self.styles["Heading2"]))
        stats_data = [
            ["Metric", "Value"],
            ["Total Log Entries", stats['total_entries']],
            ["Unique IP Addresses", stats['unique_ips']],
            ["High Severity Events", stats['high_severity']],
            ["Potential Attacks", stats['potential_attacks']]
        ]
        stats_table = Table(stats_data)
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))

        # Anomaly Details
        story.append(Paragraph("Detected Anomalies", self.styles["Heading2"]))
        story.append(Paragraph(f"Total Anomalies Detected: {anomaly_details['total_anomalies']}", self.styles["Normal"]))
        story.append(Spacer(1, 10))

        if anomaly_details['total_anomalies'] > 0:
            # Create table for anomalies
            anomaly_data = [["Timestamp", "IP Address", "Message"]]
            for i in range(min(10, len(anomaly_details['anomaly_timestamps']))):
                anomaly_data.append([
                    anomaly_details['anomaly_timestamps'][i],
                    anomaly_details['anomaly_ips'][i],
                    anomaly_details['anomaly_messages'][i][:100] + "..."  # Truncate long messages
                ])
            
            anomaly_table = Table(anomaly_data, colWidths=[120, 100, 300])
            anomaly_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('WORDWRAP', (0, 0), (-1, -1), True)
            ]))
            story.append(anomaly_table)

        doc.build(story)
        buffer.seek(0)
        return buffer

