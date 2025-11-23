import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class CyberGuardReporter:
    def __init__(self, team_name="CyberGuard"):
        self.team_name = team_name
        self.evidence_dir = "evidence"
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)

    def save_json_log(self, logs):
        """Saves the raw log data to a JSON file for data portability."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.evidence_dir, f"mission_log_{self.team_name}_{timestamp}.json")
        
        try:
            with open(filename, 'w') as f:
                json.dump(logs, f, indent=4)
            return filename
        except Exception as e:
            return f"Error saving JSON: {str(e)}"

    def generate_pdf_report(self, logs):
        """Generates a professional PDF report with embedded screenshots/evidence."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.evidence_dir, f"Mission_Report_{self.team_name}_{timestamp}.pdf")
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # --- Title Page ---
        title_style = ParagraphStyle(
            'Title', 
            parent=styles['Heading1'], 
            fontSize=26, 
            textColor=colors.darkblue,
            spaceAfter=20,
            alignment=1 # Center
        )
        
        story.append(Paragraph(f"MISSION REPORT: {self.team_name.upper()}", title_style))
        story.append(Paragraph(f"<b>Generated:</b> {str(datetime.now())}", styles['Normal']))
        story.append(Paragraph(f"<b>Security Level:</b> CLASSIFIED", styles['Normal']))
        story.append(Spacer(1, 30))

        # --- Log Entries ---
        for entry in logs:
            # Section Header
            header_text = f"MODULE: {entry['module']} | TARGET: {entry['target']}"
            story.append(Paragraph(header_text, styles['Heading3']))
            
            # Meta Data
            meta_text = f"<b>Time:</b> {entry['time']} | <b>Operator:</b> {entry.get('user', 'Unknown')}"
            story.append(Paragraph(meta_text, styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Text Data
            data_content = entry['data']
            if isinstance(data_content, dict):
                # Pretty print dictionary
                formatted_data = json.dumps(data_content, indent=2)
                # Escape HTML characters for ReportLab
                formatted_data = formatted_data.replace("<", "&lt;").replace(">", "&gt;")
                story.append(Paragraph(f"<pre>{formatted_data}</pre>", styles['Code']))
            else:
                story.append(Paragraph(f"Data: {str(data_content)}", styles['Normal']))
            
            story.append(Spacer(1, 10))

            # --- SCREENSHOT / EVIDENCE INTEGRATION ---
            if 'image_path' in entry and entry['image_path']:
                img_path = entry['image_path']
                if os.path.exists(img_path):
                    try:
                        # Add a visual label
                        story.append(Paragraph("<b>ATTACHED VISUAL EVIDENCE:</b>", styles['Normal']))
                        story.append(Spacer(1, 5))
                        
                        # Resize image to fit page width (max width ~450)
                        # 'proportional' keeps aspect ratio
                        im = Image(img_path, width=450, height=300, kind='proportional')
                        story.append(im)
                        story.append(Paragraph(f"<i>Source: {os.path.basename(img_path)}</i>", styles['Italic']))
                    except Exception as e:
                        story.append(Paragraph(f"<i>Error loading image: {str(e)}</i>", styles['Italic']))
            
            # Separator
            story.append(Spacer(1, 15))
            story.append(Paragraph("_" * 60, styles['Normal']))
            story.append(Spacer(1, 15))

        # Build PDF
        try:
            doc.build(story)
            return filename
        except Exception as e:
            return f"Error building PDF: {str(e)}"

# Helper function wrapper for backward compatibility
def generate_report(logs, team_name="CyberGuard"):
    reporter = CyberGuardReporter(team_name)
    reporter.save_json_log(logs)
    return reporter.generate_pdf_report(logs)