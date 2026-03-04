"""
Pipeline V0 - Production Backend
Receives job data, generates PDF (Option B style), sends email
Ready for Railway/Render deployment
"""

import os
import json
import base64
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from io import BytesIO
import threading

# PDF Generation
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

# Image processing
from PIL import Image as PILImage

# ============================================
# CONFIGURATION (Environment Variables)
# ============================================
CONFIG = {
    'port': int(os.environ.get('PORT', 8080)),
    'output_dir': './outputs',
    'smtp': {
        'host': os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
        'port': int(os.environ.get('SMTP_PORT', 587)),
        'user': os.environ.get('SMTP_USER', ''),
        'password': os.environ.get('SMTP_PASSWORD', ''),
    },
    'default_office_email': os.environ.get('DEFAULT_OFFICE_EMAIL', ''),
    'allowed_origins': os.environ.get('ALLOWED_ORIGINS', '*'),
}

# Company configurations (in production, this would be a database)
COMPANIES = {
    'default': {
        'name': 'VVS Eksempel AS',
        'orgNr': '987 654 321',
        'phone': '+47 22 33 44 55',
        'email': 'post@vvs-eksempel.no',
        'office_email': '',  # No default - email MUST come from form
        'logo': None
    }
}

os.makedirs(CONFIG['output_dir'], exist_ok=True)

# ============================================
# PDF GENERATOR (Option B - Detailed/Formal)
# ============================================
class PDFGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
    
    def generate(self, job_data):
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
        story = []
        page_width = 180*mm
        
        company = job_data.get('company', COMPANIES['default'])
        plumber = job_data.get('plumber', {})
        answers = job_data.get('answers', {})
        location = job_data.get('location', {})
        
        # Parse timestamp
        timestamp = job_data.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime('%d.%m.%Y')
            time_str = dt.strftime('%H:%M')
        except:
            date_str = datetime.now().strftime('%d.%m.%Y')
            time_str = datetime.now().strftime('%H:%M')
        
        # Header
        header_data = [
            [Paragraph(f"<b>{company.get('name', 'Firma')}</b><br/><font size=9>Org.nr: {company.get('orgNr', 'N/A')}</font>", self.styles['Normal']),
             Paragraph("<b>SERVICERAPPORT</b><br/><font size=9>Dokumentasjon av utført arbeid</font>", 
                       ParagraphStyle('Right', parent=self.styles['Normal'], alignment=TA_RIGHT))]
        ]
        t = Table(header_data, colWidths=[90*mm, 90*mm])
        story.append(t)
        story.append(Spacer(1, 2*mm))
        
        # Blue bar
        bar = Table([['']], colWidths=[page_width], rowHeights=[6*mm])
        bar.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), HexColor('#2C5282'))]))
        story.append(bar)
        story.append(Spacer(1, 4*mm))
        
        # Info section
        customer = job_data.get('customer', '')
        job_desc = job_data.get('jobDescription', '')
        address = customer if customer else (f"GPS: {location.get('lat', 0):.5f}, {location.get('lng', 0):.5f}" if location else 'Ikke tilgjengelig')
        
        info_left = [
            [Paragraph("<font size=8 color='#666666'>KUNDE / ADRESSE</font>", self.styles['Normal'])],
            [Paragraph(f"<b>{address}</b>", self.styles['Normal'])],
            [Spacer(1, 2*mm)],
            [Paragraph("<font size=8 color='#666666'>DATO / TID</font>", self.styles['Normal'])],
            [Paragraph(f"<b>{date_str} kl. {time_str}</b>", self.styles['Normal'])],
        ]
        info_right = [
            [Paragraph("<font size=8 color='#666666'>UTFØRT AV</font>", self.styles['Normal'])],
            [Paragraph(f"<b>{plumber.get('name', 'N/A')}</b>", self.styles['Normal'])],
            [Spacer(1, 2*mm)],
            [Paragraph("<font size=8 color='#666666'>RAPPORTNUMMER</font>", self.styles['Normal'])],
            [Paragraph(f"<b>{job_data.get('id', 'N/A')[:16]}</b>", self.styles['Normal'])],
        ]
        
        info_table = Table([
            [Table(info_left, colWidths=[85*mm]), Table(info_right, colWidths=[85*mm])]
        ], colWidths=[90*mm, 90*mm])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), HexColor('#F7FAFC')),
            ('BOX', (0,0), (-1,-1), 1, HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 4*mm))
        
        # Job description if provided
        if job_desc:
            story.append(Paragraph("<font color='#2C5282'><b>ARBEID UTFØRT</b></font>", self.styles['Heading4']))
            story.append(Paragraph(job_desc, self.styles['Normal']))
            story.append(Spacer(1, 4*mm))
        
        # Status
        story.append(Paragraph("<font color='#2C5282'><b>STATUS</b></font>", self.styles['Heading4']))
        
        def yes_no(val):
            if val is True: return '✓ JA'
            elif val is False: return '✗ NEI'
            return '—'
        
        status = [
            ['KONTROLLPUNKT', 'RESULTAT'],
            ['Arbeid fullført', yes_no(answers.get('completed'))],
            ['Materialer byttet', yes_no(answers.get('materials'))],
            ['Oppfølging påkrevd', yes_no(answers.get('followup'))],
        ]
        t = Table(status, colWidths=[page_width * 0.6, page_width * 0.4])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), HexColor('#2C5282')),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#CBD5E0')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (1,0), (1,-1), 'CENTER'),
        ]))
        story.append(t)
        story.append(Spacer(1, 4*mm))
        
        # Photos
        story.append(Paragraph("<font color='#2C5282'><b>FOTODOKUMENTASJON</b></font>", self.styles['Heading4']))
        
        photos = job_data.get('photos', {})
        photo_labels = {'before': 'FØR', 'during': 'ÅPENT', 'detail': 'DETALJ', 'after': 'ETTER'}
        photo_hints = {'before': 'Utgangspunkt', 'during': 'Under arbeid', 'detail': 'Viktig info', 'after': 'Ferdig resultat'}
        
        photo_images = []
        for key in ['before', 'during', 'detail', 'after']:
            photo_data = photos.get(key, {})
            if photo_data and photo_data.get('data'):
                try:
                    img_data = photo_data['data']
                    if ',' in img_data:
                        img_data = img_data.split(',')[1]
                    img_bytes = base64.b64decode(img_data)
                    img_buffer = BytesIO(img_bytes)
                    img = Image(img_buffer, width=85*mm, height=55*mm)
                    photo_images.append([img, Paragraph(f"<font size=8><b>{photo_labels[key]}</b> — {photo_hints[key]}</font>", 
                                                        ParagraphStyle('C', alignment=TA_CENTER))])
                except Exception as e:
                    print(f"Photo error {key}: {e}")
                    photo_images.append([Paragraph(f"{photo_labels[key]}<br/>(Ikke tilgjengelig)", self.styles['Normal']), ''])
            else:
                photo_images.append([Paragraph(f"{photo_labels[key]}<br/>(Ikke tatt)", self.styles['Normal']), ''])
        
        if len(photo_images) >= 4:
            photo_table = [
                [photo_images[0][0], photo_images[1][0]],
                [photo_images[0][1], photo_images[1][1]],
                [photo_images[2][0], photo_images[3][0]],
                [photo_images[2][1], photo_images[3][1]],
            ]
            t = Table(photo_table, colWidths=[page_width/2, page_width/2])
            t.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOX', (0,0), (-1,-1), 1, HexColor('#2C5282')),
                ('BACKGROUND', (0,0), (-1,-1), HexColor('#FAFAFA')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t)
        
        # Footer
        story.append(Spacer(1, 5*mm))
        footer_bar = Table([['']], colWidths=[page_width], rowHeights=[2*mm])
        footer_bar.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), HexColor('#2C5282'))]))
        story.append(footer_bar)
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph(
            f"<font size=7 color='#666666'>Dokumentasjon i henhold til TEK17 §4-1 (FDV) | {company.get('name', '')} | {company.get('phone', '')}</font>", 
            ParagraphStyle('Footer', alignment=TA_CENTER)
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()


# ============================================
# EMAIL SENDER
# ============================================
class EmailSender:
    def __init__(self, config):
        self.config = config
    
    def send(self, to_email, subject, body, attachments=None):
        if not self.config['user'] or not self.config['password']:
            print(f"[EMAIL] SMTP not configured. Would send to: {to_email}")
            print(f"[EMAIL] Subject: {subject}")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = f"Right Flow VVS <{self.config['user']}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            if attachments:
                for filename, content in attachments:
                    part = MIMEApplication(content, Name=filename)
                    part['Content-Disposition'] = f'attachment; filename="{filename}"'
                    msg.attach(part)
            
            context = ssl.create_default_context()
            with smtplib.SMTP(self.config['host'], self.config['port']) as server:
                server.starttls(context=context)
                server.login(self.config['user'], self.config['password'])
                server.send_message(msg)
            
            print(f"[EMAIL] Sent to {to_email}")
            return True
            
        except Exception as e:
            print(f"[EMAIL] Failed: {e}")
            return False


# ============================================
# REQUEST HANDLER
# ============================================
class PipelineHandler(BaseHTTPRequestHandler):
    pdf_generator = PDFGenerator()
    email_sender = EmailSender(CONFIG['smtp'])
    
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()
    
    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == '/api/status':
            self._json({'status': 'ok', 'version': '1.0.0', 'smtp_configured': bool(CONFIG['smtp']['user'])})
        elif path == '/health':
            self._json({'healthy': True})
        else:
            self.send_error(404)
    
    def do_POST(self):
        path = urlparse(self.path).path
        
        if path == '/api/submit':
            self._handle_submit()
        else:
            self.send_error(404)
    
    def _handle_submit(self):
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            data = json.loads(body.decode('utf-8'))
            
            job_id = data.get('id', 'unknown')
            print(f"\n[JOB] Received: {job_id}")
            
            # Generate PDF
            print("[JOB] Generating PDF...")
            pdf_bytes = self.pdf_generator.generate(data)
            
            # Save locally
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pdf_filename = f"rapport_{timestamp}.pdf"
            pdf_path = os.path.join(CONFIG['output_dir'], pdf_filename)
            with open(pdf_path, 'wb') as f:
                f.write(pdf_bytes)
            print(f"[JOB] PDF saved: {pdf_path}")
            
            # Save JSON
            json_path = os.path.join(CONFIG['output_dir'], f"job_{timestamp}.json")
            safe_data = {**data}
            if 'photos' in safe_data:
                safe_data['photos'] = {k: {'captured': bool(v)} for k, v in data.get('photos', {}).items() if v}
            if 'audio' in safe_data:
                safe_data['audio'] = {'captured': bool(data.get('audio'))}
            with open(json_path, 'w') as f:
                json.dump(safe_data, f, indent=2)
            
            # Prepare email
            company = data.get('company', {})
            plumber = data.get('plumber', {})
            answers = data.get('answers', {})
            customer = data.get('customer', 'Ikke oppgitt')
            job_desc = data.get('jobDescription', '')
            notes = data.get('notes', '')
            
            office_email = data.get('officeEmail', '').strip()
            
            # SAFETY: No fallback. If no valid email provided, reject.
            if not office_email or '@' not in office_email:
                self._json({
                    'success': False,
                    'error': 'Ingen gyldig e-postadresse oppgitt. Rapporten ble IKKE sendt.'
                }, 400)
                print(f"[JOB] REJECTED - No valid email provided")
                return
            
            subject = f"Jobbrapport - {customer or plumber.get('name', 'Ukjent')} - {timestamp[:8]}"
            body = f"""Ny jobbrapport mottatt.

Kunde/Adresse: {customer or 'Ikke oppgitt'}
Rørlegger: {plumber.get('name', 'N/A')}
Tidspunkt: {data.get('timestamp', 'N/A')[:19].replace('T', ' ')}
{f'Arbeid: {job_desc}' if job_desc else ''}

Status:
- Fullført: {'Ja' if answers.get('completed') else 'Nei'}
- Materialer byttet: {'Ja' if answers.get('materials') else 'Nei'}
- Oppfølging nødvendig: {'Ja' if answers.get('followup') else 'Nei'}
{f'Notater: {notes}' if notes else ''}

Se vedlagt PDF for detaljer og bilder.
{' Lydopptak vedlagt.' if data.get('audio') else ''}

---
Automatisk generert av VVS Dokumentasjon
"""
            
            # Prepare attachments
            attachments = [(pdf_filename, pdf_bytes)]
            
            # Add audio if present
            audio_data = data.get('audio')
            if audio_data:
                try:
                    # Extract base64 audio
                    if ',' in audio_data:
                        audio_data = audio_data.split(',')[1]
                    audio_bytes = base64.b64decode(audio_data)
                    audio_filename = f"lydopptak_{timestamp}.webm"
                    attachments.append((audio_filename, audio_bytes))
                    print(f"[JOB] Audio attached: {audio_filename}")
                except Exception as e:
                    print(f"[JOB] Audio error: {e}")
            
            # Send email
            email_sent = False
            if office_email:
                print(f"[JOB] Sending to {office_email}...")
                email_sent = self.email_sender.send(
                    to_email=office_email,
                    subject=subject,
                    body=body,
                    attachments=attachments
                )
            
            self._json({
                'success': True,
                'job_id': job_id,
                'pdf_generated': True,
                'email_sent': email_sent,
                'message': 'Jobb mottatt og behandlet'
            })
            
            print(f"[JOB] {job_id} completed\n")
            
        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()
            self._json({'success': False, 'error': str(e)}, 500)
    
    def _json(self, data, status=200):
        self.send_response(status)
        self._cors()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', CONFIG['allowed_origins'])
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
    
    def log_message(self, fmt, *args):
        print(f"[HTTP] {args[0]}")


# ============================================
# MAIN
# ============================================
def main():
    server = HTTPServer(('', CONFIG['port']), PipelineHandler)
    
    print(f"""
╔═══════════════════════════════════════════════════╗
║         PIPELINE V0 - PRODUCTION SERVER           ║
╠═══════════════════════════════════════════════════╣
║  Port: {CONFIG['port']:<42} ║
║  SMTP: {'Configured' if CONFIG['smtp']['user'] else 'Not configured':<42} ║
║  Office Email: {CONFIG['default_office_email'][:30] or 'Not set':<30} ║
╚═══════════════════════════════════════════════════╝

Endpoints:
  POST /api/submit  - Submit job
  GET  /api/status  - Server status
  GET  /health      - Health check

Waiting for jobs...
""")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
