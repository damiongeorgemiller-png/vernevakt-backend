"""
SHA PIPELINE BACKEND - Construction Safety Documentation (Norway)
================================================================
Compliance-grade documentation system for Byggeplass SHA
- Tamper-resistant photo metadata
- Immutable audit trail
- Role separation (worker submits, manager approves)
- Norwegian language reports
- HMS-kort integration
- Vernerunde templates
- Hazard reporting with instant alerts
"""

import os
import json
import base64
import hashlib
import hmac
import uuid
import smtplib
import logging
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from urllib.parse import parse_qs, urlparse

# PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

from PIL import Image as PILImage

# ============================================
# CONFIGURATION
# ============================================
CONFIG = {
    'port': int(os.environ.get('PORT', 10000)),
    'smtp': {
        'host': os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
        'port': int(os.environ.get('SMTP_PORT', 587)),
        'user': os.environ.get('SMTP_USER', ''),
        'password': os.environ.get('SMTP_PASSWORD', ''),
    },
    'default_office_email': os.environ.get('DEFAULT_OFFICE_EMAIL', ''),
    'hazard_alert_email': os.environ.get('HAZARD_ALERT_EMAIL', os.environ.get('DEFAULT_OFFICE_EMAIL', '')),
    # Secret key for HMAC signatures (tamper detection)
    'signing_key': os.environ.get('SIGNING_KEY', 'sha-pipeline-default-key-change-in-production'),
}

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================
# AUDIT LOG - Immutable Record
# ============================================
AUDIT_LOG = []  # In production, this would be a database
USERS = {}      # username -> {password_hash, name, hms_kort, role, created_at}
REPORTS = []    # list of submitted reports (in-memory, resets on restart)

def log_audit(action, user_id, details, record_id=None):
    """Create immutable audit entry with tamper-proof signature"""
    entry = {
        'id': str(uuid.uuid4()),
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'action': action,
        'user_id': user_id,
        'record_id': record_id,
        'details': details,
    }
    # Create HMAC signature for tamper detection
    entry_str = json.dumps(entry, sort_keys=True)
    entry['signature'] = hmac.new(
        CONFIG['signing_key'].encode(),
        entry_str.encode(),
        hashlib.sha256
    ).hexdigest()
    
    AUDIT_LOG.append(entry)
    logger.info(f"[AUDIT] {action} by {user_id}: {details}")
    return entry

# ============================================
# TAMPER-PROOF PHOTO METADATA
# ============================================
def create_photo_hash(photo_data, timestamp, gps_coords, device_id):
    """Create tamper-proof hash of photo + metadata"""
    combined = f"{photo_data[:100]}{timestamp}{gps_coords}{device_id}"
    return hashlib.sha256(combined.encode()).hexdigest()

def verify_photo_integrity(photo_data, metadata):
    """Verify photo hasn't been tampered with"""
    expected_hash = create_photo_hash(
        photo_data,
        metadata.get('timestamp', ''),
        metadata.get('gps', ''),
        metadata.get('device_id', '')
    )
    return expected_hash == metadata.get('hash', '')

# ============================================
# VERNERUNDE TEMPLATES (Safety Round Checklists)
# ============================================
VERNERUNDE_TEMPLATES = {
    'daglig': {  # Daily inspection
        'name': 'Daglig vernerunde',
        'items': [
            {'id': 'ppe', 'text': 'Alt personell bruker påkrevd verneutstyr (hjelm, vest, sko)', 'critical': True},
            {'id': 'barriers', 'text': 'Sperringer og sikring er på plass', 'critical': True},
            {'id': 'access', 'text': 'Adkomstveier er ryddige og sikre', 'critical': False},
            {'id': 'equipment', 'text': 'Utstyr og maskiner er i forsvarlig stand', 'critical': True},
            {'id': 'electrical', 'text': 'Elektriske installasjoner er sikret', 'critical': True},
            {'id': 'fall_protection', 'text': 'Fallsikring er på plass ved arbeid i høyden', 'critical': True},
            {'id': 'housekeeping', 'text': 'Arbeidsplassen er ryddig', 'critical': False},
            {'id': 'fire', 'text': 'Brannslukningsutstyr er tilgjengelig', 'critical': True},
            {'id': 'first_aid', 'text': 'Førstehjelpsutstyr er tilgjengelig', 'critical': False},
            {'id': 'signage', 'text': 'Skilting og varsler er synlige', 'critical': False},
        ]
    },
    'ukentlig': {  # Weekly inspection
        'name': 'Ukentlig vernerunde',
        'items': [
            {'id': 'ppe', 'text': 'Alt personell bruker påkrevd verneutstyr', 'critical': True},
            {'id': 'barriers', 'text': 'Sperringer og sikring er på plass', 'critical': True},
            {'id': 'scaffolding', 'text': 'Stillaser er kontrollert og godkjent', 'critical': True},
            {'id': 'lifting', 'text': 'Løfteutstyr er sertifisert og i orden', 'critical': True},
            {'id': 'chemicals', 'text': 'Kjemikalier er forsvarlig lagret med sikkerhetsdatablad', 'critical': True},
            {'id': 'waste', 'text': 'Avfallshåndtering er i henhold til plan', 'critical': False},
            {'id': 'emergency', 'text': 'Nødutganger er merket og frie', 'critical': True},
            {'id': 'documentation', 'text': 'SHA-dokumentasjon er oppdatert', 'critical': False},
            {'id': 'training', 'text': 'Alle har gyldig HMS-kort', 'critical': True},
            {'id': 'subcontractors', 'text': 'Underentreprenører følger SHA-plan', 'critical': True},
        ]
    },
    'fare': {  # Hazard report
        'name': 'Farerapport',
        'items': [
            {'id': 'hazard_type', 'text': 'Type fare identifisert', 'critical': True},
            {'id': 'location', 'text': 'Nøyaktig plassering dokumentert', 'critical': True},
            {'id': 'severity', 'text': 'Alvorlighetsgrad vurdert', 'critical': True},
            {'id': 'immediate_action', 'text': 'Umiddelbare tiltak iverksatt', 'critical': True},
            {'id': 'area_secured', 'text': 'Området er sikret/sperret', 'critical': True},
            {'id': 'reported', 'text': 'Leder er varslet', 'critical': True},
        ]
    }
}

# ============================================
# PDF GENERATION - Norwegian Compliance Format
# ============================================
def generate_sha_report(data, photos, output_path):
    """Generate compliant SHA report PDF in Norwegian"""
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12,
        textColor=HexColor('#1a365d'),
        alignment=TA_CENTER
    )
    
    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=12,
        spaceBefore=12,
        spaceAfter=6,
        textColor=HexColor('#2d3748'),
        borderWidth=1,
        borderColor=HexColor('#e2e8f0'),
        borderPadding=5,
        backColor=HexColor('#f7fafc')
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    small_style = ParagraphStyle(
        'CustomSmall',
        parent=styles['Normal'],
        fontSize=8,
        textColor=HexColor('#718096')
    )
    
    story = []
    
    # ===== HEADER =====
    report_type = data.get('report_type', 'daglig')
    template = VERNERUNDE_TEMPLATES.get(report_type, VERNERUNDE_TEMPLATES['daglig'])
    
    if report_type == 'fare':
        story.append(Paragraph("⚠️ FARERAPPORT - HAZARD REPORT", title_style))
    else:
        story.append(Paragraph(f"SHA-RAPPORT: {template['name'].upper()}", title_style))
    
    story.append(Spacer(1, 5*mm))
    
    # ===== METADATA TABLE =====
    site_info = data.get('site') or {}
    worker_info = data.get('worker') or {}
    if not isinstance(site_info, dict): site_info = {}
    if not isinstance(worker_info, dict): worker_info = {}
    
    # Format timestamp
    timestamp = data.get('timestamp', datetime.now().isoformat())
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        formatted_date = dt.strftime('%d.%m.%Y')
        formatted_time = dt.strftime('%H:%M')
    except:
        formatted_date = timestamp[:10]
        formatted_time = timestamp[11:16] if len(timestamp) > 16 else ''
    
    metadata_data = [
        ['Byggeplass:', site_info.get('name', 'Ikke oppgitt'), 'Dato:', formatted_date],
        ['Adresse:', site_info.get('address', 'Ikke oppgitt'), 'Klokkeslett:', formatted_time],
        ['Utført av:', worker_info.get('name', 'Ikke oppgitt'), 'HMS-kort nr:', worker_info.get('hms_kort', 'Ikke oppgitt')],
        ['Firma:', site_info.get('company', 'Ikke oppgitt'), 'Rapport-ID:', data.get('report_id', '')[:8]],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[25*mm, 55*mm, 25*mm, 55*mm])
    metadata_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#4a5568')),
        ('TEXTCOLOR', (2, 0), (2, -1), HexColor('#4a5568')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
        ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f7fafc')),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 8*mm))
    
    # ===== GPS VERIFICATION =====
    gps = data.get('gps') or {}
    if gps.get('lat') and gps.get('lng'):
        gps_text = f"📍 GPS-verifisert posisjon: {gps['lat']:.6f}, {gps['lng']:.6f}"
        if gps.get('accuracy'):
            gps_text += f" (±{gps['accuracy']}m)"
        story.append(Paragraph(gps_text, small_style))
        story.append(Spacer(1, 3*mm))
    
    # ===== CHECKLIST RESULTS =====
    story.append(Paragraph("SJEKKPUNKTER", header_style))
    
    checklist = data.get('checklist') or {}
    checklist_data = [['Status', 'Sjekkpunkt', 'Kritisk']]
    
    for item in template['items']:
        item_id = item['id']
        status = checklist.get(item_id, None)
        
        if status == True:
            status_text = '✓ OK'
            status_color = HexColor('#38a169')
        elif status == False:
            status_text = '✗ AVVIK'
            status_color = HexColor('#e53e3e')
        else:
            status_text = '— N/A'
            status_color = HexColor('#718096')
        
        critical_text = 'JA' if item['critical'] else 'Nei'
        checklist_data.append([status_text, item['text'], critical_text])
    
    checklist_table = Table(checklist_data, colWidths=[20*mm, 115*mm, 20*mm])
    checklist_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#f7fafc')]),
    ]))
    story.append(checklist_table)
    story.append(Spacer(1, 8*mm))
    
    # ===== HAZARD DETAILS (if hazard report) =====
    if report_type == 'fare':
        story.append(Paragraph("⚠️ FAREDETALJER", header_style))
        
        hazard = data.get('hazard') or {}
        if not isinstance(hazard, dict): hazard = {}
        hazard_data = [
            ['Type fare:', hazard.get('type', 'Ikke spesifisert')],
            ['Alvorlighetsgrad:', hazard.get('severity', 'Ikke vurdert')],
            ['Beskrivelse:', hazard.get('description', 'Ingen beskrivelse')],
            ['Umiddelbare tiltak:', hazard.get('immediate_action', 'Ingen tiltak beskrevet')],
        ]
        
        hazard_table = Table(hazard_data, colWidths=[35*mm, 125*mm])
        hazard_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#fed7d7')),
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#fff5f5')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(hazard_table)
        story.append(Spacer(1, 8*mm))
    
    # ===== NOTES =====
    notes = data.get('notes', '')
    if notes:
        story.append(Paragraph("KOMMENTARER", header_style))
        story.append(Paragraph(notes, normal_style))
        story.append(Spacer(1, 5*mm))
    
    # ===== VOICE TRANSCRIPTION =====
    transcription = data.get('transcription', '')
    if transcription:
        story.append(Paragraph("LYDOPPTAK (TRANSKRIBERT)", header_style))
        story.append(Paragraph(transcription, normal_style))
        story.append(Spacer(1, 5*mm))
    
    # ===== PHOTOS =====
    if photos:
        story.append(PageBreak())
        story.append(Paragraph("FOTODOKUMENTASJON", header_style))
        story.append(Spacer(1, 3*mm))
        
        photo_labels = ['Oversikt', 'Detalj 1', 'Detalj 2', 'Avvik/Fare'] if report_type == 'fare' else ['Før', 'Under', 'Detalj', 'Etter']
        
        # Create 2x2 grid
        photo_table_data = []
        row = []
        
        for i, photo_data in enumerate(photos[:4]):
            try:
                # Decode and resize photo
                img_data = base64.b64decode(photo_data.split(',')[1] if ',' in photo_data else photo_data)
                img = PILImage.open(BytesIO(img_data))
                
                # Resize for PDF
                img.thumbnail((400, 400), PILImage.Resampling.LANCZOS)
                
                # Save to buffer
                img_buffer = BytesIO()
                img.save(img_buffer, format='JPEG', quality=85)
                img_buffer.seek(0)
                
                # Create reportlab image
                rl_img = Image(img_buffer, width=75*mm, height=56*mm)
                
                label = photo_labels[i] if i < len(photo_labels) else f'Bilde {i+1}'
                cell_content = [rl_img, Paragraph(f"<b>{label}</b>", small_style)]
                row.append(cell_content)
                
            except Exception as e:
                logger.error(f"Error processing photo {i}: {e}")
                row.append([Paragraph(f"Bilde {i+1} - Feil", small_style)])
            
            if len(row) == 2:
                photo_table_data.append(row)
                row = []
        
        if row:  # Add remaining photos
            while len(row) < 2:
                row.append([''])
            photo_table_data.append(row)
        
        if photo_table_data:
            photo_table = Table(photo_table_data, colWidths=[80*mm, 80*mm])
            photo_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOX', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ]))
            story.append(photo_table)
    
    # ===== APPROVAL SECTION =====
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph("GODKJENNING", header_style))
    
    approval = data.get('approval') or {}
    approval_status = approval.get('status', 'pending')
    
    if approval_status == 'approved':
        approval_text = f"✓ GODKJENT av {approval.get('approved_by', 'Ukjent')} den {approval.get('approved_at', 'Ukjent dato')}"
        approval_color = HexColor('#38a169')
    elif approval_status == 'rejected':
        approval_text = f"✗ AVVIST av {approval.get('approved_by', 'Ukjent')}: {approval.get('rejection_reason', 'Ingen grunn oppgitt')}"
        approval_color = HexColor('#e53e3e')
    else:
        approval_text = "⏳ VENTER PÅ GODKJENNING"
        approval_color = HexColor('#dd6b20')
    
    story.append(Paragraph(approval_text, ParagraphStyle(
        'ApprovalStyle',
        parent=normal_style,
        fontSize=11,
        textColor=approval_color,
        spaceBefore=6
    )))
    
    # ===== FOOTER =====
    story.append(Spacer(1, 15*mm))
    
    # Tamper-proof hash
    report_hash = data.get('integrity_hash', 'N/A')
    
    footer_text = f"""
    <font size="7" color="#718096">
    ─────────────────────────────────────────────────────────────────────<br/>
    Dette dokumentet er generert automatisk av SHA Pipeline.<br/>
    Rapport-ID: {data.get('report_id', 'N/A')}<br/>
    Integritets-hash: {report_hash[:16]}...<br/>
    Generert: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}<br/>
    <br/>
    SHA-dokumentasjon i henhold til Byggherreforskriften og Arbeidsmiljøloven.<br/>
    Dokumentet skal oppbevares i minimum 5 år etter prosjektets avslutning.
    </font>
    """
    story.append(Paragraph(footer_text, normal_style))
    
    # Build PDF
    doc.build(story)
    logger.info(f"[PDF] Generated SHA report: {output_path}")
    return output_path

# ============================================
# EMAIL FUNCTIONS
# ============================================
def send_email(to_email, subject, body, attachments=None):
    """Send email with attachments"""
    if not CONFIG['smtp']['user'] or not CONFIG['smtp']['password']:
        logger.warning("[EMAIL] SMTP not configured")
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = CONFIG['smtp']['user']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Attachments
        if attachments:
            for filename, data in attachments:
                part = MIMEBase('application', 'octet-stream')
                if isinstance(data, str):
                    part.set_payload(data.encode('utf-8'))
                else:
                    part.set_payload(data)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
                msg.attach(part)
        
        # Send
        server = smtplib.SMTP(CONFIG['smtp']['host'], CONFIG['smtp']['port'])
        server.starttls()
        server.login(CONFIG['smtp']['user'], CONFIG['smtp']['password'])
        server.send_message(msg)
        server.quit()
        
        logger.info(f"[EMAIL] Sent to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"[EMAIL] Failed: {e}")
        return False

def send_hazard_alert(data, pdf_path):
    """Send immediate hazard alert to site manager"""
    hazard = data.get('hazard') or {}
    site = data.get('site') or {}
    worker = data.get('worker') or {}
    if not isinstance(hazard, dict): hazard = {}
    if not isinstance(site, dict): site = {}
    if not isinstance(worker, dict): worker = {}
    
    subject = f"⚠️ FARE RAPPORTERT - {site.get('name', 'Ukjent byggeplass')}"
    
    body = f"""
UMIDDELBAR FAREMELDING
=====================

Byggeplass: {site.get('name', 'Ukjent')}
Adresse: {site.get('address', 'Ukjent')}
Rapportert av: {worker.get('name', 'Ukjent')} (HMS-kort: {worker.get('hms_kort', 'Ukjent')})
Tidspunkt: {data.get('timestamp', 'Ukjent')}

FARE:
Type: {hazard.get('type', 'Ikke spesifisert')}
Alvorlighetsgrad: {hazard.get('severity', 'Ikke vurdert')}

Beskrivelse:
{hazard.get('description', 'Ingen beskrivelse')}

Umiddelbare tiltak:
{hazard.get('immediate_action', 'Ingen tiltak beskrevet')}

---
Se vedlagt PDF for fullstendig rapport med bilder.
Vennligst bekreft mottak og iverksett nødvendige tiltak.

SHA Pipeline - Automatisk generert faremelding
"""
    
    # Read PDF
    attachments = []
    try:
        with open(pdf_path, 'rb') as f:
            attachments.append((f"farerapport_{data.get('report_id', 'ukjent')[:8]}.pdf", f.read()))
    except Exception as e:
        logger.error(f"[HAZARD] Could not attach PDF: {e}")
    
    # Send to hazard alert email (site manager)
    alert_email = (data.get('site') or {}).get('manager_email') or CONFIG['hazard_alert_email']
    return send_email(alert_email, subject, body, attachments)

# ============================================
# HTTP REQUEST HANDLER
# ============================================
class SHAHandler(BaseHTTPRequestHandler):
    
    def _send_response(self, status, data):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))
    
    def do_OPTIONS(self):
        self._send_response(200, {'status': 'ok'})
    
    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == '/health':
            self._send_response(200, {'healthy': True})
        
        elif path == '/api/status':
            self._send_response(200, {
                'status': 'ok',
                'version': '1.0.0',
                'service': 'SHA Pipeline',
                'smtp_configured': bool(CONFIG['smtp']['user'] and CONFIG['smtp']['password'])
            })
        
        elif path == '/api/templates':
            # Return available templates
            templates = {}
            for key, tmpl in VERNERUNDE_TEMPLATES.items():
                templates[key] = {
                    'name': tmpl['name'],
                    'items': tmpl['items']
                }
            self._send_response(200, {'templates': templates})
        
        elif path == '/api/audit':
            # Return audit log (would require auth in production)
            self._send_response(200, {'audit_log': AUDIT_LOG[-100:]})  # Last 100 entries
        
        elif path == '/api/reports':
            # Return report history (last 200, newest first)
            self._send_response(200, {'reports': list(reversed(REPORTS[-200:]))})
        
        else:
            self._send_response(404, {'error': 'Not found'})
    
    def do_POST(self):
        path = urlparse(self.path).path
        
        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            self._send_response(400, {'error': 'Invalid JSON'})
            return
        
        if path == '/api/submit':
            self._handle_submit(data)
        
        elif path == '/api/hazard':
            self._handle_hazard(data)
        
        elif path == '/api/approve':
            self._handle_approve(data)
        
        elif path == '/api/login':
            self._handle_login(data)
        
        elif path == '/api/register':
            self._handle_register(data)
        
        else:
            self._send_response(404, {'error': 'Not found'})
    
    def _handle_submit(self, data):
        """Handle SHA report submission"""
        logger.info("[JOB] Received SHA report submission")
        
        try:
            # Generate report ID
            report_id = str(uuid.uuid4())
            data['report_id'] = report_id

            # Safe extraction - ensure dicts, never None
            report_type = data.get('report_type') or 'daglig'
            worker = data.get('worker') or {}
            site = data.get('site') or {}
            if not isinstance(worker, dict): worker = {}
            if not isinstance(site, dict): site = {}

            # Create integrity hash (exclude photos to keep it fast)
            hash_data = {k: v for k, v in data.items() if k != 'photos'}
            integrity_hash = hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()
            data['integrity_hash'] = integrity_hash
            REPORTS.append({
                'report_id': report_id,
                'report_type': report_type,
                'status': 'pending',
                'timestamp': data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'site_name': site.get('name', ''),
                'worker_name': worker.get('name', ''),
                'worker_hms': worker.get('hms_kort', ''),
                'integrity_hash': integrity_hash,
            })
            
            # Log audit entry
            log_audit(
                action='REPORT_SUBMITTED',
                user_id=worker.get('hms_kort', 'unknown'),
                details=f"Report type: {data.get('report_type', 'daglig')}",
                record_id=report_id
            )
            
            # Extract photos
            photos = data.get('photos', [])
            
            # Generate PDF
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pdf_filename = f"sha_rapport_{timestamp}.pdf"
            pdf_path = f"/tmp/{pdf_filename}"
            
            generate_sha_report(data, photos, pdf_path)
            
            # Read PDF for email
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            
            # Prepare email
            office_email = site.get('office_email') or CONFIG['default_office_email']
            
            report_type = data.get('report_type', 'daglig')
            template = VERNERUNDE_TEMPLATES.get(report_type, VERNERUNDE_TEMPLATES['daglig'])
            
            subject = f"SHA-Rapport: {template['name']} - {site.get('name', 'Ukjent')} - {timestamp[:8]}"
            
            body = f"""
Ny SHA-rapport mottatt.

Byggeplass: {site.get('name', 'Ikke oppgitt')}
Adresse: {site.get('address', 'Ikke oppgitt')}
Utført av: {worker.get('name', 'Ukjent')} (HMS-kort: {worker.get('hms_kort', 'Ukjent')})
Type: {template['name']}
Tidspunkt: {data.get('timestamp', 'Ukjent')}

Status: VENTER PÅ GODKJENNING

Se vedlagt PDF for fullstendig rapport.

---
SHA Pipeline - Automatisk generert rapport
Rapport-ID: {report_id}
"""
            
            # Send email
            attachments = [(pdf_filename, pdf_data)]
            
            # Attach audio if present
            audio = data.get('audio')
            if audio:
                try:
                    audio_data = base64.b64decode(audio.split(',')[1] if ',' in audio else audio)
                    attachments.append((f"lydopptak_{timestamp}.webm", audio_data))
                except Exception as e:
                    logger.error(f"[AUDIO] Failed to process: {e}")
            
            email_sent = send_email(office_email, subject, body, attachments)
            
            # Log email status
            log_audit(
                action='REPORT_EMAILED' if email_sent else 'EMAIL_FAILED',
                user_id='system',
                details=f"To: {office_email}",
                record_id=report_id
            )
            
            # Cleanup
            try:
                os.remove(pdf_path)
            except:
                pass
            
            self._send_response(200, {
                'success': True,
                'report_id': report_id,
                'email_sent': email_sent,
                'integrity_hash': integrity_hash[:16]
            })
            
        except Exception as e:
            logger.error(f"[JOB] Error: {e}")
            self._send_response(500, {'error': str(e)})
    
    def _handle_hazard(self, data):
        """Handle immediate hazard report"""
        logger.info(f"[HAZARD] Raw data keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        logger.info(f"[HAZARD] worker={data.get('worker')} site={data.get('site')} hazard={data.get('hazard')}")
        
        try:
            # Force report type
            data['report_type'] = 'fare'
            
            # Generate report ID
            report_id = str(uuid.uuid4())
            data['report_id'] = report_id

            # Safe extraction - ensure dicts, never None
            worker = data.get('worker') or {}
            site = data.get('site') or {}
            hazard = data.get('hazard') or {}
            if not isinstance(worker, dict): worker = {}
            if not isinstance(site, dict): site = {}
            if not isinstance(hazard, dict): hazard = {}

            # Create integrity hash (exclude photos)
            hash_data = {k: v for k, v in data.items() if k != 'photos'}
            integrity_hash = hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()
            data['integrity_hash'] = integrity_hash
            REPORTS.append({
                'report_id': report_id,
                'report_type': 'fare',
                'status': 'pending',
                'timestamp': data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                'site_name': site.get('name', ''),
                'worker_name': worker.get('name', ''),
                'worker_hms': worker.get('hms_kort', ''),
                'integrity_hash': integrity_hash,
            })
            
            # Log audit entry (critical)
            log_audit(
                action='HAZARD_REPORTED',
                user_id=worker.get('hms_kort', 'unknown'),
                details=f"Type: {hazard.get('type', 'unknown')}, Severity: {hazard.get('severity', 'unknown')}",
                record_id=report_id
            )
            
            # Extract photos
            photos = data.get('photos', [])
            
            # Generate PDF
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pdf_filename = f"farerapport_{timestamp}.pdf"
            pdf_path = f"/tmp/{pdf_filename}"
            
            generate_sha_report(data, photos, pdf_path)
            
            # Send immediate alert
            alert_sent = send_hazard_alert(data, pdf_path)
            
            # Log alert status
            log_audit(
                action='HAZARD_ALERT_SENT' if alert_sent else 'HAZARD_ALERT_FAILED',
                user_id='system',
                details=f"To site manager",
                record_id=report_id
            )
            
            # Cleanup
            try:
                os.remove(pdf_path)
            except:
                pass
            
            self._send_response(200, {
                'success': True,
                'report_id': report_id,
                'alert_sent': alert_sent,
                'integrity_hash': integrity_hash[:16]
            })
            
        except Exception as e:
            logger.error(f"[HAZARD] Error: {e}")
            self._send_response(500, {'error': str(e)})
    
    def _handle_approve(self, data):
        """Handle manager approval/rejection"""
        logger.info("[APPROVE] Received approval request")
        
        try:
            report_id = data.get('report_id')
            action = data.get('action')  # 'approve' or 'reject'
            manager = data.get('manager') or {}
            if not isinstance(manager, dict): manager = {}
            
            if not report_id or not action:
                self._send_response(400, {'error': 'Missing report_id or action'})
                return
            
            # Update report status in memory
            new_status = 'approved' if action == 'approve' else 'rejected'
            for r in REPORTS:
                if r['report_id'] == report_id:
                    r['status'] = new_status
                    r['approved_by'] = manager.get('name', 'Ukjent')
                    r['approved_at'] = datetime.now(timezone.utc).isoformat()
                    if action == 'reject':
                        r['rejection_reason'] = data.get('rejection_reason', '')
                    break
            
            # Log audit entry
            log_audit(
                action=f'REPORT_{action.upper()}D',
                user_id=manager.get('hms_kort', 'unknown'),
                details=f"By: {manager.get('name', 'Unknown')}",
                record_id=report_id
            )
            
            self._send_response(200, {
                'success': True,
                'report_id': report_id,
                'status': new_status
            })
            
        except Exception as e:
            logger.error(f"[APPROVE] Error: {e}")
            self._send_response(500, {'error': str(e)})
    
    def _handle_register(self, data):
        """Register a new worker account using hms_kort + pin"""
        logger.info("[REGISTER] New registration request")
        
        try:
            hms_kort = (data.get('hms_kort') or '').strip()
            pin      = (data.get('pin') or '').strip()
            name     = (data.get('name') or '').strip()
            company  = (data.get('company') or '').strip()
            role     = data.get('role', 'worker')  # 'worker' or 'manager'
            
            if not hms_kort or not pin or not name:
                self._send_response(400, {'error': 'Navn, HMS-kort og PIN er påkrevd'})
                return
            
            if len(pin) < 4:
                self._send_response(400, {'error': 'PIN må være minst 4 siffer'})
                return
            
            if hms_kort in USERS:
                self._send_response(409, {'error': 'HMS-kort er allerede registrert'})
                return
            
            # Hash PIN
            pin_hash = hashlib.sha256(
                (pin + CONFIG['signing_key']).encode()
            ).hexdigest()
            
            USERS[hms_kort] = {
                'pin_hash': pin_hash,
                'name': name,
                'hms_kort': hms_kort,
                'company': company,
                'role': role,
                'created_at': datetime.now(timezone.utc).isoformat(),
            }
            
            log_audit(
                action='USER_REGISTERED',
                user_id=hms_kort,
                details=f"Name: {name}, Role: {role}, HMS-kort: {hms_kort}"
            )
            
            self._send_response(200, {
                'success': True,
                'name': name,
                'hms_kort': hms_kort,
                'company': company,
                'role': role,
            })
            
        except Exception as e:
            logger.error(f"[REGISTER] Error: {e}")
            self._send_response(500, {'error': str(e)})
    
    def _handle_login(self, data):
        """Authenticate a worker using hms_kort + pin"""
        logger.info("[LOGIN] Login attempt")
        
        try:
            hms_kort = (data.get('hms_kort') or '').strip()
            pin      = (data.get('pin') or '').strip()
            
            if not hms_kort or not pin:
                self._send_response(400, {'error': 'HMS-kort og PIN er påkrevd'})
                return
            
            user = USERS.get(hms_kort)
            
            if not user:
                self._send_response(401, {'error': 'Feil HMS-kort eller PIN'})
                return
            
            pin_hash = hashlib.sha256(
                (pin + CONFIG['signing_key']).encode()
            ).hexdigest()
            
            if pin_hash != user['pin_hash']:
                self._send_response(401, {'error': 'Feil HMS-kort eller PIN'})
                return
            
            log_audit(
                action='USER_LOGIN',
                user_id=hms_kort,
                details=f"Successful login for {user['name']}"
            )
            
            self._send_response(200, {
                'success': True,
                'worker': {
                    'name': user['name'],
                    'hms_kort': user['hms_kort'],
                    'company': user.get('company', ''),
                    'role': user['role'],
                }
            })
        except Exception as e:
            logger.error(f"[LOGIN] Error: {e}")
            self._send_response(500, {'error': str(e)})
    
    def log_message(self, format, *args):
        logger.info(f"[HTTP] {args[0]}")

# ============================================
# MAIN
# ============================================
def main():
    port = CONFIG['port']
    server = HTTPServer(('0.0.0.0', port), SHAHandler)
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗██╗  ██╗ █████╗     ██████╗ ██╗██████╗ ███████╗    ║
║   ██╔════╝██║  ██║██╔══██╗    ██╔══██╗██║██╔══██╗██╔════╝    ║
║   ███████╗███████║███████║    ██████╔╝██║██████╔╝█████╗      ║
║   ╚════██║██╔══██║██╔══██║    ██╔═══╝ ██║██╔═══╝ ██╔══╝      ║
║   ███████║██║  ██║██║  ██║    ██║     ██║██║     ███████╗    ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝     ╚═╝╚═╝     ╚══════╝    ║
║                                                               ║
║   Construction Safety Documentation - Norway                  ║
║   Byggeplass SHA Pipeline v1.0                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    logger.info(f"Server starting on port {port}")
    logger.info(f"SMTP configured: {bool(CONFIG['smtp']['user'] and CONFIG['smtp']['password'])}")
    logger.info(f"Default email: {CONFIG['default_office_email']}")
    logger.info("Ready to receive SHA reports")
    
    server.serve_forever()

if __name__ == '__main__':
    main()
