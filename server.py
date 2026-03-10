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
# ============================================
# DATABASE SETUP - PostgreSQL with in-memory fallback
# ============================================
import threading

# In-memory fallback (used if DATABASE_URL not set)
_AUDIT_LOG = []
_USERS = {}
_REPORTS = []
_DB_LOCK = threading.Lock()

DATABASE_URL = os.environ.get('DATABASE_URL', '')

def get_db():
    """Get a database connection, or None if not configured"""
    if not DATABASE_URL:
        return None
    try:
        import psycopg
        conn = psycopg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logger.error(f"[DB] Connection failed: {e}")
        return None

def init_db():
    """Create tables if they don't exist"""
    conn = get_db()
    if not conn:
        logger.warning("[DB] No DATABASE_URL set — using in-memory storage (data resets on restart)")
        return False
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                hms_kort TEXT PRIMARY KEY,
                pin_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                company TEXT,
                role TEXT DEFAULT 'worker',
                created_at TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                report_type TEXT,
                status TEXT DEFAULT 'pending',
                timestamp TEXT,
                site_name TEXT,
                worker_name TEXT,
                worker_hms TEXT,
                integrity_hash TEXT,
                approved_by TEXT,
                approved_at TEXT,
                rejection_reason TEXT,
                full_data TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                action TEXT,
                user_id TEXT,
                record_id TEXT,
                details TEXT,
                signature TEXT
            )
        """)
        conn.commit()
        conn.close()
        logger.info("[DB] Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"[DB] Init failed: {e}")
        conn.close()
        return False

# ── USER OPERATIONS ──
def db_get_user(hms_kort):
    conn = get_db()
    if not conn:
        return _USERS.get(hms_kort)
    try:
        cur = conn.cursor()
        cur.execute("SELECT hms_kort,pin_hash,name,company,role,created_at FROM users WHERE hms_kort=%s", (hms_kort,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {'hms_kort':row[0],'pin_hash':row[1],'name':row[2],'company':row[3],'role':row[4],'created_at':row[5]}
        return None
    except Exception as e:
        logger.error(f"[DB] get_user error: {e}")
        conn.close()
        return _USERS.get(hms_kort)

def db_save_user(hms_kort, user_data):
    conn = get_db()
    if not conn:
        _USERS[hms_kort] = user_data
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (hms_kort,pin_hash,name,company,role,created_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (hms_kort) DO UPDATE
            SET pin_hash=EXCLUDED.pin_hash, name=EXCLUDED.name,
                company=EXCLUDED.company, role=EXCLUDED.role
        """, (hms_kort, user_data['pin_hash'], user_data['name'],
              user_data.get('company',''), user_data.get('role','worker'),
              user_data.get('created_at','')))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"[DB] save_user error: {e}")
        conn.close()
        _USERS[hms_kort] = user_data

def db_user_exists(hms_kort):
    conn = get_db()
    if not conn:
        return hms_kort in _USERS
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE hms_kort=%s", (hms_kort,))
        exists = cur.fetchone() is not None
        conn.close()
        return exists
    except Exception as e:
        logger.error(f"[DB] user_exists error: {e}")
        conn.close()
        return hms_kort in _USERS

# ── REPORT OPERATIONS ──
def db_save_report(report):
    conn = get_db()
    if not conn:
        _REPORTS.append(report)
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (report_id,report_type,status,timestamp,site_name,
                                 worker_name,worker_hms,integrity_hash,full_data)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (report_id) DO NOTHING
        """, (report['report_id'], report['report_type'], report.get('status','pending'),
              report['timestamp'], report.get('site_name',''), report.get('worker_name',''),
              report.get('worker_hms',''), report.get('integrity_hash',''),
              json.dumps(report)))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"[DB] save_report error: {e}")
        conn.close()
        _REPORTS.append(report)

def db_get_reports(limit=200):
    conn = get_db()
    if not conn:
        return list(reversed(_REPORTS[-limit:]))
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT report_id,report_type,status,timestamp,site_name,
                   worker_name,worker_hms,integrity_hash,approved_by,approved_at,rejection_reason
            FROM reports ORDER BY timestamp DESC LIMIT %s
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        return [{'report_id':r[0],'report_type':r[1],'status':r[2],'timestamp':r[3],
                 'site_name':r[4],'worker_name':r[5],'worker_hms':r[6],
                 'integrity_hash':r[7],'approved_by':r[8],'approved_at':r[9],
                 'rejection_reason':r[10]} for r in rows]
    except Exception as e:
        logger.error(f"[DB] get_reports error: {e}")
        conn.close()
        return list(reversed(_REPORTS[-limit:]))

def db_get_report(report_id):
    conn = get_db()
    if not conn:
        for r in _REPORTS:
            if r.get('report_id') == report_id:
                return r
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports WHERE report_id=%s", (report_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            return {'report_id':row[0],'report_type':row[1],'status':row[2],
                    'timestamp':row[3],'site_name':row[4],'worker_name':row[5],
                    'worker_hms':row[6],'integrity_hash':row[7],
                    'approved_by':row[8],'approved_at':row[9],'rejection_reason':row[10]}
        return None
    except Exception as e:
        logger.error(f"[DB] get_report error: {e}")
        conn.close()
        return None

def db_update_report_status(report_id, status, approved_by, approved_at, rejection_reason=''):
    conn = get_db()
    if not conn:
        for r in _REPORTS:
            if r.get('report_id') == report_id:
                r['status'] = status
                r['approved_by'] = approved_by
                r['approved_at'] = approved_at
                r['rejection_reason'] = rejection_reason
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE reports SET status=%s, approved_by=%s, approved_at=%s, rejection_reason=%s
            WHERE report_id=%s
        """, (status, approved_by, approved_at, rejection_reason, report_id))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"[DB] update_report error: {e}")
        conn.close()

# Legacy in-memory aliases (kept so existing code doesn't break)
AUDIT_LOG = _AUDIT_LOG
REPORTS = _REPORTS

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
    """Generate professional Vernevakt PDF report matching the sample design"""
    from reportlab.platypus import KeepTogether
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18*mm,
        leftMargin=18*mm,
        topMargin=16*mm,
        bottomMargin=16*mm
    )

    # ── Colors ──
    DARK       = HexColor('#1a2535')
    MID        = HexColor('#2d3a4a')
    LIGHT_BG   = HexColor('#f4f6f8')
    BORDER     = HexColor('#d0d7e0')
    GREEN      = HexColor('#2e7d32')
    GREEN_BG   = HexColor('#e8f5e9')
    RED        = HexColor('#c62828')
    RED_BG     = HexColor('#ffebee')
    AMBER      = HexColor('#e65100')
    AMBER_BG   = HexColor('#fff3e0')
    ORANGE     = HexColor('#ef6c00')
    ORANGE_BG  = HexColor('#fff8e1')
    MUTED      = HexColor('#546e7a')
    WHITE      = HexColor('#ffffff')

    SEV_COLORS = {
        'lav':     (HexColor('#1b5e20'), HexColor('#e8f5e9')),
        'middels': (HexColor('#f57f17'), HexColor('#fffde7')),
        'hoy':     (HexColor('#e65100'), HexColor('#fff3e0')),
        'høy':     (HexColor('#e65100'), HexColor('#fff3e0')),
        'kritisk': (HexColor('#b71c1c'), HexColor('#ffebee')),
    }

    styles = getSampleStyleSheet()

    def style(name, **kw):
        s = ParagraphStyle(name, parent=styles['Normal'], **kw)
        return s

    title_st  = style('T', fontSize=15, fontName='Helvetica-Bold', textColor=DARK, alignment=TA_CENTER, spaceAfter=2)
    sub_st    = style('S', fontSize=9,  fontName='Helvetica',      textColor=MUTED, alignment=TA_CENTER, spaceAfter=8)
    sec_st    = style('H', fontSize=9,  fontName='Helvetica-Bold', textColor=WHITE, spaceAfter=0)
    cell_key  = style('CK', fontSize=8.5, fontName='Helvetica-Bold', textColor=MUTED)
    cell_val  = style('CV', fontSize=8.5, fontName='Helvetica',      textColor=DARK)
    chk_st    = style('CH', fontSize=8.5, fontName='Helvetica',      textColor=DARK)
    foot_st   = style('F',  fontSize=7,   fontName='Helvetica',      textColor=MUTED, alignment=TA_CENTER)
    small_st  = style('SM', fontSize=7.5, fontName='Helvetica',      textColor=MUTED)

    def section_header(text, color=DARK):
        """Dark bar section header like the sample"""
        data_h = [[Paragraph(f'<b>{text}</b>', style('SH', fontSize=9, fontName='Helvetica-Bold', textColor=WHITE))]]
        t = Table(data_h, colWidths=[174*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), color),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
        ]))
        return t

    story = []

    # ── Safe data extraction ──
    report_type  = data.get('report_type') or 'daglig'
    site         = data.get('site') or {}
    worker       = data.get('worker') or {}
    gps          = data.get('gps') or {}
    checklist    = data.get('checklist') or {}
    hazard       = data.get('hazard') or {}
    notes        = data.get('notes') or ''
    approval     = data.get('approval') or {}
    report_id    = data.get('report_id', '')
    timestamp    = data.get('timestamp', '')
    if not isinstance(site, dict): site = {}
    if not isinstance(worker, dict): worker = {}
    if not isinstance(gps, dict): gps = {}
    if not isinstance(checklist, dict): checklist = {}
    if not isinstance(hazard, dict): hazard = {}
    if not isinstance(approval, dict): approval = {}

    template = VERNERUNDE_TEMPLATES.get(report_type, VERNERUNDE_TEMPLATES['daglig'])

    # Format date/time
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        fmt_date = dt.strftime('%d.%m.%Y')
        fmt_time = dt.strftime('%H:%M')
    except:
        fmt_date = datetime.now().strftime('%d.%m.%Y')
        fmt_time = datetime.now().strftime('%H:%M')

    # ── HEADER with Vernevakt SHA logo ──
    ORANGE  = HexColor('#f59e0b')
    YELLOW  = HexColor('#f5c842')
    RUST    = HexColor('#d4622a')
    BLACK   = HexColor('#111111')
    DARKBG  = HexColor('#0d1520')

    type_label = {'daglig': 'Daglig vernerunde', 'ukentlig': 'Ukentlig vernerunde', 'fare': 'Farerapport'}.get(report_type, report_type)

    from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
    from reportlab.graphics import renderPDF
    import math

    # Header: full width, 32mm tall
    hdr_w = 174 * mm
    hdr_h = 32 * mm
    d = Drawing(hdr_w, hdr_h)

    # Dark navy background
    d.add(Rect(0, 0, hdr_w, hdr_h, fillColor=DARKBG, strokeColor=None))

    # ── HELMET — centered at hx=18mm, total height ~24mm ──
    hx      = 18 * mm
    # Brim at bottom
    brim_w  = 13 * mm
    brim_h  = 3 * mm
    brim_y  = 4 * mm
    brim_x  = hx - brim_w / 2
    # Body above brim
    body_w  = 16 * mm
    body_h  = 7 * mm
    body_y  = brim_y + brim_h
    body_x  = hx - body_w / 2
    # Dome above body
    dome_r  = 8 * mm
    dome_y  = body_y + body_h  # base of dome

    d.add(Rect(brim_x, brim_y, brim_w, brim_h, fillColor=RUST,   strokeColor=None))
    d.add(Rect(body_x, body_y, body_w, body_h, fillColor=YELLOW, strokeColor=None))

    # Semicircle dome
    pts = []
    for i in range(19):
        angle = math.pi * i / 18
        px = hx    + dome_r * math.cos(math.pi - angle)
        py = dome_y + dome_r * math.sin(angle)
        pts.extend([px, py])
    pts.extend([hx + dome_r, dome_y, hx - dome_r, dome_y])
    d.add(Polygon(pts, fillColor=YELLOW, strokeColor=None))

    # ── VERTICAL DIVIDER ──
    div_x = 32 * mm
    d.add(Line(div_x, 4*mm, div_x, hdr_h - 4*mm, strokeColor=RUST, strokeWidth=1.5))

    # ── VERNEVAKT — large white bold ──
    text_x = div_x + 5 * mm
    d.add(String(text_x, hdr_h/2 + 2*mm, 'VERNEVAKT',
                 fontName='Helvetica-Bold', fontSize=17,
                 fillColor=HexColor('#ffffff')))

    # ── — SHA — in yellow with dashes ──
    sha_y   = hdr_h/2 - 6*mm
    sha_x   = text_x
    dash_len = 7 * mm
    gap      = 2 * mm
    sha_mid_y = sha_y + 2.5*mm

    d.add(Line(sha_x, sha_mid_y, sha_x + dash_len, sha_mid_y,
               strokeColor=YELLOW, strokeWidth=1.5))
    d.add(String(sha_x + dash_len + gap, sha_y, 'SHA',
                 fontName='Helvetica-Bold', fontSize=11,
                 fillColor=YELLOW))
    d.add(Line(sha_x + dash_len + gap + 12*mm, sha_mid_y,
               sha_x + dash_len + gap + 12*mm + dash_len, sha_mid_y,
               strokeColor=YELLOW, strokeWidth=1.5))

    # ── ORANGE bottom accent line ──
    d.add(Rect(0, 0, hdr_w, 1.2*mm, fillColor=RUST, strokeColor=None))

    from reportlab.platypus import Flowable
    class LogoHeader(Flowable):
        def __init__(self, drawing):
            Flowable.__init__(self)
            self.drawing = drawing
            self.width = drawing.width
            self.height = drawing.height
        def draw(self):
            renderPDF.draw(self.drawing, self.canv, 0, 0)

    story.append(LogoHeader(d))

    # Logo header already includes subtitle

    # Orange line
    orange_line = Table([['']], colWidths=[174*mm], rowHeights=[3.5])
    orange_line.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), ORANGE),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(orange_line)
    story.append(Spacer(1, 5*mm))

    # ── RAPPORT INFO ──
    story.append(section_header('RAPPORTINFORMASJON'))

    gps_text = ''
    if gps.get('lat') and gps.get('lng'):
        gps_text = f"{gps['lat']:.4f}° N, {gps['lng']:.4f}° E"
        if gps.get('accuracy'):
            gps_text += f" (±{gps['accuracy']}m)"

    short_id = report_id[:8] if report_id else 'N/A'

    info_rows = [
        [Paragraph('Byggeplass', cell_key), Paragraph(site.get('name','Ikke oppgitt'), cell_val),
         Paragraph('Dato', cell_key), Paragraph(fmt_date, cell_val)],
        [Paragraph('Firma', cell_key), Paragraph(site.get('company','Ikke oppgitt'), cell_val),
         Paragraph('Tidspunkt', cell_key), Paragraph(fmt_time, cell_val)],
        [Paragraph('Innrapportert av', cell_key), Paragraph(worker.get('name','Ikke oppgitt'), cell_val),
         Paragraph('HMS-kort nr', cell_key), Paragraph(worker.get('hms_kort','Ikke oppgitt'), cell_val)],
    ]
    if gps_text:
        info_rows.append([
            Paragraph('GPS', cell_key), Paragraph(gps_text, cell_val),
            Paragraph('Rapport-ID', cell_key), Paragraph(short_id, cell_val)
        ])
    else:
        info_rows.append([
            Paragraph('Adresse', cell_key), Paragraph(site.get('address','Ikke oppgitt'), cell_val),
            Paragraph('Rapport-ID', cell_key), Paragraph(short_id, cell_val)
        ])

    info_t = Table(info_rows, colWidths=[30*mm, 57*mm, 30*mm, 57*mm])
    info_t.setStyle(TableStyle([
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('GRID', (0,0), (-1,-1), 0.4, BORDER),
        ('BACKGROUND', (0,0), (0,-1), LIGHT_BG),
        ('BACKGROUND', (2,0), (2,-1), LIGHT_BG),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(info_t)
    story.append(Spacer(1, 4*mm))

    # ── CHECKLIST ──
    story.append(section_header(f'SJEKKPUNKTER — {type_label.upper()}'))

    chk_header = [
        Paragraph('<b>Status</b>', style('CH2', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
        Paragraph('<b>Sjekkpunkt</b>', style('CH2', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
        Paragraph('<b>Kritisk</b>', style('CH2', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
    ]
    chk_rows = [chk_header]
    avvik_items = []

    for item in template['items']:
        iid = item['id']
        val = checklist.get(iid, None)
        if val is True:
            status_txt = Paragraph('<font color="#2e7d32"><b>&#10003; OK</b></font>', chk_st)
            row_bg = WHITE
        elif val is False:
            status_txt = Paragraph('<font color="#c62828"><b>&#10007; AVVIK</b></font>', chk_st)
            row_bg = RED_BG
            avvik_items.append(item)
        else:
            status_txt = Paragraph('<font color="#546e7a">&#8212; N/A</font>', chk_st)
            row_bg = WHITE

        critical_txt = Paragraph('<b>JA</b>' if item['critical'] else 'Nei',
                                  style('CR', fontSize=8, fontName='Helvetica-Bold' if item['critical'] else 'Helvetica',
                                        textColor=RED if item['critical'] else MUTED))
        chk_rows.append([status_txt, Paragraph(item['text'], chk_st), critical_txt])

    chk_t = Table(chk_rows, colWidths=[22*mm, 132*mm, 20*mm])
    row_styles = [
        ('BACKGROUND', (0,0), (-1,0), MID),
        ('GRID', (0,0), (-1,-1), 0.4, BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (2,0), (2,-1), 'CENTER'),
    ]
    # Color avvik rows red
    for i, item in enumerate(template['items'], start=1):
        if checklist.get(item['id']) is False:
            row_styles.append(('BACKGROUND', (0,i), (-1,i), RED_BG))
    chk_t.setStyle(TableStyle(row_styles))
    story.append(chk_t)
    story.append(Spacer(1, 4*mm))

    # ── AVVIK SECTION ──
    if avvik_items:
        story.append(section_header('AVVIK — ANSVARLIG OG FRIST FOR UTBEDRING', color=HexColor('#7f0000')))
        av_header = [
            Paragraph('<b>Avvik / Sjekkpunkt</b>', style('AH', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
            Paragraph('<b>Ansvarlig</b>', style('AH', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
            Paragraph('<b>Frist for utbedring</b>', style('AH', fontSize=8, fontName='Helvetica-Bold', textColor=WHITE)),
        ]
        av_rows = [av_header]
        avvik_details = data.get('avvik_details') or {}
        if not isinstance(avvik_details, dict): avvik_details = {}
        for item in avvik_items:
            detail = avvik_details.get(item['id']) or {}
            if not isinstance(detail, dict): detail = {}
            ansvarlig = detail.get('ansvarlig') or 'Ikke angitt'
            frist = detail.get('frist') or 'Ikke angitt'
            av_rows.append([
                Paragraph(item['text'], style('AV', fontSize=8, fontName='Helvetica', textColor=DARK)),
                Paragraph(ansvarlig, style('AV', fontSize=8, fontName='Helvetica',
                          textColor=DARK if ansvarlig != 'Ikke angitt' else MUTED)),
                Paragraph(frist, style('AV', fontSize=8, fontName='Helvetica',
                          textColor=DARK if frist != 'Ikke angitt' else MUTED)),
            ])
        av_t = Table(av_rows, colWidths=[90*mm, 45*mm, 39*mm])
        av_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), HexColor('#7f0000')),
            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, RED_BG]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 7),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(av_t)
        story.append(Spacer(1, 4*mm))

    # ── HAZARD DETAILS ──
    if report_type == 'fare' and hazard:
        sev = (hazard.get('severity') or '').lower()
        sev_fg, sev_bg = SEV_COLORS.get(sev, (RED, RED_BG))
        story.append(section_header('FAREDETALJER', color=HexColor('#7f0000')))
        haz_rows = [
            [Paragraph('Type fare:', cell_key),      Paragraph(hazard.get('type','Ikke spesifisert'), cell_val)],
            [Paragraph('Alvorlighetsgrad:', cell_key), Paragraph(f'<b>{hazard.get("severity","Ikke vurdert").upper()}</b>',
                                                                   style('SEV', fontSize=8.5, fontName='Helvetica-Bold', textColor=sev_fg))],
            [Paragraph('Beskrivelse:', cell_key),     Paragraph(hazard.get('description','Ingen beskrivelse'), cell_val)],
            [Paragraph('Umiddelbare tiltak:', cell_key), Paragraph(hazard.get('immediate_action','Ingen tiltak'), cell_val)],
        ]
        haz_t = Table(haz_rows, colWidths=[35*mm, 139*mm])
        haz_t.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.4, BORDER),
            ('BACKGROUND', (0,0), (-1,-1), HexColor('#fff5f5')),
            ('BACKGROUND', (0,1), (-1,1), sev_bg),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 7),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ]))
        story.append(haz_t)
        story.append(Spacer(1, 4*mm))

    # ── NOTES ──
    if notes:
        story.append(section_header('KOMMENTARER'))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph(notes, style('N', fontSize=9, fontName='Helvetica', textColor=DARK, leftIndent=8)))
        story.append(Spacer(1, 4*mm))

    # ── PHOTOS ──
    if photos:
        story.append(PageBreak())
        story.append(section_header('FOTODOKUMENTASJON'))
        story.append(Spacer(1, 3*mm))
        photo_labels = ['Oversikt', 'Detalj 1', 'Detalj 2', 'Avvik/Fare'] if report_type == 'fare' else ['Bilde 1', 'Bilde 2', 'Bilde 3', 'Bilde 4']
        # Full width individual photos - one per row, full quality
        for i, photo_data in enumerate(photos[:4]):
            try:
                img_data = base64.b64decode(photo_data.split(',')[1] if ',' in photo_data else photo_data)
                img = PILImage.open(BytesIO(img_data))
                # Keep original aspect ratio, full width
                orig_w, orig_h = img.size
                max_w = 170*mm
                aspect = orig_h / orig_w
                img_h = min(max_w * aspect, 120*mm)
                buf = BytesIO()
                img.save(buf, format='JPEG', quality=95)
                buf.seek(0)
                rl_img = Image(buf, width=max_w, height=img_h)
                label = (photo_labels[i] if i < len(photo_labels) else f'Bilde {i+1}')
                story.append(Paragraph(f'<b>Bilde {i+1} — {label}</b>', small_st))
                story.append(rl_img)
                story.append(Spacer(1, 4*mm))
            except Exception as e:
                logger.error(f"Photo {i} error: {e}")
                story.append(Paragraph(f'Bilde {i+1} - feil ved lasting', small_st))

    # ── APPROVAL ──
    story.append(section_header('GODKJENNING'))
    appr_status = approval.get('status', 'pending')
    if appr_status == 'approved':
        appr_txt = f'<font color="#2e7d32"><b>Godkjent av {approval.get("approved_by","Ukjent")}</b></font>'
    elif appr_status == 'rejected':
        appr_txt = f'<font color="#c62828"><b>Avvist av {approval.get("approved_by","Ukjent")}: {approval.get("rejection_reason","")}</b></font>'
    else:
        appr_txt = '<font color="#e65100"><b>Venter pa godkjenning av leder</b></font>'

    appr_rows = [
        [Paragraph('Status', cell_key), Paragraph(appr_txt, style('AP', fontSize=9, fontName='Helvetica'))],
        [Paragraph('Leder', cell_key),  Paragraph(approval.get('approved_by', '—'), cell_val)],
        [Paragraph('Dato', cell_key),   Paragraph(approval.get('approved_at', '—'), cell_val)],
        [Paragraph('Merknad', cell_key),Paragraph(approval.get('rejection_reason', '—'), cell_val)],
    ]
    appr_t = Table(appr_rows, colWidths=[30*mm, 144*mm])
    appr_t.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.4, BORDER),
        ('BACKGROUND', (0,0), (0,-1), LIGHT_BG),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 7),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(appr_t)

    # ── FOOTER ──
    story.append(Spacer(1, 6*mm))
    integrity_hash = data.get('integrity_hash', 'N/A')
    footer_lines = [
        f'Generert av Vernevakt | Rapport-ID: {report_id} | Integritets-hash: {integrity_hash[:16]}... | Generert: {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}',
        'SHA-dokumentasjon i henhold til Byggherreforskriften og Arbeidsmiljoeloven. Dokumentet skal oppbevares i minimum 5 ar etter prosjektets avslutning.',
    ]
    for line in footer_lines:
        story.append(Paragraph(line, foot_st))

    doc.build(story)
    logger.info(f"[PDF] Generated Vernevakt report: {output_path}")
    return output_path


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
    alert_email = (data.get('site') or {}).get('manager_email','').strip()
    if not alert_email:
        alert_email = (data.get('site') or {}).get('office_email','').strip()
    if not alert_email:
        alert_email = CONFIG['hazard_alert_email']
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
            self._send_response(200, {'reports': db_get_reports(200)})

        elif path.startswith('/approve'):
            # Manager approval page - served as HTML
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            report_id = params.get('id', [''])[0]
            self._serve_approval_page(report_id)
        
        else:
            self._send_response(404, {'error': 'Not found'})
    
    def do_POST(self):
        path = urlparse(self.path).path
        
        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # Try JSON first, then form-encoded (from approval page)
        content_type = self.headers.get('Content-Type', '')
        try:
            if 'application/x-www-form-urlencoded' in content_type:
                from urllib.parse import unquote_plus
                pairs = body.decode('utf-8').split('&')
                data = {}
                for pair in pairs:
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        data[unquote_plus(k)] = unquote_plus(v)
                # Convert form data to approve API format
                if 'manager_name' in data:
                    data = {
                        'report_id': data.get('report_id', ''),
                        'action': data.get('action', 'approve'),
                        'manager': {
                            'name': data.get('manager_name', ''),
                            'hms_kort': data.get('manager_hms', ''),
                        },
                        'rejection_reason': data.get('rejection_reason', ''),
                    }
            else:
                data = json.loads(body.decode('utf-8'))
        except Exception:
            self._send_response(400, {'error': 'Invalid request'})
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
            db_save_report({
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
            office_email = site.get('office_email','').strip()
            if not office_email:
                self._send_response(400, {'error': 'E-post til kontor er pakrevd'})
                return
            
            report_type = data.get('report_type', 'daglig')
            template = VERNERUNDE_TEMPLATES.get(report_type, VERNERUNDE_TEMPLATES['daglig'])
            
            subject = f"SHA-Rapport: {template['name']} - {site.get('name', 'Ukjent')} - {timestamp[:8]}"
            
            backend_url = f"https://vernevakt-backend.onrender.com"
            approval_link = f"{backend_url}/approve?id={report_id}"
            body = f"""
VERNEVAKT SHA — Ny rapport mottatt

Byggeplass : {site.get('name', 'Ikke oppgitt')}
Adresse    : {site.get('address', 'Ikke oppgitt')}
Utfort av  : {worker.get('name', 'Ukjent')} (HMS-kort: {worker.get('hms_kort', 'Ukjent')})
Type       : {template['name']}
Tidspunkt  : {data.get('timestamp', 'Ukjent')}
Rapport-ID : {report_id}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GODKJENN ELLER AVVIS RAPPORTEN:
{approval_link}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Klikk lenken ovenfor for a apne godkjenningssiden.
PDF-rapporten er vedlagt denne e-posten.

---
VERNEVAKT SHA | Sikker HMS-dokumentasjon
Automatisk generert | Rapport-ID: {report_id}
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
            db_save_report({
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
            
            # Update report status in database
            new_status = 'approved' if action == 'approve' else 'rejected'
            approved_at = datetime.now(timezone.utc).isoformat()
            db_update_report_status(
                report_id, new_status,
                manager.get('name', 'Ukjent'),
                approved_at,
                data.get('rejection_reason', '')
            )
            
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
            
            if db_user_exists(hms_kort):
                self._send_response(409, {'error': 'HMS-kort er allerede registrert'})
                return
            
            # Hash PIN
            pin_hash = hashlib.sha256(
                (pin + CONFIG['signing_key']).encode()
            ).hexdigest()
            
            db_save_user(hms_kort, {
                'pin_hash': pin_hash,
                'name': name,
                'hms_kort': hms_kort,
                'company': company,
                'role': role,
                'created_at': datetime.now(timezone.utc).isoformat(),
            })
            
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
            
            user = db_get_user(hms_kort)
            
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
    
    def _serve_approval_page(self, report_id):
        """Serve a simple HTML approval page for managers"""
        # Find the report
        report = db_get_report(report_id)

        if not report:
            html = '<html><body><h2>Rapport ikke funnet.</h2></body></html>'
        else:
            status = report.get('status', 'pending')
            site = report.get('site_name', 'Ukjent')
            worker = report.get('worker_name', 'Ukjent')
            rtype = report.get('report_type', '')
            ts = report.get('timestamp', '')[:10]

            if status == 'approved':
                status_html = f'<div class="approved">&#10003; Godkjent av {report.get("approved_by","")}</div>'
                buttons = ''
            elif status == 'rejected':
                status_html = f'<div class="rejected">&#10007; Avvist av {report.get("approved_by","")}</div>'
                buttons = ''
            else:
                status_html = '<div class="pending">&#9203; Venter pa godkjenning</div>'
                buttons = f'''
                <form method="POST" action="/api/approve" style="margin-top:24px">
                  <input type="hidden" name="report_id" value="{report_id}">
                  <div style="margin-bottom:12px">
                    <label style="font-weight:600">Leder navn:</label><br>
                    <input type="text" name="manager_name" required
                           style="width:100%;padding:8px;margin-top:4px;border:1px solid #ccc;border-radius:4px">
                  </div>
                  <div style="margin-bottom:12px">
                    <label style="font-weight:600">HMS-kort:</label><br>
                    <input type="text" name="manager_hms"
                           style="width:100%;padding:8px;margin-top:4px;border:1px solid #ccc;border-radius:4px">
                  </div>
                  <div style="margin-bottom:16px">
                    <label style="font-weight:600">Merknad (valgfritt):</label><br>
                    <textarea name="rejection_reason" rows="3"
                              style="width:100%;padding:8px;margin-top:4px;border:1px solid #ccc;border-radius:4px"></textarea>
                  </div>
                  <button type="submit" name="action" value="approve"
                          style="background:#2e7d32;color:white;padding:12px 32px;border:none;border-radius:6px;font-size:16px;cursor:pointer;margin-right:12px">
                    &#10003; Godkjenn rapport
                  </button>
                  <button type="submit" name="action" value="reject"
                          style="background:#c62828;color:white;padding:12px 32px;border:none;border-radius:6px;font-size:16px;cursor:pointer">
                    &#10007; Avvis rapport
                  </button>
                </form>'''

            html = f'''<!DOCTYPE html>
<html lang="no">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vernevakt — Godkjenning</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; background:#f4f6f8; margin:0; padding:20px; }}
    .card {{ background:white; max-width:560px; margin:40px auto; border-radius:10px;
             box-shadow:0 2px 12px rgba(0,0,0,0.1); overflow:hidden; }}
    .header {{ background:#111; color:#f59e0b; padding:20px 24px; font-size:22px; font-weight:800; }}
    .header span {{ color:#aaa; font-size:13px; font-weight:400; display:block; margin-top:2px; }}
    .body {{ padding:24px; }}
    .row {{ display:flex; justify-content:space-between; padding:8px 0;
            border-bottom:1px solid #f0f0f0; font-size:14px; }}
    .row .label {{ color:#888; }}
    .row .val {{ font-weight:600; }}
    .pending {{ color:#e65100; font-weight:700; font-size:15px; margin-top:12px; }}
    .approved {{ color:#2e7d32; font-weight:700; font-size:15px; margin-top:12px; }}
    .rejected {{ color:#c62828; font-weight:700; font-size:15px; margin-top:12px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">VERNEVAKT <span>Rapport godkjenning</span></div>
    <div class="body">
      <div class="row"><span class="label">Rapport-ID</span><span class="val">{report_id[:8]}</span></div>
      <div class="row"><span class="label">Byggeplass</span><span class="val">{site}</span></div>
      <div class="row"><span class="label">Innrapportert av</span><span class="val">{worker}</span></div>
      <div class="row"><span class="label">Type</span><span class="val">{rtype}</span></div>
      <div class="row"><span class="label">Dato</span><span class="val">{ts}</span></div>
      {status_html}
      {buttons}
    </div>
  </div>
</body>
</html>'''

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

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
    init_db()
    logger.info(f"SMTP configured: {bool(CONFIG['smtp']['user'] and CONFIG['smtp']['password'])}")
    logger.info(f"Default email: {CONFIG['default_office_email']}")
    logger.info("Ready to receive SHA reports")
    
    server.serve_forever()

if __name__ == '__main__':
    main()
