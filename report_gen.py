from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime, timezone
import os

# Color palette
BLACK = colors.HexColor('#0a0a0a')
DARK = colors.HexColor('#1a1a2e')
ACCENT = colors.HexColor('#00d4aa')
RED = colors.HexColor('#ff4444')
ORANGE = colors.HexColor('#ff8c00')
YELLOW = colors.HexColor('#ffd700')
GREEN = colors.HexColor('#00cc66')
WHITE = colors.white
GRAY = colors.HexColor('#888888')
LIGHT_GRAY = colors.HexColor('#f4f4f4')

SEVERITY_COLORS = {
    'HIGH': RED,
    'CRITICAL': RED,
    'MEDIUM': ORANGE,
    'LOW': YELLOW,
    'INFO': GRAY,
    'SAFE': GREEN,
}

def generate_pdf_report(results, target_url, output_path):
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    
    styles = getSampleStyleSheet()
    story = []

    # ── Header ──────────────────────────────────────────────
    title_style = ParagraphStyle('Title', fontName='Helvetica-Bold', fontSize=24,
                                  textColor=DARK, alignment=TA_LEFT, spaceAfter=4)
    sub_style = ParagraphStyle('Sub', fontName='Helvetica', fontSize=10,
                                textColor=GRAY, alignment=TA_LEFT, spaceAfter=2)
    
    story.append(Paragraph("🔍 BugFinder AI", title_style))
    story.append(Paragraph("Security Vulnerability Assessment Report", sub_style))
    story.append(HRFlowable(width='100%', thickness=2, color=ACCENT, spaceAfter=12))

    # ── Meta Info ───────────────────────────────────────────
    def is_real_vulnerability(bug):
        if not bug or 'error' in bug:
            return False
        if bug.get('title') == 'Scan Error':
            return False
        if bug.get('severity') == 'INFO':
            return False
        return True

    risk = results.get('risk_score', 'Unknown')
    risk_color = SEVERITY_COLORS.get(risk, GRAY)
    vuln_data = results.get('vulnerabilities', {})
    total_bugs = sum(1 for v in vuln_data.values() for bug in v if is_real_vulnerability(bug))
    
    meta_data = [
        ['Target URL', target_url],
        ['Scan Date', results.get('scan_time', datetime.now(timezone.utc).isoformat())[:19].replace('T', ' ')],
        ['Total Bugs Found', str(total_bugs)],
        ['Risk Score', risk],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), DARK),
        ('TEXTCOLOR', (1,3), (1,3), risk_color),
        ('FONTNAME', (1,3), (1,3), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [LIGHT_GRAY, WHITE]),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # ── Summary Stats ────────────────────────────────────────
    vuln_data = results.get('vulnerabilities', {})
    high_count = sum(1 for v in vuln_data.values() for i in v if is_real_vulnerability(i) and i.get('severity') == 'HIGH')
    med_count = sum(1 for v in vuln_data.values() for i in v if is_real_vulnerability(i) and i.get('severity') == 'MEDIUM')
    low_count = sum(1 for v in vuln_data.values() for i in v if is_real_vulnerability(i) and i.get('severity') == 'LOW')

    summary_style = ParagraphStyle('SHead', fontName='Helvetica-Bold', fontSize=14,
                                    textColor=DARK, spaceAfter=8, spaceBefore=12)
    story.append(Paragraph("Executive Summary", summary_style))
    
    stat_data = [
        ['HIGH Risk', 'MEDIUM Risk', 'LOW Risk', 'Total'],
        [str(high_count), str(med_count), str(low_count), str(total_bugs)],
    ]
    stat_table = Table(stat_data, colWidths=[4.25*cm]*4)
    stat_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,0), RED),
        ('TEXTCOLOR', (1,0), (1,0), ORANGE),
        ('TEXTCOLOR', (2,0), (2,0), YELLOW),
        ('TEXTCOLOR', (3,0), (3,0), DARK),
        ('TEXTCOLOR', (0,1), (0,1), RED),
        ('TEXTCOLOR', (1,1), (1,1), ORANGE),
        ('TEXTCOLOR', (2,1), (2,1), colors.HexColor('#b8860b')),
        ('TEXTCOLOR', (3,1), (3,1), DARK),
        ('BACKGROUND', (0,0), (-1,0), LIGHT_GRAY),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#dddddd')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 20))

    # ── Detailed Findings ────────────────────────────────────
    story.append(Paragraph("Detailed Findings", summary_style))
    story.append(HRFlowable(width='100%', thickness=1, color=LIGHT_GRAY, spaceAfter=10))

    category_names = {
        'security_headers': '🔒 Security Headers',
        'ssl_tls': '🔐 SSL / TLS Configuration',
        'info_disclosure': '📂 Information Disclosure',
        'exposed_paths': '🗂 Exposed Paths & Files',
        'xss': '⚠️ Cross-Site Scripting (XSS)',
        'cors': '🌐 CORS Misconfiguration',
    }

    body_style = ParagraphStyle('Body', fontName='Helvetica', fontSize=9,
                                 textColor=colors.HexColor('#333333'), spaceAfter=4)
    bold_style = ParagraphStyle('Bold', fontName='Helvetica-Bold', fontSize=9,
                                 textColor=DARK, spaceAfter=2)
    cat_style = ParagraphStyle('Cat', fontName='Helvetica-Bold', fontSize=12,
                                textColor=DARK, spaceBefore=14, spaceAfter=6)
    fix_style = ParagraphStyle('Fix', fontName='Helvetica-Oblique', fontSize=9,
                                textColor=colors.HexColor('#006633'), spaceAfter=6)

    for cat_key, vulns in vuln_data.items():
        if not vulns:
            continue
        cat_name = category_names.get(cat_key, cat_key.replace('_', ' ').title())
        story.append(Paragraph(cat_name, cat_style))
        
        for i, bug in enumerate(vulns, 1):
            if 'error' in bug:
                continue
            sev = bug.get('severity', 'INFO')
            sev_color = SEVERITY_COLORS.get(sev, GRAY)
            
            # Bug row
            bug_data = [[
                Paragraph(f"<b>#{i} {bug.get('title', 'Unknown')}</b>", bold_style),
                Paragraph(sev, ParagraphStyle('Sev', fontName='Helvetica-Bold', fontSize=9,
                                               textColor=sev_color, alignment=TA_RIGHT))
            ]]
            bug_table = Table(bug_data, colWidths=[14*cm, 3*cm])
            bug_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 2),
                ('LEFTPADDING', (0,0), (0,0), 8),
                ('BACKGROUND', (0,0), (-1,-1), LIGHT_GRAY),
            ]))
            story.append(bug_table)
            story.append(Paragraph(f"<b>Description:</b> {bug.get('description', '')}", body_style))
            story.append(Paragraph(f"✅ Fix: {bug.get('fix', '')}", fix_style))
            story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#eeeeee'), spaceAfter=4))

    # ── Footer ───────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width='100%', thickness=1, color=ACCENT, spaceBefore=10, spaceAfter=6))
    footer_style = ParagraphStyle('Footer', fontName='Helvetica', fontSize=8,
                                   textColor=GRAY, alignment=TA_CENTER)
    story.append(Paragraph(
        f"Report generated by BugFinder AI • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC • "
        f"For educational & authorized testing only", footer_style))

    doc.build(story)
    return output_path
