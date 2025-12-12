# pdf_generator.py
# Generates Transaction PDF reports using reportlab Platypus.
# VERSION: Minimal changes to use pre-formatted timestamp string.

import io
import datetime
import logging
from decimal import Decimal, InvalidOperation # Keep Decimal import for amount validation if needed
from modules.db_engine import DBEngine

# ReportLab Imports
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib import colors

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] pdf_generator: %(message)s')

# --- Header/Footer Function ---
def _header_footer(canvas, doc):
    """Draws header and footer content on each page of the PDF document."""
    canvas.saveState()
    styles = getSampleStyleSheet()

    # --- Footer ---
    footer_style = styles['Normal']
    footer_style.alignment = TA_CENTER
    footer_style.fontSize = 8
    footer_text = f"QSB Demo Transaction Report - Page {doc.page}"
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.grey)
    canvas.drawCentredString(doc.width/2.0 + doc.leftMargin, 0.5 * inch, footer_text)

    # --- Header ---
    log_id_for_header = getattr(doc, 'log_id_for_header_footer', 'N/A')
    header_text = f"Log ID: {log_id_for_header}"
    # Generation time clearly marked as UTC for clarity
    generation_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(colors.darkgrey)
    canvas.drawString(doc.leftMargin, doc.height + doc.topMargin + 0.3*inch, f"Generated: {generation_time}")
    canvas.drawRightString(doc.width + doc.leftMargin, doc.height + doc.topMargin + 0.3*inch, header_text)
    canvas.setStrokeColor(colors.lightgrey); canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, doc.height + doc.topMargin + 0.25*inch, doc.width + doc.leftMargin, doc.height + doc.topMargin + 0.25*inch)

    canvas.restoreState()

# --- Main PDF Generation Function ---
# Function name matches expected call from app.py
def create_qkd_report(log_data: dict) -> bytes | None:
    """
    Generates an enhanced PDF report for a transaction log entry using Platypus.
    Assumes 'timestamp' and 'amount' in log_data are already localized/formatted strings.

    Args:
        log_data (dict): Dictionary containing formatted transaction details.
                         Expected keys: 'log_id', 'timestamp' (formatted string),
                         'sender_details', 'receiver_details', 'amount' (formatted string),
                         'qkd_status', 'qber', 'is_flagged', 'fraud_reason' (or None),
                         'encrypted_confirmation_data' (or None).

    Returns:
        bytes: The generated PDF content as bytes, or None on error.
    """
    log_id = log_data.get('log_id', 'N/A')
    logging.info(f"Generating Transaction PDF report for Log ID: {log_id}")

    # --- Get PRE-FORMATTED strings directly ---
    timestamp_str = log_data.get('timestamp', 'N/A') # Use string from app.py
    amount_str_pdf = log_data.get('amount', '₹ N/A')  # Use pre-formatted amount string
    sender_details_str = log_data.get('sender_details', 'N/A')
    receiver_details_str = log_data.get('receiver_details', 'N/A')
    qkd_status_text = str(log_data.get('qkd_status', 'N/A')).replace("_", " ")
    qber_text = str(log_data.get('qber', 'N/A'))
    is_flagged = log_data.get('is_flagged', False)
    fraud_flag_text = 'Yes' if is_flagged else 'No'
    fraud_reason_text = log_data.get('fraud_reason') # Will be None if not flagged or no reason
    encrypted_data = log_data.get('encrypted_confirmation_data')

    # Add note if reason is missing but flagged
    if is_flagged and not fraud_reason_text:
         fraud_reason_text = "(Flagged - No specific reason recorded)"
    # --- End getting pre-formatted strings ---

    logging.debug(f"Data for PDF Log {log_id}: Time='{timestamp_str}', Amount='{amount_str_pdf}', Flagged={is_flagged}")

    buffer = io.BytesIO()
    try:
        # --- Document Setup ---
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=1.0*inch, bottomMargin=1.0*inch,
                                title=f"QSB Transaction Report - Log {log_id}")
        setattr(doc, 'log_id_for_header_footer', log_id)

        # --- Styles ---
        styles = getSampleStyleSheet()
        story = []
        title_style = styles['h1']; title_style.alignment = TA_CENTER; title_style.spaceAfter = 6; title_style.fontSize = 16
        subtitle_style = styles['h2']; subtitle_style.fontSize = 12; subtitle_style.alignment = TA_CENTER; subtitle_style.spaceAfter = 18
        section_heading_style = styles['h3']; section_heading_style.fontSize = 11; section_heading_style.fontName = 'Helvetica-Bold'; section_heading_style.spaceAfter = 6
        table_body_style = ParagraphStyle(name='TableBody', parent=styles['BodyText'], fontSize=10)
        table_body_style_bold = ParagraphStyle(name='TableBodyBold', parent=table_body_style, fontName='Helvetica-Bold')
        table_body_style_mono = ParagraphStyle(name='TableBodyMono', parent=table_body_style, fontName='Courier')
        code_style = ParagraphStyle(name='CodeSmall', parent=styles['Code'], fontSize=7, leading=9)
        italic_style = ParagraphStyle(name='ItalicNote', parent=styles['Italic'], fontSize=9)

        # --- PDF Content ---
        story.append(Paragraph("Quantum-Secured Transaction Statement", title_style))
        story.append(Paragraph(f"Log Reference ID: {log_id}", subtitle_style))

        # --- Transaction Details Table ---
        story.append(Paragraph("Transaction Details", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=2, spaceAfter=6))
        details_data = [
            # Use the pre-formatted timestamp string
            [Paragraph('Timestamp:', table_body_style_bold), Paragraph(timestamp_str, table_body_style)],
            [Paragraph('Sender:', table_body_style_bold), Paragraph(sender_details_str, table_body_style)],
            [Paragraph('Receiver:', table_body_style_bold), Paragraph(receiver_details_str, table_body_style)],
            [Paragraph('Amount:', table_body_style_bold), Paragraph(amount_str_pdf, table_body_style_mono)],
        ]
        details_table = Table(details_data, colWidths=[1.75*inch, 5.25*inch])
        details_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'TOP'), ('BOTTOMPADDING', (0,0), (-1,-1), 6), ('TOPPADDING', (0,0), (-1,-1), 2)]))
        story.append(details_table); story.append(Spacer(1, 18))

        # --- Security & Status Table ---
        story.append(Paragraph("Security Status", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=2, spaceAfter=6))

        status_lower = qkd_status_text.lower(); status_color = colors.darkgrey
        if 'secured' in status_lower and 'flagged' not in status_lower: status_color = colors.darkgreen
        elif 'flagged' in status_lower: status_color = colors.darkorange
        elif 'fail' in status_lower or 'error' in status_lower : status_color = colors.red

        qkd_status_style = ParagraphStyle(name='QKDStatusStyle', parent=table_body_style, textColor=status_color, fontName='Helvetica-Bold')
        fraud_flag_style = ParagraphStyle(name='FraudFlagStyle', parent=table_body_style, textColor=(colors.red if is_flagged else colors.darkgreen), fontName='Helvetica-Bold')
        reason_style = ParagraphStyle(name='ReasonStyle', parent=table_body_style, fontSize=9)

        status_data = [
            [Paragraph('QKD Status:', table_body_style_bold), Paragraph(qkd_status_text, qkd_status_style)],
            [Paragraph('QBER:', table_body_style_bold), Paragraph(qber_text, table_body_style_mono)],
            [Paragraph('Fraud Flagged:', table_body_style_bold), Paragraph(fraud_flag_text, fraud_flag_style)],
        ]
        if fraud_reason_text: # Add reason row only if a reason exists
            status_data.append([Paragraph('Flag Reason:', table_body_style_bold), Paragraph(fraud_reason_text, reason_style)])

        status_table = Table(status_data, colWidths=[1.75*inch, 5.25*inch])
        flag_bg_color = colors.Color(255/255, 224/255, 224/255) if is_flagged else colors.Color(224/255, 255/255, 224/255)
        table_style_cmds = [
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6), ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BACKGROUND', (0, 2), (-1, 2), flag_bg_color),
        ]
        if fraud_reason_text: table_style_cmds.append(('SPAN', (1, 3), (1, 3))) # Add SPAN only if row exists
        status_table.setStyle(TableStyle(table_style_cmds))
        story.append(status_table); story.append(Spacer(1, 18))

        # --- Encrypted Confirmation Data ---
        if encrypted_data:
            story.append(Paragraph("Encrypted Confirmation Token", section_heading_style))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=2, spaceAfter=6))
            chunk_size = 85
            wrapped_data = '<br/>'.join(encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size))
            story.append(Paragraph(wrapped_data, code_style))
            story.append(Spacer(1, 6))
            story.append(Paragraph("<i>(Secured using transaction's QKD key)</i>", italic_style))
        else:
             story.append(Paragraph("Encrypted Confirmation Token:", section_heading_style))
             story.append(Paragraph("Not Available / Applicable.", table_body_style))

        # --- Build PDF ---
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)

        pdf_bytes = buffer.getvalue()
        buffer.close()
        logging.info(f"Successfully generated Transaction PDF report bytes for log ID {log_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except Exception as e:
        logging.error(f"CRITICAL Error generating Transaction PDF for log ID {log_id}: {e}", exc_info=True)
        if buffer and not buffer.closed: buffer.close()
        return None
