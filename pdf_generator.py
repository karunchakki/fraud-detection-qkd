# pdf_generator.py
# Generates Transaction PDF reports using reportlab Platypus.
# VERSION: Tier 1 - Enhanced Styling and Footer

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib import colors
from io import BytesIO
import datetime
import logging
from decimal import Decimal

# --- Function to generate the PDF report for a transaction log entry ---
# Note: Imported as create_txn_report_pdf in app.py
def create_qkd_report(log_data: dict) -> bytes | None:
    """
    Generates a PDF report for a QKD transaction log entry using Platypus.
    Includes enhanced details and a footer with page numbers.

    Args:
        log_data (dict): Dictionary containing formatted transaction details.

    Returns:
        bytes: The generated PDF content as bytes, or None on error.
    """
    log_id = log_data.get('id', 'N/A')
    logging.info(f"Generating Transaction PDF report for Log ID: {log_id}")
    buffer = None # Initialize buffer
    try:
        buffer = BytesIO()
        # Setup document template with adjusted bottom margin for footer
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=1.0*inch) # Increased bottom margin
        styles = getSampleStyleSheet()
        story = []

        # --- Title ---
        title_style = styles['h1']; title_style.alignment = TA_CENTER
        story.append(Paragraph(f"Transaction Report - Log ID: {log_id}", title_style))
        story.append(Spacer(1, 0.25*inch)) # More space after title

        # --- Transaction Details Table ---
        details_style = styles['BodyText']; details_style.fontSize = 10
        amount_str = f"₹ {log_data.get('amount', '0.00')}"
        try: Decimal(log_data.get('amount', '0.00')) # Validate
        except Exception: amount_str = "₹ N/A"

        details_data = [
            [Paragraph('<b>Timestamp:</b>', details_style), Paragraph(log_data.get('timestamp', 'N/A'), details_style)],
            [Paragraph('<b>Sender:</b>', details_style), Paragraph(log_data.get('sender', 'N/A'), details_style)],
            [Paragraph('<b>Receiver:</b>', details_style), Paragraph(log_data.get('receiver', 'N/A'), details_style)],
            [Paragraph('<b>Amount:</b>', details_style), Paragraph(amount_str, details_style)],
        ]
        details_table = Table(details_data, colWidths=[1.5*inch, 5.5*inch])
        details_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'), # Labels left-aligned
            ('ALIGN', (1, 0), (1, -1), 'LEFT'), # Values left-aligned
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('LINEBELOW', (0, -1), (-1, -1), 0.5, colors.grey), # Line below last item
        ]))
        story.append(details_table)
        story.append(Spacer(1, 0.15*inch))

        # --- Security Details Table ---
        qkd_status_text = str(log_data.get('qkd_status', 'N/A')).replace("_", " ")
        qber_text = str(log_data.get('qber', 'N/A'))
        fraud_flag_text = 'Yes' if log_data.get('is_flagged') else 'No'
        fraud_reason_text = log_data.get('fraud_reason', 'N/A') if log_data.get('is_flagged') else 'N/A'

        security_data = [
            [Paragraph('<b>QKD Status:</b>', details_style), Paragraph(qkd_status_text, details_style)],
            [Paragraph('<b>QBER:</b>', details_style), Paragraph(qber_text, details_style)],
            [Paragraph('<b>Fraud Flagged:</b>', details_style), Paragraph(fraud_flag_text, details_style)],
        ]
        if log_data.get('is_flagged'):
            security_data.append([Paragraph('<b>Flag Reason:</b>', details_style), Paragraph(fraud_reason_text, details_style)])

        security_table = Table(security_data, colWidths=[1.5*inch, 5.5*inch])
        security_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            # Conditional background color for fraud flag status row (index 2)
            ('BACKGROUND', (1, 2), (1, 2), colors.lightpink if log_data.get('is_flagged') else colors.palegreen), # Adjusted colors slightly
            ('TEXTCOLOR', (1, 2), (1, 2), colors.darkred if log_data.get('is_flagged') else colors.darkgreen),
            ('LINEABOVE', (0, 0), (-1, 0), 1, colors.grey), # Line above first item
        ]))
        story.append(security_table)
        story.append(Spacer(1, 0.15*inch))

        # --- Encrypted Confirmation Data ---
        story.append(Paragraph("<b>Encrypted Confirmation (Base64):</b>", styles['h3']))
        encrypted_data = log_data.get('encrypted_hex', None) # Get Base64 data
        if encrypted_data and encrypted_data != 'N/A':
            code_style = styles['Code']
            code_style.wordWrap = 'CJK'; code_style.fontSize = 6; code_style.leading = 8
            # Use Paragraph's built-in wrapping if possible, otherwise split
            wrapped_data_para = Paragraph(encrypted_data, code_style)
            story.append(wrapped_data_para)
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("<i>Note: Encrypted using QKD-derived key.</i>", styles['Italic']))
        else:
             story.append(Paragraph("Not Applicable / Not Available", styles['BodyText']))

        # --- DEFINE FOOTER FUNCTION ---
        def footer_content(canvas, doc):
            """Draws the footer text on each page."""
            canvas.saveState()
            footer_style = styles['Normal']; footer_style.fontSize = 8
            page_num_text = f"Page {doc.page}"; canvas.drawRightString(doc.width + doc.leftMargin*0.9, 0.5*inch, page_num_text)
            canvas.setFont('Times-Roman', 8)
            canvas.drawString(doc.leftMargin, 0.5*inch, f"QSB Transaction Report - Log ID {log_id} - Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
            canvas.restoreState()
        # --- END FOOTER FUNCTION ---

        # Build the document
        doc.build(story, onFirstPage=footer_content, onLaterPages=footer_content)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        logging.info(f"Transaction PDF report generated successfully for Log ID {log_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except Exception as e:
        logging.error(f"Error generating Transaction PDF for log ID {log_id}: {e}", exc_info=True)
        if buffer and not buffer.closed:
             buffer.close()
        return None
