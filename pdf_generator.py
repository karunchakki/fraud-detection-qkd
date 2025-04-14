# pdf_generator.py
# Generates PDF reports for QKD transaction log entries using reportlab Platypus.

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib import colors
from io import BytesIO
import datetime
import logging
from decimal import Decimal # Import Decimal for formatting check

def create_qkd_report(log_data: dict) -> bytes | None:
    """
    Generates a PDF report for a QKD transaction log entry using Platypus.

    Args:
        log_data (dict): Dictionary containing formatted transaction details.
                         Expected keys: 'id', 'timestamp', 'sender', 'receiver',
                         'amount', 'qkd_status', 'qber', 'encrypted_hex',
                         'is_flagged', 'fraud_reason'.

    Returns:
        bytes: The generated PDF content as bytes, or None on error.
    """
    log_id = log_data.get('id', 'N/A')
    logging.info(f"Generating PDF report for Log ID: {log_id}")
    try:
        buffer = BytesIO()
        # Setup document template
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []

        # --- Title ---
        title_style = styles['h1']
        title_style.alignment = TA_CENTER
        title_text = f"Quantum-Secured Transaction Report"
        story.append(Paragraph(title_text, title_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"Log ID: {log_id}", styles['h2']))
        story.append(Spacer(1, 18))

        # --- Transaction Details Table ---
        details_style = styles['BodyText']
        details_style.fontSize = 10
        # Ensure amount is formatted correctly with currency
        amount_str = f"₹ {log_data.get('amount', '0.00')}"
        try:
            # Validate amount format if needed
            Decimal(log_data.get('amount', '0.00'))
        except Exception:
            amount_str = "₹ N/A" # Fallback if amount is invalid

        details_data = [
            [Paragraph('<b>Timestamp:</b>', details_style), Paragraph(log_data.get('timestamp', 'N/A'), details_style)],
            [Paragraph('<b>Sender:</b>', details_style), Paragraph(log_data.get('sender', 'N/A'), details_style)],
            [Paragraph('<b>Receiver:</b>', details_style), Paragraph(log_data.get('receiver', 'N/A'), details_style)],
            [Paragraph('<b>Amount:</b>', details_style), Paragraph(amount_str, details_style)],
        ]
        details_table = Table(details_data, colWidths=[1.5*inch, 5.5*inch])
        details_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        story.append(details_table)
        story.append(Spacer(1, 12))

        # --- Security Details Table ---
        qkd_status_text = str(log_data.get('qkd_status', 'N/A')).replace("_", " ")
        qber_text = str(log_data.get('qber', 'N/A'))
        fraud_flag_text = 'Yes' if log_data.get('is_flagged') else 'No'
        fraud_reason_text = log_data.get('fraud_reason') if log_data.get('is_flagged') else 'N/A'

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
            ('TOPPADDING', (0,0), (-1,-1), 0),
            # Conditional background color for fraud flag status
            ('BACKGROUND', (1, 2), (1, 2), colors.pink if log_data.get('is_flagged') else colors.lightgreen),
            ('TEXTCOLOR', (1, 2), (1, 2), colors.darkred if log_data.get('is_flagged') else colors.darkgreen),
        ]))
        story.append(security_table)
        story.append(Spacer(1, 12))

        # --- Encrypted Confirmation Data ---
        encrypted_data = log_data.get('encrypted_hex', 'N/A')
        if encrypted_data != 'N/A' and encrypted_data:
            story.append(Paragraph("<b>Encrypted Confirmation (Base64):</b>", styles['h3']))
            # Use a Code style for monospace and wrapping
            code_style = styles['Code']
            code_style.wordWrap = 'CJK' # Helps break long strings without spaces
            code_style.fontSize = 7 # Smaller font for dense data
            code_style.leading = 9 # Adjust line spacing
            # Break long string manually into chunks for better wrapping in Paragraph
            chunk_size = 90
            wrapped_data = '<br/>'.join(encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size))
            story.append(Paragraph(wrapped_data, code_style))
            story.append(Spacer(1, 6))
            story.append(Paragraph("<i>Note: This data is encrypted using a key derived from the QKD session.</i>", styles['Italic']))
        else:
             story.append(Paragraph("<b>Encrypted Confirmation:</b> Not Applicable / Not Available", styles['h3']))


        # --- Footer ---
        # Placeholder for footer content drawn on each page by the template
        def footer(canvas, doc):
            canvas.saveState()
            footer_style = styles['Normal']
            footer_style.alignment = TA_CENTER
            footer_style.fontSize = 8
            footer_text = f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - QSB Demo - Log ID: {log_id} - Page %d" % doc.page
            canvas.drawString(doc.leftMargin, 0.5*inch, footer_text)
            canvas.restoreState()

        # Build the document
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        logging.info(f"Successfully generated PDF report for log ID {log_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except Exception as e:
        logging.error(f"Error generating PDF for log ID {log_id}: {e}", exc_info=True)
        return None

# Import required for Platypus measurements
from reportlab.lib.units import inch
