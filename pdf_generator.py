# pdf_generator.py
# Generates Transaction PDF reports using reportlab Platypus.

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib import colors
from io import BytesIO
import datetime
import logging
from decimal import Decimal # Import Decimal for formatting check

# --- Renamed in app.py import as create_txn_report_pdf ---
def create_qkd_report(log_data: dict) -> bytes | None:
    """
    Generates a PDF report for a QKD transaction log entry using Platypus.
    Includes enhanced details and a footer with page numbers.

    Args:
        log_data (dict): Dictionary containing formatted transaction details.
                         Expected keys: 'id', 'timestamp', 'sender', 'receiver',
                         'amount', 'qkd_status', 'qber', 'encrypted_hex',
                         'is_flagged', 'fraud_reason'.

    Returns:
        bytes: The generated PDF content as bytes, or None on error.
    """
    log_id = log_data.get('id', 'N/A')
    logging.info(f"Generating Transaction PDF report for Log ID: {log_id}")
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
        story.append(Spacer(1, 18)) # More space after title

        # --- Transaction Details Table ---
        details_style = styles['BodyText']; details_style.fontSize = 10
        # Ensure amount is formatted correctly with currency symbol
        amount_str = f"₹ {log_data.get('amount', '0.00')}"
        try:
            Decimal(log_data.get('amount', '0.00')) # Validate it's a number
        except Exception:
            amount_str = "₹ N/A" # Fallback

        # Make sure all expected keys are present in log_data from get_log_entry_details
        details_data = [
            [Paragraph('<b>Timestamp:</b>', details_style), Paragraph(log_data.get('timestamp', 'N/A'), details_style)],
            [Paragraph('<b>Sender:</b>', details_style), Paragraph(log_data.get('sender', 'N/A'), details_style)],
            [Paragraph('<b>Receiver:</b>', details_style), Paragraph(log_data.get('receiver', 'N/A'), details_style)],
            [Paragraph('<b>Amount:</b>', details_style), Paragraph(amount_str, details_style)],
        ]
        details_table = Table(details_data, colWidths=[1.5*inch, 5.5*inch]) # Adjusted colWidths if needed
        details_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'), # Labels left-aligned
            ('ALIGN', (1, 0), (1, -1), 'LEFT'), # Values left-aligned
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 2), # Reduced top padding slightly
            ('LINEBELOW', (0, -1), (-1, -1), 1, colors.grey), # Line below last item
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
            # Use Paragraph for potentially long reasons
            security_data.append([Paragraph('<b>Flag Reason:</b>', details_style), Paragraph(fraud_reason_text, details_style)])

        security_table = Table(security_data, colWidths=[1.5*inch, 5.5*inch])
        security_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            # Conditional background color for fraud flag status row (index 2)
            ('BACKGROUND', (1, 2), (1, 2), colors.lightpink if log_data.get('is_flagged') else colors.lightgreen),
            ('TEXTCOLOR', (1, 2), (1, 2), colors.darkred if log_data.get('is_flagged') else colors.darkgreen),
            # Apply grid or lines if desired
            # ('BOX', (0,0), (-1,-1), 1, colors.black),
            # ('INNERGRID', (0,0), (-1,-1), 0.25, colors.grey),
        ]))
        story.append(security_table)
        story.append(Spacer(1, 12))

        # --- Encrypted Confirmation Data ---
        encrypted_data = log_data.get('encrypted_hex', 'N/A') # Should be base64
        if encrypted_data and encrypted_data != 'N/A':
            story.append(Paragraph("<b>Encrypted Confirmation (Base64):</b>", styles['h3']))
            code_style = styles['Code']
            code_style.wordWrap = 'CJK'
            code_style.fontSize = 6 # Make smaller for long data
            code_style.leading = 8
            # Simple splitting for display (might not be perfect wrap in PDF)
            wrapped_data = '<br/>'.join([encrypted_data[i:i+100] for i in range(0, len(encrypted_data), 100)])
            story.append(Paragraph(wrapped_data, code_style))
            story.append(Spacer(1, 6))
            story.append(Paragraph("<i>Note: This data is encrypted using a key derived from the QKD session.</i>", styles['Italic']))
        else:
             story.append(Paragraph("<b>Encrypted Confirmation:</b> Not Applicable / Not Available", styles['h3']))


        # --- DEFINE FOOTER FUNCTION ---
        def footer_content(canvas, doc):
            """Draws the footer text on each page."""
            canvas.saveState()
            footer_style = styles['Normal']
            footer_style.fontSize = 8
            # Page number
            page_num_text = f"Page {doc.page}"
            canvas.drawRightString(doc.width + doc.leftMargin, 0.5*inch, page_num_text)
            # Report Info
            canvas.setFont('Times-Roman', 8)
            canvas.drawString(doc.leftMargin, 0.5*inch, f"QSB Transaction Report - Log ID {log_id} - Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
            canvas.restoreState()
        # --- END FOOTER FUNCTION ---

        # Build the document, applying the footer function to each page
        doc.build(story, onFirstPage=footer_content, onLaterPages=footer_content)

        pdf_bytes = buffer.getvalue()
        buffer.close()
        logging.info(f"Successfully generated Transaction PDF report for log ID {log_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except Exception as e:
        logging.error(f"Error generating Transaction PDF for log ID {log_id}: {e}", exc_info=True)
        if 'buffer' in locals() and not buffer.closed:
             buffer.close()
        return None

# Required for measurements inside the function
from reportlab.lib.units import inch
