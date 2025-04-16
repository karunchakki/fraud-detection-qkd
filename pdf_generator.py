# pdf_generator.py
# Generates Transaction PDF reports using reportlab Platypus.
# VERSION: Enhanced layout, styling, conditional content, corrected keys, added Rupee symbol.

import io
import datetime
import logging
from decimal import Decimal, InvalidOperation # Import Decimal and InvalidOperation for validation

# ReportLab Imports
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib import colors

# Configure logging (ensure level is appropriate for debugging/production)
# logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s')
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
    # Safely get log_id attribute that was added to the doc object
    log_id_for_header = getattr(doc, 'log_id_for_header_footer', 'N/A')
    header_text = f"Log ID: {log_id_for_header}"
    generation_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC") # Use UTC or local timezone consistently

    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(colors.darkgrey) # Slightly darker grey for header text

    # Draw generation time on the left
    canvas.drawString(doc.leftMargin, doc.height + doc.topMargin + 0.3*inch, f"Generated: {generation_time}")

    # Draw Log ID on the right
    canvas.drawRightString(doc.width + doc.leftMargin, doc.height + doc.topMargin + 0.3*inch, header_text)

    # Draw horizontal line below header info
    canvas.setStrokeColor(colors.lightgrey) # Lighter line
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, doc.height + doc.topMargin + 0.25*inch, doc.width + doc.leftMargin, doc.height + doc.topMargin + 0.25*inch)

    canvas.restoreState()

# --- Main PDF Generation Function ---
# Function name matches expected call from app.py
def create_qkd_report(log_data: dict) -> bytes | None:
    """
    Generates an enhanced PDF report for a transaction log entry using Platypus.

    Args:
        log_data (dict): Dictionary containing formatted transaction details.
                         Expected keys: 'log_id', 'timestamp', 'sender_details',
                         'receiver_details', 'amount', 'qkd_status', 'qber',
                         'is_flagged', 'fraud_reason', 'encrypted_confirmation_data'.

    Returns:
        bytes: The generated PDF content as bytes, or None on error.
    """
    # --- Safely Get Data ---
    # Use the correct 'log_id' key provided by get_log_entry_details
    log_id = log_data.get('log_id', 'N/A')
    logging.info(f"Generating Transaction PDF report for Log ID: {log_id}")
    logging.debug(f"Input log_data: {log_data}") # Log input data for debugging if needed

    buffer = io.BytesIO() # Create PDF in memory buffer
    try:
        # --- Document Setup ---
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=1.0*inch, bottomMargin=1.0*inch,
                                title=f"QSB Transaction Report - Log {log_id}") # Set PDF title metadata

        # Add log_id as an attribute to the doc object for header/footer access
        setattr(doc, 'log_id_for_header_footer', log_id)

        # --- Styles ---
        styles = getSampleStyleSheet()
        story = [] # List to hold Platypus Flowables

        # Customize styles
        title_style = styles['h1']
        title_style.alignment = TA_CENTER
        title_style.spaceAfter = 6
        title_style.fontSize = 16 # Slightly larger title

        subtitle_style = styles['h2']
        subtitle_style.fontSize = 12
        subtitle_style.alignment = TA_CENTER
        subtitle_style.spaceAfter = 18

        section_heading_style = styles['h3']
        section_heading_style.fontSize = 11
        section_heading_style.fontName = 'Helvetica-Bold' # Make section headings bold
        section_heading_style.spaceAfter = 6

        # Base styles for table content
        table_body_style = ParagraphStyle(name='TableBody', parent=styles['BodyText'], fontSize=10)
        # Clone and modify for bold labels
        table_body_style_bold = ParagraphStyle(name='TableBodyBold', parent=table_body_style, fontName='Helvetica-Bold')
        # Clone and modify for monospaced values (like QBER, Amount)
        table_body_style_mono = ParagraphStyle(name='TableBodyMono', parent=table_body_style, fontName='Courier')
        # Style for small code/encrypted data
        code_style = ParagraphStyle(name='CodeSmall', parent=styles['Code'], fontSize=7, leading=9)
        # Italic style for notes
        italic_style = ParagraphStyle(name='ItalicNote', parent=styles['Italic'], fontSize=9)

        # --- PDF Content ---
        # Report Title
        story.append(Paragraph("Quantum-Secured Transaction Statement", title_style))
        story.append(Paragraph(f"Log Reference ID: {log_id}", subtitle_style))

        # --- Transaction Details Table ---
        story.append(Paragraph("Transaction Details", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=2, spaceAfter=6)) # Separator

        # Safely format amount WITH RUPEE SYMBOL
        amount_str = "₹ N/A" # Default value
        try:
            amount_val = log_data.get('amount', '0.00') # Get raw amount string/decimal
            amount_decimal = Decimal(amount_val) # Convert to Decimal
            amount_str = f"₹ {amount_decimal:,.2f}" # Format with comma for thousands and ₹
        except (InvalidOperation, TypeError, ValueError) as amount_err: # Catch potential errors
            logging.warning(f"Invalid amount format in log data for {log_id}: '{amount_val}' - Error: {amount_err}")
            # Keep amount_str as "₹ N/A"

        details_data = [
            [Paragraph('Timestamp:', table_body_style_bold), Paragraph(log_data.get('timestamp', 'N/A'), table_body_style)],
            # Use corrected keys: 'sender_details' and 'receiver_details'
            [Paragraph('Sender:', table_body_style_bold), Paragraph(log_data.get('sender_details', 'N/A'), table_body_style)],
            [Paragraph('Receiver:', table_body_style_bold), Paragraph(log_data.get('receiver_details', 'N/A'), table_body_style)],
            # Use the updated amount_str which includes ₹
            [Paragraph('Amount:', table_body_style_bold), Paragraph(amount_str, table_body_style_mono)], # Use mono for amount
        ]
        details_table = Table(details_data, colWidths=[1.75*inch, 5.25*inch])
        details_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),      # Labels left-aligned
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),      # Values left-aligned
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),    # Adjusted padding
            ('TOPPADDING', (0,0), (-1,-1), 2),
            # ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey), # Optional: Add grid lines for debugging layout
        ]))
        story.append(details_table)
        story.append(Spacer(1, 18)) # Space after table

        # --- Security & Status Table ---
        story.append(Paragraph("Security Status", section_heading_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=2, spaceAfter=6)) # Separator

        qkd_status_text = str(log_data.get('qkd_status', 'N/A')).replace("_", " ")
        qber_text = str(log_data.get('qber', 'N/A'))
        is_flagged = log_data.get('is_flagged', False)
        fraud_flag_text = 'Yes' if is_flagged else 'No'
        # Default to '--' if flagged but reason is missing/empty
        fraud_reason_text = log_data.get('fraud_reason') if is_flagged else '--'
        if is_flagged and not fraud_reason_text: # If flagged but reason is None or empty string
             fraud_reason_text = "(Flagged - No specific reason recorded)"


        # Determine status color based on text content
        status_color = colors.darkgrey # Default color
        status_lower = qkd_status_text.lower()
        if 'secured' in status_lower and 'flagged' not in status_lower: status_color = colors.darkgreen
        elif 'flagged' in status_lower: status_color = colors.darkorange # Use darkorange for flagged
        elif 'fail' in status_lower or 'exceeded' in status_lower or 'error' in status_lower or 'invalid' in status_lower: status_color = colors.red

        # Create specific paragraph styles with dynamic colors
        qkd_status_style = ParagraphStyle(name='QKDStatusStyle', parent=table_body_style, textColor=status_color, fontName='Helvetica-Bold')
        fraud_flag_style = ParagraphStyle(name='FraudFlagStyle', parent=table_body_style, textColor=(colors.red if is_flagged else colors.darkgreen), fontName='Helvetica-Bold')
        reason_style = ParagraphStyle(name='ReasonStyle', parent=table_body_style, fontSize=9) # Smaller font for reason

        status_data = [
            [Paragraph('QKD Status:', table_body_style_bold), Paragraph(qkd_status_text, qkd_status_style)],
            [Paragraph('QBER:', table_body_style_bold), Paragraph(qber_text, table_body_style_mono)],
            [Paragraph('Fraud Flagged:', table_body_style_bold), Paragraph(fraud_flag_text, fraud_flag_style)],
        ]
        if is_flagged:
             # Add reason row only if flagged
            status_data.append([Paragraph('Flag Reason:', table_body_style_bold), Paragraph(fraud_reason_text, reason_style)])

        status_table = Table(status_data, colWidths=[1.75*inch, 5.25*inch])
        status_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6), # Adjusted padding
            ('TOPPADDING', (0,0), (-1,-1), 2),
            # ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey), # Optional: Add grid lines
            # Conditional background highlight for the 'Fraud Flagged' row (index 2)
            # Use lighter colors for background
            ('BACKGROUND', (0, 2), (-1, 2), colors.Color(255/255, 224/255, 224/255) if is_flagged else colors.Color(224/255, 255/255, 224/255)), # Light Pink / Light Green
             # Span the reason text across the value column if it exists (row index 3)
            ('SPAN', (1, 3), (1, 3)), # Ensures reason uses full width if present
        ]))
        story.append(status_table)
        story.append(Spacer(1, 18)) # Space after table

        # --- Encrypted Confirmation Data ---
        # Use corrected key: 'encrypted_confirmation_data'
        encrypted_data = log_data.get('encrypted_confirmation_data', None)

        # Check more carefully if data exists and is not placeholder/None string
        if encrypted_data and encrypted_data not in ['N/A', 'None', None]:
            story.append(Paragraph("Encrypted Confirmation Token", section_heading_style))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceBefore=2, spaceAfter=6)) # Separator

            # Wrap long encrypted string
            chunk_size = 85 # Characters per line
            wrapped_data = '<br/>'.join(encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size))
            story.append(Paragraph(wrapped_data, code_style))
            story.append(Spacer(1, 6))
            story.append(Paragraph("<i>(This data is secured using the transaction's unique QKD-derived key)</i>", italic_style))
        else:
             story.append(Paragraph("Encrypted Confirmation Token:", section_heading_style))
             story.append(Paragraph("Not Available / Applicable for this transaction type.", table_body_style))


        # --- Build PDF ---
        # Build the document using the story list and add header/footer to each page
        doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)

        # --- Get PDF Bytes ---
        pdf_bytes = buffer.getvalue()
        buffer.close()
        logging.info(f"Successfully generated Transaction PDF report bytes for log ID {log_id}")
        return pdf_bytes

    except Exception as e:
        # Log any error during PDF generation
        logging.error(f"CRITICAL Error generating Transaction PDF for log ID {log_id}: {e}", exc_info=True)
        if buffer: # Ensure buffer is closed even on error
             try: buffer.close()
             except Exception: pass # Ignore errors during close on error
        return None # Return None to indicate failure
