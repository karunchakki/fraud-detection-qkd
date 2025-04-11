# pdf_generator.py
# Generates PDF reports for QKD transaction log entries using reportlab.

import io
from datetime import datetime
import traceback # Import for detailed error printing

# --- ReportLab Imports ---
# Ensure installed: pip install reportlab
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter # Standard US Letter size (8.5x11 inches)
    from reportlab.lib.units import inch      # For easier measurement specification
    from reportlab.lib.colors import navy, red, green, black, gray # For some basic color
    from reportlab.platypus import Paragraph # For potential text wrapping (more advanced)
    from reportlab.lib.styles import getSampleStyleSheet # For Paragraph styles
except ImportError:
    print("\nERROR: 'reportlab' library not found.")
    print("Please install it using: pip install reportlab\n")
    exit()


def create_qkd_report(log_entry_data: dict) -> bytes | None:
    """
    Generates a simple PDF report for a given QKD transaction log entry
    in memory using reportlab. Handles data structure from app.py's get_log_entry_details.

    Args:
        log_entry_data (dict): Data for the specific transaction log entry.

    Returns:
        bytes | None: The generated PDF content as bytes, or None if generation failed.
    """
    log_id = log_entry_data.get('id', 'N/A')
    print(f"Attempting PDF report generation for Log ID: {log_id}")

    buffer = io.BytesIO() # Create an in-memory binary stream

    try:
        # Create the PDF object, using the buffer as its "file."
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter # Get page dimensions (points: 612 x 792)

        # --- Set up drawing coordinates and styles ---
        margin = 1 * inch
        text_x = margin
        line_height = 0.25 * inch # Spacing between lines
        current_y = height - margin # Start 1 inch from the top

        # --- Title ---
        p.setFont("Helvetica-Bold", 16)
        p.setFillColor(navy)
        p.drawString(text_x, current_y, f"Quantum-Secured Transaction Report")
        current_y -= line_height * 1.5 # Extra space after title
        p.setStrokeColorRGB(0.1, 0.1, 0.4) # Navy-like color for line
        p.line(text_x, current_y, width - margin, current_y) # Draw a line across margins
        current_y -= line_height * 1.2

        # --- Transaction Details ---
        p.setFont("Helvetica", 10) # Slightly smaller font for details
        p.setFillColor(black)

        # Prepare details, handle potential None values gracefully
        details = [
            ("Log ID:", str(log_entry_data.get('id', 'N/A'))),
            ("Timestamp:", str(log_entry_data.get('timestamp', 'N/A'))),
            ("Sender:", str(log_entry_data.get('sender', 'N/A'))),
            ("Receiver:", str(log_entry_data.get('receiver', 'N/A'))),
            # Use Indian Rupee symbol if appropriate, else use generic currency or none
            ("Amount:", f"₹ {log_entry_data.get('amount', '0.00')}"), # Format amount
            ("QKD Status:", str(log_entry_data.get('qkd_status', 'N/A'))),
            ("QBER:", str(log_entry_data.get('qber', 'N/A'))),
            ("Decryption Context:", str(log_entry_data.get('decrypted_details', '[Not Available]'))),
        ]

        # Calculate max label width for alignment (optional, simple fixed width used below)
        label_width = 2.0 * inch # Fixed width for labels

        for label, value in details:
            if current_y < margin: # Check if we need a new page (basic check)
                p.showPage()
                p.setFont("Helvetica", 10) # Reset font on new page
                current_y = height - margin

            p.drawString(text_x, current_y, label)
            # Simple drawing for value, consider Paragraph for wrapping long values
            p.drawString(text_x + label_width, current_y, value)
            current_y -= line_height

        # --- Add Encrypted Token (potentially long) ---
        current_y -= line_height * 0.5 # Extra space
        p.setFont("Helvetica-Oblique", 9)
        p.setFillColor(gray) # Use gray for less prominent info

        enc_token_b64 = log_entry_data.get('encrypted_hex', 'N/A') # This is the Fernet token
        p.drawString(text_x, current_y, "Encrypted Token (Base64 - Truncated):")
        current_y -= line_height * 0.7
        # Simple wrap/truncation for long token string
        max_chars_per_line = 75 # Adjust based on font size/margins
        if enc_token_b64 != 'N/A':
            # Display first part, add ellipsis if longer
             display_token = enc_token_b64[:max_chars_per_line] + ('...' if len(enc_token_b64) > max_chars_per_line else '')
             p.drawString(text_x + 0.2*inch, current_y, display_token)
        else:
             p.drawString(text_x + 0.2*inch, current_y, "N/A")
        current_y -= line_height

        # --- Fraud Status ---
        current_y -= line_height # Extra space before fraud info
        p.setFont("Helvetica-Bold", 11)
        is_flagged = log_entry_data.get('is_flagged', False)
        fraud_reason = log_entry_data.get('fraud_reason', None)

        if is_flagged:
            p.setFillColor(red)
            p.drawString(text_x, current_y, "Fraud Alert Status: YES")
            current_y -= line_height
            if fraud_reason:
                p.setFont("Helvetica", 9)
                p.setFillColor(black)
                # Use Paragraph for potential wrapping of long reasons
                styles = getSampleStyleSheet()
                reason_para = Paragraph(f"Reason: {fraud_reason}", styles['Normal'])
                reason_para.wrapOn(p, width - 2*margin - (0.2*inch), line_height) # Calculate available width
                reason_para.drawOn(p, text_x + 0.2*inch, current_y - reason_para.height)
                current_y -= reason_para.height + (line_height * 0.2) # Adjust Y position after drawing paragraph
            else:
                 p.setFont("Helvetica", 9)
                 p.setFillColor(black)
                 p.drawString(text_x + 0.2*inch, current_y, "Reason: Flagged, reason not specified")
                 current_y -= line_height
        else:
            p.setFillColor(green)
            p.drawString(text_x, current_y, "Fraud Alert Status: NO")
            current_y -= line_height

        # --- Footer ---
        p.setFont("Helvetica", 8)
        p.setFillColor(gray)
        footer_text = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Quantum Secure Bank Demo (Log ID: {log_id})"
        p.drawCentredString(width / 2.0, 0.5 * inch, footer_text)

        # Finalize the PDF page and save the buffer content.
        p.showPage()
        p.save()

        # Get the value of the BytesIO buffer and return it.
        pdf_bytes = buffer.getvalue()
        print(f"PDF report generated successfully for Log ID: {log_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except Exception as e:
        print(f"ERROR generating PDF for Log ID {log_id}: {e}")
        traceback.print_exc() # Print full traceback for debugging
        return None # Indicate failure

    finally:
        buffer.close() # Ensure the buffer is closed


# --- Example Usage (for testing directly) ---
if __name__ == '__main__':
    print("--- Testing PDF Generation ---")

    # Updated sample data reflecting potential structure from app.py's helper
    sample_log_success_clean = {
        'id': 101,
        'sender_customer_id': 1, 'receiver_customer_id': 2, # For testing auth logic
        'timestamp': '2023-10-27 10:30:00',
        'sender': 'Alice (Acc: 1)',
        'receiver': 'Bob (Acc: 2)',
        'amount': '150.75',
        'qkd_status': 'SECURED',
        'qber': '0.015',
        'iv_hex': None, # Correctly set to None
        'encrypted_hex': 'gAAAAABlT3xq9r...example_fernet_token...xyz=', # Example Base64 Fernet Token
        'decrypted_details': '[Decryption not performed in PDF context]', # Correct message
        'is_flagged': False,
        'fraud_reason': None
    }

    sample_log_failure_flagged = {
        'id': 102,
        'sender_customer_id': 3, 'receiver_customer_id': 4,
        'timestamp': '2023-10-27 11:05:10',
        'sender': 'Charlie (Acc: 3)',
        'receiver': 'Mallory (Acc: 4)',
        'amount': '25000.00',
        'qkd_status': 'SECURED_FLAGGED', # Example status
        'qber': '0.008',
        'iv_hex': None,
        'encrypted_hex': 'gAAAAABlT4aBcD...another_example_token...abc=',
        'decrypted_details': '[Decryption not performed in PDF context]',
        'is_flagged': True,
        'fraud_reason': 'Amount (25000.00) exceeds threshold (10000.00); Recipient \'Mallory (Acc: 4)\' is blacklisted'
    }

    pdf_bytes_1 = create_qkd_report(sample_log_success_clean)
    if pdf_bytes_1:
        with open("test_report_clean.pdf", "wb") as f:
            f.write(pdf_bytes_1)
        print("Saved test_report_clean.pdf")
    else:
        print("Failed to generate clean report.")

    pdf_bytes_2 = create_qkd_report(sample_log_failure_flagged)
    if pdf_bytes_2:
        with open("test_report_flagged.pdf", "wb") as f:
            f.write(pdf_bytes_2)
        print("Saved test_report_flagged.pdf")
    else:
        print("Failed to generate flagged report.")
