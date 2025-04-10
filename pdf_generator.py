# pdf_generator.py
# Generates PDF reports for QKD transaction log entries using reportlab.

import io
from datetime import datetime

# --- ReportLab Imports ---
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter # Standard US Letter size (8.5x11 inches)
from reportlab.lib.units import inch      # For easier measurement specification
from reportlab.lib.colors import navy, red, green, black # For some basic color

def create_qkd_report(log_entry_data: dict) -> bytes | None:
    """
    Generates a simple PDF report for a given QKD transaction log entry
    in memory using reportlab.

    Args:
        log_entry_data (dict): Data for the specific transaction log entry.
                               Expected keys match those used in app.py history route.

    Returns:
        bytes | None: The generated PDF content as bytes, or None if generation failed.
    """
    log_id = log_entry_data.get('id', 'N/A')
    print(f"Attempting PDF report generation for Log ID: {log_id}")

    buffer = io.BytesIO() # Create an in-memory binary stream

    try:
        # Create the PDF object, using the buffer as its "file."
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter # Get page dimensions (points)

        # --- Set up drawing coordinates and styles ---
        text_x = 1 * inch       # Left margin
        line_height = 0.25 * inch # Spacing between lines
        current_y = height - 1 * inch # Start 1 inch from the top

        # --- Title ---
        p.setFont("Helvetica-Bold", 16)
        p.setFillColor(navy)
        p.drawString(text_x, current_y, f"Quantum-Secured Transaction Report")
        current_y -= line_height * 1.5 # Extra space after title
        p.setStrokeColorRGB(0.1, 0.1, 0.4) # Navy-like color for line
        p.line(text_x, current_y, width - text_x, current_y) # Draw a line
        current_y -= line_height * 1.2

        # --- Transaction Details ---
        p.setFont("Helvetica", 11)
        p.setFillColor(black)

        details = [
            ("Log ID:", log_entry_data.get('id', 'N/A')),
            ("Timestamp:", log_entry_data.get('timestamp', 'N/A')),
            ("Sender:", log_entry_data.get('sender', 'N/A')),
            ("Receiver:", log_entry_data.get('receiver', 'N/A')),
            ("Amount:", f"${log_entry_data.get('amount', '0.00')}"), # Format amount
            ("QKD Status:", log_entry_data.get('qkd_status', 'N/A')),
            ("QBER:", log_entry_data.get('qber', 'N/A')),
            # ("IV (Hex):", log_entry_data.get('iv_hex', 'N/A')), # Can be long
            # ("Encrypted Confirmation (Hex):", log_entry_data.get('encrypted_hex', 'N/A')), # Often too long
            ("Decrypted Details:", log_entry_data.get('decrypted_details', '[Not Available]')), # Show decrypted if possible
        ]

        for label, value in details:
            if current_y < 1 * inch: # Check if we need a new page (basic check)
                p.showPage()
                p.setFont("Helvetica", 11) # Reset font on new page
                current_y = height - 1 * inch

            p.drawString(text_x, current_y, f"{label:<25} {str(value)}") # Basic alignment
            current_y -= line_height

        # --- Add longer fields with potential wrapping (manual example) ---
        current_y -= line_height * 0.5 # Extra space
        p.setFont("Helvetica-Oblique", 9)

        iv_hex = log_entry_data.get('iv_hex', 'N/A')
        p.drawString(text_x, current_y, "IV (Hex):")
        current_y -= line_height * 0.7
        # Simple wrap for long hex string
        max_chars_per_line = 80
        for i in range(0, len(iv_hex), max_chars_per_line):
             p.drawString(text_x + 0.2*inch, current_y, iv_hex[i:i+max_chars_per_line])
             current_y -= line_height * 0.6
             if current_y < 1*inch: p.showPage(); current_y = height - 1 * inch # basic pagination

        current_y -= line_height * 0.5 # Extra space

        enc_hex = log_entry_data.get('encrypted_hex', 'N/A')
        p.drawString(text_x, current_y, "Encrypted Data (Hex - Truncated):")
        current_y -= line_height * 0.7
        p.drawString(text_x + 0.2*inch, current_y, enc_hex[:max_chars_per_line] + ('...' if len(enc_hex) > max_chars_per_line else ''))
        current_y -= line_height

        # --- Fraud Status ---
        current_y -= line_height # Extra space before fraud info
        p.setFont("Helvetica-Bold", 12)
        is_flagged = log_entry_data.get('is_flagged', False)
        fraud_reason = log_entry_data.get('fraud_reason', None)

        if is_flagged:
            p.setFillColor(red)
            p.drawString(text_x, current_y, "Fraud Alert: YES")
            current_y -= line_height
            p.setFont("Helvetica", 10)
            p.setFillColor(black)
            p.drawString(text_x + 0.2*inch, current_y, f"Reason: {fraud_reason if fraud_reason else 'Flagged, reason not specified'}")
        else:
            p.setFillColor(green)
            p.drawString(text_x, current_y, "Fraud Alert: NO")

        # --- Footer (Example) ---
        p.setFont("Helvetica", 8)
        p.setFillColor(black)
        footer_text = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Quantum Secure Bank Demo"
        p.drawCentredString(width / 2.0, 0.5 * inch, footer_text)

        # Close the PDF object cleanly.
        p.showPage()
        p.save()

        # Get the value of the BytesIO buffer and return it.
        pdf_bytes = buffer.getvalue()
        print(f"PDF report generated successfully for Log ID: {log_id} ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    except Exception as e:
        print(f"Error generating PDF for Log ID {log_id}: {e}")
        import traceback
        traceback.print_exc() # Print full traceback for debugging
        return None # Indicate failure

    finally:
        buffer.close() # Ensure the buffer is closed in all cases


# --- Example Usage (for testing directly) ---
if __name__ == '__main__':
    print("--- Testing PDF Generation ---")

    sample_log_success_clean = {
        'id': 101,
        'timestamp': '2023-10-27 10:30:00',
        'sender': 'Alice (Acc: 1)',
        'receiver': 'Bob (Acc: 2)',
        'amount': '150.75',
        'qkd_status': 'SECURED',
        'qber': '0.015',
        'iv_hex': 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', # Long example
        'encrypted_hex': 'f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5', # Long example
        'decrypted_details': 'CONFIRMED;FROM:1;TO:2;AMT:150.75;TIME:2023-10-27 10:29:55;QBER:0.0150',
        'is_flagged': False,
        'fraud_reason': None
    }

    sample_log_failure_flagged = {
        'id': 102,
        'timestamp': '2023-10-27 11:05:10',
        'sender': 'Charlie (Acc: 3)',
        'receiver': 'Mallory (Acc: 4)',
        'amount': '25000.00',
        'qkd_status': 'SECURED_FLAGGED', # Or potentially VALIDATION_FAIL etc.
        'qber': '0.008',
        'iv_hex': '11223344556677881122334455667788',
        'encrypted_hex': 'aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011',
        'decrypted_details': '[Encrypted - Key Unavailable/Expired]', # Example if key missing
        'is_flagged': True,
        'fraud_reason': 'Amount (25000.00) exceeds threshold (10000.00); Recipient \'Mallory\' is blacklisted'
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
