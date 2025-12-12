import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def create_qkd_report(transaction_data):
    """
    Generates a PDF report for a single QKD-secured transaction.
    Existing function logic...
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    # Title
    elements.append(Paragraph("Quantum-Secure Transaction Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # Data Table
    data = [
        ["Transaction ID", str(transaction_data.get('log_id', 'N/A'))],
        ["Timestamp", str(transaction_data.get('timestamp', 'N/A'))],
        ["Sender", str(transaction_data.get('sender_details', 'N/A'))],
        ["Receiver", str(transaction_data.get('receiver_details', 'N/A'))],
        ["Amount", f"₹ {transaction_data.get('amount', '0.00')}"],
        ["QKD Status", str(transaction_data.get('qkd_status', 'UNKNOWN'))],
        ["QBER", f"{float(transaction_data.get('qber_value', 0))*100:.2f}%"],
        ["Fraud Check", "FLAGGED" if transaction_data.get('is_flagged') else "CLEAN"],
        ["Encrypted Receipt", str(transaction_data.get('encrypted_confirmation_data', 'N/A'))[:64] + "..."]
    ]

    t = Table(data, colWidths=[150, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(t)
    
    # Footer
    elements.append(Spacer(1, 24))
    elements.append(Paragraph("This document is cryptographically verifiable via the Quantum Ledger.", styles['Normal']))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

def create_qkd_report_pdf(simulation_log):
    """
    Generates a technical report for the QKD Simulation session (QBER chart, etc).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("QKD Session Technical Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # Content for simulation log
    # (Simplified for fix implementation)
    status = simulation_log.get('status', 'UNKNOWN')
    qber = simulation_log.get('qber', 0)
    
    data = [
        ["Session Status", status],
        ["Measured QBER", f"{qber:.4f} ({qber*100:.2f}%)"],
        ["Key Length", f"{len(simulation_log.get('raw_key_bytes', b'')) * 8} bits"],
        ["Eve Detected", "YES" if simulation_log.get('eve_detected') else "NO"]
    ]

    t = Table(data)
    t.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 1, colors.black)]))
    elements.append(t)

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

# --- ALIAS EXPORT (THE FIX) ---
# app.py expects 'create_transaction_report', so we map it here.
create_transaction_report = create_qkd_report
