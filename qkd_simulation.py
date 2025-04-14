# qkd_simulation.py
# This module simulates the BB84 Quantum Key Distribution protocol using Qiskit.
# Includes options for Eve simulation, QBER calculation, and PDF report generation for the simulation details.

# --- Ensure necessary libraries are installed: pip install qiskit-aer numpy reportlab ---

# --- Core Qiskit & Simulation Imports ---
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
import random
import numpy as np
import math
import logging # Use logging for simulation messages

# --- PDF Generation Imports (ReportLab) ---
import datetime # For timestamp in PDF
import io # For creating PDF in memory
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    logging.warning("\n'reportlab' library not found. PDF report generation for QKD simulation will be disabled.")
    logging.warning("Install using: pip install reportlab\n")
    REPORTLAB_AVAILABLE = False


# --- Constants ---
DEFAULT_QBER_SAMPLE_FRACTION = 0.5
MIN_SIFTED_FOR_QBER = 10
MIN_FINAL_KEY_LENGTH = 16 # Needs enough bits for a symmetric key (e.g., 128 bits for AES)

# --- BB84 Simulation Function ---
def simulate_bb84(n_qubits=600, simulate_eve=False, qber_threshold=0.15, eve_interception_rate=0.25):
    """
    Simulates the BB84 protocol, optionally with Eve and QBER check.

    Args:
        n_qubits (int): Number of initial qubits Alice prepares.
        simulate_eve (bool): If True, simulates Eve introducing errors.
        qber_threshold (float): Max acceptable QBER before flagging Eve.
        eve_interception_rate (float): Probability Eve's action causes an error per qubit.

    Returns:
        dict: A dictionary containing simulation results:
              'final_key_binary': str | None, 'qber': float (-1,-2,-3 for errors),
              'eve_detected': bool, 'initial_qubits': int, 'sifted_indices_count': int,
              'qber_sample_count': int, 'qber_disagreements': int, 'final_key_length': int,
              'alice_bits': list (sample), 'alice_bases': list (sample), 'bob_bases': list (sample),
              'bob_measurement_results': list (sample), 'sifted_key_sample': str (sample),
              'eve_simulated': bool, 'eve_error_rate_used': float, 'eve_errors_introduced': int,
              'qber_threshold_used': float
    """
    # Initialize result dictionary structure
    result_dict = {
        'final_key_binary': None, 'qber': -1.0, 'eve_detected': False,
        'initial_qubits': n_qubits, 'sifted_indices_count': 0,
        'qber_sample_count': 0, 'qber_disagreements': 0, 'final_key_length': 0,
        'alice_bits': [], 'alice_bases': [], 'bob_bases': [],
        'bob_measurement_results': [], 'sifted_key_sample': "",
        'eve_simulated': simulate_eve, 'eve_error_rate_used': 0.0, 'eve_errors_introduced': 0,
        'qber_threshold_used': qber_threshold # Store threshold used
    }

    # Basic validation
    min_required_qubits = math.ceil(MIN_FINAL_KEY_LENGTH / (0.5 * (1.0 - DEFAULT_QBER_SAMPLE_FRACTION))) * 2
    if n_qubits < min_required_qubits or n_qubits < 4 * MIN_FINAL_KEY_LENGTH:
         required = max(min_required_qubits, 4 * MIN_FINAL_KEY_LENGTH)
         logging.error(f"Error: n_qubits ({n_qubits}) too low. Need >= {required}.")
         result_dict['qber'] = -2.0 # Insufficient start qubits code
         return result_dict

    # --- Steps 1-5: Alice, Bob, Circuit, Simulation ---
    logging.info(f"Starting BB84 sim: {n_qubits} qubits, Eve={simulate_eve} (Rate={eve_interception_rate if simulate_eve else 0}), QBER_Thresh={qber_threshold}")
    alice_bits = [random.randint(0, 1) for _ in range(n_qubits)]
    alice_bases = [random.randint(0, 1) for _ in range(n_qubits)] # 0=Z, 1=X
    result_dict['alice_bits'] = alice_bits[:50]
    result_dict['alice_bases'] = alice_bases[:50]

    qc = QuantumCircuit(n_qubits, n_qubits)
    for i in range(n_qubits):
        if alice_bits[i] == 1: qc.x(i)
        if alice_bases[i] == 1: qc.h(i)

    bob_bases = [random.randint(0, 1) for _ in range(n_qubits)]
    result_dict['bob_bases'] = bob_bases[:50]

    for i in range(n_qubits):
        if bob_bases[i] == 1: qc.h(i)
        qc.measure(i, i)

    try:
        simulator = AerSimulator()
        job = simulator.run(qc, shots=1, memory=True)
        sim_result = job.result()
        measured_bits_str = sim_result.get_memory(qc)[0]
        bob_measured_bits_ideal = [int(bit) for bit in measured_bits_str[::-1]]
    except Exception as e:
        logging.error(f"Error during Qiskit simulation: {e}", exc_info=True)
        result_dict['qber'] = -3.0 # Simulation failed code
        return result_dict

    # --- Simulate Eve's Effect ---
    bob_measured_bits = list(bob_measured_bits_ideal)
    if simulate_eve:
        logging.warning(f"!!! Simulating Eavesdropper (Eve) with error rate: {eve_interception_rate:.2f} !!!")
        error_count = 0
        for i in range(n_qubits):
             if random.random() < eve_interception_rate:
                  bob_measured_bits[i] = 1 - bob_measured_bits[i]
                  error_count += 1
        result_dict['eve_errors_introduced'] = error_count
        result_dict['eve_error_rate_used'] = eve_interception_rate # Store the used rate
        logging.info(f"Eve simulation introduced approx {error_count} errors.")
    result_dict['bob_measurement_results'] = bob_measured_bits[:50]

    # --- 6. Sifting ---
    alice_sifted_bits = []; bob_sifted_bits = []; sifted_indices = []
    for i in range(n_qubits):
        if alice_bases[i] == bob_bases[i]:
            alice_sifted_bits.append(alice_bits[i])
            bob_sifted_bits.append(bob_measured_bits[i])
            sifted_indices.append(i)
    num_sifted = len(alice_sifted_bits)
    result_dict['sifted_indices_count'] = num_sifted
    result_dict['sifted_key_sample'] = "".join(map(str, alice_sifted_bits[:50]))
    logging.info(f"--- Sifting --- \nNumber of sifted bits: {num_sifted} (Efficiency: {num_sifted/n_qubits:.2f})")

    # --- 7. QBER Calculation ---
    if num_sifted < MIN_SIFTED_FOR_QBER:
         logging.warning(f"Only {num_sifted} sifted bits (< {MIN_SIFTED_FOR_QBER}). Cannot calculate QBER.")
         return result_dict # qber remains -1.0

    num_qber_samples = int(num_sifted * DEFAULT_QBER_SAMPLE_FRACTION)
    num_qber_samples = max(1, min(num_qber_samples, num_sifted))
    result_dict['qber_sample_count'] = num_qber_samples
    try: qber_indices_in_sifted_list = random.sample(range(num_sifted), num_qber_samples)
    except ValueError as e: logging.error(f"Error selecting QBER samples: {e}"); return result_dict

    disagreements = sum(alice_sifted_bits[i] != bob_sifted_bits[i] for i in qber_indices_in_sifted_list)
    result_dict['qber_disagreements'] = disagreements
    try: qber = float(disagreements / num_qber_samples) if num_qber_samples > 0 else -1.0
    except ZeroDivisionError: qber = -1.0; logging.error("Division by zero during QBER calculation.")

    result_dict['qber'] = round(qber, 5) if qber >= 0 else qber
    logging.info(f"--- QBER Check ---")
    logging.info(f"Comparing {num_qber_samples} bits, found {disagreements} disagreements. QBER = {result_dict['qber']:.4f}")

    if qber >= 0 and qber > qber_threshold:
        logging.warning(f"ALERT: QBER ({qber:.4f}) > threshold ({qber_threshold:.4f}). Eavesdropping likely!")
        result_dict['eve_detected'] = True
        return result_dict # Abort, no key generated
    elif qber >= 0:
        logging.info(f"QBER ({qber:.4f}) <= threshold ({qber_threshold:.4f}).")
        result_dict['eve_detected'] = False
    # else: QBER calc failed

    # --- 8. Final Key Generation ---
    final_key_list = []
    qber_indices_set = set(qber_indices_in_sifted_list)
    for i in range(num_sifted):
        if i not in qber_indices_set: final_key_list.append(alice_sifted_bits[i])
    final_key_length = len(final_key_list)
    result_dict['final_key_length'] = final_key_length
    logging.info(f"Bits remaining for final key: {final_key_length}")

    if final_key_length < MIN_FINAL_KEY_LENGTH:
        logging.error(f"Error: Final key length ({final_key_length}) < minimum required ({MIN_FINAL_KEY_LENGTH}).")
        return result_dict

    final_key_binary_str = "".join(map(str, final_key_list))
    result_dict['final_key_binary'] = final_key_binary_str
    logging.info(f"Final Key Generated (first 50 bits): {final_key_binary_str[:50]}...")
    logging.info(f"----------------------")

    return result_dict


# --- PDF Generation Function (Added/Merged) ---
def create_qkd_report_pdf(results: dict) -> bytes | None:
    """
    Generates a comprehensive PDF report from the QKD simulation results dictionary.

    Args:
        results (dict): The dictionary returned by simulate_bb84.

    Returns:
        bytes: The content of the generated PDF as bytes, or None if error or reportlab unavailable.
    """
    if not REPORTLAB_AVAILABLE:
        logging.error("Cannot generate QKD PDF report: reportlab library not found.")
        return None
    if not results:
        logging.error("Cannot generate QKD PDF report: No simulation results provided.")
        return None

    buffer = io.BytesIO()
    try:
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []
        run_timestamp = datetime.datetime.now() # Timestamp for the report itself

        # --- Title and Timestamp ---
        title = "QKD Simulation Report (BB84)"
        timestamp_str = run_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph(title, styles['h1']))
        story.append(Paragraph(f"Report Generated: {timestamp_str}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # --- Determine Overall Status ---
        status = "Error"; status_style = styles['h3'] # Use h3 for status
        status_style.textColor = colors.red # Default to red
        qber = results.get('qber', -1.0); eve_detected = results.get('eve_detected', False)
        final_key = results.get('final_key_binary'); final_key_len = results.get('final_key_length', 0)
        sifted_count = results.get('sifted_indices_count', 0)

        if qber == -3.0: status = "Failure: Qiskit Simulation Error"
        elif qber == -2.0: status = "Failure: Insufficient Initial Qubits"
        elif qber == -1.0 and sifted_count < MIN_SIFTED_FOR_QBER: status, status_style.textColor = "Failure: Not Enough Sifted Bits for QBER", colors.orange
        elif qber == -1.0: status = "Failure: QBER Calculation Failed"
        elif eve_detected: status = "Failure: Eavesdropping Detected (High QBER)"
        elif not final_key or final_key_len < MIN_FINAL_KEY_LENGTH: status, status_style.textColor = "Failure: Final Key Too Short / Not Generated", colors.orange
        elif final_key: status, status_style.textColor = "Success: Secure Key Established", colors.darkgreen

        story.append(Paragraph(f"Overall Status: {status}", status_style))
        story.append(Spacer(1, 0.2*inch))

        # --- Summary Table ---
        story.append(Paragraph("Simulation Summary:", styles['h2']))
        qber_str = f"{qber:.4f} ({qber*100:.2f}%)" if qber >= 0 else ("Sim Err" if qber == -3.0 else ("Low Qubits" if qber == -2.0 else "Calc Fail"))
        eve_details = "No"
        if results.get('eve_simulated'): eve_details = f"Yes (Rate: {results.get('eve_error_rate_used', 0):.3f}, Approx Errors: {results.get('eve_errors_introduced', 0)})"

        summary_data = [
            ['Parameter', 'Value'],
            ['Initial Qubits:', str(results.get('initial_qubits', 'N/A'))],
            ['Bases Matched (Sifted):', f"{sifted_count} ({sifted_count / results.get('initial_qubits', 1):.1%})"],
            ['QBER Threshold Used:', f"{results.get('qber_threshold_used', 'N/A'):.3f}"],
            ['Calculated QBER:', qber_str],
            ['Eve Detected (QBER > Thresh):', 'Yes' if results.get('eve_detected') else 'No'],
            ['Eve Simulation Active:', eve_details],
            ['Final Key Generated:', 'Yes' if final_key else 'No'],
            ['Final Key Length:', str(final_key_len) if final_key else 'N/A'],
        ]
        summary_table = Table(summary_data, colWidths=[2.5*inch, 3.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10), ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black), ('FONTSIZE', (0, 1), (-1,-1), 9),]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))

        # --- QBER Check Details ---
        if qber >= -1.0 and sifted_count >= MIN_SIFTED_FOR_QBER :
            story.append(Paragraph("QBER Check Details:", styles['h2']))
            qber_detail_data = [
                ['Metric', 'Value'],
                ['Sifted Bits Available:', str(sifted_count)],
                ['Bits Sampled for QBER:', f"{results.get('qber_sample_count', 'N/A')} ({results.get('qber_sample_count', 0) / sifted_count:.1%})"],
                ['Disagreements Found:', str(results.get('qber_disagreements', 'N/A'))],]
            qber_table = Table(qber_detail_data, colWidths=[2.5*inch, 3.5*inch])
            qber_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkslateblue),('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 0), (-1, 0), 8),('BACKGROUND', (0, 1), (-1, -1), colors.lightsteelblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),('FONTSIZE', (0, 1), (-1,-1), 9),]))
            story.append(qber_table)
            story.append(Spacer(1, 0.2*inch))

        # --- Final Key Sample ---
        if final_key:
            story.append(Paragraph("Final Secret Key (Sample):", styles['h2']))
            key_sample = final_key[:120] + ("..." if len(final_key) > 120 else "")
            key_paragraph = Paragraph(key_sample, styles['Code']); story.append(key_paragraph)
            story.append(Spacer(1, 0.2*inch))

        # --- Log Samples Table ---
        story.append(Paragraph("Simulation Log Samples (First 50 Qubits):", styles['h2']))
        code_style_small = styles['Code']; code_style_small.fontSize = 7; code_style_small.leading = 8
        log_data = [
            ['Item', 'Value Sample'],
            ['Alice Bits:', Paragraph("".join(map(str, results.get('alice_bits', []))), code_style_small)],
            ['Alice Bases:', Paragraph("".join(map(str, results.get('alice_bases', []))), code_style_small)],
            ['Bob Bases:', Paragraph("".join(map(str, results.get('bob_bases', []))), code_style_small)],
            ['Bob Measured:', Paragraph("".join(map(str, results.get('bob_measurement_results', []))), code_style_small)],
            ['Sifted Key (Pre-QBER):', Paragraph(results.get('sifted_key_sample', ''), code_style_small)],]
        log_table = Table(log_data, colWidths=[1.5*inch, 4.5*inch]) # Adjusted width
        log_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),('FONTNAME', (0, 1), (-1, -1), 'Courier'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),('GRID', (0, 0), (-1, -1), 0.5, colors.darkgrey),
            ('FONTSIZE', (0, 1), (-1,-1), 7),]))
        story.append(log_table)

        # --- Build PDF ---
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        logging.info(f"QKD PDF report generated successfully ({len(pdf_bytes)} bytes)")
        return pdf_bytes
    except Exception as e:
        logging.error(f"Error building QKD PDF report: {e}", exc_info=True)
        if buffer: buffer.close()
        return None

# --- Example Usage (for testing directly) ---
if __name__ == '__main__':
    # Setup basic logging for direct script run
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    print("\n" + "="*25 + " Running QKD Simulation Tests " + "="*25 + "\n")
    test_qber_threshold = 0.1

    # Test 1: No Eve
    print("Test 1: No Eve...")
    results_no_eve = simulate_bb84(n_qubits=300, simulate_eve=False, qber_threshold=test_qber_threshold)
    if results_no_eve:
        pdf_data_1 = create_qkd_report_pdf(results_no_eve)
        if pdf_data_1:
            with open("qkd_report_test1_no_eve.pdf", "wb") as f: f.write(pdf_data_1)
            print("Saved PDF: qkd_report_test1_no_eve.pdf")
        else: print("PDF generation failed for Test 1.")
    print("-" * 30)

    # Test 2: With Eve
    print("Test 2: With Eve...")
    results_with_eve = simulate_bb84(n_qubits=600, simulate_eve=True, qber_threshold=test_qber_threshold, eve_interception_rate=0.30)
    if results_with_eve:
        pdf_data_2 = create_qkd_report_pdf(results_with_eve)
        if pdf_data_2:
            with open("qkd_report_test2_with_eve.pdf", "wb") as f: f.write(pdf_data_2)
            print("Saved PDF: qkd_report_test2_with_eve.pdf")
        else: print("PDF generation failed for Test 2.")

    print("\n" + "="*25 + " End Simulation Tests " + "="*25 + "\n")
