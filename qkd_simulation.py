# qkd_simulation.py
# This module simulates the BB84 Quantum Key Distribution protocol using Qiskit.
# It includes options to simulate an eavesdropper (Eve) and calculates the
# Quantum Bit Error Rate (QBER) to detect potential eavesdropping.

# --- Ensure necessary libraries are installed: pip install qiskit-aer numpy ---

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator # Use AerSimulator for newer Qiskit versions
import random
import numpy as np # Keep numpy if used elsewhere, otherwise optional for this specific code
import math # For ceiling function

# Define the default fraction of sifted bits to use for the QBER check
DEFAULT_QBER_SAMPLE_FRACTION = 0.5 # Use 50% of sifted bits for QBER check
MIN_SIFTED_FOR_QBER = 10 # Minimum number of sifted bits needed to attempt QBER calculation
MIN_FINAL_KEY_LENGTH = 16 # Minimum acceptable length for the final key (e.g., for AES-128)

def simulate_bb84(n_qubits=600, simulate_eve=False, qber_threshold=0.15, eve_interception_rate=0.25):
    """
    Simulates the BB84 protocol, optionally with Eve and QBER check.

    Args:
        n_qubits (int): Number of initial qubits Alice prepares.
        simulate_eve (bool): If True, simulates Eve introducing errors into the channel.
        qber_threshold (float): The maximum acceptable QBER. If calculated QBER exceeds
                                this, 'eve_detected' flag is set to True.
        eve_interception_rate (float): The probability that Eve's action causes an error
                                     on a given qubit transmission if simulate_eve is True.
                                     This simplified model directly introduces errors.

    Returns:
        dict: A dictionary containing simulation results and logs:
              {
                  'final_key_binary': str | None,  # Final key as '011...' string or None on failure
                  'qber': float,                 # Calculated QBER (-1.0 if calc failed, -2.0 low qubits, -3.0 sim error)
                  'eve_detected': bool,          # True if QBER > threshold
                  'initial_qubits': int,         # Number of qubits started with
                  'sifted_indices_count': int,   # Number of bits remaining after basis sifting
                  'qber_sample_count': int,      # Number of sifted bits used for QBER check
                  'qber_disagreements': int,     # Number of disagreements found in QBER sample
                  'final_key_length': int,       # Number of bits in the final key
                  # Log data (potentially truncated for brevity):
                  'alice_bits': list,            # Alice's initial random bits (first 50)
                  'alice_bases': list,           # Alice's initial random bases (first 50)
                  'bob_bases': list,             # Bob's initial random bases (first 50)
                  'bob_measurement_results': list, # Bob's measured bits (first 50, potentially with errors)
                  'sifted_key_sample': str,      # Sample of the key *before* QBER check bits removed (first 50)
                  'eve_simulated': bool,         # Was Eve simulation active?
                  'eve_error_rate_used': float   # Error rate used in Eve sim (if active)
                  'eve_errors_introduced': int   # Approx number of errors Eve introduced (if active)
              }
    """
    # Initialize result dictionary structure for consistent return format
    result_dict = {
        'final_key_binary': None, 'qber': -1.0, 'eve_detected': False,
        'initial_qubits': n_qubits, 'sifted_indices_count': 0,
        'qber_sample_count': 0, 'qber_disagreements': 0, 'final_key_length': 0,
        'alice_bits': [], 'alice_bases': [], 'bob_bases': [],
        'bob_measurement_results': [], 'sifted_key_sample': "",
        'eve_simulated': simulate_eve, 'eve_error_rate_used': 0.0, 'eve_errors_introduced': 0
    }

    # Basic validation for the number of qubits
    # Need enough for sifting (~50%), QBER check (~50% of sifted), and final key
    min_required_qubits = math.ceil(MIN_FINAL_KEY_LENGTH / (0.5 * (1.0 - DEFAULT_QBER_SAMPLE_FRACTION))) * 2 # Rough estimate
    if n_qubits < min_required_qubits or n_qubits < 4 * MIN_FINAL_KEY_LENGTH:
         required = max(min_required_qubits, 4 * MIN_FINAL_KEY_LENGTH)
         print(f"Error: n_qubits ({n_qubits}) is too low for reliable key generation. Recommend >= {required}.")
         result_dict['qber'] = -2.0 # Use a specific code for insufficient start qubits
         return result_dict

    # 1. Alice generates her random bits and basis choices
    alice_bits = [random.randint(0, 1) for _ in range(n_qubits)]
    alice_bases = [random.randint(0, 1) for _ in range(n_qubits)] # 0=Z (|0>,|1>), 1=X (|+>,|->)
    result_dict['alice_bits'] = alice_bits[:50] # Log sample
    result_dict['alice_bases'] = alice_bases[:50] # Log sample

    # Create Quantum Circuit
    qc = QuantumCircuit(n_qubits, n_qubits)

    # 2. Alice prepares qubits according to her bits and bases
    for i in range(n_qubits):
        if alice_bits[i] == 1: qc.x(i) # Flip |0> to |1> if bit is 1
        if alice_bases[i] == 1: qc.h(i) # Change to X basis if basis is 1

    # --- Quantum Channel Simulation ---

    # 3. Bob chooses his measurement bases randomly
    bob_bases = [random.randint(0, 1) for _ in range(n_qubits)]
    result_dict['bob_bases'] = bob_bases[:50] # Log sample

    # 4. Bob applies gates corresponding to his measurement bases before measuring in Z
    for i in range(n_qubits):
        if bob_bases[i] == 1: qc.h(i) # If Bob chooses X-basis, apply H again
        qc.measure(i, i) # Measure in the Z-basis

    # 5. Simulate the quantum circuit execution using Qiskit AerSimulator
    try:
        # Consider adding noise model here for more realistic simulation
        simulator = AerSimulator()
        # Use memory=True to get the bitstring output for the single shot
        job = simulator.run(qc, shots=1, memory=True)
        result = job.result()
        measured_bits_str = result.get_memory(qc)[0]
        # Convert bitstring (often reversed by Qiskit) to list of ints matching qubit index
        bob_measured_bits_ideal = [int(bit) for bit in measured_bits_str[::-1]]
    except Exception as e:
        print(f"Error during Qiskit simulation: {e}")
        result_dict['qber'] = -3.0 # Simulation failed code
        return result_dict

    # --- Simulate Eve's Effect (Simplified Error Injection Model) ---
    bob_measured_bits = list(bob_measured_bits_ideal) # Start with Bob's ideal results
    if simulate_eve:
        print(f"!!! Simulating Eavesdropper (Eve) with error rate: {eve_interception_rate:.2f} !!!")
        error_count = 0
        for i in range(n_qubits):
             # Simplified model: Eve's action has a chance to flip Bob's measurement result
             if random.random() < eve_interception_rate:
                  bob_measured_bits[i] = 1 - bob_measured_bits[i] # Flip 0->1 or 1->0
                  error_count += 1
        result_dict['eve_errors_introduced'] = error_count
        result_dict['eve_error_rate_used'] = eve_interception_rate
        print(f"Eve simulation introduced approx {error_count} errors into Bob's measurements.")
    result_dict['bob_measurement_results'] = bob_measured_bits[:50] # Log potentially modified sample

    # 6. Sifting (Public Classical Channel Communication)
    # Keep only bits where Alice's and Bob's bases matched
    alice_sifted_bits = []
    bob_sifted_bits = []
    sifted_indices = [] # Store original indices for potential advanced analysis (optional)

    for i in range(n_qubits):
        if alice_bases[i] == bob_bases[i]:
            alice_sifted_bits.append(alice_bits[i]) # Alice uses her original bit
            bob_sifted_bits.append(bob_measured_bits[i]) # Bob uses his potentially noisy measured bit
            sifted_indices.append(i)

    num_sifted = len(alice_sifted_bits)
    result_dict['sifted_indices_count'] = num_sifted
    result_dict['sifted_key_sample'] = "".join(map(str, alice_sifted_bits[:50])) # Log sample before QBER removal
    print(f"--- Sifting ---")
    print(f"Number of sifted bits (bases matched): {num_sifted} (Efficiency: {num_sifted/n_qubits:.2f})")

    # 7. QBER Calculation (Error Estimation)
    # Check if enough bits remain after sifting for a meaningful QBER check
    if num_sifted < MIN_SIFTED_FOR_QBER:
         print(f"Warning: Only {num_sifted} sifted bits. Not enough for reliable QBER calculation (need >= {MIN_SIFTED_FOR_QBER}).")
         # Keep qber as -1.0 (default code for QBER calculation failure)
         return result_dict # Cannot proceed

    # Determine number of bits to sacrifice for QBER check
    num_qber_samples = int(num_sifted * DEFAULT_QBER_SAMPLE_FRACTION)
    # Ensure sampling at least 1 bit, but not more than available
    num_qber_samples = max(1, min(num_qber_samples, num_sifted))
    result_dict['qber_sample_count'] = num_qber_samples

    # Randomly choose distinct indices *from the sifted list* to compare
    try:
        # Sample indices from the range 0 to num_sifted-1
        qber_indices_in_sifted_list = random.sample(range(num_sifted), num_qber_samples)
    except ValueError as e:
         # This can happen if num_qber_samples > num_sifted, but the check above should prevent it
         print(f"Error selecting QBER samples (num_sifted={num_sifted}, num_qber_samples={num_qber_samples}): {e}")
         return result_dict # Cannot proceed

    disagreements = 0
    # Compare Alice's and Bob's bits at the randomly selected sifted indices
    for index_in_sifted in qber_indices_in_sifted_list:
        if alice_sifted_bits[index_in_sifted] != bob_sifted_bits[index_in_sifted]:
            disagreements += 1
    result_dict['qber_disagreements'] = disagreements

    # Calculate QBER as a fraction
    try:
        qber = float(disagreements / num_qber_samples)
    except ZeroDivisionError:
        print("Error: Division by zero during QBER calculation (num_qber_samples=0). Should not happen.")
        qber = -1.0 # Indicate calculation failure

    result_dict['qber'] = round(qber, 5) if qber >= 0 else qber # Store calculated QBER or error code

    print(f"--- QBER Check ---")
    print(f"Comparing {num_qber_samples} randomly chosen sifted bits.")
    print(f"Found {disagreements} disagreements.")
    if qber >= 0: print(f"Calculated QBER: {qber:.4f} ({qber*100:.2f}%)")

    # Check QBER against threshold to determine if Eve was detected
    if qber >= 0 and qber > qber_threshold:
        print(f"ALERT: QBER ({qber:.4f}) exceeds threshold ({qber_threshold:.4f}). Eavesdropping likely!")
        result_dict['eve_detected'] = True
        # Don't generate a final key if QBER is too high
        return result_dict
    elif qber >= 0:
        print(f"QBER ({qber:.4f}) is within acceptable threshold ({qber_threshold:.4f}).")
        result_dict['eve_detected'] = False # Explicitly set False if check passes
    # else: QBER calculation failed, eve_detected remains False (or default)

    # 8. Final Key Generation
    # Remove the bits used for the QBER check from Alice's sifted bits
    final_key_list = []
    qber_indices_set = set(qber_indices_in_sifted_list)
    for i in range(num_sifted):
        # Keep the bit if its index (within the sifted list) was NOT used for QBER
        if i not in qber_indices_set:
            # Use Alice's original, error-free bits for the final key
            final_key_list.append(alice_sifted_bits[i])

    final_key_length = len(final_key_list)
    result_dict['final_key_length'] = final_key_length
    print(f"Number of bits remaining for final secret key: {final_key_length}")

    # Check if final key length is sufficient
    if final_key_length < MIN_FINAL_KEY_LENGTH:
        print(f"Error: Final key length ({final_key_length}) is less than minimum required ({MIN_FINAL_KEY_LENGTH}).")
        # Keep QBER/eve_detected status, but set key to None
        return result_dict # Return the dict with final_key_binary still None

    # Convert final key list to binary string '0110...'
    final_key_binary_str = "".join(map(str, final_key_list))
    result_dict['final_key_binary'] = final_key_binary_str

    print(f"Final Key Generated (first 50 bits): {final_key_binary_str[:50]}...")
    print(f"----------------------")

    return result_dict

# --- Example Usage (for testing the module directly) ---
if __name__ == '__main__':
    print("\n" + "="*25 + " Running QKD Simulation Tests " + "="*25 + "\n")
    print("Test 1: No Eve, Standard Parameters...")
    test_qber_threshold = 0.1 # Stricter threshold for testing
    results_no_eve = simulate_bb84(n_qubits=300, simulate_eve=False, qber_threshold=test_qber_threshold)
    print("\nResults (No Eve):")
    import json
    print(json.dumps(results_no_eve, indent=2))
    if results_no_eve.get('final_key_binary') and not results_no_eve.get('eve_detected'):
        print("Outcome: Success (No Eve, Key Generated)")
    else:
        print(f"Outcome: Failure (No Eve - Key: {bool(results_no_eve.get('final_key_binary'))}, Eve Detected: {results_no_eve.get('eve_detected')}, QBER: {results_no_eve.get('qber')})")

    print("\n" + "="*30 + "\n")

    print("Test 2: With Eve, Standard Parameters...")
    # Use a relatively high interception rate to likely trigger detection
    results_with_eve = simulate_bb84(n_qubits=600, simulate_eve=True, qber_threshold=test_qber_threshold, eve_interception_rate=0.35)
    print("\nResults (With Eve):")
    print(json.dumps(results_with_eve, indent=2))
    if not results_with_eve.get('final_key_binary') and results_with_eve.get('eve_detected'):
        print("Outcome: Success (Eve Detected as expected, No Key Generated)")
    elif results_with_eve.get('final_key_binary') and not results_with_eve.get('eve_detected'):
         print("Outcome: Potential Failure (Eve NOT detected despite simulation!)")
    elif results_with_eve.get('qber', -1.0) < 0:
         print(f"Outcome: Failure (QBER calculation failed/Invalid Qubits - Code: {results_with_eve.get('qber')})")
    else:
        print(f"Outcome: Unexpected ({'Key generated' if results_with_eve.get('final_key_binary') else 'No key'}, Eve Detected: {results_with_eve.get('eve_detected')})")

    print("\n" + "="*25 + " End Simulation Tests " + "="*25 + "\n")
