# qkd_simulation.py
# This module simulates the BB84 Quantum Key Distribution protocol using Qiskit.
# It includes options to simulate an eavesdropper (Eve) and calculates the
# Quantum Bit Error Rate (QBER) to detect potential eavesdropping.

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator # Use AerSimulator for newer Qiskit versions
import random
import numpy as np

# Define the fraction of sifted bits to use for the QBER check
QBER_SAMPLE_FRACTION = 0.5 # Use 50% of sifted bits for QBER check

def simulate_bb84(n_qubits=40, simulate_eve=False):
    """
    Simulates the BB84 protocol, optionally with Eve and QBER check.

    Args:
        n_qubits (int): Number of initial qubits Alice prepares.
                        Should be sufficiently large (e.g., >= 100) for reliable QBER and key length.
        simulate_eve (bool): If True, simulates Eve introducing errors into the channel.

    Returns:
        tuple: (final_key, qber)
               final_key (list | None): A list of 0s and 1s representing the agreed secret key
                                        bits after the QBER check. Returns None if the process
                                        fails (e.g., QBER too high, key too short).
               qber (float): The calculated Quantum Bit Error Rate (fraction of disagreements
                             in the sample). Returns -1.0 if not enough sifted bits were
                             available for a reliable QBER calculation.
    """
    # Basic validation for the number of qubits
    if n_qubits < 20: # Need enough qubits for sifting AND QBER check
         print(f"Warning: n_qubits ({n_qubits}) is low. May result in insufficient key length or unreliable QBER.")
         # Return format consistent with failure cases
         return None, -1.0

    # 1. Alice generates her random bits and basis choices
    alice_bits = [random.randint(0, 1) for _ in range(n_qubits)]
    # Basis choice: 0 = Z-basis (|0>, |1>), 1 = X-basis (|+>, |->)
    alice_bases = [random.randint(0, 1) for _ in range(n_qubits)]

    # Create Quantum Circuit for Alice's qubit preparation
    # n qubits for data, n classical bits for measurement results
    qc = QuantumCircuit(n_qubits, n_qubits)

    # 2. Alice prepares qubits according to her bits and bases
    for i in range(n_qubits):
        # Encode bit: Apply X gate if bit is 1 (flips |0> to |1>)
        if alice_bits[i] == 1:
            qc.x(i)
        # Encode basis: Apply H (Hadamard) gate if basis is X (1)
        # (Changes |0> to |+>, |1> to |->)
        if alice_bases[i] == 1:
            qc.h(i)

    # --- Quantum Channel Simulation ---
    # Qubits conceptually travel from Alice to Bob.
    # Eve might intercept here (simulated later by adding errors).

    # 3. Bob chooses his measurement bases randomly
    # 0 = Z-basis, 1 = X-basis
    bob_bases = [random.randint(0, 1) for _ in range(n_qubits)]

    # 4. Bob applies gates corresponding to his measurement bases
    # If Bob uses X-basis (1), he applies H gate before standard Z-measurement.
    for i in range(n_qubits):
        if bob_bases[i] == 1: # Bob chose X-basis
            qc.h(i) # Apply H to rotate |+>/|-> states towards |0>/|1>
        # Standard measurement is always in the Z-basis
        qc.measure(i, i) # Measure qubit 'i', store result in classical bit 'i'

    # 5. Simulate the quantum circuit execution using Qiskit AerSimulator
    simulator = AerSimulator()
    # Run the circuit once (shots=1), as BB84 deals with single transmissions conceptually
    job = simulator.run(qc, shots=1)
    result = job.result()
    counts = result.get_counts(qc) # Get measurement outcomes

    # Process simulation results
    if not counts:
         print("Error: Qiskit simulation returned no results.")
         return None, 0.0 # Indicate failure, QBER not calculated
    # Get the single outcome bitstring (e.g., '01101...')
    measured_bits_str = list(counts.keys())[0]
    # Convert bitstring to list of ints. Reverse because Qiskit's bit order is little-endian.
    bob_measured_bits_ideal = [int(bit) for bit in measured_bits_str[::-1]]

    # --- Simulate Eve's Effect (Enhancement 2) ---
    # If simulate_eve is True, introduce errors into Bob's results *after* simulation.
    bob_measured_bits = list(bob_measured_bits_ideal) # Start with ideal results
    if simulate_eve:
        print("!!! Simulating Eavesdropper (Eve) introducing errors !!!")
        error_count = 0
        # Model: Eve randomly measuring introduces ~25% error rate on average
        # for bits where Alice and Bob's bases would have matched.
        eve_error_rate = 0.25
        for i in range(n_qubits):
             # Randomly flip Bob's measured bit with probability eve_error_rate
             if random.random() < eve_error_rate:
                  bob_measured_bits[i] = 1 - bob_measured_bits[i] # Flip 0->1 or 1->0
                  error_count +=1
        print(f"Eve simulation introduced {error_count} potential errors in Bob's measurements.")

    # 6. Sifting (Public Classical Channel Communication)
    # Alice and Bob compare their basis choices publicly and keep only the bits
    # where their bases matched.
    alice_sifted_bits = []
    bob_sifted_bits = [] # Bob needs his version (potentially with errors) for QBER check
    sifted_indices = [] # Keep track of original indices corresponding to sifted bits

    for i in range(n_qubits):
        # Keep the bit if bases match
        if alice_bases[i] == bob_bases[i]:
            alice_sifted_bits.append(alice_bits[i])        # Alice uses her original bit
            bob_sifted_bits.append(bob_measured_bits[i]) # Bob uses his measured bit
            sifted_indices.append(i)                      # Record the index

    print(f"--- Sifting ---")
    # print(f"Original indices where bases matched: {sifted_indices}") # Can be verbose
    print(f"Number of sifted bits (before QBER check): {len(alice_sifted_bits)}")

    # 7. QBER Calculation (Error Estimation)
    num_sifted = len(alice_sifted_bits)
    # Check if enough bits remain for a statistically meaningful QBER
    MIN_SIFTED_FOR_QBER = 20 # Need a reasonable sample size
    if num_sifted < MIN_SIFTED_FOR_QBER:
         print(f"Warning: Only {num_sifted} sifted bits. Not enough for reliable QBER calculation (need >= {MIN_SIFTED_FOR_QBER}).")
         return None, -1.0 # Indicate QBER calculation failed

    # Determine number of bits to sacrifice for QBER check based on fraction
    num_qber_samples = int(num_sifted * QBER_SAMPLE_FRACTION)
    # Ensure we sample at least a few bits, but not more than available
    num_qber_samples = max(1, min(num_qber_samples, num_sifted))

    # Randomly choose distinct indices *from the sifted list* to compare
    qber_indices_in_sifted_list = random.sample(range(num_sifted), num_qber_samples)

    disagreements = 0
    # Compare Alice's and Bob's bits at the randomly selected sifted indices
    for index_in_sifted in qber_indices_in_sifted_list:
        if alice_sifted_bits[index_in_sifted] != bob_sifted_bits[index_in_sifted]:
            disagreements += 1

    # Calculate QBER
    qber = float(disagreements / num_qber_samples) # Ensure float division

    print(f"--- QBER Check ---")
    print(f"Comparing {num_qber_samples} randomly chosen sifted bits for errors.")
    print(f"Found {disagreements} disagreements.")
    print(f"Calculated QBER: {qber:.4f}")

    # 8. Final Key Generation
    # Remove the bits used for the QBER check from Alice's sifted bits
    # to form the final secret key.
    final_key = []
    # Create a set for efficient lookup of indices used for QBER check
    qber_indices_set = set(qber_indices_in_sifted_list)
    # Iterate through the original sifted bits
    for i in range(num_sifted):
        # Keep the bit if its index (within the sifted list) was NOT used for QBER
        if i not in qber_indices_set:
            # Use Alice's original, error-free bits for the final key
            final_key.append(alice_sifted_bits[i])

    print(f"Number of bits remaining for final secret key: {len(final_key)}")
    print(f"----------------------")

    # Return the final key bits (list of 0s and 1s) and the calculated QBER
    # Note: app.py will check if final_key is None or too short
    return final_key, qber
