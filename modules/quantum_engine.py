import requests
import secrets
import logging

# Configuration for ANU Quantum Random Number Generator
ANU_QRNG_URL = "https://qrng.anu.edu.au/API/jsonI.php?length={}&type=uint8"

class QuantumEntropySource:
    @staticmethod
    def get_true_random_numbers(length, fallback=True):
        """Fetches True Random Numbers from ANU Quantum Lab API."""
        try:
            url = ANU_QRNG_URL.format(length)
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()['data']
                # Convert 0-255 ints to 0-1 bits
                return [x % 2 for x in data]
        except Exception as e:
            logging.warning(f"QRNG API Failed: {e}. Using fallback entropy.")
            if fallback:
                return [secrets.randbelow(2) for _ in range(length)]
            raise e

class QuantumEngine:
    def __init__(self, n_qubits=600, qber_threshold=0.15):
        self.n_qubits = n_qubits
        self.qber_threshold = qber_threshold
        self.entropy_source = QuantumEntropySource()

    def start_session(self, simulate_eve=False):
        """
        Runs the BB84 simulation using True Quantum Entropy.
        Returns status, QBER, and Raw Key.
        """
        # 1. Get Physical Entropy (Patent Claim 4)
        alice_bits = self.entropy_source.get_true_random_numbers(self.n_qubits)
        alice_bases = self.entropy_source.get_true_random_numbers(self.n_qubits)
        bob_bases = self.entropy_source.get_true_random_numbers(self.n_qubits)
        
        # 2. Simulation Logic (BB84)
        sifted_key = []
        errors = 0
        
        for i in range(self.n_qubits):
            bit = alice_bits[i]
            # Eve Interception Logic
            if simulate_eve and secrets.randbelow(100) < 25: 
                 if secrets.randbelow(2) == 1:
                     bit = 1 - bit # Flip bit
            
            if alice_bases[i] == bob_bases[i]:
                sifted_key.append(bit)
                if bit != alice_bits[i]:
                    errors += 1
        
        if len(sifted_key) == 0:
             return {"status": "FAILED", "reason": "No bits sifted", "qber": 1.0, "eve_detected": True}

        qber = errors / len(sifted_key)
        status = "SECURE" if qber <= self.qber_threshold else "COMPROMISED"
        
        # Convert bits to bytes for Key Generation
        key_int = 0
        for b in sifted_key:
            key_int = (key_int << 1) | b
        key_bytes = key_int.to_bytes((len(sifted_key) + 7) // 8, byteorder='big')
        
        # Visualization String
        final_key_binary = "".join(map(str, sifted_key[:50])) + "..."

        return {
            "status": status,
            "qber": qber,
            "raw_key_bytes": key_bytes,
            "final_key_binary": final_key_binary,
            "eve_detected": qber > self.qber_threshold
        }