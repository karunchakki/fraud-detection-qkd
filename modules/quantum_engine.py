import requests
import secrets
import logging
import uuid
import time

ANU_QRNG_URL = "https://qrng.anu.edu.au/API/jsonI.php?length={}&type=uint8"

class QuantumEntropySource:
    @staticmethod
    def get_true_random_numbers(length, fallback=True):
        try:
            url = ANU_QRNG_URL.format(length)
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return [x % 2 for x in response.json()['data']]
        except Exception:
            pass
        if fallback:
            return [secrets.randbelow(2) for _ in range(length)]
        return []

class QuantumEngine:
    def __init__(self, n_qubits=600, qber_threshold=0.15):
        self.n_qubits = n_qubits
        self.qber_threshold = qber_threshold
        self.entropy_source = QuantumEntropySource()

    def start_session(self, simulate_eve=False):
        try:
            alice_bits = self.entropy_source.get_true_random_numbers(self.n_qubits)
            alice_bases = self.entropy_source.get_true_random_numbers(self.n_qubits)
            bob_bases = self.entropy_source.get_true_random_numbers(self.n_qubits)
            
            sifted_key = []
            errors = 0
            
            for i in range(len(alice_bits)):
                bit = alice_bits[i]
                
                # --- EVE LOGIC (AGGRESSIVE) ---
                # Increased interception to 50% to ensure QBER > 15%
                if simulate_eve and secrets.randbelow(100) < 50: 
                     if secrets.randbelow(2) == 1:
                         bit = 1 - bit
                # -----------------------------

                if alice_bases[i] == bob_bases[i]:
                    sifted_key.append(bit)
                    if bit != alice_bits[i]:
                        errors += 1
            
            if len(sifted_key) == 0:
                qber = 1.0
            else:
                qber = errors / len(sifted_key)
            
            # Strict Status Check
            status = "SECURE" if qber <= self.qber_threshold else "COMPROMISED"
            
            # Key Derivation
            key_int = 0
            for b in sifted_key:
                key_int = (key_int << 1) | b
            key_bytes = key_int.to_bytes((len(sifted_key) + 7) // 8, byteorder='big')
            
            return {
                "status": status,
                "qber": qber,
                "raw_key_bytes": key_bytes,
                "sifted_bits_count": len(sifted_key),
                "eve_detected": qber > self.qber_threshold,
                "session_id": str(uuid.uuid4())
            }

        except Exception as e:
            logging.error(f"QKD Error: {e}")
            return {
                "status": "ERROR",
                "qber": 1.0,
                "raw_key_bytes": b'',
                "session_id": str(uuid.uuid4())
            }
