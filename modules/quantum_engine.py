import requests
import secrets
import logging
import uuid
import time

# Configuration
ANU_QRNG_URL = "https://qrng.anu.edu.au/API/jsonI.php?length={}&type=uint8"

class QuantumEntropySource:
    @staticmethod
    def get_true_random_numbers(length, fallback=True):
        """Fetches True Random Numbers from ANU Quantum Lab."""
        try:
            # Short timeout (2s) to prevent hanging on Render
            url = ANU_QRNG_URL.format(length)
            response = requests.get(url, timeout=2) 
            if response.status_code == 200:
                data = response.json()['data']
                # Convert 0-255 ints to 0-1 bits
                return [x % 2 for x in data]
        except Exception as e:
            logging.warning(f"QRNG API Failed ({e}). Switching to local entropy.")
        
        # Fallback: Python's CSPRNG (Cryptographically Strong Pseudo-Random Number Generator)
        # This ensures the system NEVER crashes even if the internet is down
        if fallback:
            return [secrets.randbelow(2) for _ in range(length)]
        return []

class QuantumEngine:
    def __init__(self, n_qubits=600, qber_threshold=0.15):
        self.n_qubits = n_qubits
        self.qber_threshold = qber_threshold
        self.entropy_source = QuantumEntropySource()

    def start_session(self, simulate_eve=False):
        """
        Runs BB84 simulation. 
        CRITICAL FIX: This function ALWAYS returns a dict, never None.
        """
        try:
            # 1. Get Entropy (Alice & Bob)
            alice_bits = self.entropy_source.get_true_random_numbers(self.n_qubits)
            alice_bases = self.entropy_source.get_true_random_numbers(self.n_qubits)
            bob_bases = self.entropy_source.get_true_random_numbers(self.n_qubits)
            
            # 2. Simulation Logic (BB84 Protocol)
            sifted_key = []
            errors = 0
            
            for i in range(len(alice_bits)):
                bit = alice_bits[i]
                # Eve Interception Logic
                if simulate_eve and secrets.randbelow(100) < 25: # 25% Interception Probability
                     # Eve measures in random basis (50% chance to flip bit)
                     if secrets.randbelow(2) == 1:
                         bit = 1 - bit
                
                # Sifting: Alice & Bob keep bits where bases matched
                if alice_bases[i] == bob_bases[i]:
                    sifted_key.append(bit)
                    # Check error (if bit flipped by Eve or Noise)
                    if bit != alice_bits[i]:
                        errors += 1
            
            # 3. Calculate QBER
            if len(sifted_key) == 0:
                qber = 1.0 # Maximum error if no bits passed
            else:
                qber = errors / len(sifted_key)
            
            status = "SECURE" if qber <= self.qber_threshold else "COMPROMISED"
            
            # 4. Key Derivation (Raw Binary -> Bytes)
            key_int = 0
            for b in sifted_key:
                key_int = (key_int << 1) | b
            
            # Ensure byte length matches bit length
            byte_len = (len(sifted_key) + 7) // 8
            key_bytes = key_int.to_bytes(byte_len, byteorder='big')
            
            return {
                "status": status,
                "qber": qber,
                "raw_key_bytes": key_bytes,
                "sifted_bits_count": len(sifted_key),
                "eve_detected": qber > self.qber_threshold,
                "session_id": str(uuid.uuid4()),
                "timestamp": time.time()
            }

        except Exception as e:
            logging.error(f"Quantum Engine Critical Fail: {e}")
            # FAIL-SAFE RETURN: Prevents 'NoneType' error in Transaction Service
            return {
                "status": "ERROR",
                "qber": 1.0,
                "raw_key_bytes": b'',
                "sifted_bits_count": 0,
                "eve_detected": True,
                "session_id": str(uuid.uuid4()),
                "error": str(e)
            }
