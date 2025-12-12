import hashlib
import base64
from cryptography.fernet import Fernet

class SecurityUtils:
    @staticmethod
    def generate_key_fingerprint(key_bytes):
        """Creates a non-reversible fingerprint for logs."""
        return hashlib.sha256(key_bytes).hexdigest()[:16]

    @staticmethod
    def encrypt_receipt(message, session_key_b64):
        """Encrypts transaction receipt using the ephemeral session key."""
        try:
            f = Fernet(session_key_b64)
            return f.encrypt(message.encode()).decode()
        except Exception:
            return "ENCRYPTION_FAILED"
