import logging
import base64
import uuid
from decimal import Decimal
from modules.quantum_engine import QuantumEngine
from modules.pqc_engine import PQCEngine
from modules.ml_engine import MLEngine
from modules.db_engine import SecureTransactionManager, DBEngine
from modules.security import SecurityUtils

class TransactionService:
    def __init__(self):
        self.db = DBEngine()
        self.q_engine = QuantumEngine()
        self.pqc_engine = PQCEngine()
        self.ml_engine = MLEngine()
        self.tx_manager = SecureTransactionManager(self.db)

    def process_secure_transfer(self, sender_id, receiver_id, amount, simulate_eve=False):
        """
        Orchestrates the entire Hybrid Post-Quantum Transaction Flow.
        Returns: (success: bool, message: str, logs: dict)
        """
        logs = {}
        
        # 1. Quantum & Hybrid Key Gen
        try:
            qkd_res = self.q_engine.start_session(simulate_eve=simulate_eve)
        except Exception as e:
            logging.error(f"QKD Engine Failed: {e}")
            qkd_res = None

        # FAIL-SAFE: If QKD returns None (API error or logic crash), mock a failed state
        if not qkd_res:
            qkd_res = {
                'status': 'FAILED',
                'qber': 1.0,
                'raw_key_bytes': b'',
                'session_id': str(uuid.uuid4())
            }
        
        logs['qkd'] = qkd_res
        
        session_id = qkd_res.get('session_id') or str(uuid.uuid4())
        
        final_key_bytes = None
        final_key_b64 = None
        key_fingerprint = None
        
        if qkd_res.get('status') == 'SECURE':
            try:
                raw_qkd = qkd_res.get('raw_key_bytes', b'')
                pqc_secret = self.pqc_engine.encapsulate()
                final_key_bytes = self.pqc_engine.derive_hybrid_key(raw_qkd, pqc_secret)
                final_key_b64 = base64.urlsafe_b64encode(final_key_bytes)
                key_fingerprint = SecurityUtils.generate_key_fingerprint(final_key_bytes)
            except Exception as e:
                logging.error(f"Key Derivation Failed: {e}")
                qkd_res['status'] = 'CRYPTO_ERR'
        
        # 2. ML Fraud Check
        tx_features = {'amount': float(amount), 'type_TRANSFER': 1}
        is_fraud, prob, reason = self.ml_engine.predict_fraud(tx_features)
        
        if qkd_res.get('status') != 'SECURE':
            is_fraud = True
            reason += f" [QKD COMPROMISED: QBER {qkd_res.get('qber', 1.0):.2%}]"
            
        logs['fraud'] = {'is_fraud': is_fraud, 'prob': prob, 'reason': reason}

        # 3. Database Logging
        try:
            self.tx_manager.log_transaction(
                sender_id=sender_id,
                receiver_id=receiver_id,
                amount=amount,
                status=qkd_res.get('status', 'ERR'),
                qber=qkd_res.get('qber', 1.0),
                is_fraud=is_fraud,
                reason=reason,
                key_fingerprint=key_fingerprint,
                ml_score=prob,
                pqc_used=True,
                session_id=session_id
            )
        except Exception as e:
            logging.error(f"Logging Failed: {e}")

        # 4. Execute Transfer
        if is_fraud:
            return False, f"Transfer Blocked: {reason}", logs
        
        success, msg = self.tx_manager.execute_locked_transfer(sender_id, receiver_id, amount)
        
        # 5. Encrypt Receipt
        if success and final_key_b64:
            receipt = SecurityUtils.encrypt_receipt(f"CONFIRMED:{amount}", final_key_b64)
            logs['receipt'] = receipt
            
        return success, msg, logs
