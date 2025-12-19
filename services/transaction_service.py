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
        
        # 1. Fetch Balance (CRITICAL CONTEXT FOR ML)
        # We need the current balance to calculate 'oldbalanceOrg' for the fraud model
        sender_bal = self.tx_manager.get_balance(sender_id)

        # 2. Run QKD (Quantum Key Distribution)
        # We wrap this in a try-except block via the engine, but handle None here just in case
        qkd_res = self.q_engine.start_session(simulate_eve=simulate_eve)
        if not qkd_res: 
            qkd_res = {'status': 'FAILED', 'qber': 1.0, 'session_id': str(uuid.uuid4())}
        
        logs['qkd'] = qkd_res
        
        session_id = qkd_res.get('session_id') or str(uuid.uuid4())
        final_key_b64 = None
        key_fingerprint = None
        
        # 3. Hybrid Key Derivation (Only if channel is secure)
        if qkd_res.get('status') == 'SECURE':
            try:
                raw_qkd = qkd_res.get('raw_key_bytes', b'')
                pqc_secret = self.pqc_engine.encapsulate() # Claim 3: Kyber PQC
                
                # Mix QKD + PQC keys (XOR Logic)
                final_key_bytes = self.pqc_engine.derive_hybrid_key(raw_qkd, pqc_secret)
                
                # Prepare artifacts
                final_key_b64 = base64.urlsafe_b64encode(final_key_bytes)
                key_fingerprint = SecurityUtils.generate_key_fingerprint(final_key_bytes)
            except Exception as e:
                logging.error(f"Key Derivation Error: {e}")
                qkd_res['status'] = 'KEY_GEN_ERR'
        
        # 4. ML Fraud Check (Patent Claim 5)
        # We pass the real sender_balance we fetched in Step 1
        tx_features = {
            'amount': float(amount),
            'sender_balance': sender_bal,
            'type_TRANSFER': 1
        }
        is_fraud, prob, reason = self.ml_engine.predict_fraud(tx_features)
        
        # 5. GLOBAL SECURITY CHECK (The "Kill Switch")
        # If QKD failed (High QBER), we force fraud status to True regardless of ML
        if qkd_res.get('status') != 'SECURE':
            is_fraud = True
            reason = f"QKD SECURITY ALERT: Channel Compromised (QBER: {qkd_res.get('qber', 0):.2%})"
            
        logs['fraud'] = {'is_fraud': is_fraud, 'prob': prob, 'reason': reason}

        # 6. Database Logging (Audit Trail)
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

        # 7. BLOCKING LOGIC
        # If is_fraud is True (either from ML or QKD), we RETURN FALSE.
        # This prevents the database update from running.
        if is_fraud:
            return False, f"Transfer Blocked: {reason}", logs
        
        # 8. Execute Transfer (Pessimistic Locking via DB Engine)
        success, msg = self.tx_manager.execute_locked_transfer(sender_id, receiver_id, amount)
        
        # 9. Generate Encrypted Receipt (If successful)
        if success and final_key_b64:
            receipt = SecurityUtils.encrypt_receipt(f"CONFIRMED:{amount}", final_key_b64)
            logs['receipt'] = receipt
            
        return success, msg, logs
