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
        
        # 1. Quantum & Hybrid Key Generation (Patent Claim 3 & 4)
        qkd_res = self.q_engine.start_session(simulate_eve=simulate_eve)
        logs['qkd'] = qkd_res
        
        # Extract Session ID (Fallback to UUID if engine doesn't provide one)
        session_id = qkd_res.get('session_id') or str(uuid.uuid4())
        
        final_key_bytes = None
        final_key_b64 = None
        key_fingerprint = None
        
        if qkd_res['status'] == 'SECURE':
            # Hybrid Key Derivation
            raw_qkd = qkd_res['raw_key_bytes']
            pqc_secret = self.pqc_engine.encapsulate() # Claim 3: Kyber
            
            # Combine QKD + PQC (XOR Logic)
            final_key_bytes = self.pqc_engine.derive_hybrid_key(raw_qkd, pqc_secret)
            
            # Generate Key artifacts
            final_key_b64 = base64.urlsafe_b64encode(final_key_bytes)
            # Generate non-reversible fingerprint for Audit Log (Patent Requirement)
            key_fingerprint = SecurityUtils.generate_key_fingerprint(final_key_bytes)
        
        # 2. ML Fraud Check (Patent Claim 5)
        # Prepare features (In prod, fetch real history features here)
        tx_features = {'amount': float(amount), 'type_TRANSFER': 1}
        is_fraud, prob, reason = self.ml_engine.predict_fraud(tx_features)
        
        # Security Override: If QKD failed, it's automatically treated as a security risk
        if qkd_res['status'] != 'SECURE':
            is_fraud = True
            reason += f" [QKD COMPROMISED: QBER {qkd_res['qber']:.2%}]"
            
        logs['fraud'] = {'is_fraud': is_fraud, 'prob': prob, 'reason': reason}

        # 3. Database Logging (Patent Compliance: Audit Trail)
        # We log the attempt, the scores, and the crypto-metadata BEFORE committing funds
        self.tx_manager.log_transaction(
            sender_id=sender_id,
            receiver_id=receiver_id,
            amount=amount,
            status=qkd_res['status'],
            qber=qkd_res['qber'],
            is_fraud=is_fraud,
            reason=reason,
            key_fingerprint=key_fingerprint,
            ml_score=prob,
            pqc_used=True, # We used the PQC Engine
            session_id=session_id
        )

        # 4. Database Execution (Patent Claim 6: Pessimistic Locking)
        if is_fraud:
            return False, f"Transfer Blocked: {reason}", logs
        
        # Execute Transfer (Updates Balances)
        success, msg = self.tx_manager.execute_locked_transfer(sender_id, receiver_id, amount)
        
        # 5. Encrypt Receipt (Ephemeral Key)
        # If transfer worked, we generate an encrypted proof using the Hybrid Key
        if success and final_key_b64:
            receipt = SecurityUtils.encrypt_receipt(f"CONFIRMED:{amount}", final_key_b64)
            logs['receipt'] = receipt
            
        return success, msg, logs
