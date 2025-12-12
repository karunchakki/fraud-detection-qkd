import logging
import base64
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
        
        # 1. Quantum & Hybrid Key Gen (Patent Claim 3 & 4)
        qkd_res = self.q_engine.start_session(simulate_eve=simulate_eve)
        logs['qkd'] = qkd_res
        
        final_key_b64 = None
        if qkd_res['status'] == 'SECURE':
            # Hybrid Key Derivation
            raw_qkd = qkd_res['raw_key_bytes']
            pqc_secret, _ = self.pqc_engine.encapsulate()
            hybrid_key = self.pqc_engine.derive_hybrid_key(raw_qkd, pqc_secret)
            final_key_b64 = base64.urlsafe_b64encode(hybrid_key)
        
        # 2. ML Fraud Check (Patent Claim 5)
        # In prod, fetch real history features here
        tx_features = {'amount': float(amount), 'type_TRANSFER': 1}
        is_fraud, prob, reason = self.ml_engine.predict_fraud(tx_features)
        
        if qkd_res['status'] != 'SECURE':
            is_fraud = True
            reason += f" [QKD COMPROMISED: QBER {qkd_res['qber']:.2f}]"
            
        logs['fraud'] = {'is_fraud': is_fraud, 'prob': prob, 'reason': reason}

        # 3. Database Execution (Patent Claim 6: Locking)
        if is_fraud:
            # Log fraud but don't move money
            self.tx_manager.log_failed_transaction(sender_id, receiver_id, amount, reason)
            return False, f"Transfer Flagged: {reason}", logs
        
        # Execute Transfer
        success, msg = self.tx_manager.execute_locked_transfer(sender_id, receiver_id, amount)
        
        # 4. Encrypt Receipt (Ephemeral Key)
        if success and final_key_b64:
            receipt = SecurityUtils.encrypt_receipt(f"CONFIRMED:{amount}", final_key_b64)
            # In a real app, save this receipt to DB
            
        return success, msg, logs
