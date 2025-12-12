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
        logs = {}
        
        # 1. Run QKD
        qkd_res = self.q_engine.start_session(simulate_eve=simulate_eve)
        if not qkd_res: qkd_res = {'status': 'FAILED', 'qber': 1.0, 'session_id': 'error'}
        logs['qkd'] = qkd_res
        
        # 2. Run ML
        tx_features = {'amount': float(amount), 'type_TRANSFER': 1}
        is_fraud, prob, reason = self.ml_engine.predict_fraud(tx_features)
        
        # 3. GLOBAL SECURITY CHECK (The Kill Switch)
        # If QKD failed (status != SECURE), we FORCE fraud to True
        if qkd_res.get('status') != 'SECURE':
            is_fraud = True
            reason = f"QKD SECURITY ALERT: Channel Compromised (QBER: {qkd_res.get('qber', 0):.2%})"
        
        logs['fraud'] = {'is_fraud': is_fraud, 'prob': prob, 'reason': reason}

        # 4. Log to DB
        self.tx_manager.log_transaction(
            sender_id, receiver_id, amount, 
            status=qkd_res.get('status'), qber=qkd_res.get('qber'), 
            is_fraud=is_fraud, reason=reason,
            ml_score=prob, pqc_used=True, session_id=qkd_res.get('session_id')
        )

        # 5. BLOCKING LOGIC
        # If is_fraud is True (either from ML or QKD), we RETURN FALSE.
        # This prevents execute_locked_transfer from running.
        if is_fraud:
            return False, f"Transfer Blocked: {reason}", logs
        
        # 6. Execute Transfer (Only if Safe)
        success, msg = self.tx_manager.execute_locked_transfer(sender_id, receiver_id, amount)
        return success, msg, logs
