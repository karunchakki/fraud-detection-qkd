import unittest
import sys
import os

# Ensure we can import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.db_engine import DBEngine, SecureTransactionManager

class TestDBIntegration(unittest.TestCase):
    def setUp(self):
        # Use in-memory SQLite for isolated logic testing
        self.db = DBEngine(db_url=":memory:") 
        self.tm = SecureTransactionManager(self.db)
        
        # Manually create the table schema that log_transaction expects.
        # This must match the INSERT statement in db_engine.py
        conn = self.db.get_connection()
        c = conn.cursor()
        
        # Note: SQLite types are flexible, but we define them to match Postgres structure
        sql_create_table = """
        CREATE TABLE qkd_transaction_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_account_id INTEGER,
            receiver_account_id INTEGER,
            amount TEXT,
            qkd_status TEXT,
            qber_value REAL,
            is_flagged BOOLEAN,
            fraud_reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            transaction_state TEXT,
            key_fingerprint TEXT,
            ml_score REAL,
            pqc_used BOOLEAN,
            session_id TEXT
        );
        """
        c.execute(sql_create_table)
        conn.commit()
        conn.close()

    def test_log_enhanced_fields(self):
        """Test logging a transaction with the new Patent-Compliant fields."""
        lid = self.tm.log_transaction(
            sender_id=1,
            receiver_id=2,
            amount="100.00",
            status="SECURE",
            qber=0.01,
            is_fraud=False,
            reason="None",
            key_fingerprint="fp_123_abc",
            ml_score=0.15,
            pqc_used=True,
            session_id="session_uuid_999"
        )
        
        # Ensure an ID was returned (Row created)
        self.assertIsNotNone(lid)
        
        # Verify data integrity
        conn = self.db.get_connection()
        c = conn.cursor()
        c.execute("SELECT key_fingerprint, transaction_state, session_id FROM qkd_transaction_log WHERE log_id=?", (lid,))
        row = c.fetchone()
        
        # Row is a tuple in SQLite
        self.assertEqual(row[0], "fp_123_abc")   # key_fingerprint
        self.assertEqual(row[1], "COMMITTED")    # transaction_state (derived logic in db_engine)
        self.assertEqual(row[2], "session_uuid_999") # session_id
        
        conn.close()

if __name__ == '__main__':
    unittest.main()
