import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from decimal import Decimal
from contextlib import contextmanager

class DBEngine:
    def __init__(self, db_url=None):
        self.db_url = db_url or os.environ.get('DATABASE_URL')
        # Check if URL contains postgres to determine mode
        self.mode = 'postgres' if self.db_url and 'postgres' in self.db_url else 'sqlite'

    def get_connection(self):
        """Returns a raw database connection."""
        if self.mode == 'postgres':
            return psycopg2.connect(self.db_url)
        else:
            # Fallback for local testing without Postgres
            import sqlite3
            conn = sqlite3.connect('database.db')
            conn.row_factory = sqlite3.Row
            return conn

    def check_connection(self):
        """Simple ping to verify DB connectivity."""
        conn = None
        try:
            conn = self.get_connection()
            if self.mode == 'postgres':
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
            else:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
            return True
        except Exception as e:
            logging.error(f"DB Health Check Failed: {e}")
            return False
        finally:
            if conn:
                conn.close()

class SecureTransactionManager:
    def __init__(self, db_engine):
        self.db = db_engine

    def get_balance(self, user_id):
        """Helper to fetch current balance for ML Context."""
        conn = self.db.get_connection()
        try:
            # Handle DB mode differences
            if self.db.mode == 'postgres':
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                ph = "%s"
            else:
                cursor = conn.cursor()
                ph = "?"
            
            sql = f"SELECT balance FROM accounts WHERE customer_id = {ph}"
            cursor.execute(sql, (user_id,))
            res = cursor.fetchone()
            
            if res:
                # Handle dict vs tuple
                if isinstance(res, dict):
                    return float(res['balance'])
                else:
                    return float(res[0]) # Assuming balance is first column selected? 
                    # Wait, if SELECT balance, it is index 0.
            return 0.0
        except Exception as e:
            logging.error(f"Get Balance Error: {e}")
            return 0.0
        finally:
            conn.close()

    def execute_locked_transfer(self, sender_id, receiver_id, amount):
        """
        Executes transfer using Pessimistic Locking (SELECT FOR UPDATE).
        Returns: (Success_Bool, Message_String)
        """
        conn = self.db.get_connection()
        try:
            # Setup Cursor
            if self.db.mode == 'postgres':
                cursor = conn.cursor(cursor_factory=RealDictCursor)
            else:
                cursor = conn.cursor()
            
            # 1. ACQUIRE PESSIMISTIC LOCK (Patent Claim 6)
            if self.db.mode == 'postgres':
                ids = tuple(sorted([sender_id, receiver_id]))
                # PATENT EVIDENCE LOG
                logging.info(f"[PATENT EVIDENCE] EXECUTING ATOMIC LOCK: SELECT balance FROM accounts WHERE customer_id IN {ids} FOR UPDATE;")
                
                cursor.execute(
                    "SELECT customer_id, balance FROM accounts WHERE customer_id IN %s FOR UPDATE",
                    (ids,)
                )
            else:
                # SQLite fallback
                cursor.execute(
                    "SELECT customer_id, balance FROM accounts WHERE customer_id IN (?, ?)",
                    (sender_id, receiver_id)
                )

            rows = cursor.fetchall()
            
            # Map results
            if self.db.mode == 'postgres':
                 accounts_map = {row['customer_id']: row['balance'] for row in rows}
            else:
                 # Ensure row factory is working or handle tuple
                 # sqlite3.Row allows name access
                 accounts_map = {row['customer_id']: row['balance'] for row in rows}

            if sender_id not in accounts_map:
                return False, "Sender account not found"
            
            sender_bal = Decimal(str(accounts_map[sender_id]))
            amt_dec = Decimal(str(amount))

            if sender_bal < amt_dec:
                return False, "Insufficient Funds"

            # 2. EXECUTE UPDATE
            if self.db.mode == 'postgres':
                cursor.execute("UPDATE accounts SET balance = balance - %s WHERE customer_id = %s", (amt_dec, sender_id))
                cursor.execute("UPDATE accounts SET balance = balance + %s WHERE customer_id = %s", (amt_dec, receiver_id))
            else:
                cursor.execute("UPDATE accounts SET balance = balance - ? WHERE customer_id = ?", (str(amt_dec), sender_id))
                cursor.execute("UPDATE accounts SET balance = balance + ? WHERE customer_id = ?", (str(amt_dec), receiver_id))
            
            conn.commit()
            return True, "Transfer Successful"
            
        except Exception as e:
            conn.rollback()
            logging.error(f"DB Exec Error: {str(e)}")
            return False, f"DB Error: {str(e)}"
        finally:
            conn.close()

    def log_transaction(self, sender_id, receiver_id, amount, status, qber, is_fraud, reason, 
                        key_fingerprint=None, ml_score=None, pqc_used=False, session_id=None):
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor()
            tx_state = 'COMMITTED' if status == 'SECURE' and not is_fraud else 'FAILED'
            
            if self.db.mode == 'postgres':
                sql = """
                    INSERT INTO qkd_transaction_log 
                    (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, 
                     is_flagged, fraud_reason, timestamp, 
                     transaction_state, key_fingerprint, ml_score, pqc_used, session_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s, %s)
                    RETURNING log_id
                """
            else:
                sql = """
                    INSERT INTO qkd_transaction_log 
                    (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, 
                     is_flagged, fraud_reason, timestamp, 
                     transaction_state, key_fingerprint, ml_score, pqc_used, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
                """

            vals = (sender_id, receiver_id, str(amount), status, qber, is_fraud, reason,
                    tx_state, key_fingerprint, ml_score, pqc_used, session_id)
            
            cursor.execute(sql, vals)
            conn.commit()
            
            if self.db.mode == 'postgres':
                return cursor.fetchone()[0]
            else:
                return cursor.lastrowid
        except Exception as e:
            conn.rollback()
            logging.error(f"Log Tx Error: {e}")
            return None
        finally:
            conn.close()
