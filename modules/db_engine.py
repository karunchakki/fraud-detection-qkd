import os
import psycopg2
from psycopg2.extras import RealDictCursor
from decimal import Decimal

class DBEngine:
    def __init__(self, db_url=None):
        self.db_url = db_url or os.environ.get('DATABASE_URL')
        self.mode = 'postgres' if self.db_url and 'postgres' in self.db_url else 'sqlite'

    def get_connection(self):
        if self.mode == 'postgres':
            return psycopg2.connect(self.db_url)
        else:
            import sqlite3
            conn = sqlite3.connect('database.db')
            conn.row_factory = sqlite3.Row
            return conn

class SecureTransactionManager:
    def __init__(self, db_engine):
        self.db = db_engine

    def execute_locked_transfer(self, sender_id, receiver_id, amount):
        """
        Executes transfer using Pessimistic Locking (SELECT FOR UPDATE).
        Returns: (Success_Bool, Message_String)
        """
        conn = self.db.get_connection()
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor) if self.db.mode == 'postgres' else conn.cursor()
            
            # 1. ACQUIRE PESSIMISTIC LOCK (Patent Claim 6)
            if self.db.mode == 'postgres':
                # Sort IDs to prevent deadlocks
                ids = tuple(sorted([sender_id, receiver_id]))
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
            return False, f"DB Error: {str(e)}"
        finally:
            conn.close()