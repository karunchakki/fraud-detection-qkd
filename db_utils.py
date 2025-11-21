import os
import sqlite3
import psycopg2
import psycopg2.extras
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("db_utils")

class DBManager:
    def __init__(self):
        self.mode = None 
        self.db_url = os.environ.get('DATABASE_URL')

    def get_connection(self):
        # 1. Try Supabase (Postgres)
        if self.db_url:
            try:
                # connect_timeout=10 helps prevent hanging
                conn = psycopg2.connect(self.db_url, connect_timeout=10)
                self.mode = 'postgres'
                return conn
            except Exception as e:
                logger.error(f"Remote DB Connection Failed: {e}")

        # 2. Fallback to SQLite (Offline Mode)
        try:
            self.mode = 'sqlite'
            conn = sqlite3.connect('/tmp/local_bank.db', check_same_thread=False)
            conn.row_factory = sqlite3.Row 
            return conn
        except Exception as e:
            logger.critical(f"Critical: Could not connect to ANY database. {e}")
            return None

db = DBManager()
