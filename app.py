# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Includes: User Auth, PostgreSQL, QKD Sim, Fernet Encryption, ML Fraud Detection,
#           PDF Reporting, Info Pages, Risk Simulation, Real Email Sending.
# Version: Adapted for Render PostgreSQL Deployment

# --- Core Imports ---
from flask import (Flask, request, render_template, flash, redirect, url_for,
                   session, g, current_app, Response, abort, get_flashed_messages)
from functools import wraps
import os
import datetime
import base64
import hashlib
import traceback
import logging
import random
from threading import Thread
from decimal import Decimal, InvalidOperation

# --- Environment Variable Loading ---
from dotenv import load_dotenv
# Determine the directory where this script resides
script_dir = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(script_dir, '.env')
if os.path.exists(dotenv_path):
    print(f"--- Loading environment variables from: {dotenv_path} ---")
    load_dotenv(dotenv_path=dotenv_path)
else:
    print(f"--- .env file not found at {dotenv_path}, using system environment variables ---")

# --- Database Import (Using PostgreSQL) ---
POSTGRES_AVAILABLE = False
MYSQL_AVAILABLE = False
MySQLError = None # Define placeholder

# --- Attempt PostgreSQL Import ---
try:
    import psycopg2
    import psycopg2.extras # Needed for RealDictCursor
    POSTGRES_AVAILABLE = True
    logging.info("--- Psycopg2 (PostgreSQL driver) found. ---")
except ImportError:
    psycopg2 = None # Define as None if import fails
    logging.warning("--- Psycopg2 (PostgreSQL driver) not found. ---")
except Exception as e:
    psycopg2 = None
    logging.error(f"--- Unexpected error importing psycopg2: {e} ---")

# --- Attempt MySQL Import ---
try:
    import mysql.connector # Import the main connector library
    from mysql.connector import Error as MySQLError_import # Import Error specifically
    MySQLError = MySQLError_import # Assign to the global placeholder if import succeeds
    MYSQL_AVAILABLE = True
    logging.info("--- MySQL Connector found. ---")
except ImportError:
    # MySQLError remains None, MYSQL_AVAILABLE remains False
    logging.warning("--- MySQL Connector ('mysql-connector-python') not found. It's required for local MySQL execution. ---")
except Exception as e:
    # MySQLError remains None, MYSQL_AVAILABLE remains False
    logging.error(f"--- Unexpected error importing MySQL Connector: {e} ---")

# Define the Database Error Type based on environment
# (Assuming DATABASE_URL means PostgreSQL, otherwise MySQL)
if POSTGRES_AVAILABLE and 'DATABASE_URL' in os.environ:
    DB_ERROR_TYPE = psycopg2.Error if psycopg2 else Exception # Use psycopg2.Error if available, fallback
    print("--- Using PostgreSQL Error Type (psycopg2.Error) ---")
elif MYSQL_AVAILABLE and MySQLError:
    DB_ERROR_TYPE = MySQLError
    print("--- Using MySQL Error Type (MySQLError) ---")
else:
    DB_ERROR_TYPE = Exception # Fallback to generic Exception if specific libs missing
    print("--- Using generic Exception for DB errors (driver-specific type unavailable) ---")

# --- Security & Authentication ---
from werkzeug.security import generate_password_hash, check_password_hash
try:
    from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
except ImportError:
    print("\nERROR: 'itsdangerous' not found. Please install it: pip install itsdangerous")
    exit(1)

# --- Forms (Flask-WTF) ---
WTFORMS_AVAILABLE = False
try:
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, SubmitField, EmailField, DecimalField, SelectField, BooleanField
    from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, InputRequired, Optional
    WTFORMS_AVAILABLE = True
    print("--- Flask-WTF and WTForms found. Forms enabled. ---")
except ImportError:
     print("\nWARNING: 'Flask-WTF' or 'WTForms' not found. Form validation will be basic.")
     FlaskForm = None

# --- Email Sending (Flask-Mail) ---
MAIL_AVAILABLE = False
try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
    print("--- Flask-Mail found. Email features potentially available. ---")
except ImportError:
    Mail = None; Message = None
    print("\nWARNING: 'Flask-Mail' not found. Email features disabled.")

# --- Cryptography Import ---
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("\nERROR: 'cryptography' not found. Install: pip install cryptography"); exit(1)

# --- Data Handling & ML Imports ---
try:
    import numpy; import pandas; import joblib; import sklearn
    print("--- NumPy, Pandas, Joblib, Scikit-learn found. ---")
except ImportError as e:
    print(f"\nERROR: Missing ML/Data library: {e}. Install required libraries."); exit(1)

# --- PDF Generation Import ---
try:
    import reportlab
    print("--- ReportLab found. PDF generation enabled. ---")
except ImportError:
    print("\nERROR: 'reportlab' not found. PDF reporting disabled."); exit(1)


# --- Local Module Imports ---
try:
    from qkd_simulation import simulate_bb84, create_qkd_report_pdf as create_qkd_simulation_report
    from fraud_detection import detect_fraud
    from pdf_generator import create_qkd_report as create_transaction_report
    from risk_simulation import run_risk_analysis
    from ml_fraud_model import load_model as load_ml_model, MODEL_FILENAME, FEATURES_FILENAME
    print("--- Local modules (QKD, Fraud, PDF, Risk, ML Model Loader) found. ---")
except ImportError as e:
    print(f"\nERROR: Failed local module import: {e}."); exit(1)
except ModuleNotFoundError as e:
    print(f"\nERROR: Library missing for local modules: {e}"); exit(1)

# --- Initialize Flask App ---
app = Flask(__name__)

# --- Configuration Loading ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_insecure_default_secret_key_32bytes_')
if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
    print("\nCRITICAL WARNING: Using default FLASK_SECRET_KEY! Set a proper key.")

app.config['WTF_CSRF_ENABLED'] = WTFORMS_AVAILABLE and os.environ.get('WTF_CSRF_ENABLED', 'True').lower() in ('true', '1', 't')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ('true', '1', 't') # Default True for prod
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30)))

# Mail Config (remains the same)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER') or app.config.get('MAIL_USERNAME')

mail = None
if MAIL_AVAILABLE:
    try:
        mail = Mail(app)
        print(f"--- Flask-Mail initialized (Server: {app.config.get('MAIL_SERVER')}). ---")
    except Exception as mail_init_err:
        print(f"\nERROR: Failed to initialize Flask-Mail: {mail_init_err}"); mail = None; MAIL_AVAILABLE = False

# --- Database Configuration (MySQL specific, used only for fallback) ---
# These are ONLY used if DATABASE_URL is NOT set (i.e., running locally without PostgreSQL)
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD')
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')
MYSQL_CONFIG = { 'host': MYSQL_HOST, 'user': MYSQL_USER, 'password': MYSQL_PASSWORD, 'database': MYSQL_DB, 'connection_timeout': 10 }

# App Settings
QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
QKD_NUM_QUBITS = int(os.environ.get('QKD_NUM_QUBITS', 600))
INITIAL_BALANCE = Decimal(os.environ.get('INITIAL_BALANCE', '1000.00'))
app.config['FRAUD_BLACKLIST'] = set(filter(None, os.environ.get('FRAUD_BLACKLIST', '').split(',')))
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE
if not app.secret_key or app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
     raise ValueError("CRITICAL: FLASK_SECRET_KEY is not set.")

# Serializer
serializer = None
try:
    if app.secret_key and app.secret_key != 'a_very_insecure_default_secret_key_32bytes_':
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
except Exception as e: print(f"\nERROR: Failed Serializer init: {e}. Password reset disabled.")

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s [%(name)s:%(lineno)d]')
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('PIL').setLevel(logging.WARNING)

# Load ML Model
logging.info("Attempting ML Model load...")
if not load_ml_model(): logging.critical(f"ML MODEL LOAD FAILED.")
else: logging.info("ML model loaded successfully.")

# --- Forms Definitions ---
if WTFORMS_AVAILABLE:
    class LoginForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Sign In')

    class RegistrationForm(FlaskForm):
         customer_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)], filters=[lambda x: x.strip() if x else x])
         email = EmailField('Email Address', validators=[DataRequired(), Email()], filters=[lambda x: x.strip().lower() if x else x])
         phone_number = StringField('Phone Number', validators=[Optional(), Length(min=10, max=20)])
         password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
         confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
         submit = SubmitField('Register Account')

    class ForgotPasswordForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()], filters=[lambda x: x.strip().lower() if x else x])
        submit = SubmitField('Send Reset Link')

    class ResetPasswordForm(FlaskForm):
        password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
        confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
        submit = SubmitField('Reset Password')

    class TransferForm(FlaskForm):
        receiver_account_id = SelectField('Recipient Account', validators=[InputRequired(message="Please select a recipient.")])
        amount = DecimalField('Amount', places=2, rounding=None, validators=[InputRequired(message="Amount is required."), NumberRange(min=0.01, message="Amount must be at least ₹0.01.")])
        simulate_eve = BooleanField('Simulate Eavesdropper (Higher QBER)')
        submit = SubmitField('Initiate Secure Transfer')
else: # Fallback DummyForm definitions
    logging.warning("Flask-WTF not found, forms defined as dummies.")
    class DummyForm:
        def __init__(self, formdata=None, obj=None, prefix='', data=None, meta=None, **kwargs): self._formdata = formdata; self.errors = {}
        def validate_on_submit(self): return request.method == 'POST'
        def populate_obj(self, obj): pass
        def __getattr__(self, name):
             field_data = None; is_checkbox = name == 'simulate_eve'; form_source = self._formdata or (request.form if request else None)
             if form_source: field_data = (name in form_source) if is_checkbox else form_source.get(name)
             return type('DummyField', (object,), {'data': field_data, 'errors': []})()
    LoginForm=RegistrationForm=ForgotPasswordForm=ResetPasswordForm=TransferForm=DummyForm

# --- Database Helper Functions (Adapted for PostgreSQL) ---
def get_db_connection():
    """
    Establishes and returns a database connection based on environment.
    Prioritizes PostgreSQL using DATABASE_URL (for Render).
    Falls back to MySQL using MYSQL_CONFIG (for local testing).
    Returns the connection object or None on failure.
    Callers are responsible for creating cursors from the returned connection.
    """
    conn = None
    db_url = os.environ.get('DATABASE_URL') # Render injects this automatically

    # --- Primary Path: Use DATABASE_URL for PostgreSQL ---
    if db_url:
        if not POSTGRES_AVAILABLE:
            logging.critical("FATAL: DATABASE_URL is set, but psycopg2 driver is not available!")
            return None
        try:
            logging.debug("Attempting PostgreSQL connection using DATABASE_URL.")
            # Connect without specifying cursor factory here; let caller decide.
            conn = psycopg2.connect(db_url)
            # Optional: Set autocommit if desired, or handle transactions explicitly
            # conn.autocommit = True # Example, usually better to manage transactions
            logging.info("PostgreSQL connection successful via DATABASE_URL.")
            return conn
        except psycopg2.Error as e_pg: # Catch specific psycopg2 errors
            logging.critical(f"CRITICAL POSTGRESQL CONNECTION ERROR: {e_pg}")
            return None
        except Exception as e_pg_other:
            logging.critical(f"CRITICAL UNEXPECTED ERROR CONNECTING TO POSTGRESQL: {e_pg_other}", exc_info=True)
            return None

    # --- Fallback Path: Use MySQL Config ---
    else:
        logging.debug("DATABASE_URL not found. Attempting fallback to MySQL config.")
        if not MYSQL_AVAILABLE:
            logging.critical("FATAL: Running without DATABASE_URL, but MySQL Connector driver is not available!")
            return None
        if not MYSQL_CONFIG.get('password'): # Basic check for password existence
             logging.warning("MySQL password not found in config/environment. Connection likely to fail.")

        try:
            # Connect using the globally defined MYSQL_CONFIG dictionary
            conn = mysql.connector.connect(**MYSQL_CONFIG)
            # Check if connection is actually established and active
            if conn.is_connected():
                logging.info("DB connection successful (MySQL Fallback).")
                return conn
            else:
                # Should ideally not happen if connect() didn't raise error, but handle defensively
                logging.error("MySQL fallback connection failed: connect() succeeded but is_connected() is False.")
                if conn: # Close potentially broken connection
                    try: conn.close()
                    except Exception: pass # Ignore close errors on failure path
                return None
        except MySQLError as e_mysql: # Catch specific mysql.connector errors
            logging.critical(f"CRITICAL MYSQL FALLBACK CONNECTION ERROR: {e_mysql}")
            # conn object might not be assigned if connect fails early
            # No need to close here as connect likely failed
            return None
        except Exception as e_mysql_other:
             logging.critical(f"CRITICAL UNEXPECTED MYSQL FALLBACK ERROR: {e_mysql_other}", exc_info=True)
             return None

def close_db_connection(conn):
    """
    Safely closes the database connection if it exists and is open.
    Handles both psycopg2 and mysql.connector connection objects.
    """
    # Check if conn object is valid and has a 'close' method
    if not conn or not hasattr(conn, 'close'):
        logging.debug("close_db_connection called with invalid/None connection object.")
        return

    try:
        # Check if it's a psycopg2 connection and already closed
        if hasattr(conn, 'closed') and conn.closed:
             logging.debug("PostgreSQL connection already closed.")
             return

        # For MySQL, check is_connected() if available, though closing multiple times is often safe
        # We rely on the fact that calling code should ideally not call close multiple times.

        # Attempt to close the connection
        logging.debug(f"Attempting to close DB connection (Type Check: PG={isinstance(conn, psycopg2.extensions.connection if POSTGRES_AVAILABLE else False)}, MySQL={isinstance(conn, mysql.connector.connection.MySQLConnection if MYSQL_AVAILABLE else False)})")
        conn.close()
        logging.info("Database connection closed successfully.")

    # Use the globally defined DB_ERROR_TYPE for broad compatibility
    # but also catch specific types if possible for more granular logging (optional)
    except DB_ERROR_TYPE as e:
        # Log based on the actual error type determined globally
        logging.error(f"Error closing DB connection ({DB_ERROR_TYPE.__name__}): {e}")
    except Exception as e_generic:
        # Catch any other unexpected error during close
        logging.error(f"Unexpected generic error closing DB connection: {e_generic}", exc_info=True)

def get_accounts_data(customer_id_filter=None):
    """Fetches account data. Adapted for PG/MySQL. Returns list or None on DB error."""
    accounts = []; conn = None; cursor = None; db_type = "Unknown"
    try:
        conn = get_db_connection()
        if not conn: raise ConnectionError("DB connection failed in get_accounts_data.")

        # Determine cursor type
        # Use RealDictCursor for PG to get dict-like rows easily
        if hasattr(conn, 'driver_name') and conn.driver_name == 'psycopg2':
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db_type = "PostgreSQL"
        elif hasattr(conn, 'driver_name') and conn.driver_name == 'mysql':
            cursor = conn.cursor(dictionary=True) # Use dictionary cursor for MySQL
            db_type = "MySQL"
        else: # Fallback
            cursor = conn.cursor()
            db_type = "Fallback (Unknown)"
        logging.debug(f"get_accounts_data: Using {db_type} cursor.")

        # Include account_number in the SELECT
        sql = """SELECT a.account_id, a.account_number, c.customer_name, a.balance, a.customer_id
                 FROM accounts a JOIN customers c ON a.customer_id = c.customer_id"""
        params = []
        if customer_id_filter is not None:
            try:
                filter_id = int(customer_id_filter)
                sql += " WHERE a.customer_id = %s"
                params.append(filter_id)
            except (ValueError, TypeError): logging.error(f"Invalid filter type: {customer_id_filter}")
        sql += " ORDER BY a.account_id ASC" # Order by account_id
        cursor.execute(sql, tuple(params))
        raw_accounts_results = cursor.fetchall() # List of RealDictRow or dict

        for acc_row_raw in raw_accounts_results:
            acc_row = dict(acc_row_raw) # Convert row to standard dict
            try:
                balance_val = acc_row.get('balance')
                # Convert balance via string for robustness
                current_balance = Decimal(str(balance_val)) if balance_val is not None else Decimal('0.00')
                # Check for all required keys, including account_number
                required_keys = ('account_id', 'account_number', 'customer_name', 'customer_id', 'balance')
                if all(k in acc_row for k in required_keys):
                    acc_row['balance'] = current_balance
                    accounts.append(acc_row) # Append the processed dict
                else:
                    missing_keys = [k for k in required_keys if k not in acc_row]
                    logging.warning(f"Skipping account row missing keys ({missing_keys}): {acc_row.get('account_id')}")
            except (InvalidOperation, TypeError, ValueError) as e: # Catch conversion errors
                logging.warning(f"Acc {acc_row.get('account_id')}: Invalid balance ('{balance_val}'): {e}")
            except Exception as inner_e:
                logging.error(f"Acc {acc_row.get('account_id')}: Error processing row: {inner_e}", exc_info=True)

    except DB_ERROR_TYPE as e: # Use global DB_ERROR_TYPE
        logging.error(f"DB error fetch accounts ({db_type}): {e}"); return None
    except ConnectionError as e:
        logging.error(f"Conn error fetch accounts: {e}"); return None
    except Exception as e:
        logging.error(f"Unexpected error fetch accounts: {e}", exc_info=True); return None
    finally:
        # Safe cleanup
        if cursor:
            try: cursor.close()
            except DB_ERROR_TYPE: pass
            except Exception: pass
        if conn: close_db_connection(conn)
    return accounts
  
def get_user_by_email(email):
    """Fetches user details by email. Adapted for PG/MySQL. Returns dict or None."""
    user = None; conn = None; cursor = None; db_type = "Unknown"
    if not isinstance(email, str) or not email: return None # Basic input validation

    try:
        conn = get_db_connection()
        if not conn: raise ConnectionError("DB connection failed in get_user_by_email.")

        # Determine cursor type
        if hasattr(conn, 'driver_name') and conn.driver_name == 'psycopg2':
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db_type = "PostgreSQL"
        elif hasattr(conn, 'driver_name') and conn.driver_name == 'mysql':
            cursor = conn.cursor(dictionary=True)
            db_type = "MySQL"
        else: # Fallback
            cursor = conn.cursor()
            db_type = "Fallback"
        logging.debug(f"get_user_by_email: Using {db_type} cursor.")

        # SQL query remains the same, placeholders work for both
        cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,))
        user_row = cursor.fetchone() # Fetches RealDictRow or dict
        if user_row:
            user = dict(user_row) # Convert to standard dict

    except DB_ERROR_TYPE as e: # Use global DB_ERROR_TYPE
        logging.error(f"DB Error fetch user {email} ({db_type}): {e}"); user = None
    except ConnectionError as e:
        logging.error(f"Conn error fetch user {email}: {e}"); user = None
    except Exception as e:
        logging.error(f"Unexpected error fetch user {email}: {e}", exc_info=True); user = None
    finally:
        # Safe cleanup
        if cursor:
            try: cursor.close()
            except DB_ERROR_TYPE: pass
            except Exception: pass
        if conn: close_db_connection(conn)
    return user
  
def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None, exception_info=None):
    """Logs details of a failed transaction attempt. Adapted for PG/MySQL."""
    sender_id_val = int(sender_id) if sender_id is not None else None
    receiver_id_val = int(receiver_id) if receiver_id is not None else None

    # Robust amount handling
    if amount is None or not isinstance(amount, Decimal):
        try:
            amount = Decimal(str(amount).strip()) if amount is not None else Decimal('0.00')
        except (InvalidOperation, TypeError, ValueError):
            logging.warning(f"Invalid amount '{amount}' passed to log_failed_attempt, using 0.00.")
            amount = Decimal('0.00')
    amount_str = f"{amount:.2f}" # Format Decimal to string

    qber_db_val = float(qber_value) if isinstance(qber_value, (float, int)) and qber_value >= 0 else None
    is_flagged = bool(fraud_reason) # Flag if any reason exists
    reason_text = str(fraud_reason)[:255] if fraud_reason else None # Truncate

    # Combine exception info safely
    if exception_info:
        exc_str = str(exception_info)[:150] # Limit exception string length
        reason_text = f"{reason_text or 'Error'} | Exc: {exc_str}"[:255] # Combine and truncate

    logging.warning(f"Logging failed TXN: Status='{failed_status}', Reason='{reason_text}'")

    log_conn = None; log_cursor = None
    try:
        log_conn = get_db_connection()
        if not log_conn:
            logging.critical("CRITICAL: DB Conn failed. CANNOT LOG FAILED TXN.")
            return # Exit if cannot log

        log_cursor = log_conn.cursor() # Standard cursor for INSERT
        # SQL INSERT statement (placeholders work for both DBs)
        log_sql = """INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason, timestamp, encrypted_confirmation, iv) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        log_values = (
            sender_id_val, receiver_id_val, amount_str,
            failed_status[:50], # Ensure status fits DB column size
            qber_db_val, is_flagged, reason_text, # Use potentially combined/truncated reason
            datetime.datetime.now(datetime.timezone.utc), # Use timezone-aware timestamp
            None, None # No encrypted data/IV for failed attempts
        )
        log_cursor.execute(log_sql, log_values)
        log_conn.commit() # Commit the log entry
        logging.info(f"Failed attempt logged (Status: {failed_status}).")

    except DB_ERROR_TYPE as log_err: # Use global DB_ERROR_TYPE
        logging.critical(f"CRITICAL DBError log FAILED TXN: {log_err}", exc_info=True)
        # Attempt rollback if connection is still valid
        if log_conn and not getattr(log_conn, 'closed', True):
            try:
                log_conn.rollback()
                logging.warning("Attempted rollback after failed transaction logging.")
            except DB_ERROR_TYPE as rb_err: logging.error(f"Rollback failed: {rb_err}")
            except Exception as rb_gen_err: logging.error(f"Unexpected rollback error: {rb_gen_err}")
    except Exception as e:
         logging.critical(f"CRITICAL Unexpected error log FAILED TXN: {e}", exc_info=True)
         # Attempt rollback
         if log_conn and not getattr(log_conn, 'closed', True):
             try:
                 log_conn.rollback()
             except Exception as rb_gen_err: logging.error(f"Unexpected rollback error on generic exception: {rb_gen_err}")
    finally:
        # Safe cleanup
        if log_cursor:
            try: log_cursor.close()
            except DB_ERROR_TYPE: pass
            except Exception: pass
        if log_conn: close_db_connection(log_conn)
    # --- End Correction ---

# --- Authentication & Session Management ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session first
        if 'user_id' not in session:
            flash("Please log in.", "warning")
            return redirect(url_for('login', next=request.url))
        # Check g.user *and* if it has 'id' key BEFORE proceeding
        if not g.get('user') or 'id' not in g.user: # More explicit check
             session.clear()
             flash("Session invalid or incomplete. Please log in again.", "warning")
             logging.warning(f"Cleared session in decorator: g.user check failed (g.user: {g.get('user')})")
             return redirect(url_for('login'))
        # If checks pass
        logging.debug(f"Login required check passed for user: {g.user.get('id')}")
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    """Loads user data into Flask's 'g' object. Handles PG/MySQL."""
    user_id = session.get('user_id')
    g.user = None # Reset at start
    logging.debug(f"[BeforeRequest] Start. Session user_id: {user_id}")
    if user_id:
        conn = None; cursor = None; db_type = "Unknown"
        try:
            conn = get_db_connection()
            if conn:
                try:
                    # Use standard cursor for this simple fetch by primary key
                    cursor = conn.cursor()
                    db_type = getattr(conn, 'driver_name', 'Unknown') # Get type if set
                    logging.debug(f"[BeforeRequest] DB Connected ({db_type}). Querying user_id: {user_id}")
                    sql = "SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s"
                    cursor.execute(sql, (user_id,))
                    user_data_tuple = cursor.fetchone() # Fetches a tuple
                    logging.debug(f"[BeforeRequest] DB Fetch Result: {user_data_tuple}")

                    # Check tuple validity before accessing indices
                    if user_data_tuple and len(user_data_tuple) >= 3:
                        # Assign to g.user as a dictionary
                        g.user = {'id': user_data_tuple[0], 'name': user_data_tuple[1], 'email': user_data_tuple[2]}
                        session.permanent = True # Refresh session lifetime
                        logging.info(f"[BeforeRequest] Set g.user for {user_id}: {g.user}")
                    else:
                        # User ID in session but not found or data invalid in DB
                        logging.warning(f"[BeforeRequest] User {user_id} in session not found/invalid in DB ({user_data_tuple}). Clearing.")
                        session.clear(); g.user = None # Clear session and ensure g.user is None
                except DB_ERROR_TYPE as e: # Catch DB-specific error
                    logging.error(f"[BeforeRequest] DBError load session user {user_id} ({db_type}): {e}"); g.user = None
                except IndexError as e: # Catch error if tuple doesn't have expected elements
                     logging.error(f"[BeforeRequest] IndexError user {user_id} processing tuple {user_data_tuple}: {e}"); g.user = None
                except Exception as e: # Catch any other errors during DB interaction
                    logging.error(f"[BeforeRequest] Unexpected error load user {user_id}: {e}", exc_info=True); g.user = None
                finally:
                    # Safe cleanup for this block's cursor and connection
                    if cursor:
                        try: cursor.close()
                        except DB_ERROR_TYPE: pass
                        except Exception: pass
                    if conn: # Close the connection specifically obtained for this request check
                         close_db_connection(conn)
            else:
                # Failed to get DB connection
                logging.error("[BeforeRequest] DB conn failed. Clearing session."); session.clear(); g.user = None
        except Exception as outer_e:
             # Error even trying to get connection
             logging.error(f"[BeforeRequest] Outer exception {user_id}: {outer_e}", exc_info=True); session.clear(); g.user = None
    else: # No user_id in session
        logging.debug("[BeforeRequest] No user_id in session.")
    # Log final state for debugging request flow
    logging.debug(f"[BeforeRequest] End. g.user is set: {bool(g.user)}")

def clear_qkd_session_log():
     """Removes the last QKD simulation log from the user's session."""
     # Safely get user_id from g.user first, fallback to session
     user_id = getattr(g, 'user', {}).get('id') or session.get('user_id')
     if user_id:
         log_key = f'last_qkd_log_{user_id}'
         # Use pop with default None to avoid KeyError if key doesn't exist
         if session.pop(log_key, None) is not None:
             session.modified = True # Ensure session changes are saved
             logging.info(f"Cleared QKD log from session for user {user_id}")
         # else: # Optional log if needed
         #     logging.debug(f"No QKD log found in session for user {user_id} to clear.")
     # else: # Optional log if needed
     #     logging.warning("Could not determine user ID to clear QKD session log.")


# --- Async Email Helper ---
def send_async_email(app_context, msg):
    """Sends email in a background thread using app context."""
    # Pass the whole app context for Flask-Mail and config access
    with app_context:
        if not mail:
            logging.error("Flask-Mail (mail object) not initialized. Cannot send async email.")
            return
        try:
            logging.debug(f"Attempting to send async email via Flask-Mail to: {msg.recipients}")
            mail.send(msg)
            # Log success AFTER send attempt returns without error
            logging.info(f"Async email sent successfully via Flask-Mail to {msg.recipients}")
        except Exception as e:
            # Log the full error details for debugging SMTP issues
            logging.error(f"Error sending async email via Flask-Mail to {msg.recipients}: {e}", exc_info=True)

# --- Flask Routes ---
@app.route('/')
def home_redirect():
    if g.get('user'): return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    """Main dashboard page."""
    # --- MODIFIED USER ID FETCH ---
    # Safely get user ID from g.user, default to None if key missing (though decorator should prevent None g.user)
    user_id = g.user.get('id')
    if user_id is None:
         # This should ideally not happen if @login_required worked, but handle defensively
         logging.error("CRITICAL: User ID missing from g.user in /index despite login_required.")
         flash("An error occurred retrieving your user information. Please log in again.", "error")
         session.clear() # Clear potentially corrupted session
         return redirect(url_for('login'))
    user_accounts = get_accounts_data(customer_id_filter=user_id)
    all_accounts = get_accounts_data()
    if user_accounts is None: user_accounts = []; flash("Error loading account info.", "error")
    if all_accounts is None: all_accounts = []; flash("Error loading recipient list.", "error")
    receiver_accounts = [acc for acc in all_accounts if acc.get('customer_id') != user_id]
    flagged_transactions = get_flagged_transactions(user_id, limit=5)
    show_fraud_alert = bool(flagged_transactions)
    last_transfer_outcome = session.pop('last_transfer_outcome', None)
    transfer_form = None
    if WTFORMS_AVAILABLE:
        transfer_form = TransferForm()
        recipient_choices = [(str(acc['account_id']), f"{acc['customer_name']} (Acc ID: {acc['account_id']})") for acc in receiver_accounts]
        recipient_choices.insert(0, ('', '-- Select Recipient --'))
        transfer_form.receiver_account_id.choices = recipient_choices
    return render_template('index.html', user_accounts=user_accounts, receiver_accounts=receiver_accounts,
                           transfer_form=transfer_form, show_fraud_alert=show_fraud_alert,
                           flagged_transactions=flagged_transactions, last_transfer_outcome=last_transfer_outcome)

# Inside app.py

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles new customer registration. Adapted for PG/MySQL."""
    if g.user: return redirect(url_for('index'))
    form = RegistrationForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or (not WTFORMS_AVAILABLE and request.method == 'POST'):
        # --- 1. Extract Form Data ---
        if WTFORMS_AVAILABLE:
            customer_name=form.customer_name.data; email=form.email.data; password=form.password.data; phone_number=form.phone_number.data
        else: # Manual extraction and basic validation
            customer_name=request.form.get('customer_name','').strip(); email=request.form.get('email','').strip().lower(); password=request.form.get('password',''); confirm_password=request.form.get('confirm_password',''); phone_number=request.form.get('phone_number', '').strip()
            errors=[]
            if not customer_name or len(customer_name)<2: errors.append("Name required (min 2 chars).")
            if not email or '@' not in email: errors.append("Valid email required.")
            if not password or len(password)<8: errors.append("Password required (min 8 chars).")
            if password != confirm_password: errors.append("Passwords don't match.")
            if errors:
                for err in errors: flash(err, 'error')
                return render_template('register.html', form=form)

        logging.info("DEMO MODE: Skipping CAPTCHA validation.")
        logging.info("DEMO MODE: Skipping OTP validation.")

        # --- 3. Database Operations ---
        conn = None; cursor = None; user_exists = False; error_occurred = False; db_type = "Unknown"

 # 3a. Pre-check if email exists
        conn = None # Ensure conn is defined before try
        cursor = None # Ensure cursor is defined before try
        user_exists = False
        error_occurred = False
        db_type = "Unknown"

        try:
             conn = get_db_connection()
             if not conn:
                  # Set error flag and message if connection fails
                  error_occurred = True
                  flash("Database connection error during pre-check.", "error")
                  # No 'return' here, let the check after finally handle it
             else:
                 # Proceed with check only if connection succeeded
                 db_type = getattr(conn, 'driver_name', 'Unknown') # Get DB type
                 cursor = conn.cursor() # Simple cursor is fine for existence check
                 logging.debug(f"Register Pre-check: Using {db_type} cursor.")

                 cursor.execute("SELECT 1 FROM customers WHERE email = %s LIMIT 1", (email,))
                 if cursor.fetchone():
                     user_exists = True
                     # Add error based on WTForms availability
                     if WTFORMS_AVAILABLE and hasattr(form.email, 'errors'):
                         form.email.errors.append("Email address is already registered.")
                     else:
                         flash("Email address is already registered.", "error")

        except (DB_ERROR_TYPE, ConnectionError) as e:
            logging.error(f"DB pre-check error ({db_type}) for {email}: {e}")
            flash("A database error occurred during pre-check.", "error")
            error_occurred = True
        except Exception as e:
             logging.error(f"Unexpected pre-check error for {email}: {e}", exc_info=True)
             flash("An unexpected error occurred during pre-check.", "error")
             error_occurred = True
        finally:
             # --- CORRECTED FINALLY for Pre-check ---
             # Always close the cursor used for the pre-check if it exists
             if cursor:
                 try:
                     cursor.close()
                 except DB_ERROR_TYPE: pass # Ignore DB specific close errors
                 except Exception as cur_close_err: logging.warning(f"Error closing pre-check cursor: {cur_close_err}")

             # Close the connection ONLY if we are stopping (user exists or error occurred)
             # Otherwise, keep it open for the main transaction block (3b)
             if (user_exists or error_occurred) and conn and not getattr(conn, 'closed', True):
                 logging.debug("Closing connection after failed pre-check or existing user found.")
                 close_db_connection(conn)
             elif conn:
                 logging.debug("Pre-check passed. Keeping connection open for main transaction.")
             # --- END CORRECTION ---

        # --- Decision Point ---
        # If email exists OR an error occurred during pre-check, stop and re-render
        if user_exists or error_occurred:
            # Ensure connection is definitely closed if we stop here
            if conn and not getattr(conn, 'closed', True): close_db_connection(conn)
            return render_template('register.html', form=form)

        # --- 3b. Main Transaction: Insert Customer & Account ---
        cursor = None; needs_rollback = False; new_customer_id = None
        try:
            # Ensure connection is still valid (or reconnect)
            if not conn or getattr(conn, 'closed', True):
                logging.warning("DB connection invalid before insert. Reconnecting."); conn = get_db_connection()
                if not conn: raise ConnectionError("DB connection lost before registration transaction.")
            db_type = getattr(conn, 'driver_name', 'Unknown') # Re-check db_type

            cursor = conn.cursor() # Use standard cursor for DML with RETURNING
            needs_rollback = True
            hashed_pw = generate_password_hash(password)
            phone_number_to_db = phone_number if phone_number else None

            # --- Insert Customer ---
            sql_insert_customer = "INSERT INTO customers (customer_name, email, password_hash, phone_number) VALUES (%s, %s, %s, %s)"
            # Use RETURNING for PostgreSQL to reliably get the new ID
            returning_clause = " RETURNING customer_id" if db_type == 'psycopg2' else ""
            customer_params = (customer_name, email, hashed_pw, phone_number_to_db)
            cursor.execute(sql_insert_customer + returning_clause, customer_params)

            if db_type == 'psycopg2': # Get ID from RETURNING (PG)
                returned_row = cursor.fetchone()
                if returned_row and len(returned_row) > 0: new_customer_id = returned_row[0]
                else: raise DB_ERROR_TYPE("Failed to retrieve customer ID after insert (PG).")
            else: # Get ID using lastrowid (MySQL)
                new_customer_id = cursor.lastrowid
                if not new_customer_id: raise DB_ERROR_TYPE("Failed to get customer ID after insert (MySQL).")
            logging.debug(f"Inserted customer '{customer_name}' (ID: {new_customer_id})")

            # --- Generate and Insert Account ---
            account_number_generated = None; attempt = 0; max_generation_attempts = 10
            while attempt < max_generation_attempts:
                attempt += 1; min_acc=10**11; max_acc=(10**12)-1
                potential_acc_num = str(random.randint(min_acc, max_acc))
                logging.debug(f"Attempt {attempt}: Potential Acc No: {potential_acc_num}")
                try:
                    # Reuse cursor for check within transaction
                    cursor.execute("SELECT 1 FROM accounts WHERE account_number = %s LIMIT 1", (potential_acc_num,))
                    if not cursor.fetchone(): # If no row found, it's unique
                         account_number_generated = potential_acc_num
                         logging.info(f"Unique Acc No found: {account_number_generated}")
                         break # Exit loop
                    else:
                         logging.warning(f"Acc No {potential_acc_num} exists. Retrying...")
                except DB_ERROR_TYPE as check_err: # Catch DB error during check
                    raise ValueError(f"DB error check acc uniqueness: {check_err}") # Re-raise

            if account_number_generated is None: # Check if loop finished without success
                raise ValueError(f"Could not generate unique account number after {max_generation_attempts} tries.")

            # Insert account with generated number
            sql_insert_account = "INSERT INTO accounts (customer_id, balance, account_number) VALUES (%s, %s, %s)"
            returning_acc_clause = " RETURNING account_id" if db_type == 'psycopg2' else ""
            account_params = (new_customer_id, str(app.config['INITIAL_BALANCE']), account_number_generated)
            cursor.execute(sql_insert_account + returning_acc_clause, account_params)

            # Verify account insertion (get ID)
            if db_type == 'psycopg2':
                 acc_row = cursor.fetchone()
                 if not acc_row or len(acc_row) == 0: raise DB_ERROR_TYPE(f"Failed retrieve account ID cust {new_customer_id} (PG).")
                 inserted_account_id = acc_row[0]
            else: # MySQL check
                 inserted_account_id = cursor.lastrowid
                 if not inserted_account_id: raise DB_ERROR_TYPE(f"Failed get account ID cust {new_customer_id} (MySQL).")
            logging.debug(f"Inserted account {inserted_account_id} cust {new_customer_id} AccNo: {account_number_generated}")

            # --- Commit ---
            conn.commit()
            needs_rollback = False
            logging.info(f"Successfully registered user: '{customer_name}' ({email}), ID: {new_customer_id}")
            flash("Registration successful! You can now log in.", "success")

            # Explicitly close resources after commit before redirect
            if cursor: cursor.close(); cursor=None
            if conn: close_db_connection(conn); conn=None
            return redirect(url_for('login'))

        # --- Catch Errors during Transaction ---
        except (DB_ERROR_TYPE, ConnectionError, ValueError) as e:
            error_msg = str(e)
            logging.error(f"Registration DB/Value error ({db_type}) for {email}: {error_msg}", exc_info=isinstance(e, ConnectionError))
            flash(f"Registration failed: {error_msg}" if isinstance(e, ValueError) else "Database error during registration.", "error")
        except Exception as e:
            logging.error(f"Unexpected registration error for {email}: {e}", exc_info=True)
            flash("An unexpected error occurred during registration.", "error")
        finally: # Rollback and cleanup if necessary
            if conn and not getattr(conn, 'closed', True):
                if needs_rollback:
                    try: conn.rollback(); logging.warning(f"Registration rolled back for '{email}'.")
                    except Exception as rb_err: logging.error(f"Rollback failed: {rb_err}")
                if cursor: try: cursor.close() except: pass
                close_db_connection(conn)

        # Re-render form if transaction failed
        return render_template('register.html', form=form)

    # --- Handle GET Request ---
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if g.user: return redirect(url_for('index'))
    form = LoginForm() if WTFORMS_AVAILABLE else None
    logging.debug(f"Login route accessed, method: {request.method}") # Log access

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email', '').strip().lower()
        password = form.password.data if WTFORMS_AVAILABLE else request.form.get('password', '')
        logging.info(f"Login attempt for email: {email}") # Log attempt

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template('login.html', form=form)

        # *** DEBUG: Check user lookup ***
        customer = get_user_by_email(email)
        logging.debug(f"Result of get_user_by_email({email}): {'User found' if customer else 'User NOT found'}")

        if customer:
            # *** DEBUG: Check password hash ***
            stored_hash = customer.get('password_hash', '')
            logging.debug(f"Stored hash found: {'Yes' if stored_hash else 'No'}")
            is_valid_password = check_password_hash(stored_hash, password)
            logging.debug(f"Password check result: {is_valid_password}")

            if is_valid_password:
                # Login successful path
                session.clear()
                session['user_id'] = customer['customer_id']
                session.permanent = True
                # *** DEBUG: Confirm session set ***
                logging.debug(f"Session user_id set to: {session.get('user_id')}")

                # Manually load g.user immediately for this request context
                # (load_logged_in_user will run again on next request)
                g.user = {'id': customer['customer_id'], 'name': customer['customer_name'], 'email': customer['email']}
                logging.info(f"User {g.user['name']} (ID: {g.user['id']}) login successful. Redirecting...")

                flash(f"Welcome back, {g.user.get('name', 'User')}!", "success")
                next_page = request.args.get('next')
                # *** DEBUG: Check redirect target ***
                redirect_target = next_page if next_page and next_page.startswith('/') and ' ' not in next_page else url_for('index')
                logging.debug(f"Redirecting to: {redirect_target}")
                return redirect(redirect_target)
            else:
                # Invalid password path
                logging.warning(f"Failed login attempt for {email}: Invalid password.")
                flash("Invalid email or password.", "error")
        else:
            # User not found path
            logging.warning(f"Failed login attempt for {email}: User not found.")
            flash("Invalid email or password.", "error") # Keep message generic

    # Handle GET request or failed POST validation
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    user_name = g.user.get('name', 'N/A'); user_id = g.user.get('id', 'N/A')
    clear_qkd_session_log(); session.clear()
    flash("Logged out.", "info"); logging.info(f"User {user_name} (ID: {user_id}) logged out.")
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if g.user: return redirect(url_for('index'))
    form = ForgotPasswordForm() if WTFORMS_AVAILABLE else None
    if not MAIL_AVAILABLE or not serializer: flash("Password reset unavailable.", "warning"); return redirect(url_for('login'))

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):
        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email','').strip().lower()
        if not email or '@' not in email: flash("Valid email required.", "error"); return render_template('forgot_password.html', form=form)

        logging.info(f"Password reset requested for {email}")
        user = get_user_by_email(email)
        if user:
            try:
                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)
                subject = "Reset QSB Password"; sender_display_tuple = ("QSB Secure Banking", app.config['MAIL_DEFAULT_SENDER'])
                recipients = [email]; email_body = f"Hello {user.get('customer_name', 'User')},\n\nClick to reset:\n{reset_url}\n\nExpires in 1 hour.\n\nQSB Team"
                msg = Message(subject=subject, sender=sender_display_tuple, recipients=recipients, body=email_body)
                thread = Thread(target=send_async_email, args=[current_app.app_context(), msg]); thread.start()
                logging.info(f"Password reset email queued for {email}")
            except Exception as e: logging.error(f"ERROR sending reset email for {email}: {e}", exc_info=True)
        else: logging.info(f"Password reset for non-existent email: {email}")
        flash('If account exists, email sent. Check spam folder.', 'info') # Updated flash
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

# Inside app.py

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handles the password reset form submitted via the email link."""
    if g.user:
        flash("Already logged in.", "info")
        return redirect(url_for('index'))
    if not serializer:
        flash("Password reset service is unavailable.", "warning")
        return redirect(url_for('login'))

    email = None
    try:
        # Validate token and extract email
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600) # 1 hour expiry
        logging.info(f"Valid password reset token decoded for: {email}")
    except SignatureExpired:
        flash('Password reset link has expired.', 'error')
        return redirect(url_for('forgot_password'))
    except BadTimeSignature: # More specific exception
        flash('Password reset link is invalid or tampered.', 'error')
        return redirect(url_for('forgot_password'))
    except Exception as e: # Catch other potential load errors
        logging.warning(f"Invalid password reset token error: {e}")
        flash('Invalid password reset link.', 'error')
        return redirect(url_for('forgot_password'))

    # Verify user exists
    user = get_user_by_email(email)
    if not user:
        flash('User account associated with this link not found.', 'error')
        return redirect(url_for('forgot_password'))

    # Handle Form
    form = ResetPasswordForm() if WTFORMS_AVAILABLE else None
    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        new_password = form.password.data if WTFORMS_AVAILABLE else request.form.get('password')
        confirm_password = form.confirm_password.data if WTFORMS_AVAILABLE else request.form.get('confirm_password')

        # Manual validation if WTForms not used
        if not WTFORMS_AVAILABLE:
             errors = []
             if not new_password or len(new_password) < 8: errors.append("Password must be at least 8 characters long.")
             if new_password != confirm_password: errors.append("Passwords do not match.")
             if errors:
                 for err in errors: flash(err, 'error')
                 # Pass token back to template for GET request rendering if validation fails
                 return render_template('reset_password.html', form=form, token=token)

        # --- Update Password in DB ---
        new_pw_hash = generate_password_hash(new_password)
        conn = None; cursor = None; updated = False; needs_rollback = False

        try: # Main try block for database transaction
            conn = get_db_connection()
            if not conn:
                # Check connection immediately after getting it
                flash('Database connection error. Cannot update password.', 'error')
                # Ensure conn is None if it failed, to prevent issues in finally
                conn = None
                return render_template('reset_password.html', form=form, token=token)

            cursor = conn.cursor() # Standard cursor for UPDATE
            needs_rollback = True
            sql = "UPDATE customers SET password_hash = %s WHERE email = %s AND customer_id = %s"
            params = (new_pw_hash, email, user['customer_id'])

            cursor.execute(sql, params)
            rows = cursor.rowcount # Get affected rows count
            logging.info(f"Password update query for {email}, rows affected: {rows}")

            if rows == 1:
                conn.commit() # Commit the change
                updated = True
                needs_rollback = False # Don't rollback after successful commit
                logging.info(f"Password updated successfully for {email}")
            elif rows == 0:
                # Could happen if user deleted between token generation and update
                logging.error(f"Password update failed (rows=0) for {email}. User mismatch or deleted?")
                flash('Password update failed (user mismatch or no change).', 'error')
            else: # Should not happen due to WHERE clause specificity
                logging.error(f"Password update affected unexpected rows ({rows}) for {email}. Rolling back.")
                flash('Password update failed (unexpected database state).', 'error')
                # Rollback will happen in finally

        except DBError as e: # Catch PostgreSQL specific errors
            logging.error(f"DB Error during password reset for {email}: {e}", exc_info=True)
            flash('Database error during password update.', 'error')
        except Exception as e: # Catch other unexpected errors
            logging.error(f"Unexpected error during password reset for {email}: {e}", exc_info=True)
            flash('Unexpected error during password update.', 'error')
        finally: # Cleanup for the database transaction try block
            # Check connection object exists and is not closed before cleanup
            if conn and not getattr(conn, 'closed', True):
                if needs_rollback:
                    try:
                        conn.rollback()
                        logging.warning(f"Password reset transaction rolled back for {email}.")
                    except DB_ERROR_TYPE as rb_err: # Use global DB_ERROR_TYPE
                        logging.error(f"Rollback attempt failed during password reset: {rb_err}")
                    except Exception as rb_gen_err:
                        logging.error(f"Unexpected error during reset rollback: {rb_gen_err}")

                # --- CORRECTED CURSOR CLOSE for Reset Password ---
                if cursor:
                    try:
                        cursor.close()
                    except DB_ERROR_TYPE: # Use global DB_ERROR_TYPE
                        pass # Ignore DB-specific errors closing cursor
                    except Exception as cur_close_err:
                        logging.warning(f"Non-DB error closing reset password cursor: {cur_close_err}")
                # --- END CORRECTION ---

                # Close the connection used for this operation
                close_db_connection(conn)
        # --- END of finally block ---

        # Redirect or re-render based on update success
        if updated:
            flash('Password has been reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            # Re-render form if update failed
            return render_template('reset_password.html', form=form, token=token)

    # Handle GET request (show the form)
    return render_template('reset_password.html', form=form, token=token)


@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    # --- Variable Initialization ---
    sender_id = None; receiver_id = None; amount = None; simulate_eve_checked = False
    logged_in_user_id = g.user['id']
    qkd_key = None; sim_res = {}; qber = -1.0; qkd_fail_reason = None
    log_status = "INITIATED"; fraud_res = {'is_fraudulent': False, 'reason': None, 'ml_score': -1.0}
    last_outcome = {'timestamp': datetime.datetime.now().isoformat(), 'status': 'Pending', 'reason': ''}
    session.pop('last_transfer_outcome', None) # Clear previous outcome from session

    # --- 1. Input Validation & Form Handling ---
    try:
        # Re-initialize for safety within try
        sender_id = None; receiver_id = None; amount = None; simulate_eve_checked = False

        # Get Sender Account Info
        user_accounts = get_accounts_data(customer_id_filter=logged_in_user_id)
        if user_accounts is None: raise ConnectionError("Database error fetching sender account.")
        if not user_accounts: raise ValueError("Sender account could not be found.")
        sender_account = user_accounts[0] # Assume first account for simplicity
        sender_id = sender_account['account_id']
        last_outcome['sender_id'] = sender_id

        # Handle Form Submission Data
        if WTFORMS_AVAILABLE:
            transfer_form = TransferForm(request.form) # Instantiate with POST data

            # Dynamically populate choices for validation to work correctly
            all_accounts = get_accounts_data()
            if all_accounts is None: raise ConnectionError("Database error fetching recipient list for validation.")
            receiver_choices_list = [acc for acc in all_accounts if acc.get('customer_id') != logged_in_user_id]
            # Ensure choice values are strings to match WTForms default behavior with SelectField
            transfer_form.receiver_account_id.choices = [('', '-- Select Recipient --')] + \
                                                        [(str(acc['account_id']), f"{acc['customer_name']} (Acc ID: {acc['account_id']})")
                                                         for acc in receiver_choices_list]

            if transfer_form.validate_on_submit(): # Validate the submitted data
                receiver_id_str = transfer_form.receiver_account_id.data
                amount = transfer_form.amount.data # WTForms DecimalField provides Decimal
                simulate_eve_checked = transfer_form.simulate_eve.data
                # Convert receiver_id_str to int AFTER successful validation
                try: receiver_id = int(receiver_id_str)
                except (ValueError, TypeError): raise ValueError("Invalid recipient ID format received.")
            else:
                # Collate errors if WTForms validation fails
                error_msg = "; ".join([f"{field.replace('_', ' ').title()}: {', '.join(errs)}"
                                        for field, errs in transfer_form.errors.items()])
                raise ValueError(f"Invalid input: {error_msg}")
        else:
            # Manual parsing if WTForms is unavailable
            receiver_id_str = request.form.get('receiver_account_id')
            amount_str = request.form.get('amount')
            simulate_eve_checked = 'simulate_eve' in request.form

            if not receiver_id_str: raise ValueError("Please select a recipient account.")
            try: receiver_id = int(receiver_id_str)
            except (ValueError, TypeError): raise ValueError("Invalid recipient account ID selected.")
            if not amount_str: raise ValueError("Amount is missing.")
            try: amount = Decimal(amount_str.strip())
            except InvalidOperation: raise ValueError("Invalid amount format (e.g., 100.50).")

        # --- Common Validations (Post-Parsing/Validation) ---
        if not isinstance(receiver_id, int): raise ValueError("Internal Error: Recipient ID is invalid.")
        if sender_id == receiver_id: raise ValueError("Cannot transfer funds to your own account.")
        if amount is None or amount <= 0: raise ValueError("Amount must be a positive value (e.g., greater than 0.00).")

        # --- Input Validated Successfully ---
        last_outcome.update({'amount': f"{amount:.2f}", 'receiver_id': receiver_id, 'simulate_eve': simulate_eve_checked})
        log_status = "INPUT_VALIDATED"
        logging.info(f"Transfer Request Validated: ₹{amount:.2f} from Acc {sender_id} to Acc {receiver_id} (Simulate Eve: {simulate_eve_checked})")

    except (ValueError, ConnectionError, TypeError, InvalidOperation, KeyError) as e:
        # Handle specific input, connection, or data type errors
        logging.warning(f"Transfer input/setup failed: {e}", exc_info=(isinstance(e, ConnectionError)))
        flash(f"Transfer Failed: {e}", "error")
        last_outcome.update({'status': 'Failed', 'reason': f"Input/Setup Error: {str(e)[:100]}"})
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        # Ensure amount is Decimal before logging failure
        amount_for_log = amount if isinstance(amount, Decimal) else (Decimal(amount) if amount is not None else Decimal('0.00'))
        log_failed_attempt(sender_id, receiver_id, amount_for_log, "INPUT_ERROR", exception_info=e)
        return redirect(url_for('index'))
    except Exception as e:
         # Catch any other unexpected errors during the input phase
         logging.error(f"Unexpected error during transfer input validation: {e}", exc_info=True)
         flash("An unexpected error occurred while processing your request.", "error")
         last_outcome.update({'status': 'Failed', 'reason': "Unexpected Input Error"})
         session['last_transfer_outcome'] = last_outcome; session.modified = True
         amount_for_log = amount if isinstance(amount, Decimal) else (Decimal(amount) if amount is not None else Decimal('0.00'))
         log_failed_attempt(sender_id, receiver_id, amount_for_log, "UNEXPECTED_INPUT_ERR", exception_info=e)
         return redirect(url_for('index'))

    # --- 2. QKD Simulation ---
    qber_thresh = current_app.config['QBER_THRESHOLD']; n_qubits = QKD_NUM_QUBITS; eve_rate = 0.25 if simulate_eve_checked else 0.0
    qkd_fraud_reason = None # Specific reason if QKD indicates high QBER
    try:
        log_status = "QKD_RUNNING"
        logging.info(f"Running QKD simulation: N={n_qubits}, Eve={simulate_eve_checked}, Rate={eve_rate:.2f}, Thresh={qber_thresh:.3f}")
        # Call the simulation function
        sim_res = simulate_bb84(n_qubits=n_qubits, simulate_eve=simulate_eve_checked, qber_threshold=qber_thresh, eve_interception_rate=eve_rate)

        # Store result in session and update outcome
        session[f'last_qkd_log_{logged_in_user_id}'] = sim_res; session.modified = True
        last_outcome['qkd_log_stored'] = True

        # Extract results
        key_bin = sim_res.get('final_key_binary')
        qber = sim_res.get('qber', -1.0) # Default to -1 if key missing
        eve_det = sim_res.get('eve_detected', False) # Default to False
        qber_disp = f"{qber:.4f}" if qber is not None and qber >= 0 else 'N/A'
        last_outcome['qber'] = qber_disp
        key_len_bits = len(key_bin or '')
        logging.info(f"QKD Simulation Result: QBER={qber_disp}, Eve Detected={eve_det}, Key Length={key_len_bits} bits")

        # Check QKD failure conditions
        min_key_len = 128 # Minimum bits required for a reasonable derived key (adjust as needed)
        if qber < 0: # Indicates simulation error (e.g., insufficient qubits)
             qkd_fail_reason = f"QKD Simulation Error (Code: {qber}). Check simulation parameters or logs."
             log_status = "QKD_SIM_ERR"
        elif eve_det: # QBER exceeded threshold
             qkd_fail_reason = f"High QBER ({qber_disp}) detected, exceeds threshold ({qber_thresh:.3f}). Potential Eavesdropping."
             log_status = "QKD_EVE_DETECTED"
             qkd_fraud_reason = "QKD Security Alert: High Quantum Bit Error Rate detected."
        elif not key_bin or key_len_bits < min_key_len: # Key too short or missing
             qkd_fail_reason = f"Generated key is too short ({key_len_bits} bits, requires {min_key_len})."
             log_status = "QKD_KEY_INSUFFICIENT"

        # Raise error if any failure condition met
        if qkd_fail_reason:
            raise ValueError(f"QKD Failed: {qkd_fail_reason}")

        # If successful, derive the Fernet key
        key_hash = hashlib.sha256(key_bin.encode('utf-8')).digest() # SHA-256 hash (32 bytes)
        qkd_key = base64.urlsafe_b64encode(key_hash) # Base64 encode for Fernet
        logging.info(f"QKD successful (QBER:{qber_disp}). Fernet key derived.")
        log_status = "QKD_SUCCESS"
        last_outcome['qkd_status_msg'] = "Secure Channel OK"

    except ValueError as qkd_e: # Catch specific QKD failures raised above
        logging.warning(f"QKD Failure during transfer: {qkd_e}")
        flash(f"Transfer Aborted: {qkd_e}", "danger") # Show specific reason
        last_outcome.update({'status': 'Failed', 'reason': qkd_fail_reason or str(qkd_e), 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=qkd_fraud_reason, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        return redirect(url_for('index'))
    except Exception as qkd_e: # Catch unexpected errors during QKD process
        logging.error(f"Unexpected QKD Simulation Error: {qkd_e}", exc_info=True)
        log_status = "QKD_INTERNAL_ERR"
        flash('Transfer Aborted: An internal error occurred during secure channel setup.', 'danger')
        last_outcome.update({'status': 'Failed', 'reason': 'QKD Internal Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        return redirect(url_for('index'))

    # --- 3. Database Transaction, Fraud Check, and Finalization ---
    conn = None; cursor = None; needs_rollback = False; log_id = None
    try:
        # Ensure QKD key is present
        if not qkd_key:
            raise ValueError("Internal error: QKD key generation failed silently.")

        log_status = "DB_TXN_STARTING"
        conn = get_db_connection()
        if not conn:
            raise ConnectionError("Database service unavailable. Cannot complete transfer.")

        # Use DictCursor for easier data access, potentially named for server-side if needed
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
        needs_rollback = True # Assume rollback needed until commit

        # --- Lock & Validate Sender Account ---
        log_status = "DB_VALIDATE_SENDER"
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_info = cursor.fetchone()
        if not sender_info: raise ValueError(f"Sender account {sender_id} could not be found or locked.")
        # ** Critical Authorization Check **
        if sender_info['customer_id'] != logged_in_user_id:
            logging.critical(f"AUTHORIZATION FAILED: User {logged_in_user_id} attempted transfer from account {sender_id} owned by {sender_info['customer_id']}.")
            raise ValueError("Authorization Error: You do not own the source account.")
        sender_bal = Decimal(sender_info['balance'])
        if sender_bal < amount:
            raise ValueError(f"Insufficient funds. Your balance is ₹{sender_bal:.2f}, attempted transfer of ₹{amount:.2f}.")

        # --- Validate Receiver Account ---
        log_status = "DB_VALIDATE_RECEIVER"
        cursor.execute("SELECT a.account_id, c.customer_name, a.balance FROM accounts a JOIN customers c ON a.customer_id=c.customer_id WHERE a.account_id=%s", (receiver_id,))
        rx_info = cursor.fetchone()
        if not rx_info: raise ValueError(f"Receiver account {receiver_id} not found.")
        rx_name = rx_info['customer_name']
        last_outcome['receiver_name'] = rx_name # Store receiver name for outcome display

        # --- Fraud Detection ---
        log_status = "FRAUD_CHECK_RUNNING"
        logging.info("Running fraud detection analysis...")
        hist_ml = [] # Initialize history list
        try: # Fetch history safely
            sql_history = "SELECT amount, timestamp FROM qkd_transaction_log WHERE sender_account_id=%s AND qkd_status NOT LIKE '%%FAIL%%' AND qkd_status NOT LIKE '%%ERR%%' ORDER BY timestamp DESC LIMIT 10"
            cursor.execute(sql_history, (sender_id,))
            history_raw = cursor.fetchall()
            for r in history_raw:
                 try:
                     if r['amount'] is not None and isinstance(r['timestamp'], datetime.datetime):
                         hist_ml.append({'amount': Decimal(r['amount']), 'timestamp': r['timestamp']})
                 except (InvalidOperation, TypeError, ValueError) as hist_e: logging.warning(f"Skipping history record processing: {hist_e} - {r}")
        except DBError as db_hist_err: logging.error(f"DB Error fetching history for fraud check: {db_hist_err}"); flash("Warning: Error retrieving history for fraud check.", "warning")
        except Exception as e_hist: logging.error(f"Unexpected error fetching history: {e_hist}", exc_info=True); flash("Warning: Error preparing fraud check.", "warning")

        # Prepare data and call fraud detection function
        current_txn_data = {'amount': amount, 'recipient_username': rx_name, 'timestamp': datetime.datetime.now()}
        fraud_cfg = {'blacklist': app.config['FRAUD_BLACKLIST']}
        try: fraud_res = detect_fraud(current_txn_data, hist_ml, **fraud_cfg)
        except Exception as fraud_ml_err: logging.error(f"ML Fraud detection call failed: {fraud_ml_err}", exc_info=True); fraud_res = {'is_fraudulent': False, 'reason': 'Fraud Check Error', 'ml_score': -1}; flash("Warning: Fraud check error.", "warning")

        # Process fraud results and combine with QKD alert status
        last_outcome['fraud_check'] = fraud_res
        is_fraudulent_ml = fraud_res.get('is_fraudulent', False)
        ml_fraud_reason = fraud_res.get('reason')
        final_fraud_reason = qkd_fraud_reason # QKD reason takes precedence
        if is_fraudulent_ml:
             if not final_fraud_reason: final_fraud_reason = ml_fraud_reason
             elif ml_fraud_reason and ml_fraud_reason != qkd_fraud_reason: final_fraud_reason += f"; {ml_fraud_reason}"
        final_is_flagged = bool(qkd_fraud_reason) or is_fraudulent_ml # Flagged if QKD alert OR fraud detected
        if final_is_flagged: logging.warning(f"ALERT: {final_fraud_reason}")
        else: logging.info("Fraud check passed and no QKD alert.")
        qkd_status_final = "SECURED_FLAGGED" if final_is_flagged else "SECURED"
        last_outcome['qkd_status_msg'] = qkd_status_final.replace('_',' ')

        # --- Encrypt Confirmation Details ---
        log_status = "ENCRYPTING_DATA"
        msg_to_encrypt = f"CONF;{sender_id}>{receiver_id};AMT:{amount:.2f};QBER:{qber_disp};FLAGGED:{final_is_flagged};R:{final_fraud_reason or 'N/A'};T:{datetime.datetime.now().isoformat()}"
        try:
            fernet_cipher = Fernet(qkd_key)
            enc_b64 = fernet_cipher.encrypt(msg_to_encrypt.encode('utf-8')).decode('utf-8')
            last_outcome['enc_sample'] = enc_b64[:60]+'...' # Sample for outcome display
        except InvalidToken: log_status = "ENC_KEY_ERR"; raise ValueError("Internal error: Invalid encryption key.")
        except Exception as fe: log_status = "ENC_FAIL"; raise ValueError(f"Internal error: Encryption failed: {fe}")

        # --- Update Account Balances ---
        log_status = "DB_UPDATING_BALANCES"
        new_sender_bal = sender_bal - amount
        # Lock receiver row for update before calculating new balance
        cursor.execute("SELECT balance FROM accounts WHERE account_id=%s FOR UPDATE", (receiver_id,))
        rx_bal_row_locked = cursor.fetchone()
        if not rx_bal_row_locked: raise ValueError(f"Receiver account {receiver_id} disappeared before balance update.")
        new_receiver_bal = Decimal(rx_bal_row_locked['balance']) + amount

        # Execute balance updates
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_sender_bal), sender_id))
        if cursor.rowcount != 1: raise DBError(f"Sender balance update failed (rows={cursor.rowcount})")
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_receiver_bal), receiver_id))
        if cursor.rowcount != 1: raise DBError(f"Receiver balance update failed (rows={cursor.rowcount})")
        logging.info("Account balances updated successfully.")

        # --- Log Successful Transaction ---
        log_status = "DB_LOGGING_TXN"
        log_sql = """
            INSERT INTO qkd_transaction_log (
                sender_account_id, receiver_account_id, amount, qkd_status,
                encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason,
                timestamp
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING log_id
            """ # Use RETURNING for PostgreSQL
        log_qber_val = qber if qber is not None and qber >= 0 else None
        log_fraud_reason_val = final_fraud_reason[:255] if final_fraud_reason else None # Truncate reason
        log_values = (
            sender_id, receiver_id, str(amount), qkd_status_final, enc_b64, None, # iv is NULL
            log_qber_val, final_is_flagged, log_fraud_reason_val, datetime.datetime.now()
        )
        cursor.execute(log_sql, log_values)
        # Fetch the returned log_id
        log_row = cursor.fetchone()
        if log_row and len(log_row) > 0:
             log_id = log_row[0] # Or log_row['log_id'] if using DictCursor consistently
        else:
             raise DBError("Failed to retrieve log ID after insert using RETURNING.")
        last_outcome['log_id'] = log_id
        logging.info(f"Transaction successfully logged with ID: {log_id}")

        # --- Commit Transaction ---
        log_status = "DB_COMMITTING"
        conn.commit()
        needs_rollback = False # Commit successful, no rollback needed
        logging.info("Database transaction committed successfully.")
        last_outcome['status'] = 'Success' # Set final outcome

        # --- Flash Success Message ---
        flash_msg = f"Success! ₹{amount:.2f} sent. Log ID: {log_id}. Status: {qkd_status_final.replace('_',' ')} (QBER:{qber_disp})."
        flash_cat = "success"
        if final_is_flagged:
            short_reason = (final_fraud_reason or 'Flagged').split(';')[0]
            flash_msg = f"Success (Log ID: {log_id}), but transfer FLAGGED: {short_reason}. QBER: {qber_disp}."
            flash_cat = "warning"
        flash(flash_msg, flash_cat)

    # --- Exception Handling for the Main Transaction Block ---
    except (DBError, ValueError, InvalidOperation, ConnectionError, AssertionError) as e: # Catch specific errors
        error_message = str(e)
        # Determine failure status code if not already set by QKD/Encryption
        if log_status.startswith("DB_") or log_status in ["INITIATED", "FRAUD_CHECK_RUNNING", "ENCRYPTING_DATA"]:
            if isinstance(e, (ValueError, AssertionError)): log_status = "VALIDATION_FAIL"
            elif isinstance(e, ConnectionError): log_status = "DB_CONN_ERR"
            elif isinstance(e, DBError): log_status = "DB_TXN_ERR"
            else: log_status = "UNKNOWN_TXN_FAIL"
        logging.error(f"Transaction Error ({log_status}) during transfer {sender_id}->{receiver_id}: {error_message}", exc_info=True)
        last_outcome.update({'status': 'Failed', 'reason': error_message[:200], 'qkd_status_msg': log_status.replace('_',' ')})
        flash(f"Transfer Failed: {error_message}" if log_status == "VALIDATION_FAIL" else "Transfer Failed due to a system error.", "error")
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=f"Txn Error: {error_message[:100]}", exception_info=e)

    except Exception as e: # Catch any other unexpected errors
        log_status = "UNEXPECTED_TXN_ERR"; error_message = str(e)
        logging.critical(f"CRITICAL UNEXPECTED Error during transfer {sender_id}->{receiver_id}: {error_message}", exc_info=True)
        flash("Transfer Failed due to a critical unexpected error.", "danger")
        last_outcome.update({'status': 'Failed', 'reason': 'Critical Unexpected Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason="Critical Unexpected Error", exception_info=e)

    # --- Finally Block for Cleanup (Rollback/Close Resources) ---
    finally:
        # Ensure connection and cursor are closed properly
        if conn and not getattr(conn, 'closed', True): # Check connection exists and not closed
            if needs_rollback: # Check if rollback is needed (commit didn't happen)
                try:
                    conn.rollback()
                    logging.info(f"Transfer transaction rolled back (Final Status before rollback: {log_status}).")
                except DBError as rb_err:
                    logging.error(f"Rollback failed during transfer error handling: {rb_err}")
                except Exception as rb_gen_err:
                     logging.error(f"Unexpected error during transfer rollback: {rb_gen_err}")

            # Close cursor if it exists and is not already closed
            if cursor and not getattr(cursor, 'closed', True):
                 try:
                     cursor.close()
                 except DBError: # Ignore psycopg2 errors closing cursor
                     pass
                 except Exception as cur_close_err:
                     logging.error(f"Unexpected error closing transfer cursor: {cur_close_err}")

            # Always attempt to close the connection obtained in this try block
            close_db_connection(conn)

    # --- After try/except/finally ---
    # Store final outcome in session and redirect back to index
    session['last_transfer_outcome'] = last_outcome
    session.modified = True
    return redirect(url_for('index'))


@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays transaction history for the logged-in user."""
    user_id = g.user['id']
    display_log = [] # Initialize list to hold formatted log entries
    conn = None # Initialize connection outside try
    cursor = None # Initialize cursor outside try

    try:
        conn = get_db_connection() # Attempt to get DB connection
        if not conn:
            # If connection failed, flash error and return template with empty list
            flash("Database connection error. Cannot load history.", "error")
            return render_template('history.html', log_entries=[], user_id=user_id)

        # Use DictCursor for easier row access by column name (PostgreSQL specific)
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # SQL query to fetch relevant transaction logs
        sql = """
            SELECT
                l.log_id, l.timestamp AS ts,
                l.sender_account_id AS sender_id,
                s_cust.customer_name AS sender_name,
                s_acc.customer_id AS sender_cust_id,
                l.receiver_account_id AS receiver_id,
                r_cust.customer_name AS receiver_name,
                r_acc.customer_id AS receiver_cust_id,
                l.amount, l.qkd_status, l.qber_value AS qber,
                l.encrypted_confirmation AS enc_confirm,
                l.is_flagged, l.fraud_reason
            FROM qkd_transaction_log l
            LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
            LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
            LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
            LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
            WHERE s_acc.customer_id = %s OR r_acc.customer_id = %s
            ORDER BY l.timestamp DESC
            LIMIT 100
            """
        cursor.execute(sql, (user_id, user_id))
        entries_raw = cursor.fetchall() # Fetch all matching rows

        # Process each fetched row
        for entry in entries_raw:
            try: # Inner try for formatting each individual log entry
                # Safely get and format amount
                amt = Decimal(entry.get('amount', '0.00'))

                # Safely format QBER
                qber_raw = entry.get('qber')
                qber_val = f"{qber_raw:.3f}" if qber_raw is not None and isinstance(qber_raw, (float, Decimal)) else "N/A"

                # Determine encrypted status (show N/A for failed txns)
                qkd_status = entry.get('qkd_status','N/A')
                enc_status = "[Encrypted]" if entry.get('enc_confirm') else "[N/A]"
                if "FAIL" in qkd_status or "ERR" in qkd_status:
                     enc_status = "[N/A - Failed Txn]"

                # Format flagged status and reason
                is_flagged = entry.get('is_flagged', False)
                raw_reason = entry.get('fraud_reason')
                display_reason = raw_reason if is_flagged and raw_reason else ("Yes" if is_flagged else "No")

                # Determine direction relative to the logged-in user
                direction = "Sent" if entry.get('sender_cust_id') == user_id else \
                            ("Received" if entry.get('receiver_cust_id') == user_id else "")

                # Append formatted data to display list
                display_log.append({
                    'id': entry.get('log_id'), # Use get for safety
                    'timestamp': entry.get('ts').strftime('%Y-%m-%d %H:%M:%S') if entry.get('ts') else 'N/A',
                    'sender': f"{entry.get('sender_name', '?')} ({entry.get('sender_id', '?')})",
                    'receiver': f"{entry.get('receiver_name', '?')} ({entry.get('receiver_id', '?')})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': qkd_status.replace('_', ' '), # Make status readable
                    'qber': qber_val,
                    'encrypted_details_status': enc_status,
                    'is_flagged_display': display_reason, # Display reason or Yes/No
                    'fraud_reason': raw_reason, # Keep raw reason for potential tooltips etc.
                    'is_flagged': is_flagged, # Boolean value for template logic
                    'direction': direction # Sent/Received indicator
                })
            except Exception as display_err:
                # Log if formatting a specific entry fails, but continue with others
                logging.warning(f"Error formatting log entry {entry.get('log_id', '?')} for history display: {display_err}")

    except DBError as e: # Catch PostgreSQL specific errors during query
        flash(f"Database error retrieving history: {e}", "error")
        logging.error(f"History Database Error for user {user_id}: {e}", exc_info=True)
        # Return template with empty list as display_log will be empty
    except Exception as e: # Catch other unexpected errors
        flash("An unexpected error occurred while loading history.", "error")
        logging.error(f"Unexpected History Error for user {user_id}: {e}", exc_info=True)
        # Return template with empty list
    finally: # Ensure resources are cleaned up
        # *** CORRECTED FINALLY BLOCK ***
        if cursor:
            try:
                cursor.close()
            except DBError: # Use DBError
                pass # Ignore DB errors during close
            except Exception as cur_close_err:
                logging.error(f"Unexpected error closing history cursor: {cur_close_err}")
        # Always close the connection if it was obtained
        if conn: # Check if conn was successfully assigned
             close_db_connection(conn)
        # *** END CORRECTION ***

    # Render the template with the processed log entries (or empty list on error)
    return render_template('history.html', log_entries=display_log, user_id=user_id)

@app.route('/qkd')
@login_required
def qkd_page():
    """Displays QKD info, last sim log, and QBER chart."""
    user_id = g.user['id']
    logging.info(f"--- User {user_id} accessing QKD page ---")

    # --- 1. Get Last Simulation Log ---
    sim_log = None
    log_key = f'last_qkd_log_{user_id}'
    try:
        sim_log = session.get(log_key, None)
        logging.debug(f"Retrieved sim_log from session key '{log_key}': {type(sim_log)}")
    except Exception as session_err:
        logging.error(f"Error retrieving QKD log from session user {user_id}: {session_err}", exc_info=True)
        flash("Could not load previous simulation data.", "warning")

    # --- 2. Prepare Threshold Values ---
    qber_threshold_original = 0.15 # Default original value
    qber_threshold_pct = 15.0      # Default percentage value
    try:
        qber_threshold_config = current_app.config['QBER_THRESHOLD']
        qber_threshold_original = float(qber_threshold_config)
        qber_threshold_pct = qber_threshold_original * 100
        logging.debug(f"QBER Thresholds: Original={qber_threshold_original}, Percent={qber_threshold_pct}")
    except (ValueError, TypeError, KeyError) as thresh_err:
         logging.error(f"Invalid or missing QBER_THRESHOLD config: {thresh_err}")
         flash("Threshold config error. Using default.", "warning")
         # Keep default values defined above

    # --- 3. Fetch QBER History for Chart ---
    labels = []; values = []
    conn = None; cursor = None; limit = 15 # Max history points for chart

    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
            sql = """
                SELECT l.log_id, l.timestamp, l.qber_value AS qber
                FROM qkd_transaction_log l
                LEFT JOIN accounts s ON l.sender_account_id=s.account_id
                LEFT JOIN accounts r ON l.receiver_account_id=r.account_id
                WHERE (s.customer_id=%s OR r.customer_id=%s)
                  AND l.qber_value IS NOT NULL AND l.qber_value >= 0
                  AND (l.qkd_status LIKE 'SECURED%%' OR l.qkd_status = 'QKD_EVE_DETECTED')
                ORDER BY l.timestamp DESC
                LIMIT %s
                """
            cursor.execute(sql, (user_id, user_id, limit))
            history = cursor.fetchall()
            history.reverse() # Oldest first for chart display

            for entry in history:
                 log_id = entry.get('log_id'); qber_val = entry.get('qber'); ts = entry.get('timestamp')
                 if log_id and qber_val is not None and ts:
                     label = f"{ts.strftime('%m/%d %H:%M')} (ID:{log_id})" # Format label
                     try:
                         labels.append(label)
                         values.append(round(float(qber_val) * 100, 2)) # Calculate percentage
                     except (ValueError, TypeError):
                         logging.warning(f"Skipping QBER chart entry {log_id}: Invalid QBER value '{qber_val}'")
                         # Continue to next entry, don't append bad data
                 else:
                      logging.warning(f"Skipping QBER history entry due to missing data: {entry}")
        else:
            # Connection failed
            labels, values = ['DB Unavailable'], [0]
            flash("Database connection error loading QBER history.", "error")

    except DBError as e: # Catch PostgreSQL errors
        logging.error(f"QBER history DB error for user {user_id}: {e}", exc_info=True)
        labels, values = ['DB Error'], [0]
        flash("Database error loading QBER history.", "error")
    except Exception as e: # Catch other unexpected errors
        logging.error(f"QBER history unexpected error for user {user_id}: {e}", exc_info=True)
        labels, values = ['Processing Error'], [0]
        flash("Unexpected error loading QBER history.", "error")
    finally:
        # --- Corrected Finally Block ---
        if cursor:
            try:
                cursor.close()
            except DBError: # Use DBError
                pass # Ignore DB errors closing cursor
            except Exception as cur_close_err:
                logging.error(f"Unexpected error closing QKD page cursor: {cur_close_err}")
        # Check connection before closing
        if conn:
            close_db_connection(conn)
        # --- End Correction ---

    # Set default chart data if history fetch failed or returned empty
    if not labels:
        labels, values = ['No Recent QBER History'], [0]

    # --- 4. Render Template ---
    try:
        return render_template('qkd.html',
                           simulation_log=sim_log,
                           QBER_THRESHOLD_PCT=qber_threshold_pct,
                           QBER_THRESHOLD_ORIGINAL=qber_threshold_original, # Pass original for comparisons
                           qber_history_labels=labels,
                           qber_history_values=values)
    except Exception as render_err:
         logging.error(f"Error rendering qkd.html template: {render_err}", exc_info=True)
         abort(500) # Trigger 500 handler if template render fails

@app.route('/qkd/report/download')
@login_required
def download_qkd_report():
    user_id = g.user['id']; sim_log = session.get(f'last_qkd_log_{user_id}')
    if not sim_log: flash("No QKD data found.", "warning"); return redirect(url_for('qkd_page'))
    logging.info(f"User {user_id} downloading QKD sim report.")
    try:
        pdf_bytes = create_qkd_simulation_report(sim_log)
        if not pdf_bytes: logging.error("QKD PDF generation failed."); flash("Failed QKD PDF generation.", "danger"); return redirect(url_for('qkd_page'))
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); fname = f"QKD_Sim_Report_{ts}.pdf"
        logging.info(f"Serving QKD Sim PDF '{fname}'"); return Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": f"attachment;filename={fname}"})
    except Exception as e: logging.error(f"QKD PDF report error: {e}", exc_info=True); flash("QKD report error.", "danger"); return redirect(url_for('qkd_page'))

@app.route('/quantum-impact')
def quantum_impact(): return render_template("quantum_impact.html")

@app.route('/about')
def about(): return render_template("about.html")

def get_flagged_transactions(user_id, limit=50):
    """
    Fetches recently flagged transactions involving the user.
    Adapted for PostgreSQL.
    """
    txns = [] # Initialize list for results
    conn = None # Initialize connection outside try
    cursor = None # Initialize cursor outside try

    try:
        conn = get_db_connection() # Attempt to get connection
        if not conn:
            logging.error(f"DB Connection failed fetching flagged tx for user {user_id}")
            # No flash here, let calling route handle UI message if needed
            return txns # Return empty list

        # Use DictCursor for easier access by column name
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        sql = """
            SELECT
                l.log_id, l.timestamp AS ts,
                s_cust.customer_name AS sender,
                r_cust.customer_name AS receiver,
                l.amount, l.fraud_reason
            FROM qkd_transaction_log l
            LEFT JOIN accounts s ON l.sender_account_id = s.account_id
            LEFT JOIN customers s_cust ON s.customer_id = s_cust.customer_id
            LEFT JOIN accounts r ON l.receiver_account_id = r.account_id
            LEFT JOIN customers r_cust ON r.customer_id = r_cust.customer_id
            WHERE (s.customer_id = %s OR r.customer_id = %s) -- User involved as sender OR receiver
              AND l.is_flagged = TRUE -- Only flagged transactions
            ORDER BY l.timestamp DESC
            LIMIT %s
            """
        cursor.execute(sql, (user_id, user_id, limit))
        raw_flagged_txns = cursor.fetchall() # Fetch all results

        # Process results safely
        for entry in raw_flagged_txns:
             try: # Inner try to handle formatting errors for individual rows
                 # Safely convert amount
                 amt_val = entry.get('amount')
                 amt = Decimal(amt_val) if amt_val is not None else Decimal('0.00')
                 # Safely format timestamp
                 ts_val = entry.get('ts')
                 ts_str = ts_val.strftime('%Y-%m-%d %H:%M:%S') if isinstance(ts_val, datetime.datetime) else 'N/A'
                 # Append formatted dict to results list
                 txns.append({
                     'id': entry.get('log_id'), # Use get for safety
                     'timestamp': ts_str,
                     'sender': f"{entry.get('sender', '?')}", # Use get for safety
                     'receiver': f"{entry.get('receiver', '?')}",
                     'amount': f"{amt:.2f}",
                     'fraud_reason': entry.get('fraud_reason', 'N/A') # Use get with default
                 })
             except (InvalidOperation, TypeError, ValueError) as fe:
                 logging.warning(f"Error formatting flagged tx data {entry.get('log_id', '?')}: {fe}")
             except Exception as fe_other: # Catch unexpected formatting errors
                  logging.error(f"Unexpected error formatting flagged tx {entry.get('log_id', '?')}: {fe_other}", exc_info=True)

    except DBError as e: # Catch PostgreSQL specific errors
        logging.error(f"Flagged tx DB error user {user_id}: {e}", exc_info=True)
        # Flash message should be handled by the route calling this function
        # flash("Error loading flagged transaction data.", "error") # Avoid flashing in helper
    except Exception as e: # Catch other unexpected errors during fetch/processing
        logging.error(f"Unexpected error loading flagged tx user {user_id}: {e}", exc_info=True)
        # flash("Unexpected error loading flagged transactions.", "error") # Avoid flashing in helper
    finally: # Ensure resources are always cleaned up
        # *** CORRECTED FINALLY BLOCK ***
        if cursor:
            try:
                cursor.close()
            except DBError: # Use DBError
                pass # Ignore DB errors during close
            except Exception as cur_close_err:
                logging.error(f"Unexpected error closing flagged_txns cursor: {cur_close_err}")
        # Check connection before closing
        if conn:
            close_db_connection(conn)
        # *** END CORRECTION ***

    # Return the list of formatted transactions (might be empty)
    return txns

@app.route('/profile')
@login_required
def profile():
    """Displays the user profile page with details and logout."""
    user_id = g.user['id']
    account = None # Initialize account to None
    conn = None # Initialize connection variable
    cursor = None # Initialize cursor variable
    db_type = "Unknown" # To track which DB is being used

    try:
        conn = get_db_connection() # Get connection first
        if not conn:
            # Raise an error or handle appropriately if connection failed
            raise ConnectionError("Database connection failed.")

        # --- Cursor Creation based on DB type ---
        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            # Using PostgreSQL (check instance type for safety)
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db_type = "PostgreSQL"
        elif MYSQL_AVAILABLE and hasattr(conn, 'is_connected'): # Heuristic for MySQL conn
            # Using MySQL
            cursor = conn.cursor(dictionary=True)
            db_type = "MySQL"
        else:
            # Fallback (might error later, but attempts basic cursor)
            cursor = conn.cursor()
            db_type = "Fallback"
        logging.debug(f"Profile: Using {db_type} cursor.")
        # --- End Cursor Creation ---

        # Fetch the primary account associated with the customer ID
        cursor.execute("""
            SELECT account_id, account_number, balance
            FROM accounts
            WHERE customer_id = %s
            ORDER BY account_id ASC
            LIMIT 1
        """, (user_id,))
        account_raw = cursor.fetchone() # Fetches as RealDictRow (psql) or dict (mysql)

        if account_raw:
             # Ensure balance is Decimal
             try:
                 # Convert balance via string for better cross-DB compatibility
                 raw_balance = account_raw.get('balance', '0.00') # Get balance safely
                 account_raw['balance'] = Decimal(str(raw_balance))
             except (InvalidOperation, TypeError, ValueError) as dec_err:
                  logging.warning(f"Profile: Could not convert balance '{raw_balance}' to Decimal for user {user_id}: {dec_err}")
                  account_raw['balance'] = Decimal('0.00') # Default on error

             # Convert row to standard dict before passing to template
             account = dict(account_raw)
        else:
             logging.warning(f"No account found for user {user_id} in profile page.")

    # --- Catch appropriate DB Error ---
    except DB_ERROR_TYPE as e: # Use the DB_ERROR_TYPE defined based on environment
        logging.error(f"Profile: DB error fetching account details (User {user_id}) using {db_type}: {e}")
        flash("Could not load account details due to a database error.", "warning")
    # --- Catch ConnectionError specifically ---
    except ConnectionError as e:
         logging.error(f"Profile: Connection Error for user {user_id}: {e}")
         flash(str(e), "error") # Show connection error message
    # --- Catch other potential errors ---
    except Exception as e:
         logging.error(f"Profile: Unexpected error fetching account details (User {user_id}): {e}", exc_info=True)
         flash("An unexpected error occurred while loading profile details.", "warning")
    # --- Ensure cleanup in finally ---
    finally:
        if cursor:
            try: cursor.close()
            # Catch potential close errors for the specific DB type or fallback
            except DB_ERROR_TYPE: pass
            except Exception: pass
        if conn:
            # Use your existing close_db_connection helper
            close_db_connection(conn)

    # Pass user (from g) and account details (fetched or None) to the template
    return render_template('profile.html', user=g.user, account=account)
  
@app.route('/fraud')
@login_required
def fraud_page():
    """Displays the fraud center page."""
    user_id = g.user['id']
    logging.info(f"User {user_id} accessing fraud page.")
    flagged_txns = get_flagged_transactions(user_id)
    # Flash message if retrieval failed (get_flagged_transactions returns empty on error)
    # is handled within get_flagged_transactions or the calling route could check len()
    return render_template("fraud.html", flagged_txns=flagged_txns)

def get_log_entry_details(log_id):
    """
    Fetches detailed information for a specific transaction log entry.
    Adapted for PostgreSQL. Returns dict or None.
    """
    details = None
    conn = None # Initialize outside try
    cursor = None
    logging.info(f"--- Fetching log details for log_id: {log_id} ---")

    try:
        conn = get_db_connection() # Attempt connection
        if not conn:
            logging.error(f"DB Connection failed fetching log details for {log_id}")
            return None # Cannot proceed without connection

        # Use DictCursor for easy column access by name
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # SQL query to fetch transaction log and join with customer names
        sql = """
            SELECT
                l.*, -- Select all columns from the log table
                s_acc.customer_id AS sender_cust_id,
                s_cust.customer_name AS sender_name,
                r_acc.customer_id AS receiver_cust_id,
                r_cust.customer_name AS receiver_name
            FROM qkd_transaction_log l
            LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
            LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
            LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
            LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
            WHERE l.log_id = %s
            """
        cursor.execute(sql, (log_id,))
        entry = cursor.fetchone() # Fetch one row (DictRow object or None)
        logging.debug(f"Raw DB entry fetched for log {log_id}: {'Found' if entry else 'Not Found'}")

        if entry:
            # Inner try block for safe data formatting
            try:
                # Safely get and format amount
                amt_val = entry.get('amount')
                amt_decimal = Decimal(amt_val) if amt_val is not None else Decimal('0.00')
                amount_display = f"{amt_decimal:.2f}"

                # Safely get and format QBER
                qber_val = entry.get('qber_value')
                qber_display = f"{qber_val:.4f}" if qber_val is not None and isinstance(qber_val, (float, Decimal)) else "N/A"

                # Safely get and format timestamp
                ts_val = entry.get('timestamp')
                timestamp_display = ts_val.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(ts_val, datetime.datetime) else 'N/A'

                # Get flag status and reason
                is_flagged = entry.get('is_flagged', False)
                raw_reason = entry.get('fraud_reason')
                # Assign reason only if actually flagged, otherwise None
                reason_display = raw_reason if is_flagged and raw_reason else None

                # Get encrypted data, ensure None if missing or "None" string
                enc_data = entry.get('encrypted_confirmation')
                enc_data = enc_data if enc_data and enc_data != 'None' else None

                # Format sender/receiver details safely
                sender_name = entry.get('sender_name', '?')
                sender_acc_id = entry.get('sender_account_id', '?')
                receiver_name = entry.get('receiver_name', '?')
                receiver_acc_id = entry.get('receiver_account_id', '?')
                sender_details = f"{sender_name} (Account ID: {sender_acc_id})"
                receiver_details = f"{receiver_name} (Account ID: {receiver_acc_id})"

                # Construct the final dictionary
                details = {
                    'log_id': entry.get('log_id'), # Use get for safety
                    'sender_customer_id': entry.get('sender_cust_id'),
                    'receiver_customer_id': entry.get('receiver_cust_id'),
                    'timestamp': timestamp_display,
                    'sender_details': sender_details,
                    'receiver_details': receiver_details,
                    'amount': amount_display,
                    'qkd_status': entry.get('qkd_status', 'N/A').replace('_', ' '),
                    'qber': qber_display,
                    'encrypted_confirmation_data': enc_data, # Contains data or None
                    'is_flagged': is_flagged,
                    'fraud_reason': reason_display, # Contains reason string or None
                }
                logging.debug(f"Formatted details dictionary for log {log_id}: {details}")

            except (InvalidOperation, TypeError, ValueError) as format_err:
                logging.error(f"Error formatting data for log ID {log_id}: {format_err}")
                details = None # Set details to None if formatting fails
            except Exception as format_err:
                 logging.error(f"Unexpected error formatting log {log_id}: {format_err}", exc_info=True)
                 details = None
        else:
            logging.warning(f"Log entry with ID {log_id} not found in DB.")
            details = None # Ensure details is None if entry not found

    except DBError as e: # Catch PostgreSQL specific errors
        logging.error(f"Database error fetching details for log ID {log_id}: {e}", exc_info=True)
        details = None # Ensure details is None on DB error
    except Exception as e: # Catch other unexpected errors
         logging.error(f"Unexpected error fetching details for log {log_id}: {e}", exc_info=True)
         details = None
    finally:
        # --- Corrected Finally Block ---
        if cursor:
            try:
                cursor.close()
            except DBError as cur_close_err: # Use DBError
                # Log DB-specific close errors if needed, otherwise pass
                # logging.warning(f"DBError closing get_details cursor: {cur_close_err}")
                pass
            except Exception as cur_close_err: # Catch other potential close errors
                logging.error(f"Unexpected error closing get_details cursor: {cur_close_err}")
        # Always close the connection if it was obtained
        if conn: # Check if conn was successfully assigned
            close_db_connection(conn)
        # --- End Correction ---

    logging.info(f"--- Finished fetching log details for log_id: {log_id}. Returning: {'Details found' if details else 'None'} ---")
    return details

@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    user_id = g.user['id']; log_data = get_log_entry_details(log_id)
    if not log_data: abort(404, description="Report not found.")
    if user_id != log_data.get('sender_customer_id') and user_id != log_data.get('receiver_customer_id'): abort(403)
    try:
        pdf_bytes = create_transaction_report(log_data)
        if not pdf_bytes: abort(500, description="Report gen failed.")
        fname = f"Txn_Report_{log_id}_{datetime.datetime.now():%Y%m%d}.pdf"; logging.info(f"Serving PDF '{fname}'")
        return Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": f"attachment;filename={fname}"})
    except Exception as e: logging.error(f"PDF report error {log_id}: {e}"); abort(500)

@app.route('/report/<int:log_id>')
@login_required
def show_report_page(log_id):
     user_id = g.user['id']; logging.info(f"--- User {user_id} req report page {log_id} ---")
     report_info = get_log_entry_details(log_id); logging.debug(f"Data for report {log_id}: {report_info}")
     if not report_info: logging.warning(f"Report data not found {log_id}"); abort(404)
     sender_cid = report_info.get('sender_customer_id'); receiver_cid = report_info.get('receiver_customer_id')
     logging.debug(f"Auth check {log_id}: U={user_id}, S={sender_cid}, R={receiver_cid}")
     if user_id != sender_cid and user_id != receiver_cid: logging.warning(f"AUTH FAIL report {log_id}"); abort(403)
     logging.info(f"Auth OK render report {log_id}."); logging.debug(f"Passing data to report.html: {report_info}")
     return render_template('report.html', report_info=report_info)

@app.route('/risk-analysis', methods=['GET', 'POST'])
@login_required
def risk_analysis_page():
    # This route seems less database-dependent, might not need changes unless
    # risk_simulation module interacts with the DB in a MySQL-specific way.
    risk_results = None; analysis_type='portfolio'; form_data = {}; default_alpha=0.05; default_num_assets=3
    if request.method == 'POST':
        form_data = request.form; analysis_type = request.form.get('analysis_type', 'portfolio').lower()
        logging.info(f"POST risk analysis: {analysis_type}")
        config = {}
        try:
            if analysis_type == 'risk_measure':
                alpha = float(request.form.get('param_alpha', str(default_alpha)))
                if not (0 < alpha < 1): raise ValueError("Alpha must be 0-1.")
                config['alpha'] = alpha
            elif analysis_type == 'portfolio':
                num_assets = int(request.form.get('param_num_assets', str(default_num_assets)))
                if not (1 < num_assets <= 10): raise ValueError("Assets must be 2-10.")
                config['num_assets'] = num_assets
            else: analysis_type = 'portfolio'; config['num_assets'] = default_num_assets
            logging.info(f"Running risk analysis: type='{analysis_type}', config={config}")
            risk_results = run_risk_analysis(analysis_type=analysis_type, config=config)
            if risk_results and risk_results.get('status') != 'Error': flash("Simulation complete.", "success")
            else: flash(f"Simulation failed: {risk_results.get('details', 'Unknown')}", "error")
        except (ValueError, TypeError) as param_err: flash(f"Invalid parameter: {param_err}", "error"); risk_results = {'status': 'Error', 'details': f'Invalid parameter: {param_err}'}
        except Exception as e: logging.error(f"Risk sim error ({analysis_type}): {e}", exc_info=True); flash("Simulation failed.", "error"); risk_results = {'status': 'Error', 'details': f'Internal error: {e}'}
        return render_template('risk_analysis.html', risk_results=risk_results, analysis_type=analysis_type, form_data=form_data)
    return render_template('risk_analysis.html', risk_results=None, analysis_type=analysis_type, form_data={})

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    current_year = datetime.datetime.now().year
    return dict(session_user=g.get('user'), INITIAL_BALANCE_DISPLAY=f"{app.config.get('INITIAL_BALANCE', Decimal('0.00')):.2f}",
                QBER_THRESHOLD_DISPLAY=f"{app.config.get('QBER_THRESHOLD', 0.15):.2%}", current_year=current_year,
                is_mail_available=MAIL_AVAILABLE, are_forms_enabled=WTFORMS_AVAILABLE)

# --- Error Handlers ---
@app.errorhandler(404)
@app.errorhandler(404)
def page_not_found(e):
    # --- MODIFIED USER ID FETCH ---
    # Check if g.user exists AND is not None before trying to get id
    user_id = g.user.get('id', 'Anonymous') if hasattr(g, 'user') and g.user else 'Anonymous'
    # --- END MODIFICATION ---
    logging.warning(f"404 Not Found: URL={request.url}, User={user_id}, Error={e.description}")
    return render_template('errors/404.html', error=e), 404

@app.errorhandler(403)
def forbidden(e): user_id = getattr(g, 'user', {}).get('id', 'Anon'); logging.warning(f"403: {request.url} U={user_id} E={e.description}"); return render_template('errors/403.html', error=e), 403

@app.errorhandler(500)
@app.errorhandler(Exception) # Catch other unhandled exceptions
def internal_server_error(e):
    original_exception = getattr(e, "original_exception", e) # Get original exception
    # --- MODIFIED USER ID FETCH ---
    # Check if g.user exists AND is not None before trying to get id
    user_id = g.user.get('id', 'Anonymous') if hasattr(g, 'user') and g.user else 'Anonymous'
    # --- END MODIFICATION ---
    logging.error(f"500 Internal Server Error: URL={request.url}, User={user_id}, Error={original_exception}", exc_info=original_exception)
    # ... (rest of the handler) ...
    return render_template('errors/500.html', error=original_exception), 500

# --- Main execution block ---
if __name__ == '__main__':
     print("\n" + "="*60 + "\n--- Starting QKD Secure Banking Demo App ---\n" + "="*60)
     # Status checks ... (condensed)
     print("\n--- Status Checks ---")
     print(f"  - WTForms: {'OK' if WTFORMS_AVAILABLE else 'Disabled'}")
     print(f"  - Mail: {'OK' if MAIL_AVAILABLE else 'Disabled'}")
     try: model_fn=MODEL_FILENAME; feat_fn=FEATURES_FILENAME
     except NameError: model_fn='fraud_model.joblib'; feat_fn='fraud_model_features.joblib'
     print(f"  - ML Models: {'OK' if os.path.exists(os.path.join(script_dir, model_fn)) and os.path.exists(os.path.join(script_dir, feat_fn)) else 'MISSING!'}")
     conn_test = get_db_connection()
     print(f"  - DB Connection: {'OK' if conn_test else 'FAILED!'}")
     if conn_test: close_db_connection(conn_test)
     else: exit("FATAL: DB connection required.")
     if MAIL_AVAILABLE: print(f"  - Email Config: {'OK' if app.config.get('MAIL_SERVER') else 'Incomplete'}")
     if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_': print("\n  WARNING: Using default FLASK_SECRET_KEY!")

     # Start Server
     print("\n--- Starting Server ---")
     port = int(os.environ.get('PORT', 5000)); host = os.environ.get('HOST', '0.0.0.0')
     debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
     print(f"  * Mode: {'dev' if debug_mode else 'prod'} | Debug: {'on' if debug_mode else 'off'} | Host: {host} | Port: {port}")
     print(f"  * Access: http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/")
     print("="*60 + "\n")
     try:
         from waitress import serve; print("--- Using Waitress ---"); serve(app, host=host, port=port, threads=8)
     except ImportError:
         print("--- Waitress not found, using Flask Dev Server ---")
         if not debug_mode: print("  WARNING: Flask dev server not for production.")
         app.run(debug=debug_mode, host=host, port=port)
     except Exception as start_err: logging.critical(f"Server start failed: {start_err}", exc_info=True); exit("FATAL: Server start failed.")
