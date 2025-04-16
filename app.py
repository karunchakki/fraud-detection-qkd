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
try:
    import psycopg2
    from psycopg2 import Error as DBError # Use DBError alias
    # Optional: Use DictCursor for easier row access
    import psycopg2.extras
    print("--- PostgreSQL driver (psycopg2) found. ---")
except ImportError:
    print("\nERROR: 'psycopg2-binary' not found. Please install it: pip install psycopg2-binary")
    exit(1)

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
    """Establishes and returns a new PostgreSQL database connection using DATABASE_URL."""
    conn = None
    db_url = os.environ.get('DATABASE_URL') # Render injects this automatically

    # Fallback to MySQL connection details ONLY if DATABASE_URL is missing (for local testing)
    if not db_url:
        logging.warning("DATABASE_URL not found. Attempting fallback to MySQL config for local testing.")
        try:
            # Keep original MySQL connector import for this block only
            import mysql.connector
            from mysql.connector import Error as MySQLError
            conn = mysql.connector.connect(**MYSQL_CONFIG)
            if conn.is_connected():
                logging.debug("DB connection successful (MySQL Fallback).")
                return conn
            else: # Should not happen if connect succeeded
                logging.error("MySQL fallback connection failed (not connected).")
                if conn: conn.close()
                return None
        except ImportError:
             logging.error("MySQL fallback failed: mysql-connector-python not installed.")
             return None
        except MySQLError as e_mysql:
            logging.critical(f"CRITICAL MYSQL FALLBACK CONNECTION ERROR: {e_mysql}")
            if conn: try: conn.close() except MySQLError: pass
            return None
        except Exception as e_mysql_other:
             logging.critical(f"CRITICAL UNEXPECTED MYSQL FALLBACK ERROR: {e_mysql_other}")
             if conn: try: conn.close() except MySQLError: pass
             return None

    # --- Primary Path: Use DATABASE_URL for PostgreSQL ---
    try:
        logging.debug(f"Attempting PostgreSQL connection using DATABASE_URL.")
        # Replace protocol for psycopg2 if necessary (Render URL might be correct already)
        # db_url_conn = db_url.replace("postgres://", "postgresql://", 1)
        # Usually DATABASE_URL from Render works directly with psycopg2
        conn = psycopg2.connect(db_url)
        logging.info("PostgreSQL connection successful via DATABASE_URL.")
        return conn
    except DBError as e_pg: # Use DBError alias for psycopg2 errors
        logging.critical(f"CRITICAL POSTGRESQL CONNECTION ERROR: {e_pg}")
        return None
    except Exception as e_pg_other:
        logging.critical(f"CRITICAL UNEXPECTED ERROR CONNECTING TO POSTGRESQL: {e_pg_other}")
        return None

def close_db_connection(conn):
    """Closes the database connection if it's open."""
    # Check if connection object exists and has a close method
    if conn and hasattr(conn, 'close'):
        try:
            # Check if it's still connected before closing (for PostgreSQL)
            # Note: is_connected() is not a standard psycopg2 attribute. Check status or just try closing.
            # if not conn.closed: # psycopg2 uses 'closed' attribute
            conn.close()
            logging.debug("Database connection closed.")
        except DBError as e: # Use DBError
            logging.error(f"Error closing database connection: {e}")
        except Exception as e:
             logging.error(f"Unexpected error closing DB connection: {e}")

def get_accounts_data(customer_id_filter=None):
    """Fetches account data. Returns list or None on DB error."""
    accounts = []
    conn = get_db_connection()
    cursor = None
    if not conn: logging.error("DB conn failed in get_accounts_data."); return None

    try:
        # Use DictCursor for PostgreSQL to get results as dictionaries
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # SQL remains largely the same, %s placeholders work
        sql = """SELECT a.account_id, c.customer_name, a.balance, a.customer_id
                 FROM accounts a
                 JOIN customers c ON a.customer_id = c.customer_id"""
        params = []
        if customer_id_filter is not None:
            try:
                filter_id = int(customer_id_filter)
                sql += " WHERE a.customer_id = %s"
                params.append(filter_id)
            except (ValueError, TypeError): logging.error(f"Invalid customer_id_filter: {customer_id_filter}.")
        sql += " ORDER BY c.customer_name, a.account_id"
        cursor.execute(sql, tuple(params))
        raw_accounts = cursor.fetchall() # Returns list of DictRow objects

        for acc_row in raw_accounts:
            balance_val = None
            try:
                # Access DictRow items like a dictionary
                balance_val = acc_row['balance']
                current_balance = Decimal(balance_val) if balance_val is not None else Decimal('0.00')
                # Create a new dict to store, as DictRow might be immutable or have issues
                account_dict = dict(acc_row)
                account_dict['balance'] = current_balance
                accounts.append(account_dict)
            except (InvalidOperation, TypeError) as e: logging.warning(f"Skipping account {acc_row.get('account_id', '?')} invalid balance: {e}")
            except Exception as inner_e: logging.error(f"Error processing account row {acc_row.get('account_id', '?')}: {inner_e}", exc_info=True)

    except DBError as e: # Use DBError
        logging.error(f"DB error fetching accounts data: {e}", exc_info=True)
        return None
    except Exception as e:
        logging.error(f"Unexpected error fetching accounts: {e}", exc_info=True)
        return None
    finally:
        if cursor:
            try: cursor.close()
            except DBError: pass
        close_db_connection(conn)
    return accounts

def get_user_by_email(email):
    """Fetches user details by email. Returns dict or None."""
    conn = get_db_connection(); cursor = None; user = None
    if not conn: return None
    if not isinstance(email, str) or not email: return None

    try:
        # Use DictCursor
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,))
        user_row = cursor.fetchone()
        if user_row:
             user = dict(user_row) # Convert DictRow to standard dict
    except DBError as e: # Use DBError
        logging.error(f"DB Error fetching user by email ({email}): {e}")
        user = None
    except Exception as e:
        logging.error(f"Unexpected error fetching user ({email}): {e}", exc_info=True)
        user = None
    finally:
        if cursor:
            try: cursor.close()
            except DBError: pass
        close_db_connection(conn)
    return user

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None, exception_info=None):
    """Logs details of a failed transaction attempt."""
    sender_id_val = int(sender_id) if sender_id is not None else None
    receiver_id_val = int(receiver_id) if receiver_id is not None else None
    if amount is None: amount = Decimal('0.00')
    elif not isinstance(amount, Decimal):
        try: amount = Decimal(amount)
        except (InvalidOperation, TypeError): amount = Decimal('0.00')
    amount_str = f"{amount:.2f}"
    qber_db_val = float(qber_value) if isinstance(qber_value, (float, int)) and qber_value >= 0 else None
    is_flagged = bool(fraud_reason)
    reason_text = str(fraud_reason)[:255] if fraud_reason else None
    if exception_info: reason_text = f"{reason_text or 'Error'} | Exc: {str(exception_info)[:150]}"

    logging.warning(f"Logging failed TXN attempt: Status='{failed_status}', Reason='{reason_text}'")
    log_conn = None; log_cursor = None
    try:
        log_conn = get_db_connection();
        if not log_conn: logging.critical("CRITICAL: DB Conn failed. UNABLE TO LOG FAILED TXN."); return
        log_cursor = log_conn.cursor()
        log_sql = """INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason, timestamp, encrypted_confirmation, iv) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        log_values = (sender_id_val, receiver_id_val, amount_str, failed_status[:50], qber_db_val, is_flagged, reason_text, datetime.datetime.now(), None, None )
        log_cursor.execute(log_sql, log_values); log_conn.commit()
        logging.info(f"Failed attempt logged OK (Status: {failed_status}).")
    except DBError as log_err: # Use DBError
        logging.critical(f"CRITICAL: Failed to log FAILED TXN (Status: {failed_status}): {log_err}", exc_info=True)
        if log_conn and not log_conn.closed: try: log_conn.rollback() except DBError: pass
    except Exception as e:
         logging.critical(f"CRITICAL: Unexpected error logging failed TXN: {e}", exc_info=True)
         if log_conn and not log_conn.closed: try: log_conn.rollback() except DBError: pass
    finally:
        if log_cursor: try: log_cursor.close() except DBError: pass
        close_db_connection(log_conn)

# --- Authentication & Session Management ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: flash("Please log in.", "warning"); return redirect(url_for('login', next=request.url))
        if not g.get('user'): session.clear(); flash("Session invalid. Please log in.", "warning"); logging.warning("Cleared session: user_id OK but g.user missing."); return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id'); g.user = None
    if user_id:
        conn = get_db_connection(); cursor = None
        if conn:
            try:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
                cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s", (user_id,))
                user_data = cursor.fetchone()
                if user_data: g.user = dict(user_data); session.permanent = True
                else: logging.warning(f"User {user_id} in session not in DB. Clearing."); session.clear()
            except DBError as e: logging.error(f"DB Error loading session user {user_id}: {e}")
            except Exception as e: logging.error(f"Unexpected error loading user {user_id}: {e}", exc_info=True)
            finally:
                if cursor: try: cursor.close() except DBError: pass
                close_db_connection(conn)
        else: logging.error("DB conn failed in load_logged_in_user. Clearing session."); session.clear()

def clear_qkd_session_log():
     user_id = getattr(g, 'user', {}).get('id') or session.get('user_id')
     if user_id:
         log_key = f'last_qkd_log_{user_id}'
         if log_key in session: session.pop(log_key); session.modified = True; logging.info(f"Cleared QKD log for user {user_id}")

# --- Async Email Helper ---
def send_async_email(app_context, msg):
    with app_context:
        if not mail: logging.error("Mail not init. Cannot send."); return
        try: mail.send(msg); logging.info(f"Async email sent OK to {msg.recipients}")
        except Exception as e: logging.error(f"Error sending async email: {e}", exc_info=True)

# --- Flask Routes ---
@app.route('/')
def home_redirect():
    if g.get('user'): return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    user_id = g.user['id']
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

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    if g.user: return redirect(url_for('index'))
    form = RegistrationForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        # 1. Extract Data
        if WTFORMS_AVAILABLE:
            customer_name = form.customer_name.data; email = form.email.data
            password = form.password.data; phone_number = form.phone_number.data
        else: # Manual extraction
            customer_name = request.form.get('customer_name','').strip()
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            confirm_password = request.form.get('confirm_password','')
            phone_number = request.form.get('phone_number', '').strip()
            errors = [] # Basic manual validation
            if not customer_name or len(customer_name) < 2: errors.append("Name invalid.")
            if not email or '@' not in email: errors.append("Email invalid.")
            if not password or len(password) < 8: errors.append("Password too short.")
            if password != confirm_password: errors.append("Passwords mismatch.")
            if errors:
                for err in errors: flash(err, 'error')
                return render_template('register.html', form=form)

        # 2. Placeholder Validations (OTP/CAPTCHA)
        logging.info("DEMO MODE: Skipping CAPTCHA validation.")
        logging.info("DEMO MODE: Skipping OTP validation.")

        # --- 3. Database Operations ---
        conn = None; cursor = None; user_exists = False; error_occurred = False
        # 3a. Pre-check email
        try:
             conn = get_db_connection();
             if not conn: raise ConnectionError("DB pre-check connection error.")
             cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
             cursor.execute("SELECT customer_id FROM customers WHERE email = %s", (email,))
             if cursor.fetchone():
                 user_exists = True
                 if WTFORMS_AVAILABLE and hasattr(form.email, 'errors'): form.email.errors.append("Email already registered.")
                 else: flash("Email already registered.", "error")
        except (DBError, ConnectionError) as e: # Use DBError
            logging.error(f"DB pre-check error: {e}"); flash("DB pre-check error.", "error"); error_occurred = True
        except Exception as e: logging.error(f"Unexpected pre-check error: {e}", exc_info=True); flash("Unexpected error.", "error"); error_occurred = True
        finally:
             if cursor: cursor.close()
             if (user_exists or error_occurred) and conn and not getattr(conn, 'closed', True): close_db_connection(conn) # Check 'closed' attr for psycopg2

        if user_exists or error_occurred: return render_template('register.html', form=form)

        # 3b. Insert User
        cursor = None; needs_rollback = False; new_customer_id = None
        try:
            if not conn or getattr(conn, 'closed', True): raise ConnectionError("DB connection lost before insert.")
            cursor = conn.cursor() # Standard cursor for DML
            needs_rollback = True; hashed_pw = generate_password_hash(password)
            sql_insert_customer = "INSERT INTO customers (customer_name, email, password_hash, phone_number) VALUES (%s, %s, %s, %s) RETURNING customer_id" # Use RETURNING
            phone_number_to_db = phone_number if phone_number else None
            customer_params = (customer_name, email, hashed_pw, phone_number_to_db)
            cursor.execute(sql_insert_customer, customer_params)

            # Fetch the returned customer_id for PostgreSQL
            returned_row = cursor.fetchone()
            if returned_row and len(returned_row) > 0: new_customer_id = returned_row[0]
            else: raise DBError("Failed to get customer ID after insert using RETURNING.")
            logging.debug(f"Inserted customer '{customer_name}' (ID: {new_customer_id})")

            # Insert Account
            sql_insert_account = "INSERT INTO accounts (customer_id, balance) VALUES (%s, %s) RETURNING account_id" # Use RETURNING
            account_params = (new_customer_id, str(app.config['INITIAL_BALANCE']))
            cursor.execute(sql_insert_account, account_params)
            # Fetch the returned account_id
            account_row = cursor.fetchone()
            if account_row and len(account_row) > 0: new_account_id = account_row[0]
            else: raise DBError(f"Failed to get account ID after insert for customer {new_customer_id}.")
            logging.debug(f"Inserted account {new_account_id} for customer {new_customer_id}")

            conn.commit(); needs_rollback = False
            logging.info(f"Registered new user: '{customer_name}' ({email}), ID: {new_customer_id}")
            flash("Registration successful! Please log in.", "success")
            if cursor: cursor.close(); cursor=None # Close cursor after commit
            close_db_connection(conn); conn=None # Close connection after commit
            return redirect(url_for('login'))

        except (DBError, ConnectionError) as e: # Use DBError
            logging.error(f"DB insert error during registration: {e}", exc_info=True)
            flash("Database registration error.", "error")
        except Exception as e:
            logging.error(f"Unexpected registration error: {e}", exc_info=True)
            flash("Unexpected error during registration.", "error")
        finally: # Cleanup for insert try block
            if conn and not getattr(conn, 'closed', True):
                if needs_rollback:
                    try: conn.rollback(); logging.warning(f"Reg rolled back for {email}.")
                    except DBError as rb_err: logging.error(f"Rollback failed: {rb_err}")
                if cursor: try: cursor.close() except DBError: pass
                close_db_connection(conn)

        return render_template('register.html', form=form)

    # --- Handle GET Request ---
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: return redirect(url_for('index'))
    form = LoginForm() if WTFORMS_AVAILABLE else None
    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):
        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email', '').strip().lower()
        password = form.password.data if WTFORMS_AVAILABLE else request.form.get('password', '')
        if not email or not password: flash("Email/password required.", "error"); return render_template('login.html', form=form)
        customer = get_user_by_email(email)
        if customer and check_password_hash(customer.get('password_hash',''), password):
            session.clear(); session['user_id'] = customer['customer_id']; session.permanent = True
            g.user = {'id': customer['customer_id'], 'name': customer['customer_name'], 'email': customer['email']}
            logging.info(f"User {customer['customer_name']} (ID: {customer['customer_id']}) logged in.")
            flash(f"Welcome back, {customer.get('customer_name', 'User')}!", "success")
            next_page = request.args.get('next'); return redirect(next_page) if next_page and next_page.startswith('/') and ' ' not in next_page else redirect(url_for('index'))
        else: logging.warning(f"Failed login: {email}"); flash("Invalid email or password.", "error")
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

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if g.user: flash("Already logged in.", "info"); return redirect(url_for('index'))
    if not serializer: flash("Password reset unavailable.", "warning"); return redirect(url_for('login'))
    email = None
    try: email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired: flash('Link expired.', 'error'); return redirect(url_for('forgot_password'))
    except Exception as e: logging.warning(f"Invalid token: {e}"); flash('Invalid link.', 'error'); return redirect(url_for('forgot_password'))
    user = get_user_by_email(email)
    if not user: flash('User account not found.', 'error'); return redirect(url_for('forgot_password'))
    form = ResetPasswordForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):
        new_password = form.password.data if WTFORMS_AVAILABLE else request.form.get('password')
        confirm_password = form.confirm_password.data if WTFORMS_AVAILABLE else request.form.get('confirm_password')
        if not WTFORMS_AVAILABLE: # Manual validation
             errors = [];
             if not new_password or len(new_password) < 8: errors.append("Password min 8 chars")
             if new_password != confirm_password: errors.append("Passwords mismatch")
             if errors:
                 for err in errors: flash(err, 'error')
                 return render_template('reset_password.html', form=form, token=token)

        new_pw_hash = generate_password_hash(new_password); conn = None; cursor = None; updated = False; needs_rollback = False
        conn = get_db_connection()
        if not conn: flash('DB error.', 'error'); return render_template('reset_password.html', form=form, token=token)
        try:
            cursor = conn.cursor(); needs_rollback = True
            sql = "UPDATE customers SET password_hash = %s WHERE email = %s AND customer_id = %s"
            params = (new_pw_hash, email, user['customer_id'])
            cursor.execute(sql, params); rows = cursor.rowcount
            if rows == 1: conn.commit(); updated = True; needs_rollback = False; logging.info(f"Password updated for {email}")
            else: flash('Password update failed.', 'error')
        except DBError as e: logging.error(f"DB Error reset pw: {e}", exc_info=True); flash('DB update error.', 'error') # Use DBError
        except Exception as e: logging.error(f"Unexpected err reset pw: {e}", exc_info=True); flash('Update error.', 'error')
        finally:
             if conn and not getattr(conn, 'closed', True):
                 if needs_rollback: try: conn.rollback() except DBError: pass # Use DBError
                 if cursor: try: cursor.close() except DBError: pass
                 close_db_connection(conn)
        if updated: flash('Password reset. Please log in.', 'success'); return redirect(url_for('login'))
        else: return render_template('reset_password.html', form=form, token=token)
    return render_template('reset_password.html', form=form, token=token)


@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    sender_id = None; receiver_id = None; amount = None; simulate_eve_checked = False
    logged_in_user_id = g.user['id']
    qkd_key = None; sim_res = {}; qber = -1.0; qkd_fail_reason = None
    log_status = "INITIATED"; fraud_res = {'is_fraudulent': False, 'reason': None, 'ml_score': -1.0}
    last_outcome = {'timestamp': datetime.datetime.now().isoformat(), 'status': 'Pending', 'reason': ''}
    session.pop('last_transfer_outcome', None)

    # --- 1. Input Validation & Form Handling ---
    try:
        user_accounts = get_accounts_data(customer_id_filter=logged_in_user_id)
        if user_accounts is None: raise ConnectionError("DB error fetching sender.")
        if not user_accounts: raise ValueError("Sender account not found.")
        sender_account = user_accounts[0]; sender_id = sender_account['account_id']
        last_outcome['sender_id'] = sender_id

        if WTFORMS_AVAILABLE:
            transfer_form = TransferForm(request.form)
            all_accounts = get_accounts_data();
            if all_accounts is None: raise ConnectionError("DB error fetching recipients.")
            rec_choices = [(str(a['account_id']), f"{a['customer_name']} (Acc ID: {a['account_id']})") for a in all_accounts if a.get('customer_id') != logged_in_user_id]
            transfer_form.receiver_account_id.choices = [('', '-- Select Recipient --')] + rec_choices
            if transfer_form.validate_on_submit():
                rec_id_str = transfer_form.receiver_account_id.data; amount = transfer_form.amount.data; simulate_eve_checked = transfer_form.simulate_eve.data
                try: receiver_id = int(rec_id_str)
                except (ValueError, TypeError): raise ValueError("Invalid recipient ID.")
            else: raise ValueError("Invalid input: " + "; ".join([f"{f}: {', '.join(e)}" for f, e in transfer_form.errors.items()]))
        else: # Manual
            rec_id_str = request.form.get('receiver_account_id'); amount_str = request.form.get('amount'); simulate_eve_checked = 'simulate_eve' in request.form
            if not rec_id_str: raise ValueError("Select recipient.")
            try: receiver_id = int(rec_id_str)
            except (ValueError, TypeError): raise ValueError("Invalid recipient ID.")
            if not amount_str: raise ValueError("Amount missing.")
            try: amount = Decimal(amount_str.strip())
            except InvalidOperation: raise ValueError("Invalid amount.")

        if not isinstance(receiver_id, int): raise ValueError("Internal Recipient ID error.")
        if sender_id == receiver_id: raise ValueError("Cannot transfer to self.")
        if amount is None or amount <= 0: raise ValueError("Amount must be positive.")

        last_outcome.update({'amount': f"{amount:.2f}", 'receiver_id': receiver_id, 'simulate_eve': simulate_eve_checked})
        log_status = "INPUT_VALIDATED"; logging.info(f"Transfer Validated: {amount:.2f} from {sender_id} to {receiver_id}")

    except (ValueError, ConnectionError, TypeError, InvalidOperation, KeyError) as e:
        logging.warning(f"Transfer input failed: {e}", exc_info=False); flash(f"Transfer Failed: {e}", "error")
        last_outcome.update({'status': 'Failed', 'reason': f"Input Error: {str(e)[:100]}"})
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        amount_for_log = amount if amount is not None else Decimal('0.00'); log_failed_attempt(sender_id, receiver_id, amount_for_log, "INPUT_ERROR", exception_info=e)
        return redirect(url_for('index'))
    except Exception as e:
         logging.error(f"Unexpected transfer input error: {e}", exc_info=True); flash("Unexpected error.", "error")
         last_outcome.update({'status': 'Failed', 'reason': "Unexpected Input Error"}); session['last_transfer_outcome'] = last_outcome; session.modified = True
         amount_for_log = amount if amount is not None else Decimal('0.00'); log_failed_attempt(sender_id, receiver_id, amount_for_log, "UNEXPECTED_INPUT_ERR", exception_info=e)
         return redirect(url_for('index'))

    # --- 2. QKD Simulation ---
    qber_thresh = current_app.config['QBER_THRESHOLD']; n_qubits = QKD_NUM_QUBITS; eve_rate = 0.25 if simulate_eve_checked else 0.0
    qkd_fraud_reason = None
    try:
        log_status = "QKD_RUNNING"
        sim_res = simulate_bb84(n_qubits=n_qubits, simulate_eve=simulate_eve_checked, qber_threshold=qber_thresh, eve_interception_rate=eve_rate)
        session[f'last_qkd_log_{logged_in_user_id}'] = sim_res; session.modified = True; last_outcome['qkd_log_stored'] = True
        key_bin = sim_res.get('final_key_binary'); qber = sim_res.get('qber', -1.0); eve_det = sim_res.get('eve_detected', False)
        qber_disp = f"{qber:.4f}" if qber >= 0 else 'N/A'; last_outcome['qber'] = qber_disp
        logging.info(f"QKD Result: QBER={qber_disp}, Eve={eve_det}, KeyLen={len(key_bin or '')}")
        if qber < 0: qkd_fail_reason = f"QKD Sim Error ({qber})"; log_status = "QKD_SIM_ERR"
        elif eve_det: qkd_fail_reason = f"High QBER ({qber_disp})"; log_status = "QKD_EVE_DETECTED"; qkd_fraud_reason = "QKD Alert: High QBER"
        elif not key_bin or len(key_bin) < 128: qkd_fail_reason = f"Short Key ({len(key_bin or '')})"; log_status = "QKD_KEY_INSUFFICIENT"
        if qkd_fail_reason: raise ValueError(f"QKD Failed: {qkd_fail_reason}")
        key_hash = hashlib.sha256(key_bin.encode('utf-8')).digest(); qkd_key = base64.urlsafe_b64encode(key_hash)
        logging.info(f"QKD OK (QBER:{qber_disp})."); log_status = "QKD_SUCCESS"; last_outcome['qkd_status_msg'] = "Secure Channel OK"
    except ValueError as qkd_e:
        logging.warning(f"QKD Failure: {qkd_e}"); flash(f"Aborted: {qkd_e}", "danger")
        last_outcome.update({'status': 'Failed', 'reason': qkd_fail_reason or str(qkd_e), 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=qkd_fraud_reason, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))
    except Exception as qkd_e:
        logging.error(f"Unexpected QKD Error: {qkd_e}", exc_info=True); log_status = "QKD_INTERNAL_ERR"
        flash('Aborted: Secure channel error.', 'danger')
        last_outcome.update({'status': 'Failed', 'reason': 'QKD Internal Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, exception_info=qkd_e); session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))

    # --- 3. Database Transaction & Fraud Check ---
    conn = None; cursor = None; needs_rollback = False; log_id = None
    try:
        if not qkd_key: raise ValueError("Internal error: QKD key missing.")
        log_status = "DB_TXN_STARTING"; conn = get_db_connection();
        if not conn: raise ConnectionError("DB connection failed.")
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor, name='transfer_cursor'); needs_rollback = True # Use server-side cursor potentially

        # Lock & Validate Sender
        log_status = "DB_VALIDATE_SENDER"
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_info = cursor.fetchone();
        if not sender_info: raise ValueError(f"Sender {sender_id} not found.")
        if sender_info['customer_id'] != logged_in_user_id: logging.critical(f"AUTH FAIL U:{logged_in_user_id} Acc:{sender_id}."); raise ValueError("Auth Error.")
        sender_bal = Decimal(sender_info['balance'])
        if sender_bal < amount: raise ValueError(f"Insufficient funds (Bal:₹{sender_bal:.2f})")

        # Validate Receiver
        log_status = "DB_VALIDATE_RECEIVER"
        cursor.execute("SELECT a.account_id, c.customer_name, a.balance FROM accounts a JOIN customers c ON a.customer_id=c.customer_id WHERE a.account_id=%s", (receiver_id,))
        rx_info = cursor.fetchone()
        if not rx_info: raise ValueError(f"Receiver {receiver_id} not found.")
        rx_name = rx_info['customer_name']; last_outcome['receiver_name'] = rx_name

        # Fraud Detection
        log_status = "FRAUD_CHECK_RUNNING"; logging.info("Running fraud check...")
        hist_ml = []
        try:
             cursor.execute("SELECT amount, timestamp FROM qkd_transaction_log WHERE sender_account_id=%s AND qkd_status NOT LIKE '%%FAIL%%' ORDER BY timestamp DESC LIMIT 10", (sender_id,))
             for r in cursor.fetchall(): # Use fetchall on server-side cursor if defined with name
                 try: hist_ml.append({'amount': Decimal(r['amount']), 'timestamp': r['timestamp']})
                 except Exception as hist_e: logging.warning(f"Skipping hist record: {hist_e} - {r}")
        except DBError as db_hist_err: logging.error(f"DB Error fetching history: {db_hist_err}")

        curr_txn = {'amount': amount, 'recipient_username': rx_name, 'timestamp': datetime.datetime.now()}
        fraud_cfg = {'blacklist': app.config['FRAUD_BLACKLIST']}
        try: fraud_res = detect_fraud(curr_txn, hist_ml, **fraud_cfg)
        except Exception as fraud_ml_err: logging.error(f"ML Fraud error: {fraud_ml_err}", exc_info=True); fraud_res = {'is_fraudulent': False, 'reason': 'Fraud Check Error', 'ml_score': -1}; flash("Warn: Fraud check error.", "warning")

        last_outcome['fraud_check'] = fraud_res; is_fraudulent = fraud_res.get('is_fraudulent', False); ml_fraud_reason = fraud_res.get('reason')
        final_fraud_reason = qkd_fraud_reason or ml_fraud_reason if is_fraudulent else None
        if is_fraudulent: logging.warning(f"FRAUD ALERT: {final_fraud_reason}") else: logging.info("Fraud check OK.")
        qkd_status_final = "SECURED_FLAGGED" if is_fraudulent else "SECURED"; last_outcome['qkd_status_msg'] = qkd_status_final.replace('_',' ')

        # Encrypt Confirmation
        log_status = "ENCRYPTING_DATA"
        msg = f"CONF;{sender_id}>{receiver_id};AMT:{amount:.2f};QBER:{qber_disp};FRAUD:{is_fraudulent};R:{final_fraud_reason or 'N/A'};T:{datetime.datetime.now().isoformat()}"
        try: f = Fernet(qkd_key); enc_b64 = f.encrypt(msg.encode('utf-8')).decode('utf-8'); last_outcome['enc_sample'] = enc_b64[:60]+'...'
        except Exception as fe: log_status = "ENC_FAIL"; raise ValueError(f"Encrypt fail: {fe}")

        # Update Balances
        log_status = "DB_UPDATING_BALANCES"; new_sender_bal = sender_bal - amount
        cursor.execute("SELECT balance FROM accounts WHERE account_id=%s FOR UPDATE", (receiver_id,))
        rx_bal_row = cursor.fetchone();
        if not rx_bal_row: raise ValueError("Receiver vanished.")
        new_receiver_bal = Decimal(rx_bal_row['balance']) + amount
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_sender_bal), sender_id));
        if cursor.rowcount != 1: raise DBError(f"Sender update fail (rows={cursor.rowcount})") # Use DBError
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_receiver_bal), receiver_id));
        if cursor.rowcount != 1: raise DBError(f"Receiver update fail (rows={cursor.rowcount})") # Use DBError

        # Log Transaction
        log_status = "DB_LOGGING_TXN"
        sql = "INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING log_id" # Use RETURNING
        log_qber = qber if qber is not None and qber >= 0 else None; log_fraud = final_fraud_reason[:255] if final_fraud_reason else None
        vals = (sender_id, receiver_id, str(amount), qkd_status_final, enc_b64, None, log_qber, is_fraudulent, log_fraud, datetime.datetime.now())
        cursor.execute(sql, vals)
        log_row = cursor.fetchone() # Fetch returned ID
        if log_row and len(log_row) > 0: log_id = log_row['log_id'] # Adjust index if needed
        else: raise DBError("Failed to get log ID after insert.")
        last_outcome['log_id'] = log_id; logging.info(f"Txn logged: ID={log_id}")

        # Commit
        log_status = "DB_COMMITTING"; conn.commit(); needs_rollback = False
        logging.info("DB commit OK."); last_outcome['status'] = 'Success'
        flash_msg = f"Success! ₹{amount:.2f} sent. Log:{log_id}. Status:{qkd_status_final.replace('_',' ')}."; flash_cat = "success"
        if is_fraudulent: short_r = (final_fraud_reason or 'Flagged').split(';')[0]; flash_msg = f"Success (Log:{log_id}), but FLAGGED:{short_r}."; flash_cat = "warning"
        flash(flash_msg, flash_cat)

    except (DBError, ValueError, InvalidOperation, ConnectionError, AssertionError) as e: # Use DBError
        error_message = str(e)
        if log_status.startswith("DB_") or log_status in ["INITIATED", "FRAUD_CHECK_RUNNING", "ENCRYPTING_DATA"]:
             if isinstance(e, (ValueError, AssertionError)): log_status = "VALIDATION_FAIL"
             elif isinstance(e, ConnectionError): log_status = "DB_CONN_ERR"
             elif isinstance(e, DBError): log_status = "DB_TXN_ERR" # Use DBError
             else: log_status = "UNKNOWN_TXN_FAIL"
        logging.error(f"Txn Error ({log_status}): {error_message}", exc_info=True)
        last_outcome.update({'status': 'Failed', 'reason': error_message[:200], 'qkd_status_msg': log_status.replace('_',' ')})
        flash(f"Failed: {error_message}" if log_status=="VALIDATION_FAIL" else "Failed: System error.", "error")
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=f"Txn Err: {error_message[:100]}", exception_info=e)
    except Exception as e:
        log_status = "UNEXPECTED_TXN_ERR"; error_message = str(e)
        logging.critical(f"CRITICAL UNEXPECTED Txn Error: {error_message}", exc_info=True)
        flash("Transfer Failed: Critical error.", "danger"); last_outcome.update({'status': 'Failed', 'reason': 'Critical Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason="Critical Error", exception_info=e)
    finally:
        if conn and not getattr(conn, 'closed', True):
            if needs_rollback: try: conn.rollback(); logging.info(f"Txn rolled back ({log_status}).") except DBError as rb_err: logging.error(f"Rollback fail: {rb_err}") # Use DBError
            if cursor: try: cursor.close() except DBError: pass # Use DBError
            close_db_connection(conn)
    session['last_transfer_outcome'] = last_outcome; session.modified = True
    return redirect(url_for('index'))

@app.route('/history', methods=['GET'])
@login_required
def history():
    user_id = g.user['id']; display_log = []; conn = get_db_connection(); cursor = None
    if not conn: flash("DB error.", "error"); return render_template('history.html', log_entries=[], user_id=user_id)
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
        sql = """ SELECT l.log_id, l.timestamp AS ts, [...] FROM qkd_transaction_log l [...] """ # Abbreviated SQL
        cursor.execute(sql, (user_id, user_id))
        entries_raw = cursor.fetchall()
        for entry in entries_raw:
            try:
                amt = Decimal(entry.get('amount', '0.00')); qber_val = f"{entry.get('qber'):.3f}" if entry.get('qber') is not None else "N/A"
                enc_status = "[Encrypted]" if entry.get('enc_confirm') else "[N/A]"; qkd_status = entry.get('qkd_status','N/A')
                if "FAIL" in qkd_status: enc_status = "[N/A - Failed Txn]"
                is_flagged = entry.get('is_flagged', False); raw_reason = entry.get('fraud_reason'); display_reason = raw_reason if is_flagged and raw_reason else ("Yes" if is_flagged else "No")
                direction = "Sent" if entry.get('sender_cust_id') == user_id else ("Received" if entry.get('receiver_cust_id') == user_id else "")
                display_log.append({ 'id': entry['log_id'], 'timestamp': entry['ts'].strftime('%Y-%m-%d %H:%M:%S') if entry['ts'] else 'N/A',
                                     'sender': f"{entry.get('sender_name', '?')} ({entry.get('sender_id', '?')})", 'receiver': f"{entry.get('receiver_name', '?')} ({entry.get('receiver_id', '?')})",
                                     'amount': f"{amt:.2f}", 'qkd_status': qkd_status.replace('_', ' '), 'qber': qber_val, 'encrypted_details_status': enc_status,
                                     'is_flagged_display': display_reason, 'fraud_reason': raw_reason, 'is_flagged': is_flagged, 'direction': direction})
            except Exception as display_err: logging.warning(f"Err formatting log {entry.get('log_id', '?')}: {display_err}")
    except DBError as e: flash(f"History error: {e}", "error"); logging.error(f"History DB error user {user_id}: {e}", exc_info=True) # Use DBError
    except Exception as e: flash("History unexpected error.", "error"); logging.error(f"Unexpected history error user {user_id}: {e}", exc_info=True)
    finally:
        if cursor: try: cursor.close() except DBError: pass # Use DBError
        close_db_connection(conn)
    return render_template('history.html', log_entries=display_log, user_id=user_id)

@app.route('/qkd')
@login_required
def qkd_page():
    user_id = g.user['id']; logging.info(f"--- User {user_id} accessing QKD page ---")
    sim_log = session.get(f'last_qkd_log_{user_id}', None); labels = []; values = []
    qber_threshold_config = current_app.config['QBER_THRESHOLD']; qber_threshold_original = 0.15; qber_threshold_pct = 15.0
    try: qber_threshold_original = float(qber_threshold_config); qber_threshold_pct = qber_threshold_original * 100
    except Exception as thresh_err: logging.error(f"Invalid QBER_THRESHOLD: {thresh_err}"); flash("Threshold config error.", "warning")

    conn = None; cursor = None; limit = 15
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
            sql = """ SELECT l.log_id, l.timestamp, l.qber_value AS qber FROM qkd_transaction_log l [...] ORDER BY l.timestamp DESC LIMIT %s """ # Abbreviated SQL
            cursor.execute(sql, (user_id, user_id, limit))
            history = cursor.fetchall(); history.reverse()
            for entry in history:
                 log_id = entry.get('log_id'); qber_val = entry.get('qber'); ts = entry.get('timestamp')
                 if log_id and qber_val is not None and ts:
                     label = f"{ts.strftime('%m/%d %H:%M')} (ID:{log_id})"
                     try: labels.append(label); values.append(round(float(qber_val) * 100, 2))
                     except (ValueError, TypeError): pass
        else: labels, values = ['DB N/A'], [0]; flash("DB conn error.", "error")
    except DBError as e: logging.error(f"QBER history DB error: {e}"); labels, values = ['DB Err'], [0]; flash("DB history error.", "error") # Use DBError
    except Exception as e: logging.error(f"QBER history unexpected error: {e}"); labels, values = ['Error'], [0]; flash("History error.", "error")
    finally:
         if cursor: try: cursor.close() except DBError: pass # Use DBError
         if conn: close_db_connection(conn)

    if not labels: labels, values = ['No History'], [0]
    return render_template('qkd.html', simulation_log=sim_log, QBER_THRESHOLD_PCT=qber_threshold_pct,
                           QBER_THRESHOLD_ORIGINAL=qber_threshold_original, qber_history_labels=labels, qber_history_values=values)

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
    txns = []; conn = get_db_connection(); cursor = None
    if not conn: logging.error(f"DB Conn fail flagged tx user {user_id}"); return txns
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
        sql = """SELECT l.log_id, l.timestamp AS ts, s_cust.customer_name AS sender, [...] """ # Abbreviated SQL
        cursor.execute(sql, (user_id, user_id, limit)); raw = cursor.fetchall()
        for entry in raw:
             try:
                 amt = Decimal(entry.get('amount', '0.00')); ts_str = entry.get('ts').strftime('%Y-%m-%d %H:%M:%S') if entry.get('ts') else 'N/A'
                 txns.append({ 'id': entry['log_id'], 'timestamp': ts_str, 'sender': f"{entry.get('sender', '?')}", 'receiver': f"{entry.get('receiver', '?')}", 'amount': f"{amt:.2f}", 'fraud_reason': entry.get('fraud_reason', 'N/A') })
             except Exception as fe: logging.warning(f"Error formatting flagged tx {entry.get('log_id', '?')}: {fe}")
    except DBError as e: logging.error(f"Flagged tx DB error user {user_id}: {e}"); flash("Flagged data error.", "error") # Use DBError
    except Exception as e: logging.error(f"Unexpected flagged tx error user {user_id}: {e}"); flash("Unexpected flagged data error.", "error")
    finally:
        if cursor: try: cursor.close() except DBError: pass; close_db_connection(conn) # Use DBError
    return txns

@app.route('/fraud')
@login_required
def fraud_page():
    flagged_txns = get_flagged_transactions(g.user['id'])
    return render_template("fraud.html", flagged_txns=flagged_txns)

def get_log_entry_details(log_id):
    details = None; conn = get_db_connection(); cursor = None
    logging.info(f"--- Fetching log details for {log_id} ---")
    if not conn: logging.error(f"DB Conn fail log {log_id}"); return None
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor) # Use DictCursor
        sql = """ SELECT l.*, s_acc.customer_id AS sender_cust_id, s_cust.customer_name AS sender_name, [...] """ # Abbreviated SQL
        cursor.execute(sql, (log_id,)); entry = cursor.fetchone()
        logging.debug(f"Raw DB entry log {log_id}: {entry}")
        if entry:
            try:
                amt = Decimal(entry['amount'] or '0.00'); qber = f"{entry['qber_value']:.4f}" if entry['qber_value'] is not None else "N/A"
                ts = entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC') if entry['timestamp'] else 'N/A'
                flagged = entry.get('is_flagged', False); reason = entry.get('fraud_reason') if flagged else None
                enc_data = entry.get('encrypted_confirmation'); enc_data = enc_data if enc_data and enc_data != 'None' else None
                sender = f"{entry.get('sender_name','?')} (ID:{entry.get('sender_account_id','?')})"
                receiver = f"{entry.get('receiver_name','?')} (ID:{entry.get('receiver_account_id','?')})"
                details = { 'log_id': entry['log_id'], 'sender_customer_id': entry.get('sender_cust_id'), 'receiver_customer_id': entry.get('receiver_cust_id'),
                            'timestamp': ts, 'sender_details': sender, 'receiver_details': receiver, 'amount': f"{amt:.2f}",
                            'qkd_status': entry.get('qkd_status', 'N/A').replace('_', ' '), 'qber': qber, 'encrypted_confirmation_data': enc_data,
                            'is_flagged': flagged, 'fraud_reason': reason }
                logging.debug(f"Formatted details log {log_id}: {details}")
            except Exception as fmt_err: logging.error(f"Err format log {log_id}: {fmt_err}"); details = None
        else: logging.warning(f"Log {log_id} not found."); details = None
    except DBError as e: logging.error(f"DB error details {log_id}: {e}"); details = None # Use DBError
    except Exception as e: logging.error(f"Unexpected err details {log_id}: {e}"); details = None
    finally:
        if cursor: try: cursor.close() except DBError: pass # Use DBError
        close_db_connection(conn)
    logging.info(f"--- Finished details {log_id}. Returning: {'OK' if details else 'None'} ---")
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
def page_not_found(e): user_id = getattr(g, 'user', {}).get('id', 'Anon'); logging.warning(f"404: {request.url} U={user_id} E={e.description}"); return render_template('errors/404.html', error=e), 404
@app.errorhandler(403)
def forbidden(e): user_id = getattr(g, 'user', {}).get('id', 'Anon'); logging.warning(f"403: {request.url} U={user_id} E={e.description}"); return render_template('errors/403.html', error=e), 403
@app.errorhandler(500)
@app.errorhandler(Exception)
def internal_server_error(e):
    original_exception = getattr(e, "original_exception", e); user_id = getattr(g, 'user', {}).get('id', 'Anon')
    logging.error(f"500: {request.url} U={user_id} E={original_exception}", exc_info=original_exception)
    # Rollback attempt removed as direct DB connection management in g is not standard
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
