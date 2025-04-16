# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Includes: User Auth, MySQL, QKD Sim, Fernet Encryption, ML Fraud Detection,
#           PDF Reporting, Info Pages, Risk Simulation, Real Email Sending.
# Version: Verified Working (Post User Confirmation & Final Cleanup)

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

# --- Database Import ---
try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:
    print("\nERROR: 'mysql-connector-python' not found. Please install it: pip install mysql-connector-python")
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
    from wtforms.validators import (DataRequired, Email, EqualTo, Length, NumberRange, InputRequired,Optional) 
    WTFORMS_AVAILABLE = True
    print("--- Flask-WTF and WTForms found. Forms enabled. ---")
except ImportError:
     print("\nWARNING: 'Flask-WTF' or 'WTForms' not found. Form validation will be basic.")
     FlaskForm = None # Set to None if import fails
     # Define dummy classes below after checking FlaskForm

# --- Email Sending (Flask-Mail) ---
MAIL_AVAILABLE = False
try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
    print("--- Flask-Mail found. Email features potentially available. ---")
except ImportError:
    Mail = None
    Message = None
    print("\nWARNING: 'Flask-Mail' not found. Email features (like password reset) disabled.")

# --- Cryptography Import ---
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("\nERROR: 'cryptography' not found. Please install it: pip install cryptography")
    exit(1)

# --- Data Handling & ML Imports ---
try:
    import numpy
    import pandas
    import joblib
    import sklearn # Check if scikit-learn is installed
    print("--- NumPy, Pandas, Joblib, Scikit-learn found. ---")
except ImportError as e:
    print(f"\nERROR: Missing ML/Data library: {e}. Please install required libraries (numpy, pandas, joblib, scikit-learn).")
    exit(1)

# --- PDF Generation Import ---
try:
    import reportlab
    print("--- ReportLab found. PDF generation enabled. ---")
except ImportError:
    print("\nERROR: 'reportlab' not found. PDF reporting disabled. Please install it: pip install reportlab")
    exit(1)


# --- Local Module Imports ---
try:
    from qkd_simulation import simulate_bb84, create_qkd_report_pdf as create_qkd_simulation_report
    from fraud_detection import detect_fraud
    from pdf_generator import create_qkd_report as create_transaction_report
    from risk_simulation import run_risk_analysis
    from ml_fraud_model import load_model as load_ml_model, MODEL_FILENAME, FEATURES_FILENAME
    print("--- Local modules (QKD, Fraud, PDF, Risk, ML Model Loader) found. ---")
except ImportError as e:
    print(f"\nERROR: Failed local module import: {e}. Ensure all helper .py files are present and their dependencies are installed.")
    exit(1)
except ModuleNotFoundError as e:
    print(f"\nERROR: A library required by local modules might be missing: {e}")
    exit(1)

# --- Initialize Flask App ---
app = Flask(__name__)

# --- Configuration Loading ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_insecure_default_secret_key_32bytes_')
if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
    print("\nCRITICAL WARNING: Using default FLASK_SECRET_KEY! Set a proper key in .env or environment.")

# Use WTFORMS_AVAILABLE flag for CSRF config
app.config['WTF_CSRF_ENABLED'] = WTFORMS_AVAILABLE and os.environ.get('WTF_CSRF_ENABLED', 'True').lower() in ('true', '1', 't')

# Session Cookie Settings
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 't')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30)))

# Flask-Mail Configuration
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
        is_local_debug = app.config.get('MAIL_SERVER') == 'localhost' and app.config.get('MAIL_PORT') == 1025
        essential_config_present = all([
            app.config.get('MAIL_SERVER'),
            app.config.get('MAIL_USERNAME') if not is_local_debug else True,
            app.config.get('MAIL_PASSWORD') is not None if not is_local_debug else True,
            app.config.get('MAIL_DEFAULT_SENDER')
        ])
        if not essential_config_present and not is_local_debug:
            print("\nWARNING: Email config incomplete in environment variables. Email features may fail.")
        else:
            print(f"--- Flask-Mail initialized (Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}). ---")
    except Exception as mail_init_err:
        print(f"\nERROR: Failed to initialize Flask-Mail: {mail_init_err}")
        mail = None
        MAIL_AVAILABLE = False # Mark as unavailable if init fails
# No else needed here, MAIL_AVAILABLE handles it

# Database Configuration
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD')
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')
if not MYSQL_PASSWORD:
    print("\nCRITICAL WARNING: MYSQL_PASSWORD is not set in environment variables! Database connection will likely fail.")
MYSQL_CONFIG = {
    'host': MYSQL_HOST,
    'user': MYSQL_USER,
    'password': MYSQL_PASSWORD,
    'database': MYSQL_DB,
    'use_pure': True,
    'connection_timeout': 10
}

# Application-specific Settings
QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
QKD_NUM_QUBITS = int(os.environ.get('QKD_NUM_QUBITS', 600))
INITIAL_BALANCE = Decimal(os.environ.get('INITIAL_BALANCE', '1000.00'))
app.config['FRAUD_BLACKLIST'] = set(filter(None, os.environ.get('FRAUD_BLACKLIST', '').split(',')))
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE
if not app.secret_key or app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
     raise ValueError("CRITICAL: FLASK_SECRET_KEY is not set to a secure value.")

# Serializer for Tokens (Password Reset) - Requires SECRET_KEY
serializer = None # Initialize
try:
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
except Exception as e:
    print(f"\nERROR: Failed to initialize URLSafeTimedSerializer: {e}. Password reset disabled.")
    # Serializer remains None

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s [%(name)s:%(lineno)d]')
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('mysql.connector').setLevel(logging.WARNING)
logging.getLogger('PIL').setLevel(logging.WARNING) # Used by reportlab

# Load ML Model at startup
logging.info("Attempting ML Model load...")
if not load_ml_model():
    logging.critical(f"ML MODEL LOAD FAILED. Fraud detection may not work correctly.")
else:
    logging.info("ML model loaded successfully.")

# --- Forms Definition Block ---
if WTFORMS_AVAILABLE:
    class LoginForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Sign In')

    class RegistrationForm(FlaskForm):
         customer_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)], filters=[lambda x: x.strip() if x else x])
         email = EmailField('Email Address', validators=[DataRequired(), Email()], filters=[lambda x: x.strip().lower() if x else x])
         # *** ADD THIS LINE ***
         phone_number = StringField('Phone Number', validators=[Optional(), Length(min=10, max=20)]) # Added Optional() validator
         # *** END ADDITION ***
         password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
         confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
         # OTP and CAPTCHA fields are still omitted from the form class
         submit = SubmitField('Register Account')

    class ForgotPasswordForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()], filters=[lambda x: x.strip().lower() if x else x])
        submit = SubmitField('Send Reset Link')

    class ResetPasswordForm(FlaskForm):
        password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
        confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
        submit = SubmitField('Reset Password')

    class TransferForm(FlaskForm):
        # Use StringField for SelectField value consistency, coerce in route if needed
        receiver_account_id = SelectField('Recipient Account', validators=[InputRequired(message="Please select a recipient.")])
        amount = DecimalField('Amount', places=2, rounding=None,
                             validators=[InputRequired(message="Amount is required."),
                                         NumberRange(min=0.01, message="Amount must be at least ₹0.01.")]) # Updated message
        simulate_eve = BooleanField('Simulate Eavesdropper (Higher QBER)')
        submit = SubmitField('Initiate Secure Transfer')

else:
    # Fallback if WTForms not available
    logging.warning("Flask-WTF not found, forms defined as dummies. Using basic request.form checks.")
    class DummyForm:
        # Basic init to prevent errors on instantiation
        def __init__(self, formdata=None, obj=None, prefix='', data=None, meta=None, **kwargs):
            self._formdata = formdata # Store formdata if passed
            self.errors = {} # Initialize errors dict

        def validate_on_submit(self):
             # Crude validation: just check if it's a POST request
             return request.method == 'POST'

        def populate_obj(self, obj): pass # No-op

        def __getattr__(self, name):
             # Attempt to simulate field access
             field_data = None
             is_checkbox = name == 'simulate_eve' # Example specific checkbox handling

             if request and request.form:
                 if is_checkbox:
                     field_data = name in request.form # Checkbox presence
                 elif name in request.form:
                      field_data = request.form[name]
             elif self._formdata: # Check formdata passed during init
                 if is_checkbox:
                     field_data = name in self._formdata
                 elif name in self._formdata:
                      field_data = self._formdata[name]

             # Return a simple object that has a 'data' attribute
             field_obj = type('DummyField', (object,), {'data': field_data, 'errors': []})()
             return field_obj

    LoginForm = DummyForm
    RegistrationForm = DummyForm
    ForgotPasswordForm = DummyForm
    ResetPasswordForm = DummyForm
    TransferForm = DummyForm
# *** END FORMS DEFINITION ***

# --- Database Helper Functions ---
def get_db_connection():
    """Establishes and returns a new database connection."""
    conn = None
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected():
            logging.debug("DB connection successful.")
            return conn
        else:
            # Should not happen if connect() succeeded without error, but handle defensively
            logging.error("DB connection failed: Connection established but not active.")
            if conn: conn.close() # Close potentially broken connection
            return None
    except MySQLError as e:
        logging.critical(f"CRITICAL DATABASE CONNECTION ERROR: {e}")
        if conn: # Ensure closure even if connection failed mid-process
            try: conn.close()
            except MySQLError: pass
        return None
    except Exception as e: # Catch other errors like config issues
        logging.critical(f"CRITICAL UNEXPECTED ERROR CONNECTING TO DB: {e}")
        if conn:
            try: conn.close()
            except MySQLError: pass
        return None

def close_db_connection(conn):
    """Closes the database connection if it's open."""
    if conn and conn.is_connected():
        try:
            conn.close()
            logging.debug("Database connection closed.")
        except MySQLError as e:
            logging.error(f"Error closing database connection: {e}")
        except Exception as e:
             logging.error(f"Unexpected error closing DB connection: {e}")

def get_accounts_data(customer_id_filter=None):
    """Fetches account data, optionally filtered by customer ID. Returns list or None on DB error."""
    accounts = []
    conn = get_db_connection()
    cursor = None
    if not conn:
        # Log error, route should handle user feedback (e.g., flash message)
        logging.error("DB connection failed in get_accounts_data.")
        return None # Indicate DB error

    try:
        cursor = conn.cursor(dictionary=True)
        sql = """SELECT a.account_id, c.customer_name, a.balance, a.customer_id
                 FROM accounts a
                 JOIN customers c ON a.customer_id = c.customer_id"""
        params = []
        if customer_id_filter is not None:
            try:
                filter_id = int(customer_id_filter)
                sql += " WHERE a.customer_id = %s"
                params.append(filter_id)
            except (ValueError, TypeError):
                 logging.error(f"Invalid customer_id_filter type: {customer_id_filter}. Ignoring.")

        sql += " ORDER BY c.customer_name, a.account_id" # Consistent sort order
        cursor.execute(sql, tuple(params))
        raw_accounts = cursor.fetchall()

        for acc_row in raw_accounts:
            balance_val = None # Initialize for logging in except block
            try: # Inner try for processing each account row
                balance_val = acc_row.get('balance')
                current_balance = Decimal(balance_val) if balance_val is not None else Decimal('0.00')

                if all(k in acc_row for k in ('account_id', 'customer_name', 'customer_id')):
                    acc_row['balance'] = current_balance # Update balance in dict
                    accounts.append(acc_row) # Append the modified dict
                else:
                    logging.warning(f"Skipping account row missing required keys: {acc_row.get('account_id', 'N/A')}")

            except (InvalidOperation, TypeError) as e:
                logging.warning(f"Skipping account {acc_row.get('account_id', 'N/A')} due to invalid balance ('{balance_val}'): {e}")
            except Exception as inner_e:
                 logging.error(f"Unexpected error processing account row {acc_row.get('account_id', 'N/A')}: {inner_e}", exc_info=True)

    except MySQLError as e:
        logging.error(f"Database error fetching accounts data: {e}", exc_info=True)
        # Flash error in the route that calls this function if needed
        return None # Indicate DB error
    except Exception as e:
        logging.error(f"Unexpected error in get_accounts_data: {e}", exc_info=True)
        return None # Indicate unexpected error
    finally:
        if cursor:
            try: cursor.close()
            except MySQLError: pass
        # Close connection obtained by this function
        close_db_connection(conn)
    return accounts

def get_user_by_email(email):
    """Fetches user details by email. Returns dict or None."""
    conn = get_db_connection()
    cursor = None
    user = None
    if not conn: return None # DB connection failed
    if not isinstance(email, str) or not email: return None # Basic validation

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,))
        user = cursor.fetchone()
    except MySQLError as e:
        logging.error(f"DB Error fetching user by email ({email}): {e}")
        user = None # Ensure None on error
    except Exception as e:
        logging.error(f"Unexpected error fetching user by email ({email}): {e}", exc_info=True)
        user = None
    finally:
        if cursor:
            try: cursor.close()
            except MySQLError: pass
        close_db_connection(conn)
    return user

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None, exception_info=None):
    """Logs details of a failed transaction attempt."""
    sender_id_val = int(sender_id) if sender_id is not None else None
    receiver_id_val = int(receiver_id) if receiver_id is not None else None
    amount_str = str(amount) if isinstance(amount, Decimal) else (str(amount) if amount is not None else None)
    qber_db_val = float(qber_value) if isinstance(qber_value, (float, int)) and qber_value >= 0 else None
    is_flagged = bool(fraud_reason)
    reason_text = str(fraud_reason)[:255] if fraud_reason else None # Truncate reason
    if exception_info: # Append exception info if available
         reason_text = f"{reason_text or 'Error'} | Exception: {str(exception_info)[:150]}" # Truncate long exceptions

    logging.warning(f"Logging failed transaction attempt: Status='{failed_status}', Reason='{reason_text}'")

    log_conn = None; log_cursor = None
    try:
        log_conn = get_db_connection()
        if not log_conn:
            logging.critical("CRITICAL: DB Connection failed. UNABLE TO LOG FAILED TRANSACTION.")
            return

        log_cursor = log_conn.cursor()
        # Ensure SQL matches the table structure (including timestamp etc.)
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status,
                      qber_value, is_flagged, fraud_reason, timestamp, encrypted_confirmation, iv)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        log_values = (
            sender_id_val, receiver_id_val, amount_str, failed_status[:50], # Truncate status
            qber_db_val, is_flagged, reason_text,
            datetime.datetime.now(), # Timestamp of the failure logging
            None, None # No encrypted data/IV for failed attempts
        )
        log_cursor.execute(log_sql, log_values)
        log_conn.commit()
        logging.info(f"Failed attempt logged successfully (Status: {failed_status}).")

    except MySQLError as log_err:
        logging.critical(f"CRITICAL: Failed to log FAILED TRANSACTION (Status: {failed_status}): {log_err}", exc_info=True)
        if log_conn and log_conn.is_connected():
            try: log_conn.rollback()
            except MySQLError: pass
    except Exception as e:
         logging.critical(f"CRITICAL: Unexpected error logging failed TXN: {e}", exc_info=True)
         if log_conn and log_conn.is_connected():
             try: log_conn.rollback()
             except MySQLError: pass
    finally:
        if log_cursor:
            try: log_cursor.close()
            except MySQLError: pass
        close_db_connection(log_conn)

# --- Authentication & Session Management ---
def login_required(f):
    """Decorator to ensure user is logged in and session is valid."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        if not g.get('user'):
             # If user_id exists but g.user not loaded, session is likely invalid
             session.clear()
             flash("Your session has expired or is invalid. Please log in again.", "warning")
             logging.warning("Cleared session: user_id found but g.user not loaded.")
             return redirect(url_for('login'))
        # User is logged in and g.user is loaded
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    """Load user data into Flask's 'g' object before each request if logged in."""
    user_id = session.get('user_id')
    g.user = None # Default to None for this request
    if user_id:
        conn = get_db_connection()
        cursor = None
        if conn:
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s", (user_id,))
                user_data = cursor.fetchone()
                if user_data:
                    # User found, store in g
                    g.user = {'id': user_data['customer_id'], 'name': user_data['customer_name'], 'email': user_data['email']}
                    session.permanent = True # Refresh session lifetime on activity
                else:
                    # User ID in session but not in DB - clear invalid session
                    logging.warning(f"User {user_id} in session not found in DB. Clearing session.")
                    session.clear()
            except MySQLError as e:
                logging.error(f"DB Error loading user {user_id} for session: {e}")
                # Don't clear session on temporary DB error, but g.user remains None
            except Exception as e:
                logging.error(f"Unexpected error loading user {user_id}: {e}", exc_info=True)
            finally:
                if cursor:
                    try: cursor.close()
                    except MySQLError: pass
                close_db_connection(conn) # Close the connection used for this check
        else:
            # DB connection failed, cannot verify session validity. Clear it for safety.
            logging.error("DB connection failed in load_logged_in_user. Clearing session.")
            session.clear()

def clear_qkd_session_log():
     """Removes the last QKD simulation log from the user's session."""
     user_id = getattr(g, 'user', {}).get('id')
     if not user_id and 'user_id' in session: user_id = session['user_id'] # Fallback
     if user_id:
         log_key = f'last_qkd_log_{user_id}'
         if log_key in session:
             session.pop(log_key)
             session.modified = True # Ensure session changes are saved
             logging.info(f"Cleared QKD log from session for user {user_id}")

# --- Async Email Helper ---
def send_async_email(app_context, msg):
    """Sends email in a background thread using app context."""
    with app_context: # Use provided app context
        if not mail:
            logging.error("Mail object not initialized. Cannot send async email.")
            return
        try:
            mail.send(msg)
            logging.info(f"Async email sent successfully to {msg.recipients}")
        except Exception as e:
            logging.error(f"Error sending async email to {msg.recipients}: {e}", exc_info=True)

# --- Flask Routes ---
@app.route('/')
def home_redirect():
    """Redirects to login or index based on login status."""
    if g.get('user'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    """Main dashboard page."""
    user_id = g.user['id']
    user_accounts = get_accounts_data(customer_id_filter=user_id)
    all_accounts = get_accounts_data() # For recipient list

    if user_accounts is None: # DB error occurred
        user_accounts = []
        flash("Error loading your account information.", "error")
    if all_accounts is None:
        all_accounts = []
        flash("Error loading recipient list. Transfers may be disabled.", "error")

    receiver_accounts = [acc for acc in all_accounts if acc.get('customer_id') != user_id]
    flagged_transactions = get_flagged_transactions(user_id, limit=5)
    show_fraud_alert = bool(flagged_transactions)
    last_transfer_outcome = session.pop('last_transfer_outcome', None)

    # Prepare TransferForm (only if WTForms available)
    transfer_form = None
    if WTFORMS_AVAILABLE:
        transfer_form = TransferForm()
        # Populate choices dynamically - ensure account_id is string for value
        recipient_choices = [(str(acc['account_id']), f"{acc['customer_name']} (Acc ID: {acc['account_id']})") for acc in receiver_accounts]
        recipient_choices.insert(0, ('', '-- Select Recipient --'))
        transfer_form.receiver_account_id.choices = recipient_choices

    return render_template('index.html',
                           user_accounts=user_accounts,
                           receiver_accounts=receiver_accounts, # Pass raw list as well
                           transfer_form=transfer_form, # Pass form object (or None)
                           show_fraud_alert=show_fraud_alert,
                           flagged_transactions=flagged_transactions, # Pass for potential display
                           last_transfer_outcome=last_transfer_outcome)

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles new customer registration."""
    if g.user: return redirect(url_for('index')) # Redirect if already logged in
    form = RegistrationForm() if WTFORMS_AVAILABLE else None # Instantiate form if WTForms available

    # --- Handle POST Request ---
    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        # --- 1. Extract Form Data ---
        # This section now handles both WTForms success and manual POST data extraction
        if WTFORMS_AVAILABLE:
            # Data already validated by form.validate_on_submit()
            customer_name = form.customer_name.data
            email = form.email.data
            password = form.password.data
            phone_number = form.phone_number.data # Assumes phone_number field exists in WTForm
        else:
            # Manual extraction from request.form (for when WTFORMS_AVAILABLE is False)
            customer_name = request.form.get('customer_name','').strip()
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            confirm_password = request.form.get('confirm_password','')
            phone_number = request.form.get('phone_number', '').strip() # Get phone number

            # Basic Manual Validation (if WTForms didn't run)
            errors = []
            if not customer_name or len(customer_name) < 2: errors.append("Full Name must be at least 2 characters.")
            if not email or '@' not in email: errors.append("Please enter a valid email address.")
            if not password or len(password) < 8: errors.append("Password must be at least 8 characters long.")
            if password != confirm_password: errors.append("Passwords do not match.")
            # Optional: Basic phone number check (e.g., length) if needed here
            # if phone_number and (len(phone_number) < 10 or not phone_number.isdigit()): errors.append("Invalid phone number format.")

            if errors: # If manual validation fails
                for err in errors: flash(err, 'error')
                # Pass form=None if WTForms unavailable, otherwise pass the failed form object
                return render_template('register.html', form=form)

        # --- 2. Placeholder Validations (OTP/CAPTCHA) ---
        # These are skipped for the demo but show where real validation would occur

        # Placeholder for CAPTCHA Validation
        # captcha_response = request.form.get('g-recaptcha-response') # Example field name from CAPTCHA widget
        # In a real app, you would call a function to verify this response with the CAPTCHA provider:
        # if not verify_captcha(captcha_response):
        #     flash("Invalid CAPTCHA verification. Please try again.", "error")
        #     return render_template('register.html', form=form)
        logging.info("DEMO MODE: Skipping CAPTCHA validation.") # Log that it's skipped

        # Placeholder for OTP Validation
        # This would typically happen after the user receives and enters an OTP,
        # possibly involving an intermediate step or AJAX verification.
        # submitted_otp = request.form.get('otp_field_name') # Example OTP input field name
        # In a real app, you would verify the submitted OTP against a stored value:
        # if not verify_otp(email_or_phone, submitted_otp): # Verify against stored OTP
        #     flash("The OTP entered is incorrect or has expired.", "error")
        #     return render_template('register.html', form=form) # Or redirect back to OTP entry
        logging.info("DEMO MODE: Skipping OTP validation.") # Log that it's skipped

        # --- 3. Database Operations ---
        conn = None; cursor = None; user_exists = False; error_occurred = False

        # 3a. Pre-check if email exists
        try:
             conn = get_db_connection()
             if not conn:
                 flash("Database connection error during pre-check.", "error")
                 return render_template('register.html', form=form)

             cursor = conn.cursor(dictionary=True)
             cursor.execute("SELECT customer_id FROM customers WHERE email = %s", (email,))
             if cursor.fetchone():
                 user_exists = True
                 # Add error to form if WTForms used, otherwise flash
                 if WTFORMS_AVAILABLE and hasattr(form.email, 'errors'):
                      form.email.errors.append("Email address is already registered.")
                 else:
                      flash("Email address is already registered.", "error")
             # Optional: Add pre-check for phone number uniqueness if required

        except MySQLError as e:
            logging.error(f"Database error during registration pre-check for {email}: {e}")
            flash("A database error occurred during pre-check.", "error")
            error_occurred = True
        except Exception as e:
             logging.error(f"Unexpected error during registration pre-check: {e}", exc_info=True)
             flash("An unexpected error occurred during pre-check.", "error")
             error_occurred = True
        finally:
             if cursor:
                 try: cursor.close()
                 except MySQLError: pass
             # Keep connection ONLY if checks passed and no error
             if (user_exists or error_occurred) and conn and conn.is_connected():
                 close_db_connection(conn)

        # If email exists or error occurred, stop and re-render
        if user_exists or error_occurred:
            return render_template('register.html', form=form)

                # 3b. Insert new user (if pre-checks passed)
        # Connection should still be open from the pre-check phase if successful
        cursor = None; needs_rollback = False; new_customer_id = None
        try:
            # Double-check connection state
            if not conn or not conn.is_connected():
                logging.error("DB connection lost before registration insert transaction.")
                flash("Database connection lost. Please try registering again.", "error")
                if conn: close_db_connection(conn) # Cleanup just in case
                return render_template('register.html', form=form)

            cursor = conn.cursor() # Use standard cursor for inserts
            needs_rollback = True # Assume rollback needed until commit succeeds
            hashed_pw = generate_password_hash(password)

            # Define the SQL query to include the phone_number column
            sql_insert_customer = """
                INSERT INTO customers
                (customer_name, email, password_hash, phone_number)
                VALUES (%s, %s, %s, %s)
            """

            # Prepare the phone number value for the database:
            # If the retrieved phone_number string is empty, set it to None
            # so that NULL is inserted into the database column.
            phone_number_to_db = phone_number if phone_number else None

            # Create the tuple of parameters in the correct order for the SQL query
            customer_params = (customer_name, email, hashed_pw, phone_number_to_db)

            # ---> CODE TO ADD/EXECUTE NEXT <---

            # Execute Insert Customer Query
            cursor.execute(sql_insert_customer, customer_params)

            # Get the ID of the newly inserted customer
            new_customer_id = cursor.lastrowid
            # Check if ID was generated (crucial!)
            if not new_customer_id:
                raise MySQLError("Failed to get customer ID after insert (lastrowid is null).")
            logging.debug(f"Inserted customer '{customer_name}' (ID: {new_customer_id}) with phone: {phone_number_to_db}")

            # Insert initial account for the new customer
            sql_insert_account = "INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)"
            account_params = (new_customer_id, str(app.config['INITIAL_BALANCE']))
            cursor.execute(sql_insert_account, account_params)
            new_account_id = cursor.lastrowid
            # Check if account ID was generated
            if not new_account_id:
                raise MySQLError(f"Failed to get account ID after insert for customer {new_customer_id}.")
            logging.debug(f"Inserted account {new_account_id} for customer {new_customer_id}")

            # If both inserts succeeded, commit the transaction
            conn.commit()
            needs_rollback = False # No need to rollback if commit succeeded
            logging.info(f"Successfully registered new user: '{customer_name}' ({email}), ID: {new_customer_id}")
            flash("Registration successful! You can now log in.", "success")

            # Close resources and redirect AFTER successful commit
            if cursor: cursor.close()
            close_db_connection(conn)
            return redirect(url_for('login'))

            # ---> END OF CODE TO ADD <---

        except (MySQLError, ConnectionError) as e:
            # Handle DB errors during insert/commit
            logging.error(f"Database error during registration insert/commit for {email}: {e}", exc_info=True)
            flash("A database error occurred during registration.", "error")
        except Exception as e:
            # Handle any other unexpected errors
            logging.error(f"Unexpected error during registration insert/commit: {e}", exc_info=True)
            flash("An unexpected error occurred during registration.", "error")
        finally:
            # Cleanup: Rollback if needed, close cursor/connection
            if conn and conn.is_connected():
                if needs_rollback:
                    try:
                        conn.rollback()
                        logging.warning(f"Registration transaction rolled back for '{email}'.")
                    except MySQLError as rb_err:
                        logging.error(f"Rollback attempt failed for '{email}': {rb_err}")
                if cursor:
                    try: cursor.close()
                    except MySQLError: pass # Ignore cursor close errors here
                close_db_connection(conn) # Always close the connection used

        # If we reach here, it means the 'try' block failed after pre-checks
        # Re-render the form (flashed errors will be displayed)
        return render_template('register.html', form=form)

    # --- Handle GET Request ---
    # This renders the initial empty form or re-renders if WTForms validation failed on initial POST
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if g.user: return redirect(url_for('index'))
    form = LoginForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email', '').strip().lower()
        password = form.password.data if WTFORMS_AVAILABLE else request.form.get('password', '')

        if not email or not password: # Basic check if no WTForms
            flash("Email and password are required.", "error")
            return render_template('login.html', form=form)

        customer = get_user_by_email(email)

        if customer and check_password_hash(customer.get('password_hash',''), password):
            # Login successful
            session.clear()
            session['user_id'] = customer['customer_id']
            session.permanent = True # Use configured lifetime
            g.user = {'id': customer['customer_id'], 'name': customer['customer_name'], 'email': customer['email']} # Load g.user

            logging.info(f"User {customer['customer_name']} (ID: {customer['customer_id']}) logged in.")
            flash(f"Welcome back, {customer.get('customer_name', 'User')}!", "success")

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/') and ' ' not in next_page: # Basic redirect check
                return redirect(next_page)
            else:
                return redirect(url_for('index'))
        else:
            # Login failed
            logging.warning(f"Failed login attempt for email: {email}")
            flash("Invalid email or password.", "error")

    # Handle GET request or failed POST
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    user_name = g.user.get('name', 'N/A')
    user_id = g.user.get('id', 'N/A')
    clear_qkd_session_log() # Clear specific session data
    session.clear() # Clear all session data
    flash("You have been successfully logged out.", "info")
    logging.info(f"User {user_name} (ID: {user_id}) logged out.")
    return redirect(url_for('login'))

# Inside app.py

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handles password reset request (sending email)."""
    if g.user: return redirect(url_for('index')) # Redirect if already logged in
    form = ForgotPasswordForm() if WTFORMS_AVAILABLE else None # Instantiate form if WTForms available

    # --- Prerequisite Check ---
    # Ensure mail and serializer components are ready before proceeding
    if not MAIL_AVAILABLE or not serializer:
        log_msg = "Password reset unavailable:"
        if not MAIL_AVAILABLE: log_msg += " Mail system not configured/available."
        if not serializer: log_msg += " Serializer not initialized (SECRET_KEY issue?)."
        logging.warning(log_msg)
        flash("Password reset service is currently unavailable.", "warning")
        return redirect(url_for('login')) # Redirect if prerequisites fail

    # --- Handle POST Request ---
    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        # --- 1. Extract Email ---
        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email','').strip().lower()
        # Basic validation if WTForms not used
        if not email or '@' not in email:
             flash("Please enter a valid email address.", "error")
             return render_template('forgot_password.html', form=form)

        logging.info(f"Password reset requested for email: {email}")

        # --- 2. Check if User Exists ---
        user = get_user_by_email(email)

        # --- 3. Generate Token and Send Email (only if user exists) ---
        if user:
            try:
                # Generate Timed Token
                token_expiration_seconds = 3600 # 1 hour validity
                # Use a specific salt for password reset tokens
                token = serializer.dumps(email, salt='password-reset-salt')
                # Generate the full external URL for the reset link
                reset_url = url_for('reset_password', token=token, _external=True)
                logging.info(f"Generated password reset token/URL for {email}")

                # Prepare Email Content
                subject = "Password Reset Request - QKD Secure Bank"

                # *** CUSTOMIZE SENDER DISPLAY ***
                # Define the display name and use the configured sender address
                # This tuple formats the 'From' field in many email clients
                sender_display_tuple = ("QSB Secure Banking", app.config['MAIL_DEFAULT_SENDER'])
                # *** END CUSTOMIZATION ***

                recipients_list = [email] # Use a clear variable name
                email_body = f"""Hello {user.get('customer_name', 'Valued Customer')},

You recently requested to reset your password for your QKD Secure Bank account.
Click the link below to set a new password:

{reset_url}

This link is valid for {token_expiration_seconds // 60} minutes.

If you did not request a password reset, please ignore this email or contact support if you have concerns.

Thank you,
The QKD Secure Bank Team"""

                # Create the Flask-Mail Message object
                msg = Message(subject=subject,
                              # Use the tuple for the sender argument
                              sender=sender_display_tuple,
                              recipients=recipients_list,
                              body=email_body)

                # Queue the email for sending in a background thread
                # Pass the application context to the thread function
                thread = Thread(target=send_async_email, args=[current_app.app_context(), msg])
                thread.start()
                logging.info(f"Password reset email queued for background sending to {email}")

            except Exception as e:
                # Log errors during token generation or email queuing
                logging.error(f"ERROR generating token or queueing email for {email}: {e}", exc_info=True)
                # IMPORTANT: Do not flash a specific error here to avoid revealing internal issues
                # The code will fall through to the generic success message below

        elif not user:
            # Log the attempt for a non-existent email but don't inform the requester
            logging.info(f"Password reset requested for non-existent email address: {email}")

        # --- 4. Show Generic Confirmation Message ---
        # Always flash the same message regardless of whether the user exists
        # or if an internal error occurred during email sending.
        # This prevents attackers from probing for valid email addresses.
        flash('If an account with that email address exists, instructions have been sent. Please also check your spam or junk folder.', 'info')
        # Redirect to the login page after processing the request
        return redirect(url_for('login'))

    # --- Handle GET Request ---
    # Show the forgot password form initially
    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handles the password reset form submitted via the email link."""
    if g.user: flash("Already logged in.", "info"); return redirect(url_for('index'))
    if not serializer:
        flash("Password reset service is unavailable.", "warning"); return redirect(url_for('login'))

    email = None
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600) # 1 hour expiry
        logging.info(f"Valid password reset token decoded for: {email}")
    except SignatureExpired:
        flash('Password reset link has expired.', 'error'); return redirect(url_for('forgot_password'))
    except BadTimeSignature:
        flash('Password reset link is invalid or tampered.', 'error'); return redirect(url_for('forgot_password'))
    except Exception as e:
        logging.warning(f"Invalid password reset token error: {e}"); flash('Invalid password reset link.', 'error'); return redirect(url_for('forgot_password'))

    user = get_user_by_email(email)
    if not user:
        flash('User account associated with this link not found.', 'error'); return redirect(url_for('forgot_password'))

    form = ResetPasswordForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        new_password = form.password.data if WTFORMS_AVAILABLE else request.form.get('password')
        confirm_password = form.confirm_password.data if WTFORMS_AVAILABLE else request.form.get('confirm_password')

        # Manual validation if no WTForms
        if not WTFORMS_AVAILABLE:
             errors = []
             if not new_password or len(new_password) < 8: errors.append("Password min 8 chars")
             if new_password != confirm_password: errors.append("Passwords don't match")
             if errors:
                 for err in errors: flash(err, 'error')
                 return render_template('reset_password.html', form=form, token=token)

        # --- Update Password in DB ---
        new_pw_hash = generate_password_hash(new_password)
        conn = None; cursor = None; updated = False; needs_rollback = False

        conn = get_db_connection() # Get connection outside try for finally block access
        if not conn:
            flash('Database error. Cannot update password.', 'error')
            return render_template('reset_password.html', form=form, token=token)

        try: # Try block for the database update transaction
            cursor = conn.cursor()
            needs_rollback = True
            sql = "UPDATE customers SET password_hash = %s WHERE email = %s AND customer_id = %s" # Be specific
            params = (new_pw_hash, email, user['customer_id'])
            cursor.execute(sql, params)
            rows = cursor.rowcount
            logging.info(f"Password update query for {email}, rows affected: {rows}")

            if rows == 1:
                conn.commit()
                updated = True
                needs_rollback = False
                logging.info(f"Password updated successfully for {email}")
            elif rows == 0:
                logging.error(f"Password update failed (rows=0) for {email}. User mismatch or deleted?")
                flash('Password update failed (user mismatch or no change).', 'error')
            else: # Should not happen
                logging.error(f"Password update affected unexpected rows ({rows}) for {email}.")
                flash('Password update failed (unexpected error).', 'error')

        except MySQLError as e:
            logging.error(f"DB Error resetting password for {email}: {e}", exc_info=True)
            flash('Database error during password update.', 'error')
        except Exception as e:
            logging.error(f"Unexpected error resetting password for {email}: {e}", exc_info=True)
            flash('Unexpected error during password update.', 'error')
        finally: # Finally block associated with the DB transaction try
             if conn and conn.is_connected(): # Check connection is still valid
                 if needs_rollback:
                     try:
                         conn.rollback()
                         logging.warning(f"Password reset transaction rolled back for {email}.")
                     except MySQLError as rb_err:
                         logging.error(f"Rollback failed during password reset: {rb_err}")
                 if cursor: cursor.close()
                 close_db_connection(conn) # Close connection used for this operation

        if updated:
            flash('Password has been reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            # Re-render form if update failed after DB interaction
            return render_template('reset_password.html', form=form, token=token)

    # Handle GET request
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
    session.pop('last_transfer_outcome', None)

    # --- 1. Input Validation & Form Handling ---
    try:
        # Initialize variables that might not be set if validation fails early
        sender_id = None
        receiver_id = None # Will be set after validation
        amount = None # Initialize amount to None
        simulate_eve_checked = False

        # Get Sender Account (Needs to happen first)
        user_accounts = get_accounts_data(customer_id_filter=logged_in_user_id)
        if user_accounts is None: raise ConnectionError("DB error fetching sender account.")
        if not user_accounts: raise ValueError("Sender account not found.")
        sender_account = user_accounts[0]
        sender_id = sender_account['account_id'] # Sender ID is now known
        last_outcome['sender_id'] = sender_id

        # Handle Form Data
        if WTFORMS_AVAILABLE:
            logging.debug("WTForms available, attempting validation.")
            transfer_form = TransferForm(request.form) # Use submitted data

            # Repopulate choices is essential for validation
            all_accounts_choices = get_accounts_data()
            if all_accounts_choices is None: raise ConnectionError("DB error fetching recipient list.")
            receiver_choices_list = [acc for acc in all_accounts_choices if acc.get('customer_id') != logged_in_user_id]
            # IMPORTANT: Convert account_id to string for WTForms choices value matching request.form
            transfer_form.receiver_account_id.choices = [(str(acc['account_id']), f"{acc['customer_name']} (Acc ID: {acc['account_id']})") for acc in receiver_choices_list]
            transfer_form.receiver_account_id.choices.insert(0, ('', '-- Select Recipient --')) # Placeholder has value ''

            if transfer_form.validate_on_submit():
                logging.debug("WTForms validation successful.")
                # Data is now validated, but receiver_id is STRING
                receiver_id_str = transfer_form.receiver_account_id.data
                amount = transfer_form.amount.data # DecimalField handles this
                simulate_eve_checked = transfer_form.simulate_eve.data

                # Manual Conversion after Validation
                if not receiver_id_str: raise ValueError("Recipient selection error.")
                try: receiver_id = int(receiver_id_str) # Convert valid string ID to int
                except ValueError: raise ValueError("Invalid recipient ID format.")

            else: # WTForms validation failed
                logging.warning(f"WTForms validation failed. Errors: {transfer_form.errors}")
                errors = [f"{field.replace('_', ' ').title()}: {', '.join(errs)}" for field, errs in transfer_form.errors.items()]
                raise ValueError("Invalid input: " + "; ".join(errors))

        else: # Manual parsing if WTForms unavailable
            logging.debug("WTForms not available, using manual parsing.")
            receiver_id_str = request.form.get('receiver_account_id')
            amount_str = request.form.get('amount')
            simulate_eve_checked = 'simulate_eve' in request.form

            if not receiver_id_str: raise ValueError("Please select a recipient account.")
            try: receiver_id = int(receiver_id_str)
            except ValueError: raise ValueError("Invalid recipient account ID selected.")

            if not amount_str: raise ValueError("Amount is missing.")
            try: amount = Decimal(amount_str.strip())
            except InvalidOperation: raise ValueError("Invalid amount format.")

        # --- Common Validations (Post-Parsing) ---
        if not isinstance(receiver_id, int): raise ValueError("Internal error: Recipient ID invalid.")
        if sender_id == receiver_id: raise ValueError("Cannot transfer funds to your own account.")
        if amount is None or amount <= 0: raise ValueError("Amount must be a positive value.")

        # --- If all input validation passes ---
        last_outcome.update({'amount': f"{amount:.2f}", 'receiver_id': receiver_id, 'simulate_eve': simulate_eve_checked})
        log_status = "INPUT_VALIDATED"
        logging.info(f"Transfer Request Validated: {amount:.2f} from Acc {sender_id} to Acc {receiver_id} (SimEve: {simulate_eve_checked})")

    except (ValueError, ConnectionError, TypeError, InvalidOperation, KeyError) as e:
        logging.warning(f"Transfer input/setup failed: {e}", exc_info=(isinstance(e, ConnectionError)))
        flash(f"Transfer Failed: {e}", "error")
        last_outcome.update({'status': 'Failed', 'reason': f"Input/Setup Error: {str(e)[:100]}"})
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        amount_for_log = amount if amount is not None else Decimal('0.00')
        log_failed_attempt(sender_id, receiver_id, amount_for_log, "INPUT_ERROR", exception_info=e)
        return redirect(url_for('index'))

    except Exception as e: # Catch unexpected errors during input phase
         logging.error(f"Unexpected error during transfer input validation: {e}", exc_info=True)
         flash("An unexpected error occurred while processing your request.", "error")
         last_outcome.update({'status': 'Failed', 'reason': "Unexpected Input Error"})
         session['last_transfer_outcome'] = last_outcome; session.modified = True
         amount_for_log = amount if amount is not None else Decimal('0.00')
         log_failed_attempt(sender_id, receiver_id, amount_for_log, "UNEXPECTED_INPUT_ERR", exception_info=e)
         return redirect(url_for('index'))

    # --- 2. QKD Simulation ---
    qber_thresh = current_app.config.get('QBER_THRESHOLD', 0.15)
    n_qubits = QKD_NUM_QUBITS
    eve_rate = 0.25 if simulate_eve_checked else 0.0
    qkd_fraud_reason = None # Specific reason if QKD detects high QBER
    try:
        log_status = "QKD_RUNNING"
        logging.info(f"Running QKD simulation: N={n_qubits}, Eve={simulate_eve_checked}, Rate={eve_rate}, Thresh={qber_thresh}")
        sim_res = simulate_bb84(n_qubits=n_qubits, simulate_eve=simulate_eve_checked, qber_threshold=qber_thresh, eve_interception_rate=eve_rate)
        session[f'last_qkd_log_{logged_in_user_id}'] = sim_res; session.modified = True
        last_outcome['qkd_log_stored'] = True

        key_bin = sim_res.get('final_key_binary')
        qber = sim_res.get('qber', -1.0)
        eve_det = sim_res.get('eve_detected', False)
        qber_disp = f"{qber:.4f}" if qber >= 0 else 'N/A'
        last_outcome['qber'] = qber_disp
        logging.info(f"QKD Result: QBER={qber_disp}, Eve={eve_det}, KeyLen={len(key_bin or '')}")

        # Check QKD failure conditions
        if qber < 0: qkd_fail_reason = f"QKD simulation error ({qber})."; log_status = f"QKD_SIM_ERR"
        elif eve_det: qkd_fail_reason = f"High QBER ({qber_disp}) > Threshold ({qber_thresh:.3f}). Eve detected."; log_status = "QKD_EVE_DETECTED"; qkd_fraud_reason = "QKD Alert: High QBER"
        elif not key_bin or len(key_bin) < 128: qkd_fail_reason = f"Insufficient key bits ({len(key_bin or '')})."; log_status = "QKD_KEY_INSUFFICIENT"

        if qkd_fail_reason: raise ValueError(f"QKD Failed: {qkd_fail_reason}")

        # Derive Fernet key
        key_hash = hashlib.sha256(key_bin.encode('utf-8')).digest()
        qkd_key = base64.urlsafe_b64encode(key_hash)
        logging.info(f"QKD OK (QBER:{qber_disp}). Fernet key derived.")
        log_status = "QKD_SUCCESS"
        last_outcome['qkd_status_msg'] = "Secure Channel OK"

    except ValueError as qkd_e: # Catch specific QKD value errors
        logging.warning(f"QKD Failure: {qkd_e}")
        flash(f"Transfer Aborted: {qkd_e}", "danger")
        last_outcome.update({'status': 'Failed', 'reason': qkd_fail_reason or str(qkd_e), 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=qkd_fraud_reason, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        return redirect(url_for('index'))
    except Exception as qkd_e: # Catch unexpected QKD errors
        logging.error(f"Unexpected QKD Error: {qkd_e}", exc_info=True)
        log_status = "QKD_INTERNAL_ERR"
        flash('Transfer Aborted: Secure channel establishment error.', 'danger')
        last_outcome.update({'status': 'Failed', 'reason': 'QKD Internal Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        return redirect(url_for('index'))

    # --- 3. Database Transaction & Fraud Check ---
    conn = None; cursor = None; needs_rollback = False; log_id = None
    try:
        if not qkd_key: raise ValueError("Internal error: QKD key missing.")
        log_status = "DB_TXN_STARTING"
        conn = get_db_connection()
        if not conn: raise ConnectionError("Database connection failed before transaction.")
        cursor = conn.cursor(dictionary=True, buffered=True)
        needs_rollback = True

        # Lock & Validate Sender
        log_status = "DB_VALIDATE_SENDER"
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_info = cursor.fetchone()
        if not sender_info: raise ValueError(f"Sender account {sender_id} not found.")
        if sender_info['customer_id'] != logged_in_user_id:
            logging.critical(f"AUTHORIZATION FAILED: User {logged_in_user_id} tried account {sender_id}.")
            raise ValueError("Authorization Error: Account mismatch.")
        sender_bal = Decimal(sender_info['balance'])
        if sender_bal < amount: raise ValueError(f"Insufficient funds. Balance: ₹{sender_bal:.2f}") # Added ₹

        # Validate Receiver
        log_status = "DB_VALIDATE_RECEIVER"
        cursor.execute("SELECT a.account_id, c.customer_name, a.balance FROM accounts a JOIN customers c ON a.customer_id=c.customer_id WHERE a.account_id=%s", (receiver_id,))
        rx_info = cursor.fetchone()
        if not rx_info: raise ValueError(f"Receiver account {receiver_id} not found.")
        rx_name = rx_info['customer_name']
        last_outcome['receiver_name'] = rx_name

        # Fraud Detection
        log_status = "FRAUD_CHECK_RUNNING"
        logging.info("Running fraud check...")
        # Fetch history safely
        hist_ml = []
        try:
            cursor.execute("SELECT amount, timestamp FROM qkd_transaction_log WHERE sender_account_id=%s AND qkd_status NOT LIKE '%FAIL%' ORDER BY timestamp DESC LIMIT 10", (sender_id,))
            hist_raw = cursor.fetchall()
            for r in hist_raw:
                 try: # Inner try for each history record processing
                     amount_val = r.get('amount')
                     ts_val = r.get('timestamp')
                     if amount_val is not None and isinstance(ts_val, datetime.datetime):
                         hist_ml.append({'amount': Decimal(amount_val), 'timestamp': ts_val})
                 except (TypeError, InvalidOperation, ValueError) as hist_e:
                     logging.warning(f"Skipping history record due to processing error: {hist_e} - Record: {r}")
        except MySQLError as db_hist_err:
             logging.error(f"DB Error fetching transaction history for fraud check: {db_hist_err}")
             # Continue without history? Or fail? For demo, maybe continue.

        curr_txn = {'amount': amount, 'recipient_username': rx_name, 'timestamp': datetime.datetime.now()}
        fraud_cfg = {'blacklist': app.config.get('FRAUD_BLACKLIST', set())}
        try:
            fraud_res = detect_fraud(curr_txn, hist_ml, **fraud_cfg)
        except Exception as fraud_ml_err:
            logging.error(f"ML Fraud detection call failed: {fraud_ml_err}", exc_info=True)
            fraud_res = {'is_fraudulent': False, 'reason': 'Fraud Check Error', 'ml_score': -1}
            flash("Warning: Fraud check system error.", "warning")

        last_outcome['fraud_check'] = fraud_res
        is_fraudulent = fraud_res.get('is_fraudulent', False)
        ml_fraud_reason = fraud_res.get('reason')
        # Combine reasons: QKD reason takes precedence if it exists
        final_fraud_reason = qkd_fraud_reason or ml_fraud_reason if is_fraudulent else None
        if is_fraudulent: logging.warning(f"FRAUD ALERT: {final_fraud_reason}")
        else: logging.info("Fraud check passed or no fraud detected.")

        # Determine final status
        qkd_status_final = "SECURED_FLAGGED" if is_fraudulent else "SECURED"
        last_outcome['qkd_status_msg'] = qkd_status_final.replace('_',' ')

        # Encrypt Confirmation
        log_status = "ENCRYPTING_DATA"
        msg_to_encrypt = f"CONF;{sender_id}>{receiver_id};AMT:{amount:.2f};QBER:{qber_disp};FRAUD:{is_fraudulent};R:{final_fraud_reason or 'N/A'};T:{datetime.datetime.now().isoformat()}"
        try:
            f = Fernet(qkd_key)
            enc_b64 = f.encrypt(msg_to_encrypt.encode('utf-8')).decode('utf-8')
            last_outcome['enc_sample'] = enc_b64[:60]+'...'
        except InvalidToken: log_status = "ENC_KEY_ERR"; raise ValueError("Internal key error.")
        except Exception as fe: log_status = "ENC_FAIL"; raise ValueError(f"Encryption failed: {fe}")

        # Update Balances
        log_status = "DB_UPDATING_BALANCES"
        new_sender_bal = sender_bal - amount
        # Lock receiver row FOR UPDATE before calculating new balance
        cursor.execute("SELECT balance FROM accounts WHERE account_id=%s FOR UPDATE", (receiver_id,))
        rx_bal_row_locked = cursor.fetchone()
        if not rx_bal_row_locked: raise ValueError("Receiver account disappeared before update.")
        new_receiver_bal = Decimal(rx_bal_row_locked['balance']) + amount

        # Execute updates
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_sender_bal), sender_id))
        if cursor.rowcount != 1: raise MySQLError(f"Sender update failed (rows={cursor.rowcount})")
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_receiver_bal), receiver_id))
        if cursor.rowcount != 1: raise MySQLError(f"Receiver update failed (rows={cursor.rowcount})")

        # Log Transaction
        log_status = "DB_LOGGING_TXN"
        log_sql = "INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        log_qber_val = qber if qber is not None and qber >= 0 else None
        log_fraud_reason_val = final_fraud_reason[:255] if final_fraud_reason else None
        log_values = (sender_id, receiver_id, str(amount), qkd_status_final, enc_b64, None, log_qber_val, is_fraudulent, log_fraud_reason_val, datetime.datetime.now())
        cursor.execute(log_sql, log_values)
        log_id = cursor.lastrowid
        if not log_id: raise MySQLError("Failed to get log ID after insert.")
        last_outcome['log_id'] = log_id; logging.info(f"Txn logged: ID={log_id}")

        # Commit
        log_status = "DB_COMMITTING"
        conn.commit()
        needs_rollback = False
        logging.info("DB transaction committed successfully.")
        last_outcome['status'] = 'Success'

        # Flash success message with Rupee symbol
        flash_msg = f"Success! ₹{amount:.2f} sent. Log ID: {log_id}. Status: {qkd_status_final.replace('_',' ')} (QBER:{qber_disp})." # Added ₹
        flash_cat = "success"
        if is_fraudulent:
            short_r = (final_fraud_reason or 'Flagged').split(';')[0]
            flash_msg = f"Success (Log ID: {log_id}), but transfer FLAGGED: {short_r}. QBER: {qber_disp}."
            flash_cat = "warning"
        flash(flash_msg, flash_cat)

    except (MySQLError, ValueError, InvalidOperation, ConnectionError, AssertionError) as e:
        error_message = str(e)
        # Determine failure status if not already set by QKD/Encryption fail
        if log_status.startswith("DB_") or log_status == "INITIATED" or log_status == "FRAUD_CHECK":
            if isinstance(e, (ValueError, AssertionError)): log_status = "VALIDATION_FAIL"
            elif isinstance(e, ConnectionError): log_status = "DB_CONN_ERR"
            elif isinstance(e, MySQLError): log_status = "DB_TXN_ERR"
            else: log_status = "UNKNOWN_TXN_FAIL"

        logging.error(f"Transaction Error ({log_status}): {error_message}", exc_info=True)
        last_outcome.update({'status': 'Failed', 'reason': error_message[:200], 'qkd_status_msg': log_status.replace('_',' ')})
        if log_status == "VALIDATION_FAIL": flash(f"Transfer Failed: {error_message}", "error")
        else: flash("Transfer Failed due to a system error.", "error")
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=f"Txn Error: {error_message[:100]}", exception_info=e)

    except Exception as e: # Catch unexpected errors
        log_status = "UNEXPECTED_TXN_ERR"
        error_message = str(e)
        logging.critical(f"CRITICAL UNEXPECTED Error during transfer: {error_message}", exc_info=True)
        flash("Transfer Failed due to a critical unexpected error.", "danger")
        last_outcome.update({'status': 'Failed', 'reason': 'Critical Unexpected Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason="Critical Unexpected Error", exception_info=e)

    finally: # Cleanup for the main transaction block
        if conn and conn.is_connected():
            if needs_rollback:
                try:
                    conn.rollback()
                    logging.info(f"Transfer transaction rolled back (Final Status: {log_status}).")
                except MySQLError as rb_err:
                    logging.error(f"Rollback failed during transfer error handling: {rb_err}")
            if cursor:
                 try: cursor.close()
                 except MySQLError: pass
            close_db_connection(conn) # Close connection used for the transaction

    session['last_transfer_outcome'] = last_outcome
    session.modified = True
    return redirect(url_for('index'))

@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays transaction history for the logged-in user."""
    user_id = g.user['id']
    display_log = []
    conn = get_db_connection()
    cursor = None
    if not conn:
        flash("Database error. Cannot load history.", "error")
        return render_template('history.html', log_entries=[], user_id=user_id)

    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp AS ts,
                       l.sender_account_id AS sender_id, s_cust.customer_name AS sender_name, s_acc.customer_id AS sender_cust_id,
                       l.receiver_account_id AS receiver_id, r_cust.customer_name AS receiver_name, r_acc.customer_id AS receiver_cust_id,
                       l.amount, l.qkd_status, l.qber_value AS qber, l.encrypted_confirmation AS enc_confirm,
                       l.is_flagged, l.fraud_reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id=s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id=s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id=r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id=r_cust.customer_id
                  WHERE s_acc.customer_id=%s OR r_acc.customer_id=%s
                  ORDER BY l.timestamp DESC LIMIT 100 """
        cursor.execute(sql, (user_id, user_id))
        entries_raw = cursor.fetchall()

        for entry in entries_raw:
            try: # Inner try for formatting each log entry
                amt = Decimal(entry.get('amount', '0.00'))
                qber_val = f"{entry.get('qber'):.3f}" if entry.get('qber') is not None else "N/A"
                enc_status = "[Encrypted]" if entry.get('enc_confirm') else "[N/A]"
                if "FAIL" in entry.get('qkd_status',''): enc_status = "[N/A - Failed Txn]"

                is_flagged = entry.get('is_flagged', False)
                raw_reason = entry.get('fraud_reason')
                display_reason = raw_reason if is_flagged and raw_reason else ("Yes" if is_flagged else "No")

                direction = "Sent" if entry.get('sender_cust_id') == user_id else ("Received" if entry.get('receiver_cust_id') == user_id else "")

                display_log.append({
                    'id': entry.get('log_id'),
                    'timestamp': entry.get('ts').strftime('%Y-%m-%d %H:%M:%S') if entry.get('ts') else 'N/A',
                    'sender': f"{entry.get('sender_name', '?')} ({entry.get('sender_id', '?')})",
                    'receiver': f"{entry.get('receiver_name', '?')} ({entry.get('receiver_id', '?')})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': entry.get('qkd_status', 'N/A').replace('_', ' '),
                    'qber': qber_val,
                    'encrypted_details_status': enc_status,
                    'is_flagged_display': display_reason,
                    'fraud_reason': raw_reason,
                    'is_flagged': is_flagged,
                    'direction': direction
                })
            except Exception as display_err: # Catch errors during formatting
                logging.warning(f"Error formatting log entry {entry.get('log_id', '?')} for history: {display_err}")

    except MySQLError as e:
        flash(f"History retrieval error: {e}", "error")
        logging.error(f"History DB error user {user_id}: {e}", exc_info=True)
    except Exception as e:
        flash("Unexpected error loading history.", "error")
        logging.error(f"Unexpected history error user {user_id}: {e}", exc_info=True)
    finally: # Ensure cleanup
        if cursor: cursor.close()
        close_db_connection(conn)

    return render_template('history.html', log_entries=display_log, user_id=user_id)


@app.route('/qkd')
@login_required
def qkd_page():
    """Displays QKD info, last sim log, and QBER chart."""
    user_id = g.user['id']
    logging.info(f"--- User {user_id} accessing QKD page ---") # Add start log

    # --- 1. Get Last Simulation Log ---
    sim_log = None # Default to None
    log_key = f'last_qkd_log_{user_id}'
    try:
        sim_log = session.get(log_key, None)
        logging.debug(f"Retrieved sim_log from session key '{log_key}': {type(sim_log)}")
        if isinstance(sim_log, dict):
             logging.debug(f"Sim log keys: {list(sim_log.keys())}")
        elif sim_log is not None:
             logging.warning(f"Sim log retrieved from session is not a dictionary: {sim_log}")
    except Exception as session_err:
        logging.error(f"Error retrieving QKD simulation log from session for user {user_id}: {session_err}", exc_info=True)
        flash("Could not load previous simulation data due to a session error.", "warning")

    # --- 2. Fetch QBER History for Chart ---
    labels = []; values = []
    conn = None; cursor = None; limit = 15

    try: # Outer try for DB operations
        conn = get_db_connection()
        if conn:
            logging.debug("DB connection successful for QBER history fetch.")
            cursor = conn.cursor(dictionary=True)
            sql = """ SELECT l.log_id, l.timestamp, l.qber_value AS qber
                      FROM qkd_transaction_log l
                      LEFT JOIN accounts s ON l.sender_account_id=s.account_id
                      LEFT JOIN accounts r ON l.receiver_account_id=r.account_id
                      WHERE (s.customer_id=%s OR r.customer_id=%s)
                        AND l.qber_value IS NOT NULL AND l.qber_value >= 0
                        AND (l.qkd_status LIKE 'SECURED%' OR l.qkd_status = 'QKD_EVE_DETECTED')
                      ORDER BY l.timestamp DESC LIMIT %s """
            logging.debug(f"Executing QBER history SQL with params: ({user_id}, {user_id}, {limit})")
            cursor.execute(sql, (user_id, user_id, limit))
            history = cursor.fetchall()
            logging.debug(f"Fetched {len(history)} rows for QBER history.")
            history.reverse() # Oldest first for chart

            for entry in history:
                logging.debug(f"Processing history entry: {entry}")
                log_id = entry.get('log_id'); qber_val = entry.get('qber'); ts = entry.get('timestamp')
                if log_id and qber_val is not None and ts:
                    label = f"{ts.strftime('%m/%d %H:%M')} (ID:{log_id})"
                    try:
                        logging.debug(f"Attempting to convert QBER value '{qber_val}' (type: {type(qber_val)}) to float.")
                        qber_pct = float(qber_val) * 100
                        labels.append(label); values.append(round(qber_pct, 2))
                    except (ValueError, TypeError) as chart_err:
                        logging.warning(f"Could not process QBER value '{qber_val}' for chart (Log ID: {log_id}): {chart_err}")
                    except Exception as inner_chart_err: # Catch any other unexpected errors here
                         logging.error(f"Unexpected error processing chart data for log {log_id}: {inner_chart_err}", exc_info=True)
                else:
                    logging.warning(f"Skipping history entry due to missing data: {entry}")

        else: # DB Connection failed
            logging.error(f"DB connection failed fetching QBER history for user {user_id}.")
            labels, values = ['DB Unavailable'], [0]
            flash("Could not load QBER history due to a database connection issue.", "error")

    except MySQLError as e: # Catch DB errors
        logging.error(f"Database error fetching QBER history for user {user_id}: {e}", exc_info=True)
        labels, values = ['DB Error'], [0]
        flash("An error occurred while retrieving QBER history.", "error")
    except Exception as e: # Catch other unexpected errors
         logging.error(f"Unexpected error fetching/processing QBER history for user {user_id}: {e}", exc_info=True)
         labels, values = ['Processing Error'], [0]
         flash("An unexpected error occurred while processing history data.", "error")
    finally: # Ensure cleanup
         if cursor:
             try: cursor.close()
             except MySQLError as cur_e: logging.error(f"Error closing QBER history cursor: {cur_e}")
         if conn: close_db_connection(conn)
         logging.debug("Finished QBER history fetch attempt.")

    # --- 3. Prepare Data for Template ---
    if not labels: labels, values = ['No History'], [0] # Default chart data

    # *** FIX: Define qber_threshold_original consistently ***
    qber_threshold_config = current_app.config.get('QBER_THRESHOLD', 0.15)
    qber_threshold_original = 0.15 # Default original value
    qber_threshold_pct = 15.0      # Default percentage value
    try:
        logging.debug(f"QBER Threshold from config: {qber_threshold_config} (type: {type(qber_threshold_config)})")
        # Assign to the correct variable name WITHOUT underscore
        qber_threshold_original = float(qber_threshold_config)
        qber_threshold_pct = qber_threshold_original * 100
    except (ValueError, TypeError) as thresh_err:
         logging.error(f"Invalid QBER_THRESHOLD configuration value: {qber_threshold_config} - {thresh_err}")
         # Keep the defaults defined above
         flash("Error reading QBER threshold configuration. Using default.", "warning")
    # *** END FIX ***

    # --- 4. Render Template ---
    try:
        logging.debug(f"Rendering qkd.html with sim_log type: {type(sim_log)}")
        logging.debug(f"Passing QBER threshold original: {qber_threshold_original}") # Pass original
        logging.debug(f"Passing QBER threshold %: {qber_threshold_pct}")
        logging.debug(f"Passing history labels: {labels}")
        logging.debug(f"Passing history values: {values}")

        return render_template('qkd.html',
                           simulation_log=sim_log,
                           QBER_THRESHOLD_PCT=qber_threshold_pct, # For display/chart line
                           # *** Ensure this uses the corrected variable name ***
                           QBER_THRESHOLD_ORIGINAL=qber_threshold_original, # For comparisons in template
                           qber_history_labels=labels, # Renamed for clarity
                           qber_history_values=values) # Renamed for clarity
    except Exception as render_err:
         logging.error(f"Error rendering qkd.html template: {render_err}", exc_info=True)
         abort(500) # Trigger 500 handler


@app.route('/qkd/report/download')
@login_required
def download_qkd_report():
    """Generates and serves the PDF report for the last QKD simulation."""
    user_id = g.user['id']
    simulation_log = session.get(f'last_qkd_log_{user_id}')

    if not simulation_log:
        flash("No QKD simulation data found in session.", "warning")
        return redirect(url_for('qkd_page'))

    logging.info(f"User {user_id} downloading QKD simulation report.")
    try:
        pdf_bytes = create_qkd_simulation_report(simulation_log)
        if not pdf_bytes:
            logging.error(f"QKD PDF generation failed (returned None) for user {user_id}.")
            flash("Failed to generate QKD simulation report.", "danger")
            return redirect(url_for('qkd_page'))

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"QKD_Simulation_Report_{ts}.pdf"
        logging.info(f"Serving QKD Simulation PDF '{filename}'")
        return Response(pdf_bytes, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment;filename={filename}"})
    except Exception as e: # Catch errors during PDF generation/response
        logging.error(f"Error generating/sending QKD PDF report for user {user_id}: {e}", exc_info=True)
        flash("An error occurred while preparing the QKD report.", "danger")
        return redirect(url_for('qkd_page'))


@app.route('/quantum-impact')
def quantum_impact(): return render_template("quantum_impact.html")

@app.route('/about')
def about(): return render_template("about.html")


def get_flagged_transactions(user_id, limit=50):
    """Fetches recently flagged transactions involving the user."""
    txns = []; conn = get_db_connection(); cursor = None
    if not conn:
        logging.error(f"DB Conn fail flagged tx for user {user_id}")
        return txns # Return empty list

    try:
        cursor = conn.cursor(dictionary=True)
        sql = """SELECT l.log_id, l.timestamp AS ts, s_cust.customer_name AS sender,
                       r_cust.customer_name AS receiver, l.amount, l.fraud_reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s ON l.sender_account_id=s.account_id
                  LEFT JOIN customers s_cust ON s.customer_id=s_cust.customer_id
                  LEFT JOIN accounts r ON l.receiver_account_id=r.account_id
                  LEFT JOIN customers r_cust ON r.customer_id=r_cust.customer_id
                  WHERE (s.customer_id=%s OR r.customer_id=%s) AND l.is_flagged=TRUE
                  ORDER BY l.timestamp DESC LIMIT %s"""
        cursor.execute(sql, (user_id, user_id, limit))
        raw = cursor.fetchall()

        for entry in raw:
             try: # Process each row safely
                 amt = Decimal(entry.get('amount', '0.00'))
                 ts_str = entry.get('ts').strftime('%Y-%m-%d %H:%M:%S') if entry.get('ts') else 'N/A' # Use full timestamp
                 txns.append({
                     'id': entry.get('log_id'), 'timestamp': ts_str,
                     'sender': f"{entry.get('sender', '?')}",
                     'receiver': f"{entry.get('receiver', '?')}",
                     'amount': f"{amt:.2f}",
                     'fraud_reason': entry.get('fraud_reason', 'N/A') })
             except Exception as fe:
                 logging.warning(f"Error formatting flagged tx {entry.get('log_id', '?')}: {fe}")

    except MySQLError as e:
        logging.error(f"Flagged tx DB error user {user_id}: {e}", exc_info=True)
        flash("Error loading flagged transaction data.", "error") # Flash error in the calling context
    except Exception as e:
        logging.error(f"Unexpected error loading flagged tx user {user_id}: {e}", exc_info=True)
        flash("Unexpected error loading flagged transactions.", "error")
    finally: # Ensure cleanup
        if cursor: cursor.close()
        close_db_connection(conn)
    return txns


@app.route('/fraud')
@login_required
def fraud_page():
    """Displays the fraud center page."""
    flagged_txns = get_flagged_transactions(g.user['id'])
    return render_template("fraud.html", flagged_txns=flagged_txns)

def get_log_entry_details(log_id):
    """Fetches detailed information for a specific transaction log entry."""
    details = None
    conn = get_db_connection()
    cursor = None
    logging.info(f"--- Fetching log details for log_id: {log_id} ---") # Add this

    if not conn:
        logging.error(f"DB Conn fail log details {log_id}")
        return None

    try:
        cursor = conn.cursor(dictionary=True)
        sql = """
            SELECT
                l.*, s_acc.customer_id AS sender_cust_id, s_cust.customer_name AS sender_name,
                r_acc.customer_id AS receiver_cust_id, r_cust.customer_name AS receiver_name
            FROM qkd_transaction_log l
            LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
            LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
            LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
            LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
            WHERE l.log_id = %s
        """
        cursor.execute(sql, (log_id,))
        entry = cursor.fetchone()
        logging.debug(f"Raw DB entry fetched for log {log_id}: {entry}") # Add this

        if entry:
            try:
                # Format data carefully
                amount_val = entry.get('amount')
                amount_decimal = Decimal(amount_val) if amount_val is not None else Decimal('0.00')
                amount_display = f"{amount_decimal:.2f}"

                qber_val = entry.get('qber_value')
                qber_display = f"{qber_val:.4f}" if qber_val is not None and isinstance(qber_val, (float, Decimal)) else "N/A"

                timestamp_val = entry.get('timestamp')
                timestamp_display = timestamp_val.strftime('%Y-%m-%d %H:%M:%S UTC') if isinstance(timestamp_val, datetime.datetime) else 'N/A'

                is_flagged = entry.get('is_flagged', False)
                raw_reason = entry.get('fraud_reason')
                # Use raw reason if flagged, otherwise None/N/A
                reason_display = raw_reason if is_flagged and raw_reason else (None if not is_flagged else 'N/A')

                encrypted_hex = entry.get('encrypted_confirmation', None)
                if not encrypted_hex or encrypted_hex == 'None': # Handle if 'None' string is stored
                    encrypted_hex = None

                sender_name = entry.get('sender_name', '?')
                sender_acc_id = entry.get('sender_account_id', '?')
                receiver_name = entry.get('receiver_name', '?')
                receiver_acc_id = entry.get('receiver_account_id', '?')
                logging.debug(f"Formatting Sender: Name='{sender_name}', AccID='{sender_acc_id}'")
                logging.debug(f"Formatting Receiver: Name='{receiver_name}', AccID='{receiver_acc_id}'")

                details = {
                    'log_id': entry['log_id'],
                    'sender_customer_id': entry.get('sender_cust_id'),
                    'receiver_customer_id': entry.get('receiver_cust_id'),
                    'timestamp': timestamp_display,
                    'sender_details': f"{sender_name} (Account ID: {sender_acc_id})",
                    'receiver_details': f"{receiver_name} (Account ID: {receiver_acc_id})",
                    'amount': amount_display,
                    'qkd_status': entry.get('qkd_status', 'N/A').replace('_', ' '),
                    'qber': qber_display,
                    'encrypted_confirmation_data': encrypted_hex, # Holds actual data or None
                    'is_flagged': is_flagged,
                    'fraud_reason': reason_display, # Holds reason string or None/N/A
                }
                logging.debug(f"Formatted details dictionary for log {log_id}: {details}")

            except (InvalidOperation, TypeError, ValueError) as format_err:
                logging.error(f"Error formatting log details for log ID {log_id}: {format_err}")
                details = None
            except Exception as format_err:
                 logging.error(f"Unexpected error formatting log {log_id}: {format_err}", exc_info=True)
                 details = None
        else:
            logging.warning(f"Log entry with ID {log_id} not found in DB.")
            details = None

    except MySQLError as e:
        logging.error(f"Database error fetching details for log ID {log_id}: {e}", exc_info=True)
        details = None
    except Exception as e:
         logging.error(f"Unexpected error fetching details for log {log_id}: {e}", exc_info=True)
         details = None
    finally:
        if cursor:
            try: cursor.close()
            except MySQLError as cur_e: logging.error(f"Error closing log details cursor: {cur_e}")
        close_db_connection(conn)

    logging.info(f"--- Finished fetching log details for log_id: {log_id}. Returning: {'Details found' if details else 'None'} ---")
    return details


@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    """Generates and serves a PDF transaction report."""
    user_id = g.user['id']
    log_data = get_log_entry_details(log_id)

    if not log_data: abort(404, description="Transaction report not found.")
    # Authorization Check
    if user_id != log_data.get('sender_customer_id') and user_id != log_data.get('receiver_customer_id'):
        logging.warning(f"Auth fail: User {user_id} tried download report for log {log_id}.")
        abort(403, description="You are not authorized to view this report.")

    try:
        pdf_bytes = create_transaction_report(log_data) # Generate PDF
        if not pdf_bytes:
            logging.error(f"Transaction PDF generation failed for log {log_id}.")
            abort(500, description="Failed to generate transaction report.")

        fname = f"Transaction_Report_{log_id}_{datetime.datetime.now():%Y%m%d}.pdf"
        logging.info(f"Serving Transaction PDF '{fname}' for log {log_id}")
        return Response(pdf_bytes, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment;filename={fname}"})
    except Exception as e:
        logging.error(f"Error generating/serving transaction PDF log {log_id}: {e}", exc_info=True)
        abort(500, description="Error creating transaction report.")

@app.route('/report/<int:log_id>')
@login_required
def show_report_page(log_id):
     """Displays an HTML summary page for a specific transaction report."""
     user_id = g.user['id']
     logging.info(f"--- User {user_id} requesting report page for log_id: {log_id} ---")

     # Fetch detailed log data
     report_info = get_log_entry_details(log_id)
     logging.debug(f"Data received from get_log_entry_details for log {log_id}: {report_info}")

     # --- Authorization Check ---
     if not report_info:
         logging.warning(f"User {user_id} attempted view report page for non-existent/unfetchable log ID {log_id}.")
         flash("Report data not found.", "error")
         abort(404)

     sender_cid = report_info.get('sender_customer_id')
     receiver_cid = report_info.get('receiver_customer_id')
     logging.debug(f"Auth check for log {log_id}: User={user_id}, SenderCID={sender_cid}, ReceiverCID={receiver_cid}")
     if user_id != sender_cid and user_id != receiver_cid:
         logging.warning(f"AUTH FAILED: User {user_id} attempted view report page for log {log_id}.")
         flash("You are not authorized to view this report page.", "danger")
         abort(403)

     logging.info(f"User {user_id} authorized. Preparing render report summary page log {log_id}.")
     logging.debug(f"Passing report_info to template report.html: {report_info}")

     # Render the template, passing the fetched report_info
     return render_template('report.html', report_info=report_info)


@app.route('/risk-analysis', methods=['GET', 'POST'])
@login_required
def risk_analysis_page():
    """Handles risk analysis simulation requests."""
    risk_results = None; analysis_type='portfolio'; form_data = {}

    if request.method == 'POST':
        form_data = request.form # Preserve form data for re-rendering
        analysis_type = request.form.get('analysis_type', 'portfolio').lower()
        logging.info(f"POST request for risk analysis type: {analysis_type}")
        config = {}; default_alpha=0.05; default_num_assets=3

        try: # Parameter parsing and validation
            if analysis_type == 'risk_measure':
                alpha = float(request.form.get('param_alpha', str(default_alpha)))
                if not (0 < alpha < 1): raise ValueError("Alpha must be between 0 and 1.")
                config['alpha'] = alpha
            elif analysis_type == 'portfolio':
                num_assets = int(request.form.get('param_num_assets', str(default_num_assets)))
                if not (1 < num_assets <= 10): raise ValueError("Assets must be 2-10.")
                config['num_assets'] = num_assets
            else: # Unknown type, default to portfolio
                 logging.warning(f"Unknown risk analysis type '{analysis_type}'.")
                 analysis_type = 'portfolio'; config['num_assets'] = default_num_assets

            # Run Simulation
            logging.info(f"Running risk analysis: type='{analysis_type}', config={config}")
            risk_results = run_risk_analysis(analysis_type=analysis_type, config=config)
            if risk_results and risk_results.get('status') != 'Error':
                flash("Risk analysis simulation completed.", "success")
            else:
                flash(f"Simulation failed: {risk_results.get('details', 'Unknown error')}", "error")

        except (ValueError, TypeError) as param_err:
            logging.warning(f"Invalid parameter for risk analysis '{analysis_type}': {param_err}")
            flash(f"Invalid input parameter: {param_err}", "error")
            risk_results = {'status': 'Error', 'details': f'Invalid parameter: {param_err}'}
        except Exception as e: # Catch errors during simulation execution
            logging.error(f"Risk simulation execution error ({analysis_type}): {e}", exc_info=True)
            flash(f"Simulation failed due to an internal error.", "error")
            risk_results = {'status': 'Error', 'details': f'Internal simulation error: {e}'}

        # Render page again with results/errors and repopulated form
        return render_template('risk_analysis.html', risk_results=risk_results, analysis_type=analysis_type, form_data=form_data)

    # Handle GET request (show initial form)
    return render_template('risk_analysis.html', risk_results=None, analysis_type=analysis_type, form_data={})

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    """Inject common variables into template contexts."""
    current_year = datetime.datetime.now().year
    return dict(
        session_user=g.get('user'), # User info or None
        INITIAL_BALANCE_DISPLAY=f"{app.config.get('INITIAL_BALANCE', Decimal('0.00')):.2f}",
        QBER_THRESHOLD_DISPLAY=f"{app.config.get('QBER_THRESHOLD', 0.15):.2%}",
        current_year=current_year,
        is_mail_available=MAIL_AVAILABLE,
        are_forms_enabled=WTFORMS_AVAILABLE
        )

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    user_id = g.user.get('id', 'Anonymous') if g.get('user') else 'Anonymous'
    logging.warning(f"404 Not Found: URL={request.url}, User={user_id}, Error={e.description}")
    return render_template('errors/404.html', error=e), 404

@app.errorhandler(403)
def forbidden(e):
    user_id = g.user.get('id', 'Anonymous') if g.get('user') else 'Anonymous'
    logging.warning(f"403 Forbidden: URL={request.url}, User={user_id}, Error={e.description}")
    return render_template('errors/403.html', error=e), 403

@app.errorhandler(500)
@app.errorhandler(Exception) # Catch other unhandled exceptions
def internal_server_error(e):
    """Handles 500 errors and attempts DB rollback if possible."""
    original_exception = getattr(e, "original_exception", e) # Get original exception
    user_id = g.user.get('id', 'Anonymous') if g.get('user') else 'Anonymous'
    logging.error(f"500 Internal Server Error: URL={request.url}, User={user_id}, Error={original_exception}", exc_info=original_exception)

    # Best-effort rollback - This is complex without proper context management
    # Consider using Flask-SQLAlchemy or similar for easier transaction handling
    # conn = getattr(g, 'db_conn', None) # Hypothetical connection in g
    # if conn and conn.is_connected(): # Attempt only if connection seems to exist
    #     try:
    #         conn.rollback()
    #         logging.info("Attempted DB rollback on 500 handler.")
    #     except Exception as rb_err:
    #         logging.error(f"Rollback attempt failed during 500 handling: {rb_err}")

    return render_template('errors/500.html', error=original_exception), 500

# --- Main execution block ---
if __name__ == '__main__':
     print("\n" + "="*60 + "\n--- Starting QKD Secure Banking Demo App ---\n" + "="*60)

     # --- Dependency Checks Summary ---
     print("\n--- Dependency Status ---")
     # Optional modules check
     if WTFORMS_AVAILABLE: print("  [OK] Flask-WTF/WTForms available.")
     else: print("  [WARN] Flask-WTF/WTForms not available. Form validation limited.")
     if MAIL_AVAILABLE: print("  [OK] Flask-Mail available.")
     else: print("  [WARN] Flask-Mail not available/configured. Email features disabled.")
     # Assume critical dependencies checked during imports

     # --- Check ML Model Files ---
     print("\n--- Checking ML Model Files ---")
     try:
         model_fn = MODEL_FILENAME; features_fn = FEATURES_FILENAME
     except NameError: # Fallback if not imported
         model_fn = 'fraud_model.joblib'; features_fn = 'fraud_model_features.joblib'
         logging.warning("ML Filenames not found from import, using defaults.")
     model_path = os.path.join(script_dir, model_fn)
     features_path = os.path.join(script_dir, features_fn)
     if os.path.exists(model_path) and os.path.exists(features_path):
         print(f"  [OK] ML files found ('{model_fn}', '{features_fn}').")
         # Assume load_ml_model() succeeded earlier if we reached this point
     else:
         print(f"  [ERROR] ML file(s) NOT FOUND (Model: {model_path}, Features: {features_path}).")
         print("  [ERROR] Fraud detection may fail. Please run the training script.")
         # Consider exiting: exit(1)

     # --- Check DB Connection ---
     print("\n--- Checking DB Connection ---")
     conn_test = get_db_connection()
     if conn_test:
         print(f"  [OK] DB connection successful (Host: {MYSQL_HOST}, DB: {MYSQL_DB}).")
         try: # Simple query test
             cursor = conn_test.cursor(); cursor.execute("SELECT 1"); cursor.fetchone(); cursor.close()
             print("  [OK] DB test query successful.")
         except Exception as db_test_err:
             print(f"  [WARN] DB connected, but test query failed: {db_test_err}")
         finally: close_db_connection(conn_test)
     else:
         print(f"  [FATAL] Database connection FAILED.")
         print(f"  Config: Host={MYSQL_HOST}, User={MYSQL_USER}, DB={MYSQL_DB}, Pwd Provided={'Yes' if MYSQL_PASSWORD else 'NO'}")
         exit("FATAL: DB connection required.")

     # --- Check Email Config Summary ---
     print("\n--- Checking Email Config ---")
     if MAIL_AVAILABLE:
         is_local_dbg = app.config.get('MAIL_SERVER') == 'localhost' and app.config.get('MAIL_PORT') == 1025
         essential_cfg = all([ app.config.get('MAIL_SERVER'), app.config.get('MAIL_USERNAME') if not is_local_dbg else True, app.config.get('MAIL_PASSWORD') is not None if not is_local_dbg else True, app.config.get('MAIL_DEFAULT_SENDER') ])
         if essential_cfg or is_local_dbg: print(f"  [OK] Email configured (Server: {app.config.get('MAIL_SERVER')}).")
         else: print("  [WARN] Email config appears incomplete. Check .env/environment vars.")
     # No message needed if Mail is unavailable, already printed warning earlier

     # --- Final Checks & Server Start ---
     if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
         print("\n" + "*"*60 + "\n  CRITICAL WARNING: Using default FLASK_SECRET_KEY! Insecure.\n" + "*"*60 + "\n")

     print("\n--- Starting Server ---")
     port = int(os.environ.get('PORT', 5000))
     host = os.environ.get('HOST', '0.0.0.0') # Use '0.0.0.0' to be accessible externally
     debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

     print(f"  * Environment: {'development' if debug_mode else 'production'}")
     print(f"  * Debug mode: {'on' if debug_mode else 'off'}")
     print(f"  * Running on http://{host}:{port}/ (Press CTRL+C to quit)")
     print("="*60 + "\n")

     try:
         # Prefer Waitress for production if available
         from waitress import serve
         print("--- Using Waitress Production Server ---")
         serve(app, host=host, port=port, threads=8) # Adjust threads as needed
     except ImportError:
         print("--- Waitress not found, using Flask Development Server ---")
         if not debug_mode:
              print("  WARNING: Flask's development server is not recommended for production.")
              print("  Install Waitress for better performance: pip install waitress")
         app.run(debug=debug_mode, host=host, port=port)
     except Exception as start_err:
          logging.critical(f"Server failed to start: {start_err}", exc_info=True)
          exit("FATAL: Server start failed.")
