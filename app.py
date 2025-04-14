# app.py
# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Includes: User Auth, MySQL, QKD Sim, Fernet Encryption, ML Fraud Detection,
#           PDF Reporting, Info Pages, Risk Simulation. (Added Debug Logging)

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
from logging.handlers import RotatingFileHandler # For file logging

# --- Database Import ---
import mysql.connector
from mysql.connector import Error as MySQLError

# --- Security & Authentication ---
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# --- Forms (Flask-WTF) ---
try:
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, SubmitField, EmailField
    from wtforms.validators import DataRequired, Email, EqualTo, Length
    import email_validator
except ImportError:
     print("\nERROR: 'Flask-WTF', 'WTForms', or 'email-validator' not found.")
     print("Please install them using: pip install Flask-WTF email-validator\n")
     exit()

# --- Cryptography Import ---
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("\nERROR: 'cryptography' library not found.")
    print("Please install it using: pip install cryptography\n")
    exit()

# --- Data Handling & ML Imports ---
from decimal import Decimal, InvalidOperation
try:
    import numpy
    import pandas
    import joblib
    import sklearn
except ImportError as e:
     print(f"\nERROR: Missing critical ML/Data library: {e}")
     print("Please ensure numpy, pandas, and scikit-learn are installed: pip install numpy pandas scikit-learn")
     exit()

# --- Local Module Imports ---
try:
    from qkd_simulation import simulate_bb84, create_qkd_report_pdf
    from fraud_detection import detect_fraud
    from pdf_generator import create_qkd_report as create_txn_report_pdf
    from risk_simulation import run_risk_analysis
    from ml_fraud_model import load_model as load_ml_model, MODEL_FILENAME, FEATURES_FILENAME
except ImportError as e:
    print(f"\nERROR: Failed to import local module: {e}")
    print("Ensure qkd_simulation.py, fraud_detection.py, pdf_generator.py, risk_simulation.py, and ml_fraud_model.py exist.")
    exit()
except ModuleNotFoundError as e:
    print(f"\nERROR: A required library for local modules might be missing: {e}")
    print("Ensure scikit-learn (which includes joblib) and pandas are installed: pip install scikit-learn pandas")
    exit()


# --- Initialize Flask App ---
app = Flask(__name__)

# --- Configuration ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_insecure_default_secret_key_32bytes_')
if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
    print("\n" + "="*60 + "\nWARNING: Using default FLASK_SECRET_KEY! Set environment variable.\n" + "="*60 + "\n")

app.config.update(
    WTF_CSRF_ENABLED=True,
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30)))
)

# --- Database Configuration ---
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'WindowsPass123!') # Use your actual password or env var
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')
MYSQL_CONFIG = {'host': MYSQL_HOST, 'user': MYSQL_USER, 'password': MYSQL_PASSWORD, 'database': MYSQL_DB, 'use_pure': True, 'connection_timeout': 10}

# --- Application Specific Config ---
QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
QKD_NUM_QUBITS = int(os.environ.get('QKD_NUM_QUBITS', 600))
INITIAL_BALANCE = Decimal(os.environ.get('INITIAL_BALANCE', '1000.00'))
app.config['FRAUD_BLACKLIST'] = set(filter(None, os.environ.get('FRAUD_BLACKLIST', 'bad_user1,scammer_acc').split(',')))
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE

# --- Token Serializer Setup ---
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Setup Logging (with File Handler) ---
# CHANGE LEVEL TO logging.DEBUG TEMPORARILY FOR VERBOSE OUTPUT
log_level = logging.INFO
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(name)s:%(lineno)d]')

# Console Handler (set level via basicConfig)
logging.basicConfig(level=log_level, format='%(asctime)s [%(levelname)s] %(message)s [%(name)s:%(lineno)d]')

# File Handler (Rotating)
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'qsb_app.log')
# Rotate logs: 3 files, max 5MB each
file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(log_level) # Set file handler level

# Add file handler to the root logger
logging.getLogger('').addHandler(file_handler)

# Reduce noise from libraries
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logging.getLogger('mysql.connector').setLevel(logging.WARNING)
logging.getLogger('qiskit').setLevel(logging.WARNING)

logging.info("--- Application Logging Initialized (Console & File) ---")
# --- End Logging Setup ---


# --- Load ML Model AT STARTUP ---
logging.info("Attempting to load ML Fraud Model at app startup...")
if not load_ml_model():
    logging.critical(f"ML FRAUD DETECTION MODEL FAILED TO LOAD. Check logs and ensure '{MODEL_FILENAME}' and '{FEATURES_FILENAME}' exist. Fraud detection may be limited.")
else:
    logging.info("ML model loaded successfully at app startup.")


# --- Forms Definition ---
class LoginForm(FlaskForm):
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
     customer_name = StringField('Customer Name', validators=[DataRequired(), Length(min=2)])
     email = EmailField('Email Address', validators=[DataRequired(), Email()])
     password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
     confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
     submit = SubmitField('Register Account')

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')


# --- Database Helper Functions ---
def get_db_connection():
    logging.debug("Attempting to get DB connection...")
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected(): logging.debug("DB connection successful."); return conn
        else: logging.error("DB connection failed: Not connected state."); return None
    except MySQLError as e: logging.critical(f"CRITICAL DB Connect Error: {e}"); return None

def close_db_connection(conn):
    if conn and conn.is_connected():
        try: conn.close(); logging.debug("DB connection closed.")
        except MySQLError as e: logging.error(f"Error closing DB connection: {e}")

def get_accounts_data(customer_id_filter=None):
    logging.debug(f"Fetching accounts data (Filter: {customer_id_filter})...")
    accounts = []; conn = get_db_connection(); cursor = None
    if not conn: return accounts # Error logged in get_db_connection
    try:
        cursor = conn.cursor(dictionary=True)
        sql = "SELECT a.account_id, c.customer_name, a.balance, a.customer_id FROM accounts a JOIN customers c ON a.customer_id = c.customer_id"
        params = []
        if customer_id_filter is not None: sql += " WHERE a.customer_id = %s"; params.append(customer_id_filter)
        sql += " ORDER BY a.account_id"
        cursor.execute(sql, tuple(params)); raw_accounts = cursor.fetchall()
        logging.debug(f"Found {len(raw_accounts)} raw account(s).")
        for acc in raw_accounts:
            try:
                balance_val = acc.get('balance'); acc['balance'] = Decimal(balance_val) if balance_val is not None else Decimal('0.00')
                if all(k in acc for k in ('account_id', 'customer_name', 'customer_id')): accounts.append(acc)
                else: logging.warning(f"Skipping account due to missing keys: {acc.get('account_id', 'N/A')}")
            except (InvalidOperation, TypeError) as e: logging.warning(f"Skipping account {acc.get('account_id')} due to invalid balance format ('{balance_val}'): {e}")
    except MySQLError as e: logging.error(f"Error fetching accounts: {e}", exc_info=True); flash("Error loading account data.", "error")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    logging.debug(f"Returning {len(accounts)} processed account(s).")
    return accounts

def get_user_by_email(email):
    logging.debug(f"Fetching user by email: {email}")
    conn = get_db_connection(); cursor = None; user = None
    if not conn: return None
    try: cursor = conn.cursor(dictionary=True); cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,)); user = cursor.fetchone()
    except MySQLError as e: logging.error(f"DB Error getting user by email ({email}): {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    logging.debug(f"User lookup result for {email}: {'Found' if user else 'Not Found'}")
    return user

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None):
     sender_id_val = sender_id if sender_id is not None else -1
     receiver_id_val = receiver_id if receiver_id is not None else -1
     amount_str = str(amount) if isinstance(amount, Decimal) else (str(amount) if amount is not None else None)
     log_conn = None; log_cursor = None
     logging.info(f"Logging failed transaction attempt status: {failed_status}")
     try:
        log_conn = get_db_connection();
        if not log_conn: raise ConnectionError("DB Connection failed for logging failed transaction")
        log_cursor = log_conn.cursor()
        log_sql = "INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason, encrypted_confirmation) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        qber_db_val = qber_value if isinstance(qber_value, (float, int)) and qber_value >= 0 else None
        is_flagged = bool(fraud_reason)
        log_values = (sender_id_val, receiver_id_val, amount_str, failed_status, qber_db_val, is_flagged, fraud_reason, None)
        log_cursor.execute(log_sql, log_values); log_conn.commit()
        logging.info(f"Failed attempt logged. Status: {failed_status}, Flagged: {is_flagged}, Reason: {fraud_reason}")
     except (MySQLError, ConnectionError) as log_err:
        logging.critical(f"CRITICAL: Failed to log FAILED transaction ({failed_status}): {log_err}", exc_info=True);
        if log_conn and log_conn.is_connected():
            try: log_conn.rollback()
            except MySQLError: pass
     finally:
        if log_cursor: log_cursor.close(); close_db_connection(log_conn)


# --- Authentication & Session Management ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
             flash("Please log in to access this page.", "warning")
             return redirect(url_for('login', next=request.url))
        if not g.get('user'):
             session.clear(); flash("Session error or user not found. Please log in again.", "warning")
             return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id'); g.user = None
    if user_id:
         conn = get_db_connection(); cursor = None
         if conn:
             try:
                 cursor = conn.cursor(dictionary=True)
                 cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s", (user_id,))
                 user_data = cursor.fetchone()
                 if user_data: g.user = {'id': user_data.get('customer_id'), 'name': user_data.get('customer_name'), 'email': user_data.get('email')}
                 else: logging.warning(f"User ID {user_id} in session but not found in DB. Clearing session."); session.clear()
             except MySQLError as e: logging.error(f"Error fetching user details for session user ID {user_id}: {e}")
             finally:
                 if cursor: cursor.close(); close_db_connection(conn)
         else: session.clear(); logging.error("DB connection failed during load_logged_in_user. Cleared session.")

def clear_qkd_session_log():
     user_id = getattr(g, 'user', {}).get('id')
     if not user_id and 'user_id' in session: user_id = session['user_id']
     if user_id:
         log_key = f'last_qkd_log_{user_id}'
         if log_key in session: session.pop(log_key); session.modified = True; logging.info(f"Cleared QKD log data for user {user_id}")


# --- Flask Routes ---

@app.route('/')
def home_redirect():
    logging.debug("Routing '/'")
    if g.get('user'): return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    logging.debug(f"Rendering index page for user {g.user['id']}")
    user_id = g.user['id']
    user_accounts = get_accounts_data(customer_id_filter=user_id)
    all_accounts = get_accounts_data()
    if user_accounts is None: user_accounts = []
    if all_accounts is None: all_accounts = []
    receiver_accounts = [acc for acc in all_accounts if acc.get('customer_id') != user_id]
    flagged_transactions = get_flagged_transactions(user_id, limit=5)
    show_fraud_alert = bool(flagged_transactions)
    last_transfer_outcome = session.pop('last_transfer_outcome', None)
    if last_transfer_outcome: logging.debug(f"Displaying last transfer outcome: {last_transfer_outcome.get('status')}")
    return render_template('index.html', user_accounts=user_accounts, receiver_accounts=receiver_accounts, show_fraud_alert=show_fraud_alert, last_transfer_outcome=last_transfer_outcome)

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    logging.debug(f"Entered register_customer route (Method: {request.method})")
    if g.user: return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        customer_name = form.customer_name.data.strip(); email = form.email.data.strip().lower(); password = form.password.data
        logging.info(f"Registration attempt for email: {email}")
        conn = get_db_connection(); cursor = None
        needs_rollback = False
        if not conn:
            flash("Database connection error.", "error")
            return render_template('register.html', form=form)
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT customer_id FROM customers WHERE customer_name = %s OR email = %s", (customer_name, email))
            existing_user = cursor.fetchone()
            if existing_user:
                cursor.execute("SELECT customer_id FROM customers WHERE email = %s", (email,))
                if cursor.fetchone(): form.email.errors.append(f"Email already registered.")
                else: form.customer_name.errors.append(f"Name already exists.")
                if cursor: cursor.close(); close_db_connection(conn)
                return render_template('register.html', form=form)

            needs_rollback = True
            hashed_pw = generate_password_hash(password)
            logging.debug("Inserting new customer...")
            cursor.execute("INSERT INTO customers (customer_name, email, password_hash) VALUES (%s, %s, %s)", (customer_name, email, hashed_pw)); customer_id = cursor.lastrowid
            if not customer_id: raise MySQLError("Failed customer insert.")
            logging.debug(f"Inserted customer {customer_id}. Inserting account...")
            cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (customer_id, str(app.config['INITIAL_BALANCE']))); account_id = cursor.lastrowid
            if not account_id: raise MySQLError("Failed account insert.")
            logging.debug(f"Inserted account {account_id} for customer {customer_id}. Committing...")
            conn.commit(); needs_rollback = False
            logging.info(f"Registered {customer_name} ({email}) - CustID {customer_id}, AccID {account_id}")
            flash(f"Customer '{customer_name}' registered! Please login.", "success")
            if cursor: cursor.close(); close_db_connection(conn)
            return redirect(url_for('login'))

        except MySQLError as e:
            logging.error(f"DB error during registration: {e}", exc_info=True)
            flash("DB registration error.", "error")
        except Exception as e:
             logging.error(f"Unexpected registration error: {e}", exc_info=True)
             flash("Unexpected registration error.", "error")
        finally:
            if conn and conn.is_connected():
                if needs_rollback:
                    try: conn.rollback(); logging.warning(f"Transaction rolled back due to registration error.")
                    except MySQLError as rb_err: logging.error(f"Rollback attempt failed during registration error handling: {rb_err}")
                if cursor: cursor.close()
                close_db_connection(conn)
        logging.debug("Exiting register_customer route after error or validation failure.")
        return render_template('register.html', form=form)
    logging.debug("Exiting register_customer route (GET request or initial validation failure).")
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.debug(f"Entered login route (Method: {request.method})")
    if g.user: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower(); password = form.password.data
        logging.info(f"Login attempt for email: {email}")
        customer = get_user_by_email(email)
        if customer and check_password_hash(customer.get('password_hash',''), password):
            session.clear(); session['user_id'] = customer['customer_id']; session['user_name'] = customer['customer_name']; session['user_email'] = customer['email']; session.permanent = True
            logging.info(f"User {customer['customer_name']} (ID: {customer['customer_id']}) logged in successfully.")
            flash(f"Welcome back, {customer['customer_name']}!", "success")
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/') and not next_page.startswith('//') and ' ' not in next_page:
                logging.debug(f"Redirecting logged-in user to 'next' page: {next_page}")
                return redirect(next_page)
            else:
                logging.debug("Redirecting logged-in user to index.")
                return redirect(url_for('index'))
        else: logging.warning(f"Failed login attempt for email: {email}"); flash("Invalid email or password.", "error")
    logging.debug("Exiting login route (GET or failed validation).")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    user_name_for_log = g.user.get('name', 'N/A'); user_id_for_log = g.user.get('id', 'N/A')
    logging.debug(f"Logging out user {user_name_for_log} (ID: {user_id_for_log})")
    clear_qkd_session_log(); session.clear()
    flash("You have been logged out.", "info"); logging.info(f"User {user_name_for_log} (ID: {user_id_for_log}) logged out.")
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    logging.debug(f"Entered forgot_password route (Method: {request.method})")
    if g.user: return redirect(url_for('index'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        logging.info(f"Password reset requested for: {email}"); user = get_user_by_email(email)
        if user:
            try:
                token = serializer.dumps(email, salt='password-reset-salt')
                reset_url = url_for('reset_password', token=token, _external=True)
                logging.info(f"Generated reset URL for {email}")
                print("\n" + "*" * 80 + f"\nSIMULATING PASSWORD RESET EMAIL:\nTo: {email}\nSubject: Reset Your QSB Password\nBody:\n Hello {user.get('customer_name', '')},\n Reset link (expires 1hr):\n {reset_url}\n Ignore if not requested.\n" + "*" * 80 + "\n")
            except Exception as e: logging.error(f"ERROR during token/URL generation for {email}: {e}", exc_info=True)
        flash('If an account exists, password reset instructions sent.', 'info'); return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    logging.debug(f"Entered reset_password route (Method: {request.method})")
    if g.user: flash("You are already logged in.", "info"); return redirect(url_for('index'))
    email = None
    try: email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired: flash('Password reset link expired.', 'error'); return redirect(url_for('forgot_password'))
    except Exception as e: logging.warning(f"Invalid reset token. Error: {e}"); flash('Invalid reset link.', 'error'); return redirect(url_for('forgot_password'))
    user = get_user_by_email(email)
    if not user: flash('User not found.', 'error'); return redirect(url_for('forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password_hash = generate_password_hash(form.password.data); conn = get_db_connection(); cursor = None; updated = False
        needs_rollback = False
        if not conn: flash('DB error.', 'error'); return render_template('reset_password.html', form=form, token=token)
        else:
            try:
                cursor = conn.cursor()
                needs_rollback = True
                logging.debug(f"Attempting password update for {email}")
                cursor.execute("UPDATE customers SET password_hash = %s WHERE email = %s", (new_password_hash, email))
                if cursor.rowcount == 1:
                    conn.commit(); updated = True; needs_rollback = False
                    logging.info(f"Password updated for {email}")
                else:
                    logging.error(f"Password update failed (rowcount={cursor.rowcount}) for {email}."); flash('Update failed.', 'error')
            except MySQLError as e:
                 logging.error(f"DB Error resetting password for {email}: {e}", exc_info=True)
                 flash('DB error during update.', 'error')
            except Exception as e:
                 logging.error(f"Unexpected error resetting password for {email}: {e}", exc_info=True)
                 flash('Unexpected error during update.', 'error')
            finally:
                 if conn and conn.is_connected():
                     if needs_rollback:
                         try: conn.rollback(); logging.warning(f"Transaction rolled back during password reset for {email}.")
                         except MySQLError as rb_err: logging.error(f"Rollback attempt failed during password reset error handling: {rb_err}")
                     if cursor: cursor.close()
                     close_db_connection(conn)
        if updated: flash('Password reset successful. Please log in.', 'success'); return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, token=token)


# --- Transfer Route ---
@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    logging.debug("Entered transfer_funds route")
    # 1. Input Extraction & Basic Validation
    sender_id_str = request.form.get('sender_account_id'); receiver_id_str = request.form.get('receiver_account_id'); amount_str = request.form.get('amount')
    simulate_eve_checked = 'simulate_eve' in request.form
    sender_id = None; receiver_id = None; amount = None;
    logged_in_user_id = g.user['id']
    session.pop('last_transfer_outcome', None); last_outcome = {'timestamp': datetime.datetime.now().isoformat()}
    try:
        if not sender_id_str: raise ValueError("Sender account must be selected.")
        sender_id = int(sender_id_str); logging.debug(f"Sender ID: {sender_id}")
        if not receiver_id_str: raise ValueError("Receiver account must be selected.")
        receiver_id = int(receiver_id_str); logging.debug(f"Receiver ID: {receiver_id}")
        if not amount_str: raise ValueError("Transfer amount must be entered.")
        amount = Decimal(amount_str.strip()); logging.debug(f"Amount: {amount}")
        if sender_id == receiver_id: raise ValueError("Sender and Receiver accounts cannot be the same.")
        if amount <= 0: raise ValueError("Transfer amount must be positive.")
        last_outcome.update({'amount': f"{amount:.2f}", 'sender_id': sender_id, 'receiver_id': receiver_id})
    except (TypeError, ValueError, InvalidOperation) as e:
        logging.warning(f"Invalid transfer input by User {logged_in_user_id}: {e}")
        flash(f"Invalid input: {e}", "error")
        last_outcome.update({'status': 'Failed', 'reason': f"Invalid Input: {e}"})
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))

    # 2. QKD Simulation & Key Generation
    logging.info(f"Transfer Request by User {logged_in_user_id}: {amount:.2f} from Acct {sender_id} to Acct {receiver_id} (Sim Eve: {simulate_eve_checked})")
    qber_threshold = current_app.config.get('QBER_THRESHOLD', 0.15); num_qubits = QKD_NUM_QUBITS; eve_rate = 0.25
    qkd_fernet_key = None; simulation_result = {}; qber = -1.0; qkd_failure_reason = None
    failed_status_for_log = "UNKNOWN_QKD_FAIL"; fraud_reason_for_log = None
    logging.debug("Calling QKD simulation...")
    try:
        simulation_result = simulate_bb84(n_qubits=num_qubits, simulate_eve=simulate_eve_checked, qber_threshold=qber_threshold, eve_interception_rate=eve_rate if simulate_eve_checked else 0.0)
        session[f'last_qkd_log_{logged_in_user_id}'] = simulation_result; session.modified = True; last_outcome['qkd_log_stored'] = True
        logging.debug(f"QKD simulation returned: QBER={simulation_result.get('qber')}, KeyLength={simulation_result.get('final_key_length')}, EveDetected={simulation_result.get('eve_detected')}")
        final_key_binary = simulation_result.get('final_key_binary'); qber = simulation_result.get('qber', -1.0); eve_detected_by_sim = simulation_result.get('eve_detected', False)
        qber_display = f"{qber:.4f}" if qber >= 0 else ('N/A' if qber == -1.0 else f"ERR_{int(abs(qber))}"); last_outcome['qber'] = qber_display
        if qber < 0: qkd_failure_reason = f"QKD simulation/QBER failed (Code: {qber})."; failed_status_for_log = f"QKD_ERROR_{int(abs(qber))}"
        elif eve_detected_by_sim: qkd_failure_reason = f"Eavesdropping Detected / High QBER ({qber_display} > {qber_threshold:.2f})."; failed_status_for_log = "QBER_THRESHOLD_EXCEEDED"; fraud_reason_for_log = f"QKD Alert: {qkd_failure_reason}"
        elif not final_key_binary: qkd_failure_reason = f"Insufficient key bits generated (QBER OK: {qber_display})."; failed_status_for_log = "KEY_LENGTH_FAIL"
        if qkd_failure_reason: raise ValueError(f"QKD Failed: {qkd_failure_reason}")
        logging.info(f"QKD Succeeded (QBER: {qber_display}). Deriving Fernet key...")
        key_hash_bytes = hashlib.sha256(final_key_binary.encode('utf-8')).digest(); qkd_fernet_key = base64.urlsafe_b64encode(key_hash_bytes)
    except ValueError as qkd_fail_e:
        logging.warning(f"QKD Failure for User {logged_in_user_id}: {qkd_fail_e}")
        flash(f"Transfer Aborted: {qkd_fail_e}", "danger")
        last_outcome.update({'status': 'Failed', 'reason': qkd_failure_reason, 'qkd_status_msg': failed_status_for_log.replace("_", " ")})
        log_failed_attempt(sender_id, receiver_id, amount, failed_status_for_log, qber_value=qber if qber >=0 else None, fraud_reason=fraud_reason_for_log)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))
    except Exception as qkd_err:
        logging.error(f"Unexpected QKD/Key error for User {logged_in_user_id}: {qkd_err}", exc_info=True)
        failed_status = "QKD_INTERNAL_ERROR"; flash(f'Transfer Aborted: Secure channel error.', 'danger')
        last_outcome.update({'status': 'Failed', 'reason': 'QKD Internal Error', 'qkd_status_msg': failed_status.replace("_", " ")})
        log_failed_attempt(sender_id, receiver_id, amount, failed_status)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))

    # 3. Database Transaction & Classical/ML Checks
    conn = None; cursor = None; failed_status = "UNKNOWN_DB_FAIL"; fraud_check_result = {'is_fraudulent': False, 'reason': None, 'ml_score': -1.0}; needs_rollback = False
    try:
        if not qkd_fernet_key: raise ValueError("Internal Error: QKD key missing.")
        conn = get_db_connection();
        if not conn: raise ConnectionError("Database connection failed before transaction.")
        # conn.start_transaction(); # Use commit/rollback on connection
        cursor = conn.cursor(dictionary=True, buffered=True);
        needs_rollback = True
        logging.debug("Starting DB transaction for transfer.")

        # 3a. Auth & Pre-Transfer DB Checks
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,)); sender_info = cursor.fetchone()
        if not sender_info: raise ValueError(f"Sender account {sender_id} not found.")
        if sender_info['customer_id'] != logged_in_user_id: raise ValueError("Authorization Error.")
        sender_balance = Decimal(sender_info['balance']);
        if sender_balance < amount: raise ValueError(f"Insufficient funds (Bal: {sender_balance:.2f})")
        cursor.execute("SELECT a.account_id, c.customer_name FROM accounts a JOIN customers c ON a.customer_id = c.customer_id WHERE a.account_id = %s", (receiver_id,)); receiver_info = cursor.fetchone()
        if not receiver_info: raise ValueError(f"Receiver account {receiver_id} not found.")
        receiver_username = receiver_info['customer_name']; last_outcome['receiver_name'] = receiver_username
        logging.debug(f"DB Checks Passed: Sender Bal: {sender_balance}, Receiver: {receiver_username}")

        # 3b. Fraud Detection Call
        logging.info("Running ML-based fraud detection...")
        cursor.execute("SELECT amount, timestamp FROM qkd_transaction_log WHERE sender_account_id = %s ORDER BY timestamp DESC LIMIT 5", (sender_id,))
        history_raw = cursor.fetchall(); history_for_ml = []
        for r in history_raw:
             try:
                 hist_amount = Decimal(r['amount']) if r.get('amount') is not None else Decimal('0.00'); hist_ts = r.get('timestamp');
                 if isinstance(hist_ts, datetime.datetime): history_for_ml.append({'amount': hist_amount, 'timestamp': hist_ts})
             except Exception as hist_e: logging.warning(f"Skipping history record for ML preprocessing: {hist_e}")
        current_txn_for_fraud = {'amount': amount, 'recipient_username': receiver_username, 'timestamp': datetime.datetime.now()}
        fraud_config = {'blacklist': current_app.config.get('FRAUD_BLACKLIST', set())}
        fraud_check_result = detect_fraud(current_transaction=current_txn_for_fraud, user_transaction_history=history_for_ml, **fraud_config)
        last_outcome['fraud_check'] = fraud_check_result; logging.debug(f"Fraud detection result: {fraud_check_result}")

        qkd_status = "SECURED_FLAGGED" if fraud_check_result['is_fraudulent'] else "SECURED"
        if fraud_check_result['is_fraudulent']: logging.warning(f"Fraud Alert for Txn: {fraud_check_result['reason']}")
        else: logging.info("Fraud check passed.")

        # 3c. Encrypt Confirmation Message
        logging.info("Encrypting confirmation message...")
        msg_to_encrypt = f"CONFIRMED;FROM:{sender_id};TO:{receiver_id};AMT:{amount:.2f};QBER:{qber_display};TIME:{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        try:
            f = Fernet(qkd_fernet_key); encrypted_confirmation_bytes = f.encrypt(msg_to_encrypt.encode('utf-8')); encrypted_confirmation_b64 = encrypted_confirmation_bytes.decode('utf-8')
            last_outcome['encrypted_sample'] = encrypted_confirmation_b64[:60] + ('...' if len(encrypted_confirmation_b64) > 60 else '')
            logging.debug("Encryption successful.")
        except InvalidToken: failed_status = "ENCRYPTION_KEY_ERROR"; raise ValueError("Internal encryption error.")
        except Exception as fernet_err: failed_status = "ENCRYPTION_FAIL"; raise ValueError(f"Encryption failed: {fernet_err}")

        # 3d. Database Balance Update
        logging.info("Updating account balances..."); new_sender_balance = sender_balance - amount
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (receiver_id,)); receiver_balance_row = cursor.fetchone();
        if not receiver_balance_row: raise ValueError("Receiver account disappeared.")
        new_receiver_balance = Decimal(receiver_balance_row['balance']) + amount
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_sender_balance), sender_id));
        if cursor.rowcount != 1: raise MySQLError(f"Sender update failed for {sender_id}")
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_receiver_balance), receiver_id));
        if cursor.rowcount != 1: raise MySQLError(f"Receiver update failed for {receiver_id}")
        logging.debug(f"Balances updated: Sender={new_sender_balance}, Receiver={new_receiver_balance}")

        # 3e. Log Successful Transaction
        logging.info(f"Logging successful transaction to DB with status: {qkd_status}")
        log_sql = "INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, qber_value, is_flagged, fraud_reason) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        log_qber_db = qber if qber is not None and qber >= 0 else None
        log_values = (sender_id, receiver_id, str(amount), qkd_status, encrypted_confirmation_b64, log_qber_db, fraud_check_result['is_fraudulent'], fraud_check_result['reason'])
        cursor.execute(log_sql, log_values); log_id = cursor.lastrowid
        if not log_id: raise MySQLError("Failed log insert.")
        last_outcome['log_id'] = log_id; logging.debug(f"Transaction logged with ID: {log_id}")

        # 3f. Commit Transaction
        logging.info("Attempting transaction commit...")
        conn.commit(); needs_rollback = False
        logging.info("Database transaction committed.")
        last_outcome['status'] = 'Success'; last_outcome['qkd_status_msg'] = qkd_status.replace("_", " ")

        flash_msg = f"Transfer successful! Log ID: {log_id}. Secured (QBER: {qber_display})."
        flash_category = "success"
        if fraud_check_result['is_fraudulent']:
            short_reason = fraud_check_result.get('reason', "Flagged").split(';')[0]
            flash_msg = f"Transfer successful (Log ID: {log_id}), but FLAGED: {short_reason}"
            flash_category = "warning"
        flash(flash_msg, flash_category)

    except (MySQLError, ValueError, InvalidOperation, ConnectionError, AssertionError) as e:
        if failed_status == "UNKNOWN_DB_FAIL":
            if isinstance(e, (ValueError, AssertionError)): failed_status = "VALIDATION_FAIL"
            elif isinstance(e, ConnectionError): failed_status = "DB_CONNECTION_ERROR"
            else: failed_status = "DB_TRANSACTION_ERROR"
        logging.error(f"Transaction Error ({failed_status}) for User {logged_in_user_id}: {e}", exc_info=True)
        last_outcome.update({'status': 'Failed', 'reason': str(e), 'qkd_status_msg': failed_status.replace("_", " ")})
        # Rollback handled in finally
        if failed_status == "VALIDATION_FAIL": flash(f"Transfer Failed: {e}", "error")
        else: flash("Transfer Failed due to a system error.", "error")
        log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=qber if qber >=0 else None, fraud_reason=f"Txn Error: {str(e)}")
    finally:
        if conn and conn.is_connected():
            if needs_rollback:
                logging.debug("Attempting transaction rollback...")
                try: conn.rollback(); logging.info("Transaction rolled back due to error.")
                except MySQLError as rb_err: logging.error(f"Rollback attempt FAILED during transfer error handling: {rb_err}")
            if cursor: cursor.close()
            close_db_connection(conn)

    # 4. Redirect to Index with Outcome
    logging.debug(f"Exiting transfer_funds route. Outcome: {last_outcome.get('status')}")
    session['last_transfer_outcome'] = last_outcome; session.modified = True;
    return redirect(url_for('index'))


# --- History Route ---
@app.route('/history', methods=['GET'])
@login_required
def history():
    logging.debug(f"Rendering history page for user {g.user['id']}")
    user_id = g.user['id']; display_log = []; conn = get_db_connection(); cursor = None
    if not conn: flash("Database error loading history.", "error"); return render_template('history.html', log_entries=[])
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp, l.sender_account_id, s_cust.customer_name AS sender_name,
                       l.receiver_account_id, r_cust.customer_name AS receiver_name, l.amount, l.qkd_status,
                       l.qber_value, l.encrypted_confirmation, l.is_flagged, l.fraud_reason
                  FROM qkd_transaction_log l LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE s_acc.customer_id = %s OR r_acc.customer_id = %s ORDER BY l.timestamp DESC LIMIT 100 """
        cursor.execute(sql, (user_id, user_id)); log_entries_raw = cursor.fetchall()
        for entry in log_entries_raw:
            try:
                amt = Decimal(entry['amount'] or '0.00'); qber = f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A";
                decrypted_details = "[Encrypted]" if entry.get('encrypted_confirmation') else "[Not Applicable]"
                display_log.append({
                    'id': entry['log_id'], 'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (Acc: {entry.get('sender_account_id', '?')})", 'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})",
                    'amount': f"{amt:.2f}", 'qkd_status': entry['qkd_status'], 'qber': qber, 'decrypted_details': decrypted_details,
                    'is_flagged': entry.get('is_flagged', False), 'fraud_reason': entry.get('fraud_reason')})
            except Exception as display_err: logging.warning(f"Error formatting log entry {entry.get('log_id', '?')} for history: {display_err}")
    except MySQLError as e: flash(f"Could not retrieve history: {e}", "error"); logging.error(f"Error retrieving history for user {user_id}: {e}", exc_info=True)
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return render_template('history.html', log_entries=display_log)


# --- Info/Feature Routes ---
@app.route('/qkd')
@login_required
def qkd_page():
    logging.debug(f"Rendering QKD page for user {g.user['id']}")
    user_id = g.user['id']; simulation_log = session.get(f'last_qkd_log_{user_id}', None)
    qber_history_labels = []; qber_history_values = []; conn = get_db_connection(); cursor = None; history_limit = 10
    if conn:
        try:
             cursor = conn.cursor(dictionary=True)
             sql = """ SELECT log_id, qber_value FROM qkd_transaction_log l LEFT JOIN accounts s ON l.sender_account_id = s.account_id LEFT JOIN accounts r ON l.receiver_account_id = r.account_id
                       WHERE (s.customer_id = %s OR r.customer_id = %s) AND l.qber_value IS NOT NULL AND l.qber_value >= 0 ORDER BY l.timestamp DESC LIMIT %s """
             cursor.execute(sql, (user_id, user_id, history_limit)); history_data = cursor.fetchall(); history_data.reverse()
             for entry in history_data: qber_history_labels.append(f"Log {entry['log_id']}"); qber_history_values.append(round((entry['qber_value'] * 100), 2))
             logging.info(f"Fetched {len(qber_history_labels)} QBER history entries for user {user_id}.")
        except MySQLError as e:
             logging.warning(f"Could not fetch QBER history for user {user_id}: {e}")
             flash("Could not load QBER history from database.", "warning")
        except Exception as e:
             logging.error(f"Unexpected error fetching QBER history for user {user_id}: {e}", exc_info=True)
             flash("An error occurred while loading QBER history.", "warning")
        finally:
             if cursor: cursor.close(); close_db_connection(conn)
    else:
         logging.error(f"DB connection failed while trying to fetch QBER history for user {user_id}.")
         flash("Database connection error loading QBER history.", "error")

    # Use placeholder data if DB fetch fails or returns nothing
    if not qber_history_labels:
         logging.debug("Using placeholder QBER history data.")
         qber_history_labels = ['Run 1', 'Run 2', 'Run 3', 'Run 4', 'Run 5'];
         qber_history_values = [1.2, 0.8, 15.3, 0.5, 2.1]

    return render_template('qkd.html', simulation_log=simulation_log, QBER_THRESHOLD=current_app.config.get('QBER_THRESHOLD'), qber_history_labels=qber_history_labels, qber_history_values=qber_history_values)

@app.route('/qkd/report/download')
@login_required
def download_qkd_report():
    user_id = g.user['id']; simulation_log = session.get(f'last_qkd_log_{user_id}')
    if not simulation_log: flash("No QKD simulation data found in session.", "warning"); return redirect(url_for('qkd_page'))
    logging.info(f"User {user_id} attempting QKD simulation report download.")
    try:
        pdf_bytes = create_qkd_report_pdf(simulation_log) # Uses qkd_simulation.py
        if not pdf_bytes: flash("Failed to generate QKD PDF report.", "danger"); logging.error(f"create_qkd_report_pdf returned None for user {user_id}"); return redirect(url_for('qkd_page'))
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); filename = f"QKD_Simulation_Report_{timestamp}.pdf"
        logging.info(f"Serving QKD Sim PDF report '{filename}' to user {user_id}.")
        return Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": f"attachment;filename={filename}"})
    except Exception as e: logging.error(f"Error generating QKD PDF for user {user_id}: {e}", exc_info=True); flash("Error preparing QKD report.", "danger"); return redirect(url_for('qkd_page'))

@app.route('/quantum-impact')
def quantum_impact(): return render_template("quantum_impact.html")

@app.route('/about')
def about(): return render_template("about.html")

def get_flagged_transactions(user_id, limit=50):
    flagged_txns = []; conn = get_db_connection(); cursor = None;
    if not conn: logging.error(f"DB Conn failed fetching flagged tx for user {user_id}"); return flagged_txns
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp, s_cust.customer_name AS sender_name, r_cust.customer_name AS receiver_name, l.amount, l.fraud_reason
                  FROM qkd_transaction_log l LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE (s_acc.customer_id = %s OR r_acc.customer_id = %s) AND l.is_flagged = TRUE ORDER BY l.timestamp DESC LIMIT %s """
        cursor.execute(sql, (user_id, user_id, limit)); raw_flagged = cursor.fetchall()
        for entry in raw_flagged:
             try:
                 amt = Decimal(entry['amount'] or '0.00');
                 flagged_txns.append({'id': entry['log_id'], 'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (...)", 'receiver': f"{entry['receiver_name'] or '?'} (...)",
                    'amount': f"{amt:.2f}", 'fraud_reason': entry.get('fraud_reason', 'N/A') })
             except Exception as format_err: logging.warning(f"Error formatting flagged txn {entry.get('log_id', '?')}: {format_err}")
    except MySQLError as e: logging.error(f"Error fetching flagged tx for user {user_id}: {e}", exc_info=True); flash("Could not load flagged data.", "error")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return flagged_txns

@app.route('/fraud')
@login_required
def fraud_page(): return render_template("fraud.html", flagged_txns=get_flagged_transactions(g.user['id']))

def get_log_entry_details(log_id):
    conn = get_db_connection(); cursor = None; details = None
    if not conn: logging.error(f"DB Conn failed fetching log details (ID {log_id})"); return None
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.*, s_acc.customer_id sd_cid, s_cust.customer_name sd_nm, r_acc.customer_id rv_cid, r_cust.customer_name rv_nm
                  FROM qkd_transaction_log l LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id WHERE l.log_id = %s """
        cursor.execute(sql, (log_id,)); entry = cursor.fetchone()
        if entry:
            details = {'id': entry['log_id'], 'sender_customer_id': entry.get('sd_cid'), 'receiver_customer_id': entry.get('rv_cid'),
                'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                'sender': f"{entry['sd_nm'] or '?'} (Acc: {entry.get('sender_account_id', '?')})", 'receiver': f"{entry['rv_nm'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})",
                'amount': f"{Decimal(entry['amount'] or '0.00'):.2f}", 'qkd_status': entry['qkd_status'], 'qber': f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A",
                'encrypted_hex': entry.get('encrypted_confirmation', 'N/A'), # This is the base64 data
                'is_flagged': entry.get('is_flagged', False), 'fraud_reason': entry.get('fraud_reason'),
                'decrypted_details': "[Encrypted data - Decryption not available here]" }
    except Exception as e: logging.error(f"Error fetching log details for PDF (ID {log_id}): {e}", exc_info=True)
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return details

@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    user_id = g.user['id']; log_data = get_log_entry_details(log_id)
    if not log_data: abort(404, description="Log entry not found.")
    if user_id != log_data.get('sender_customer_id') and user_id != log_data.get('receiver_customer_id'): abort(403, description="Unauthorized.")
    pdf_bytes = create_txn_report_pdf(log_data) # Uses renamed import
    if not pdf_bytes: abort(500, description="Failed to generate transaction PDF report.")
    filename = f"Transaction_Report_Log_{log_id}.pdf"; logging.info(f"Serving Txn PDF report '{filename}' to user {user_id}.")
    return Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": f"attachment;filename={filename}"})

@app.route('/report/<int:log_id>')
@login_required
def show_report_page(log_id):
     user_id = g.user['id']; report_info = get_log_entry_details(log_id)
     if not report_info: abort(404, "Log entry not found.")
     if user_id != report_info.get('sender_customer_id') and user_id != report_info.get('receiver_customer_id'): abort(403, description="Unauthorized.")
     display_info = {'log_id': report_info.get('id'), 'timestamp': report_info.get('timestamp'), 'sender': report_info.get('sender')}
     return render_template('report.html', report_info=display_info)

@app.route('/risk-analysis')
@login_required
def risk_analysis_page():
    analysis_type = request.args.get('type', 'portfolio').lower(); config = {}
    if analysis_type == 'risk_measure': config['alpha'] = 0.05; logging.info(f"Running risk measure sim: {config}")
    elif analysis_type == 'portfolio': config['num_assets'] = 3; logging.info(f"Running portfolio sim: {config}")
    else: logging.warning(f"Unknown analysis type '{analysis_type}', defaulting to portfolio."); analysis_type = 'portfolio'; config['num_assets'] = 3
    try: risk_results = run_risk_analysis(analysis_type=analysis_type, config=config)
    except Exception as e: logging.error(f"ERROR calling run_risk_analysis: {e}", exc_info=True); flash(f"Risk analysis error: {e}", "error"); risk_results = {'status': f'Sim Error: {e}'}
    return render_template('risk_analysis.html', risk_results=risk_results, analysis_type=analysis_type)


# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    return dict(session_user=g.get('user'), INITIAL_BALANCE=app.config.get('INITIAL_BALANCE'), QBER_THRESHOLD=app.config.get('QBER_THRESHOLD'))

# --- Main execution block ---
if __name__ == '__main__':
     print("\n" + "="*60 + "\nStarting QKD Bank Demo Server...\n" + "="*60)
     print("\nDB Schema: Ensure 'iv' column removed/nullable in qkd_transaction_log.")
     print("\nChecking Dependencies...")
     dependencies = {
         "cryptography": True, "qiskit_aer": False, "reportlab": True,
         "mysql.connector": True, "flask_wtf": True, "email_validator": True,
         "numpy": True, "sklearn": True, "joblib": True, "pandas": True
     }
     critical_deps = {name for name, is_critical in dependencies.items() if is_critical}
     all_found = True

     for name, is_critical in dependencies.items():
         pip_name = name; module_name = name.replace("-", "_")
         try:
             if name == "sklearn": pip_name = "scikit-learn"; import sklearn
             elif name == "joblib": pip_name = "joblib"; import joblib
             elif name == "flask_wtf": pip_name = "Flask-WTF"; import flask_wtf
             elif name == "mysql.connector": pip_name = "mysql-connector-python"; import mysql.connector
             elif name == "qiskit_aer": pip_name = "qiskit-aer"; import qiskit_aer
             elif name == "email_validator": pip_name = "email-validator"; import email_validator
             elif name == "pandas": pip_name = "pandas"; import pandas
             else: __import__(module_name)
             print(f"  - [OK] {name}")
         except ImportError:
             level = "ERROR" if is_critical else "WARN"
             pip_install_suggestion = f"pip install {pip_name}" if name != "joblib" else "pip install scikit-learn"
             print(f"  - [{level}] '{name}' not found! (Try: {pip_install_suggestion})")
             if is_critical: all_found = False
         except Exception as e:
             level = "ERROR" if is_critical else "WARN"
             print(f"  - [{level}] Error importing '{name}': {e}")
             if is_critical: all_found = False

     if not all_found: print(f"\nPlease install missing critical dependencies before running."); exit()

     print("\nChecking for ML Model Files...")
     _MODEL_FILENAME = 'fraud_model.joblib'; _FEATURES_FILENAME = 'fraud_model_features.joblib'
     try: model_file_path = os.path.join(os.path.dirname(__file__), MODEL_FILENAME); features_file_path = os.path.join(os.path.dirname(__file__), FEATURES_FILENAME)
     except NameError: model_file_path = os.path.join(os.path.dirname(__file__), _MODEL_FILENAME); features_file_path = os.path.join(os.path.dirname(__file__), _FEATURES_FILENAME)
     if os.path.exists(model_file_path) and os.path.exists(features_file_path): print(f"  - [OK] ML files '{os.path.basename(model_file_path)}' and '{os.path.basename(features_file_path)}' found.")
     else: print(f"  - [WARN] ML files not found in {os.path.dirname(__file__)}. Run 'train_fraud_model.py'. ML fraud detection disabled.");

     print("\nChecking Database Connection...")
     conn_test = get_db_connection()
     if conn_test:
         print(f"  - [OK] Database connection successful ({MYSQL_HOST}/{MYSQL_DB})."); close_db_connection(conn_test)
         print("\nStarting Server..."); print(f"Access at: http://127.0.0.1:5001/ (or http://0.0.0.0:5001/)"); print("Press CTRL+C to stop.\n" + "="*60 + "\n")
         try:
             from waitress import serve
             print("--- Running with Waitress ---")
             serve(app, host='0.0.0.0', port=5001, threads=8) # Increased threads slightly
         except ImportError:
             print("--- Waitress not found. Running with Flask Dev Server (NOT FOR PRODUCTION!) ---")
             app.run(debug=True, host='0.0.0.0', port=5001)
     else:
          print("\n" + "="*60 + "\nFATAL: Database connection failed."); print(f"Config: HOST={MYSQL_HOST}, USER={MYSQL_USER}, DB={MYSQL_DB}"); print("Check MySQL server, credentials, privileges, DB/tables exist."); print("="*60 + "\n"); exit()
