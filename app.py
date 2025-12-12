# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Updated for Supabase (Postgres) + SQLite Fallback
# Preserves: ML, QKD, PDF, Email, Risk Analysis, and Auth logic.

# --- Core Imports ---
import base64
import datetime
import hashlib
import logging
import os
import random
import traceback
from decimal import Decimal, InvalidOperation
from functools import wraps
from threading import Thread
from datetime import timezone

# --- Third-Party Library Imports ---
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import (Flask, request, render_template, flash, redirect, url_for,
                   session, g, current_app, Response, abort, get_flashed_messages)
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
# --- MODULAR ENGINE IMPORTS ---
from modules.quantum_engine import QuantumEngine
from modules.pqc_engine import PQCEngine
from modules.db_engine import DBEngine, SecureTransactionManager
from modules.ml_engine import MLEngine

# --- DATABASE IMPORTS (UPDATED) ---
import psycopg2.extras
from db_utils import db  # <--- The new connector

# --- Environment Variable Loading ---
script_dir = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(script_dir, '.env')
if os.path.exists(dotenv_path):
    print(f"--- Loading environment variables from: {dotenv_path} ---")
    load_dotenv(dotenv_path=dotenv_path)

# --- DB Error Handling ---
DB_ERROR_TYPE = Exception

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
    from wtforms.validators import (DataRequired, Email, EqualTo, Length, NumberRange, InputRequired, Optional) 
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
    Mail = None
    Message = None
    print("\nWARNING: 'Flask-Mail' not found. Email features disabled.")

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
    import sklearn 
    print("--- NumPy, Pandas, Joblib, Scikit-learn found. ---")
except ImportError as e:
    print(f"\nERROR: Missing ML/Data library: {e}.")
    exit(1)

# --- PDF Generation Import ---
try:
    import reportlab
    print("--- ReportLab found. PDF generation enabled. ---")
except ImportError:
    print("\nERROR: 'reportlab' not found. PDF reporting disabled.")
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
    print(f"\nERROR: Failed local module import: {e}.")
    exit(1)

# --- Define Global Timezone ---
PYTZ_AVAILABLE = False
pytz = None 
LOCAL_TIMEZONE = timezone.utc 

try:
    import pytz 
    PYTZ_AVAILABLE = True
    try:
        LOCAL_TIMEZONE_STR = os.environ.get('LOCAL_TIMEZONE', 'Asia/Kolkata')
        LOCAL_TIMEZONE = pytz.timezone(LOCAL_TIMEZONE_STR) 
    except pytz.UnknownTimeZoneError:
        LOCAL_TIMEZONE = pytz.utc 
except ImportError:
    pass

# Initialize Patent-Compliant Engines
db_engine = DBEngine()
q_engine = QuantumEngine(n_qubits=app.config.get('QKD_NUM_QUBITS', 600))
pqc_engine = PQCEngine()
ml_engine = MLEngine()
secure_tx_manager = SecureTransactionManager(db_engine)

# --- Initialize Flask App ---
app = Flask(__name__)

# --- Configuration Loading ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev_key_change_in_prod')
app.config['WTF_CSRF_ENABLED'] = WTFORMS_AVAILABLE and os.environ.get('WTF_CSRF_ENABLED', 'True').lower() in ('true', '1', 't')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 't')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30)))

# Flask-Mail Config
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'False').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('QuantumVault Security', app.config['MAIL_USERNAME'])
app.config['QBER_THRESHOLD_PCT'] = int(os.environ.get('QBER_THRESHOLD_PCT', 25))
app.config['QKD_NUM_QUBITS'] = int(os.environ.get('QKD_NUM_QUBITS', 512))

# Initialize Mail
mail = None
if MAIL_AVAILABLE:
    try:
        mail = Mail(app)
    except Exception as e:
        logging.error(f"Mail init failed: {e}")
        MAIL_AVAILABLE = False

# App Settings
QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
QKD_NUM_QUBITS = int(os.environ.get('QKD_NUM_QUBITS', 600))
INITIAL_BALANCE = Decimal(os.environ.get('INITIAL_BALANCE', '1000.00'))
app.config['FRAUD_BLACKLIST'] = set(filter(None, os.environ.get('FRAUD_BLACKLIST', '').split(',')))
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE

# Serializer
serializer = None
try:
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
except Exception:
    pass

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

# Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- User Class ---
class User(UserMixin):
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

# Load ML Model
if not load_ml_model():
    logging.critical("ML MODEL LOAD FAILED.")
else:
    logging.info("ML model loaded successfully.")

# --- Forms Definition ---
if WTFORMS_AVAILABLE:
    class LoginForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Sign In')

    class RegistrationForm(FlaskForm):
         customer_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
         email = EmailField('Email Address', validators=[DataRequired(), Email()])
         phone_number = StringField('Phone Number', validators=[Optional(), Length(min=10, max=20)])
         password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
         confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
         submit = SubmitField('Register Account')

    class ForgotPasswordForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()])
        submit = SubmitField('Send Reset Link')

    class ResetPasswordForm(FlaskForm):
        password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
        confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
        submit = SubmitField('Reset Password')

    class TransferForm(FlaskForm):
        receiver_account_id = SelectField('Recipient Account', validators=[InputRequired()])
        amount = DecimalField('Amount (₹)', places=2, validators=[InputRequired(), NumberRange(min=Decimal('0.01'))])
        simulate_eve = BooleanField('Simulate Eavesdropper (Higher QBER)')
        submit = SubmitField('Initiate Secure Transfer')
else:
    # Minimal dummy classes if needed
    class DummyForm:
        def __init__(self, *args, **kwargs): self.data = {}; self.errors = {}
        def validate_on_submit(self): return request.method == 'POST'
    LoginForm = RegistrationForm = ForgotPasswordForm = ResetPasswordForm = TransferForm = DummyForm

# --- DATABASE HELPER FUNCTION (UPDATED) ---
def get_db_connection():
    """Establishes DB connection via db_utils (Auto-fallback)."""
    return db.get_connection()

def close_db_connection(conn):
    if conn:
        try:
            conn.close()
        except Exception:
            pass

# --- Helper: Get Cursor (Crucial for PG vs SQLite compatibility) ---
def get_cursor(conn):
    """Returns the correct dictionary-like cursor based on DB mode."""
    if db.mode == 'postgres':
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        # SQLite connection from db_utils already has row_factory set
        return conn.cursor()

# --- Data Fetching Functions ---

def get_accounts_data(customer_id_filter=None):
    accounts = []
    conn = get_db_connection()
    if not conn: return None
    
    try:
        cursor = get_cursor(conn)
        sql = """SELECT a.account_id, a.account_number, c.customer_name, a.balance, a.customer_id
                 FROM accounts a
                 JOIN customers c ON a.customer_id = c.customer_id"""
        params = []
        if customer_id_filter:
            sql += " WHERE a.customer_id = %s"
            params.append(customer_id_filter)
        sql += " ORDER BY a.account_id ASC"
        
        cursor.execute(sql, tuple(params))
        for row in cursor.fetchall():
            acc = dict(row)
            # Ensure balance is Decimal
            acc['balance'] = Decimal(str(acc['balance']))
            accounts.append(acc)
            
        cursor.close()
        close_db_connection(conn)
        return accounts
    except Exception as e:
        logging.error(f"Error fetching accounts: {e}")
        close_db_connection(conn)
        return None

def get_user_by_email(email):
    conn = get_db_connection()
    if not conn: return None
    user = None
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,))
        row = cursor.fetchone()
        if row:
            user = dict(row)
        cursor.close()
    except Exception as e:
        logging.error(f"Error fetching user {email}: {e}")
    finally:
        close_db_connection(conn)
    return user

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None, exception_info=None):
    conn = get_db_connection()
    if not conn: return
    try:
        cursor = conn.cursor()
        sql = """INSERT INTO qkd_transaction_log
                 (sender_account_id, receiver_account_id, amount, qkd_status,
                  qber_value, is_flagged, fraud_reason, timestamp)
                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        vals = (sender_id, receiver_id, str(amount), failed_status[:50],
                qber_value, bool(fraud_reason), str(fraud_reason)[:255] if fraud_reason else None,
                datetime.datetime.now(timezone.utc))
        cursor.execute(sql, vals)
        conn.commit()
        cursor.close()
    except Exception as e:
        logging.error(f"Failed to log error: {e}")
    finally:
        close_db_connection(conn)

# --- Auth Helpers ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def clear_qkd_session_log():
    user_id = session.get('user_id')
    if user_id:
        session.pop(f'last_qkd_log_{user_id}', None)

def send_async_email(app_context, msg):
    with app_context:
        if mail:
            try: mail.send(msg)
            except Exception as e: logging.error(f"Email error: {e}")

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn: return None
    try:
        cursor = get_cursor(conn)
        cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s", (user_id,))
        row = cursor.fetchone()
        close_db_connection(conn)
        if row:
            return User(id=row['customer_id'], name=row['customer_name'], email=row['email'])
    except Exception:
        close_db_connection(conn)
    return None

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id:
        conn = get_db_connection()
        if conn:
            try:
                cursor = get_cursor(conn)
                cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s", (user_id,))
                row = cursor.fetchone()
                if row:
                    g.user = {'id': row['customer_id'], 'name': row['customer_name'], 'email': row['email']}
                cursor.close()
            except Exception:
                pass
            finally:
                close_db_connection(conn)

# --- Routes ---

@app.route('/')
def home_redirect():
    return redirect(url_for('index')) if g.get('user') else redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    user_id = g.user['id']
    user_accounts = get_accounts_data(user_id) or []
    all_accounts = get_accounts_data() or []
    receiver_accounts = [acc for acc in all_accounts if acc['customer_id'] != user_id]
    flagged_transactions = get_flagged_transactions(user_id, limit=5)
    
    transfer_form = None
    if WTFORMS_AVAILABLE:
        transfer_form = TransferForm()
        transfer_form.receiver_account_id.choices = [('', '-- Select --')] + \
            [(str(a['account_id']), f"{a['customer_name']} (ID:{a['account_id']})") for a in receiver_accounts]

    return render_template('index.html', user_accounts=user_accounts, receiver_accounts=receiver_accounts,
                           transfer_form=transfer_form, flagged_transactions=flagged_transactions,
                           last_transfer_outcome=session.pop('last_transfer_outcome', None))

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    if g.user: return redirect(url_for('index'))
    form = RegistrationForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or (not WTFORMS_AVAILABLE and request.method == 'POST'):
        if WTFORMS_AVAILABLE:
            c_name, email, pw = form.customer_name.data, form.email.data, form.password.data
            phone = form.phone_number.data
        else:
            c_name, email, pw = request.form.get('customer_name'), request.form.get('email'), request.form.get('password')
            phone = request.form.get('phone_number')

        conn = get_db_connection()
        if not conn:
            flash("Database error", "error")
            return render_template('register.html', form=form)

        try:
            cursor = conn.cursor()
            hashed_pw = generate_password_hash(pw)
            
            # Insert Customer
            if db.mode == 'postgres':
                cursor.execute("INSERT INTO customers (customer_name, email, password_hash, phone_number) VALUES (%s, %s, %s, %s) RETURNING customer_id", 
                               (c_name, email, hashed_pw, phone))
                new_cid = cursor.fetchone()[0]
            else:
                cursor.execute("INSERT INTO customers (customer_name, email, password_hash, phone_number) VALUES (%s, %s, %s, %s)", 
                               (c_name, email, hashed_pw, phone))
                new_cid = cursor.lastrowid

            # Insert Account
            acc_num = str(random.randint(10**11, (10**12)-1))
            if db.mode == 'postgres':
                cursor.execute("INSERT INTO accounts (customer_id, balance, account_number) VALUES (%s, %s, %s) RETURNING account_id",
                               (new_cid, str(app.config['INITIAL_BALANCE']), acc_num))
            else:
                cursor.execute("INSERT INTO accounts (customer_id, balance, account_number) VALUES (%s, %s, %s)",
                               (new_cid, str(app.config['INITIAL_BALANCE']), acc_num))
            
            conn.commit()
            flash("Registration successful!", "success")
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            logging.error(f"Reg error: {e}")
            flash("Registration failed (Email might exist)", "error")
        finally:
            close_db_connection(conn)

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: return redirect(url_for('index'))
    form = LoginForm() if WTFORMS_AVAILABLE else None

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or (not WTFORMS_AVAILABLE and request.method == 'POST'):
        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email')
        pw = form.password.data if WTFORMS_AVAILABLE else request.form.get('password')
        
        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], pw):
            session.clear()
            session['user_id'] = user['customer_id']
            session.permanent = True
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials", "error")

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    clear_qkd_session_log()
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# --- Routes: Forgot/Reset Password (Preserved Logic) ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if g.user: return redirect(url_for('index'))
    form = ForgotPasswordForm() if WTFORMS_AVAILABLE else None
    if not MAIL_AVAILABLE:
        flash("Email service unavailable", "warning")
        return render_template('forgot_password.html', form=form)

    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or (not WTFORMS_AVAILABLE and request.method == 'POST'):
        email = form.email.data if WTFORMS_AVAILABLE else request.form.get('email')
        user = get_user_by_email(email)
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset", recipients=[email], body=f"Click to reset: {link}")
            Thread(target=send_async_email, args=[current_app.app_context(), msg]).start()
        flash("If account exists, email sent.", "info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=600)
    except:
        flash("Invalid/Expired link", "error")
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm() if WTFORMS_AVAILABLE else None
    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or (not WTFORMS_AVAILABLE and request.method == 'POST'):
        new_pw = form.password.data if WTFORMS_AVAILABLE else request.form.get('password')
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE customers SET password_hash = %s WHERE email = %s", (generate_password_hash(new_pw), email))
            conn.commit()
            close_db_connection(conn)
            flash("Password reset. Log in.", "success")
            return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, token=token)

# --- Route: Transfer Funds (Critical Logic) ---
@app.route('/transfer-funds', methods=['POST'])
@login_required
def transfer_funds():
    user_id = g.user['id']
    # ... Input Parsing ...
    try:
        if WTFORMS_AVAILABLE:
            form = TransferForm(request.form)
            # Hack: validate choices dynamically
            all_acc = get_accounts_data()
            form.receiver_account_id.choices = [('', '')] + [(str(a['account_id']), '') for a in all_acc]
            if not form.validate(): raise ValueError("Invalid form")
            rx_id = int(form.receiver_account_id.data)
            amt = form.amount.data
            sim_eve = form.simulate_eve.data
        else:
            rx_id = int(request.form.get('receiver_account_id'))
            amt = Decimal(request.form.get('amount'))
            sim_eve = 'simulate_eve' in request.form
        
        if rx_id == 0: raise ValueError("Select recipient")
    except Exception as e:
        flash(f"Input Error: {e}", "error")
        return redirect(url_for('index'))

    
    # 1. Quantum & Hybrid Key Generation (Claim 4 & 3)
    # Uses True Entropy from modules/quantum_engine.py
    qkd_res = q_engine.start_session(simulate_eve=sim_eve)
    session[f'last_qkd_log_{user_id}'] = qkd_res 

    qber = qkd_res.get('qber', -1)
    qkd_key = None
    qkd_status = qkd_res['status']

    if qkd_status == 'SECURE':
        # Hybrid Key Derivation (Claim 2: XOR Logic)
        raw_qkd_key = qkd_res['raw_key_bytes']
        pqc_secret = pqc_engine.encapsulate() # Claim 3: Kyber
        final_key_bytes = pqc_engine.derive_hybrid_key(raw_qkd_key, pqc_secret)
        qkd_key = base64.urlsafe_b64encode(final_key_bytes) # For Fernet
    
    # 2. ML Fraud Check (Claim 5)
    fraud_check_data = {
        'amount': float(amt), 
        'oldbalanceOrg': 0, # In prod, fetch real balances
        'newbalanceOrig': 0,
        'type_TRANSFER': 1
    }
    is_fraud, fraud_prob, fraud_reason = ml_engine.predict_fraud(fraud_check_data)

    if qkd_status != 'SECURE':
        is_fraud = True
        fraud_reason = f"Quantum Channel Compromised (QBER: {qber:.2%})"

    # 3. Database Transaction with Pessimistic Locking (Claim 6)
    if not is_fraud:
        success, msg = secure_tx_manager.execute_locked_transfer(user_id, rx_id, amt)
        if not success:
            flash(f"Transfer Failed: {msg}", "error")
            return redirect(url_for('index'))
    # --- NEW PATENT-COMPLIANT LOGIC END ---

        # Execute Transfer
        cursor.execute("UPDATE accounts SET balance = balance - %s WHERE customer_id = %s", (amt, user_id))
        cursor.execute("UPDATE accounts SET balance = balance + %s WHERE account_id = %s", (amt, rx_id))
        
        # Log
        enc_conf = None
        if qkd_key:
            f = Fernet(qkd_key)
            enc_conf = f.encrypt(f"CONF:{amt}".encode()).decode()

        vals = (user_id, rx_id, str(amt), qkd_status, qber, is_fraud, fraud_data['reason'], enc_conf, datetime.datetime.now(timezone.utc))
        
        if db.mode == 'postgres':
            cursor.execute("""INSERT INTO qkd_transaction_log 
                (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason, encrypted_confirmation, timestamp)
                VALUES ((SELECT account_id FROM accounts WHERE customer_id=%s LIMIT 1), %s, %s, %s, %s, %s, %s, %s, %s) RETURNING log_id""", vals)
            lid = cursor.fetchone()['log_id']
        else:
            # SQLite fallback - need explicit sender account ID
            cursor.execute("SELECT account_id FROM accounts WHERE customer_id=%s LIMIT 1", (user_id,))
            sid = cursor.fetchone()['account_id']
            vals_lite = (sid, rx_id, str(amt), qkd_status, qber, is_fraud, fraud_data['reason'], enc_conf, datetime.datetime.now(timezone.utc))
            cursor.execute("""INSERT INTO qkd_transaction_log 
                (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason, encrypted_confirmation, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""", vals_lite)
            lid = cursor.lastrowid

        conn.commit()
        flash(f"Transfer {'FLAGGED' if is_fraud else 'Success'}. Log ID: {lid}", "warning" if is_fraud else "success")
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Tx Error: {e}")
        flash(f"Transfer Failed: {e}", "error")
    finally:
        close_db_connection(conn)
        
    return redirect(url_for('index'))

# --- Helper Class for Template Compatibility ---
class DictObj:
    def __init__(self, d):
        self.__dict__.update(d)

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    txns = []
    if conn:
        cursor = get_cursor(conn)
        # Simplified query for compatibility
        sql = """SELECT l.log_id as id, l.timestamp, s_c.customer_name as sender, r_c.customer_name as receiver,
                 l.amount, l.qkd_status, l.qber_value as qber, l.encrypted_confirmation as encrypted_details_status,
                 l.is_flagged, l.fraud_reason
                 FROM qkd_transaction_log l
                 JOIN accounts s_a ON l.sender_account_id = s_a.account_id
                 JOIN customers s_c ON s_a.customer_id = s_c.customer_id
                 JOIN accounts r_a ON l.receiver_account_id = r_a.account_id
                 JOIN customers r_c ON r_a.customer_id = r_c.customer_id
                 WHERE s_c.customer_id = %s OR r_c.customer_id = %s
                 ORDER BY l.timestamp DESC LIMIT 50"""
        cursor.execute(sql, (g.user['id'], g.user['id']))
        for row in cursor.fetchall():
            d = dict(row)
            d['amount'] = Decimal(str(d['amount']))
            
            # Fix missing fields expected by template
            d['sender'] = d['sender'] 
            d['receiver'] = d['receiver']
            d['is_flagged_display'] = "Yes" if d['is_flagged'] else "No"
            
            # Timezone fix
            if d['timestamp'].tzinfo is None:
                d['timestamp'] = pytz.utc.localize(d['timestamp'])
            if LOCAL_TIMEZONE:
                d['timestamp'] = d['timestamp'].astimezone(LOCAL_TIMEZONE)
            
            # Convert dict to object for template (entry.id access)
            txns.append(DictObj(d))
            
        close_db_connection(conn)
    return render_template('history.html', log_entries=txns)

@app.route('/qkd')
@login_required
def qkd_page():
    sim_log = session.get(f'last_qkd_log_{g.user["id"]}')
    qber_thresh = app.config['QBER_THRESHOLD']
    
    # Fetch History for Chart
    labels = []
    values = []
    conn = get_db_connection()
    if conn:
        try:
            cursor = get_cursor(conn)
            # Fetch recent QBERs for the user to populate the graph
            sql = """SELECT l.log_id, l.timestamp, l.qber_value 
                     FROM qkd_transaction_log l
                     JOIN accounts s ON l.sender_account_id = s.account_id
                     WHERE s.customer_id = %s 
                     AND l.qber_value >= 0
                     ORDER BY l.timestamp DESC LIMIT 15"""
            cursor.execute(sql, (g.user['id'],))
            rows = cursor.fetchall()
            rows.reverse() # Chronological order for chart
            
            for r in rows:
                # Simple date formatting
                ts = r['timestamp']
                if hasattr(ts, 'strftime'):
                    lbl = ts.strftime('%m/%d %H:%M')
                else:
                    lbl = str(ts)[:16]
                
                val = round(float(r['qber_value']) * 100, 2)
                labels.append(lbl)
                values.append(val)
            cursor.close()
        except Exception as e:
            logging.error(f"Chart error: {e}")
        finally:
            close_db_connection(conn)
            
    if not labels:
        labels, values = ["No Data"], [0]

    return render_template('qkd.html', 
                           simulation_log=sim_log, 
                           QBER_THRESHOLD_PCT=qber_thresh*100,
                           QBER_THRESHOLD_ORIGINAL=qber_thresh,
                           qber_history_labels=labels,
                           qber_history_values=values)

@app.route('/profile')
@login_required
def profile():
    acc = None
    conn = get_db_connection()
    if conn:
        cur = get_cursor(conn)
        cur.execute("SELECT * FROM accounts WHERE customer_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if row: acc = dict(row)
        close_db_connection(conn)
    return render_template('profile.html', user=g.user, account=acc)

@app.route('/fraud')
@login_required
def fraud_page():
    txns = get_flagged_transactions(g.user['id'])
    return render_template("fraud.html", flagged_txns=txns)

# --- Helpers for Report/Fraud ---
def get_flagged_transactions(uid, limit=50):
    conn = get_db_connection()
    if not conn: return []
    cur = get_cursor(conn)
    sql = """SELECT l.log_id as id, l.timestamp, s_c.customer_name as sender, r_c.customer_name as receiver, 
             l.amount, l.fraud_reason 
             FROM qkd_transaction_log l
             JOIN accounts s ON l.sender_account_id = s.account_id
             JOIN customers s_c ON s.customer_id = s_c.customer_id
             JOIN accounts r ON l.receiver_account_id = r.account_id
             JOIN customers r_c ON r.customer_id = r_c.customer_id
             WHERE (s.customer_id = %s OR r.customer_id = %s) AND l.is_flagged = %s
             ORDER BY l.timestamp DESC LIMIT %s"""
    # Boolean True depends on DB. Postgres=True, SQLite=1. 
    # Python driver usually handles True -> 1/true automatically.
    cur.execute(sql, (uid, uid, True, limit))
    res = []
    for r in cur.fetchall():
        d = dict(r)
        d['amount'] = f"{Decimal(str(d['amount'])):.2f}"
        res.append(d)
    close_db_connection(conn)
    return res

def get_log_entry_details(lid):
    conn = get_db_connection()
    if not conn: return None
    cur = get_cursor(conn)
    sql = """SELECT l.*, s_a.customer_id as sender_cust_id, r_a.customer_id as receiver_cust_id,
             s_c.customer_name as sender_name, r_c.customer_name as receiver_name
             FROM qkd_transaction_log l
             JOIN accounts s_a ON l.sender_account_id = s_a.account_id
             JOIN customers s_c ON s_a.customer_id = s_c.customer_id
             JOIN accounts r_a ON l.receiver_account_id = r_a.account_id
             JOIN customers r_c ON r_a.customer_id = r_c.customer_id
             WHERE l.log_id = %s"""
    cur.execute(sql, (lid,))
    row = cur.fetchone()
    close_db_connection(conn)
    if not row: return None
    
    d = dict(row)
    d['amount'] = f"{Decimal(str(d['amount'])):.2f}"
    d['sender_details'] = f"{d['sender_name']} (Acc: {d['sender_account_id']})"
    d['receiver_details'] = f"{d['receiver_name']} (Acc: {d['receiver_account_id']})"
    d['timestamp'] = str(d['timestamp']) # simplify for PDF
    d['encrypted_confirmation_data'] = d.get('encrypted_confirmation')
    return d

@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    data = get_log_entry_details(log_id)
    if not data or (g.user['id'] not in [data['sender_cust_id'], data['receiver_cust_id']]):
        return abort(403)
    pdf = create_transaction_report(data)
    return Response(pdf, mimetype='application/pdf', headers={"Content-Disposition": f"attachment;filename=Tx_{log_id}.pdf"})

@app.route('/qkd/report/download')
@login_required
def download_qkd_report():
    log = session.get(f'last_qkd_log_{g.user["id"]}')
    if not log: return redirect(url_for('qkd_page'))
    pdf = create_qkd_simulation_report(log)
    return Response(pdf, mimetype='application/pdf', headers={"Content-Disposition": "attachment;filename=QKD_Report.pdf"})

# --- Risk Analysis Route (Restored) ---
@app.route('/risk-analysis', methods=['GET', 'POST'])
@login_required
def risk_analysis_page():
    risk_results = None
    analysis_type = 'portfolio'
    form_data = {}

    if request.method == 'POST':
        form_data = request.form
        analysis_type = request.form.get('analysis_type', 'portfolio').lower()
        config = {}
        try:
            if analysis_type == 'risk_measure':
                config['alpha'] = float(request.form.get('param_alpha', 0.05))
            elif analysis_type == 'portfolio':
                config['num_assets'] = int(request.form.get('param_num_assets', 3))
            
            risk_results = run_risk_analysis(analysis_type=analysis_type, config=config)
            if risk_results and risk_results.get('status') != 'Error':
                flash("Simulation completed.", "success")
            else:
                flash(f"Simulation failed: {risk_results.get('details')}", "error")
        except Exception as e:
            logging.error(f"Risk sim error: {e}")
            flash("Simulation error", "error")

    return render_template('risk_analysis.html', risk_results=risk_results, analysis_type=analysis_type, form_data=form_data)

# --- Misc Routes ---
@app.route('/quantum-impact')
def quantum_impact(): return render_template("quantum_impact.html")
@app.route('/about')
def about(): return render_template("about.html")
@app.route('/report/<int:log_id>')
@login_required
def show_report_page(log_id):
    data = get_log_entry_details(log_id)
    return render_template('report.html', report_info=data)

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    return dict(
        session_user=g.get('user'),
        INITIAL_BALANCE_DISPLAY=f"{app.config.get('INITIAL_BALANCE', Decimal('0.00')):.2f}",
        QBER_THRESHOLD_DISPLAY=f"{app.config.get('QBER_THRESHOLD', 0.15):.2%}",
        current_year=datetime.datetime.now().year,
        is_mail_available=MAIL_AVAILABLE,
        are_forms_enabled=WTFORMS_AVAILABLE
    )

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html', error=e), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('errors/500.html', error=e), 500

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
