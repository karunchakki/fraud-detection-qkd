# app.py
# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Includes: User Auth (Email Login, Register, Forgot/Reset Password w/ Debug), MySQL,
#           QKD Sim (BB84), Fernet Encryption, Fraud Detection, PDF Reporting, Info Pages.

# --- Core Imports ---
from flask import (Flask, request, render_template, flash, redirect, url_for,
                   session, g, current_app, Response, abort, get_flashed_messages) # Added get_flashed_messages
from functools import wraps
import os
import datetime
import base64
import hashlib
import traceback # For detailed error logging
import logging # For better logging

# --- Database Import ---
import mysql.connector
from mysql.connector import Error as MySQLError

# --- Security & Authentication ---
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature # For password reset tokens

# --- Forms (Flask-WTF) ---
try:
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, SubmitField, EmailField # Using EmailField now
    from wtforms.validators import DataRequired, Email, EqualTo, Length
    import email_validator # Required by WTForms Email validator
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

# --- Data Handling Import ---
from decimal import Decimal, InvalidOperation

# --- Local Module Imports ---
try:
    from qkd_simulation import simulate_bb84
    from fraud_detection import detect_fraud
    from pdf_generator import create_qkd_report
except ImportError as e:
    print(f"\nERROR: Failed to import local module: {e}")
    print("Please ensure qkd_simulation.py, fraud_detection.py, and pdf_generator.py exist.")
    exit()

# --- Initialize Flask App ---
app = Flask(__name__)

# --- Configuration ---
# IMPORTANT: Use a strong, random secret key in production!
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_insecure_default_secret_key_32bytes_') # MUST be strong & secret in production
if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
    print("\n" + "="*60 + "\nWARNING: Using default FLASK_SECRET_KEY! Set a proper environment variable.\n" + "="*60 + "\n")

app.config.update(
    WTF_CSRF_ENABLED=True, # Enable CSRF protection for WTForms
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 30))) # Session lifetime
)

# --- Email Configuration (Placeholder for real sending) ---
# app.config['MAIL_SERVER'] = 'smtp.example.com'
# ... (rest of mail config)
# from flask_mail import Mail, Message
# mail = Mail(app)

# --- Database Configuration ---
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'WindowsPass123!')
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')
MYSQL_CONFIG = {'host': MYSQL_HOST, 'user': MYSQL_USER, 'password': MYSQL_PASSWORD, 'database': MYSQL_DB, 'use_pure': True, 'connection_timeout': 10}

# --- Application Specific Config ---
QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
QKD_NUM_QUBITS = int(os.environ.get('QKD_NUM_QUBITS', 600))
INITIAL_BALANCE = Decimal(os.environ.get('INITIAL_BALANCE', '1000.00'))
app.config['FRAUD_BLACKLIST'] = set(filter(None, os.environ.get('FRAUD_BLACKLIST', 'bad_user1,scammer_acc').split(',')))
app.config['FRAUD_AMOUNT_THRESHOLD'] = float(os.environ.get('FRAUD_AMOUNT_THRESHOLD', 10000.00))
app.config['FRAUD_RAPID_TRANSACTION_SECONDS'] = int(os.environ.get('FRAUD_RAPID_SECONDS', 10))
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE

# --- Token Serializer Setup ---
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Setup Logging ---
# Configure logging to show INFO level messages and above
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# You might want to configure logging to a file in production:
# logging.basicConfig(filename='qsb_app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Simulated User Database (Replace with real DB interaction) ---
# REMOVED - Relying solely on DB now via helper functions


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
     submit = SubmitField('Register')

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email Address', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')


# --- Database Helper Functions ---
def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        # Add pool_name and pool_size for connection pooling (optional but recommended)
        # conn = mysql.connector.connect(**MYSQL_CONFIG, pool_name="qsbpool", pool_size=5)
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected():
            logging.debug("DB connection successful.")
            return conn
        else:
            logging.error("DB connection failed: Not connected state.")
            return None
    except MySQLError as e:
        logging.critical(f"CRITICAL DB Connect Error: {e}")
        return None

def close_db_connection(conn):
    """Closes the database connection if it's open and connected."""
    if conn and conn.is_connected():
        try:
            conn.close()
            logging.debug("DB connection closed.")
        except MySQLError as e:
            logging.error(f"Error closing DB connection: {e}")

def get_accounts_data(customer_id_filter=None):
    """Fetches account data, optionally filtering by customer_id. Returns empty list on error."""
    accounts = []; conn = get_db_connection(); cursor = None
    if not conn:
        # Avoid duplicate flashing if already flashed by other functions
        # flash("Database error. Cannot load account data.", "error") # Flashing moved higher up potentially
        return accounts
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """SELECT a.account_id, c.customer_name, a.balance, a.customer_id
                 FROM accounts a JOIN customers c ON a.customer_id = c.customer_id"""
        params = []
        if customer_id_filter is not None:
            sql += " WHERE a.customer_id = %s"
            params.append(customer_id_filter)
        sql += " ORDER BY a.account_id"
        cursor.execute(sql, tuple(params))
        raw_accounts = cursor.fetchall()
        for acc in raw_accounts:
            try:
                acc['balance'] = Decimal(acc.get('balance') or '0.00')
                accounts.append(acc)
            except (InvalidOperation, TypeError) as e:
                logging.warning(f"Skipping account {acc.get('account_id')} due to invalid balance format: {e}")
    except MySQLError as e:
        logging.error(f"Error fetching accounts: {e}")
        flash("Error loading account data.", "error")
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)
    return accounts

# --- Helper Function for user lookup by email ---
def get_user_by_email(email):
    """Finds user by email from the database."""
    conn = get_db_connection()
    if not conn: return None
    cursor = None
    user = None
    try:
        cursor = conn.cursor(dictionary=True)
        # Ensure your customers table has an 'email' column with a UNIQUE index
        cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,))
        user = cursor.fetchone()
    except MySQLError as e:
        logging.error(f"DB Error getting user by email ({email}): {e}")
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)
    return user # Returns user dict or None


def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None):
     """Logs a failed transaction attempt into the database."""
     sender_id_val = sender_id or -1; receiver_id_val = receiver_id or -1
     amount_str = str(amount) if amount is not None else '0.00'; log_conn = None; log_cursor = None
     logging.info(f"Logging failed transaction attempt status: {failed_status}")
     try:
        log_conn = get_db_connection()
        if not log_conn: raise ConnectionError("DB Conn failed for logging")
        log_cursor = log_conn.cursor()
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason, encrypted_confirmation, iv)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        qber_db_val = qber_value if isinstance(qber_value, (float, int)) else None
        is_flagged = bool(fraud_reason) # Set flag to TRUE if a fraud_reason is provided
        log_values = (sender_id_val, receiver_id_val, amount_str, failed_status, qber_db_val, is_flagged, fraud_reason, None, None) # Null encrypt/iv on failure
        log_cursor.execute(log_sql, log_values)
        log_conn.commit()
        logging.info(f"Failed attempt logged. Flagged: {is_flagged}, Reason: {fraud_reason}")
     except (MySQLError, ConnectionError) as log_err:
        logging.critical(f"CRITICAL: Failed to log FAILED transaction: {log_err}");
        if log_conn and log_conn.is_connected():
            try: log_conn.rollback()
            except MySQLError as rb_err: logging.error(f"Rollback failed during error logging: {rb_err}")
     finally:
        if log_cursor: log_cursor.close(); close_db_connection(log_conn)


# --- Authentication & Session Management ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
             flash("Please log in to access this page.", "warning")
             return redirect(url_for('login', next=request.url))
        # Ensure g.user is loaded (should be by before_request)
        if not g.get('user'):
             # User ID in session but couldn't be loaded from DB/source
             session.clear()
             flash("Session error. Please log in again.", "warning")
             return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    # Load user details into g for the duration of the request if logged in
    user_id = session.get('user_id')
    g.user = None # Default to None
    if user_id:
         # Use the helper function to get user details from DB
         user_data = None
         conn = get_db_connection()
         if conn:
             cursor = None
             try:
                 cursor = conn.cursor(dictionary=True)
                 # Select necessary fields
                 cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s", (user_id,))
                 user_data = cursor.fetchone()
                 if user_data:
                     g.user = {
                         'id': user_data.get('customer_id'),
                         'name': user_data.get('customer_name'),
                         'email': user_data.get('email')
                     }
                 else:
                     # User ID in session but not found in DB -> session invalid
                     logging.warning(f"User ID {user_id} in session but not found in DB. Clearing session.")
                     session.clear()
             except MySQLError as e:
                 logging.error(f"Error fetching user details for session {user_id}: {e}")
                 # Don't clear session on temporary DB error, but g.user remains None
             finally:
                 if cursor: cursor.close()
                 close_db_connection(conn)
         else:
              # DB connection failed during user load, treat as not logged in for safety
              session.clear()
              logging.error("DB connection failed during load_logged_in_user. Cleared session.")
    # If user_id wasn't in session or DB lookup failed/returned None, g.user remains None


# --- Clear QKD Session Log ---
def clear_qkd_session_log():
     """Clears only the last QKD log from the session."""
     user_id = getattr(g, 'user', {}).get('id') # Get user_id from g.user if available
     if not user_id and 'user_id' in session: user_id = session['user_id'] # Fallback for logout

     if user_id:
         log_cleared = session.pop(f'last_qkd_log_{user_id}', None) is not None
         if log_cleared:
             session.modified = True; logging.info(f"Cleared QKD log data for user {user_id}")

# --- Flask Routes ---

# Home Redirect
@app.route('/')
def home_redirect():
    if g.user: return redirect(url_for('index')) # Check g.user set by before_request
    return redirect(url_for('login'))

# Dashboard
@app.route('/index')
@login_required
def index():
    """Renders the dashboard."""
    user_id = g.user['id'] # Assumes g.user is populated by login_required/before_request
    user_accounts = get_accounts_data(customer_id_filter=user_id)
    all_accounts = get_accounts_data()
    if all_accounts is None: all_accounts = []
    if user_accounts is None: user_accounts = []

    # Defensive check: ensure customer_id key exists before comparison
    receiver_accounts = [acc for acc in all_accounts if acc.get('customer_id') != user_id]
    flagged_transactions = get_flagged_transactions(user_id, limit=5)
    show_fraud_alert = bool(flagged_transactions)
    last_transfer_outcome = session.pop('last_transfer_outcome', None)
    # g.user is automatically available via context_processor
    return render_template('index.html',
                           user_accounts=user_accounts,
                           receiver_accounts=receiver_accounts,
                           show_fraud_alert=show_fraud_alert,
                           last_transfer_outcome=last_transfer_outcome)

# Registration (Updated with WTForms & Email)
@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles customer registration using WTForms."""
    if g.user: return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        customer_name = form.customer_name.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        conn = get_db_connection(); cursor = None
        if not conn:
             flash("Database connection error. Cannot register at this time.", "error")
             return render_template('register.html', form=form)
        try:
            cursor = conn.cursor(dictionary=True)
            # Check if name OR email already exists
            cursor.execute("SELECT customer_id, customer_name, email FROM customers WHERE customer_name = %s OR email = %s", (customer_name, email))
            existing_user = cursor.fetchone()
            if existing_user:
                if existing_user.get('customer_name') == customer_name:
                     flash(f"Customer name '{customer_name}' already exists.", "error")
                elif existing_user.get('email') == email:
                     flash(f"Email address '{email}' is already registered.", "error")
                else:
                     flash("An existing user conflicts with this registration.", "error")
                return render_template('register.html', form=form) # Re-render with error
            else:
                # Proceed with insertion
                hashed_pw = generate_password_hash(password)
                cursor.execute("INSERT INTO customers (customer_name, email, password_hash) VALUES (%s, %s, %s)",
                               (customer_name, email, hashed_pw))
                customer_id = cursor.lastrowid
                if not customer_id: raise MySQLError("Failed customer insert.")

                cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)",
                               (customer_id, str(app.config['INITIAL_BALANCE'])))
                account_id = cursor.lastrowid
                if not account_id: raise MySQLError("Failed account insert.")

                conn.commit()
                logging.info(f"Successfully registered {customer_name} ({email}) with ID {customer_id}")

                flash(f"Customer '{customer_name}' registered successfully! Please login.", "success")
                return redirect(url_for('login'))
        except MySQLError as e:
            if conn and conn.is_connected(): conn.rollback()
            logging.error(f"DB error during registration: {e}")
            flash("Registration failed due to a database error.", "error")
        finally:
            if cursor: cursor.close(); close_db_connection(conn)
        # Re-render form with errors if commit failed or exception occurred
        return render_template('register.html', form=form)

    # Pass form to template on GET request
    return render_template('register.html', form=form)


# Login (Updated with WTForms & Email)
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles customer login using email and WTForms."""
    if g.user: return redirect(url_for('index'))
    form = LoginForm() # Instantiate form for both GET and POST
    if form.validate_on_submit(): # Runs only on valid POST
        email = form.email.data.strip().lower()
        password = form.password.data

        customer = get_user_by_email(email) # Using helper

        if customer and check_password_hash(customer.get('password_hash',''), password):
            # Login successful
            session.clear() # Ensure old session is cleared before setting new
            session['user_id'] = customer['customer_id']
            session['user_name'] = customer['customer_name'] # Use 'customer_name' from DB result
            session['user_email'] = customer['email'] # Store email
            session.permanent = True # Use app's lifetime config
            logging.info(f"User {customer['customer_name']} ({email}) logged in successfully.")
            flash(f"Welcome back, {customer['customer_name']}!", "success")
            next_page = request.args.get('next')
            # Basic security check for next_page to prevent open redirect
            if next_page and next_page.startswith('/') and not next_page.startswith('//') and ' ' not in next_page:
                 return redirect(next_page)
            else:
                 return redirect(url_for('index'))
        else:
            # Login failed
            logging.warning(f"Failed login attempt for email: {email}")
            flash("Invalid email or password.", "error")
            # Fall through to render template with form below (no redirect needed)

    # Pass form for GET requests AND for failed POST validation/login attempts
    return render_template('login.html', form=form)


# Logout
@app.route('/logout')
@login_required # Ensure user is logged in to log out
def logout():
    """Logs the user out and clears the session."""
    user_name_for_log = g.user.get('name', 'Unknown') if g.user else 'Unknown'
    user_id_for_log = g.user.get('id', 'Unknown') if g.user else 'Unknown'
    clear_qkd_session_log() # Clear specific session data first
    session.clear() # Clear the entire session
    flash("You have been logged out.", "info")
    logging.info(f"User {user_name_for_log} (ID: {user_id_for_log}) logged out.")
    return redirect(url_for('login'))

# --- Forgot Password Route with Debugging ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if g.user: return redirect(url_for('index')) # Redirect if logged in

    form = ForgotPasswordForm()
    if form.validate_on_submit(): # Runs only on valid POST
        email = form.email.data.strip().lower()
        logging.info(f"Password reset requested for: {email}")
        user = None # Initialize user to None
        try:
            user = get_user_by_email(email)
            logging.info(f"User lookup result for {email}: {'Found (' + user.get('customer_name', 'N/A') + ')' if user else 'Not Found'}")
        except Exception as e_lookup:
            logging.error(f"ERROR during get_user_by_email: {e_lookup}", exc_info=True) # Log traceback
            flash('An error occurred while checking your email. Please try again later.', 'error')
            return redirect(url_for('login')) # Redirect for security

        # Security Note: Show same message regardless of user existence
        if user: # Only proceed if user actually exists
            try:
                token_expiration = 3600 # 1 hour in seconds
                logging.info(f"Generating password reset token for {email}...")
                # Use dumps() to generate token
                token = serializer.dumps(email, salt='password-reset-salt') # Expiration checked on verify
                logging.info(f"Token generated successfully: {token[:15]}...")
                logging.info("Building reset URL...")
                reset_url = url_for('reset_password', token=token, _external=True)
                logging.info(f"Reset URL generated: {reset_url}")
            except Exception as e_token_url:
                logging.error(f"ERROR during token/URL generation for {email}: {e_token_url}", exc_info=True)
                flash('Failed to generate the password reset link. Please contact support if this persists.', 'error')
                return redirect(url_for('login'))

            # --- Simulate Sending Email (Print to Console) ---
            print("*" * 80) # Use print for visibility during dev/debug
            print("SIMULATING PASSWORD RESET EMAIL:")
            print(f"To: {email}")
            print(f"Subject: Reset Your QSB Portal Password")
            print("Body:")
            print(f" Please click the link below to reset your password:")
            print(f" {reset_url}")
            print(f" This link will expire in {token_expiration // 60} minutes.")
            print(" If you did not request this, please ignore this email.")
            print("*" * 80)
            # --- End Simulation ---

            # --- Real Email Sending Code would go here (using Flask-Mail etc.) ---

        flash('If an account with that email exists, instructions to reset your password have been sent.', 'info')
        return redirect(url_for('login')) # Redirect back to login page

    # Pass form for GET requests or if POST validation failed initially
    return render_template('forgot_password.html', form=form)


# --- Reset Password Route ---
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Redirect logged-in users away from reset page
    if g.user:
        return redirect(url_for('index'))

    try:
        # Verify the token signature and expiry (max_age = 3600 seconds = 1 hour)
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600) # Use loads() to verify
        logging.info(f"Password reset token verified for email: {email}")
    except SignatureExpired:
        logging.warning(f"Expired reset token used: {token}")
        flash('The password reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except (BadTimeSignature, Exception) as e: # Catch bad signature or other errors
        logging.warning(f"Invalid reset token attempt: {token} - Error: {e}") # Log the error
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('forgot_password'))

    # Token is valid, get the user associated with the email
    user = get_user_by_email(email) # Using helper
    if not user:
        # This scenario implies the user might have been deleted after token generation
        logging.error(f"User not found for valid reset token email: {email}")
        flash('User associated with this link not found.', 'error')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.password.data
        new_password_hash = generate_password_hash(new_password)

        # --- Update User Password in Database ---
        conn = get_db_connection(); cursor = None
        updated = False
        if not conn:
             flash('Database error. Could not update password.', 'error')
             return render_template('reset_password.html', form=form, token=token)
        else:
            try:
                cursor = conn.cursor()
                cursor.execute("UPDATE customers SET password_hash = %s WHERE email = %s", (new_password_hash, email))
                if cursor.rowcount == 1: # Check if update actually affected one row
                    conn.commit()
                    updated = True
                    logging.info(f"Password updated successfully in DB for {email}")
                else:
                    conn.rollback()
                    logging.error(f"Password update failed (rowcount={cursor.rowcount}) for {email}.")
                    flash('Password update failed. Please try the reset process again.', 'error')
            except MySQLError as e:
                 if conn and conn.is_connected(): conn.rollback()
                 logging.error(f"DB Error resetting password for {email}: {e}")
                 flash('An error occurred updating your password. Please try again.', 'error')
            finally:
                 if cursor: cursor.close()
                 close_db_connection(conn)

        if updated:
            flash('Your password has been successfully reset. Please log in.', 'success')
            return redirect(url_for('login'))
        # else: # If update failed, error was flashed, re-render form

    # Pass form for GET requests or failed POST validation
    return render_template('reset_password.html', form=form, token=token)


# --- Transfer Route ---
@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    # ... (Keep existing implementation - It's quite long, assuming it works) ...
    """Handles fund transfer: Runs QKD, validates, detects fraud, (conditionally) logs & updates balances. Stores outcome in session and redirects to index."""
    sender_id_str = request.form.get('sender_account_id'); receiver_id_str = request.form.get('receiver_account_id'); amount_str = request.form.get('amount')
    simulate_eve_checked = 'simulate_eve' in request.form
    sender_id = None; receiver_id = None; amount = None; logged_in_user_id = g.user['id']
    session.pop('last_transfer_outcome', None); last_outcome = {}
    try:
        sender_id = int(sender_id_str) if sender_id_str else None
        receiver_id = int(receiver_id_str) if receiver_id_str else None
        if not sender_id or not receiver_id: raise ValueError("Sender and Receiver accounts must be selected.")
        if sender_id == receiver_id: raise ValueError("Sender and Receiver accounts cannot be the same.")
        amount = Decimal(amount_str.strip());
        if amount <= 0: raise ValueError("Transfer amount must be positive.")
        last_outcome.update({'amount': f"{amount:.2f}", 'sender_id': sender_id, 'receiver_id': receiver_id})
    except (TypeError, ValueError, InvalidOperation) as e:
        flash(f"Invalid input: {e}", "error")
        session['last_transfer_outcome'] = {'status': 'Failed', 'reason': f"Invalid Input: {e}"}
        session.modified = True; return redirect(url_for('index'))

    logging.info(f"Transfer Request by User {logged_in_user_id}: {amount:.2f} from {sender_id} to {receiver_id} (Sim Eve: {simulate_eve_checked})")
    qber_threshold = current_app.config.get('QBER_THRESHOLD'); num_qubits = QKD_NUM_QUBITS; eve_rate = 0.25
    qkd_fernet_key = None; simulation_result = {}; qber = None; qkd_failure_reason = None
    failed_status_for_log = "UNKNOWN_QKD_FAIL"; fraud_reason_for_log = None
    try:
        simulation_result = simulate_bb84(n_qubits=num_qubits, simulate_eve=simulate_eve_checked, qber_threshold=qber_threshold, eve_interception_rate=eve_rate if simulate_eve_checked else 0.0)
        session[f'last_qkd_log_{logged_in_user_id}'] = simulation_result; session.modified = True; last_outcome['qkd_log_stored'] = True
        final_key_binary = simulation_result.get('final_key_binary'); qber = simulation_result.get('qber'); eve_detected = simulation_result.get('eve_detected', False)
        qber_display = f"{qber:.4f}" if qber is not None and qber >= 0 else 'N/A'; last_outcome['qber'] = qber_display

        if qber is None or qber < 0: qkd_failure_reason = "QBER calculation failed."; failed_status_for_log = "QBER_CALC_FAIL"
        elif eve_detected: qkd_failure_reason = f"Eavesdropping Detected / High QBER ({qber_display} > {qber_threshold:.2f})."; failed_status_for_log = "QBER_THRESHOLD_EXCEEDED"; fraud_reason_for_log = f"QKD Security Alert: {qkd_failure_reason}"
        elif not final_key_binary: qkd_failure_reason = f"Insufficient secure key bits generated (QBER OK: {qber_display})."; failed_status_for_log = "KEY_LENGTH_FAIL"

        if qkd_failure_reason: raise ValueError(f"QKD Failed: {qkd_failure_reason}") # Raise error to enter QKD fail block

        logging.info(f"QKD Succeeded (QBER: {qber_display}). Deriving key...")
        key_hash_bytes = hashlib.sha256(final_key_binary.encode('utf-8')).digest(); qkd_fernet_key = base64.urlsafe_b64encode(key_hash_bytes)

    except ValueError as qkd_fail_e: # Catch the specific QKD failure
        logging.warning(qkd_fail_e)
        flash(f"Transfer Aborted: {qkd_fail_e}", "danger")
        last_outcome.update({'status': 'Failed', 'reason': qkd_failure_reason, 'qkd_status_msg': failed_status_for_log.replace("_", " ")})
        log_failed_attempt(sender_id, receiver_id, amount, failed_status_for_log, qber_value=qber if qber is not None and qber >=0 else None, fraud_reason=fraud_reason_for_log)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))
    except Exception as qkd_err: # Catch other unexpected QKD/key derivation errors
        logging.error(f"Unexpected QKD/Key error: {qkd_err}", exc_info=True)
        flash(f'Transfer Aborted: Error during secure channel setup ({type(qkd_err).__name__}).', 'danger')
        failed_status = "QKD_INTERNAL_ERROR"
        last_outcome.update({'status': 'Failed', 'reason': 'QKD Internal Error', 'qkd_status_msg': failed_status.replace("_", " ")})
        log_failed_attempt(sender_id, receiver_id, amount, failed_status)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))

    # 5. Proceed with DB Transaction
    conn = None; cursor = None; failed_status = "UNKNOWN_FAIL"; fraud_check_result = {'is_fraudulent': False, 'reason': None}
    try:
        if not qkd_fernet_key: raise ValueError("Internal Error: QKD key missing.") # Should be caught above
        conn = get_db_connection();
        if not conn: raise ConnectionError("Database connection failed")
        cursor = conn.cursor(dictionary=True, buffered=True); conn.autocommit = False;

        # 5a. Auth & Pre-Transfer DB Checks
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,)); sender_info = cursor.fetchone()
        if not sender_info or sender_info['customer_id'] != logged_in_user_id: raise ValueError("Authorization Error or Sender Not Found.")
        sender_balance = Decimal(sender_info['balance']);
        if sender_balance < amount: raise ValueError(f"Insufficient funds (Balance: {sender_balance:.2f})")
        cursor.execute("SELECT a.account_id, c.customer_name FROM accounts a JOIN customers c ON a.customer_id = c.customer_id WHERE a.account_id = %s", (receiver_id,)); receiver_info = cursor.fetchone()
        if not receiver_info: raise ValueError(f"Receiver account {receiver_id} not found.")
        receiver_username = receiver_info['customer_name']; last_outcome['receiver_name'] = receiver_username

        # 5b. Fraud Detection
        logging.info("Running classical fraud detection...")
        cursor.execute("SELECT amount, timestamp FROM qkd_transaction_log WHERE sender_account_id = %s ORDER BY timestamp DESC LIMIT 5", (sender_id,))
        history = [{'amount': Decimal(r['amount']), 'timestamp': r['timestamp']} for r in cursor.fetchall() if isinstance(r.get('timestamp'), datetime.datetime)]
        current_txn = {'amount': float(amount), 'recipient_username': receiver_username, 'timestamp': datetime.datetime.now()}
        fraud_config = { 'blacklist': current_app.config.get('FRAUD_BLACKLIST', set()), 'amount_threshold': current_app.config.get('FRAUD_AMOUNT_THRESHOLD'), 'rapid_transaction_seconds': current_app.config.get('FRAUD_RAPID_TRANSACTION_SECONDS') }
        fraud_check_result = detect_fraud( current_transaction=current_txn, user_transaction_history=history, **fraud_config )
        qkd_status = "SECURED_FLAGGED" if fraud_check_result['is_fraudulent'] else "SECURED"; last_outcome['fraud_check'] = fraud_check_result
        if fraud_check_result['is_fraudulent']: logging.warning(f"Classical Fraud Alert for Txn: {fraud_check_result['reason']}")

        # 5c. Encrypt Confirmation
        logging.info("Encrypting confirmation...")
        qber_str = last_outcome['qber']
        msg_to_encrypt = f"CONFIRMED;FROM:{sender_id};TO:{receiver_id};AMT:{amount:.2f};TIME:{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')};QBER:{qber_str}"
        try:
            f = Fernet(qkd_fernet_key); encrypted_confirmation_bytes = f.encrypt(msg_to_encrypt.encode('utf-8'));
            encrypted_confirmation_b64 = encrypted_confirmation_bytes.decode('utf-8')
            last_outcome['encrypted_sample'] = encrypted_confirmation_b64[:60] + ('...' if len(encrypted_confirmation_b64) > 60 else '')
        except Exception as fernet_err:
            logging.error(f"ERROR: Fernet encryption failed: {fernet_err}"); failed_status = "ENCRYPTION_FAIL"; raise ValueError("Encryption failed, aborting transfer.")

        # 5d. Balance Update
        logging.info("Updating balances...")
        new_sender_balance = sender_balance - amount
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (receiver_id,)); new_receiver_balance = Decimal(cursor.fetchone()['balance']) + amount
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_sender_balance), sender_id))
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_receiver_balance), receiver_id))
        logging.info("Balances updated in DB cursor.")

        # 5e. Log Transaction
        logging.info(f"Logging transaction with status: {qkd_status}")
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        log_qber_db = qber if qber is not None and qber >= 0 else None
        log_values = (sender_id, receiver_id, str(amount), qkd_status, encrypted_confirmation_b64, None, log_qber_db, fraud_check_result['is_fraudulent'], fraud_check_result['reason'])
        cursor.execute(log_sql, log_values); last_outcome['log_id'] = cursor.lastrowid
        logging.info(f"Transaction logged with ID: {last_outcome['log_id']}")

        # 5f. Commit Transaction
        conn.commit(); logging.info("Transaction committed.")
        last_outcome['status'] = 'Success'; last_outcome['qkd_status_msg'] = qkd_status.replace("_", " ")
        flash_msg = f"Transfer successful! Log ID: {last_outcome['log_id']}. Secured (QBER: {qber_str})." if not fraud_check_result['is_fraudulent'] else f"Transfer successful (Log ID: {last_outcome['log_id']}), but FLAGED by classical rules: {fraud_check_result['reason']}";
        flash(flash_msg, "success" if not fraud_check_result['is_fraudulent'] else "warning")

    except (MySQLError, ValueError, InvalidOperation, ConnectionError) as e:
        if failed_status == "UNKNOWN_FAIL":
            if isinstance(e, ValueError): failed_status = "VALIDATION_FAIL"
            elif isinstance(e, ConnectionError): failed_status = "DB_CONNECTION_ERROR"
            else: failed_status = "DB_TRANSACTION_ERROR"
        logging.error(f"Transaction Error ({failed_status}): {e}", exc_info=True)
        last_outcome.update({'status': 'Failed', 'reason': str(e), 'qkd_status_msg': failed_status.replace("_", " ")})
        if conn and conn.is_connected():
            try: conn.rollback(); logging.info("Transaction rolled back due to error.")
            except MySQLError as rb_err: logging.error(f"Rollback Error: {rb_err}")
        if failed_status == "VALIDATION_FAIL": flash(f"Transfer Failed: {e}", "error")
        else: flash("Transfer Failed due to system error.", "error")
        log_failed_attempt(sender_id, receiver_id, amount, failed_status,
                           qber_value=last_outcome.get('qber'),
                           fraud_reason=fraud_check_result.get('reason'))

    finally:
        if cursor: cursor.close(); close_db_connection(conn)

    session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))


# --- History Route ---
@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays the transaction history, shows fraud status, indicates encrypted status."""
    user_id = g.user['id']; display_log = []; conn = get_db_connection(); cursor = None
    if not conn: flash("Database error. Cannot load history.", "error"); return render_template('history.html', log_entries=[])
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp, l.sender_account_id, s_cust.customer_name AS sender_name,
                       l.receiver_account_id, r_cust.customer_name AS receiver_name, l.amount, l.qkd_status,
                       l.qber_value, l.encrypted_confirmation, l.is_flagged, l.fraud_reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE s_acc.customer_id = %s OR r_acc.customer_id = %s
                  ORDER BY l.timestamp DESC LIMIT 100 """
        cursor.execute(sql, (user_id, user_id)); log_entries_raw = cursor.fetchall()
        for entry in log_entries_raw:
            try:
                amt = Decimal(entry['amount'] or '0.00'); qber = f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A"; enc_data_b64 = entry.get('encrypted_confirmation');
                if enc_data_b64: decrypted_details = "[Encrypted]"
                else: decrypted_details = "[Not Applicable]"
                display_log.append({
                    'id': entry['log_id'],
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (Acc: {entry.get('sender_account_id', '?')})",
                    'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': entry['qkd_status'], 'qber': qber,
                    'decrypted_details': decrypted_details,
                    'is_flagged': entry.get('is_flagged', False),
                    'fraud_reason': entry.get('fraud_reason')
                })
            except Exception as display_err: logging.warning(f"Error formatting log entry {entry.get('log_id', '?')} for history: {display_err}")
    except MySQLError as e: flash(f"Could not retrieve history: {e}", "error"); logging.error(f"Error retrieving history for user {user_id}: {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return render_template('history.html', log_entries=display_log)


# --- Info/Feature Routes ---
@app.route('/qkd')
@login_required
def qkd_page():
    """Displays the results of the last QKD simulation run from session."""
    user_id = g.user['id']; simulation_log = session.get(f'last_qkd_log_{user_id}', None)
    # TODO: Fetch actual QBER history from DB for the chart if desired
    qber_history_labels = ['Run 1', 'Run 2', 'Run 3', 'Run 4', 'Run 5']; qber_history_values = [1.2, 0.8, 15.3, 0.5, 2.1] # Example only
    return render_template('qkd.html',
                           simulation_log=simulation_log,
                           QBER_THRESHOLD=current_app.config.get('QBER_THRESHOLD'),
                           qber_history_labels=qber_history_labels,
                           qber_history_values=qber_history_values)

@app.route('/quantum-impact')
def quantum_impact(): return render_template("quantum_impact.html")

@app.route('/about')
def about(): return render_template("about.html")

def get_flagged_transactions(user_id, limit=50):
    """Helper function to fetch flagged transactions involving the user."""
    flagged_txns = []; conn = get_db_connection(); cursor = None;
    if not conn: return flagged_txns
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp, s_cust.customer_name AS sender_name, l.sender_account_id,
                       r_cust.customer_name AS receiver_name, l.receiver_account_id, l.amount, l.qkd_status, l.fraud_reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE (s_acc.customer_id = %s OR r_acc.customer_id = %s) AND l.is_flagged = TRUE
                  ORDER BY l.timestamp DESC LIMIT %s """
        cursor.execute(sql, (user_id, user_id, limit)); raw_flagged = cursor.fetchall()
        for entry in raw_flagged:
             try: amt = Decimal(entry['amount'] or '0.00'); flagged_txns.append({ 'id': entry['log_id'], 'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A', 'sender': f"{entry['sender_name'] or '?'} (Acc: {entry.get('sender_account_id', '?')})", 'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})", 'amount': f"{amt:.2f}", 'qkd_status': entry['qkd_status'], 'fraud_reason': entry.get('fraud_reason', 'Reason not specified') })
             except Exception as format_err: logging.warning(f"Error formatting flagged txn {entry.get('log_id', '?')} for fraud page: {format_err}")
    except MySQLError as e: logging.error(f"Error fetching flagged transactions for user {user_id}: {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return flagged_txns
@app.route('/fraud')
@login_required
def fraud_page():
    """Displays transactions flagged as fraudulent for the current user."""
    user_id = g.user['id']; flagged_transactions = get_flagged_transactions(user_id)
    return render_template("fraud.html", flagged_txns=flagged_transactions)

def get_log_entry_details(log_id):
    """ Fetches and formats log entry details for PDF generation & Auth check. """
    conn = get_db_connection(); cursor = None; details = None
    if not conn: return None
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.*, s_acc.customer_id AS sender_customer_id, s_cust.customer_name AS sender_name,
                       r_acc.customer_id AS receiver_customer_id, r_cust.customer_name AS receiver_name
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE l.log_id = %s """
        cursor.execute(sql, (log_id,)); entry = cursor.fetchone()
        if entry:
            details = { 'id': entry['log_id'], 'sender_customer_id': entry.get('sender_customer_id'), 'receiver_customer_id': entry.get('receiver_customer_id'), 'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A', 'sender': f"{entry['sender_name'] or '?'} (Acc: {entry.get('sender_account_id', '?')})", 'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})", 'amount': f"{Decimal(entry['amount'] or '0.00'):.2f}", 'qkd_status': entry['qkd_status'], 'qber': f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A", 'encrypted_hex': entry.get('encrypted_confirmation', 'N/A'), 'iv_hex': None, 'decrypted_details': "[Decryption not performed in PDF context]", 'is_flagged': entry.get('is_flagged', False), 'fraud_reason': entry.get('fraud_reason') }
    except Exception as e: logging.error(f"Error fetching log details for PDF (ID {log_id}): {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return details
@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    """Generates and serves the PDF report for a specific log entry after auth check."""
    user_id = g.user['id']; log_data = get_log_entry_details(log_id)
    if not log_data: abort(404, description="Log entry not found.")
    # Authorization Check
    if user_id != log_data.get('sender_customer_id') and user_id != log_data.get('receiver_customer_id'):
         logging.warning(f"Unauthorized attempt to download report {log_id} by user {user_id}")
         abort(403, description="You are not authorized to view this report.")
    pdf_bytes = create_qkd_report(log_data)
    if not pdf_bytes: abort(500, description="Failed to generate PDF report.")
    filename = f"QKD_Report_Log_{log_id}.pdf"
    return Response(pdf_bytes, mimetype="application/pdf", headers={"Content-Disposition": f"attachment;filename={filename}"})

@app.route('/report/<int:log_id>')
@login_required
def show_report_page(log_id):
     """(Optional) Displays a page confirming the report download action after auth check."""
     user_id = g.user['id']; report_info = get_log_entry_details(log_id)
     if not report_info: abort(404, "Log entry not found.")
     # Authorization Check
     if user_id != report_info.get('sender_customer_id') and user_id != report_info.get('receiver_customer_id'):
          logging.warning(f"Unauthorized attempt to view report page {log_id} by user {user_id}")
          abort(403, description="You are not authorized to view this report info.")
     display_info = { 'log_id': report_info.get('id'), 'timestamp': report_info.get('timestamp'), 'sender': report_info.get('sender') }
     # Ensure you have a 'templates/report.html' template
     return render_template('report.html', report_info=display_info) # You need to create this template

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    """Make session user and global constants available to all templates."""
    # Now uses g.user set in before_request
    return dict(
        session_user=g.get('user'),
        INITIAL_BALANCE=app.config.get('INITIAL_BALANCE'),
        QBER_THRESHOLD=app.config.get('QBER_THRESHOLD')
    )

# --- Main execution block ---
if __name__ == '__main__':
     print("\n" + "="*60); print("Starting Flask Development Server for QKD Bank Demo..."); print("="*60)
     print("\nIMPORTANT - Database Schema Requirements:");
     print("  - `customers` table needs `email` (VARCHAR, UNIQUE)") # Added email requirement
     print("  - `qkd_transaction_log` table needs:"); print("    * `is_flagged` (BOOLEAN or TINYINT(1) DEFAULT 0)"); print("    * `fraud_reason` (TEXT DEFAULT NULL)"); print("    * `encrypted_confirmation` (TEXT or LONGTEXT for base64)"); print("    * `iv` column should be NULLABLE (or removed if only using Fernet)")
     print("\nChecking Dependencies...")
     dependencies_ok = True
     # Check main dependencies
     try: import cryptography; print("  - [OK] cryptography")
     except ImportError: print("  - [ERROR] 'cryptography' not found! (pip install cryptography)"); dependencies_ok = False
     try: import qiskit_aer; print("  - [OK] qiskit-aer") # Assuming used by qkd_simulation
     except ImportError: print("  - [WARN] 'qiskit-aer' not found! QKD sim might fail. (pip install qiskit-aer)"); # Warn
     try: import reportlab; print("  - [OK] reportlab")
     except ImportError: print("  - [ERROR] 'reportlab' not found! (pip install reportlab)"); dependencies_ok = False
     try: import mysql.connector; print("  - [OK] mysql-connector-python")
     except ImportError: print("  - [ERROR] 'mysql-connector-python' not found! (pip install mysql-connector-python)"); dependencies_ok = False
     # Check added dependencies
     try: import flask_wtf; print("  - [OK] Flask-WTF")
     except ImportError: print("  - [ERROR] 'Flask-WTF' not found! (pip install Flask-WTF)"); dependencies_ok = False
     try: import email_validator; print("  - [OK] email-validator")
     except ImportError: print("  - [ERROR] 'email-validator' not found! (pip install email-validator)"); dependencies_ok = False

     if not dependencies_ok: print("\nPlease install missing dependencies before running."); exit()

     print("\nChecking Database Connection...")
     conn_test = get_db_connection()
     if conn_test:
         print("  - [OK] Database connection successful."); close_db_connection(conn_test)
         print("\nStarting Server..."); print(f"Access at: http://127.0.0.1:5001/ (or http://<your-ip>:5001/ if on network)"); print("Press CTRL+C to stop."); print("="*60 + "\n")
         # Run on specified port, use 0.0.0.0 to make accessible on network
         app.run(debug=True, host='0.0.0.0', port=5001)
     else:
          print("\n" + "="*60); print("FATAL: Database connection failed."); print(f"Using config: HOST={MYSQL_HOST}, USER={MYSQL_USER}, DB={MYSQL_DB}"); print("Check MySQL server status, credentials, user privileges, and if DB/tables exist."); print("="*60 + "\n"); exit()