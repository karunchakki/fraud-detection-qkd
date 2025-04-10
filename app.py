# app.py
# FINAL VERSION WITH USER AUTHENTICATION & MySQL Fix & Template Context Fix
# ++ INTEGRATED FRAUD DETECTION, QKD PAGE, NEW QKD FLOW ++
# +++ ADDED PDF REPORTING +++

# --- Core Imports ---
from flask import Flask, request, render_template, flash, redirect, url_for, session, g, current_app
# --- NEW PDF Imports ---
from flask import Response, abort # Import Response and abort
# --- End PDF Imports ---
from functools import wraps
import os
import datetime
import base64 # Added
import hashlib # Added

# --- Database Import ---
import mysql.connector
from mysql.connector import Error as MySQLError

# --- Security & Authentication ---
from werkzeug.security import generate_password_hash, check_password_hash

# --- Cryptography Imports ---
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Data Handling Import ---
from decimal import Decimal, InvalidOperation

# --- QKD Simulation Import ---
from qkd_simulation import simulate_bb84

# --- NEW: Fraud Detection Import ---
from fraud_detection import detect_fraud

# --- NEW: PDF Generation Import ---
from pdf_generator import create_qkd_report # Make sure pdf_generator.py exists

# --- Initialize Flask App ---
app = Flask(__name__)
# ...(keep existing app setup and config)...
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_default_but_still_random_32_byte_key_!@#$%^&*()_+') # Use ENV VAR in prod
if app.secret_key == 'a_default_but_still_random_32_byte_key_!@#$%^&*()_+':
    print("WARNING: Using default FLASK_SECRET_KEY! Set a proper environment variable.")
app.config.update(
    SESSION_COOKIE_SECURE=False, # Set True if using HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=10) # Example: Session key lasts 10 mins
)

# --- Configuration Constants ---
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user') # Make sure this matches your MySQL setup
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'WindowsPass123!') # Use ENV VAR!
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')

MYSQL_CONFIG = {'host': MYSQL_HOST, 'user': MYSQL_USER, 'password': MYSQL_PASSWORD, 'database': MYSQL_DB, 'use_pure': True}

AES_KEY_SIZE_BYTES = 16 # AES-128
QBER_THRESHOLD = 0.15 # 15%
QKD_NUM_QUBITS = 600 # Number of qubits for simulation
INITIAL_BALANCE = Decimal('1000.00')

# --- NEW: Fraud Detection Config ---
# Load from a safer place in reality
app.config['FRAUD_BLACKLIST'] = {'bad_user1', 'scammer_acc'} # Example blacklist
app.config['FRAUD_AMOUNT_THRESHOLD'] = 10000.00
app.config['FRAUD_RAPID_TRANSACTION_SECONDS'] = 10

# Make accessible in templates
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE


# --- Database Helper Functions ---
# ...(keep get_db_connection, close_db_connection, get_accounts_data, log_failed_attempt)...
def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected(): return conn
    except MySQLError as e: print(f"CRITICAL DB Connect Error: {e}")
    return None

def close_db_connection(conn):
    """Closes the database connection if it's open and connected."""
    if conn and conn.is_connected():
        try: conn.close()
        except MySQLError as e: print(f"Error closing DB connection: {e}")

def get_accounts_data(customer_id_filter=None):
    """Fetches account data, optionally filtering by customer_id."""
    accounts = []
    conn = get_db_connection()
    if not conn: flash("Database connection error.", "error"); return accounts
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """SELECT a.account_id, c.customer_name, a.balance, a.customer_id
                 FROM accounts a JOIN customers c ON a.customer_id = c.customer_id"""
        params = []
        if customer_id_filter is not None: # Check for None explicitly
            sql += " WHERE a.customer_id = %s"
            params.append(customer_id_filter)
        sql += " ORDER BY a.account_id"
        cursor.execute(sql, tuple(params))
        accounts_raw = cursor.fetchall()
        for acc in accounts_raw:
            try:
                # Ensure balance is Decimal, default to 0 if None or invalid
                balance_raw = acc.get('balance')
                acc['balance'] = Decimal(balance_raw) if balance_raw is not None else Decimal('0.00')
                accounts.append(acc)
            except (InvalidOperation, TypeError) as e:
                 print(f"Warning: Skipping account {acc.get('account_id')} due to invalid balance: {balance_raw} ({e})")
                 continue # Skip bad data
    except MySQLError as e: print(f"Error fetching accounts: {e}"); flash("Error loading account data.", "error")
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)
    return accounts

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None):
     """Logs a failed transaction attempt."""
     sender_id_val = sender_id if sender_id is not None else -1
     receiver_id_val = receiver_id if receiver_id is not None else -1
     amount_str = str(amount) if amount is not None else '0.00'
     print(f"Logging failed transaction attempt with status: {failed_status}")
     log_conn = None; log_cursor = None
     try:
        log_conn = get_db_connection()
        if not log_conn: raise ConnectionError("DB Conn failed for logging")
        log_cursor = log_conn.cursor()
        # *** ASSUMPTION: Added is_flagged (BOOL/TINYINT) and fraud_reason (TEXT) to qkd_transaction_log table ***
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status, qber_value, is_flagged, fraud_reason)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)"""
        qber_db_val = qber_value if isinstance(qber_value, (float, int)) else None
        is_flagged = True if fraud_reason else False # Flag if there's a reason
        log_values = (sender_id_val, receiver_id_val, amount_str, failed_status, qber_db_val, is_flagged, fraud_reason)
        log_cursor.execute(log_sql, log_values)
        log_conn.commit()
        print("Failed attempt logged.")
     except (MySQLError, ConnectionError) as log_err:
        print(f"CRITICAL: Failed to log the FAILED transaction attempt: {log_err}")
        if log_conn and log_conn.is_connected(): log_conn.rollback()
     finally:
        if log_cursor: log_cursor.close()
        close_db_connection(log_conn)


# --- Authentication Decorator ---
# ...(keep login_required decorator)...
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        # Load user info into g for this request
        g.user_id = session['user_id']
        g.user_name = session.get('user_name', 'User') # Use g instead of passing to f
        return f(*args, **kwargs)
    return decorated_function

# --- Before Request Handler ---
# ...(keep load_logged_in_user)...
@app.before_request
def load_logged_in_user():
    # Make user info globally available via 'g' if logged in
    user_id = session.get('user_id')
    if user_id:
        g.user = {'id': user_id, 'name': session.get('user_name')}
    else:
        g.user = None

# --- QKD Key Management ---
# ...(keep store_qkd_key, get_qkd_key, clear_qkd_key)...
def store_qkd_key(aes_key_bytes):
    """Stores the AES key (bytes) securely in session (DEMO ONLY)."""
    user_id = g.user['id']
    session[f'qkd_key_{user_id}'] = base64.urlsafe_b64encode(aes_key_bytes).decode('utf-8')
    session[f'qkd_key_time_{user_id}'] = datetime.datetime.now().isoformat()
    session.modified = True # Ensure session is saved
    print(f"Stored new QKD-derived AES key for user {user_id}")

def get_qkd_key():
    """Retrieves the AES key (bytes) from session, checks expiry (DEMO ONLY)."""
    if not g.user or 'id' not in g.user: return None
    user_id = g.user['id']

    key_b64 = session.get(f'qkd_key_{user_id}')
    key_time_str = session.get(f'qkd_key_time_{user_id}')

    if not key_b64 or not key_time_str: return None

    try:
        key_time = datetime.datetime.fromisoformat(key_time_str)
        now = datetime.datetime.now()
        key_age = now - key_time
        max_age = app.config.get('PERMANENT_SESSION_LIFETIME', datetime.timedelta(minutes=10)) # Use session lifetime

        if key_age > max_age:
            print(f"QKD key for user {user_id} has expired.")
            clear_qkd_key() # Remove expired key
            return None

        key_bytes = base64.urlsafe_b64decode(key_b64.encode('utf-8'))
        if len(key_bytes) != AES_KEY_SIZE_BYTES:
             print(f"Invalid key length retrieved for user {user_id}")
             clear_qkd_key()
             return None
        # print(f"Retrieved active QKD key for user {user_id}")
        return key_bytes
    except (ValueError, TypeError, base64.binascii.Error) as e:
        print(f"Error decoding/validating key for user {user_id}: {e}")
        clear_qkd_key() # Remove invalid key
        return None

def clear_qkd_key():
    """Clears the QKD key and related info from the session."""
    if g.user and 'id' in g.user:
        user_id = g.user['id']
        session.pop(f'qkd_key_{user_id}', None)
        session.pop(f'qkd_key_time_{user_id}', None)
        session.pop(f'last_qkd_log_{user_id}', None) # Also clear log
        session.modified = True
        print(f"Cleared QKD key for user {user_id}")


# --- Flask Routes ---

# ...(keep routes: /, /register, /login, /logout, /run_qkd, /transfer)...
@app.route('/')
@login_required
def index():
    """Renders the main transfer page with user's and potential receiver accounts."""
    user_id = g.user['id']
    user_accounts = get_accounts_data(customer_id_filter=user_id)
    all_accounts = get_accounts_data()
    # Ensure receiver accounts are filtered correctly, excluding sender's accounts
    receiver_accounts = [acc for acc in all_accounts if acc['customer_id'] != user_id]

    # Check for fraud alerts to display on dashboard
    # Need to fetch recent transactions for the user to check flags
    flagged_transactions = get_flagged_transactions(user_id, limit=5) # Get last 5 flagged
    show_fraud_alert = bool(flagged_transactions)

    # Check QKD key status
    key_status = "No Key Generated"
    key_age_str = None
    key_time_str = session.get(f'qkd_key_time_{user_id}')
    active_key = get_qkd_key() # This checks expiry implicitly

    if active_key:
        key_status = "Key Active"
        try:
             key_time = datetime.datetime.fromisoformat(key_time_str)
             now = datetime.datetime.now()
             age_delta = now - key_time
             key_age_str = f"{int(age_delta.total_seconds())} sec ago"
        except (ValueError, TypeError):
             key_age_str = "Timestamp Error"
    elif key_time_str: # Key exists in session but get_qkd_key returned None (likely expired)
        key_status = "Key Expired - Run QKD"

    return render_template('index.html',
                           user_accounts=user_accounts,
                           receiver_accounts=receiver_accounts,
                           show_fraud_alert=show_fraud_alert, # For alert box
                           key_status=key_status,           # For key status display
                           key_age=key_age_str)             # For key age display


@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles customer registration."""
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        error = False
        if not customer_name or len(customer_name) < 2: flash("Valid name required (min 2 chars).", "error"); error = True
        if not password or len(password) < 6: flash("Password required (min 6 chars).", "error"); error = True
        if password != confirm_password: flash("Passwords do not match.", "error"); error = True
        # Use configured initial balance
        initial_balance_value = app.config.get('INITIAL_BALANCE', Decimal('1000.00'))

        if error: return render_template('register.html') # Context processor handles INITIAL_BALANCE

        conn = get_db_connection()
        if not conn: flash("Database error.", "error"); return render_template('register.html')
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            # Check if customer name already exists
            cursor.execute("SELECT customer_id FROM customers WHERE customer_name = %s", (customer_name,))
            if cursor.fetchone():
                flash(f"Customer name '{customer_name}' already exists.", "error")
            else:
                hashed_pw = generate_password_hash(password)
                # Insert into customers table
                cursor.execute("INSERT INTO customers (customer_name, password_hash) VALUES (%s, %s)", (customer_name, hashed_pw))
                customer_id = cursor.lastrowid
                if not customer_id: raise MySQLError("Failed customer insert.")
                # Insert into accounts table with initial balance
                cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (customer_id, str(initial_balance_value)))
                account_id = cursor.lastrowid
                if not account_id: raise MySQLError("Failed account insert.")
                conn.commit()
                flash(f"Customer '{customer_name}' registered! Account ID: {account_id}. Please login.", "success")
                print(f"Registered Customer ID: {customer_id}, Account ID: {account_id}")
                return redirect(url_for('login'))
        except MySQLError as e:
            if conn and conn.is_connected(): conn.rollback()
            print(f"DB error during registration: {e}")
            flash(f"Registration failed due to database error.", "error")
        finally:
            if cursor: cursor.close()
            close_db_connection(conn)
        # Re-render on error/user exists
        return render_template('register.html')

    # GET request
    return render_template('register.html') # Context processor handles INITIAL_BALANCE


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles customer login."""
    if g.user: # Already logged in (checked by load_logged_in_user)
        return redirect(url_for('index'))

    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip()
        password = request.form.get('password')
        if not customer_name or not password:
            flash("Please enter both customer name and password.", "error")
            return render_template('login.html')

        conn = get_db_connection()
        if not conn: flash("Database connection error.", "error"); return render_template('login.html')
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT customer_id, customer_name, password_hash FROM customers WHERE customer_name = %s", (customer_name,))
            customer = cursor.fetchone()
            if customer and customer.get('password_hash') and check_password_hash(customer['password_hash'], password):
                session.clear() # Clear any old session data
                session['user_id'] = customer['customer_id']
                session['user_name'] = customer['customer_name']
                session.permanent = True # Use configured lifetime
                # Clear any potentially stale QKD key from a previous session/user
                # clear_qkd_key() # clear_qkd_key now relies on g.user, which isn't set yet
                # Manually clear potential keys based on new user ID
                session.pop(f'qkd_key_{customer["customer_id"]}', None)
                session.pop(f'qkd_key_time_{customer["customer_id"]}', None)
                session.pop(f'last_qkd_log_{customer["customer_id"]}', None)
                session.modified = True

                flash(f"Welcome back, {customer['customer_name']}!", "success")
                print(f"Login successful: {customer_name} (ID: {customer['customer_id']})")
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash("Invalid customer name or password.", "error"); print(f"Login failed: {customer_name}")
        except MySQLError as e:
            print(f"DB error during login for {customer_name}: {e}"); flash("Login error.", "error")
        finally:
            if cursor: cursor.close()
            close_db_connection(conn)
        return render_template('login.html') # Re-render login on failure

    return render_template('login.html') # Show login form on GET


@app.route('/logout')
@login_required
def logout():
    """Logs the user out and clears the session."""
    user_name_for_log = g.user.get('name', 'Unknown')
    clear_qkd_key() # Clear key associated with this user
    session.clear() # Clear everything else
    flash(f"You have been logged out.", "info")
    print(f"User {user_name_for_log} logged out.")
    return redirect(url_for('login'))


@app.route('/run_qkd', methods=['POST'])
@login_required
def run_qkd():
    """Runs the QKD simulation and stores the derived AES key if successful."""
    user_id = g.user['id']
    simulate_eve_checked = 'simulate_eve' in request.form
    # Get QBER threshold from app config
    qber_threshold = current_app.config.get('QBER_THRESHOLD', 0.15)
    # Get num qubits from app config or use default
    num_qubits = current_app.config.get('QKD_NUM_QUBITS', 600)
    eve_rate = 0.25 # Example fixed rate, could be a form input

    print(f"User {user_id} initiating QKD run (Qubits: {num_qubits}, Threshold: {qber_threshold})...")
    if simulate_eve_checked: print("*** EVE SIMULATION ENABLED ***")

    try:
        simulation_result = simulate_bb84(
            n_qubits=num_qubits,
            simulate_eve=simulate_eve_checked,
            qber_threshold=qber_threshold, # Pass threshold to simulator
            eve_interception_rate=eve_rate if simulate_eve_checked else 0.0
        )

        # Store the full log for the /qkd page
        session[f'last_qkd_log_{user_id}'] = simulation_result
        session.modified = True

        # Process results from the returned dictionary
        final_key_binary = simulation_result.get('final_key_binary')
        qber = simulation_result.get('qber', -1.0)
        eve_detected = simulation_result.get('eve_detected', False) # Use the flag from result
        final_key_length = simulation_result.get('final_key_length', 0)

        if qber < 0: # Check for calculation failure codes (-1.0, -2.0, -3.0)
            flash(f'QKD Simulation Error: QBER calculation failed (Code: {qber}).', 'danger')
            clear_qkd_key()
        elif eve_detected: # Check the explicit flag
            flash(f'Eavesdropper Detected or High QBER! QBER = {qber:.2%}. Key REJECTED.', 'danger')
            clear_qkd_key()
        elif final_key_binary:
            # Key generated and QBER okay
            try:
                # Convert binary string key to bytes for storage
                key_int = int(final_key_binary, 2)
                # Ensure correct byte size - pad if necessary (though BB84 should ideally yield enough)
                # Note: Fernet requires urlsafe base64 encoded 32 bytes key. We need to derive that.
                # Using SHA256 hash of the QKD key provides a fixed-size 32-byte key.
                key_hash_bytes = hashlib.sha256(final_key_binary.encode('utf-8')).digest() # 32 bytes
                aes_key_for_storage = base64.urlsafe_b64encode(key_hash_bytes) # Fernet compatible key

                # Re-implement store_qkd_key to accept the Fernet key
                store_fernet_qkd_key(aes_key_for_storage) # Need to adjust storage function
                flash(f'QKD successful! New AES key generated (derived from {final_key_length} bits). QBER = {qber:.2%}', 'success')

            except ValueError as e:
                 flash(f'Error deriving AES key from QKD result: {e}', 'danger')
                 clear_qkd_key()
            except Exception as e_key: # Catch other potential errors
                 flash(f'Error storing derived key: {e_key}', 'danger')
                 clear_qkd_key()

        else:
             # QBER okay, but no key generated (e.g., too short after QBER check)
            flash(f'QKD failed: Final key too short or not generated (Length: {final_key_length}). QBER = {qber:.2%}.', 'warning')
            clear_qkd_key()

    except Exception as e:
        flash(f'An unexpected error occurred during QKD simulation: {e}', 'danger')
        print(f"QKD Runtime Error for user {user_id}: {e}") # Log the error server-side
        clear_qkd_key()

    return redirect(url_for('index'))


@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    """Handles fund transfer: requires QKD key, validates, detects fraud, logs, updates balances."""
    sender_id_str = request.form.get('sender_account_id')
    receiver_id_str = request.form.get('receiver_account_id')
    amount_str = request.form.get('amount')
    error_occurred = False; sender_id = None; receiver_id = None; amount = None
    logged_in_user_id = g.user['id']
    render_context = {}

    # --- 1. Retrieve QKD Key (expects Fernet compatible key now) ---
    qkd_fernet_key = get_fernet_qkd_key() # Need to adjust retrieval function
    if not qkd_fernet_key:
        flash("No active QKD key found. Please run the QKD simulation first.", "warning")
        return redirect(url_for('index'))

    # --- 2. Input Validation ---
    # ...(keep input validation as is)...
    try:
        sender_id = int(sender_id_str) if sender_id_str else None
        receiver_id = int(receiver_id_str) if receiver_id_str else None
        if not sender_id or not receiver_id: raise ValueError("Account IDs required")
        if sender_id == receiver_id: raise ValueError("Sender/Receiver accounts same")
        amount = Decimal(amount_str.strip())
        if amount <= 0: raise ValueError("Amount must be positive")
    except (TypeError, ValueError, InvalidOperation) as e:
        error_occurred = True; print(f"Input validation error: {e}")
        if str(e) == "Sender/Receiver accounts same": flash("Sender and Receiver accounts cannot be the same.", "error")
        elif str(e) == "Amount must be positive": flash("Transfer amount must be positive.", "error")
        elif str(e) == "Account IDs required": flash("Please select both sender and receiver accounts.", "error")
        else: flash(f"Invalid amount format provided.", "error")
        # Redirect back to index if validation fails
        return redirect(url_for('index'))


    # --- Proceed if validation passed ---
    print(f"\n--- Starting Transfer Request by User {logged_in_user_id} ---")
    print(f"Attempting transfer: {amount:.2f} from Account ID {sender_id} to Account ID {receiver_id}")
    print(f"Using active QKD key (Fernet).")

    transfer_successful = False; qkd_status = "PENDING"; encrypted_confirmation_b64 = None; # Store as base64 string
    iv = None # IV is handled by Fernet internally
    log_qber_value = None;
    fraud_check_result = {'is_fraudulent': False, 'reason': None}
    conn = None; cursor = None

    try:
        conn = get_db_connection();
        if not conn: raise ConnectionError("Database connection failed")
        cursor = conn.cursor(dictionary=True, buffered=True)
        conn.autocommit = False # Control transactions

        # --- 3. Authorization & Pre-Transfer DB Checks ---
        # ...(keep DB checks as is)...
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_info = cursor.fetchone()
        if not sender_info: raise ValueError(f"Sender account {sender_id} not found.")
        if sender_info['customer_id'] != logged_in_user_id: raise ValueError("Authorization Error: Sender account does not belong to logged-in user.")
        sender_balance = Decimal(sender_info['balance'])
        if sender_balance < amount: raise ValueError(f"Insufficient funds. Balance: {sender_balance:.2f}")
        # Check receiver exists (lock not strictly needed unless updating receiver atomically elsewhere)
        cursor.execute("SELECT account_id, customer_id FROM accounts WHERE account_id = %s", (receiver_id,))
        receiver_info = cursor.fetchone()
        if not receiver_info: raise ValueError(f"Receiver account {receiver_id} not found.")
        # Get receiver name for fraud check
        cursor.execute("SELECT customer_name FROM customers WHERE customer_id = %s", (receiver_info['customer_id'],))
        receiver_customer = cursor.fetchone()
        receiver_username = receiver_customer['customer_name'] if receiver_customer else 'Unknown_Receiver'


        # --- 4. Fraud Detection ---
        # ...(keep fraud detection logic as is)...
        print("Running fraud detection...")
        # Fetch necessary history for fraud check (e.g., last N transactions)
        # This query could be more sophisticated based on fraud logic needs
        cursor.execute("""
            SELECT amount, timestamp FROM qkd_transaction_log
            WHERE sender_account_id = %s
            ORDER BY timestamp DESC LIMIT 5
        """, (sender_id,))
        # Convert timestamps from DB format to datetime objects for fraud_detection.py
        raw_history = cursor.fetchall()
        user_transaction_history_for_fraud = []
        for row in raw_history:
            try:
                history_ts = row['timestamp'] # Should be datetime object from connector
                if isinstance(history_ts, datetime.datetime):
                     user_transaction_history_for_fraud.append({
                        'amount': Decimal(row['amount']),
                        'timestamp': history_ts
                    })
                else:
                    print(f"Warning: Skipping history entry with invalid timestamp: {history_ts}")
            except (InvalidOperation, TypeError, KeyError):
                print(f"Warning: Skipping history entry due to conversion error: {row}")
                continue

        current_txn_data_for_fraud = {
            'amount': float(amount), # fraud_detection expects float for now
            'recipient_username': receiver_username, # Use actual recipient username
            'timestamp': datetime.datetime.now() # Current time for check
        }
        blacklist = current_app.config.get('FRAUD_BLACKLIST', set())
        # Pass specific config values to fraud detection function
        fraud_check_result = detect_fraud(
            current_transaction=current_txn_data_for_fraud,
            user_transaction_history=user_transaction_history_for_fraud,
            blacklist=blacklist,
            amount_threshold=current_app.config.get('FRAUD_AMOUNT_THRESHOLD'),
            rapid_transaction_seconds=current_app.config.get('FRAUD_RAPID_TRANSACTION_SECONDS')
        )
        if fraud_check_result['is_fraudulent']:
            print(f"Fraud Alert: Reason(s) - {fraud_check_result['reason']}")
            # Decide action: block transaction or just flag it? For demo, we'll just flag.
            qkd_status = "SECURED_FLAGGED"
        else:
            print("Fraud check passed.")
            qkd_status = "SECURED"


        # --- 5. Encrypt Confirmation (using Fernet) ---
        print(f"Encrypting confirmation log using Fernet...")
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_qkd_log = session.get(f'last_qkd_log_{logged_in_user_id}', {})
        qber_from_log = last_qkd_log.get('qber', 'N/A')
        qber_str = f"{qber_from_log:.4f}" if isinstance(qber_from_log, float) else str(qber_from_log)

        confirmation_msg = f"CONFIRMED;FROM:{sender_id};TO:{receiver_id};AMT:{amount:.2f};TIME:{timestamp_now};QBER:{qber_str}"
        try:
             # Use Fernet for encryption
             f = Fernet(qkd_fernet_key)
             encrypted_confirmation_bytes = f.encrypt(confirmation_msg.encode('utf-8'))
             # Store the encrypted bytes as a URL-safe base64 string
             encrypted_confirmation_b64 = encrypted_confirmation_bytes.decode('utf-8')
             print(f"Confirmation log encrypted (Fernet).")
        except Exception as fernet_err:
             print(f"ERROR: Fernet encryption failed: {fernet_err}")
             qkd_status = "ENCRYPTION_FAIL" # Mark status as failed
             raise ValueError("Encryption failed, aborting transfer.") # Abort transaction

        # --- 6. Balance Update ---
        # ...(keep balance update as is)...
        print("Updating balances...")
        new_sender_balance = sender_balance - amount
        # Fetch receiver balance again inside transaction for atomicity
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (receiver_id,))
        receiver_current_balance = Decimal(cursor.fetchone()['balance'])
        new_receiver_balance = receiver_current_balance + amount
        # Update balances
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_sender_balance), sender_id))
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_receiver_balance), receiver_id))
        print(f"Balances updated.")
        transfer_successful = True


        # --- 7. Log Transaction ---
        print(f"Logging transaction: {qkd_status}")
        # *** Changed: encrypted_confirmation is now TEXT, iv is NULL (handled by Fernet) ***
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status,
                      encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        log_qber_value = qber_from_log if isinstance(qber_from_log, float) else None
        log_values = (
            sender_id, receiver_id, str(amount), qkd_status,
            encrypted_confirmation_b64, None, log_qber_value, # Store base64 string, IV is None
            fraud_check_result['is_fraudulent'], fraud_check_result['reason']
        )
        cursor.execute(log_sql, log_values)

        # --- 8. Commit ---
        conn.commit(); print("Transaction committed.")
        if fraud_check_result['is_fraudulent']:
             flash(f"Transfer successful, but FLAGED as potentially fraudulent: {fraud_check_result['reason']}", "warning")
        else:
            flash(f"Transfer successful! Log secured using QKD key (QBER: {qber_str}).", "success")
        render_context['transfer_status'] = "Success"
        # ... (rest of success handling) ...

    except (MySQLError, ValueError, InvalidOperation, ConnectionError) as e:
        # ...(keep error handling as is)...
         # Determine failure reason more specifically
        if isinstance(e, ValueError) and "QKD" in str(e).upper(): # Specific QKD errors from validation step (shouldn't happen here now)
             failed_status = "QKD_FAIL"
        elif isinstance(e, ValueError) and "Encryption failed" in str(e):
            failed_status = "ENCRYPTION_FAIL" # Specific encryption failure
        elif isinstance(e, ValueError): # Other validation errors (insufficient funds, auth, etc.)
             failed_status = "VALIDATION_FAIL"
        elif isinstance(e, ConnectionError):
             failed_status = "DB_CONNECTION_ERROR"
        else: # General MySQL errors during transaction
             failed_status = "DB_TRANSACTION_ERROR"

        print(f"Transaction Error ({failed_status}): {e}") # Log detailed error server-side
        if conn and conn.is_connected():
            try: conn.rollback(); print(f"Transaction rolled back.")
            except MySQLError as rb_err: print(f"Rollback Error: {rb_err}")

        # Provide user-friendly error message
        if failed_status == "VALIDATION_FAIL":
             flash(f"Transaction Failed: {e}", "error") # Show specific validation reason
        elif failed_status == "DB_CONNECTION_ERROR":
             flash("Transaction Failed: Database Connection Error.", "error")
        elif failed_status == "ENCRYPTION_FAIL":
            flash("Transaction Failed: Could not secure transaction details.", "error")
        else:
             flash(f"Transaction Failed due to a system error.", "error") # Generic error for others

        transfer_successful = False
        render_context['transfer_status'] = "Failed"
        render_context['qkd_status'] = failed_status # Log the failure reason

        # Log the failed attempt
        log_failed_attempt(sender_id, receiver_id, amount, failed_status,
                           fraud_reason=fraud_check_result.get('reason')) # Log fraud reason if failure occurred after check


    finally:
        if cursor: cursor.close()
        close_db_connection(conn)

    return redirect(url_for('history'))


# --- Route to view stored transaction log ---
@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays the transaction history, attempts decryption (Fernet), shows fraud status."""
    user_id = g.user['id']
    display_log = []
    conn = get_db_connection()
    if not conn: flash("DB connection error.", "error"); return render_template('history.html', log_entries=[])
    cursor = None
    # Try to get current Fernet key for decryption
    current_qkd_fernet_key = get_fernet_qkd_key() # Adjusted function name

    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp, l.sender_account_id,
                       s_cust.customer_name AS sender_name, l.receiver_account_id,
                       r_cust.customer_name AS receiver_name, l.amount, l.qkd_status,
                       l.qber_value, l.encrypted_confirmation, l.iv, -- IV likely NULL now
                       l.is_flagged, l.fraud_reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE s_acc.customer_id = %s OR r_acc.customer_id = %s
                  ORDER BY l.timestamp DESC LIMIT 100 """
        cursor.execute(sql, (user_id, user_id))
        log_entries_raw = cursor.fetchall()

        for entry in log_entries_raw:
            try:
                amt = Decimal(entry['amount']) if entry['amount'] is not None else Decimal('0.00')
                qber = f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A"
                # Encrypted confirmation is now TEXT (base64 string)
                enc_data_b64 = entry.get('encrypted_confirmation')
                # iv_data = entry.get('iv') # No longer needed for Fernet
                # enc_hex = enc_data.hex() if isinstance(enc_data, (bytes, bytearray)) else "N/A"
                # iv_hex = iv_data.hex() if isinstance(iv_data, (bytes, bytearray)) else "N/A"
                decrypted_details = "[Encrypted]"

                # Attempt decryption using Fernet
                if current_qkd_fernet_key and enc_data_b64:
                    try:
                        f = Fernet(current_qkd_fernet_key)
                        dec_bytes = f.decrypt(enc_data_b64.encode('utf-8')) # Decrypt from bytes
                        decrypted_details = dec_bytes.decode('utf-8')
                    except InvalidToken:
                         decrypted_details = "[Decryption Failed: Invalid Key/Token]"
                    except Exception as dec_err:
                        decrypted_details = f"[Decryption Error: {type(dec_err).__name__}]"
                elif enc_data_b64:
                    decrypted_details = "[Encrypted - Key Unavailable/Expired]"
                else:
                     decrypted_details = "[No Encrypted Data]"

                display_log.append({
                    'id': entry['log_id'],
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (Acc: {entry['sender_account_id'] or '?'})",
                    'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry['receiver_account_id'] or '?'})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': entry['qkd_status'],
                    'qber': qber,
                    # 'encrypted_hex': enc_hex, # Maybe display truncated b64? Or remove.
                    # 'iv_hex': iv_hex, # Remove IV
                    'decrypted_details': decrypted_details,
                    'is_flagged': entry.get('is_flagged', False),
                    'fraud_reason': entry.get('fraud_reason')
                })
            except Exception as display_err:
                print(f"Error formatting log entry {entry.get('log_id', '?')}: {display_err}")
    except MySQLError as e:
        flash(f"Could not retrieve history: {e}", "error")
        print(f"Error retrieving history for user {user_id}: {e}")
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)

    return render_template('history.html', log_entries=display_log)


# --- NEW: Informational and Feature Routes ---
# ...(keep /qkd, /quantum-impact, /about, /fraud)...
@app.route('/qkd')
@login_required
def qkd_page():
    """Displays the QKD simulation explanation and results page."""
    user_id = g.user['id']
    # Retrieve the log from the last QKD run stored in the session
    simulation_log = session.get(f'last_qkd_log_{user_id}', None)
    # Pass the log and threshold to the template
    return render_template('qkd.html',
                           simulation_log=simulation_log,
                           QBER_THRESHOLD=current_app.config.get('QBER_THRESHOLD') # Pass threshold to template
                           )


@app.route('/quantum-impact')
def quantum_impact():
    """Serves the Quantum Impact educational page."""
    # Assumes templates/quantum_impact.html exists
    return render_template("quantum_impact.html")


@app.route('/about')
def about():
    """Serves the About page."""
    # Assumes templates/about.html exists
    return render_template("about.html")


def get_flagged_transactions(user_id, limit=50):
    """Helper function to fetch flagged transactions for a user."""
    flagged_txns = []
    conn = get_db_connection()
    if not conn: return flagged_txns # Return empty list on DB error
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        # Fetch flagged transactions involving the user
        # *** ASSUMPTION: Added is_flagged, fraud_reason columns to SELECT ***
        sql = """ SELECT l.log_id, l.timestamp, l.sender_account_id,
                       s_cust.customer_name AS sender_name, l.receiver_account_id,
                       r_cust.customer_name AS receiver_name, l.amount, l.qkd_status,
                       l.fraud_reason -- Added fraud reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE (s_acc.customer_id = %s OR r_acc.customer_id = %s) AND l.is_flagged = TRUE
                  ORDER BY l.timestamp DESC LIMIT %s """
        cursor.execute(sql, (user_id, user_id, limit))
        raw_flagged = cursor.fetchall()
        for entry in raw_flagged:
             # Simplified formatting for fraud page
             try:
                 amt = Decimal(entry['amount']) if entry['amount'] is not None else Decimal('0.00')
                 flagged_txns.append({
                    'id': entry['log_id'],
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (Acc: {entry['sender_account_id'] or '?'})",
                    'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry['receiver_account_id'] or '?'})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': entry['qkd_status'],
                    'fraud_reason': entry.get('fraud_reason', 'Reason not specified')
                 })
             except Exception as format_err:
                 print(f"Error formatting flagged txn {entry.get('log_id', '?')}: {format_err}")
                 continue

    except MySQLError as e:
        print(f"Error fetching flagged transactions for user {user_id}: {e}")
        # Don't flash here, just return empty list or partial results
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)
    return flagged_txns

@app.route('/fraud')
@login_required
def fraud_page():
    """Displays transactions flagged as fraudulent for the current user."""
    user_id = g.user['id']
    flagged_transactions = get_flagged_transactions(user_id)
    # Assumes templates/fraud.html exists
    return render_template("fraud.html", flagged_txns=flagged_transactions)

# --- NEW: PDF Reporting Routes and Helper ---

# Function to get details for a specific log entry (modified for PDF needs)
def get_log_entry_details(log_id):
    """ Fetches and formats log entry details suitable for PDF generation. """
    conn = get_db_connection()
    if not conn: return None
    cursor = None
    details = None
    try:
        cursor = conn.cursor(dictionary=True)
        # Query adjusted to ensure necessary account IDs are fetched for user check
        sql = """ SELECT l.log_id AS id, l.timestamp,
                       l.sender_account_id, s_acc.customer_id AS sender_customer_id, s_cust.customer_name AS sender_name,
                       l.receiver_account_id, r_acc.customer_id AS receiver_customer_id, r_cust.customer_name AS receiver_name,
                       l.amount, l.qkd_status, l.qber_value AS qber,
                       l.encrypted_confirmation, l.iv, l.is_flagged, l.fraud_reason
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  WHERE l.log_id = %s """
        cursor.execute(sql, (log_id,))
        entry = cursor.fetchone()
        if entry:
            # Format data similarly to how history route does it for the PDF generator
            details = {
                 'id': entry['id'],
                 'sender_customer_id': entry.get('sender_customer_id'), # For Auth check
                 'receiver_customer_id': entry.get('receiver_customer_id'), # For Auth check
                 'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                 'sender': f"{entry['sender_name'] or '?'} (Acc: {entry.get('sender_account_id', '?')})",
                 'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})",
                 'amount': f"{Decimal(entry['amount']):.2f}" if entry['amount'] is not None else '0.00',
                 'qkd_status': entry['qkd_status'],
                 'qber': f"{entry['qber']:.3f}" if entry['qber'] is not None else "N/A",
                 # Encrypted confirmation is now TEXT (base64)
                 'encrypted_hex': entry.get('encrypted_confirmation', 'N/A'), # Keep name, content is base64
                 'iv_hex': None, # IV is null with Fernet
                 'decrypted_details': "[Decryption not possible in PDF context]", # PDF usually won't have live key
                 'is_flagged': entry.get('is_flagged', False),
                 'fraud_reason': entry.get('fraud_reason')
            }

    except Exception as e:
        print(f"Error fetching log details for ID {log_id}: {e}")
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)
    return details


@app.route('/report/download/<int:log_id>')
@login_required # Ensure user is logged in
def download_report(log_id):
    """Fetches log data, generates PDF, and returns it for download."""
    user_id = g.user['id'] # Assuming g.user is set

    # Fetch the log entry details
    log_data = get_log_entry_details(log_id)

    if not log_data:
        abort(404, description="Log entry not found.")

    # --- Authorization Check ---
    # Check if the current user was the sender OR receiver of this transaction
    sender_cust_id = log_data.get('sender_customer_id')
    receiver_cust_id = log_data.get('receiver_customer_id')
    if user_id != sender_cust_id and user_id != receiver_cust_id:
         print(f"Authorization failed: User {user_id} tried to access report for log {log_id}")
         abort(403, description="You are not authorized to view this report.") # Forbidden
    # --- End Authorization Check ---


    # Generate the PDF using the fetched data
    pdf_bytes = create_qkd_report(log_data) # Function from pdf_generator.py

    if not pdf_bytes:
        abort(500, description="Failed to generate PDF report.") # Server error

    # Create filename
    filename = f"QKD_Report_Log_{log_id}.pdf"

    # Return the PDF bytes as a response
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment;filename={filename}" # Use attachment to prompt download
        }
    )

@app.route('/report/<int:log_id>')
@login_required
def show_report_page(log_id):
     """Displays a page confirming the report to be downloaded."""
     user_id = g.user['id']
     # Fetch basic info to display on the page before download
     report_info = get_log_entry_details(log_id) # Reuse fetching logic
     if not report_info:
          abort(404, "Log entry not found.")

     # --- Authorization Check ---
     sender_cust_id = report_info.get('sender_customer_id')
     receiver_cust_id = report_info.get('receiver_customer_id')
     if user_id != sender_cust_id and user_id != receiver_cust_id:
          print(f"Authorization failed: User {user_id} tried to access report page for log {log_id}")
          abort(403, description="You are not authorized to view this report page.")
     # --- End Authorization Check ---

     # Simplify data for display on the HTML page
     display_info = {
         'log_id': report_info.get('id'),
         'timestamp': report_info.get('timestamp'),
         'sender': report_info.get('sender')
     }
     return render_template('report.html', report_info=display_info)

# --- End PDF Routes ---


# --- Context Processors ---
# ...(keep inject_global_vars)...
@app.context_processor
def inject_global_vars():
    """Make session user and constants available to all templates."""
    return dict(
        session_user=g.get('user'),
        INITIAL_BALANCE=app.config.get('INITIAL_BALANCE'),
        QBER_THRESHOLD=app.config.get('QBER_THRESHOLD')
    )

# --- Main execution block ---
# ...(keep if __name__ == '__main__':)...
if __name__ == '__main__':
     print("Starting Flask Development Server...")
     print(f"WARNING: Running in Development Mode. Use Waitress/Gunicorn for Production.")
     print(f"WARNING: QKD keys stored in session are INSECURE for production.")
     # Ensure FRAUD_BLACKLIST is loaded from a secure source in production
     print(f"Fraud Blacklist (Example): {app.config.get('FRAUD_BLACKLIST')}")
     # Switch to using Fernet for encryption - Requires cryptography library
     try:
         from cryptography.fernet import Fernet, InvalidToken # Import Fernet here for check
         print("Cryptography (Fernet) library found.")
     except ImportError:
         print("ERROR: 'cryptography' library not found. Please install it (`pip install cryptography`).")
         exit() # Exit if essential crypto library is missing

     # Add helper functions for Fernet key management if not already adjusted
     def store_fernet_qkd_key(fernet_key_bytes):
         """Stores the Fernet key (bytes) in session (DEMO ONLY)."""
         if g.user and 'id' in g.user:
             user_id = g.user['id']
             # Store the raw bytes directly, encoded as base64 string in session
             session[f'qkd_fernet_key_{user_id}'] = base64.urlsafe_b64encode(fernet_key_bytes).decode('utf-8')
             session[f'qkd_key_time_{user_id}'] = datetime.datetime.now().isoformat() # Reuse time key
             session.modified = True
             print(f"Stored new QKD-derived Fernet key for user {user_id}")
         else:
             print("Error: Cannot store key, user context not found.")

     def get_fernet_qkd_key():
         """Retrieves the Fernet key (bytes) from session, checks expiry (DEMO ONLY)."""
         if not g.user or 'id' not in g.user: return None
         user_id = g.user['id']
         key_b64 = session.get(f'qkd_fernet_key_{user_id}')
         key_time_str = session.get(f'qkd_key_time_{user_id}')

         if not key_b64 or not key_time_str: return None

         try:
             key_time = datetime.datetime.fromisoformat(key_time_str)
             now = datetime.datetime.now()
             key_age = now - key_time
             max_age = app.config.get('PERMANENT_SESSION_LIFETIME', datetime.timedelta(minutes=10))

             if key_age > max_age:
                 print(f"QKD Fernet key for user {user_id} has expired.")
                 clear_qkd_key() # Clear associated keys/logs
                 return None

             key_bytes = base64.urlsafe_b64decode(key_b64.encode('utf-8'))
             # No specific length check needed for Fernet itself, but it expects a valid key
             return key_bytes # Return the raw bytes
         except (ValueError, TypeError, base64.binascii.Error) as e:
             print(f"Error decoding/validating Fernet key for user {user_id}: {e}")
             clear_qkd_key()
             return None

     # Make sure clear_qkd_key also clears the fernet key
     original_clear_qkd_key = clear_qkd_key # Keep a reference
     def clear_qkd_key():
         """Clears QKD related info including Fernet key."""
         if g.user and 'id' in g.user:
             user_id = g.user['id']
             session.pop(f'qkd_fernet_key_{user_id}', None) # Remove Fernet key too
             original_clear_qkd_key() # Call the original logic
         # else: # Handle case where g.user might not be set? Original handled this.
         #     print("Cannot clear key, user context not available.")


     # Check DB connection before running
     conn_test = get_db_connection()
     if conn_test:
         print("Database connection successful.")
         close_db_connection(conn_test)
         app.run(debug=True, port=5001) # Run on a different port if 5000 is busy
     else:
          print("FATAL: Database connection failed. Please check credentials and MySQL server status.")
          print(f"Using config: HOST={MYSQL_HOST}, USER={MYSQL_USER}, DB={MYSQL_DB}")
