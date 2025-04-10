# app.py
# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Includes: User Auth, MySQL, QKD Sim (BB84), Fernet Encryption,
#           Fraud Detection, PDF Reporting, Informational Pages.
# Revision: Integrated QKD run into /transfer route, removed separate key mgmt.
# Revision: Flag QKD failures (high QBER) as fraudulent in logs.

# --- Core Imports ---
from flask import (Flask, request, render_template, flash, redirect, url_for,
                   session, g, current_app, Response, abort)
from functools import wraps
import os
import datetime
import base64
import hashlib
import traceback # For detailed error logging

# --- Database Import ---
import mysql.connector
from mysql.connector import Error as MySQLError

# --- Security & Authentication ---
from werkzeug.security import generate_password_hash, check_password_hash

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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_insecure_default_secret_key_32bytes_')
if app.secret_key == 'a_very_insecure_default_secret_key_32bytes_':
    print("\n" + "="*60 + "\nWARNING: Using default FLASK_SECRET_KEY! Set a proper environment variable.\n" + "="*60 + "\n")

app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', 20)))
)

MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'WindowsPass123!')
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')
MYSQL_CONFIG = {'host': MYSQL_HOST, 'user': MYSQL_USER, 'password': MYSQL_PASSWORD, 'database': MYSQL_DB, 'use_pure': True, 'connection_timeout': 10}

QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
QKD_NUM_QUBITS = int(os.environ.get('QKD_NUM_QUBITS', 600))
INITIAL_BALANCE = Decimal(os.environ.get('INITIAL_BALANCE', '1000.00'))

app.config['FRAUD_BLACKLIST'] = set(filter(None, os.environ.get('FRAUD_BLACKLIST', 'bad_user1,scammer_acc').split(',')))
app.config['FRAUD_AMOUNT_THRESHOLD'] = float(os.environ.get('FRAUD_AMOUNT_THRESHOLD', 10000.00))
app.config['FRAUD_RAPID_TRANSACTION_SECONDS'] = int(os.environ.get('FRAUD_RAPID_SECONDS', 10))

app.config['QBER_THRESHOLD'] = QBER_THRESHOLD
app.config['INITIAL_BALANCE'] = INITIAL_BALANCE

# --- Database Helper Functions ---
def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected(): return conn
        else: print("DB connection failed: Not connected."); return None
    except MySQLError as e: print(f"CRITICAL DB Connect Error: {e}"); return None

def close_db_connection(conn):
    """Closes the database connection if it's open and connected."""
    if conn and conn.is_connected():
        try: conn.close()
        except MySQLError as e: print(f"Error closing DB connection: {e}")

def get_accounts_data(customer_id_filter=None):
    """Fetches account data, optionally filtering by customer_id. Returns empty list on error."""
    accounts = []; conn = get_db_connection(); cursor = None
    if not conn: flash("Database error. Cannot load account data.", "error"); return accounts
    try:
        cursor = conn.cursor(dictionary=True)
        sql = "SELECT a.account_id, c.customer_name, a.balance, a.customer_id FROM accounts a JOIN customers c ON a.customer_id = c.customer_id"
        params = []
        if customer_id_filter is not None: sql += " WHERE a.customer_id = %s"; params.append(customer_id_filter)
        sql += " ORDER BY a.account_id"
        cursor.execute(sql, tuple(params))
        for acc in cursor.fetchall():
            try: acc['balance'] = Decimal(acc.get('balance') or '0.00'); accounts.append(acc)
            except (InvalidOperation, TypeError) as e: print(f"Warning: Skipping acc {acc.get('account_id')} invalid balance: {e}")
    except MySQLError as e: print(f"Error fetching accounts: {e}"); flash("Error loading account data.", "error")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return accounts

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=None, fraud_reason=None):
     """Logs a failed transaction attempt into the database."""
     sender_id_val = sender_id or -1; receiver_id_val = receiver_id or -1
     amount_str = str(amount) if amount is not None else '0.00'; log_conn = None; log_cursor = None
     print(f"Logging failed transaction attempt status: {failed_status}")
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
        print(f"Failed attempt logged. Flagged: {is_flagged}, Reason: {fraud_reason}")
     except (MySQLError, ConnectionError) as log_err:
        print(f"CRITICAL: Failed to log FAILED transaction: {log_err}");
        if log_conn and log_conn.is_connected():
            try: log_conn.rollback()
            except MySQLError as rb_err: print(f"Rollback failed during error logging: {rb_err}")
     finally:
        if log_cursor: log_cursor.close(); close_db_connection(log_conn)

# --- Authentication ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: flash("Please log in to access this page.", "warning"); return redirect(url_for('login', next=request.url))
        g.user_id = session['user_id']; g.user_name = session.get('user_name', 'User')
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id'); g.user = {'id': user_id, 'name': session.get('user_name')} if user_id else None

# --- No Persistent QKD Key Management Needed ---

def clear_qkd_session_log():
     """Clears only the last QKD log from the session."""
     if g.user and 'id' in g.user:
         user_id = g.user['id']
         log_cleared = session.pop(f'last_qkd_log_{user_id}', None) is not None
         if log_cleared:
             session.modified = True; print(f"Cleared QKD log data for user {user_id}")

# --- Flask Routes ---

@app.route('/')
@login_required
def index():
    """Renders the dashboard, passing any transfer outcome from the session."""
    user_id = g.user['id']
    user_accounts = get_accounts_data(customer_id_filter=user_id)
    all_accounts = get_accounts_data()
    receiver_accounts = [acc for acc in all_accounts if acc['customer_id'] != user_id]
    flagged_transactions = get_flagged_transactions(user_id, limit=5)
    show_fraud_alert = bool(flagged_transactions)
    last_transfer_outcome = session.pop('last_transfer_outcome', None) # Get and remove outcome
    return render_template('index.html',
                           user_accounts=user_accounts,
                           receiver_accounts=receiver_accounts,
                           show_fraud_alert=show_fraud_alert,
                           last_transfer_outcome=last_transfer_outcome)

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles customer registration."""
    if g.user: return redirect(url_for('index'))
    customer_name_from_form = request.form.get('customer_name', '') if request.method == 'POST' else ''
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip(); password = request.form.get('password'); confirm_password = request.form.get('confirm_password'); error = False
        if not customer_name or len(customer_name) < 2: flash("Valid name required (min 2 chars).", "error"); error = True
        if not password or len(password) < 6: flash("Password required (min 6 chars).", "error"); error = True
        if password != confirm_password: flash("Passwords do not match.", "error"); error = True
        if error: return render_template('register.html', customer_name=customer_name_from_form)
        conn = get_db_connection(); cursor = None
        if not conn: flash("Database error.", "error"); return render_template('register.html', customer_name=customer_name_from_form)
        try:
            cursor = conn.cursor(dictionary=True); cursor.execute("SELECT customer_id FROM customers WHERE customer_name = %s", (customer_name,))
            if cursor.fetchone(): flash(f"Customer name '{customer_name}' already exists.", "error")
            else:
                hashed_pw = generate_password_hash(password); cursor.execute("INSERT INTO customers (customer_name, password_hash) VALUES (%s, %s)", (customer_name, hashed_pw)); customer_id = cursor.lastrowid
                if not customer_id: raise MySQLError("Failed customer insert.")
                cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (customer_id, str(INITIAL_BALANCE))); account_id = cursor.lastrowid
                if not account_id: raise MySQLError("Failed account insert.")
                conn.commit(); flash(f"Customer '{customer_name}' registered! Please login.", "success"); return redirect(url_for('login'))
        except MySQLError as e:
            if conn and conn.is_connected(): conn.rollback()
            print(f"DB error during registration: {e}"); flash("Registration failed.", "error")
        finally:
            if cursor: cursor.close(); close_db_connection(conn)
        return render_template('register.html', customer_name=customer_name_from_form)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles customer login."""
    if g.user: return redirect(url_for('index'))
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip(); password = request.form.get('password')
        if not customer_name or not password: flash("Please enter name and password.", "error"); return render_template('login.html')
        conn = get_db_connection(); cursor = None
        if not conn: flash("Database connection error.", "error"); return render_template('login.html')
        try:
            cursor = conn.cursor(dictionary=True); cursor.execute("SELECT customer_id, customer_name, password_hash FROM customers WHERE customer_name = %s", (customer_name,))
            customer = cursor.fetchone()
            if customer and check_password_hash(customer.get('password_hash',''), password):
                session.clear(); session['user_id'] = customer['customer_id']; session['user_name'] = customer['customer_name']; session.permanent = True
                flash(f"Welcome back, {customer['customer_name']}!", "success"); next_page = request.args.get('next'); return redirect(next_page or url_for('index'))
            else: flash("Invalid customer name or password.", "error")
        except MySQLError as e: print(f"DB error during login: {e}"); flash("Login error.", "error")
        finally:
            if cursor: cursor.close(); close_db_connection(conn)
        return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logs the user out and clears the session."""
    user_name_for_log = g.user.get('name', 'Unknown'); clear_qkd_session_log(); session.clear(); flash("You have been logged out.", "info"); print(f"User {user_name_for_log} logged out."); return redirect(url_for('login'))

# --- REMOVED /run_qkd Route ---

@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    """Handles fund transfer: Runs QKD, validates, detects fraud, (conditionally) logs & updates balances. Stores outcome in session and redirects to index."""
    # 1. Get Form Data
    sender_id_str = request.form.get('sender_account_id'); receiver_id_str = request.form.get('receiver_account_id'); amount_str = request.form.get('amount')
    simulate_eve_checked = 'simulate_eve' in request.form # Get Eve checkbox state
    sender_id = None; receiver_id = None; amount = None; logged_in_user_id = g.user['id']
    session.pop('last_transfer_outcome', None) # Clear previous outcome
    last_outcome = {} # Dictionary to store results for display on index page

    # 2. Input Validation
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
        session.modified = True
        return redirect(url_for('index'))

    print(f"\n--- Transfer Request by User {logged_in_user_id}: {amount:.2f} from {sender_id} to {receiver_id} (Sim Eve: {simulate_eve_checked})---")

    # 3. Run QKD Simulation
    qber_threshold = current_app.config.get('QBER_THRESHOLD'); num_qubits = QKD_NUM_QUBITS; eve_rate = 0.25
    qkd_fernet_key = None # Will be derived only if QKD succeeds
    try:
        simulation_result = simulate_bb84(
            n_qubits=num_qubits,
            simulate_eve=simulate_eve_checked,
            qber_threshold=qber_threshold,
            eve_interception_rate=eve_rate if simulate_eve_checked else 0.0
        )
        session[f'last_qkd_log_{logged_in_user_id}'] = simulation_result; session.modified = True
        last_outcome['qkd_log_stored'] = True

        final_key_binary = simulation_result.get('final_key_binary')
        qber = simulation_result.get('qber')
        eve_detected = simulation_result.get('eve_detected', False) # This flag is set if qber > threshold
        qber_display = f"{qber:.4f}" if qber is not None and qber >= 0 else 'N/A'
        last_outcome['qber'] = qber_display

        # 4. Check QKD Outcome and Decide Action
        qkd_failure_reason = None
        failed_status_for_log = "UNKNOWN_QKD_FAIL"
        fraud_reason_for_log = None # Explicitly initialize for this attempt

        if qber is None:
            qkd_failure_reason = "QBER could not be determined."
            failed_status_for_log = "QBER_CALC_FAIL"
        elif qber < 0:
            qkd_failure_reason = f"QBER calculation failed (Code: {qber})."
            failed_status_for_log = "QBER_CALC_FAIL"
        elif eve_detected: # Check the flag set by simulate_bb84
            qkd_failure_reason = f"Eavesdropping Detected / High QBER ({qber_display} > {qber_threshold:.2f})."
            failed_status_for_log = "QBER_THRESHOLD_EXCEEDED"
            # ---- MODIFICATION: Set fraud reason for this specific QKD security failure ----
            fraud_reason_for_log = f"QKD Security Alert: {qkd_failure_reason}"
            # --------------------------------------------------------------------------------
        elif not final_key_binary:
            qkd_failure_reason = f"Insufficient secure key bits generated (QBER OK: {qber_display})."
            failed_status_for_log = "KEY_LENGTH_FAIL"

        if qkd_failure_reason:
            # QKD FAILED - Log failure, store outcome, redirect
            print(f"QKD Failed: {qkd_failure_reason}")
            flash(f"Transfer Aborted: QKD failed - {qkd_failure_reason}", "danger")
            last_outcome.update({'status': 'Failed', 'reason': qkd_failure_reason, 'qkd_status_msg': failed_status_for_log.replace("_", " ")})
            # Pass the potentially set fraud_reason_for_log
            log_failed_attempt(sender_id, receiver_id, amount, failed_status_for_log,
                               qber_value=qber if qber is not None and qber >=0 else None,
                               fraud_reason=fraud_reason_for_log) # Log as flagged if QKD sec fail
            session['last_transfer_outcome'] = last_outcome; session.modified = True
            return redirect(url_for('index'))
        else:
            # QKD SUCCEEDED - Derive key for this transfer attempt
            print(f"QKD Succeeded (QBER: {qber_display}). Deriving key...")
            try:
                key_hash_bytes = hashlib.sha256(final_key_binary.encode('utf-8')).digest()
                qkd_fernet_key = base64.urlsafe_b64encode(key_hash_bytes) # Key derived successfully
            except Exception as e_key:
                print(f"Error deriving Fernet key after successful QKD: {e_key}")
                flash("Transfer Aborted: Error processing QKD key.", "danger")
                failed_status = "KEY_DERIVATION_FAIL"
                last_outcome.update({'status': 'Failed', 'reason': 'Key processing error', 'qkd_status_msg': failed_status.replace("_", " ")})
                log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value=qber)
                session['last_transfer_outcome'] = last_outcome; session.modified = True
                return redirect(url_for('index'))

    except Exception as qkd_err:
        # Handle unexpected errors during QKD simulation call itself
        print(f"Unexpected QKD simulation error: {qkd_err}"); traceback.print_exc()
        flash(f'Transfer Aborted: Error during QKD simulation ({type(qkd_err).__name__}).', 'danger')
        failed_status = "QKD_SIM_ERROR"
        last_outcome.update({'status': 'Failed', 'reason': 'QKD Simulation Error', 'qkd_status_msg': failed_status.replace("_", " ")})
        log_failed_attempt(sender_id, receiver_id, amount, failed_status)
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        return redirect(url_for('index'))

    # 5. Proceed with DB Transaction ONLY if QKD Succeeded and Key Derived
    conn = None; cursor = None; failed_status = "UNKNOWN_FAIL"; fraud_check_result = {'is_fraudulent': False, 'reason': None}
    try:
        if not qkd_fernet_key: # Should not happen if logic above is correct, but safety check
             raise ValueError("Internal Error: QKD key missing after successful simulation check.")

        conn = get_db_connection();
        if not conn: raise ConnectionError("Database connection failed")
        cursor = conn.cursor(dictionary=True, buffered=True); conn.autocommit = False;

        # 5a. Auth & Pre-Transfer DB Checks (Atomic)
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,)); sender_info = cursor.fetchone()
        if not sender_info or sender_info['customer_id'] != logged_in_user_id: raise ValueError("Authorization Error or Sender Not Found.")
        sender_balance = Decimal(sender_info['balance']);
        if sender_balance < amount: raise ValueError(f"Insufficient funds (Balance: {sender_balance:.2f})")
        cursor.execute("SELECT a.account_id, c.customer_name FROM accounts a JOIN customers c ON a.customer_id = c.customer_id WHERE a.account_id = %s", (receiver_id,)); receiver_info = cursor.fetchone()
        if not receiver_info: raise ValueError(f"Receiver account {receiver_id} not found.")
        receiver_username = receiver_info['customer_name']; last_outcome['receiver_name'] = receiver_username

        # 5b. Fraud Detection (Classical rules)
        print("Running classical fraud detection...")
        cursor.execute("SELECT amount, timestamp FROM qkd_transaction_log WHERE sender_account_id = %s ORDER BY timestamp DESC LIMIT 5", (sender_id,))
        history = [{'amount': Decimal(r['amount']), 'timestamp': r['timestamp']} for r in cursor.fetchall() if isinstance(r.get('timestamp'), datetime.datetime)]
        current_txn = {'amount': float(amount), 'recipient_username': receiver_username, 'timestamp': datetime.datetime.now()}
        fraud_config = { 'blacklist': current_app.config.get('FRAUD_BLACKLIST', set()), 'amount_threshold': current_app.config.get('FRAUD_AMOUNT_THRESHOLD'), 'rapid_transaction_seconds': current_app.config.get('FRAUD_RAPID_TRANSACTION_SECONDS') }
        fraud_check_result = detect_fraud( current_transaction=current_txn, user_transaction_history=history, **fraud_config )
        # Determine final QKD status for log based on classical fraud check
        qkd_status = "SECURED_FLAGGED" if fraud_check_result['is_fraudulent'] else "SECURED"
        last_outcome['fraud_check'] = fraud_check_result # Store classical fraud result
        if fraud_check_result['is_fraudulent']: print(f"Classical Fraud Alert: {fraud_check_result['reason']}")

        # 5c. Encrypt Confirmation using derived Fernet key
        print("Encrypting confirmation...")
        qber_str = last_outcome['qber'] # Get QBER from outcome dict
        msg_to_encrypt = f"CONFIRMED;FROM:{sender_id};TO:{receiver_id};AMT:{amount:.2f};TIME:{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')};QBER:{qber_str}"
        try:
            f = Fernet(qkd_fernet_key); encrypted_confirmation_bytes = f.encrypt(msg_to_encrypt.encode('utf-8'));
            encrypted_confirmation_b64 = encrypted_confirmation_bytes.decode('utf-8') # Store as string
            last_outcome['encrypted_sample'] = encrypted_confirmation_b64[:60] + ('...' if len(encrypted_confirmation_b64) > 60 else '')
            print("Confirmation encrypted.")
        except Exception as fernet_err:
            print(f"ERROR: Fernet encryption failed: {fernet_err}"); failed_status = "ENCRYPTION_FAIL"; raise ValueError("Encryption failed, aborting transfer.")

        # 5d. Balance Update (Atomic)
        print("Updating balances...")
        new_sender_balance = sender_balance - amount
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (receiver_id,)); new_receiver_balance = Decimal(cursor.fetchone()['balance']) + amount
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_sender_balance), sender_id))
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_receiver_balance), receiver_id))
        print("Balances updated.")

        # 5e. Log Transaction
        print(f"Logging transaction: {qkd_status}")
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        log_qber_db = qber if qber is not None and qber >= 0 else None
        # Log using the classical fraud check results
        log_values = (sender_id, receiver_id, str(amount), qkd_status, encrypted_confirmation_b64, None, log_qber_db, fraud_check_result['is_fraudulent'], fraud_check_result['reason'])
        cursor.execute(log_sql, log_values); last_outcome['log_id'] = cursor.lastrowid
        print(f"Transaction logged with ID: {last_outcome['log_id']}")

        # 5f. Commit Transaction
        conn.commit(); print("Transaction committed.")
        last_outcome['status'] = 'Success'; last_outcome['qkd_status_msg'] = qkd_status.replace("_", " ")
        flash_msg = f"Transfer successful! Log ID: {last_outcome['log_id']}. Secured (QBER: {qber_str})." if not fraud_check_result['is_fraudulent'] else f"Transfer successful (Log ID: {last_outcome['log_id']}), but FLAGED by classical rules: {fraud_check_result['reason']}";
        flash(flash_msg, "success" if not fraud_check_result['is_fraudulent'] else "warning")

    except (MySQLError, ValueError, InvalidOperation, ConnectionError) as e:
        # Error occurred during DB transaction part
        if failed_status == "UNKNOWN_FAIL": # If not already set by encryption failure
            if isinstance(e, ValueError): failed_status = "VALIDATION_FAIL"
            elif isinstance(e, ConnectionError): failed_status = "DB_CONNECTION_ERROR"
            else: failed_status = "DB_TRANSACTION_ERROR"
        print(f"Transaction Error ({failed_status}): {e}"); last_outcome.update({'status': 'Failed', 'reason': str(e), 'qkd_status_msg': failed_status.replace("_", " ")})
        if conn and conn.is_connected():
            try: conn.rollback(); print("Transaction rolled back.")
            except MySQLError as rb_err: print(f"Rollback Error: {rb_err}")
        if failed_status == "VALIDATION_FAIL": flash(f"Transfer Failed: {e}", "error")
        else: flash("Transfer Failed due to system error.", "error")
        # Log the failed attempt (use QBER from outcome, pass CLASSICAL fraud reason if check happened before failure)
        log_failed_attempt(sender_id, receiver_id, amount, failed_status,
                           qber_value=last_outcome.get('qber'),
                           fraud_reason=fraud_check_result.get('reason')) # Log classical reason if available

    finally:
        if cursor: cursor.close(); close_db_connection(conn)

    # Store final outcome (success or failure) in session and redirect
    session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))


# --- /history route ---
@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays the transaction history, shows fraud status, indicates encrypted status."""
    user_id = g.user['id']; display_log = []; conn = get_db_connection(); cursor = None
    if not conn: flash("Database error.", "error"); return render_template('history.html', log_entries=[])
    # No key fetching needed here as decryption isn't performed in history view
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
                # Indicate status based on presence of encrypted data
                if enc_data_b64: decrypted_details = "[Encrypted]"
                else: decrypted_details = "[Not Applicable]" # Or "[Failed Attempt]" etc.
                # Format for display
                display_log.append({
                    'id': entry['log_id'],
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (Acc: {entry.get('sender_account_id', '?')})",
                    'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry.get('receiver_account_id', '?')})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': entry['qkd_status'], 'qber': qber,
                    'decrypted_details': decrypted_details, # Shows status only
                    'is_flagged': entry.get('is_flagged', False),
                    'fraud_reason': entry.get('fraud_reason')
                })
            except Exception as display_err: print(f"Error formatting log entry {entry.get('log_id', '?')} for history: {display_err}")
    except MySQLError as e: flash(f"Could not retrieve history: {e}", "error"); print(f"Error retrieving history for user {user_id}: {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return render_template('history.html', log_entries=display_log)

# --- Informational and Feature Routes ---
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
                           qber_history_labels=qber_history_labels, # For Chart.js
                           qber_history_values=qber_history_values) # For Chart.js

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
             except Exception as format_err: print(f"Error formatting flagged txn {entry.get('log_id', '?')} for fraud page: {format_err}")
    except MySQLError as e: print(f"Error fetching flagged transactions for user {user_id}: {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return flagged_txns

@app.route('/fraud')
@login_required
def fraud_page():
    """Displays transactions flagged as fraudulent for the current user."""
    user_id = g.user['id']; flagged_transactions = get_flagged_transactions(user_id)
    return render_template("fraud.html", flagged_txns=flagged_transactions) # Assumes templates/fraud.html exists

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
    except Exception as e: print(f"Error fetching log details for PDF (ID {log_id}): {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return details

@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    """Generates and serves the PDF report for a specific log entry after auth check."""
    user_id = g.user['id']; log_data = get_log_entry_details(log_id)
    if not log_data: abort(404, description="Log entry not found.")
    if user_id != log_data.get('sender_customer_id') and user_id != log_data.get('receiver_customer_id'): abort(403, description="You are not authorized to view this report.")
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
     if user_id != report_info.get('sender_customer_id') and user_id != report_info.get('receiver_customer_id'): abort(403, description="You are not authorized to view this report info.")
     display_info = { 'log_id': report_info.get('id'), 'timestamp': report_info.get('timestamp'), 'sender': report_info.get('sender') }
     return render_template('report.html', report_info=display_info) # Assumes templates/report.html exists

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    """Make session user and global constants available to all templates."""
    return dict(
        session_user=g.get('user'),
        INITIAL_BALANCE=app.config.get('INITIAL_BALANCE'),
        QBER_THRESHOLD=app.config.get('QBER_THRESHOLD')
    )

# --- Main execution block ---
if __name__ == '__main__':
     print("\n" + "="*60); print("Starting Flask Development Server for QKD Bank Demo..."); print("="*60)
     print("\nIMPORTANT - Database Schema Requirements:"); print("  - `qkd_transaction_log` table needs:"); print("    * `is_flagged` (BOOLEAN or TINYINT(1) DEFAULT 0)"); print("    * `fraud_reason` (TEXT DEFAULT NULL)"); print("    * `encrypted_confirmation` (TEXT or LONGTEXT for base64)"); print("    * `iv` column should be NULLABLE (or removed if only using Fernet)")
     print("\nChecking Dependencies...")
     dependencies_ok = True
     try: import cryptography; print("  - [OK] cryptography")
     except ImportError: print("  - [ERROR] 'cryptography' not found! (pip install cryptography)"); dependencies_ok = False
     try: import qiskit_aer; print("  - [OK] qiskit-aer")
     except ImportError: print("  - [ERROR] 'qiskit-aer' not found! (pip install qiskit-aer)"); dependencies_ok = False
     try: import reportlab; print("  - [OK] reportlab")
     except ImportError: print("  - [ERROR] 'reportlab' not found! (pip install reportlab)"); dependencies_ok = False
     try: import mysql.connector; print("  - [OK] mysql-connector-python")
     except ImportError: print("  - [ERROR] 'mysql-connector-python' not found! (pip install mysql-connector-python)"); dependencies_ok = False
     if not dependencies_ok: print("\nPlease install missing dependencies before running."); exit()

     print("\nChecking Database Connection...")
     conn_test = get_db_connection()
     if conn_test:
         print("  - [OK] Database connection successful."); close_db_connection(conn_test)
         print("\nStarting Server..."); print(f"Access at: http://127.0.0.1:5001/ (or http://<your-ip>:5001/ if on network)"); print("Press CTRL+C to stop."); print("="*60 + "\n")
         app.run(debug=True, host='0.0.0.0', port=5001)
     else:
          print("\n" + "="*60); print("FATAL: Database connection failed."); print(f"Using config: HOST={MYSQL_HOST}, USER={MYSQL_USER}, DB={MYSQL_DB}"); print("Check MySQL server status, credentials, user privileges, and if DB/tables exist."); print("="*60 + "\n"); exit()
