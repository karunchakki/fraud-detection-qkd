# app.py
# FINAL VERSION WITH USER AUTHENTICATION & MySQL Fix & Template Context Fix

# --- Core Imports ---
from flask import Flask, request, render_template, flash, redirect, url_for, session, g
from functools import wraps
import os
import datetime

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

# --- Initialize Flask App ---
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_default_but_still_random_32_byte_key_!@#$%^&*()_+') # Use ENV VAR in prod
if app.secret_key == 'a_default_but_still_random_32_byte_key_!@#$%^&*()_+':
    print("WARNING: Using default FLASK_SECRET_KEY! Set a proper environment variable.")
app.config.update(
    SESSION_COOKIE_SECURE=False, # Set True if using HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=1) # Example: Session lasts 1 day
)

# --- Configuration Constants ---
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user') # Make sure this matches your MySQL setup
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'WindowsPass123!') # Use ENV VAR!
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')

MYSQL_CONFIG = {'host': MYSQL_HOST, 'user': MYSQL_USER, 'password': MYSQL_PASSWORD, 'database': MYSQL_DB, 'use_pure': True}

AES_KEY_SIZE_BYTES = 16
QBER_THRESHOLD = 0.15
QKD_NUM_QUBITS = 600
INITIAL_BALANCE = Decimal('1000.00')

app.config['QBER_THRESHOLD'] = QBER_THRESHOLD # Make accessible in templates via app.config

# --- Database Helper Functions ---
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

# (Optional: init_db_check_samples can be run manually once after table creation)
# def init_db_check_samples(): ... (Code from previous versions if needed)

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
                acc['balance'] = Decimal(acc['balance']) if acc['balance'] is not None else Decimal('0.00')
                accounts.append(acc)
            except (InvalidOperation, TypeError): continue # Skip bad data
    except MySQLError as e: print(f"Error fetching accounts: {e}"); flash("Error loading account data.", "error")
    finally:
        if cursor: cursor.close()
        close_db_connection(conn)
    return accounts

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value):
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
        log_sql = """INSERT INTO qkd_transaction_log
                     (sender_account_id, receiver_account_id, amount, qkd_status, qber_value)
                     VALUES (%s, %s, %s, %s, %s)"""
        qber_db_val = qber_value if isinstance(qber_value, (float, int)) else None
        log_values = (sender_id_val, receiver_id_val, amount_str, failed_status, qber_db_val)
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
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        g.user_id = session['user_id']
        g.user_name = session.get('user_name', 'User')
        return f(*args, **kwargs)
    return decorated_function

# --- Before Request Handler ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = {'id': user_id, 'name': session.get('user_name')} if user_id else None

# --- Flask Routes ---

@app.route('/', methods=['GET'])
@login_required
def index():
    """Renders the main transfer page with user's and potential receiver accounts."""
    user_accounts = get_accounts_data(customer_id_filter=session['user_id'])
    all_accounts = get_accounts_data()
    # Ensure receiver accounts are filtered correctly, excluding sender's accounts
    receiver_accounts = [acc for acc in all_accounts if acc['customer_id'] != session['user_id']]
    return render_template('index.html',
                           user_accounts=user_accounts,
                           receiver_accounts=receiver_accounts)


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
        if error: return render_template('register.html', INITIAL_BALANCE=INITIAL_BALANCE)

        conn = get_db_connection()
        if not conn: flash("Database error.", "error"); return render_template('register.html', INITIAL_BALANCE=INITIAL_BALANCE)
        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT customer_id FROM customers WHERE customer_name = %s", (customer_name,))
            if cursor.fetchone():
                flash(f"Customer name '{customer_name}' already exists.", "error")
            else:
                hashed_pw = generate_password_hash(password)
                cursor.execute("INSERT INTO customers (customer_name, password_hash) VALUES (%s, %s)", (customer_name, hashed_pw))
                customer_id = cursor.lastrowid
                if not customer_id: raise MySQLError("Failed customer insert.")
                cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (customer_id, str(INITIAL_BALANCE)))
                account_id = cursor.lastrowid
                if not account_id: raise MySQLError("Failed account insert.")
                conn.commit()
                flash(f"Customer '{customer_name}' registered! Account ID: {account_id}. Please login.", "success")
                print(f"Registered Customer ID: {customer_id}, Account ID: {account_id}")
                return redirect(url_for('login'))
        except MySQLError as e:
            if conn.is_connected(): conn.rollback()
            print(f"DB error during registration: {e}")
            flash(f"Registration failed due to database error.", "error")
        finally:
            if cursor: cursor.close()
            close_db_connection(conn)
        return render_template('register.html', INITIAL_BALANCE=INITIAL_BALANCE) # Re-render on error/user exists

    # GET request
    return render_template('register.html', INITIAL_BALANCE=INITIAL_BALANCE)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles customer login."""
    if 'user_id' in session: return redirect(url_for('index'))

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
                session.clear()
                session['user_id'] = customer['customer_id']
                session['user_name'] = customer['customer_name']
                session.permanent = True # Use configured lifetime
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
    """Logs the user out."""
    user_name = session.pop('user_name', 'User')
    session.pop('user_id', None)
    session.clear()
    flash(f"You have been logged out.", "success") # Simpler message
    print(f"User {user_name} logged out.")
    return redirect(url_for('login'))


@app.route('/transfer', methods=['POST'])
@login_required
def transfer_funds():
    """Handles fund transfer request, validation, QKD, logging, and balance updates."""
    sender_id_str = request.form.get('sender_account_id')
    receiver_id_str = request.form.get('receiver_account_id')
    amount_str = request.form.get('amount')
    simulate_eve_checked = 'simulate_eve' in request.form
    error_occurred = False; sender_id = None; receiver_id = None; amount = None
    logged_in_user_id = session['user_id']
    render_context = {} # Initialize context early

    try: # Combined validation block
        sender_id = int(sender_id_str) if sender_id_str else None
        receiver_id = int(receiver_id_str) if receiver_id_str else None
        if not sender_id or not receiver_id: raise ValueError("Account IDs required")
        if sender_id == receiver_id: raise ValueError("Sender/Receiver accounts same")
        amount = Decimal(amount_str.strip())
        if amount <= 0: raise ValueError("Amount must be positive")
    except (TypeError, ValueError, InvalidOperation) as e:
        error_occurred = True; print(f"Input validation error: {e}")
        # Flash appropriate message
        if str(e) == "Sender/Receiver accounts same": flash("Sender and Receiver accounts cannot be the same.", "error")
        elif str(e) == "Amount must be positive": flash("Transfer amount must be positive.", "error")
        elif str(e) == "Account IDs required": flash("Please select both sender and receiver accounts.", "error")
        else: flash(f"Invalid amount format provided.", "error")

    if error_occurred:
        # Fetch accounts again ONLY IF validation failed, to redisplay form
        user_accounts = get_accounts_data(customer_id_filter=logged_in_user_id)
        all_accounts = get_accounts_data()
        receiver_accounts = [acc for acc in all_accounts if acc['customer_id'] != logged_in_user_id]
        return render_template('index.html', user_accounts=user_accounts, receiver_accounts=receiver_accounts)

    # Proceed if initial validation passed
    print(f"\n--- Starting Transfer Request by User {logged_in_user_id} ---")
    print(f"Attempting transfer: {amount:.2f} from Account ID {sender_id} to Account ID {receiver_id}")
    if simulate_eve_checked: print("*** EVE SIMULATION ENABLED ***")

    transfer_successful = False; qkd_status = "PENDING"; encrypted_confirmation = None;
    iv = None; qber = None; final_key_bits = None; log_qber_value = None;
    conn = None; cursor = None

    try:
        conn = get_db_connection();
        if not conn: raise ConnectionError("Database connection failed")
        cursor = conn.cursor(dictionary=True, buffered=True)
        conn.autocommit = False # Ensure we control transactions
        # Start Transaction implicitly handled by autocommit=False, or use conn.start_transaction()

        # --- Authorization & Pre-Transfer Validation (Atomic Check & Lock) ---
        cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_info = cursor.fetchone()
        if not sender_info: raise ValueError(f"Sender account {sender_id} not found.")
        if sender_info['customer_id'] != logged_in_user_id: raise ValueError("Authorization Error.")
        sender_balance = Decimal(sender_info['balance'])
        if sender_balance < amount: raise ValueError(f"Insufficient funds. Balance: {sender_balance:.2f}")
        cursor.execute("SELECT account_id FROM accounts WHERE account_id = %s", (receiver_id,))
        if not cursor.fetchone(): raise ValueError(f"Receiver account {receiver_id} not found.")

        # --- QKD ---
        print(f"Running QKD simulation...")
        final_key_bits, qber = simulate_bb84(n_qubits=QKD_NUM_QUBITS, simulate_eve=simulate_eve_checked)
        log_qber_value = qber if qber != -1.0 else None
        render_context["qber_val"] = f"{qber:.3f}" if qber != -1.0 else "Calc Fail"
        if qber == -1.0: qkd_status = "QBER_CALC_FAIL"; raise ValueError("QKD Calc Failed")
        if qber > QBER_THRESHOLD: qkd_status = "QBER_THRESHOLD_EXCEEDED"; raise ValueError(f"High QBER: {qber*100:.1f}%")
        required_bits = AES_KEY_SIZE_BYTES * 8
        if final_key_bits is None or len(final_key_bits) < required_bits:
            qkd_status = "KEY_LENGTH_FAIL"; key_len = len(final_key_bits or [])
            raise ValueError(f"QKD Key Too Short: got {key_len}")

        # --- Encrypt Confirmation ---
        print(f"QKD OK (QBER={qber:.4f}). Encrypting log...")
        key_bits_for_aes = final_key_bits[:required_bits]
        key_int = int(''.join(map(str, key_bits_for_aes)), 2)
        key_bytes = key_int.to_bytes(AES_KEY_SIZE_BYTES, byteorder='big')
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        confirmation_msg = f"CONFIRMED;FROM:{sender_id};TO:{receiver_id};AMT:{amount:.2f};TIME:{timestamp_now};QBER:{qber:.4f}"
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        encrypted_confirmation = cipher.encrypt(pad(confirmation_msg.encode('utf-8'), AES.block_size))
        qkd_status = "SECURED"; print(f"Log encrypted.")
        render_context.update({'key_hex': key_bytes.hex(), 'iv_hex': iv.hex(), 'encrypted_hex': encrypted_confirmation.hex()})
        try: # Decryption check
             decipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
             dec_bytes = unpad(decipher.decrypt(encrypted_confirmation), AES.block_size)
             render_context['decrypted_text'] = dec_bytes.decode('utf-8'); print("Decryption OK.")
        except Exception as dec_err: render_context['decrypted_text'] = f"Decrypt Fail: {dec_err}"; print(f"Decrypt Error: {dec_err}")

        # --- Balance Update ---
        print("Updating balances...")
        new_sender_balance = sender_balance - amount
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (receiver_id,))
        new_receiver_balance = Decimal(cursor.fetchone()['balance']) + amount
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_sender_balance), sender_id))
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_receiver_balance), receiver_id))
        print(f"Balances updated.")
        transfer_successful = True

        # --- Log Transaction ---
        print(f"Logging transaction: {qkd_status}")
        log_sql = """INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount,
                     qkd_status, encrypted_confirmation, iv, qber_value)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)"""
        log_values = (sender_id, receiver_id, str(amount), qkd_status, encrypted_confirmation, iv, log_qber_value)
        cursor.execute(log_sql, log_values)

        # --- Commit ---
        conn.commit(); print("Transaction committed.")
        flash(f"Transfer successful! Log secured via QKD (QBER: {qber:.3f}).", "success")
        render_context['transfer_status'] = "Success"

    except (MySQLError, ValueError, InvalidOperation, ConnectionError) as e:
        failed_status = qkd_status if qkd_status not in ["PENDING", "SECURED"] else "VALIDATION_FAIL"
        print(f"Transaction Error ({failed_status}): {e}") # Log detailed error server-side
        if conn and conn.is_connected():
            try: conn.rollback(); print(f"Transaction rolled back.")
            except MySQLError as rb_err: print(f"Rollback Error: {rb_err}")
        if isinstance(e, ValueError): flash(f"Transaction Failed: {e}", "error") # Show user validation/QKD errors
        elif isinstance(e, ConnectionError): flash("Database Connection Error.", "error")
        else: flash(f"Transaction Failed due to database error.", "error") # General DB error
        transfer_successful = False
        render_context['transfer_status'] = "Failed"; render_context['qkd_status'] = failed_status
        log_failed_attempt(sender_id, receiver_id, amount, failed_status, log_qber_value) # Log the failure

    finally:
        if cursor: cursor.close()
        close_db_connection(conn)

    # --- Render results page ---
    user_accounts = get_accounts_data(customer_id_filter=logged_in_user_id)
    all_accounts = get_accounts_data()
    receiver_accounts = [acc for acc in all_accounts if acc['customer_id'] != logged_in_user_id]
    render_context["user_accounts"] = user_accounts
    render_context["receiver_accounts"] = receiver_accounts
    return render_template('index.html', **render_context)


# --- Route to view stored transaction log ---
@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays the history from the QKD transaction log."""
    # (Keep the /history route exactly as in the previous final version)
    log_entries = []
    conn = get_db_connection()
    if not conn: flash("DB connection error.", "error"); return render_template('history.html', log_entries=[])
    cursor = None; display_log = []
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """ SELECT l.log_id, l.timestamp, s_acc.account_id AS sender_acc_id,
                       s_cust.customer_name AS sender_name, r_acc.account_id AS receiver_acc_id,
                       r_cust.customer_name AS receiver_name, l.amount, l.qkd_status,
                       l.qber_value, l.encrypted_confirmation, l.iv
                  FROM qkd_transaction_log l
                  LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
                  LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
                  LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
                  LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
                  ORDER BY l.timestamp DESC LIMIT 100 """
        cursor.execute(sql)
        log_entries_raw = cursor.fetchall()
        for entry in log_entries_raw:
            try:
                amt = Decimal(entry['amount']) if entry['amount'] is not None else Decimal('0.00')
                qber = f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A"
                enc_hex = entry['encrypted_confirmation'].hex() if isinstance(entry['encrypted_confirmation'], (bytes, bytearray)) else "N/A"
                iv_hex = entry['iv'].hex() if isinstance(entry['iv'], (bytes, bytearray)) else "N/A"
                display_log.append({
                    'id': entry['log_id'],
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A',
                    'sender': f"{entry['sender_name'] or '?'} (Acc: {entry['sender_acc_id'] or '?'})",
                    'receiver': f"{entry['receiver_name'] or '?'} (Acc: {entry['receiver_acc_id'] or '?'})",
                    'amount': f"{amt:.2f}", 'qkd_status': entry['qkd_status'], 'qber': qber,
                    'encrypted_hex': enc_hex, 'iv_hex': iv_hex })
            except Exception as display_err: print(f"Err format log {entry.get('log_id', '?')}: {display_err}") # Log formatting errors
    except MySQLError as e: flash(f"Could not retrieve history: {e}", "error"); print(f"Err retrieve history: {e}")
    finally:
        if cursor: cursor.close(); close_db_connection(conn)
    return render_template('history.html', log_entries=display_log)


# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    """Make session user and constants available to all templates."""
    return dict(
        session_user=g.get('user'),
        INITIAL_BALANCE=INITIAL_BALANCE,
        # Add other constants here if needed globally
    )

# --- Main execution block (for Waitress) ---
# if __name__ == '__main__':
    # print("Starting QKD Bank Server (MySQL)... Run with Waitress.")
    # init_db_check_samples() # Optional: Run manually once
