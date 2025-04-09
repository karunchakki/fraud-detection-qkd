# app.py
# Main Flask application for the Quantum-Secure Banking Simulation

# --- Core Imports ---
from flask import Flask, request, render_template, flash, redirect, url_for
import os
import datetime # For timestamps in confirmation message

# --- Database Import ---
import mysql.connector # MySQL connector
from mysql.connector import Error as MySQLError

# --- Cryptography Imports ---
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Data Handling Import ---
from decimal import Decimal, InvalidOperation # Use Decimal for currency calculations

# --- QKD Simulation Import ---
# Ensure qkd_simulation.py is in the same directory or Python path
# and contains the updated simulate_bb84(n_qubits, simulate_eve) function
from qkd_simulation import simulate_bb84

# --- Initialize Flask App ---
app = Flask(__name__)
# IMPORTANT: Set a strong, random secret key for production
# For development, os.urandom is okay, but it changes on each restart.
# Consider setting via environment variable: os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
app.secret_key = os.urandom(24)

# --- Configuration Constants ---
# Load from environment variables if available, otherwise use defaults (for local dev)
MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
MYSQL_USER = os.environ.get('MYSQL_USER', 'qkd_app_user') # Replace default if needed
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'WindowsPass123!') # Replace default if needed
MYSQL_DB = os.environ.get('MYSQL_DB', 'qkd_bank_db')

MYSQL_CONFIG = {
    'host': MYSQL_HOST,
    'user': MYSQL_USER,
    'password': MYSQL_PASSWORD,
    'database': MYSQL_DB,
    'use_pure': True # Optional: Use pure Python connector if C extension causes issues
}

AES_KEY_SIZE_BYTES = 16 # Corresponds to AES-128
QBER_THRESHOLD = 0.15 # Maximum acceptable Quantum Bit Error Rate (15%)
QKD_NUM_QUBITS = 600 # Number of initial qubits for BB84 simulation (increased for reliability)
INITIAL_BALANCE = Decimal('1000.00') # Starting balance for newly registered accounts

# Add QBER_THRESHOLD to Flask config for access in templates
app.config['QBER_THRESHOLD'] = QBER_THRESHOLD

# --- Database Helper Functions ---

def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected():
            return conn
    except MySQLError as e:
        print(f"CRITICAL Error connecting to MySQL Database: {e}")
    # Return None if connection fails
    return None

def init_db_check_samples():
    """Checks if sample data exists and adds it if tables are empty.
       Assumes tables were created externally (e.g., via SQL script)."""
    print("Checking for sample data...")
    conn = get_db_connection()
    if not conn:
        print("DB connection failed during init_db_check_samples.")
        return # Cannot proceed without DB connection

    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM customers")
        customer_count = cursor.fetchone()[0]

        if customer_count == 0:
            print("Adding sample customer and account data...")
            conn.autocommit = True # Use autocommit for simple sample data insertion

            # Add sample customer Alice
            cursor.execute("INSERT INTO customers (customer_name) VALUES (%s)", ('Alice',))
            alice_id = cursor.lastrowid
            cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (alice_id, str(Decimal('10000.00'))))

            # Add sample customer Bob
            cursor.execute("INSERT INTO customers (customer_name) VALUES (%s)", ('Bob',))
            bob_id = cursor.lastrowid
            cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (bob_id, str(Decimal('5000.00'))))

            # Add sample customer Charlie
            cursor.execute("INSERT INTO customers (customer_name) VALUES (%s)", ('Charlie',))
            charlie_id = cursor.lastrowid
            cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)", (charlie_id, str(Decimal('25000.00'))))

            print("Sample data added.")
        else:
            print("Sample data check: Tables not empty.")

    except MySQLError as e:
        print(f"Database Error during sample data check/insert: {e}")
        # No rollback needed for check/autocommit insert generally
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

def get_accounts_data():
    """Fetches all account data joined with customer names for display."""
    accounts = []
    conn = get_db_connection()
    if not conn:
        flash("Database connection error. Could not load account data.", "error")
        return accounts # Return empty list on connection failure

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True) # Get rows as dictionaries
        cursor.execute("""
            SELECT a.account_id, c.customer_name, a.balance
            FROM accounts a
            JOIN customers c ON a.customer_id = c.customer_id
            ORDER BY a.account_id
        """)
        accounts_raw = cursor.fetchall()
        # Convert balance to Decimal for consistent handling
        for acc in accounts_raw:
            try:
                 acc['balance'] = Decimal(acc['balance'])
                 accounts.append(acc)
            except (InvalidOperation, TypeError) as conversion_err:
                 print(f"Warning: Could not convert balance for account {acc.get('account_id')}: {conversion_err}")
                 # Optionally skip this account or set balance to None/0

    except MySQLError as e:
        print(f"Error fetching accounts: {e}")
        flash("Error loading account data.", "error")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    return accounts

def log_failed_attempt(sender_id, receiver_id, amount, failed_status, qber_value):
     """Logs a failed transaction attempt outside the main transaction block."""
     sender_id_val = sender_id if sender_id is not None else -1 # Use placeholder ID if unknown
     receiver_id_val = receiver_id if receiver_id is not None else -1
     amount_str = str(amount) if amount is not None else '0.00' # Ensure amount is string for DB if needed

     print(f"Logging failed transaction attempt with status: {failed_status}")
     log_conn = None; log_cursor = None
     try:
        log_conn = get_db_connection()
        if not log_conn:
            print("CRITICAL: Cannot log failed attempt - DB connection failed.")
            return # Cannot log if connection fails

        log_cursor = log_conn.cursor()
        log_sql = """
            INSERT INTO qkd_transaction_log
            (sender_account_id, receiver_account_id, amount, qkd_status, qber_value)
            VALUES (%s, %s, %s, %s, %s)
        """
        # Ensure log_qber_value is None or a float/compatible type for DB
        qber_db_val = qber_value if isinstance(qber_value, (float, int)) else None
        log_values = (sender_id_val, receiver_id_val, amount_str, failed_status, qber_db_val)
        log_cursor.execute(log_sql, log_values)
        log_conn.commit()
        print("Failed attempt logged.")
     except MySQLError as log_err:
        print(f"CRITICAL: Failed to log the FAILED transaction attempt: {log_err}")
        if log_conn and log_conn.is_connected(): log_conn.rollback() # Rollback log insert if failed
     finally:
        if log_cursor: log_cursor.close()
        if log_conn and log_conn.is_connected(): log_conn.close()


# --- Flask Routes ---

@app.route('/', methods=['GET'])
def index():
    """Renders the main page: transfer form and account balances."""
    accounts_data = get_accounts_data()
    # Pass accounts data to the template
    return render_template('index.html', accounts=accounts_data)

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles customer registration and initial account creation."""
    if request.method == 'POST':
        customer_name = request.form.get('customer_name')
        # Basic validation for name
        if not customer_name or len(customer_name.strip()) < 2:
            flash("Please enter a valid customer name (at least 2 characters).", "error")
            return render_template('register.html')

        conn = get_db_connection()
        if not conn:
            flash("Database connection error. Cannot register.", "error")
            return render_template('register.html')

        cursor = None
        try:
            cursor = conn.cursor()
            conn.start_transaction() # Begin transaction

            # Insert new customer
            cursor.execute("INSERT INTO customers (customer_name) VALUES (%s)", (customer_name.strip(),))
            customer_id = cursor.lastrowid
            if not customer_id: raise MySQLError("Failed to get customer ID after insert.")

            # Create associated account with initial balance
            cursor.execute("INSERT INTO accounts (customer_id, balance) VALUES (%s, %s)",
                           (customer_id, str(INITIAL_BALANCE))) # Store Decimal as string
            account_id = cursor.lastrowid
            if not account_id: raise MySQLError("Failed to get account ID after insert.")

            conn.commit() # Commit transaction
            flash(f"Customer '{customer_name.strip()}' registered successfully! New Account ID: {account_id} with Balance: ₹{INITIAL_BALANCE:.2f}", "success")
            print(f"Registered Customer ID: {customer_id}, Account ID: {account_id}")
            return redirect(url_for('index')) # Redirect to main page

        except MySQLError as e:
            if conn.is_connected(): conn.rollback() # Rollback on error
            print(f"Database error during registration: {e}")
            flash(f"Registration failed due to a database error. Please try again.", "error")
            # Return to registration form on error
            return render_template('register.html')
        finally:
            # Ensure resources are closed
            if cursor: cursor.close()
            if conn and conn.is_connected(): conn.close()

    # GET request: Just show the registration form
    return render_template('register.html')


@app.route('/transfer', methods=['POST'])
def transfer_funds():
    """Handles fund transfer request, validation, QKD, logging, and balance updates."""
    # --- Get Form Data ---
    sender_id_str = request.form.get('sender_account_id')
    receiver_id_str = request.form.get('receiver_account_id')
    amount_str = request.form.get('amount')
    simulate_eve_checked = 'simulate_eve' in request.form

    # --- Input Validation ---
    error_occurred = False; sender_id = None; receiver_id = None; amount = None
    try:
        # Validate account IDs are integers
        sender_id = int(sender_id_str) if sender_id_str else None
        receiver_id = int(receiver_id_str) if receiver_id_str else None
        if not sender_id or not receiver_id: raise ValueError("Account IDs required")
        if sender_id == receiver_id: raise ValueError("Sender/Receiver accounts same")

        # Validate amount is a positive Decimal
        amount = Decimal(amount_str.strip())
        if amount <= 0: raise ValueError("Amount must be positive")

    except (TypeError, ValueError, InvalidOperation) as e:
        # Provide specific user feedback based on validation error
        if str(e) == "Sender/Receiver accounts same": flash(str(e), "error")
        elif str(e) == "Amount must be positive": flash("Transfer amount must be positive.", "error")
        elif str(e) == "Account IDs required": flash("Please select both sender and receiver accounts.", "error")
        else: flash(f"Invalid input format provided.", "error") # General error for other cases
        print(f"Input validation error: {e}")
        error_occurred = True

    if error_occurred:
        # If validation fails, redisplay form with current account data and error message
        accounts_data = get_accounts_data()
        return render_template('index.html', accounts=accounts_data)

    print(f"\n--- Starting Transfer Request ---")
    print(f"Attempting transfer: {amount:.2f} from Account ID {sender_id} to Account ID {receiver_id}")
    if simulate_eve_checked: print("*** EVE SIMULATION ENABLED ***")

    # --- Initialize variables for workflow ---
    transfer_successful = False
    qkd_status = "PENDING"; encrypted_confirmation = None; iv = None; qber = None
    final_key_bits = None; log_qber_value = None;
    render_context = {} # Dictionary to pass results back to template

    conn = None; cursor = None # Initialize DB resources

    # --- Main Transaction Block ---
    try:
        conn = get_db_connection()
        if not conn: raise ConnectionError("Database connection failed") # Abort if no connection
        # Use dictionary cursor for easier row access by column name
        cursor = conn.cursor(dictionary=True, buffered=True) # Buffered might be needed for multiple SELECTs before UPDATE
        conn.start_transaction() # Start MySQL transaction

        # --- Pre-Transfer DB Validation (within transaction) ---
        # Fetch sender details & lock row using FOR UPDATE (Requires InnoDB)
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_row = cursor.fetchone()
        if not sender_row: raise ValueError(f"Sender account {sender_id} not found.")
        sender_balance = Decimal(sender_row['balance'])

        # Fetch receiver details (just check existence)
        cursor.execute("SELECT account_id FROM accounts WHERE account_id = %s", (receiver_id,))
        receiver_row = cursor.fetchone()
        if not receiver_row: raise ValueError(f"Receiver account {receiver_id} not found.")

        # Check sufficient funds
        if sender_balance < amount:
             raise ValueError(f"Insufficient funds in sender account {sender_id}. Balance: {sender_balance:.2f}")

        # --- QKD Simulation & Security Check ---
        print(f"Running QKD simulation with {QKD_NUM_QUBITS} qubits...")
        final_key_bits, qber = simulate_bb84(n_qubits=QKD_NUM_QUBITS, simulate_eve=simulate_eve_checked)
        log_qber_value = qber if qber != -1.0 else None
        render_context["qber_val"] = f"{qber:.3f}" if qber != -1.0 else "Calc Fail"

        # Check QBER calculation result
        if qber == -1.0:
            qkd_status = "QBER_CALC_FAIL";
            raise ValueError("QKD failed (QBER calculation error)") # Abort transaction
        # Check QBER threshold
        if qber > QBER_THRESHOLD:
            qkd_status = "QBER_THRESHOLD_EXCEEDED";
            raise ValueError(f"High QKD Error Rate Detected (QBER = {qber*100:.1f}%)") # Abort transaction
        # Check final key length
        required_bits = AES_KEY_SIZE_BYTES * 8
        if final_key_bits is None or len(final_key_bits) < required_bits:
            qkd_status = "KEY_LENGTH_FAIL";
            key_len = len(final_key_bits) if final_key_bits is not None else 0
            raise ValueError(f"QKD Error (Final key too short: got {key_len}, need {required_bits})") # Abort transaction

        # --- QKD Success: Prepare & Encrypt Confirmation Log Entry ---
        print(f"QKD successful (QBER={qber:.4f}). Preparing secure log...")
        key_bits_for_aes = final_key_bits[:required_bits]
        key_int = int(''.join(map(str, key_bits_for_aes)), 2)
        key_bytes = key_int.to_bytes(AES_KEY_SIZE_BYTES, byteorder='big')

        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        confirmation_msg = f"CONFIRMED_TRANSFER;FROM:{sender_id};TO:{receiver_id};AMOUNT:{amount:.2f};TIME:{timestamp_now};QBER:{qber:.4f}"
        plaintext_bytes = confirmation_msg.encode('utf-8')
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        encrypted_confirmation = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        qkd_status = "SECURED" # Mark as secured since encryption successful
        print(f"Confirmation message encrypted.")

        # Add crypto details to render context for display on success
        render_context['key_hex'] = key_bytes.hex(); render_context['iv_hex'] = iv.hex()
        render_context['encrypted_hex'] = encrypted_confirmation.hex()
        # Perform decryption verification (for demo display)
        try:
             decipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
             dec_bytes = unpad(decipher.decrypt(encrypted_confirmation), AES.block_size)
             render_context['decrypted_text'] = dec_bytes.decode('utf-8')
             print("Decryption verification successful.")
        except Exception as dec_err: render_context['decrypted_text'] = f"Decryption Failed: {dec_err}"; print(f"Error: {dec_err}")

        # --- Perform Balance Update ---
        print("Updating account balances...")
        new_sender_balance = sender_balance - amount
        # Fetch receiver balance again inside transaction (less crucial with row lock, but safe)
        cursor.execute("SELECT balance FROM accounts WHERE account_id = %s FOR UPDATE", (receiver_id,))
        new_receiver_balance = Decimal(cursor.fetchone()['balance']) + amount
        # Update balances using %s placeholders
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_sender_balance), sender_id))
        cursor.execute("UPDATE accounts SET balance = %s WHERE account_id = %s", (str(new_receiver_balance), receiver_id))
        print(f"Balances updated: Sender={new_sender_balance:.2f}, Receiver={new_receiver_balance:.2f}")
        transfer_successful = True # Mark transfer as successful at DB level

        # --- Log the SECURED Transaction ---
        print(f"Logging transaction with final status: {qkd_status}")
        log_sql = """
            INSERT INTO qkd_transaction_log
            (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        # Ensure amount is stored as string for DECIMAL compatibility if needed
        log_values = (sender_id, receiver_id, str(amount), qkd_status, encrypted_confirmation, iv, log_qber_value)
        cursor.execute(log_sql, log_values)

        # --- Commit Transaction ---
        conn.commit() # Commit balance update + log together atomically
        print("Database transaction committed.")
        flash(f"Transfer successful! Log entry secured via QKD (QBER: {qber:.3f}).", "success")
        render_context['transfer_status'] = "Success"

    except (MySQLError, ValueError, InvalidOperation, ConnectionError) as e:
        # Handle all errors that should cause a rollback and failure message
        if conn and conn.is_connected():
            try:
                conn.rollback()
                print(f"Database transaction rolled back due to error: {e}")
            except MySQLError as rb_err:
                print(f"Error during rollback: {rb_err}")

        # Determine failure status based on where the error occurred
        failed_status = qkd_status if qkd_status != "PENDING" else "VALIDATION_FAIL" # Default if error was pre-QKD

        # Flash appropriate error message to user
        # Check if the error is a ValueError we raised with a specific message
        if isinstance(e, ValueError):
             flash(f"Transaction Failed: {e}", "error") # Show specific reason (Insufficient funds, QBER fail etc)
        elif isinstance(e, ConnectionError):
            flash("Database Connection Error. Please try again later.", "error")
        else: # General DB or other error
            flash(f"Transaction Failed due to an unexpected error. Please contact support.", "error")
            print(f"Unexpected error details: {e}") # Log the full error server-side

        transfer_successful = False
        render_context['transfer_status'] = "Failed"
        # Reflect QKD status if it reached that point before failing
        render_context['qkd_status'] = failed_status

        # Log the failed attempt (outside the rolled-back transaction)
        log_failed_attempt(sender_id, receiver_id, amount, failed_status, log_qber_value)

    finally:
        # Ensure cursor and connection are closed
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

    # --- Render results page ---
    accounts_data = get_accounts_data() # Fetch updated balances for display
    render_context["accounts"] = accounts_data
    return render_template('index.html', **render_context)


# --- Route to view stored transaction log ---
@app.route('/history', methods=['GET'])
def history():
    """Displays the history from the QKD transaction log using MySQL."""
    log_entries = []
    conn = get_db_connection()
    if not conn:
         flash("Database connection error loading history.", "error")
         return render_template('history.html', log_entries=[]) # Return empty list

    cursor = None
    display_log = [] # Initialize list to store processed log entries
    try:
        cursor = conn.cursor(dictionary=True)
        # Join with customer names for better readability
        sql = """
            SELECT
                l.log_id, l.timestamp,
                s_acc.account_id AS sender_acc_id, s_cust.customer_name AS sender_name,
                r_acc.account_id AS receiver_acc_id, r_cust.customer_name AS receiver_name,
                l.amount, l.qkd_status, l.qber_value,
                l.encrypted_confirmation, l.iv
            FROM qkd_transaction_log l
            LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
            LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
            LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
            LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
            ORDER BY l.timestamp DESC
            LIMIT 100
        """ # Added LIMIT for performance on potentially large logs
        cursor.execute(sql)
        log_entries_raw = cursor.fetchall()

        # Process for display (handle None values, format hex/decimal)
        for entry in log_entries_raw:
            try:
                # Use Decimal for amount formatting
                amount_decimal = Decimal(entry['amount']) if entry['amount'] is not None else Decimal('0.00')
                qber_formatted = f"{entry['qber_value']:.3f}" if entry['qber_value'] is not None else "N/A"
                # Check type before calling .hex()
                encrypted_hex = entry['encrypted_confirmation'].hex() if isinstance(entry['encrypted_confirmation'], (bytes, bytearray)) else "N/A"
                iv_hex = entry['iv'].hex() if isinstance(entry['iv'], (bytes, bytearray)) else "N/A"

                display_log.append({
                    'id': entry['log_id'],
                    'timestamp': entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if entry['timestamp'] else 'N/A', # Format timestamp
                    'sender': f"{entry['sender_name'] or 'Unknown/Deleted'} (Acc: {entry['sender_acc_id'] or 'N/A'})",
                    'receiver': f"{entry['receiver_name'] or 'Unknown/Deleted'} (Acc: {entry['receiver_acc_id'] or 'N/A'})",
                    'amount': f"{amount_decimal:.2f}", # Format amount
                    'qkd_status': entry['qkd_status'],
                    'qber': qber_formatted,
                    'encrypted_hex': encrypted_hex,
                    'iv_hex': iv_hex
                })
            except Exception as display_err:
                 # Log error and add a placeholder entry for robustness
                 print(f"Error formatting log entry {entry.get('log_id', 'N/A')} for display: {display_err}")
                 display_log.append({ 'id': entry.get('log_id', 'N/A'), 'timestamp': entry.get('timestamp', 'N/A'), 'sender': 'Error', 'receiver': 'Error', 'amount': 'Error', 'qkd_status': 'Display Error' })

    except MySQLError as e:
        flash(f"Could not retrieve history: {e}", "error")
        print(f"Error retrieving history: {e}")
        # display_log will remain empty or partially filled if error occurred mid-loop
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()

    return render_template('history.html', log_entries=display_log)


# --- Main execution block ---
if __name__ == '__main__':
    # This block is NOT run when using Waitress/Gunicorn
    # It's primarily for direct execution (`python app.py`) which uses Flask's dev server
    print("Starting Real-Time Banking QKD Flask server (using MySQL)...")
    print("NOTE: This uses Flask's development server. For deployment, use a WSGI server like Waitress.")
    # Optional: Check/add sample data if running directly
    # init_db_check_samples()
    # app.run(host='127.0.0.1', port=5000, debug=True) # Keep commented out for Waitress
