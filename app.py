# QUANTUM-SECURE BANKING SYSTEM (Patent Compliant)
# Main Controller - Handles Routing & UI Only
# Architecture: MVC (Model-View-Controller) with Service Layer

import os
import datetime
import logging
from decimal import Decimal

# --- Flask & Extensions ---
from flask import (Flask, request, render_template, flash, redirect, url_for,
                   session, g, current_app, Response, abort)
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
from config import Config

# --- Modular Architecture Imports ---
from modules.db_engine import DBEngine
from modules.pdf_engine import create_transaction_report, create_qkd_report_pdf
from modules.risk_engine import run_risk_analysis
from services.transaction_service import TransactionService

# --- Initialize Flask App ---
app = Flask(__name__)
app.config.from_object(Config)

# --- Service Layer Initialization ---
db_engine = DBEngine()
tx_service = TransactionService()

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# --- Auth Setup ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Forms Definitions (Restored) ---
# We define these here so the UI can render them properly
try:
    from flask_wtf import FlaskForm
    from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, DecimalField, EmailField
    from wtforms.validators import DataRequired, NumberRange, InputRequired, Email, EqualTo, Length
    WTFORMS_AVAILABLE = True

    class LoginForm(FlaskForm):
        email = EmailField('Email Address', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Sign In')

    class RegistrationForm(FlaskForm):
        customer_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
        email = EmailField('Email Address', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
        confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
        submit = SubmitField('Register Account')

    class TransferForm(FlaskForm):
        receiver_account_id = SelectField('Recipient', validators=[InputRequired()])
        amount = DecimalField('Amount', validators=[InputRequired(), NumberRange(min=0.01)])
        simulate_eve = BooleanField('Simulate Attack')
        submit = SubmitField('Transfer')

except ImportError:
    WTFORMS_AVAILABLE = False
    # Dummy classes to prevent crashes if libs missing
    class LoginForm: pass
    class RegistrationForm: pass
    class TransferForm: pass

# --- Mail Setup ---
try:
    from flask_mail import Mail, Message
    mail = Mail(app)
    MAIL_AVAILABLE = True
except ImportError:
    mail = None
    MAIL_AVAILABLE = False

# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_db_connection():
    return db_engine.get_connection()

def get_cursor(conn):
    if db_engine.mode == 'postgres':
        from psycopg2.extras import RealDictCursor
        return conn.cursor(cursor_factory=RealDictCursor)
    return conn.cursor()

class User(UserMixin):
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = None
    try:
        cur = get_cursor(conn)
        query = "SELECT customer_id, customer_name, email FROM customers WHERE customer_id = %s"
        if db_engine.mode != 'postgres':
            query = query.replace('%s', '?')
            
        cur.execute(query, (user_id,))
        row = cur.fetchone()
        
        if row:
            uid = row['customer_id'] if isinstance(row, dict) else row[0]
            name = row['customer_name'] if isinstance(row, dict) else row[1]
            email = row['email'] if isinstance(row, dict) else row[2]
            user = User(uid, name, email)
    except Exception as e:
        logger.error(f"User load error: {e}")
    finally:
        conn.close()
    return user

# =========================================================
# ROUTES
# =========================================================

@app.route('/')
def home_redirect():
    return redirect(url_for('index')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/health')
def health():
    db_status = db_engine.check_connection()
    response = {
        "status": "healthy" if db_status else "degraded",
        "timestamp": datetime.datetime.now().isoformat(),
        "database": "connected" if db_status else "disconnected"
    }
    return response, (200 if db_status else 503)

@app.route('/index')
@login_required
def index():
    user_id = current_user.id
    conn = get_db_connection()
    user_accounts = []
    receiver_accounts = []
    
    try:
        cur = get_cursor(conn)
        ph = "%s" if db_engine.mode == 'postgres' else "?"
        
        cur.execute(f"SELECT * FROM accounts WHERE customer_id = {ph}", (user_id,))
        rows = cur.fetchall()
        user_accounts = [dict(row) for row in rows]

        cur.execute(f"""SELECT a.account_id, c.customer_name 
                        FROM accounts a JOIN customers c ON a.customer_id = c.customer_id 
                        WHERE a.customer_id != {ph}""", (user_id,))
        r_rows = cur.fetchall()
        receiver_accounts = [dict(row) for row in r_rows]
    except Exception as e:
        logger.error(f"Index DB Error: {e}")
    finally:
        conn.close()

    # Instantiate form for the modal
    form = TransferForm() if WTFORMS_AVAILABLE else None
    if form:
        form.receiver_account_id.choices = [('', 'Select Recipient')] + \
            [(str(r['account_id']), f"{r['customer_name']} (ID: {r['account_id']})") for r in receiver_accounts]

    return render_template('index.html', 
                           user_accounts=user_accounts, 
                           receiver_accounts=receiver_accounts, 
                           transfer_form=form)

@app.route('/transfer-funds', methods=['POST'])
@login_required
def transfer_funds():
    user_id = current_user.id
    
    # Handle Form Data
    if WTFORMS_AVAILABLE:
        # We need to re-populate choices for validation to pass
        form = TransferForm(request.form)
        # Hack to bypass choice validation or re-fetch needed choices
        # For simplicity in this demo, we assume valid input from UI or fallback to request.form
        rx_id = form.receiver_account_id.data
        amount = form.amount.data
        simulate_eve = form.simulate_eve.data
    else:
        rx_id = request.form.get('receiver_account_id')
        amount = request.form.get('amount')
        simulate_eve = 'simulate_eve' in request.form
    
    if not rx_id or not amount:
        flash("Invalid parameters.", "error")
        return redirect(url_for('index'))

    try:
        success, msg, logs = tx_service.process_secure_transfer(
            sender_id=user_id,
            receiver_id=int(rx_id),
            amount=Decimal(amount),
            simulate_eve=simulate_eve
        )
        
        session[f'last_qkd_log_{user_id}'] = logs.get('qkd')
        
        if success:
            flash(f"SUCCESS: {msg}", "success")
        else:
            if "QKD COMPROMISED" in msg:
                flash(f"SECURITY ALERT: {msg}", "error")
            elif "Fraud" in msg:
                flash(f"FRAUD BLOCKED: {msg}", "warning")
            else:
                flash(f"Failed: {msg}", "error")

    except Exception as e:
        logger.error(f"Transfer Error: {e}")
        flash("System Error during secure transfer.", "error")

    return redirect(url_for('index'))

# --- AUTH ROUTES (FIXED FORM PASSING) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() if WTFORMS_AVAILABLE else None
    
    # Handle POST (Login Attempt)
    if request.method == 'POST':
        # Use form.validate_on_submit() if using forms, else manual request.form
        if (form and form.validate_on_submit()) or (not form):
            email = form.email.data if form else request.form.get('email')
            password = form.password.data if form else request.form.get('password')
            
            conn = get_db_connection()
            try:
                cur = get_cursor(conn)
                ph = "%s" if db_engine.mode == 'postgres' else "?"
                cur.execute(f"SELECT * FROM customers WHERE email = {ph}", (email,))
                data = cur.fetchone()
                
                if data:
                    uid = data['customer_id'] if isinstance(data, dict) else data[0]
                    name = data['customer_name'] if isinstance(data, dict) else data[1]
                    p_hash = data['password_hash'] if isinstance(data, dict) else data[3]
                    u_email = data['email'] if isinstance(data, dict) else data[2]

                    if check_password_hash(p_hash, password):
                        user = User(uid, name, u_email)
                        login_user(user)
                        return redirect(url_for('index'))
                
                flash("Invalid credentials.", "error")
            except Exception as e:
                logger.error(f"Login Error: {e}")
                flash("Login failed due to system error.", "error")
            finally:
                conn.close()
    
    # PASS THE FORM TO THE TEMPLATE
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out securely.", "info")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm() if WTFORMS_AVAILABLE else None

    if request.method == 'POST':
        if (form and form.validate_on_submit()) or (not form):
            name = form.customer_name.data if form else request.form.get('customer_name')
            email = form.email.data if form else request.form.get('email')
            password = form.password.data if form else request.form.get('password')
            hashed_pw = generate_password_hash(password)
            
            conn = get_db_connection()
            try:
                cur = conn.cursor()
                ph = "%s" if db_engine.mode == 'postgres' else "?"
                
                if db_engine.mode == 'postgres':
                    cur.execute("INSERT INTO customers (customer_name, email, password_hash) VALUES (%s, %s, %s) RETURNING customer_id", (name, email, hashed_pw))
                    cid = cur.fetchone()[0]
                    cur.execute("INSERT INTO accounts (customer_id, balance, account_number) VALUES (%s, %s, %s)", (cid, 1000.00, str(int(datetime.datetime.now().timestamp()))))
                else:
                    cur.execute("INSERT INTO customers (customer_name, email, password_hash) VALUES (?, ?, ?)", (name, email, hashed_pw))
                    cid = cur.lastrowid
                    cur.execute("INSERT INTO accounts (customer_id, balance, account_number) VALUES (?, ?, ?)", (cid, 1000.00, str(int(datetime.datetime.now().timestamp()))))
                
                conn.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for('login'))
            except Exception as e:
                conn.rollback()
                logger.error(f"Reg Error: {e}")
                flash("Registration failed (Email may exist).", "error")
            finally:
                conn.close()
    
    # PASS THE FORM TO THE TEMPLATE
    return render_template('register.html', form=form)

# --- INFO & MISC ROUTES ---

@app.route('/quantum-impact')
def quantum_impact():
    return render_template("quantum_impact.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/profile')
@login_required
def profile():
    user_id = current_user.id
    conn = get_db_connection()
    account = None
    try:
        cur = get_cursor(conn)
        ph = "%s" if db_engine.mode == 'postgres' else "?"
        cur.execute(f"SELECT * FROM accounts WHERE customer_id = {ph}", (user_id,))
        row = cur.fetchone()
        if row:
            account = dict(row) if isinstance(row, dict) else {'balance': row[2], 'account_number': row[3]}
    except Exception as e:
        logger.error(f"Profile Error: {e}")
    finally:
        conn.close()
    return render_template('profile.html', user=current_user, account=account)

@app.route('/fraud')
@login_required
def fraud_page():
    user_id = current_user.id
    conn = get_db_connection()
    txns = []
    try:
        cur = get_cursor(conn)
        ph = "%s" if db_engine.mode == 'postgres' else "?"
        query = f"""SELECT l.log_id as id, l.timestamp, l.amount, l.fraud_reason 
                    FROM qkd_transaction_log l
                    JOIN accounts s ON l.sender_account_id = s.account_id
                    WHERE s.customer_id = {ph} AND l.is_flagged = {ph}
                    ORDER BY l.timestamp DESC LIMIT 20"""
        
        true_val = True if db_engine.mode == 'postgres' else 1
        cur.execute(query, (user_id, true_val))
        rows = cur.fetchall()
        for r in rows:
            d = dict(r) if isinstance(r, dict) else {'id': r[0], 'timestamp': r[1], 'amount': r[2], 'fraud_reason': r[3]}
            d['amount'] = f"{Decimal(str(d['amount'])):.2f}"
            txns.append(d)
    except Exception as e:
        logger.error(f"Fraud Page Error: {e}")
    finally:
        conn.close()
    return render_template("fraud.html", flagged_txns=txns)

@app.route('/risk-analysis', methods=['GET', 'POST'])
@login_required
def risk_analysis_page():
    results = None
    if request.method == 'POST':
        atype = request.form.get('analysis_type', 'portfolio')
        results = run_risk_analysis(analysis_type=atype)
    return render_template('risk_analysis.html', risk_results=results)

@app.route('/qkd')
@login_required
def qkd_page():
    sim_log = session.get(f'last_qkd_log_{current_user.id}')
    return render_template('qkd.html', 
                           simulation_log=sim_log,
                           QBER_THRESHOLD_PCT=app.config['QBER_THRESHOLD']*100)

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    txns = []
    try:
        cur = get_cursor(conn)
        uid = current_user.id
        ph = "%s" if db_engine.mode == 'postgres' else "?"
        
        query = f"""SELECT l.*, s_c.customer_name as sender, r_c.customer_name as receiver
                   FROM qkd_transaction_log l
                   JOIN accounts s ON l.sender_account_id = s.account_id
                   JOIN customers s_c ON s.customer_id = s_c.customer_id
                   JOIN accounts r ON l.receiver_account_id = r.account_id
                   JOIN customers r_c ON r.customer_id = r_c.customer_id
                   WHERE s.customer_id = {ph} OR r.customer_id = {ph}
                   ORDER BY l.timestamp DESC LIMIT 20"""
        
        cur.execute(query, (uid, uid))
        rows = cur.fetchall()
        for r in rows:
            if isinstance(r, dict):
                txns.append(r)
            else:
                d = {'log_id': r[0], 'amount': r[3], 'qkd_status': r[4], 
                     'is_flagged': r[6], 'timestamp': r[9], 
                     'sender': r[-2], 'receiver': r[-1]}
                txns.append(d)
    except Exception as e:
        logger.error(f"History Error: {e}")
    finally:
        conn.close()
    return render_template('history.html', log_entries=txns)

@app.route('/report/download/<int:log_id>')
@login_required
def download_report(log_id):
    conn = get_db_connection()
    try:
        cur = get_cursor(conn)
        ph = "%s" if db_engine.mode == 'postgres' else "?"
        cur.execute(f"SELECT * FROM qkd_transaction_log WHERE log_id = {ph}", (log_id,))
        txn_data = cur.fetchone()
        if not txn_data: return abort(404)
        
        data_dict = dict(txn_data) if isinstance(txn_data, dict) else {}
        pdf = create_transaction_report(data_dict)
        return Response(pdf, mimetype='application/pdf', 
                        headers={"Content-Disposition": f"attachment;filename=Tx_{log_id}.pdf"})
    except Exception as e:
        logger.error(f"PDF Error: {e}")
        return abort(500)
    finally:
        conn.close()

# --- CONTEXT ---
@app.context_processor
def inject_globals():
    return dict(current_year=datetime.datetime.now().year)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
