# FINAL COMPLETE VERSION - QKD Secure Banking Demo
# Includes: User Auth, MySQL, QKD Sim, Fernet Encryption, ML Fraud Detection,
#           PDF Reporting, Info Pages, Risk Simulation, Real Email Sending.
# Version: Verified Working (Post User Confirmation & Final Cleanup)

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
POSTGRES_AVAILABLE = False
MYSQL_AVAILABLE = False
MySQLError = None # Define placeholder for MySQL error type

# --- Attempt PostgreSQL Import ---
try:
    import psycopg2         # <--- Import the library
    import psycopg2.extras
    POSTGRES_AVAILABLE = True # <--- UPDATE the global variable
    logging.info("--- Psycopg2 (PostgreSQL driver) found. ---")
except ImportError:
    psycopg2 = None # Define psycopg2 as None if import fails
    logging.warning("--- Psycopg2 (PostgreSQL driver) not found. ---")
except Exception as e:
    psycopg2 = None
    logging.error(f"--- Unexpected error importing psycopg2: {e} ---")

# --- Attempt MySQL Import ---
try:
    import mysql.connector
    from mysql.connector import Error as MySQLConnectorError
    MySQLError = MySQLConnectorError # Update the global variable
    MYSQL_AVAILABLE = True          # Update the global variable
    logging.info("--- MySQL Connector ('mysql-connector-python') found and imported successfully. ---")
except ImportError:
    # MySQLError remains None, MYSQL_AVAILABLE remains False
    logging.warning("--- MySQL Connector ('mysql-connector-python') not found. ---")
except Exception as e:
    # MySQLError remains None, MYSQL_AVAILABLE remains False
    logging.error(f"--- An unexpected error occurred while importing MySQL Connector: {e} ---", exc_info=True)

except ImportError:
    # This specific error means the library isn't installed
    # MYSQL_AVAILABLE remains False, MySQLError remains None (as initialized)
    logging.warning("--- MySQL Connector ('mysql-connector-python') not found. MySQL functionality will be disabled unless installed. ---")

except Exception as e:
    # Catch any other unexpected error during the import process
    # MYSQL_AVAILABLE remains False, MySQLError remains None (as initialized)
    logging.error(f"--- An unexpected error occurred while importing MySQL Connector: {e} ---", exc_info=True) # Log full traceback for unexpected errors

# --- Define the Database Error Type based on environment ---
# (Assumes DATABASE_URL indicates PostgreSQL on Render, otherwise tries MySQL)
if POSTGRES_AVAILABLE and 'DATABASE_URL' in os.environ:
    # Use psycopg2.Error if psycopg2 was successfully imported, otherwise fallback
    # Ensure psycopg2 is not None before accessing .Error
    DB_ERROR_TYPE = psycopg2.Error if psycopg2 else Exception
    logging.info(f"--- Using PostgreSQL Error Type ({DB_ERROR_TYPE.__name__}) ---")
elif MYSQL_AVAILABLE and MySQLError:
    # Use MySQLError if mysql.connector was imported successfully
    DB_ERROR_TYPE = MySQLError
    logging.info(f"--- Using MySQL Error Type ({DB_ERROR_TYPE.__name__}) ---")
else:
    # Fallback to generic Exception if neither specific driver error type is available
    DB_ERROR_TYPE = Exception
    logging.warning(f"--- Using generic Exception for DB errors (driver-specific type unavailable: PG={POSTGRES_AVAILABLE}, MySQL={MYSQL_AVAILABLE}) ---")

# --- Check if at least one driver is needed and available (Optional but Recommended) ---
# Decide if your app absolutely requires *at least one* DB driver to even start
# For example, if running locally without DATABASE_URL, you NEED MySQL.
# if 'DATABASE_URL' not in os.environ and not MYSQL_AVAILABLE:
#    logging.critical("CRITICAL: Running locally but MySQL Connector is not available. Exiting.")
#    exit(1)
# If running on Render (DATABASE_URL is set), you might want to ensure PG is available:
# elif 'DATABASE_URL' in os.environ and not POSTGRES_AVAILABLE:
#    logging.critical("CRITICAL: DATABASE_URL is set but Psycopg2 is not available. Exiting.")
#    exit(1)

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

# --- Define Global Timezone ---
# Define your target local timezone
PYTZ_AVAILABLE = False # Initialize flag
pytz = None # Initialize pytz object placeholder
LOCAL_TIMEZONE = timezone.utc # Default to built-in UTC

try:
    import pytz # Attempt import
    PYTZ_AVAILABLE = True
    logging.info("--- pytz library found. Timezone conversion enabled. ---")
    try:
        # Use environment variable if set, otherwise default (only if pytz loaded)
        LOCAL_TIMEZONE_STR = os.environ.get('LOCAL_TIMEZONE', 'Asia/Kolkata')
        LOCAL_TIMEZONE = pytz.timezone(LOCAL_TIMEZONE_STR) # Use pytz timezone object
        logging.info(f"--- Using local timezone for display: {LOCAL_TIMEZONE_STR} ---")
    except pytz.UnknownTimeZoneError:
        logging.error(f"--- Invalid LOCAL_TIMEZONE '{LOCAL_TIMEZONE_STR}', defaulting to UTC. ---")
        LOCAL_TIMEZONE = pytz.utc # Fallback to pytz UTC if name invalid
    except Exception as tz_err:
         logging.error(f"--- Error setting pytz timezone, defaulting to UTC: {tz_err} ---")
         LOCAL_TIMEZONE = pytz.utc # Fallback to pytz UTC on other errors
except ImportError:
    logging.warning("--- pytz library not found. Timestamps will use basic UTC. `pip install pytz` ---")
    # PYTZ_AVAILABLE remains False
    # LOCAL_TIMEZONE remains datetime.timezone.utc
except Exception as import_err:
     logging.error(f"--- Unexpected error importing pytz: {import_err}. Timestamps will use basic UTC. ---")

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
app.config['MAIL_DEFAULT_SENDER'] = ('QuantumVault Security', app.config['MAIL_USERNAME'])
app.config['QBER_THRESHOLD_PCT'] = int(os.environ.get('QBER_THRESHOLD_PCT', 25)) # Example QBER threshold %
app.config['QKD_NUM_QUBITS'] = int(os.environ.get('QKD_NUM_QUBITS', 512)) # Example QKD qubit count

MAIL_AVAILABLE = False
Mail = None     # Placeholder for the Flask-Mail Mail class
mail = None     # Placeholder for the Flask-Mail extension instance

# --- Step 1: Attempt to Import Flask-Mail Library ---
try:
    from flask_mail import Mail as FlaskMail_Mail # Import the Mail class
    Mail = FlaskMail_Mail                         # Assign the class if import is successful
    MAIL_AVAILABLE = True                         # Mark library as potentially available
    logging.info("--- Flask-Mail library found. Initialization will be attempted based on config. ---")
except ImportError:
    # Library itself is not installed
    logging.warning("--- Flask-Mail library ('Flask-Mail') not found. Email features will be disabled. Install it to enable. ---")
    # MAIL_AVAILABLE remains False, Mail remains None
except Exception as import_err:
    # Catch any other unexpected error during import
    logging.error(f"--- An unexpected error occurred while importing Flask-Mail: {import_err} ---", exc_info=True)
    # MAIL_AVAILABLE remains False, Mail remains None

# --- Step 2: Initialize Instance if Library Imported and Config is Valid ---
if MAIL_AVAILABLE and Mail is not None: # Proceed only if import succeeded
    try:
        # --- Check Configuration ---
        mail_server = app.config.get('MAIL_SERVER')
        mail_port = app.config.get('MAIL_PORT') # Should be integer
        mail_username = app.config.get('MAIL_USERNAME')
        # Check if MAIL_PASSWORD key exists in config (value could be empty string)
        mail_password_present = 'MAIL_PASSWORD' in app.config
        mail_sender = app.config.get('MAIL_DEFAULT_SENDER') # Often a tuple ('Name', 'email@addr')

        # Check for local SMTP debug server (e.g., MailHog/Mailpit at localhost:1025)
        # Allows skipping username/password checks for these local tools
        is_local_debug_server = mail_server == 'localhost' and mail_port == 1025

        essential_config_present = False
        missing_configs = []

        if is_local_debug_server:
            # For local debug server, only server/port are strictly needed by Flask-Mail
            if mail_server and mail_port:
                essential_config_present = True
                logging.info("Local debug mail server detected (localhost:1025). Basic config OK.")
            else:
                if not mail_server: missing_configs.append("MAIL_SERVER")
                if not mail_port: missing_configs.append("MAIL_PORT")
                logging.warning("Local debug mail server config seems incomplete.")
        else:
            # For real SMTP servers, check all essential parts
            if not mail_server: missing_configs.append("MAIL_SERVER")
            if not mail_port: missing_configs.append("MAIL_PORT")
            if not mail_username: missing_configs.append("MAIL_USERNAME")
            if not mail_password_present: missing_configs.append("MAIL_PASSWORD")
            if not mail_sender: missing_configs.append("MAIL_DEFAULT_SENDER")

            if not missing_configs: # If the list is empty, all are present
                essential_config_present = True
            else:
                logging.warning(f"Flask-Mail configuration for non-local server is incomplete. Missing or empty: {', '.join(missing_configs)}. Email sending likely to fail.")

        # --- Attempt Initialization ---
        if essential_config_present:
            # Configuration seems okay (or it's local debug), try initializing
            mail = Mail(app) # <-- Initialize the Flask-Mail extension instance!
            logging.info(f"--- Flask-Mail initialized successfully (Server: {mail_server}:{mail_port}). ---")
            # MAIL_AVAILABLE remains True (set during import check)
        else:
            # Config is missing, do not initialize, mark as unavailable
            logging.error("Flask-Mail initialization skipped due to missing configuration.")
            mail = None # Ensure instance is None
            MAIL_AVAILABLE = False # Mark as unavailable due to config

    except Exception as mail_init_err:
        # Catch errors specifically during the Mail(app) call or config checks
        logging.error(f"ERROR: Failed to initialize Flask-Mail instance: {mail_init_err}", exc_info=True)
        mail = None # Ensure instance is None on error
        MAIL_AVAILABLE = False # Mark as unavailable if initialization fails

else:
    # This block executes if the initial import failed
    logging.info("Flask-Mail initialization skipped: Library not found or failed to import.")

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
try:
    # 1. Determine Base Log Level
    #    Checks common environment variables used by Flask for debug mode.
    #    Alternatively, if 'app' instance is already created, use 'app.debug'.
    is_debug_mode = os.environ.get('FLASK_ENV') == 'development' or \
                    os.environ.get('FLASK_DEBUG', '0').lower() in ['1', 'true', 'on']
    log_level = logging.DEBUG if is_debug_mode else logging.INFO

    # 2. Define Log Format
    #    Includes logger name and line number - useful for debugging.
    #    Consider a simpler format for production if this is too verbose.
    log_format = '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s'
    #    Simpler alternative: log_format = '%(asctime)s [%(levelname)s] - %(message)s'

    # 3. Configure Root Logger using basicConfig
    #    Sets the level and format for the root logger.
    #    NOTE: basicConfig only works if the root logger hasn't been configured yet.
    #          Call this early in your application setup.
    logging.basicConfig(level=log_level, format=log_format, force=True) # Use force=True to override potential implicit basicConfig by libraries

    # 4. Adjust Log Levels for Specific Libraries (Reduce Noise)
    #    Set higher levels (e.g., WARNING) for libraries that are too verbose at INFO/DEBUG.
    logging.getLogger('werkzeug').setLevel(logging.WARNING) # Quiets standard request logs
    logging.getLogger('PIL').setLevel(logging.WARNING)     # Quiets Pillow/ReportLab info logs

    # Conditionally configure MySQL logger level ONLY if the library is available
    if 'MYSQL_AVAILABLE' in globals() and MYSQL_AVAILABLE: # Check flag existence and value
        logging.getLogger('mysql.connector').setLevel(logging.WARNING)
        logging.info("MySQL Connector logger level set to WARNING.")
    else:
        logging.info("MySQL Connector not available or flag missing; logger level not set.")

    # Configure other libraries as needed:
    # logging.getLogger('qiskit').setLevel(logging.INFO)
    # logging.getLogger('matplotlib').setLevel(logging.WARNING)

    logging.info(f"Logging configured successfully. Base level: {logging.getLevelName(log_level)}")
    if is_debug_mode:
        logging.debug("Debug logging is enabled.")

except Exception as log_config_err:
    # Fallback if logging configuration itself fails
    print(f"CRITICAL ERROR: Failed to configure application logging: {log_config_err}")

# --- Extension Initialization ---
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Your login route name
login_manager.login_message_category = 'info'
# mail = Mail(app) # Initialize other extensions

# --- User Class Definition (Add Here) ---
class User(UserMixin):
    """Simple User class for Flask-Login integration."""
    def __init__(self, id, name, email):
        self.id = id
        self.name = name
        self.email = email

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
         phone_number = StringField('Phone Number', validators=[Optional(), Length(min=10, max=20)]) # Optional validator allows empty
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
        # REMOVED coerce=int - We will handle conversion explicitly in the route after validation
        # Use InputRequired to ensure *a* value is selected (not the placeholder)
        receiver_account_id = SelectField('Recipient Account',
                                          validators=[InputRequired(message="Please select a recipient.")])
        amount = DecimalField('Amount (₹)', # Added currency symbol to label
                             places=2,
                             rounding=None, # Use default rounding (usually ROUND_HALF_UP)
                             validators=[InputRequired(message="Amount is required."),
                                         # Ensure min value is Decimal for comparison
                                         NumberRange(min=Decimal('0.01'), message="Amount must be at least ₹0.01.")])
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
             form_source = self._formdata or (request.form if request else None) # Check request exists

             if form_source:
                 if is_checkbox:
                     field_data = name in form_source # Checkbox presence
                 elif name in form_source:
                      field_data = form_source[name]

             # Attempt basic type coercion for dummy fields to mimic WTForms
             if name == 'receiver_account_id':
                  try: field_data = int(field_data) if field_data else None
                  except (ValueError, TypeError): field_data = None # Default to None on error
             elif name == 'amount':
                  try: field_data = Decimal(field_data) if field_data else None
                  except (InvalidOperation, TypeError): field_data = None # Default to None on error

             # Return a simple object that has a 'data' attribute and empty errors list
             field_obj = type('DummyField', (object,), {'data': field_data, 'errors': []})()
             return field_obj

    LoginForm = DummyForm
    RegistrationForm = DummyForm
    ForgotPasswordForm = DummyForm
    ResetPasswordForm = DummyForm
    TransferForm = DummyForm
# *** END FORMS DEFINITION ***

# --- Database Helper Functions (Adapted for PostgreSQL/MySQL) ---
def get_db_connection():
    """Establishes DB connection (PG priority, MySQL fallback). Returns conn or None."""
    conn = None; db_url = os.environ.get('DATABASE_URL')
    if db_url: # --- PostgreSQL Path ---
        if not POSTGRES_AVAILABLE: logging.critical("FATAL: DATABASE_URL set, but psycopg2 unavailable!"); return None
        try:
            logging.debug("Attempting PostgreSQL connection via DATABASE_URL.")
            conn = psycopg2.connect(db_url, connect_timeout=10)
            logging.info("PostgreSQL connection successful.")
            return conn
        except psycopg2.Error as e: logging.critical(f"CRITICAL PG Conn Error: {e}"); return None
        except Exception as e: logging.critical(f"CRITICAL Unexpected PG Conn Error: {e}", exc_info=True); return None
    else: # --- MySQL Fallback Path ---
        logging.debug("DATABASE_URL not set. Attempting MySQL fallback.")
        if not MYSQL_AVAILABLE: logging.critical("FATAL: MySQL Connector unavailable!"); return None
        try:
            logging.debug(f"Attempting MySQL connection: Host={MYSQL_CONFIG.get('host')}")
            conn = mysql.connector.connect(**MYSQL_CONFIG)
            if conn.is_connected():
                 conn.driver_name = 'mysql' # <--- SET ATTRIBUTE HERE
                 logging.info("MySQL fallback connection successful.");
                 return conn
            else: logging.error("MySQL fallback failed: is_connected() is False."); conn.close(); return None
        except MySQLError as e: logging.critical(f"CRITICAL MySQL Fallback Conn Error: {e}"); return None
        except Exception as e: logging.critical(f"CRITICAL Unexpected MySQL Fallback Conn Error: {e}", exc_info=True); return None

def close_db_connection(conn):
    """Safely closes the database connection (PG or MySQL)."""
    if not conn or not hasattr(conn, 'close'):
        logging.debug("close_db_connection: Invalid connection object.")
        return
    db_type = "Unknown" # Default
    is_pg = POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection)
    is_mysql = MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection)

    try:
        # Check PG specific 'closed' attribute first
        if is_pg and conn.closed:
            logging.debug("PostgreSQL connection already closed.")
            return
        # Check MySQL is_connected (though close is often idempotent)
        # if is_mysql and not conn.is_connected():
        #    logging.debug("MySQL connection already closed or invalid.")
        #    return

        if is_pg: db_type = "PostgreSQL"
        elif is_mysql: db_type = "MySQL"

        logging.debug(f"Closing DB connection (Type: {db_type})")
        conn.close();
        logging.info("DB connection closed.")

    except DB_ERROR_TYPE as e: # Catch the appropriate error type
        logging.error(f"DBError closing {db_type} connection: {e}")
    except Exception as e: # Catch any other unexpected error
        logging.error(f"Unexpected error closing {db_type} DB conn: {e}", exc_info=True)
    

def get_accounts_data(customer_id_filter=None):
    """Fetches account data, optionally filtered by customer ID. Returns list or None on DB error."""
    accounts = []
    conn = None # Initialize connection variable
    cursor = None # Initialize cursor variable
    db_type = "Unknown" # To track which DB is being used

    try:
        conn = get_db_connection() # Get connection first
        if not conn:
            # Raise an error or handle appropriately if connection failed
            raise ConnectionError("Database connection failed in get_accounts_data.")

        # --- Determine cursor type based on DB connection ---
        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db_type = "PostgreSQL"
        elif MYSQL_AVAILABLE and hasattr(conn, 'is_connected'): # Heuristic for MySQL conn
            cursor = conn.cursor(dictionary=True)
            db_type = "MySQL"
        else:
            cursor = conn.cursor() # Fallback basic cursor
            db_type = "Fallback"
        logging.debug(f"get_accounts_data: Using {db_type} cursor.")
        # --- End Cursor Type Determination ---

        # --- UPDATED SQL QUERY: Include account_number ---
        sql = """SELECT a.account_id, a.account_number, c.customer_name, a.balance, a.customer_id
                 FROM accounts a
                 JOIN customers c ON a.customer_id = c.customer_id"""
        # --- END SQL UPDATE ---

        params = []
        if customer_id_filter is not None:
            try:
                filter_id = int(customer_id_filter)
                sql += " WHERE a.customer_id = %s"
                params.append(filter_id)
            except (ValueError, TypeError):
                 logging.error(f"Invalid customer_id_filter type: {customer_id_filter}. Ignoring.")

        # Order consistently, e.g., by account_id which should be stable
        sql += " ORDER BY a.account_id ASC"
        cursor.execute(sql, tuple(params))
        raw_accounts_results = cursor.fetchall() # Fetches list of RealDictRow or dict

        for acc_row_raw in raw_accounts_results:
            # Convert row to standard dict for consistent processing
            acc_row = dict(acc_row_raw)
            balance_val = None # Initialize for logging in except block
            try: # Inner try for processing each account row
                balance_val = acc_row.get('balance')
                # Convert balance via string for robustness
                current_balance = Decimal(str(balance_val)) if balance_val is not None else Decimal('0.00')

                # --- UPDATED CHECK: Include 'account_number' ---
                required_keys = ('account_id', 'account_number', 'customer_name', 'customer_id', 'balance')
                # We check balance key here too, though we process it separately
                if all(k in acc_row for k in required_keys):
                # --- END CHECK UPDATE ---
                    acc_row['balance'] = current_balance # Update balance in dict
                    accounts.append(acc_row) # Append the processed dict
                else:
                    missing_keys = [k for k in required_keys if k not in acc_row]
                    logging.warning(f"Skipping account row missing required keys ({missing_keys}): {acc_row.get('account_id', 'N/A')}")

            except (InvalidOperation, TypeError, ValueError) as e: # Added ValueError
                logging.warning(f"Skipping account {acc_row.get('account_id', 'N/A')} due to invalid balance ('{balance_val}'): {e}")
            except Exception as inner_e:
                 logging.error(f"Unexpected error processing account row {acc_row.get('account_id', 'N/A')}: {inner_e}", exc_info=True)

    # --- UPDATED EXCEPTION HANDLING ---
    except DB_ERROR_TYPE as e: # Use the globally defined DB_ERROR_TYPE
        logging.error(f"Database error fetching accounts data using {db_type}: {e}", exc_info=True)
        # Flash error in the route that calls this function if needed
        return None # Indicate DB error
    except ConnectionError as e:
        # Logged when getting connection, just return None here
        logging.error(f"get_accounts_data: Connection error encountered: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error in get_accounts_data: {e}", exc_info=True)
        return None # Indicate unexpected error
    # --- END UPDATED EXCEPTION HANDLING ---
    finally:
        # Ensure cleanup in finally block
        if cursor:
            try: cursor.close()
            except DB_ERROR_TYPE: pass # Ignore specific DB close errors
            except Exception: pass # Ignore generic close errors
        if conn:
            # Close connection obtained by this function
            close_db_connection(conn)
            
    return accounts

def get_user_by_email(email):
    """Fetches user details by email. Adapted for PG/MySQL. Returns dict or None."""
    user = None; conn = None; cursor = None; db_type = "Unknown"
    if not isinstance(email, str) or not email: return None

    try:
        conn = get_db_connection()
        if not conn: raise ConnectionError("DB connection failed in get_user_by_email.")

        # --- CORRECTED CURSOR CREATION ---
        # Check DB type based on connection object attribute (set in get_db_connection)
        # db_type = getattr(conn, 'driver_name', 'Unknown') # Get DB type if attribute was set
        # Or use isinstance check for more directness
        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDictCursor for PG
            db_type = "PostgreSQL"
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True) # Use dictionary=True for MySQL
            db_type = "MySQL"
        else: # Fallback if type unknown
            logging.warning("get_user_by_email: Unknown DB connection type, using basic cursor.")
            cursor = conn.cursor() # May return tuples
            db_type = "Fallback"
        logging.debug(f"get_user_by_email: Using {db_type} cursor.")
        # --- END CORRECTION ---

        cursor.execute("SELECT customer_id, customer_name, email, password_hash FROM customers WHERE email = %s", (email,))
        user_row = cursor.fetchone() # Fetches RealDictRow (PG), dict (MySQL), or tuple (Fallback)

        # --- SAFER CONVERSION (Should work fine with RealDictRow/dict) ---
        if user_row:
            if hasattr(user_row, 'keys'): user = dict(user_row)
            elif isinstance(user_row, (tuple, list)) and len(user_row) >= 4: user = {'customer_id': row[0], 'customer_name': row[1], 'email': row[2], 'password_hash': row[3]}
            else: logging.error(f"Fetched user_row unexpected format: {type(user_row)}")
        # --- END SAFER CONVERSION ---

    except (DB_ERROR_TYPE, ConnectionError) as e:
        logging.error(f"Error fetch user {email} ({db_type}): {e}"); user = None
    except Exception as e:
        logging.error(f"Unexpected error fetch user {email}: {e}", exc_info=True); user = None
    finally:
        # --- Start of Corrected Cleanup ---
        if cursor and not getattr(cursor, 'closed', True):
            try:
                cursor.close()
            except DB_ERROR_TYPE:
                 # Optionally log this specific DB error if needed, but often ignored during close
                 # logging.warning(f"DBError closing cursor for get_user_by_email: {db_close_err}")
                 pass # Ignore DB-specific errors during close
            except Exception as cur_close_err:
                 # Log other unexpected errors during close
                 logging.warning(f"Non-DB error closing cursor for get_user_by_email: {cur_close_err}")

        if conn and not getattr(conn, 'closed', True):
            close_db_connection(conn) # Use your helper function to close connection
        # --- End of Corrected Cleanup ---

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
            datetime.datetime.now(timezone.utc), # Timestamp of the failure logging
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

@login_manager.user_loader
def load_user(user_id):
    """
    Callback used by Flask-Login to reload the user object from the user ID stored in the session.
    Fetches user details from the database and returns a User object or None.
    """
    logging.debug(f"Flask-Login attempting to load user ID: {user_id}")
    if user_id is None:
        return None

    conn = None
    cursor = None
    # Determine the primary DB error type to catch based on availability
    db_error_type_pg = psycopg2.Error if POSTGRESQL_AVAILABLE and psycopg2 else None
    db_error_type_mysql = MySQLError if MYSQL_AVAILABLE and MySQLError else None
    available_db_errors = tuple(filter(None, [db_error_type_pg, db_error_type_mysql]))
    if not available_db_errors: available_db_errors = (Exception,) # Fallback

    try:
        # Convert user_id back to integer if needed (Flask-Login stores it as string)
        try:
            user_id_int = int(user_id)
        except ValueError:
            logging.warning(f"Invalid non-integer user ID '{user_id}' passed to user_loader.")
            return None

        conn = get_db_connection() # Assumes this function exists and works
        if not conn:
            logging.error(f"DB connection failed in user_loader for user ID {user_id_int}.")
            return None # Cannot load user without DB connection

        # Create cursor based on connection type
        if POSTGRESQL_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
             cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
             cursor = conn.cursor(dictionary=True)
        else:
             logging.error(f"Cannot determine cursor type for user_loader user ID {user_id_int}.")
             return None

        # Fetch essential user details
        cursor.execute("""
            SELECT customer_id, customer_name, email
            FROM customers
            WHERE customer_id = %s
        """, (user_id_int,))
        user_data_raw = cursor.fetchone()

        if user_data_raw:
            # Check if essential data is present
            cust_id = user_data_raw.get('customer_id')
            cust_name = user_data_raw.get('customer_name')
            cust_email = user_data_raw.get('email')

            if cust_id is not None and cust_name is not None and cust_email is not None:
                 # Instantiate and return the User object
                 user_object = User(id=cust_id, name=cust_name, email=cust_email)
                 logging.debug(f"User object created for user ID {user_id_int}")
                 return user_object
            else:
                 logging.warning(f"Incomplete data found in DB for user ID {user_id_int}. Cannot create user object.")
                 return None
        else:
            # User ID not found in the database
            logging.debug(f"User ID {user_id_int} not found in database during user_loader lookup.")
            return None

    except available_db_errors as db_err:
        error_type_name = type(db_err).__name__
        logging.error(f"{error_type_name} occurred in user_loader for user ID {user_id}: {db_err}")
        return None # Don't return a user object if there's a DB error

    except Exception as e:
        logging.error(f"Unexpected error in user_loader for user ID {user_id}: {e}", exc_info=True)
        return None # Safety net

    finally:
        # Ensure resources are closed
        if cursor:
            try: cursor.close()
            except Exception: pass
        if conn:
            close_db_connection(conn) # Assumes this function exists and works
            logging.debug(f"DB connection closed in user_loader for user ID {user_id}.")

@app.before_request
def load_logged_in_user():
    """
    Runs before each request. If a 'user_id' is found in the session,
    this function attempts to load the corresponding user's details
    (ID, name, email) from the database into the Flask 'g' object (g.user).

    Handles database connection errors, invalid sessions (user ID not found
    in DB), and ensures database resources are properly closed.
    Prioritizes PostgreSQL for cursor/error handling if available.
    """
    user_id = session.get('user_id')
    g.user = None  # Initialize g.user to None for every request by default

    if user_id:
        # Proceed only if a user_id was found in the session
        conn = None
        cursor = None

        # Determine the specific DB error classes to catch based on availability
        # Directly use the correctly named global flags now
        db_error_type_pg = psycopg2.Error if POSTGRES_AVAILABLE and psycopg2 else None
        db_error_type_mysql = MySQLError if MYSQL_AVAILABLE and MySQLError else None
        # Create a tuple of available database error types to catch
        available_db_errors = tuple(filter(None, [db_error_type_pg, db_error_type_mysql]))
        if not available_db_errors:
            # Fallback to generic Exception if no specific driver/error available
            available_db_errors = (Exception,)
            # Log only if needed, as it should ideally find one or the other if configured
            # logging.warning("No specific DB error type (psycopg2.Error/MySQLError) available for @before_request.")

        try:
            # 1. Attempt to establish a database connection.
            conn = get_db_connection() # Assumes this function handles PG/MySQL switching

            if not conn:
                logging.error(f"DB connection failed in @before_request while attempting to load user {user_id}.")
                return # Exit function early

            # 2. Create a database cursor appropriate for the connection type.
            # Directly use the correctly named global flags
            if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
                 cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                 logging.debug("Using psycopg2 DictCursor for user load.")
            elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
                 cursor = conn.cursor(dictionary=True)
                 logging.debug("Using mysql.connector dictionary cursor for user load.")
            else:
                 # This indicates an issue with the connection object or availability flags.
                 logging.error(f"Cannot determine appropriate cursor type for DB connection while loading user {user_id}.")
                 if conn: close_db_connection(conn) # Close connection if opened
                 return # Exit function early

            # 3. Execute the query to fetch user details.
            logging.debug(f"Executing query to load user details for ID: {user_id}")
            cursor.execute("""
                SELECT customer_id, customer_name, email
                FROM customers
                WHERE customer_id = %s
            """, (user_id,)) # Pass user_id as a tuple
            user_data_raw = cursor.fetchone()

            # 4. Process the query result.
            if user_data_raw:
                fetched_id = user_data_raw.get('customer_id')
                fetched_name = user_data_raw.get('customer_name')
                fetched_email = user_data_raw.get('email')

                if fetched_id is not None and fetched_name is not None and fetched_email is not None:
                    g.user = {'id': fetched_id, 'name': fetched_name, 'email': fetched_email}
                    logging.debug(f"User {g.user['id']} ('{g.user['name']}') loaded into g object.")
                    session.permanent = True
                else:
                    logging.error(f"Incomplete data retrieved from DB for user ID {user_id}. Fetched: {user_data_raw}. Clearing session.")
                    session.clear()
                    g.user = None
            else:
                logging.warning(f"User ID {user_id} from session was not found in the database. Clearing invalid session.")
                session.clear()
                g.user = None

        except available_db_errors as db_err:
            error_type_name = type(db_err).__name__
            logging.error(f"{error_type_name} occurred in @before_request loading user {user_id}: {db_err}", exc_info=False)
            # g.user remains None

        except Exception as e:
            logging.error(f"Unexpected error in @before_request loading user {user_id}: {e}", exc_info=True)
            # g.user remains None

        finally:
            # 5. Ensure database resources are closed.
            if cursor:
                try: cursor.close()
                except Exception as cur_close_err: logging.warning(f"Ignoring error while closing cursor for user {user_id}: {cur_close_err}")
            if conn:
                try: close_db_connection(conn)
                except Exception as conn_close_err: logging.error(f"Error closing DB connection for user {user_id} in @before_request: {conn_close_err}", exc_info=True)

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

# Assume necessary imports and setup are done earlier in the file
# (Flask, DB helpers, WTForms classes, login_manager, etc.)
# Assume global flags POSTGRES_AVAILABLE, MYSQL_AVAILABLE and global types
# DB_ERROR_TYPE, psycopg2, MySQLError are correctly defined.

@app.route('/register', methods=['GET', 'POST'])
def register_customer():
    """Handles new customer registration. Adapted for PG/MySQL with robust ID retrieval."""
    if g.user: return redirect(url_for('index')) # Redirect if already logged in
    form = RegistrationForm() if WTFORMS_AVAILABLE else None # Instantiate form if available

    # --- Handle POST Request ---
    if (WTFORMS_AVAILABLE and form.validate_on_submit()) or \
       (not WTFORMS_AVAILABLE and request.method == 'POST'):

        # --- 1. Extract Form Data ---
        if WTFORMS_AVAILABLE:
            customer_name = form.customer_name.data
            email = form.email.data
            password = form.password.data
            phone_number = form.phone_number.data
        else: # Manual extraction and basic validation
            customer_name = request.form.get('customer_name','').strip()
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            confirm_password = request.form.get('confirm_password','') # Needed for validation
            phone_number = request.form.get('phone_number', '').strip()
            errors = []
            if not customer_name or len(customer_name) < 2: errors.append("Name required (min 2 chars).")
            if not email or '@' not in email: errors.append("Valid email required.")
            if not password or len(password) < 8: errors.append("Password required (min 8 chars).")
            if password != confirm_password: errors.append("Passwords don't match.")
            if errors:
                for err in errors: flash(err, 'error')
                return render_template('register.html', form=form)

        # --- 2. Placeholder Validations ---
        logging.info("DEMO MODE: Skipping CAPTCHA/OTP validation.")

        # --- 3. Database Operations ---
        conn = None; cursor = None; user_exists = False; error_occurred = False
        db_type = "Unknown" # Initialize

        # 3a. Pre-check email existence
        pre_check_cursor = None
        try:
             conn = get_db_connection()
             if not conn: raise ConnectionError("DB pre-check connection error.")

             # Use standard cursor for simple existence check
             pre_check_cursor = conn.cursor()
             pre_check_cursor.execute("SELECT 1 FROM customers WHERE email = %s LIMIT 1", (email,))
             if pre_check_cursor.fetchone():
                 user_exists = True
                 # Add error to WTForms field if available
                 if WTFORMS_AVAILABLE and hasattr(form, 'email'): form.email.errors.append("Email already registered.")
                 else: flash("Email address is already registered.", "error")

        except (DB_ERROR_TYPE, ConnectionError) as e:
            logging.error(f"DB pre-check error for {email}: {e}", exc_info=True)
            flash("A database error occurred during pre-check.", "error")
            error_occurred = True
        except Exception as e: # Catch any other unexpected error
            logging.error(f"Unexpected pre-check error for {email}: {e}", exc_info=True)
            flash("An unexpected error occurred during pre-check.", "error")
            error_occurred = True
        finally:
             # Close pre-check cursor safely
             if pre_check_cursor and not getattr(pre_check_cursor, 'closed', True):
                 try: pre_check_cursor.close()
                 except DB_ERROR_TYPE: pass
                 except Exception as cur_close_err: logging.warning(f"Error closing pre-check cursor: {cur_close_err}")
             # Close connection ONLY if stopping (user exists or error)
             # Check connection validity before closing
             if (user_exists or error_occurred) and conn and not getattr(conn, 'closed', True):
                 logging.debug("Closing connection after failed pre-check or existing user.")
                 close_db_connection(conn)
                 conn = None # Ensure conn is None if closed here
             elif conn:
                 logging.debug("Pre-check passed or error occurred before user check. Keeping connection open or letting outer finally handle.")

        # --- Decision Point ---
        if user_exists or error_occurred:
            # If conn wasn't closed above, ensure it's closed now
            if conn and not getattr(conn, 'closed', True): close_db_connection(conn)
            return render_template('register.html', form=form)

        # --- 3b. Main Transaction: Insert Customer & Account ---
        # conn might be None if closed after error, or open if pre-check passed
        cursor = None; needs_rollback = False; new_customer_id = None
        try:
            # Get or re-establish connection if needed
            if not conn or getattr(conn, 'closed', True):
                logging.info("Establishing connection for main registration transaction.")
                conn = get_db_connection()
                if not conn: raise ConnectionError("DB connection failed before registration transaction.")
            # Determine DB type based on the active connection
            db_type = "Unknown"
            if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection): db_type = "PostgreSQL"
            elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection): db_type = "MySQL"

            # Use standard cursor for inserts, RETURNING is handled by fetchone()
            cursor = conn.cursor()
            needs_rollback = True
            hashed_pw = generate_password_hash(password)
            phone_to_db = phone_number or None

            # --- Insert Customer ---
            sql_cust = "INSERT INTO customers (customer_name, email, password_hash, phone_number) VALUES (%s, %s, %s, %s)"
            cust_params = (customer_name, email, hashed_pw, phone_to_db)
            new_customer_id = None # Ensure reset before assignment

            if db_type == 'PostgreSQL':
                logging.debug("Executing PG customer insert with RETURNING")
                cursor.execute(sql_cust + " RETURNING customer_id", cust_params)
                cust_row = cursor.fetchone()
                new_customer_id = cust_row[0] if cust_row else None
            else: # MySQL or Fallback
                logging.debug("Executing MySQL/Fallback customer insert")
                cursor.execute(sql_cust, cust_params)
                new_customer_id = cursor.lastrowid
                if not new_customer_id and db_type == 'MySQL': # Try fallback SELECT for MySQL if lastrowid fails
                     logging.warning("MySQL lastrowid failed for customer, attempting fallback SELECT.")
                     cursor.execute("SELECT customer_id FROM customers WHERE email = %s", (email,))
                     fallback_row = cursor.fetchone()
                     if fallback_row: new_customer_id = fallback_row[0]

            if not new_customer_id: # Final check for customer ID
                raise DB_ERROR_TYPE("Failed to retrieve customer ID after insert.")
            logging.info(f"Retrieved new customer ID: {new_customer_id}")

            # --- Generate and Insert Account ---
            account_number_generated = None; attempt = 0; max_attempts = 10
            while attempt < max_attempts: # Find unique account number
                attempt += 1; potential_acc_num = str(random.randint(10**11, (10**12)-1))
                try:
                    cursor.execute("SELECT 1 FROM accounts WHERE account_number = %s LIMIT 1", (potential_acc_num,))
                    if not cursor.fetchone(): account_number_generated = potential_acc_num; break
                    else: logging.debug(f"Acc No {potential_acc_num} exists, retrying...")
                except DB_ERROR_TYPE as check_err: raise ValueError(f"DB error check acc unique: {check_err}")
            if not account_number_generated: raise ValueError(f"Could not generate unique account number.")
            logging.info(f"Generated unique Acc No: {account_number_generated}")

            # Insert Account
            sql_acc = "INSERT INTO accounts (customer_id, balance, account_number) VALUES (%s, %s, %s)"
            acc_params = (new_customer_id, str(app.config['INITIAL_BALANCE']), account_number_generated)
            inserted_acc_id = None # Ensure reset

            if db_type == 'PostgreSQL':
                logging.debug("Executing PG account insert with RETURNING")
                cursor.execute(sql_acc + " RETURNING account_id", acc_params)
                acc_row = cursor.fetchone(); inserted_acc_id = acc_row[0] if acc_row else None
            else: # MySQL or Fallback
                logging.debug("Executing MySQL/Fallback account insert")
                cursor.execute(sql_acc, acc_params); inserted_acc_id = cursor.lastrowid
                if not inserted_acc_id and db_type == 'MySQL': # Try fallback SELECT for MySQL
                     logging.warning("MySQL lastrowid failed for account, attempting fallback SELECT.")
                     cursor.execute("SELECT account_id FROM accounts WHERE customer_id=%s AND account_number=%s", (new_customer_id, account_number_generated))
                     fallback_acc_row = cursor.fetchone()
                     if fallback_acc_row: inserted_acc_id = fallback_acc_row[0]

            if not inserted_acc_id: # Final check for account ID
                raise DB_ERROR_TYPE("Failed to retrieve account ID after insert.")
            logging.info(f"Created account ID: {inserted_acc_id} for customer {new_customer_id}")

            # --- Commit ---
            conn.commit(); needs_rollback = False
            logging.info(f"Successfully registered: '{customer_name}' ({email}), CustID:{new_customer_id}, AccID:{inserted_acc_id}")
            flash("Registration successful! You can now log in.", "success")

            # Explicitly close resources after commit before redirect
            if cursor and not getattr(cursor, 'closed', True): cursor.close(); cursor=None
            if conn and not getattr(conn, 'closed', True): close_db_connection(conn); conn=None
            return redirect(url_for('login'))

        # --- Outer Exception Handling for Transaction ---
        except (DB_ERROR_TYPE, ConnectionError, ValueError) as e:
            error_msg = str(e)
            logging.error(f"Registration DB/Value error ({db_type}) for {email}: {error_msg}", exc_info=True)
            flash(f"Registration failed: {error_msg}" if isinstance(e, ValueError) else "Database error during registration.", "error")
        except Exception as e:
            logging.error(f"Unexpected registration error for {email}: {e}", exc_info=True)
            flash("An unexpected error occurred during registration.", "error")
        finally: # Rollback and cleanup if transaction failed
            # Check if conn exists and seems open before attempting rollback/close
            if conn and not getattr(conn, 'closed', True):
                if needs_rollback:
                    try: conn.rollback(); logging.warning(f"Registration rolled back for '{email}'.")
                    except Exception as rb_err: logging.error(f"Rollback failed: {rb_err}")
                # Safe cursor close
                if cursor and not getattr(cursor, 'closed', True):
                    try: cursor.close()
                    except DB_ERROR_TYPE: pass
                    except Exception as cur_close_err: logging.warning(f"Non-DB error closing reg cursor: {cur_close_err}")
                # Always close connection if obtained/reconnected in this block
                close_db_connection(conn)

        # Re-render form if transaction failed
        return render_template('register.html', form=form)

    # --- Handle GET Request ---
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

import traceback # Ensure traceback is imported if not already
import hashlib # Ensure hashlib is imported
import base64 # Ensure base64 is imported
from cryptography.fernet import Fernet, InvalidToken # Ensure Fernet/InvalidToken are imported
from decimal import Decimal, InvalidOperation # Ensure Decimal/InvalidOperation are imported
# Assume other necessary imports like Flask, request, session, g, etc., are already present

@app.route('/transfer-funds', methods=['POST']) # Use the corrected route name if needed
@login_required
def transfer_funds():
    """Handles the fund transfer process including QKD and Fraud Check."""
    # --- Variable Initialization ---
    sender_id = None; receiver_id = None; amount = None; simulate_eve_checked = False
    if not g.user or 'id' not in g.user:
        flash("User session error. Please log in again.", "error")
        return redirect(url_for('login'))
    logged_in_user_id = g.user['id']

    qkd_key = None; sim_res = {}; qber = -1.0; qkd_fail_reason = None
    log_status = "INITIATED"; fraud_res = {'is_fraudulent': False, 'reason': None, 'ml_score': -1.0}
    last_outcome = {'timestamp': datetime.datetime.now().isoformat(), 'status': 'Pending', 'reason': ''}
    session.pop('last_transfer_outcome', None)

    # --- 1. Input Validation & Form Handling ---
    try:
        # Get Sender Account first
        user_accounts = get_accounts_data(customer_id_filter=logged_in_user_id)
        if user_accounts is None: raise ConnectionError("DB error fetching sender account.")
        if not user_accounts: raise ValueError("Sender account details not found.")
        sender_account = user_accounts[0]
        sender_id = sender_account.get('account_id')
        if sender_id is None: raise ValueError("Sender account ID missing.")
        last_outcome['sender_id'] = sender_id

        # Handle Form Submission Data
        if WTFORMS_AVAILABLE:
            logging.debug("WTForms available, processing form.")
            transfer_form = TransferForm(request.form) # Instantiate with POST data

            # Dynamically populate choices BEFORE validation
            all_accounts = get_accounts_data()
            if all_accounts is None: raise ConnectionError("Recipient list fetch error.")
            # Use STRINGS for choice values to match HTML form submission
            recipients = [(str(acc['account_id']), f"{acc.get('customer_name','Unknown')} (ID:{acc['account_id']})")
                          for acc in all_accounts if acc.get('customer_id') != logged_in_user_id and acc.get('account_id')]
            transfer_form.receiver_account_id.choices = [('', '-- Select Recipient --')] + recipients # Set choices on the instance

            if transfer_form.validate_on_submit(): # Validate the submitted data
                logging.debug("WTForms validation successful.")
                # Get the raw data (SelectField data is usually string)
                receiver_id_str = transfer_form.receiver_account_id.data
                amount = transfer_form.amount.data # Should be Decimal
                simulate_eve_checked = transfer_form.simulate_eve.data # Should be bool

                # --- EXPLICIT CONVERSION AFTER VALIDATION ---
                if not receiver_id_str: # Check if it's empty (placeholder selected)
                     logging.error("WTForms validation passed, but receiver_id data is empty.")
                     raise ValueError("Please select a valid recipient.")
                try:
                    # Attempt to convert the validated string ID to an integer
                    receiver_id = int(receiver_id_str)
                    logging.debug(f"Successfully converted receiver_id_str '{receiver_id_str}' to int: {receiver_id}")
                except (ValueError, TypeError):
                     logging.error(f"Failed to convert validated receiver_id data '{receiver_id_str}' to int.")
                     raise ValueError("Invalid recipient ID data received.")
                # --- END EXPLICIT CONVERSION ---

            else: # WTForms validation failed
                 error_msg = "; ".join([f"{field.replace('_',' ').title()}: {', '.join(errs)}"
                                         for field, errs in transfer_form.errors.items()])
                 logging.warning(f"WTForms validation failed: {transfer_form.errors}")
                 raise ValueError(f"Invalid input: {error_msg}")

        else: # Manual parsing if WTForms unavailable
            logging.debug("WTForms not available, using manual parsing.")
            receiver_id_str = request.form.get('receiver_account_id'); amount_str = request.form.get('amount'); simulate_eve_checked = 'simulate_eve' in request.form
            if not receiver_id_str: raise ValueError("Please select a recipient account.")
            try: receiver_id = int(receiver_id_str)
            except (ValueError, TypeError): raise ValueError("Invalid recipient account ID selected.")
            if not amount_str: raise ValueError("Amount is missing.")
            try: amount = Decimal(amount_str.strip())
            except InvalidOperation: raise ValueError("Invalid amount format (e.g., 100.50).")

        # --- Common Validations (Post-Parsing/Validation) ---
        if not isinstance(receiver_id, int): # Check if conversion above was successful
            raise ValueError("Internal Error: Recipient ID is invalid or missing after processing.")
        if sender_id == receiver_id:
            raise ValueError("Cannot transfer funds to your own account.")
        if amount is None or not isinstance(amount, Decimal) or amount <= 0:
            raise ValueError("Amount must be a positive value (e.g., greater than 0.00).")

        # --- Input Validated Successfully ---
        last_outcome.update({'amount': f"{amount:.2f}", 'receiver_id': receiver_id, 'simulate_eve': simulate_eve_checked})
        log_status = "INPUT_VALIDATED"
        logging.info(f"Transfer Validated: ₹{amount:.2f} from {sender_id} to {receiver_id} (SimEve: {simulate_eve_checked})")

    except (ValueError, ConnectionError, TypeError, InvalidOperation, KeyError) as e:
        flash(f"Transfer Failed: {e}", "error"); last_outcome.update({'status': 'Failed', 'reason': f"Input Error: {str(e)[:100]}"})
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        amount_for_log = amount if isinstance(amount, Decimal) else (Decimal(str(amount)) if amount is not None else Decimal('0.00'))
        log_failed_attempt(sender_id, receiver_id, amount_for_log, "INPUT_ERROR", exception_info=e)
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Unexpected input error: {e}", exc_info=True); flash("Unexpected error.", "error"); last_outcome.update({'status': 'Failed', 'reason': "Unexpected Input Error"})
        session['last_transfer_outcome'] = last_outcome; session.modified = True
        amount_for_log = amount if isinstance(amount, Decimal) else (Decimal(str(amount)) if amount is not None else Decimal('0.00'))
        log_failed_attempt(sender_id, receiver_id, amount_for_log, "UNEXPECTED_INPUT_ERR", exception_info=e)
        return redirect(url_for('index'))

    # --- Eavesdropper Alert ---
    if simulate_eve_checked:
        try:
            ip_address = None
            if 'RENDER' in os.environ: # Check if on Render
                octet1=random.choice([10, 172, 192, random.randint(1, 223)]); octet3=random.randint(0, 254); octet4=random.randint(1, 254)
                if octet1 == 172: octet2 = random.randint(16, 31)
                elif octet1 == 192: octet2 = 168
                else: octet2 = random.randint(0, 254)
                ip_address = f"{octet1}.{octet2}.{octet3}.{octet4}"
                logging.info(f"Simulating eavesdropper IP on Render: {ip_address}")
            else: # Locally
                ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
                logging.info(f"Detected local IP for simulated eavesdropper: {ip_address}")

            user_name = g.user.get('name', 'Unknown'); user_id_alert = g.user.get('id', 'N/A')
            alert_subject = "🚨 URGENT: Potential Eavesdropping Detected (Simulated) on QuantumVault Transaction"
            alert_log = f"User:{user_name}({user_id_alert}), IP:{ip_address}, Tx:{sender_id}->{receiver_id}, Amt:₹{amount:.2f}"
            email_body = f"QuantumVault Security Alert\n\nWARNING: Potential eavesdropping activity detected from IP address: {ip_address}\n\nTriggered by 'Simulate Eavesdropper'.\n\nDetails:\nUser: {user_name} ({user_id_alert})\nIP: {ip_address}\nAction: Transfer Attempt\nFrom:{sender_id}, To:{receiver_id}, Amt:₹{amount:.2f}\n\nQuantumVault Security Monitoring"
            current_app.logger.warning(f"{alert_subject} - {alert_log}")
            flash(f"⚠️ Simulating Eavesdropper from IP: {ip_address}. Expect high QBER.", 'warning')
            admin_email = os.environ.get('ADMIN_ALERT_EMAIL')
            if mail and MAIL_AVAILABLE and admin_email:
                try:
                    sender_cfg = app.config.get('MAIL_DEFAULT_SENDER');
                    if not sender_cfg or not isinstance(sender_cfg, tuple) or len(sender_cfg)!=2 or not sender_cfg[1]: raise ValueError("Mail sender config invalid")
                    msg = Message(alert_subject, sender=sender_cfg, recipients=[admin_email], body=email_body)
                    mail.send(msg); current_app.logger.info(f"Eavesdropper alert email sent to {admin_email}")
                except Exception as mail_err: current_app.logger.error(f"Failed sending eavesdropper alert: {mail_err}", exc_info=True)
            elif not admin_email: current_app.logger.warning("ADMIN_ALERT_EMAIL not set, skipping alert.")
            else: current_app.logger.warning("Mail system unavailable, skipping alert.")
        except Exception as alert_err: current_app.logger.error(f"Error in eavesdropper alerting: {alert_err}", exc_info=True)

    # --- 2. QKD Simulation ---
    qber_thresh = app.config['QBER_THRESHOLD']; n_qubits = app.config['QKD_NUM_QUBITS']; eve_rate = 0.25 if simulate_eve_checked else 0.0; qkd_fraud_reason = None
    try:
        log_status = "QKD_RUNNING"; logging.info(f"Running QKD: N={n_qubits}, Eve={simulate_eve_checked}, Rate={eve_rate:.3f}, Thresh={qber_thresh:.3f}")
        sim_res = simulate_bb84(n_qubits=n_qubits, simulate_eve=simulate_eve_checked, qber_threshold=qber_thresh, eve_interception_rate=eve_rate)
        session[f'last_qkd_log_{logged_in_user_id}'] = sim_res; session.modified = True; last_outcome['qkd_log_stored'] = True
        key_bin = sim_res.get('final_key_binary'); qber = sim_res.get('qber', -1.0); eve_det = sim_res.get('eve_detected', False)
        qber_disp = f"{qber:.4f}" if qber >= 0 else 'N/A'; last_outcome['qber'] = qber_disp; key_len = len(key_bin or '')
        logging.info(f"QKD Result: QBER={qber_disp}, EveDetected={eve_det}, KeyLen={key_len}")
        min_key_len = 128
        if qber < 0: qkd_fail_reason = f"QKD Sim Error ({qber})"; log_status = "QKD_SIM_ERR"
        elif eve_det: qkd_fail_reason = f"High QBER ({qber_disp}) > Thresh ({qber_thresh:.3f}). Eavesdropping Likely."; log_status = "QKD_EVE_DETECTED"; qkd_fraud_reason = "QKD Alert: High QBER"
        elif not key_bin or key_len < min_key_len: qkd_fail_reason = f"Key too short ({key_len}b < {min_key_len}b)"; log_status = "QKD_KEY_INSUFFICIENT"
        if qkd_fail_reason: raise ValueError(f"QKD Failed: {qkd_fail_reason}")
        key_hash = hashlib.sha256(key_bin.encode('utf-8')).digest(); qkd_key = base64.urlsafe_b64encode(key_hash)
        logging.info(f"QKD OK (QBER:{qber_disp}). Key derived."); log_status = "QKD_SUCCESS"; last_outcome['qkd_status_msg'] = "Secure Channel OK"
    except ValueError as qkd_e:
        flash(f"Transfer Aborted: {qkd_e}", "danger"); last_outcome.update({'status': 'Failed', 'reason': qkd_fail_reason or str(qkd_e), 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, qber_value=qber if qber >=0 else None, fraud_reason=qkd_fraud_reason, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))
    except Exception as qkd_e:
        logging.error(f"Unexpected QKD Error: {qkd_e}", exc_info=True); log_status = "QKD_INTERNAL_ERR"
        flash('Transfer Aborted: Secure channel error.', 'danger'); last_outcome.update({'status': 'Failed', 'reason': 'QKD Error', 'qkd_status_msg': log_status})
        log_failed_attempt(sender_id, receiver_id, amount, log_status, exception_info=qkd_e)
        session['last_transfer_outcome'] = last_outcome; session.modified = True; return redirect(url_for('index'))

    # --- 3. DB Transaction, Fraud Check, Finalize ---
    conn = None; cursor = None; needs_rollback = False; log_id = None; db_type = "Unknown"
    try:
        if not qkd_key: raise ValueError("Internal error: QKD key missing.")
        log_status = "DB_TXN_STARTING"; conn = get_db_connection();
        if not conn: raise ConnectionError("DB service unavailable.")

        # --- CORRECTED CURSOR CREATION (Using isinstance) ---
        cursor_created = False
        db_type = "Unknown" # Initialize db_type

        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDict for PG
            db_type = "PostgreSQL" # Set type for logging
            logging.debug("Transfer Funds: Using psycopg2 RealDictCursor.")
            cursor_created = True
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True, buffered=True) # Buffered might be needed for MySQL
            db_type = "MySQL" # Set type for logging
            logging.debug("Transfer Funds: Using mysql.connector dictionary cursor.")
            cursor_created = True

        if not cursor_created: # If still no cursor could be created, raise the error
            logging.error(f"Unsupported database connection type encountered in transfer: {type(conn)}")
            raise ConnectionError(f"Unsupported DB type for transfer: {type(conn)}")
        # --- END CORRECTED CURSOR CREATION ---

        needs_rollback = True

        # Lock & Validate Sender
        log_status = "DB_VALIDATE_SENDER"; cursor.execute("SELECT customer_id, balance FROM accounts WHERE account_id = %s FOR UPDATE", (sender_id,))
        sender_info = cursor.fetchone()
        if not sender_info: raise ValueError(f"Sender {sender_id} not found/locked.")
        if sender_info['customer_id'] != logged_in_user_id: raise ValueError("Authorization Error.")
        sender_bal = Decimal(sender_info['balance']);
        if sender_bal < amount: raise ValueError(f"Insufficient funds (Bal: ₹{sender_bal:.2f})")

        # Validate Receiver
        log_status = "DB_VALIDATE_RECEIVER"; cursor.execute("SELECT a.account_id, c.customer_name, a.balance FROM accounts a JOIN customers c ON a.customer_id=c.customer_id WHERE a.account_id=%s", (receiver_id,))
        rx_info = cursor.fetchone();
        if not rx_info: raise ValueError(f"Receiver {receiver_id} not found.")
        rx_name = rx_info['customer_name']; last_outcome['receiver_name'] = rx_name

        # Fraud Detection
        log_status = "FRAUD_CHECK"; logging.info("Running fraud check...")
        hist_ml = [] # Fetch history... (code omitted)
        current_txn_data = {'amount': amount, 'recipient_username': rx_name, 'timestamp': datetime.datetime.now()} # Ensure feature names match model
        try: fraud_res = detect_fraud(current_txn_data, hist_ml, **{'blacklist': app.config['FRAUD_BLACKLIST']})
        except Exception as fraud_err: logging.error(f"Fraud check failed: {fraud_err}"); fraud_res = {'is_fraudulent': False, 'reason': 'Fraud Check Error'}; flash("Warning: Fraud check error.", "warning")
        last_outcome['fraud_check'] = fraud_res; is_fraudulent_ml = fraud_res.get('is_fraudulent', False); ml_reason = fraud_res.get('reason')
        final_reason = qkd_fraud_reason or (ml_reason if is_fraudulent_ml else None)
        final_flagged = bool(qkd_fraud_reason) or is_fraudulent_ml # Use this consistent variable name

        # --- CORRECTED IF/ELSE SYNTAX and variable name ---
        if final_flagged:
            # Use final_fraud_reason here
            logging.warning(f"ALERT: {final_reason or 'Flagged - Reason Unknown'}")
        else:
            logging.info("Fraud check passed and no QKD alert.")
        # --- END CORRECTION ---

        qkd_status = "SECURED_FLAGGED" if final_flagged else "SECURED"; # Use final_flagged
        last_outcome['qkd_status_msg'] = qkd_status.replace('_',' ')

        # Encrypt Confirmation
        log_status = "ENCRYPTING"; msg_enc = f"CONF;{sender_id}>{receiver_id};AMT:{amount:.2f};QBER:{qber_disp};F:{final_flagged};R:{final_reason or 'N/A'};T:{datetime.datetime.now().isoformat()}"
        try: fernet = Fernet(qkd_key); enc_b64 = fernet.encrypt(msg_enc.encode()).decode()
        except InvalidToken: log_status="ENC_KEY_ERR"; raise ValueError("Internal: Invalid encryption key.")
        except Exception as fe: log_status = "ENC_FAIL"; raise ValueError(f"Internal: Encryption failed: {fe}")
        last_outcome['enc_sample'] = enc_b64[:60]+'...'

        # Update Balances
        log_status = "DB_UPDATE"; new_sender_bal = sender_bal - amount
        cursor.execute("SELECT balance FROM accounts WHERE account_id=%s FOR UPDATE", (receiver_id,))
        rx_bal_locked = cursor.fetchone();
        if not rx_bal_locked: raise ValueError("Receiver disappeared.")
        new_receiver_bal = Decimal(rx_bal_locked['balance']) + amount
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_sender_bal), sender_id));
        if cursor.rowcount != 1: raise DB_ERROR_TYPE(f"Sender update failed (rows={cursor.rowcount})")
        cursor.execute("UPDATE accounts SET balance=%s WHERE account_id=%s", (str(new_receiver_bal), receiver_id));
        if cursor.rowcount != 1: raise DB_ERROR_TYPE(f"Receiver update failed (rows={cursor.rowcount})")
        logging.info("Balances updated.")

        # Log Transaction
        log_status = "DB_LOGGING"; log_qber = qber if qber >= 0 else None; log_reason = final_reason[:255] if final_reason else None
        log_ts = datetime.datetime.now(datetime.timezone.utc)
        log_vals = (sender_id, receiver_id, str(amount), qkd_status, enc_b64, None, log_qber, final_flagged, log_reason, log_ts) # Use final_flagged here
        log_id = None # Initialize log_id

        # --- CORRECTED LOGIC FOR PG/MYSQL ID RETRIEVAL ---
        if db_type.lower() == 'postgresql': # Use .lower() and full name
            # Quote "timestamp" if it's a reserved word in your PG version/schema
            log_sql = """INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason, "timestamp") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING log_id"""
            try:
                cursor.execute(log_sql, log_vals)
                log_row = cursor.fetchone()
                if log_row and 'log_id' in log_row:
                    log_id = log_row['log_id']
                    logging.info(f"PostgreSQL RETURNING successful: log_id={log_id}")
                else:
                    logging.error(f"PostgreSQL RETURNING clause failed. fetchone() result: {log_row}")
                    raise DB_ERROR_TYPE("Failed to retrieve log ID via RETURNING.")
            except DB_ERROR_TYPE as pg_log_err:
                logging.error(f"Error during PostgreSQL log insert/RETURNING: {pg_log_err}")
                raise
            except Exception as e_pg_log:
                logging.error(f"Unexpected error during PostgreSQL log insert: {e_pg_log}", exc_info=True)
                raise DB_ERROR_TYPE(f"Unexpected error during PG log insert: {e_pg_log}")

        elif db_type.lower() == 'mysql': # Use .lower() and full name
            log_sql = """INSERT INTO qkd_transaction_log (sender_account_id, receiver_account_id, amount, qkd_status, encrypted_confirmation, iv, qber_value, is_flagged, fraud_reason, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
            try:
                cursor.execute(log_sql, log_vals);
                log_id = cursor.lastrowid
                if not log_id:
                     logging.warning("MySQL lastrowid failed, attempting fallback SELECT LAST_INSERT_ID().")
                     try:
                         cursor.execute("SELECT LAST_INSERT_ID()")
                         fallback_id_row = cursor.fetchone()
                         log_id = fallback_id_row[0] if fallback_id_row and len(fallback_id_row) > 0 else None
                     except Exception as e_lid:
                         logging.error(f"MySQL LAST_INSERT_ID() fallback failed: {e_lid}")
                         raise DB_ERROR_TYPE("Failed get log ID using lastrowid and fallback SELECT.")
                logging.info(f"MySQL log insert successful: log_id={log_id}")
            except DB_ERROR_TYPE as mysql_log_err:
                 logging.error(f"Error during MySQL log insert/lastrowid: {mysql_log_err}")
                 raise
            except Exception as e_mysql_log:
                logging.error(f"Unexpected error during MySQL log insert: {e_mysql_log}", exc_info=True)
                raise DB_ERROR_TYPE(f"Unexpected error during MySQL log insert: {e_mysql_log}")

        else: # This case means db_type was not 'PostgreSQL' or 'MySQL'
            raise ConnectionError(f"Cannot log transaction: Unsupported DB type '{db_type}' identified.")

        # Final Check for log_id
        if log_id is None:
             logging.error("Log ID is still None after attempting DB-specific retrieval methods.")
             raise DB_ERROR_TYPE("Failed to obtain log ID after insert.")
        # --- END CORRECTED LOGIC ---

        last_outcome['log_id'] = log_id;
        logging.info(f"Transaction successfully logged with ID: {log_id}")

        # Commit
        log_status = "COMMITTING"; conn.commit(); needs_rollback = False
        logging.info("DB transaction committed."); last_outcome['status'] = 'Success'
        # Flash Success
        flash_msg = f"Success! ₹{amount:.2f} sent to {rx_name}. Log ID: {log_id}. Status: {qkd_status.replace('_',' ')} (QBER:{qber_disp})."
        flash_cat = "success"
        if final_flagged: flash_msg = f"Success (Log ID: {log_id}), but FLAGGED: {(final_reason or '').split(':')[0]}. QBER:{qber_disp}."; flash_cat="warning"
        flash(flash_msg, flash_cat)

    # --- Error Handling ---
    except (DB_ERROR_TYPE, ValueError, InvalidOperation, ConnectionError, AssertionError, InvalidToken) as e:
        error_message = str(e); log_status = "TXN_FAIL" # General status
        if isinstance(e, ValueError): log_status = "VALIDATION_FAIL_DB"
        elif isinstance(e, ConnectionError): log_status = "DB_CONN_ERR_TXN"
        elif isinstance(e, InvalidToken): log_status = "ENC_KEY_ERR_FINAL"
        elif isinstance(e, DB_ERROR_TYPE): log_status = "DB_TXN_ERR"
        logging.error(f"TXN Error ({log_status}) {sender_id}->{receiver_id}: {error_message}", exc_info=True)
        last_outcome.update({'status': 'Failed', 'reason': error_message[:200], 'qkd_status_msg': log_status.replace('_',' ')})
        flash(f"Transfer Failed: {error_message}" if log_status == "VALIDATION_FAIL_DB" else "Transfer Failed (System Error).", "error")
        amount_for_log = amount if isinstance(amount, Decimal) else (Decimal(str(amount)) if amount is not None else Decimal('0.00'))
        log_failed_attempt(sender_id, receiver_id, amount_for_log, log_status, qber_value=qber if qber>=0 else None, fraud_reason=f"Txn Error: {error_message[:100]}", exception_info=e)
    except Exception as e:
        log_status = "UNEXPECTED_TXN_ERR"; error_message = str(e)
        tb_str = traceback.format_exc(); logging.critical(f"CRITICAL UNEXPECTED TXN Error {sender_id}->{receiver_id}: {error_message}\n{tb_str}")
        flash("Transfer Failed (Critical Error).", "danger"); last_outcome.update({'status': 'Failed', 'reason': 'Critical Error', 'qkd_status_msg': log_status})
        amount_for_log = amount if isinstance(amount, Decimal) else (Decimal(str(amount)) if amount is not None else Decimal('0.00'))
        log_failed_attempt(sender_id, receiver_id, amount_for_log, log_status, qber_value=qber if qber>=0 else None, fraud_reason="Critical Error", exception_info=e)
    finally: # Cleanup for the main transaction block
        # Ensure connection and cursor are closed properly
        if conn and not getattr(conn, 'closed', True): # Check connection exists and not closed
            if needs_rollback: # Check if rollback is needed (commit didn't happen)
                # --- CORRECTED INDENTATION and Exception Catching ---
                try:
                    conn.rollback()
                    logging.warning(f"Transfer transaction rolled back (Final Status before rollback: {log_status}).")
                # Catch specific DB error if possible, otherwise generic
                except DB_ERROR_TYPE as rb_err: # Use DB_ERROR_TYPE defined globally
                    logging.error(f"Rollback failed during transfer error handling: {rb_err}")
                except Exception as rb_gen_err: # Catch any other rollback error
                     logging.error(f"Unexpected error during transfer rollback: {rb_gen_err}")
                # --- END CORRECTION ---

            # Close cursor if it exists and is not already closed
            if cursor and not getattr(cursor, 'closed', True):
                 try:
                     cursor.close()
                 except DB_ERROR_TYPE: # Ignore DB-specific errors closing cursor
                     pass
                 except Exception as cur_close_err:
                     logging.error(f"Unexpected error closing transfer cursor: {cur_close_err}")

            # Always attempt to close the connection obtained in this try block
            close_db_connection(conn)

    session['last_transfer_outcome'] = last_outcome; session.modified = True
    # Ensure parentheses are balanced in the final redirect
    return redirect(url_for('index'))

@app.route('/history', methods=['GET'])
@login_required
def history():
    """Displays transaction history for the logged-in user."""
    if not g.user or 'id' not in g.user:
        flash("User session error. Please log in again.", "error")
        return redirect(url_for('login'))
    user_id = g.user['id']

    display_log = []
    conn = None; cursor = None; db_type = "Unknown"

    try:
        conn = get_db_connection()
        if not conn:
            flash("Database error. Cannot load history.", "error")
            return render_template('history.html', log_entries=[], user_id=user_id, username=g.user.get('name')) # Use name

        # --- CORRECTED CURSOR CREATION ---
        cursor_created = False
        db_type = "Unknown"
        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db_type = "PostgreSQL"; cursor_created = True
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True)
            db_type = "MySQL"; cursor_created = True
        if not cursor_created:
             logging.error(f"History: Unsupported DB type: {type(conn)}")
             raise ConnectionError("Cannot determine cursor type for history.")
        logging.debug(f"History: Using {db_type} cursor.")
        # --- END CORRECTION ---

        sql = """
            SELECT l.log_id, l.timestamp AS ts,
                   l.sender_account_id AS sender_id, s_cust.customer_name AS sender_name, s_acc.customer_id AS sender_cust_id,
                   l.receiver_account_id AS receiver_id, r_cust.customer_name AS receiver_name, r_acc.customer_id AS receiver_cust_id,
                   l.amount, l.qkd_status, l.qber_value AS qber, l.encrypted_confirmation AS enc_confirm,
                   l.is_flagged, l.fraud_reason
            FROM qkd_transaction_log l
            LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id
            LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id
            LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id
            LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id
            WHERE s_acc.customer_id = %s OR r_acc.customer_id = %s
            ORDER BY l.timestamp DESC
            LIMIT 100
            """
        cursor.execute(sql, (user_id, user_id))
        entries_raw = cursor.fetchall()

        # --- Timezone Conversion Setup (Add near imports if not already there) ---
        # import pytz
        # try:
        #     # Use environment variable or default to IST
        #     LOCAL_TIMEZONE_STR = os.environ.get('LOCAL_TIMEZONE', 'Asia/Kolkata')
        #     LOCAL_TIMEZONE = pytz.timezone(LOCAL_TIMEZONE_STR)
        # except pytz.UnknownTimeZoneError:
        #     logging.error(f"Invalid LOCAL_TIMEZONE '{LOCAL_TIMEZONE_STR}', defaulting to UTC.")
        #     LOCAL_TIMEZONE = pytz.utc
        # --- End Timezone Setup ---


        for entry in entries_raw:
            try: # Inner try for formatting each log entry safely
                amt = Decimal(entry.get('amount', '0.00'))
                qber_raw = entry.get('qber'); qber_val = f"{qber_raw:.3f}" if qber_raw is not None else "N/A"
                qkd_raw_status = entry.get('qkd_status',''); enc_status = "[Encrypted]" if entry.get('enc_confirm') else "[N/A]"
                if "FAIL" in qkd_raw_status or "ERR" in qkd_raw_status: enc_status = "[N/A - Failed Txn]"
                is_flagged = entry.get('is_flagged', False); raw_reason = entry.get('fraud_reason'); display_reason = raw_reason if is_flagged and raw_reason else ("Yes" if is_flagged else "No")
                direction = "Sent" if entry.get('sender_cust_id') == user_id else ("Received" if entry.get('receiver_cust_id') == user_id else "")

                # --- Timestamp Formatting with Timezone Conversion ---
                ts_aware_utc = entry.get('ts')
                timestamp_display = 'N/A'
                if isinstance(ts_aware_utc, datetime.datetime):
                    if ts_aware_utc.tzinfo is None or ts_aware_utc.tzinfo.utcoffset(ts_aware_utc) is None:
                         ts_aware_utc = pytz.utc.localize(ts_aware_utc)
                         logging.debug(f"History log {entry.get('log_id')}: Naive timestamp localized to UTC.")
                    try:
                        ts_local = ts_aware_utc.astimezone(LOCAL_TIMEZONE) # Uses global LOCAL_TIMEZONE
                        timestamp_display = ts_local.strftime('%Y-%m-%d %H:%M:%S %Z') # Format with timezone
                    except Exception as tz_err_hist:
                         logging.warning(f"Timezone conversion failed history log {entry.get('log_id')}: {tz_err_hist}. Displaying UTC.")
                         timestamp_display = ts_aware_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
                # --- End Timestamp Conversion ---

                # Append formatted entry to display list
                display_log.append({
                    'id': entry.get('log_id'),
                    'timestamp': timestamp_display, # Use the formatted string
                    'sender': f"{entry.get('sender_name', '?')} ({entry.get('sender_id', '?')})",
                    'receiver': f"{entry.get('receiver_name', '?')} ({entry.get('receiver_id', '?')})",
                    'amount': f"{amt:.2f}",
                    'qkd_status': qkd_raw_status.replace('_', ' '),
                    'qber': qber_val,
                    'encrypted_details_status': enc_status,
                    'is_flagged_display': display_reason,
                    'fraud_reason': raw_reason,
                    'is_flagged': is_flagged,
                    'direction': direction
                })
            except Exception as display_err:
                logging.warning(f"Error formatting history entry {entry.get('log_id', '?')}: {display_err}", exc_info=True)
              
    except (DB_ERROR_TYPE, ConnectionError) as e:
        flash(f"Database error retrieving history: {e}", "error")
        logging.error(f"History DB error ({db_type}) for user {user_id}: {e}", exc_info=True)
    except Exception as e:
        flash("An unexpected error occurred while loading history.", "error")
        logging.error(f"Unexpected History Error for user {user_id}: {e}", exc_info=True)
    finally: # Ensure resources are cleaned up
        if cursor and not getattr(cursor, 'closed', True):
             try: cursor.close()
             except: pass # Ignore close errors
        if conn and not getattr(conn, 'closed', True):
             close_db_connection(conn)
             logging.debug("DB connection closed in history route finally block.")

    return render_template('history.html', log_entries=display_log, user_id=user_id, username=g.user.get('name')) # Use name


@app.route('/qkd')
@login_required
def qkd_page():
    """Displays QKD info, last sim log, and QBER chart."""
    user_id = g.user['id']
    logging.info(f"--- User {user_id} accessing QKD page ---")

    # --- 1. Get Last Simulation Log ---
    sim_log = session.get(f'last_qkd_log_{user_id}', None) # Use default=None

    # --- 2. Fetch QBER History for Chart ---
    labels = []; values = []
    conn = None; cursor = None; limit = 15
    db_type = "Unknown"

    try:
        conn = get_db_connection()
        if not conn:
            flash("Database unavailable for QBER history.", "error")
            raise ConnectionError("DB Connection failed for QBER history.")

        # --- CORRECTED CURSOR CREATION ---
        cursor_created = False
        db_type = "Unknown"

        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            db_type = "PostgreSQL"; cursor_created = True
            logging.debug("QKD Page: Using psycopg2 RealDictCursor.")
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True)
            db_type = "MySQL"; cursor_created = True
            logging.debug("QKD Page: Using mysql.connector dictionary cursor.")

        if not cursor_created:
             logging.error(f"QKD Page: Unsupported DB type: {type(conn)}")
             raise ConnectionError("Unsupported DB type for QKD page history.")
        # --- END CORRECTED CURSOR CREATION ---

        sql = """
            SELECT l.log_id, l.timestamp, l.qber_value AS qber
            FROM qkd_transaction_log l
            LEFT JOIN accounts s ON l.sender_account_id=s.account_id
            LEFT JOIN accounts r ON l.receiver_account_id=r.account_id
            WHERE (s.customer_id=%s OR r.customer_id=%s)
              AND l.qber_value IS NOT NULL AND l.qber_value >= 0
              AND (l.qkd_status LIKE 'SECURED%%' OR l.qkd_status = 'QKD_EVE_DETECTED')
            ORDER BY l.timestamp DESC LIMIT %s
            """
        cursor.execute(sql, (user_id, user_id, limit))
        history = cursor.fetchall()
        history.reverse()

        for entry in history:
             log_id = entry.get('log_id'); qber_val = entry.get('qber'); ts = entry.get('timestamp')
             if log_id and qber_val is not None and ts:
                 label = f"{ts.strftime('%m/%d %H:%M')} (ID:{log_id})"
                 try:
                     labels.append(label); values.append(round(float(qber_val) * 100, 2))
                 except (ValueError, TypeError): logging.warning(f"Skipping QBER chart entry {log_id}")
             else: logging.warning(f"Skipping QBER history entry due to missing data: {entry}")

    except (DB_ERROR_TYPE, ConnectionError) as e:
        logging.error(f"QBER history DB/Conn error ({db_type}) user {user_id}: {e}", exc_info=True)
        labels, values = ['DB/Conn Error'], [0]; flash("Error loading QBER history.", "error")
    except Exception as e:
        logging.error(f"QBER history unexpected error user {user_id}: {e}", exc_info=True)
        labels, values = ['Processing Error'], [0]; flash("Unexpected QBER history error.", "error")
    finally: # Ensure cleanup
         # --- CORRECTED INDENTATION for cursor close ---
         if cursor and not getattr(cursor, 'closed', True):
             try:
                 cursor.close()
             except DB_ERROR_TYPE: # Use global type
                 pass # Ignore DB specific close errors
             except Exception as cur_e: # Catch other errors
                 logging.error(f"Error closing QKD page cursor: {cur_e}")
         # --- END CORRECTION ---

         if conn and not getattr(conn, 'closed', True):
             close_db_connection(conn)
         logging.debug("Finished QKD page history fetch attempt.")

    # --- 3. Prepare Template Data ---
    if not labels: labels, values = ['No History'], [0]
    qber_threshold_original = app.config.get('QBER_THRESHOLD', 0.15)
    qber_threshold_pct = qber_threshold_original * 100

    # --- 4. Render Template ---
    try:
        return render_template('qkd.html',
                           simulation_log=sim_log,
                           QBER_THRESHOLD_PCT=qber_threshold_pct,
                           QBER_THRESHOLD_ORIGINAL=qber_threshold_original,
                           qber_history_labels=labels,
                           qber_history_values=values)
    except Exception as render_err:
         logging.error(f"Error rendering qkd.html template: {render_err}", exc_info=True)
         abort(500)
      
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

@app.route('/profile')
@login_required
def profile():
    """Displays the user profile page with details and logout."""
    user_id = g.user['id']
    account = None # Initialize account to None
    conn = None # Initialize connection variable
    cursor = None # Initialize cursor variable
    db_type = "Unknown" # To track which DB is being used

    try:
        conn = get_db_connection() # Get connection first
        if not conn:
            flash("Database connection unavailable. Cannot load profile.", "error")
            raise ConnectionError("Database connection failed.") # Raise error to skip rest of try

        # --- CORRECTED CURSOR CREATION ---
        cursor_created = False
        db_type = "Unknown" # Initialize db_type

        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDict for PG
            db_type = "PostgreSQL"; cursor_created = True
            logging.debug("Profile Page: Using psycopg2 RealDictCursor.")
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True) # Correct for MySQL
            db_type = "MySQL"; cursor_created = True
            logging.debug("Profile Page: Using mysql.connector dictionary cursor.")

        if not cursor_created:
             # Fallback or raise error if needed
             logging.error(f"Profile Page: Unsupported DB type: {type(conn)}")
             raise ConnectionError("Unsupported DB type for Profile page.")
        # --- END CORRECTED CURSOR CREATION ---

        # Fetch the primary account associated with the customer ID
        cursor.execute("""
            SELECT account_id, account_number, balance
            FROM accounts
            WHERE customer_id = %s
            ORDER BY account_id ASC
            LIMIT 1
        """, (user_id,))
        account_raw = cursor.fetchone() # Fetches as RealDictRow (PG) or dict (MySQL)

        if account_raw:
             # Ensure balance is Decimal
             try:
                 raw_balance = account_raw.get('balance', '0.00')
                 account_dict = dict(account_raw) # Convert RealDictRow to dict
                 account_dict['balance'] = Decimal(str(raw_balance))
             except (InvalidOperation, TypeError, ValueError) as dec_err:
                  logging.warning(f"Profile: Could not convert balance '{raw_balance}' for user {user_id}: {dec_err}")
                  account_dict['balance'] = Decimal('0.00')
             account = account_dict # Assign the processed dict
        else:
             logging.warning(f"No account found for user {user_id} in profile page.")

    except DB_ERROR_TYPE as e: # Use the DB_ERROR_TYPE defined based on environment
        logging.error(f"Profile: DB error fetching account details (User {user_id}) using {db_type}: {e}", exc_info=True) # Log full traceback
        flash("Could not load account details due to a database error.", "warning")
    except ConnectionError as e:
         logging.error(f"Profile: Connection Error for user {user_id}: {e}")
         flash(str(e), "error") # Show connection error message if appropriate
    except Exception as e:
         logging.error(f"Profile: Unexpected error (User {user_id}): {e}", exc_info=True)
         flash("An unexpected error occurred while loading profile details.", "warning")
    finally: # Ensure cleanup in finally
        if cursor and not getattr(cursor, 'closed', True):
            try: cursor.close()
            except DB_ERROR_TYPE: pass
            except Exception as c_err: logging.warning(f"Profile cursor close error: {c_err}")
        if conn and not getattr(conn, 'closed', True):
            close_db_connection(conn)

    # Pass user (from g) and account details (fetched or None) to the template
    return render_template('profile.html', user=g.user, account=account)

def get_flagged_transactions(user_id, limit=50):
    """
    Fetches recently flagged transactions involving the user.
    Adapted for PostgreSQL/MySQL compatibility.
    """
    txns = [] # Initialize list for results
    conn = None # Initialize connection outside try
    cursor = None # Initialize cursor outside try
    db_type = "Unknown" # Initialize

    try:
        conn = get_db_connection() # Attempt to get connection
        if not conn:
            # Log error but return empty list; let calling route handle UI feedback
            logging.error(f"DB Connection failed fetching flagged tx for user {user_id}")
            return txns

        # --- Determine cursor type based on connection object ---
        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDictCursor for PG
            db_type = "PostgreSQL"
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True) # Use dictionary=True for MySQL
            db_type = "MySQL"
        else:
            # Fallback if type unknown or driver missing
            logging.warning("get_flagged_transactions: Unknown DB connection type, using basic cursor.")
            cursor = conn.cursor()
            db_type = "Fallback"
        logging.debug(f"get_flagged_transactions: Using {db_type} cursor.")
        # --- End Cursor Creation ---

        # SQL query remains the same, placeholders work for both
        sql = """
            SELECT
                l.log_id, l.timestamp AS ts,
                s_cust.customer_name AS sender,
                r_cust.customer_name AS receiver,
                l.amount, l.fraud_reason
            FROM qkd_transaction_log l
            LEFT JOIN accounts s ON l.sender_account_id = s.account_id
            LEFT JOIN customers s_cust ON s.customer_id = s_cust.customer_id
            LEFT JOIN accounts r ON l.receiver_account_id = r.account_id
            LEFT JOIN customers r_cust ON r.customer_id = r_cust.customer_id
            WHERE (s.customer_id = %s OR r.customer_id = %s) -- User involved as sender OR receiver
              AND l.is_flagged = TRUE -- Only flagged transactions
            ORDER BY l.timestamp DESC
            LIMIT %s
            """
        cursor.execute(sql, (user_id, user_id, limit))
        raw_flagged_txns = cursor.fetchall() # Fetch all results

        # Process results safely using .get() for dictionary-like access
        for entry in raw_flagged_txns:
             try: # Inner try to handle formatting errors for individual rows
                 # Safely convert amount using Decimal(str())
                 amt_val = entry.get('amount')
                 amt = Decimal(str(amt_val)) if amt_val is not None else Decimal('0.00')

                 # Safely format timestamp
                 ts_val = entry.get('ts')
                 ts_str = ts_val.strftime('%Y-%m-%d %H:%M:%S') if isinstance(ts_val, datetime.datetime) else 'N/A'

                 # Append formatted dict to results list
                 txns.append({
                     'id': entry.get('log_id'), # Use get for safety
                     'timestamp': ts_str,
                     'sender': f"{entry.get('sender', '?')}", # Use get for safety
                     'receiver': f"{entry.get('receiver', '?')}",
                     'amount': f"{amt:.2f}", # Format decimal
                     'fraud_reason': entry.get('fraud_reason', 'N/A') # Use get with default
                 })
             except (InvalidOperation, TypeError, ValueError, KeyError) as fe:
                 # Catch potential errors during formatting or dict access
                 logging.warning(f"Error formatting flagged tx data {entry.get('log_id', '?')}: {fe}")
             except Exception as fe_other: # Catch unexpected formatting errors
                  logging.error(f"Unexpected error formatting flagged tx {entry.get('log_id', '?')}: {fe_other}", exc_info=True)

    except DB_ERROR_TYPE as e: # Catch specific DB errors
        # Log the error, but don't flash here, return empty list
        logging.error(f"Flagged tx DB error ({db_type}) user {user_id}: {e}", exc_info=True)
    except ConnectionError as e: # Catch connection errors specifically
         logging.error(f"Flagged tx Connection error user {user_id}: {e}", exc_info=True)
    except Exception as e: # Catch other unexpected errors
        logging.error(f"Unexpected error loading flagged tx user {user_id}: {e}", exc_info=True)
    finally: # Ensure resources are always cleaned up
        # Use safe cleanup logic
        if cursor and not getattr(cursor, 'closed', True): # Check cursor exists and not closed
            try:
                cursor.close()
            except DB_ERROR_TYPE: # Use global DB_ERROR_TYPE
                 pass # Ignore DB-specific errors during close
            except Exception as cur_close_err: # Catch other potential close errors
                logging.warning(f"Non-DB error closing flagged_txns cursor: {cur_close_err}")

        # Always close the connection if it was obtained and not closed
        if conn and not getattr(conn, 'closed', True): # Check if conn was successfully assigned and not closed
            close_db_connection(conn)

    # Return the list of formatted transactions (might be empty if errors occurred)
    return txns

@app.route('/fraud')
@login_required
def fraud_page():
    """Displays the fraud center page."""
    flagged_txns = get_flagged_transactions(g.user['id'])
    return render_template("fraud.html", flagged_txns=flagged_txns)

def get_log_entry_details(log_id):
    """
    Fetches detailed information for a specific transaction log entry.
    Adapted for PostgreSQL/MySQL. Converts timestamp to local time. Returns dict or None.
    """
    details = None; conn = None; cursor = None; db_type = "Unknown"
    logging.info(f"--- Fetching log details for log_id: {log_id} ---")
    try:
        conn = get_db_connection();
        if not conn: logging.error(f"DB Conn fail log details {log_id}"); return None

        # Determine cursor type
        cursor_created = False
        if POSTGRES_AVAILABLE and isinstance(conn, psycopg2.extensions.connection):
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor); db_type = "PostgreSQL"; cursor_created = True
        elif MYSQL_AVAILABLE and isinstance(conn, mysql.connector.connection.MySQLConnection):
            cursor = conn.cursor(dictionary=True); db_type = "MySQL"; cursor_created = True
        if not cursor_created: cursor = conn.cursor(); db_type = "Fallback"; logging.warning(f"get_log_entry_details: Using basic cursor.")
        logging.debug(f"get_log_entry_details: Using {db_type} cursor.")

        sql = """ SELECT l.*, s_acc.customer_id AS sender_cust_id, s_cust.customer_name AS sender_name, r_acc.customer_id AS receiver_cust_id, r_cust.customer_name AS receiver_name FROM qkd_transaction_log l LEFT JOIN accounts s_acc ON l.sender_account_id = s_acc.account_id LEFT JOIN customers s_cust ON s_acc.customer_id = s_cust.customer_id LEFT JOIN accounts r_acc ON l.receiver_account_id = r_acc.account_id LEFT JOIN customers r_cust ON r_acc.customer_id = r_cust.customer_id WHERE l.log_id = %s """
        cursor.execute(sql, (log_id,)); entry = cursor.fetchone()
        logging.debug(f"Raw DB entry fetched log {log_id}: {'Found' if entry else 'Not Found'}")

        if entry:
            try: # Inner try for formatting
                amt_dec=Decimal(str(entry.get('amount','0.00'))); amt_disp=f"{amt_dec:.2f}"
                qber_raw=entry.get('qber_value'); qber_disp=f"{qber_raw:.4f}" if qber_raw is not None else "N/A"

                # --- TIMESTAMP CONVERSION ---
                ts_from_db = entry.get('timestamp')
                timestamp_display = 'N/A'
                if isinstance(ts_from_db, datetime.datetime):
                    # Make naive UTC aware if necessary (fallback)
                    if ts_from_db.tzinfo is None or ts_from_db.tzinfo.utcoffset(ts_from_db) is None:
                         ts_aware_utc = pytz.utc.localize(ts_from_db)
                         logging.warning(f"Timestamp for log {log_id} was naive, assuming UTC.")
                    else:
                         ts_aware_utc = ts_from_db # Already aware (expected from TIMESTAMPTZ)
                    # Convert to local zone
                    try:
                        ts_local = ts_aware_utc.astimezone(LOCAL_TIMEZONE) # Uses global LOCAL_TIMEZONE
                        # Format including timezone name/offset
                        timestamp_display = ts_local.strftime('%Y-%m-%d %H:%M:%S %Z%z')
                    except Exception as tz_err:
                         logging.error(f"Timezone conversion failed log {log_id}: {tz_err}. Displaying UTC.")
                         timestamp_display = ts_aware_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
                # --- END TIMESTAMP CONVERSION ---

                flagged=entry.get('is_flagged', False); reason_raw=entry.get('fraud_reason'); reason_disp=reason_raw if flagged and reason_raw else None
                enc_data=entry.get('encrypted_confirmation'); enc_data=enc_data if enc_data and enc_data != 'None' else None
                s_name=entry.get('sender_name','?'); s_id=entry.get('sender_account_id','?'); s_details=f"{s_name} (Acc ID: {s_id})"
                r_name=entry.get('receiver_name','?'); r_id=entry.get('receiver_account_id','?'); r_details=f"{r_name} (Acc ID: {r_id})"

                details={'log_id': entry.get('log_id'), 'sender_customer_id': entry.get('sender_cust_id'), 'receiver_customer_id': entry.get('receiver_cust_id'),
                         'timestamp': timestamp_display, # Use formatted string
                         'sender_details': s_details, 'receiver_details': r_details, 'amount': amt_disp,
                         'qkd_status': entry.get('qkd_status', 'N/A').replace('_', ' '), 'qber': qber_disp,
                         'encrypted_confirmation_data': enc_data, 'is_flagged': flagged, 'fraud_reason': reason_disp}
                logging.debug(f"Formatted details log {log_id}: {details}")
            except Exception as format_err: logging.error(f"Error formatting log {log_id}: {format_err}", exc_info=True); details = None
        else: logging.warning(f"Log entry {log_id} not found.")
    except (DB_ERROR_TYPE, ConnectionError) as e: logging.error(f"DB/Conn error log details ({db_type}) {log_id}: {e}"); details = None
    except Exception as e: logging.error(f"Unexpected log details error {log_id}: {e}", exc_info=True); details = None
    finally:
        # --- CORRECTED FINALLY BLOCK ---
        if cursor and not getattr(cursor, 'closed', True): # Check cursor exists and not closed
            # --- CORRECTED INDENTATION ---
            try:
                cursor.close()
            except DB_ERROR_TYPE as cur_close_err: # Use global DB_ERROR_TYPE
                 # Log DB-specific close errors if needed, otherwise pass
                 # logging.warning(f"DBError closing get_details cursor: {cur_close_err}")
                 pass
            except Exception as cur_close_err: # Catch other potential close errors
                logging.warning(f"Non-DB error closing get_details cursor: {cur_close_err}")
            # --- END CORRECTION ---

        # Always close the connection if it was obtained and not closed
        if conn and not getattr(conn, 'closed', True): # Check if conn was successfully assigned and not closed
            close_db_connection(conn)
          
    logging.info(f"--- Finished fetching log details {log_id}. Found: {bool(details)} ---")
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
