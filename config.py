import os

class Config:
    # App Settings
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev_key_change_in_prod')
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    # Feature Flags (Safe Deployment)
    USE_MODULAR_BACKEND = os.environ.get('USE_MODULAR_BACKEND', 'False').lower() == 'true'
    ENABLE_TRUE_QRNG = os.environ.get('ENABLE_TRUE_QRNG', 'True').lower() == 'true'
    
    # Security Parameters
    QBER_THRESHOLD = float(os.environ.get('QBER_THRESHOLD', 0.15))
    ML_RISK_THRESHOLD = float(os.environ.get('ML_RISK_THRESHOLD', 0.5))
    SESSION_LIFETIME_MINUTES = int(os.environ.get('SESSION_LIFETIME_MINUTES', 30))
    
    # Mail Config
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
