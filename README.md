QKD Secure Banking Simulation
    This project simulates the integration of Quantum Key Distribution (QKD) using the BB84 protocol and Machine Learning (ML) for fraud detection within a Flask-based secure banking web application.
    
    It explores how quantum principles can secure key exchanges in banking, while classical ML models identify suspicious financial behavior.
    
    Note: This is an educational simulation. QKD is simulated using Qiskit, and the ML model may be trained on synthetic data. The app is not secure for real-world banking and lacks production-level security features.

🔐 Key Features
    User Authentication: Registration, login, hashed passwords, and password recovery.
    
    Database Integration: MySQL for storing user data, account details, and transactions.
    
    BB84 QKD Simulation: Simulated quantum key exchange using Qiskit; checks QBER to detect eavesdropping.
    
    Secure Transactions: AES encryption using keys derived from successful QKD.
    
    Fraud Detection: Random Forest Classifier flags suspicious transactions.
    
    PDF Reporting: Auto-generates reports for QKD events and transactions.
    
    Modern UI: Built using Flask, Tailwind CSS, and Jinja2 templates.
    
    Risk Simulation (Basic): Placeholder tools for risk analysis and CVaR calculations.
    
    Deployment-Ready: Includes wsgi.py for Gunicorn or Waitress deployment.

🗂 Folder Structure
    /
    ├── .env                       # Environment variables (secret key, DB credentials)
    ├── .env.example              # Example .env file
    ├── .gitignore                # Git ignore rules
    ├── app.py                    # Main Flask application
    ├── fraud_detection.py        # Fraud detection orchestration
    ├── ml_fraud_model.py         # Loads ML model & features, makes predictions
    ├── pdf_generator.py          # Generates PDF reports
    ├── qkd_simulation.py         # Simulates BB84 QKD
    ├── requirements.txt          # Python dependencies
    ├── risk_simulation.py        # Placeholder financial risk analysis
    ├── schema.sql                # MySQL schema setup
    ├── train_fraud_model.py      # ML model training script
    ├── wsgi.py                   # WSGI server entry point
    ├── fraud_model.joblib        # Trained fraud detection model
    ├── fraud_model_features.joblib # ML feature list
    │
    ├── static/
    │   ├── css/styles.css        # Custom styles
    │   └── js/
    │       ├── qkd.js            # Charts for QKD page
    │       └── script.js         # Global JS (UI toggles, etc.)
    │
    └── templates/
        ├── base.html             # Main layout
        ├── index.html            # Dashboard
        ├── login.html            # Login form
        ├── register.html         # Registration form
        ├── forgot_password.html  # Password recovery
        ├── reset_password.html   # Password reset
        ├── history.html          # Transaction history
        ├── fraud.html            # Fraud report page
        ├── qkd.html              # QKD simulation details
        ├── quantum_impact.html   # Info page
        ├── about.html            # About page
        ├── report.html           # PDF download confirmation
        ├── risk_analysis.html    # Risk analysis results
        └── partials/_flashes.html # Flash messages

---

## 🛠️ Setup Guide

### 1. Prerequisites

    - **Python 3.9+**
    - **MySQL Server** (with admin access)
    - **Git**
    - *(Optional)*: `bank_transactions_data_2.csv` — required to retrain ML model.

### 2. Clone the Repository

    ```bash
    git clone https://github.com/karunchakki/fraud-detection-qkd.git
    cd fraud-detection-qkd

3. Set Up a Virtual Environment

    # Create
    python -m venv venv
    
    # Activate
    # Windows:
    venv\Scripts\activate
    
    # macOS/Linux:
    source venv/bin/activate

4. Install Dependencies
    
    pip install -r requirements.txt

5. Configure MySQL
    Log in to MySQL as root and run:
    
    CREATE DATABASE IF NOT EXISTS qkd_bank_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    
    CREATE USER 'qkd_app_user'@'localhost' IDENTIFIED BY 'your_secure_password';
    
    GRANT ALL PRIVILEGES ON qkd_bank_db.* TO 'qkd_app_user'@'localhost';
    FLUSH PRIVILEGES;
    
    Then, from your terminal:
    
    mysql -u qkd_app_user -p qkd_bank_db < schema.sql

6. Setup Environment Variables
    # Windows:
    copy .env.example .env
    
    # macOS/Linux:
    cp .env.example .env

    Then edit .env and set:

    FLASK_SECRET_KEY= (generate via python -c "import secrets; print(secrets.token_hex(24))")  
    MYSQL_USER=qkd_app_user
    MYSQL_PASSWORD=your_secure_password
    MYSQL_DB=qkd_bank_db
    Adjust QBER_THRESHOLD or FRAUD_BLACKLIST if needed.

7. Train the ML Model
   python train_fraud_model.py

8. Run the App
   Using Waitress (Recommended):
    waitress-serve --host=0.0.0.0 --port=5001 wsgi:app

Access in browser: http://127.0.0.1:5001

💡 Usage Tips
    Register multiple users to simulate transfers.
    Enable "Simulate Eavesdropper" during transfer to test QKD failure due to high QBER.
    Monitor terminal logs for QKD and ML decision details.
    Explore all pages: QKD, Risk Analysis, History, Fraud Report, etc.
    PDF downloads are available post-transfer and QKD sim.

🧱 Tech Stack
    Backend: Python, Flask
    Frontend: HTML, Tailwind CSS (via CDN), Jinja2
    Database: MySQL
    Quantum Simulation: Qiskit (BB84 protocol)
    ML & Data: Scikit-learn, Joblib, Pandas, NumPy
    PDFs: ReportLab
    Forms: Flask-WTF, WTForms
    Encryption: Fernet (AES), Werkzeug
    Server: Waitress (for production)

