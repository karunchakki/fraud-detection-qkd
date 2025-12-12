-- This ensures your log table matches the new architecture
CREATE TABLE IF NOT EXISTS qkd_transaction_log (
    log_id SERIAL PRIMARY KEY,
    sender_account_id INT,
    receiver_account_id INT,
    amount DECIMAL(10, 2),
    qkd_status VARCHAR(20),
    qber_value FLOAT,
    is_flagged BOOLEAN,
    fraud_reason VARCHAR(255),
    encrypted_confirmation TEXT,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    -- New Fields for Patent
    key_fingerprint VARCHAR(64),
    ml_score FLOAT
);