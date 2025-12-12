-- UP MIGRATION
CREATE TABLE IF NOT EXISTS qkd_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    raw_key_length INT,
    qber FLOAT,
    sifted_bits_count INT,
    status VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fraud_audit_log (
    id SERIAL PRIMARY KEY,
    transaction_id INT REFERENCES qkd_transaction_log(log_id),
    ml_score FLOAT,
    reason TEXT,
    features JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- DOWN MIGRATION
-- DROP TABLE IF EXISTS fraud_audit_log;
-- DROP TABLE IF EXISTS qkd_sessions;