-- UP MIGRATION
ALTER TABLE qkd_transaction_log 
ADD COLUMN IF NOT EXISTS transaction_state VARCHAR(50) DEFAULT 'INIT',
ADD COLUMN IF NOT EXISTS key_fingerprint VARCHAR(255),
ADD COLUMN IF NOT EXISTS ml_score FLOAT,
ADD COLUMN IF NOT EXISTS pqc_used BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS hybrid_key_hash VARCHAR(255),
ADD COLUMN IF NOT EXISTS ciphertext_length INT,
ADD COLUMN IF NOT EXISTS replay_nonce VARCHAR(255),
ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);

-- Create Index for faster lookup
CREATE INDEX IF NOT EXISTS idx_txn_session ON qkd_transaction_log(session_id);

-- DOWN MIGRATION (Rollback)
-- ALTER TABLE qkd_transaction_log 
-- DROP COLUMN IF EXISTS transaction_state,
-- DROP COLUMN IF EXISTS key_fingerprint,
-- DROP COLUMN IF EXISTS ml_score,
-- DROP COLUMN IF EXISTS pqc_used,
-- DROP COLUMN IF EXISTS hybrid_key_hash,
-- DROP COLUMN IF EXISTS ciphertext_length,
-- DROP COLUMN IF EXISTS replay_nonce,
-- DROP COLUMN IF EXISTS session_id;