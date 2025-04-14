# fraud_detection.py
# Orchestrates fraud checks using simple rules and ML model predictions.
# --- VERSION WITH ML INTEGRATION AND CORRECTED LOGGING ---

import datetime
import logging
from typing import Dict, List, Any, Optional, Set

# Import functions from the new ML module
try:
    # Use the function defined in ml_fraud_model.py to check loading status
    from ml_fraud_model import preprocess_input_features, predict_fraud_proba, is_ml_model_loaded
except ImportError as e:
    logging.error(f"Could not import ML model functions: {e}. ML fraud detection disabled.")
    # Define dummy functions if import fails to prevent crashes later
    def preprocess_input_features(*args, **kwargs): return None
    def predict_fraud_proba(*args, **kwargs): return -1.0
    def is_ml_model_loaded(): return False


# --- Configuration ---
# Keep blacklist if desired
DEFAULT_BLACKLIST = {"fraudster_account", "suspicious_user123"} # Example blacklist
# Define a threshold for the ML model's probability score
# This should be tuned based on model performance (precision/recall tradeoff)
ML_FRAUD_THRESHOLD = 0.75 # Example: Flag if predicted probability > 75%

# --- Main Fraud Detection Function ---
def detect_fraud(
    current_transaction: Dict[str, Any], # Contains 'amount', 'timestamp', 'recipient_username'
    user_transaction_history: List[Dict[str, Any]], # List of dicts: 'amount', 'timestamp' (Newest first)
    blacklist: Optional[Set[str]] = None,
    # NOTE: amount_threshold and rapid_transaction_seconds arguments removed
    # as these concepts are now handled by the ML model's features.
) -> Dict[str, Any]:
    """
    Performs fraud checks using a blacklist and a pre-trained ML model.

    Args:
        current_transaction (dict): Details of the transaction to check.
        user_transaction_history (list): Recent history for the user (newest first).
        blacklist (set, optional): Set of blacklisted recipient usernames.

    Returns:
        dict: {'is_fraudulent': bool, 'reason': str | None, 'ml_score': float}
    """
    final_blacklist = blacklist if blacklist is not None else DEFAULT_BLACKLIST
    reasons = []
    ml_score = -1.0 # Default score if prediction fails or model not loaded

    # --- Rule 1: Blacklist Check (Simple Rule - Kept) ---
    recipient_username = current_transaction.get('recipient_username')
    if recipient_username and recipient_username in final_blacklist:
        logging.warning(f"Fraud Check: Recipient '{recipient_username}' is blacklisted.")
        reasons.append(f"Recipient '{recipient_username}' is blacklisted")

    # --- Rule 2: ML Model Prediction ---
    if is_ml_model_loaded():
        logging.debug("ML Model loaded. Proceeding with ML fraud check.")
        # Preprocess data for the model
        input_features_df = preprocess_input_features(current_transaction, user_transaction_history)

        if input_features_df is not None:
            # Get fraud probability from the loaded ML model
            ml_score = predict_fraud_proba(input_features_df)

            if ml_score >= ML_FRAUD_THRESHOLD:
                logging.warning(f"Fraud Check: ML Prediction Score ({ml_score:.3f}) exceeds threshold ({ML_FRAUD_THRESHOLD:.3f}). Flagging transaction.")
                # Add a specific reason indicating ML flag
                reasons.append(f"High ML Fraud Score ({ml_score:.3f})")
            elif ml_score >= 0: # Prediction successful but below threshold
                 logging.info(f"Fraud Check: ML Prediction Score: {ml_score:.3f} (Below Threshold)")
            else: # ml_score is -1.0, indicating prediction error
                 reasons.append("ML Prediction failed") # Add reason
                 logging.error("Fraud Check: ML model prediction failed (returned -1.0).")
        else:
             # Preprocessing failed
             reasons.append("ML Feature preprocessing failed")
             logging.error("Fraud Check: ML feature preprocessing failed.")
    else:
        # Log if model isn't loaded, maybe add to reasons if critical
        logging.warning("Fraud Check: ML Model is not loaded. Skipping ML prediction.")
        # Decide if 'ML Model not available' should be a flagging reason
        # For now, let's not add it automatically, rely on other rules or config
        reasons.append("ML Model not available") # Add reason if model not loaded

    # --- Determine Final Status ---
    # Flag if blacklist OR ML model score exceeds threshold.
    # Errors during ML process (preprocessing/prediction failure/model not loaded) also currently lead to flagging
    # because they add to the 'reasons' list.
    is_fraudulent = len(reasons) > 0

    # Combine reasons for logging/storage
    reason_str = "; ".join(reasons) if is_fraudulent else None

    # --- CORRECTED LOGGING ---
    # Determine the string representation for the score *before* the f-string
    ml_score_str = f"{ml_score:.3f}" if ml_score >= 0 else 'N/A'
    # Use the pre-formatted string in the log message
    logging.info(f"Final Fraud Detection Result: Flagged={is_fraudulent}, Reason='{reason_str}', ML Score={ml_score_str}")
    # --- END CORRECTION ---

    return {
        'is_fraudulent': is_fraudulent,
        'reason': reason_str,
        'ml_score': ml_score # Return score (-1.0 indicates error/not run)
    }

# --- END OF fraud_detection.py FILE ---
