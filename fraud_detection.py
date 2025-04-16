# fraud_detection.py
import logging
import datetime
from decimal import Decimal, InvalidOperation # Added InvalidOperation
from typing import List, Dict, Any # Added Type Hinting

# Import the specific functions needed from ml_fraud_model
# Use a try-except block in case the module itself has import issues
try:
    # Import with alias to potentially avoid namespace conflicts if needed later
    from ml_fraud_model import predict_fraud as ml_predict_fraud, \
                               is_ml_model_loaded, \
                               load_model as load_ml_model_explicitly
except ImportError as e:
    logging.critical(f"Failed to import from ml_fraud_model.py: {e}. ML Fraud detection will be disabled.")
    # Define dummy functions if import fails, ensuring the app doesn't crash
    def ml_predict_fraud(transaction_data: dict) -> tuple[int, float | None]: return (0, None) # Return type hint updated
    def is_ml_model_loaded() -> bool: return False
    def load_ml_model_explicitly() -> bool: return False


# --- Configuration / Rules (Example - Adjust as needed) ---
HIGH_AMOUNT_THRESHOLD = Decimal('5000.00') # Example threshold
KNOWN_RISKY_RECIPIENT_KEYWORDS = ['suspicious', 'risky_test', 'scammer']
MIN_HISTORY_FOR_VELOCITY = 1 # Need at least 1 previous txn to check gap (changed from 2)
RAPID_TRANSACTION_THRESHOLD_SECONDS = 120 # Flag if txns within 2 minutes (THIS RULE WILL BE DISABLED BELOW)

# --- Helper Functions ---
def append_reason(existing_reason: str | None, new_flag: str) -> str:
    """Helper to safely append a new reason flag to existing reasons."""
    if not existing_reason or existing_reason == "Passed":
        return new_flag
    # Avoid duplicate reasons if the same rule flags multiple times (unlikely here)
    if new_flag in existing_reason.split(';'):
         return existing_reason
    return f"{existing_reason};{new_flag}"

def apply_rules(current_transaction: Dict[str, Any], user_history: List[Dict[str, Any]], config: Dict[str, Any] = None) -> List[str]:
    """Applies rule-based checks to a transaction."""
    flags = []
    config = config or {} # Ensure config is a dict

    try:
        # Ensure amount is Decimal or float for comparisons
        try:
            amount = Decimal(current_transaction.get('amount', 0))
        except (InvalidOperation, TypeError) as e:
            logging.warning(f"Could not parse transaction amount for rules: {current_transaction.get('amount')} - {e}")
            amount = Decimal('0.0') # Default to 0 if parsing fails

        recipient = str(current_transaction.get('recipient_username', '')).lower() # Ensure string and lowercase
        now = current_transaction.get('timestamp', datetime.datetime.now())
        if not isinstance(now, datetime.datetime): # Ensure timestamp is datetime
             logging.warning("Invalid timestamp in current_transaction, using current time for rules.")
             now = datetime.datetime.now()

        # --- Rule: High Amount ---
        if amount > HIGH_AMOUNT_THRESHOLD:
            flags.append(f"Rule:HighAmount>{HIGH_AMOUNT_THRESHOLD}")

        # --- Rule: Risky Recipient Keyword ---
        if KNOWN_RISKY_RECIPIENT_KEYWORDS and recipient: # Check if list is not empty and recipient exists
            if any(keyword in recipient for keyword in KNOWN_RISKY_RECIPIENT_KEYWORDS):
                flags.append("Rule:RiskyRecipientKeyword")

        # --- Rule: Blacklist (using config passed from app.py) ---
        blacklist = config.get('blacklist', set())
        if blacklist and recipient in blacklist: # Check if blacklist has items
             flags.append("Rule:RecipientBlacklisted")

        # --- Rule: Velocity Check (Rapid Transaction) ---
        # ***** MODIFICATION: DISABLING THIS RULE FOR DEMO *****
        # if len(user_history) >= MIN_HISTORY_FOR_VELOCITY: # Check if enough history exists
        #     try:
        #         last_txn_ts = user_history[0].get('timestamp') # History should be sorted newest first
        #         if isinstance(last_txn_ts, datetime.datetime):
        #             time_diff = (now - last_txn_ts).total_seconds()
        #             if 0 <= time_diff < RAPID_TRANSACTION_THRESHOLD_SECONDS: # Allow 0 difference? Maybe > 0?
        #                  # More checks could be added: e.g., is amount similar? Is recipient the same?
        #                  flags.append(f"Rule:RapidTransaction<{RAPID_TRANSACTION_THRESHOLD_SECONDS}s")
        #                  logging.info(f"Flagged rapid transaction: {time_diff:.1f}s since last.")
        #         else:
        #              logging.warning("Could not perform velocity check: last transaction timestamp invalid format.")
        #     except (TypeError, KeyError, IndexError) as vel_err:
        #          logging.warning(f"Could not perform velocity check due to data issue in history: {vel_err}")
        # ***** END MODIFICATION *****

        # Add more rules here based on features available

    except Exception as rule_err:
        logging.error(f"Error during rule application: {rule_err}", exc_info=True)
        flags.append("Rule:ErrorInRuleCheck") # Flag if rules engine encounters an error

    logging.debug(f"Rule check completed. Flags generated: {flags}")
    return flags


# --- Main Detection Function ---
def detect_fraud(current_transaction: Dict[str, Any], user_transaction_history: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    """
    Orchestrates fraud detection using rules and ML model.

    Args:
        current_transaction (dict): Details of the transaction being checked.
                                    Expected keys: 'amount', 'recipient_username', 'timestamp', etc.
                                    (features needed by rules and ML model).
        user_transaction_history (list): List of recent transaction dicts for the user.
                                         Expected keys: 'amount', 'timestamp', etc.
                                         Should be sorted newest transaction first.
        **kwargs: Additional configuration like 'blacklist'.

    Returns:
        dict: {'is_fraudulent': bool, 'reason': str, 'ml_score': float (-1.0 if N/A)}
    """
    tx_amount = current_transaction.get('amount', 'N/A')
    logging.info(f"Starting fraud detection for Tx Amount: {tx_amount}")

    # Initialize results
    is_flagged = False
    final_reason = "Passed" # Default reason if nothing flags
    ml_score = -1.0 # Default score indicating ML wasn't used, failed, or model doesn't provide scores
    rule_reason_part = ""
    ml_reason_part = ""

    # --- 1. Apply Rules ---
    try:
        rule_flags = apply_rules(current_transaction, user_transaction_history, config=kwargs)
        if rule_flags:
            is_flagged = True # Flag if any rule matched
            rule_reason_part = ";".join(rule_flags) # Combine rule reasons
            logging.info(f"Rule-based checks flagged the transaction. Reasons: {rule_reason_part}")
        else:
             logging.info("Rule-based checks passed.")
    except Exception as e:
         logging.error(f"Critical error during rule application phase: {e}", exc_info=True)
         is_flagged = True # Flag if rules engine fails catastrophically
         rule_reason_part = "Rule:CriticalRuleEngineError"


    # --- 2. Apply ML Model (if available) ---
    ml_prediction = 0 # Default prediction (not fraud) if ML fails or isn't used
    ml_available = is_ml_model_loaded() # Check if the model object is loaded
    logging.debug(f"ML Model loaded status check: {ml_available}")

    if ml_available:
        try:
            # Pass the current transaction dict directly.
            # ml_predict_fraud should handle feature extraction/preprocessing.
            prediction_result = ml_predict_fraud(current_transaction)

            # Expected result: tuple (prediction, probability_or_None) or (0, None) on error
            if prediction_result == (0, None):
                 logging.warning("ML prediction function indicated an internal error (returned 0, None).")
                 ml_reason_part = "ML:PredictionError"
                 # POLICY DECISION: Flag if ML errors out? Yes.
                 is_flagged = True
            elif prediction_result is not None:
                 ml_prediction, ml_score_nullable = prediction_result
                 ml_score = ml_score_nullable if ml_score_nullable is not None else -1.0 # Use score if provided

                 logging.info(f"ML Model Prediction: Class={ml_prediction}, Score={ml_score:.4f}")
                 if ml_prediction == 1: # 1 indicates fraud according to the model
                     is_flagged = True # Flag if ML predicts fraud
                     ml_reason_part = f"ML:Flagged(Score:{ml_score:.2f})"
                 else:
                      ml_reason_part = "ML:Passed" # Explicitly note ML passed
            else:
                 # Should not happen if ml_predict_fraud returns correctly, but handle defensively
                 logging.error("ML prediction function returned None unexpectedly.")
                 ml_reason_part = "ML:UnexpectedReturn"
                 is_flagged = True # Flag if ML return value is malformed

        except Exception as ml_err:
            logging.error(f"Exception during ML prediction execution: {ml_err}", exc_info=True)
            ml_reason_part = "ML:ExecutionError"
            # POLICY DECISION: Flag if ML execution fails? Yes.
            is_flagged = True
    else:
        # Model was not loaded at startup or check failed
        logging.warning("ML Model is not available or failed load check. Skipping ML prediction.")
        ml_reason_part = "ML:Unavailable"
        # POLICY DECISION: Flag if model is unavailable? Depends. For this demo, let's say Yes.
        is_flagged = True


    # --- 3. Combine Reasons and Final Result ---
    if is_flagged:
        # Combine rule and ML reasons if both exist
        if rule_reason_part and ml_reason_part:
             final_reason = f"{rule_reason_part};{ml_reason_part}"
        elif rule_reason_part: # Only rules flagged (or ML passed but rules failed)
             final_reason = rule_reason_part
        elif ml_reason_part: # Only ML flagged (or rules passed but ML failed/flagged)
             final_reason = ml_reason_part
        else: # Should not happen if is_flagged is True, but fallback
             final_reason = "Flagged:UnknownReason"
    else:
         # If not flagged by either, indicate both passed (if ML was available)
         if ml_available:
             final_reason = "Passed(Rules+ML)"
         else:
             final_reason = "Passed(RulesOnly)" # ML was unavailable

    logging.info(f"Fraud Detection Final Result: Flagged={is_flagged}, Reason='{final_reason}', ML Score={ml_score:.4f}")
    return {
        'is_fraudulent': is_flagged,
        'reason': final_reason,
        'ml_score': ml_score # Return the score (or -1.0)
    }

# Optional: Explicitly load model if needed outside Flask app context (for testing)
# if __name__ == "__main__":
#     print("Attempting to load ML model directly...")
#     if load_ml_model_explicitly():
#         print("Model loaded via direct call.")
#     else:
#         print("Model failed to load via direct call.")
