# fraud_detection.py
# Module for simple classical fraud detection logic based on transaction patterns.

import datetime
from typing import List, Dict, Any, Optional, Set
from decimal import Decimal, InvalidOperation # Use Decimal for consistency if amounts are Decimal

# --- Configuration Defaults (can be overridden by values passed from app.config) ---
DEFAULT_AMOUNT_THRESHOLD = 10000.00  # Flag transactions greater than this amount
DEFAULT_RAPID_TRANSACTION_SECONDS = 10 # Flag if transaction occurs within this many seconds of the previous one
DEFAULT_BLACKLIST = {"fraudster_account", "suspicious_user123"} # Example blacklist usernames

# --- Main Fraud Detection Function ---

def detect_fraud(
    current_transaction: Dict[str, Any],
    user_transaction_history: List[Dict[str, Any]],
    blacklist: Optional[Set[str]] = None,
    amount_threshold: Optional[float] = None,
    rapid_transaction_seconds: Optional[int] = None
) -> Dict[str, Any]:
    """
    Analyzes a single NEW transaction against simple fraud rules using historical context.

    Args:
        current_transaction: Dictionary representing the transaction to check.
                             Expected keys: 'amount' (float or Decimal),
                                            'recipient_username' (str),
                                            'timestamp' (datetime.datetime).
        user_transaction_history: List of previous transactions for the same user,
                                  sorted chronologically (oldest to newest).
                                  Each element is a dict, expected keys:
                                  'amount', 'timestamp' (datetime.datetime).
        blacklist: A set of recipient usernames considered high-risk or fraudulent.
                   If None, uses DEFAULT_BLACKLIST defined in this module.
        amount_threshold: Override for the amount threshold. If None, uses DEFAULT_AMOUNT_THRESHOLD.
        rapid_transaction_seconds: Override for the time gap check. If None, uses DEFAULT_RAPID_TRANSACTION_SECONDS.


    Returns:
        A dictionary:
        {
            'is_fraudulent': bool, # True if any rule triggered
            'reason': str | None  # Explanation string if fraudulent (rules concatenated), None otherwise
        }
    """
    # Use provided config values if passed, otherwise fall back to module defaults
    final_blacklist = blacklist if blacklist is not None else DEFAULT_BLACKLIST
    final_amount_threshold = amount_threshold if amount_threshold is not None else DEFAULT_AMOUNT_THRESHOLD
    final_rapid_seconds = rapid_transaction_seconds if rapid_transaction_seconds is not None else DEFAULT_RAPID_TRANSACTION_SECONDS

    reasons = [] # List to collect reasons if multiple rules trigger

    # --- Rule 1: Amount Check ---
    try:
        # Convert amount to Decimal for reliable comparison, handle potential errors
        current_amount = Decimal(str(current_transaction.get('amount', 0)))
        threshold_decimal = Decimal(str(final_amount_threshold))

        if current_amount > threshold_decimal:
            reasons.append(f"Amount ({current_amount:.2f}) exceeds threshold ({threshold_decimal:.2f})")
    except (InvalidOperation, TypeError, KeyError, ValueError) as e:
         # Catch potential errors during conversion or key access
         print(f"Warning: Could not perform amount check due to data issue: {e}")

    # --- Rule 2: Time Gap Check ---
    # Requires sorted history and valid datetime timestamps in both current and last historical transaction
    if user_transaction_history and 'timestamp' in current_transaction:
        try:
            # Get the timestamp of the *most recent* transaction in the history (last element)
            last_txn = user_transaction_history[-1]
            last_txn_time = last_txn.get('timestamp')
            current_time = current_transaction['timestamp'] # Assumes this is a datetime object passed from app.py

            # Ensure both are valid datetime objects before calculating difference
            if isinstance(last_txn_time, datetime.datetime) and isinstance(current_time, datetime.datetime):
                time_diff = (current_time - last_txn_time).total_seconds()
                # Check if the time difference is positive (current is after last) but less than the threshold
                if 0 <= time_diff < final_rapid_seconds:
                    reasons.append(f"Rapid transaction detected ({time_diff:.1f}s after previous)")
            elif last_txn_time: # Log if types are wrong but data exists, preventing comparison
                 print(f"Warning: Timestamps are not valid datetime objects ({type(last_txn_time)}, {type(current_time)}), skipping time gap check.")

        except (KeyError, TypeError, IndexError) as e:
            # Catch potential errors if history is malformed or keys are missing
            print(f"Warning: Error during time gap check: {e}")

    # --- Rule 3: Blacklist Check ---
    recipient_username = current_transaction.get('recipient_username')
    if recipient_username and recipient_username in final_blacklist:
        reasons.append(f"Recipient '{recipient_username}' is blacklisted")

    # --- Determine Final Status ---
    is_fraudulent = len(reasons) > 0 # Flagged if any reason was added
    reason_str = "; ".join(reasons) if is_fraudulent else None # Combine reasons if flagged

    # Log the outcome of this specific check
    print(f"Fraud Detection Check: Flagged={is_fraudulent}, Reason='{reason_str}'")

    # Return the result dictionary
    return {
        'is_fraudulent': is_fraudulent,
        'reason': reason_str
    }

# --- Example Usage (for testing the module directly) ---
if __name__ == '__main__':
    print("--- Fraud Detection Module Tests ---")
    # Make sure timestamps are datetime objects for testing
    now = datetime.datetime.now()
    # Sample history data (oldest first)
    history_sample = [
        {'id': 1, 'amount': Decimal('50.00'), 'recipient_username': 'bob', 'timestamp': now - datetime.timedelta(minutes=5)},
        {'id': 2, 'amount': Decimal('100.00'), 'recipient_username': 'charlie', 'timestamp': now - datetime.timedelta(seconds=30)},
    ]

    print(f"Test History Length: {len(history_sample)}")
    if history_sample: print(f"Last history timestamp: {history_sample[-1].get('timestamp')}")

    # Test cases
    test_txn_1 = {'amount': 15000.0, 'recipient_username': 'dave', 'timestamp': now} # High amount
    test_txn_2 = {'amount': 20.0, 'recipient_username': 'eve', 'timestamp': now - datetime.timedelta(seconds=5)} # Rapid (relative to history_sample[-1])
    test_txn_3 = {'amount': 50.0, 'recipient_username': 'fraudster_account', 'timestamp': now} # Blacklisted recipient
    test_txn_4 = {'amount': 100.0, 'recipient_username': 'frank', 'timestamp': now} # Should be normal

    # Run tests using default thresholds/blacklist from this module
    print("\nTest 1 (High Amount):")
    print(detect_fraud(test_txn_1, history_sample))

    print("\nTest 2 (Rapid Transaction):")
    print(detect_fraud(test_txn_2, history_sample))

    print("\nTest 3 (Blacklisted Recipient):")
    print(detect_fraud(test_txn_3, history_sample))

    print("\nTest 4 (Normal Transaction):")
    print(detect_fraud(test_txn_4, history_sample))

    # Example combining multiple reasons
    print("\nTest 5 (Combined - High Amount, Rapid, Blacklisted):")
    combined_txn = {'amount': 12000.0, 'recipient_username': 'fraudster_account', 'timestamp': now - datetime.timedelta(seconds=3)}
    print(detect_fraud(combined_txn, history_sample))

    # Test edge case: No prior transaction history
    print("\nTest 6 (No History - Time gap check should be skipped):")
    print(detect_fraud(test_txn_4, []))

    # Test edge case: Passing custom configuration overrides
    print("\nTest 7 (Custom Config - Lower Threshold, Larger Time Gap, New Blacklist):")
    custom_blacklist_set = {'dave'}
    custom_amount_threshold_val = 50.0
    custom_rapid_seconds_val = 60 # Increase time gap allowance
    print(detect_fraud(
        current_transaction=test_txn_1, # Amount 15000, recipient 'dave'
        user_transaction_history=history_sample,
        blacklist=custom_blacklist_set, # Should trigger blacklist
        amount_threshold=custom_amount_threshold_val, # Should trigger amount
        rapid_transaction_seconds=custom_rapid_seconds_val # Should NOT trigger time gap now
    ))
    # Expected result: is_fraudulent=True, Reason includes Amount and Blacklist

    print("\n--- End Fraud Detection Tests ---")
