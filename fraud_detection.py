# fraud_detection.py
# Module for simple classical fraud detection logic based on transaction patterns.

import datetime
from typing import List, Dict, Any, Optional, Set
from decimal import Decimal, InvalidOperation # Use Decimal for consistency if amounts are Decimal

# --- Configuration Defaults (can be overridden by values from app.config) ---
DEFAULT_AMOUNT_THRESHOLD = 10000.00  # Flag transactions greater than this amount
DEFAULT_RAPID_TRANSACTION_SECONDS = 10 # Flag if transaction occurs within this many seconds of the previous one
DEFAULT_BLACKLIST = {"fraudster_account", "suspicious_user123"} # Example blacklist

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
                   If None, uses DEFAULT_BLACKLIST.
        amount_threshold: Override for the amount threshold. If None, uses DEFAULT_AMOUNT_THRESHOLD.
        rapid_transaction_seconds: Override for the time gap check. If None, uses DEFAULT_RAPID_TRANSACTION_SECONDS.


    Returns:
        A dictionary:
        {
            'is_fraudulent': bool, # True if any rule triggered
            'reason': str | None  # Explanation string if fraudulent (rules concatenated), None otherwise
        }
    """
    # Use provided config or fall back to defaults
    final_blacklist = blacklist if blacklist is not None else DEFAULT_BLACKLIST
    final_amount_threshold = amount_threshold if amount_threshold is not None else DEFAULT_AMOUNT_THRESHOLD
    final_rapid_seconds = rapid_transaction_seconds if rapid_transaction_seconds is not None else DEFAULT_RAPID_TRANSACTION_SECONDS

    reasons = [] # Collect reasons if multiple rules trigger

    # --- Rule 1: Amount Check ---
    try:
        # Handle both float and Decimal inputs gracefully
        current_amount = Decimal(str(current_transaction.get('amount', 0)))
        threshold_decimal = Decimal(str(final_amount_threshold))

        if current_amount > threshold_decimal:
            reasons.append(f"Amount ({current_amount:.2f}) exceeds threshold ({threshold_decimal:.2f})")
    except (InvalidOperation, TypeError, KeyError) as e:
         print(f"Warning: Could not perform amount check due to data issue: {e}")


    # --- Rule 2: Time Gap Check ---
    # Requires sorted history and valid datetime timestamps in both current and last historical transaction
    if user_transaction_history and 'timestamp' in current_transaction:
        try:
            # Get the timestamp of the most recent transaction in the history
            last_txn_time = user_transaction_history[-1].get('timestamp')
            current_time = current_transaction['timestamp'] # Assumes this is a datetime object passed from app.py

            # Ensure both are valid datetime objects before comparing
            if isinstance(last_txn_time, datetime.datetime) and isinstance(current_time, datetime.datetime):
                time_diff = (current_time - last_txn_time).total_seconds()
                # Check if the time difference is positive but less than the threshold
                if 0 <= time_diff < final_rapid_seconds:
                    reasons.append(f"Rapid transaction detected ({time_diff:.1f}s after previous)")
            elif last_txn_time: # Log if types are wrong but data exists
                 print(f"Warning: Timestamps are not datetime objects ({type(last_txn_time)}, {type(current_time)}), skipping time gap check.")

        except (KeyError, TypeError, IndexError) as e:
            print(f"Warning: Error during time gap check: {e}") # Catch potential errors


    # --- Rule 3: Blacklist Check ---
    recipient_username = current_transaction.get('recipient_username')
    if recipient_username and recipient_username in final_blacklist:
        reasons.append(f"Recipient '{recipient_username}' is blacklisted")


    # --- Determine Final Status ---
    is_fraudulent = len(reasons) > 0
    reason_str = "; ".join(reasons) if is_fraudulent else None

    print(f"Fraud Analysis Result: Flagged={is_fraudulent}, Reason='{reason_str}'")

    return {
        'is_fraudulent': is_fraudulent,
        'reason': reason_str
    }

# --- Example Usage (for testing directly) ---
if __name__ == '__main__':
    print("--- Fraud Detection Tests ---")
    # Make sure timestamps are datetime objects for testing
    now = datetime.datetime.now()
    history = [
        {'id': 1, 'amount': Decimal('50.00'), 'recipient_username': 'bob', 'timestamp': now - datetime.timedelta(minutes=5)},
        {'id': 2, 'amount': Decimal('100.00'), 'recipient_username': 'charlie', 'timestamp': now - datetime.timedelta(seconds=30)},
    ]

    print(f"History Length: {len(history)}")
    if history: print(f"Last history timestamp: {history[-1].get('timestamp')}")

    test_txn_1 = {'amount': 15000.0, 'recipient_username': 'dave', 'timestamp': now} # High amount
    test_txn_2 = {'amount': 20.0, 'recipient_username': 'eve', 'timestamp': now - datetime.timedelta(seconds=5)} # Rapid (relative to history[-1])
    test_txn_3 = {'amount': 50.0, 'recipient_username': 'fraudster_account', 'timestamp': now} # Blacklisted recipient
    test_txn_4 = {'amount': 100.0, 'recipient_username': 'frank', 'timestamp': now} # Normal

    # Use default thresholds/blacklist for these tests
    print("\nTest 1 (High Amount):")
    print(detect_fraud(test_txn_1, history))

    print("\nTest 2 (Rapid Transaction):")
    print(detect_fraud(test_txn_2, history))

    print("\nTest 3 (Blacklisted Recipient):")
    print(detect_fraud(test_txn_3, history))

    print("\nTest 4 (Normal Transaction):")
    print(detect_fraud(test_txn_4, history))

    # Example with combined reasons
    print("\nTest 5 (Combined - High Amount, Rapid, Blacklisted):")
    combined_txn = {'amount': 12000.0, 'recipient_username': 'fraudster_account', 'timestamp': now - datetime.timedelta(seconds=3)}
    print(detect_fraud(combined_txn, history))

    # Test edge case: No history
    print("\nTest 6 (No History):")
    print(detect_fraud(test_txn_4, []))

    # Test edge case: Custom Thresholds/Blacklist
    print("\nTest 7 (Custom Config - Lower Threshold, Larger Time Gap, New Blacklist):")
    custom_blacklist = {'dave'}
    custom_amount_thresh = 50.0
    custom_rapid_sec = 60
    print(detect_fraud(
        current_transaction=test_txn_1, # Amount 15000, recipient 'dave'
        user_transaction_history=history,
        blacklist=custom_blacklist,
        amount_threshold=custom_amount_thresh, # Should trigger amount
        rapid_transaction_seconds=custom_rapid_sec # Should NOT trigger time gap
    )) # Expected reasons: Amount; Blacklist
