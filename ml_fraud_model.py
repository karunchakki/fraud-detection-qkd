# ml_fraud_model.py
# Handles loading and predicting with the pre-trained ML fraud model.

import joblib
import pandas as pd
import os
import logging
import datetime
from typing import Dict, List, Optional

# --- Configuration ---
MODEL_DIR = os.path.dirname(__file__)
MODEL_FILENAME = 'fraud_model.joblib'
FEATURES_FILENAME = 'fraud_model_features.joblib'
MODEL_PATH = os.path.join(MODEL_DIR, MODEL_FILENAME) if MODEL_DIR else MODEL_FILENAME
FEATURES_PATH = os.path.join(MODEL_DIR, FEATURES_FILENAME) if MODEL_DIR else FEATURES_FILENAME

# --- Globals for Loaded Model/Features ---
_fraud_model = None
_model_features = None
_model_loaded = False

def load_model() -> bool:
    """Loads the trained fraud detection model and feature list. Returns True on success."""
    global _fraud_model, _model_features, _model_loaded
    if _model_loaded:
        logging.debug("ML Model already loaded.")
        return True # Already loaded

    try:
        logging.info(f"Attempting to load fraud model from: {MODEL_PATH}")
        if not os.path.exists(MODEL_PATH):
             raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
        _fraud_model = joblib.load(MODEL_PATH)

        logging.info(f"Attempting to load features from: {FEATURES_PATH}")
        if not os.path.exists(FEATURES_PATH):
             raise FileNotFoundError(f"Features file not found at {FEATURES_PATH}")
        _model_features = joblib.load(FEATURES_PATH)

        _model_loaded = True
        logging.info(f"Fraud detection model and features ({len(_model_features)} features) loaded successfully.")
        logging.info(f"Model expects features: {_model_features}")
        return True
    except FileNotFoundError as e:
        logging.error(f"ML MODEL LOADING FAILED: {e}. Ensure '{MODEL_FILENAME}' and '{FEATURES_FILENAME}' are in the correct directory relative to the running script.")
        _fraud_model = None; _model_features = None; _model_loaded = False
        return False
    except Exception as e:
        logging.error(f"Error loading fraud model: {e}", exc_info=True)
        _fraud_model = None; _model_features = None; _model_loaded = False
        return False

def is_ml_model_loaded() -> bool:
    """Checks if the ML model has been loaded successfully."""
    return _model_loaded and _fraud_model is not None and _model_features is not None

def preprocess_input_features(current_transaction: dict, user_history: list) -> Optional[pd.DataFrame]:
    """
    Prepares the input features DataFrame for the ML model prediction.

    Args:
        current_transaction: Dict with 'amount' (Decimal/float), 'timestamp' (datetime).
        user_history: List of recent transaction dicts with 'amount' (Decimal/float), 'timestamp' (datetime).
                      (Sorted newest first).

    Returns:
        A pandas DataFrame with one row and columns matching _model_features,
        or None if features cannot be calculated or model not loaded.
    """
    logging.debug(f"Entering preprocess_input_features...")
    if not is_ml_model_loaded():
        logging.error("ML Model not loaded, cannot preprocess features.")
        return None

    try:
        features = {}
        now = current_transaction.get('timestamp', datetime.datetime.now())
        logging.debug(f"Preprocessing features: Current Tx Amount={current_transaction.get('amount')}, History Count={len(user_history)}")

        # --- Feature Engineering (Must MATCH offline training) ---
        features['TransactionAmount'] = float(current_transaction.get('amount', 0.0))
        features['TransactionHour'] = now.hour

        # Calculate TransactionGap (in days)
        last_txn_time = user_history[0]['timestamp'] if user_history else None
        if isinstance(last_txn_time, datetime.datetime) and isinstance(now, datetime.datetime):
             time_diff_seconds = (now - last_txn_time).total_seconds()
             features['TransactionGap'] = max(0, time_diff_seconds) / (60.0 * 60.0 * 24.0)
        else:
             features['TransactionGap'] = 999.0 # Default gap used in training
        logging.debug(f"Calculated TransactionGap: {features['TransactionGap']:.4f} days")

        # Rolling features (sum/count over last 5 available history points)
        rolling_window = 5
        relevant_history = [tx for tx in user_history
                            if isinstance(tx.get('timestamp'), datetime.datetime) and tx['timestamp'] < now]
        relevant_history = relevant_history[:rolling_window]
        amounts_in_window = [float(tx.get('amount', 0.0)) for tx in relevant_history]

        features['sum_5days'] = sum(amounts_in_window)
        features['count_5days'] = len(amounts_in_window)
        logging.debug(f"Calculated Rolling Features: sum_5days={features['sum_5days']:.2f}, count_5days={features['count_5days']}")

        # --- Create DataFrame in correct order ---
        input_data = {}
        missing_features = []
        for feature_name in _model_features:
            if feature_name in features:
                input_data[feature_name] = features[feature_name]
            else:
                missing_features.append(feature_name)
                input_data[feature_name] = 0 # Defaulting missing feature to 0

        if missing_features:
             logging.error(f"CRITICAL: Features missing during preprocessing: {missing_features}. Check alignment with training features: {_model_features}")
             return None

        df_input = pd.DataFrame([input_data], columns=_model_features)
        logging.debug(f"Returning preprocessed DataFrame:\n{df_input.to_string()}")
        return df_input

    except Exception as e:
        logging.error(f"Error during feature preprocessing for prediction: {e}", exc_info=True)
        return None

def predict_fraud_proba(input_df: pd.DataFrame) -> float:
    """
    Makes a fraud prediction using the loaded model.

    Args:
        input_df: A pandas DataFrame with features matching the model's training.

    Returns:
        The probability of the transaction being fraudulent (float between 0 and 1),
        or -1.0 if prediction fails or model not loaded.
    """
    logging.debug("Entering predict_fraud_proba...")
    if not is_ml_model_loaded():
        logging.error("ML Model not loaded, cannot make prediction.")
        return -1.0

    if input_df is None or input_df.empty:
         logging.error("Invalid input DataFrame provided for prediction.")
         return -1.0

    try:
        logging.debug(f"Predicting fraud probability for input:\n{input_df.to_string()}")
        # Ensure input_df has the exact columns in the exact order expected by the model
        input_df_ordered = input_df[_model_features]

        probabilities = _fraud_model.predict_proba(input_df_ordered)
        if probabilities.shape == (1, 2):
            fraud_probability = probabilities[0, 1] # Probability of class 1 (fraud)
            logging.debug(f"Predicted fraud probability: {fraud_probability:.4f}")
            return float(fraud_probability)
        else:
            logging.error(f"Unexpected probability shape from model: {probabilities.shape}")
            return -1.0
    except KeyError as e:
         logging.error(f"Feature mismatch during prediction. Model needs {e}. Input has {list(input_df.columns)}", exc_info=True)
         return -1.0
    except Exception as e:
        logging.error(f"Error during model prediction: {e}", exc_info=True)
        return -1.0
