# ml_fraud_model.py
# Handles loading the pre-trained ML fraud detection PIPELINE
# and making predictions.

import joblib
import pandas as pd
import os
import logging
import datetime
from decimal import Decimal # Import Decimal for type checking if needed
from typing import List, Optional, Tuple, Any

# --- Configuration ---
# Determine directory relative to this file
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILENAME = 'fraud_model.joblib'
FEATURES_FILENAME = 'fraud_model_features.joblib' # Stores the *output* feature names from the preprocessor
MODEL_PATH = os.path.join(MODEL_DIR, MODEL_FILENAME)
FEATURES_PATH = os.path.join(MODEL_DIR, FEATURES_FILENAME)

# --- Globals for Loaded Model/Features ---
# _pipeline stores the entire loaded pipeline (preprocessor + classifier)
_pipeline = None
# _output_features stores the feature names *after* preprocessing (e.g., one-hot encoded names)
_output_features = None
_model_loaded = False

def load_model() -> bool:
    """
    Loads the trained fraud detection pipeline and feature list.
    Returns True on success, False otherwise.
    """
    global _pipeline, _output_features, _model_loaded
    if _model_loaded:
        logging.debug("ML Pipeline already loaded.")
        return True

    try:
        logging.info(f"Attempting to load fraud detection pipeline from: {MODEL_PATH}")
        if not os.path.exists(MODEL_PATH):
             raise FileNotFoundError(f"Model pipeline file not found at {MODEL_PATH}")
        _pipeline = joblib.load(MODEL_PATH)
        # Basic check: Does it look like a pipeline?
        if not hasattr(_pipeline, 'steps'):
             logging.error(f"Loaded object from {MODEL_PATH} does not appear to be a scikit-learn Pipeline.")
             raise TypeError("Loaded model is not a Pipeline object.")


        logging.info(f"Attempting to load output feature names from: {FEATURES_PATH}")
        if not os.path.exists(FEATURES_PATH):
             raise FileNotFoundError(f"Output features file not found at {FEATURES_PATH}")
        _output_features = joblib.load(FEATURES_PATH)
        if not isinstance(_output_features, list):
             logging.error(f"Features file {FEATURES_PATH} did not contain a list.")
             raise TypeError("Features file content is not a list.")


        _model_loaded = True
        logging.info(f"Fraud detection pipeline and output features ({len(_output_features)} features) loaded successfully.")
        logging.info(f"Model pipeline output feature names: {_output_features}")
        return True

    except FileNotFoundError as e:
        logging.error(f"ML PIPELINE LOADING FAILED: {e}. Ensure '{MODEL_FILENAME}' and '{FEATURES_FILENAME}' are in the same directory as this script.")
        _pipeline = None; _output_features = None; _model_loaded = False
        return False
    except Exception as e:
        logging.error(f"Error loading fraud detection pipeline: {e}", exc_info=True)
        _pipeline = None; _output_features = None; _model_loaded = False
        return False

def is_ml_model_loaded() -> bool:
    """Checks if the ML model pipeline has been loaded successfully."""
    # Check that pipeline exists and has steps, and features list exists
    return _model_loaded and _pipeline is not None and hasattr(_pipeline, 'steps') and _output_features is not None

def predict_fraud(transaction_data: dict) -> Tuple[int, Optional[float]]:
    """
    Preprocesses transaction data using the loaded pipeline and predicts fraud.

    Args:
        transaction_data (dict): Dictionary containing the raw features needed
                                 by the *start* of the training pipeline
                                 (e.g., 'amount', 'time_of_day', 'location_risk', 'transaction_type').
                                 Must also contain 'timestamp' if time_of_day needs calculation.

    Returns:
        tuple: (prediction, probability)
               prediction (int): 0 for non-fraud, 1 for fraud.
               probability (float or None): Fraud probability score (0.0 to 1.0),
                                            or None if prediction fails or model
                                            doesn't support predict_proba.
               Returns (0, None) if the model isn't loaded or preprocessing/prediction fails.
    """
    global _pipeline, _output_features # Use the loaded global objects

    if not is_ml_model_loaded():
        logging.error("Fraud model pipeline or features not loaded. Cannot predict.")
        return (0, None) # Default to non-fraud if model unavailable

    logging.debug(f"Received transaction data for prediction: {transaction_data}")
    df_input = None # Define df_input outside try for logging in except block

    try:
        # 1. Prepare Input DataFrame
        # Create a copy to avoid modifying the original dict
        data_dict_processed = transaction_data.copy()

        # --- Feature Engineering (if needed before pipeline) ---
        # Example: Calculate 'time_of_day' from 'timestamp' if required by the *original*
        # feature list used in train_fraud_model.py's ColumnTransformer.
        # Let's assume the raw features needed by the *start* of the pipeline are:
        raw_pipeline_input_features = ['amount', 'time_of_day', 'location_risk', 'transaction_type'] # *** ADJUST THIS TO MATCH YOUR TRAINING ***

        if 'timestamp' in data_dict_processed and 'time_of_day' in raw_pipeline_input_features:
            try:
                # Ensure timestamp is datetime object
                ts = data_dict_processed['timestamp']
                if not isinstance(ts, datetime.datetime):
                    ts = pd.to_datetime(ts) # Attempt conversion
                data_dict_processed['time_of_day'] = ts.hour
            except Exception as ts_err:
                logging.warning(f"Could not derive time_of_day from timestamp '{data_dict_processed.get('timestamp')}', using default 0: {ts_err}", exc_info=True)
                data_dict_processed['time_of_day'] = 0
        elif 'time_of_day' not in data_dict_processed and 'time_of_day' in raw_pipeline_input_features:
             logging.warning("'time_of_day' expected but not found, using default 0.")
             data_dict_processed['time_of_day'] = 0 # Default if timestamp absent

        # Ensure 'amount' is float/Decimal
        if 'amount' in raw_pipeline_input_features:
            try:
                # Convert amount safely, handle potential None
                amt = data_dict_processed.get('amount')
                data_dict_processed['amount'] = float(amt) if amt is not None else 0.0
            except (ValueError, TypeError) as amt_err:
                 logging.warning(f"Could not convert amount '{data_dict_processed.get('amount')}' to float, using default 0.0: {amt_err}")
                 data_dict_processed['amount'] = 0.0

        # Add other necessary type conversions or default values here based on raw_pipeline_input_features

        # Create a single-row DataFrame with columns matching the expected *raw* input features
        # Add defaults for any missing expected raw features
        input_for_df = {}
        for col in raw_pipeline_input_features:
             if col in data_dict_processed:
                  input_for_df[col] = data_dict_processed[col]
             else:
                  # Provide sensible defaults if a raw feature is missing
                  logging.warning(f"Raw feature '{col}' missing in input dict for prediction, adding default.")
                  if col in ['amount', 'time_of_day', 'location_risk']: input_for_df[col] = 0 # Numerical default
                  elif col in ['transaction_type']: input_for_df[col] = 'UNKNOWN' # Categorical default
                  else: input_for_df[col] = 0 # Generic default

        # Create the DataFrame using the exact raw feature list order if possible (though pipeline should handle order)
        df_input = pd.DataFrame([input_for_df])
        # Ensure columns exist before passing to pipeline
        df_input = df_input[raw_pipeline_input_features] # Select only the required raw columns

        logging.debug(f"DataFrame prepared for pipeline input:\n{df_input.to_string()}")
        logging.debug(f"Input dtypes:\n{df_input.dtypes}")

        # 2. Predict using the full pipeline
        # The pipeline handles both preprocessing (scaler, one-hot) and classification
        prediction = _pipeline.predict(df_input)[0] # Get the single prediction

        # 3. Get Probability (optional, but recommended)
        probability = None
        if hasattr(_pipeline, "predict_proba"):
            try:
                # predict_proba usually returns shape (n_samples, n_classes)
                probabilities = _pipeline.predict_proba(df_input)
                if probabilities.shape == (1, 2):
                    probability = probabilities[0][1] # Probability of the positive class (fraud=1)
                else:
                    logging.warning(f"Unexpected shape from predict_proba: {probabilities.shape}")
            except Exception as proba_err:
                logging.warning(f"Could not get probability: {proba_err}", exc_info=True)
        elif prediction == 1:
             probability = 1.0 # Assign max probability if only predict is available and it's fraud
        else:
             probability = 0.0 # Assign min probability

        logging.info(f"ML Prediction: {prediction}, Probability: {probability:.4f}" if probability is not None else "ML Prediction: {prediction}, Probability: N/A")
        return int(prediction), probability # Return prediction and probability

    except Exception as e:
        # Catch errors during preprocessing within the pipeline or during prediction
        logging.error(f"ERROR during ML prediction pipeline execution: {e}", exc_info=True)
        logging.error(f"Input data dictionary: {transaction_data}")
        if df_input is not None:
             logging.error(f"DataFrame input to pipeline:\n{df_input.to_string()}")
        # Default to non-fraud in case of any pipeline error
        return (0, None)

# --- Optional: Load model on module import ---
# load_model()
# You might prefer to call load_model() explicitly from app.py during startup
# as done in the previous app.py version.
