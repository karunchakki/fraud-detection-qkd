# train_fraud_model.py
# Offline script to preprocess data, train the fraud detection model,
# and save the model and feature list for the Flask app.
# --- VERSION USING COMBINED RULE-BASED SYNTHETIC LABELS ---

import pandas as pd
import numpy as np
from datetime import timedelta
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import logging
import os
import traceback

print("--- Starting Fraud Model Training Script (Combined Rule-Based Synthetic Labels) ---")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- Configuration ---
CSV_PATH = 'bank_transactions_data_2.csv' # Ensure this file exists
MODEL_FILENAME = 'fraud_model.joblib'
FEATURES_FILENAME = 'fraud_model_features.joblib'
SCRIPT_DIR = os.path.dirname(__file__)
CSV_FULL_PATH = os.path.join(SCRIPT_DIR, CSV_PATH)
MODEL_FULL_PATH = os.path.join(SCRIPT_DIR, MODEL_FILENAME)
FEATURES_FULL_PATH = os.path.join(SCRIPT_DIR, FEATURES_FILENAME)

# --- Rule Thresholds for Synthetic Label Generation ---
# (Tune these values based on your data exploration if needed)
SYNTHETIC_AMOUNT_QUANTILE = 0.995 # Flag top 0.5% amounts
SYNTHETIC_LATE_HOUR_START = 1     # Start of suspicious hours (1 AM)
SYNTHETIC_LATE_HOUR_END = 4       # End of suspicious hours (up to 4:59 AM)
SYNTHETIC_RAPID_GAP_SECONDS = 10  # Flag if gap < 10 seconds
SYNTHETIC_HIGH_COUNT_THRESHOLD = 4 # Flag if count_5days > 4

# --- 1. Load Data ---
try:
    logging.info(f"Loading data from: {CSV_FULL_PATH}")
    df = pd.read_csv(CSV_FULL_PATH)
    logging.info(f"Data loaded successfully. Shape: {df.shape}")
except FileNotFoundError:
    logging.error(f"ERROR: Cannot find data file '{CSV_FULL_PATH}'.")
    exit()
except Exception as e:
    logging.error(f"ERROR: Failed to load data. {e}")
    exit()

# --- 2. Preprocessing and Feature Engineering ---
logging.info("Preprocessing data and engineering features...")
try:
    df['TransactionDate'] = pd.to_datetime(df['TransactionDate'], errors='coerce')
    df['PreviousTransactionDate'] = pd.to_datetime(df['PreviousTransactionDate'], errors='coerce')
    df.dropna(subset=['TransactionDate'], inplace=True)
    df = df.sort_values(by=['AccountID', 'TransactionDate']).reset_index(drop=True)

    # Calculate TransactionGap (in SECONDS for rule check)
    df['TransactionGapSeconds'] = (df['TransactionDate'] - df['PreviousTransactionDate']).dt.total_seconds()
    df['TransactionGapSeconds'] = df['TransactionGapSeconds'].fillna(9999999.0).clip(lower=0)
    # Keep the 'TransactionGap' in DAYS for the ML model feature
    df['TransactionGap'] = df['TransactionGapSeconds'] / (60 * 60 * 24)

    df['TransactionHour'] = df['TransactionDate'].dt.hour

    # Calculate Rolling Features
    window_size = 5
    min_periods_required = 1
    df[f'sum_{window_size}days'] = df.groupby('AccountID')['TransactionAmount']\
                                    .transform(lambda s: s.rolling(window=window_size, min_periods=min_periods_required).sum().shift(1))
    df[f'count_{window_size}days'] = df.groupby('AccountID')['TransactionAmount']\
                                      .transform(lambda s: s.rolling(window=window_size, min_periods=min_periods_required).count().shift(1))
    df[f'sum_{window_size}days'] = df[f'sum_{window_size}days'].fillna(0)
    df[f'count_{window_size}days'] = df[f'count_{window_size}days'].fillna(0)
    df.rename(columns={f'sum_{window_size}days': 'sum_5days', f'count_{window_size}days': 'count_5days'}, inplace=True)

    logging.info("Preprocessing complete.")
    logging.info("Sample of processed data:\n%s", df[['TransactionAmount', 'TransactionHour', 'TransactionGap', 'TransactionGapSeconds', 'sum_5days', 'count_5days']].head().to_string())

except Exception as e:
    logging.error(f"ERROR during preprocessing: {e}")
    traceback.print_exc()
    exit()

# --- 3. Generate COMBINED Rule-Based Synthetic Labels ---
logging.info("Generating COMBINED rule-based synthetic 'is_fraud' labels...")
df['is_fraud'] = 0 # Initialize as not fraud

# Calculate conditions first
amount_threshold = df['TransactionAmount'].quantile(SYNTHETIC_AMOUNT_QUANTILE)
is_high_amount = df['TransactionAmount'] > amount_threshold
is_late_night = (df['TransactionHour'] >= SYNTHETIC_LATE_HOUR_START) & (df['TransactionHour'] <= SYNTHETIC_LATE_HOUR_END)
is_rapid_gap = df['TransactionGapSeconds'] < SYNTHETIC_RAPID_GAP_SECONDS
is_high_freq = df['count_5days'] > SYNTHETIC_HIGH_COUNT_THRESHOLD

logging.info(f"Rule Thresholds: Amount > {amount_threshold:.2f}, Hour in [{SYNTHETIC_LATE_HOUR_START}-{SYNTHETIC_LATE_HOUR_END}], Gap < {SYNTHETIC_RAPID_GAP_SECONDS}s, Count > {SYNTHETIC_HIGH_COUNT_THRESHOLD}")

# --- Define COMBINED flagging conditions ---
# Flag if (High Amount AND Late Night) OR (Rapid Gap AND High Frequency)
condition1 = is_high_amount & is_late_night
condition2 = is_rapid_gap & is_high_freq

df.loc[condition1 | condition2, 'is_fraud'] = 1

# Optional: Add back extremely high amount as a standalone flag if needed
# extreme_amount_threshold = df['TransactionAmount'].quantile(0.999)
# logging.info(f"Also flagging extreme amounts > {extreme_amount_threshold:.2f}")
# df.loc[df['TransactionAmount'] > extreme_amount_threshold, 'is_fraud'] = 1

# --- Final Check ---
df['is_fraud'] = df['is_fraud'].astype(int)
logging.info("Rule-based synthetic 'is_fraud' labels generated.")
distribution = df['is_fraud'].value_counts(normalize=True)
logging.info("Synthetic Fraud label distribution:\n%s", distribution.to_string())
if 0 not in distribution.index or 1 not in distribution.index:
    logging.error("ERROR: Synthetic label rules resulted in only one class (all 0s or all 1s). Adjust rules/thresholds in train_fraud_model.py.")
    exit() # Stop if only one class is present
logging.info(f"Total synthetic fraud count: {df['is_fraud'].sum()}")


# --- 4. Select Features and Target for Classifier ---
feature_names = ['TransactionAmount', 'count_5days', 'sum_5days', 'TransactionHour', 'TransactionGap']
logging.info(f"Using features for classification: {feature_names}")
missing_cols = [col for col in feature_names if col not in df.columns]
if missing_cols:
    logging.error(f"ERROR: Missing required features after preprocessing: {missing_cols}")
    exit()

X_fraud = df[feature_names]
y_fraud = df['is_fraud'] # Use the rule-based labels

# --- 5. Handle Missing Values in Features (Defensive Check) ---
if X_fraud.isnull().values.any():
    logging.warning("Warning: Found missing values in features post-processing. Filling with 0.")
    X_fraud = X_fraud.fillna(0)

# --- 6. Train-Test Split ---
logging.info("Splitting data into training and testing sets (70/30)...")
try:
    X_train, X_test, y_train, y_test = train_test_split(
        X_fraud, y_fraud, test_size=0.3, random_state=42, stratify=y_fraud )
    logging.info(f"Training set shape: {X_train.shape}, Testing set shape: {X_test.shape}")
    logging.info("Test set fraud distribution:\n%s", y_test.value_counts(normalize=True).to_string())
except ValueError as e:
     logging.error(f"ERROR during train-test split: {e}. Check class distribution (especially fraud count). There might be too few fraud samples even after rule application.")
     exit()

# --- 7. Train Random Forest Model ---
logging.info("Training RandomForestClassifier model...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced', n_jobs=-1)
rf_model.fit(X_train, y_train)
logging.info("Model training complete.")

# --- 8. Optional: Evaluate Model ---
logging.info("\nEvaluating model performance on the test set (using RULE-BASED synthetic labels)...")
y_pred_test = rf_model.predict(X_test)
# Specify labels=[0, 1] in case one class is missing ONLY in the test set after split
# although the earlier check should prevent this for the whole dataset.
report = classification_report(y_test, y_pred_test, target_names=['Normal (0)', 'Fraud (1)'], digits=4, labels=[0, 1], zero_division=0)
print(report) # Print report to console

# --- 9. Save the Trained Model and Feature List ---
logging.info(f"\nSaving trained model to: {MODEL_FULL_PATH}")
joblib.dump(rf_model, MODEL_FULL_PATH)

logging.info(f"Saving feature list to: {FEATURES_FULL_PATH}")
joblib.dump(feature_names, FEATURES_FULL_PATH)

print("\n--- Model Training Script Finished Successfully ---")
print(f"Files '{MODEL_FILENAME}' and '{FEATURES_FILENAME}' created/updated in '{SCRIPT_DIR}'.")
print(f"NOTE: Model was trained on RULE-BASED SYNTHETIC labels.")
