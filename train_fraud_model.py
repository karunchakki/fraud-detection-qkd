# train_fraud_model.py
# Script to preprocess data, train fraud detection model (with synthetic labels),
# and save the model and feature list for the Flask app.

import os
import logging
import traceback
import pandas as pd
import numpy as np
from datetime import timedelta
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

print("--- Starting Fraud Model Training Script ---")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- Configuration ---
CSV_PATH = 'bank_transactions_data_2.csv'
MODEL_FILENAME = 'fraud_model.joblib'
FEATURES_FILENAME = 'fraud_model_features.joblib'

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FULL_PATH = os.path.join(SCRIPT_DIR, CSV_PATH)
MODEL_FULL_PATH = os.path.join(SCRIPT_DIR, MODEL_FILENAME)
FEATURES_FULL_PATH = os.path.join(SCRIPT_DIR, FEATURES_FILENAME)

# --- Load Data ---
try:
    logging.info(f"Loading data from: {CSV_FULL_PATH}")
    df = pd.read_csv(CSV_FULL_PATH)
    logging.info(f"Data loaded successfully. Shape: {df.shape}")
except FileNotFoundError:
    logging.error(f"Cannot find the data file at '{CSV_FULL_PATH}'.")
    exit()
except Exception as e:
    logging.error(f"Failed to load data: {e}")
    traceback.print_exc()
    exit()

# --- Preprocessing and Feature Engineering ---
try:
    logging.info("Preprocessing data and engineering features...")

    # Convert to datetime
    df['TransactionDate'] = pd.to_datetime(df['TransactionDate'], errors='coerce')
    df['PreviousTransactionDate'] = pd.to_datetime(df['PreviousTransactionDate'], errors='coerce')

    # Drop rows with invalid dates
    df.dropna(subset=['TransactionDate'], inplace=True)
    df.sort_values(by=['AccountID', 'TransactionDate'], inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Calculate transaction gap in days
    df['TransactionGap'] = (df['TransactionDate'] - df['PreviousTransactionDate']).dt.total_seconds() / (60 * 60 * 24)
    df['TransactionGap'] = df['TransactionGap'].fillna(999.0).clip(lower=0)

    # Extract hour
    df['TransactionHour'] = df['TransactionDate'].dt.hour

    # Rolling features
    window_size = 5
    df['sum_5days'] = df.groupby('AccountID')['TransactionAmount']\
        .transform(lambda x: x.rolling(window=window_size, min_periods=1).sum().shift(1)).fillna(0)
    df['count_5days'] = df.groupby('AccountID')['TransactionAmount']\
        .transform(lambda x: x.rolling(window=window_size, min_periods=1).count().shift(1)).fillna(0)

    logging.info("Preprocessing complete.")
    logging.info("Sample:\n%s", df[['TransactionAmount', 'TransactionHour', 'TransactionGap', 'sum_5days', 'count_5days']].head().to_string())
except Exception as e:
    logging.error(f"Error in preprocessing: {e}")
    traceback.print_exc()
    exit()

# --- Generate Synthetic Labels ---
logging.warning("Generating SYNTHETIC fraud labels (2% fraud rate).")
np.random.seed(42)
df['is_fraud'] = np.random.choice([0, 1], size=len(df), p=[0.98, 0.02])
fraud_count = df['is_fraud'].sum()
logging.info(f"Synthetic fraud labels created. Fraud count: {fraud_count} ({(fraud_count / len(df)) * 100:.2f}%)")

# --- Feature Selection ---
feature_names = ['TransactionAmount', 'count_5days', 'sum_5days', 'TransactionHour', 'TransactionGap']
X = df[feature_names]
y = df['is_fraud'].astype(int)

if X.isnull().values.any():
    logging.warning("Missing values found in features. Filling with 0.")
    X = X.fillna(0)

# --- Train-Test Split ---
try:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)
    logging.info(f"Train shape: {X_train.shape}, Test shape: {X_test.shape}")
except ValueError as e:
    logging.error(f"Train-test split error: {e}")
    exit()

# --- Train Model ---
model = RandomForestClassifier(
    n_estimators=100, random_state=42, class_weight='balanced', n_jobs=-1)

model.fit(X_train, y_train)
logging.info("Model training complete.")

# --- Evaluation ---
y_pred = model.predict(X_test)
report = classification_report(y_test, y_pred, target_names=['Normal (0)', 'Fraud (1)'], digits=4)
print("\nModel Evaluation Report:\n")
print(report)

# --- Save Model and Features ---
joblib.dump(model, MODEL_FULL_PATH)
joblib.dump(feature_names, FEATURES_FULL_PATH)

print("\n--- Model Training Script Finished Successfully ---")
print(f"Saved model to: {MODEL_FULL_PATH}")
print(f"Saved feature list to: {FEATURES_FULL_PATH}")
print("NOTE: Model was trained on synthetic labels and should not be used for real fraud detection.")
