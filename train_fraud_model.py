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

# --- Logging Setup ---
print("--- Starting Fraud Detection Model Training ---")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- Configuration ---
CSV_PATH = 'bank_transactions_data_2.csv'
MODEL_FILE = 'fraud_model.joblib'
FEATURES_FILE = 'fraud_model_features.joblib'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FULL_PATH = os.path.join(BASE_DIR, CSV_PATH)
MODEL_FULL_PATH = os.path.join(BASE_DIR, MODEL_FILE)
FEATURES_FULL_PATH = os.path.join(BASE_DIR, FEATURES_FILE)

# --- Load Data ---
try:
    logging.info(f"Loading data from {CSV_FULL_PATH}")
    df = pd.read_csv(CSV_FULL_PATH)
    logging.info(f"Data shape: {df.shape}")
except FileNotFoundError:
    logging.error("CSV file not found.")
    exit()
except Exception as e:
    logging.error("Failed to read CSV file.")
    traceback.print_exc()
    exit()

# --- Preprocessing ---
try:
    logging.info("Starting preprocessing and feature engineering...")

    df['TransactionDate'] = pd.to_datetime(df['TransactionDate'], errors='coerce')
    df['PreviousTransactionDate'] = pd.to_datetime(df['PreviousTransactionDate'], errors='coerce')
    df.dropna(subset=['TransactionDate'], inplace=True)

    df.sort_values(by=['AccountID', 'TransactionDate'], inplace=True)
    df.reset_index(drop=True, inplace=True)

    df['TransactionGap'] = (df['TransactionDate'] - df['PreviousTransactionDate']).dt.total_seconds() / (60 * 60 * 24)
    df['TransactionGap'] = df['TransactionGap'].fillna(999).clip(lower=0)
    df['TransactionHour'] = df['TransactionDate'].dt.hour

    window = 5
    df['sum_5days'] = df.groupby('AccountID')['TransactionAmount'].transform(lambda x: x.rolling(window, min_periods=1).sum().shift(1)).fillna(0)
    df['count_5days'] = df.groupby('AccountID')['TransactionAmount'].transform(lambda x: x.rolling(window, min_periods=1).count().shift(1)).fillna(0)

    logging.info("Feature engineering complete.")
except Exception as e:
    logging.error("Error during preprocessing.")
    traceback.print_exc()
    exit()

# --- Synthetic Fraud Labeling ---
logging.info("Generating synthetic fraud labels...")

df['is_fraud'] = 0
amount_thresh = df['TransactionAmount'].quantile(0.995)
gap_thresh_days = 15 / (24 * 60 * 60)
count_thresh = 4
hour_range = (1, 5)

rule1 = df[df['TransactionAmount'] > amount_thresh].index
df.loc[rule1, 'is_fraud'] = 1

rule2 = df[(df['TransactionGap'] < gap_thresh_days) & (df['count_5days'] >= count_thresh)].index.difference(rule1)
df.loc[rule2, 'is_fraud'] = 1

rule3 = df[(df['TransactionHour'] >= hour_range[0]) & (df['TransactionHour'] <= hour_range[1])].index.difference(rule1).difference(rule2)
df.loc[rule3, 'is_fraud'] = 1

logging.info(f"Rule-based fraud labeling complete. Total frauds: {df['is_fraud'].sum()}")

# --- Model Training ---
features = ['TransactionAmount', 'count_5days', 'sum_5days', 'TransactionHour', 'TransactionGap']
X = df[features].fillna(0)
y = df['is_fraud'].astype(int)

try:
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    logging.info(f"Train/Test split: {X_train.shape}, {X_test.shape}")
except ValueError as e:
    logging.error("Train-test split failed.")
    exit()

model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced', n_jobs=-1)
model.fit(X_train, y_train)
logging.info("Model training completed.")

# --- Evaluation ---
y_pred = model.predict(X_test)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Fraud (1)'], digits=4))

# --- Save Model ---
joblib.dump(model, MODEL_FULL_PATH)
joblib.dump(features, FEATURES_FULL_PATH)
print("\n--- Training Complete ---")
print(f"Model saved to: {MODEL_FULL_PATH}")
print(f"Feature list saved to: {FEATURES_FULL_PATH}")
print("Note: This model is trained on synthetic data.")
