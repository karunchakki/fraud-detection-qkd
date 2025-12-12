import joblib
import pandas as pd
import logging
import os

class MLEngine:
    def __init__(self, model_path='ml_fraud_model.joblib', features_path='fraud_model_features.joblib'):
        self.model = None
        self.features = []
        self.load_model(model_path, features_path)

    def load_model(self, model_path, features_path):
        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
            if os.path.exists(features_path):
                self.features = joblib.load(features_path)
        except Exception as e:
            logging.error(f"Failed to load ML artifacts: {e}")

    def predict_fraud(self, transaction_data):
        if not self.model:
            return False, 0.0, "Model Unavailable"

        try:
            input_df = pd.DataFrame([transaction_data])
            # Ensure columns match training features
            for f in self.features:
                if f not in input_df.columns:
                    input_df[f] = 0
            
            input_df = input_df[self.features]
            
            prob = self.model.predict_proba(input_df)[0][1]
            is_fraud = prob > 0.5
            
            reason = "High ML Risk Score" if is_fraud else "Normal"
            return is_fraud, prob, reason
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return False, 0.0, f"Error: {str(e)}"