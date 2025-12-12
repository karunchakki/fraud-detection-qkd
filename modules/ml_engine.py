import joblib
import pandas as pd
import logging
import os
import datetime

class MLEngine:
    def __init__(self, model_path='model_artifacts/fraud_model.joblib', features_path='model_artifacts/fraud_model_features.joblib'):
        self.model = None
        self.features = []
        self.load_model(model_path, features_path)

    def load_model(self, model_path, features_path):
        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
            else:
                logging.warning(f"ML Model not found at {model_path}. Safe Mode.")

            if os.path.exists(features_path):
                self.features = joblib.load(features_path)
                logging.info(f"Loaded Features: {self.features}")
            else:
                # Hardcoded fallback based on your error logs
                self.features = ['amount', 'location_risk', 'time_of_day', 'transaction_type']
                logging.warning("Features file missing. Using hardcoded fallback.")

        except Exception as e:
            logging.error(f"Failed to load ML artifacts: {e}")

    def predict_fraud(self, transaction_data):
        """
        Guarantees that all required columns exist before prediction.
        """
        if not self.model:
            return False, 0.0, "Model Unavailable (Safe Mode)"

        try:
            # 1. Create a Dictionary with ALL required keys set to default 0.0
            # This prevents "columns are missing" errors.
            input_data = {feature: 0.0 for feature in self.features}
            
            # 2. Populate 'amount'
            input_data['amount'] = float(transaction_data.get('amount', 0.0))
            
            # 3. Populate 'time_of_day' (Current Hour)
            # Check if model expects this specific column name
            if 'time_of_day' in input_data:
                input_data['time_of_day'] = float(datetime.datetime.now().hour)
            
            # 4. Populate 'transaction_type' (Default to 1 = Transfer)
            if 'transaction_type' in input_data:
                input_data['transaction_type'] = 1.0
            
            # 5. Populate 'location_risk' (Default to 0 = Low)
            if 'location_risk' in input_data:
                input_data['location_risk'] = 0.0

            # 6. Legacy Support (If model uses old PaySim columns like oldbalanceOrg)
            if 'oldbalanceOrg' in input_data:
                input_data['oldbalanceOrg'] = float(transaction_data.get('sender_balance', 1000.0))
            if 'newbalanceOrig' in input_data:
                input_data['newbalanceOrig'] = float(transaction_data.get('sender_balance', 1000.0)) - input_data['amount']

            # 7. Convert to DataFrame
            # IMPORTANT: We pass [input_data] to create a single-row DataFrame
            input_df = pd.DataFrame([input_data])
            
            # 8. Reorder columns to match training data exactly
            input_df = input_df[self.features]
            
            # 9. Predict
            prob_fraud = self.model.predict_proba(input_df)[0][1]
            is_fraud = prob_fraud > 0.5
            
            reason = f"AI Risk Score: {prob_fraud:.2%}" if is_fraud else "Normal Behavior"
            return is_fraud, prob_fraud, reason

        except Exception as e:
            logging.error(f"ML Critical Error: {e}")
            # Fail-safe: Return 0.0 fraud score so we don't block valid transactions on errors
            return False, 0.0, f"ML Error: {str(e)}"
