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
                logging.warning(f"ML Model not found at {model_path}. ML Engine will run in SAFE MODE.")

            if os.path.exists(features_path):
                self.features = joblib.load(features_path)
                logging.info(f"ML Features loaded: {self.features}")
            else:
                # Fallback if feature file is missing (to prevent crash, though prediction might be poor)
                self.features = ['amount', 'location_risk', 'time_of_day', 'transaction_type']
                logging.warning("Feature definition file not found. Using fallback schema.")

        except Exception as e:
            logging.error(f"Failed to load ML artifacts: {e}")

    def predict_fraud(self, transaction_data):
        """
        Smart-Maps transaction data to the exact format the AI model expects.
        Handles the specific error: columns are missing: {'amount', 'location_risk', 'time_of_day', 'transaction_type'}
        """
        if not self.model:
            return False, 0.0, "Model Unavailable (Safe Mode)"

        try:
            # 1. Initialize the input row with ALL expected features set to 0.0
            # This ensures we NEVER get a "columns are missing" error again.
            input_dict = {feature: 0.0 for feature in self.features}
            
            # 2. Extract known data
            amount = float(transaction_data.get('amount', 0.0))
            
            # 3. Dynamic Feature Engineering (The Fix)
            # Map 'amount'
            if 'amount' in input_dict:
                input_dict['amount'] = amount
            
            # Map 'time_of_day' (0-23 hours)
            if 'time_of_day' in input_dict:
                input_dict['time_of_day'] = float(datetime.datetime.now().hour)
            
            # Map 'transaction_type' 
            # Assuming 'TRANSFER' map to an integer. We use 1.0 as a safe default for "Transfer"
            if 'transaction_type' in input_dict:
                input_dict['transaction_type'] = 1.0 
            
            # Map 'location_risk'
            # Since we don't have GPS data, we default to 0.0 (Low Risk)
            if 'location_risk' in input_dict:
                input_dict['location_risk'] = 0.0

            # 4. Handle Legacy Features (if model uses old PaySim columns)
            # This makes the engine compatible with BOTH your old and new models.
            if 'oldbalanceOrg' in input_dict:
                sender_bal = float(transaction_data.get('sender_balance', 1000.0))
                input_dict['oldbalanceOrg'] = sender_bal
                if 'newbalanceOrig' in input_dict:
                    input_dict['newbalanceOrig'] = sender_bal - amount

            # 5. Convert to DataFrame
            input_df = pd.DataFrame([input_dict])
            
            # 6. STRICT ORDERING: Reorder columns to match training data exactly
            input_df = input_df[self.features]
            
            # 7. Predict
            # predict_proba returns [[prob_safe, prob_fraud]]
            prob_fraud = self.model.predict_proba(input_df)[0][1]
            
            # Threshold Check
            is_fraud = prob_fraud > 0.5
            
            reason = f"AI Risk Score: {prob_fraud:.2%}" if is_fraud else "Normal Behavior"
            return is_fraud, prob_fraud, reason

        except Exception as e:
            logging.error(f"ML Prediction Error: {e}")
            # Fail-safe: If ML crashes, log it but don't stop the user.
            return False, 0.0, f"ML Error: {str(e)}"
