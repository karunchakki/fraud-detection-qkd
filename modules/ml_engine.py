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

            # CRITICAL FIX: Merge loaded features with the specific hardcoded requirements
            # to ensure the model never crashes due to missing column definitions.
            required_features = ['amount', 'location_risk', 'time_of_day', 'transaction_type']
            
            if os.path.exists(features_path):
                loaded_features = joblib.load(features_path)
                # Combine loaded features with required ones, removing duplicates
                feature_set = set(loaded_features)
                for req in required_features:
                    feature_set.add(req)
                self.features = list(feature_set)
            else:
                # Fallback if file missing
                self.features = required_features
            
            logging.info(f"Final ML Features: {self.features}")

        except Exception as e:
            logging.error(f"Failed to load ML artifacts: {e}")
            self.features = ['amount', 'location_risk', 'time_of_day', 'transaction_type']

    def predict_fraud(self, transaction_data):
        """
        Smart-Maps transaction data to the exact format the AI model expects.
        """
        if not self.model:
            return False, 0.0, "Model Unavailable"

        try:
            # 1. Initialize input dictionary with 0.0 for ALL required features
            # This guarantees no "missing column" error can ever occur.
            input_dict = {feature: 0.0 for feature in self.features}
            
            # 2. Populate Known Data
            # Map 'amount'
            input_dict['amount'] = float(transaction_data.get('amount', 0.0))
            
            # Map 'time_of_day' (Current Hour)
            input_dict['time_of_day'] = float(datetime.datetime.now().hour)
            
            # Map 'transaction_type' (Default to 1.0 = Transfer)
            input_dict['transaction_type'] = 1.0 
            
            # Map 'location_risk' (Default to 0.0 = Low)
            input_dict['location_risk'] = 0.0

            # 3. Populate Legacy PaySim Data (if features list contains them)
            sender_bal = float(transaction_data.get('sender_balance', 1000.0))
            
            if 'oldbalanceOrg' in input_dict:
                input_dict['oldbalanceOrg'] = sender_bal
            if 'newbalanceOrig' in input_dict:
                # Logic: New balance = Old - Amount
                input_dict['newbalanceOrig'] = sender_bal - input_dict['amount']
            if 'oldbalanceDest' in input_dict:
                input_dict['oldbalanceDest'] = float(transaction_data.get('receiver_balance', 0.0))
            if 'newbalanceDest' in input_dict:
                input_dict['newbalanceDest'] = float(transaction_data.get('receiver_balance', 0.0)) + input_dict['amount']
            if 'step' in input_dict:
                input_dict['step'] = 1
            if 'type_TRANSFER' in input_dict:
                input_dict['type_TRANSFER'] = 1.0

            # 4. Create DataFrame
            input_df = pd.DataFrame([input_dict])
            
            # 5. Strict Column Filtering & Ordering
            # Ensure the DataFrame has ONLY the columns expected by the model
            input_df = input_df[self.features]
            
            # 6. Predict
            # predict_proba returns [[prob_safe, prob_fraud]]
            prob_fraud = self.model.predict_proba(input_df)[0][1]
            
            # Threshold Check
            is_fraud = prob_fraud > 0.5
            
            reason = f"AI Risk Score: {prob_fraud:.2%}" if is_fraud else "Normal Behavior"
            return is_fraud, prob_fraud, reason

        except Exception as e:
            logging.error(f"ML Prediction Error: {e}")
            # Fail-safe: Return False (Not Fraud) if ML crashes so app keeps working
            return False, 0.0, f"ML Error (Skipped): {str(e)}"
