import joblib
import pandas as pd
import logging
import os

class MLEngine:
    def __init__(self, model_path='model_artifacts/fraud_model.joblib', features_path='model_artifacts/fraud_model_features.joblib'):
        self.model = None
        self.features = []
        # Try to load model immediately
        self.load_model(model_path, features_path)

    def load_model(self, model_path, features_path):
        try:
            # Check if files exist before loading to prevent crashes
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
            else:
                logging.warning(f"ML Model not found at {model_path}. ML Engine will run in SAFE MODE.")

            if os.path.exists(features_path):
                self.features = joblib.load(features_path)
                logging.info(f"ML Features loaded: {len(self.features)} columns expected.")
            else:
                # Fallback features if file missing (Standard PaySim features)
                self.features = ['step', 'amount', 'oldbalanceOrg', 'newbalanceOrig', 
                                 'oldbalanceDest', 'newbalanceDest', 'isFlaggedFraud', 
                                 'type_CASH_IN', 'type_CASH_OUT', 'type_DEBIT', 
                                 'type_PAYMENT', 'type_TRANSFER']
                logging.warning("Feature definition file not found. Using default PaySim schema.")

        except Exception as e:
            logging.error(f"Failed to load ML artifacts: {e}")

    def predict_fraud(self, transaction_data):
        """
        Smart-Maps transaction data to the exact format the AI model expects.
        
        transaction_data format:
        {
            'amount': float,
            'sender_balance': float,   (Optional - defaults to 0)
            'receiver_balance': float  (Optional - defaults to 0)
        }
        """
        if not self.model:
            return False, 0.0, "Model Unavailable (Safe Mode)"

        try:
            # 1. Initialize all expected features to 0.0
            # This ensures we never get a "Missing Column" error
            input_dict = {feature: 0.0 for feature in self.features}
            
            # 2. Extract Data from Input
            amount = float(transaction_data.get('amount', 0.0))
            sender_bal = float(transaction_data.get('sender_balance', 1000.0)) # Default to 1000 if unknown
            receiver_bal = float(transaction_data.get('receiver_balance', 0.0))

            # 3. Map to PaySim Column Names (The "Smart Mapping")
            input_dict['amount'] = amount
            input_dict['oldbalanceOrg'] = sender_bal
            # Logic: New balance = Old - Amount
            input_dict['newbalanceOrig'] = sender_bal - amount
            
            input_dict['oldbalanceDest'] = receiver_bal
            input_dict['newbalanceDest'] = receiver_bal + amount
            
            input_dict['step'] = 1 # Simulation step (hour)
            
            # Set Transaction Type (Assuming TRANSFER for this app)
            if 'type_TRANSFER' in input_dict:
                input_dict['type_TRANSFER'] = 1.0
            
            # 4. Convert to DataFrame
            input_df = pd.DataFrame([input_dict])
            
            # 5. STRICT ORDERING: Reorder columns to match training data exactly
            input_df = input_df[self.features]
            
            # 6. Predict
            # predict_proba returns [[prob_safe, prob_fraud]]
            prob_fraud = self.model.predict_proba(input_df)[0][1]
            
            # Threshold Check (0.5 is standard, lower = stricter)
            is_fraud = prob_fraud > 0.5
            
            reason = f"AI Risk Score: {prob_fraud:.2%}" if is_fraud else "Normal Behavior"
            return is_fraud, prob_fraud, reason

        except Exception as e:
            logging.error(f"ML Prediction Error: {e}")
            # Fail-safe: If ML crashes, don't block the user, but log it.
            return False, 0.0, f"ML Error: {str(e)}"
