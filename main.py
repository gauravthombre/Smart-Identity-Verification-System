import pandas as pd
import hashlib
import random
import time
from sklearn.ensemble import IsolationForest
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# ==========================================
# MODULE 1: SECURITY & ENCRYPTION
# ==========================================
class SecurityLayer:
    @staticmethod
    def hash_biometric(biometric_data):
        """
        Simulates SHA-256 Hashing of Biometric Data (Fingerprint/Face).
        We NEVER store the raw image, only this hash.
        """
        salt = "UIDAI_SECURE_SALT_2026"  # In production, this should be unique per user
        secure_string = biometric_data + salt
        return hashlib.sha256(secure_string.encode()).hexdigest()

    @staticmethod
    def generate_otp():
        """Generates a 6-digit Time-based OTP"""
        return random.randint(100000, 999999)

# ==========================================
# MODULE 2: AI FRAUD DETECTION ENGINE
# ==========================================
class FraudDetectionEngine:
    def __init__(self, dataset_path):
        print("\n[AI ENGINE] Initializing Fraud Detection Model...")
        self.dataset_path = dataset_path
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.is_trained = False

    def train_model(self):
        """
        Trains the AI model on historical enrolment data to learn 'Normal' behavior.
        """
        try:
            print("[AI ENGINE] Loading Dataset...")
            df = pd.read_csv(self.dataset_path)
            
            # Feature Engineering: Calculate Total Daily Enrolments per District
            df['total_enrolment'] = df['age_0_5'] + df['age_5_17'] + df['age_18_greater']
            
            # We aggregate by district to see volume trends
            # This simulates monitoring "How many people enrolled at Center X today?"
            self.district_stats = df.groupby(['state', 'district', 'date'])['total_enrolment'].sum().reset_index()
            
            print(f"[AI ENGINE] Training Isolation Forest on {len(self.district_stats)} records...")
            self.model.fit(self.district_stats[['total_enrolment']])
            self.is_trained = True
            print("[AI ENGINE] Model Trained Successfully!")
            
        except Exception as e:
            print(f"[ERROR] Could not train model: {e}")

    def check_for_anomaly(self, daily_volume, location):
        """
        Predicts if a specific enrolment volume is Fraudulent (Anomaly) or Normal.
        Returns: -1 (Fraud), 1 (Normal)
        """
        if not self.is_trained:
            print("[WARNING] Model not trained yet.")
            return 1
            
        # Predict
        score = self.model.predict([[daily_volume]])[0]
        
        if score == -1:
            print(f"!!! FRAUD ALERT !!! High Volume Anomaly detected in {location}: {daily_volume} requests.")
        else:
            print(f"[SAFE] Volume in {location} ({daily_volume}) is within normal limits.")
            
        return score

# ==========================================
# MODULE 3: MAIN SYSTEM CONTROLLER
# ==========================================
class SmartIdentitySystem:
    def __init__(self):
        self.security = SecurityLayer()
        # Initialize AI Engine with your specific CSV file
        self.ai_engine = FraudDetectionEngine('api_data_aadhar_enrolment_0_500000.csv')
        self.user_database = {} # Simulating a DB

    def run_training(self):
        self.ai_engine.train_model()

    def enroll_user(self, user_id, raw_fingerprint, mobile):
        """Simulates User Enrolment"""
        print(f"\n--- Enrolling User: {user_id} ---")
        
        # 1. Hash Biometrics
        bio_hash = self.security.hash_biometric(raw_fingerprint)
        print(f"1. Biometric Processed. Stored Hash: {bio_hash[:10]}... (Privacy Preserved)")
        
        # 2. Store in DB
        self.user_database[user_id] = {
            'bio_hash': bio_hash,
            'mobile': mobile
        }
        print("2. User Registered in Secure Database.")

    def verify_user(self, user_id, input_fingerprint):
        """Simulates Authentication Process"""
        print(f"\n--- Verifying User: {user_id} ---")
        
        if user_id not in self.user_database:
            print("Error: User not found!")
            return

        stored_data = self.user_database[user_id]
        
        # Step 1: Biometric Match
        input_hash = self.security.hash_biometric(input_fingerprint)
        if input_hash == stored_data['bio_hash']:
            print("[SUCCESS] Biometric Match Found.")
            
            # Step 2: OTP Verification
            otp = self.security.generate_otp()
            print(f"[MFA] OTP Sent to {stored_data['mobile']}: {otp}")
            
            # Simulating User Input
            user_input = otp 
            if user_input == otp:
                print(">> ACCESS GRANTED: Identity Verified.")
            else:
                print(">> ACCESS DENIED: Invalid OTP.")
        else:
            print(">> ACCESS DENIED: Biometric Mismatch!")

    def simulate_attack(self):
        """Simulates a Bot Attack to test AI Engine"""
        print("\n--- SIMULATING BOT ATTACK SCENARIO ---")
        # Scenario 1: Normal Day in a small town
        self.ai_engine.check_for_anomaly(daily_volume=45, location="Small_Town_Center")
        
        # Scenario 2: The 'Bengaluru Anomaly' we found in data analysis
        # (Massive spike in volume)
        self.ai_engine.check_for_anomaly(daily_volume=12219, location="Bengaluru_Urban_Center")

# ==========================================
# EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    system = SmartIdentitySystem()
    
    # 1. Train the Fraud Detection System
    system.run_training()
    
    # 2. Demonstrate Normal User Flow
    system.enroll_user("UID_12345", "raw_fingerprint_image_data", "+91-9876543210")
    system.verify_user("UID_12345", "raw_fingerprint_image_data")
    
    # 3. Demonstrate Fraud Detection (The "AI" Part)
    system.simulate_attack()
