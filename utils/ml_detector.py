import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()

    def prepare_features(self, df):
        # Create numerical features from log data
        features = pd.DataFrame()
        
        # Time-based features
        features['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        
        # IP-based features
        ip_counts = df['ip_address'].value_counts()
        features['ip_frequency'] = df['ip_address'].map(ip_counts)
        
        # Severity-based features
        severity_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
        features['severity_score'] = df['severity'].map(severity_map)
        
        # Attack indicator
        features['attack_indicator'] = df['attack_indicators'].astype(int)
        
        return features

    def detect_anomalies(self, df):
        try:
            features = self.prepare_features(df)
            features_scaled = self.scaler.fit_transform(features)
            
            # Detect anomalies
            predictions = self.model.fit_predict(features_scaled)
            
            # Convert predictions to binary (1 for normal, -1 for anomaly)
            anomalies = predictions == -1
            
            return anomalies, features
        except Exception as e:
            raise Exception(f"Error in anomaly detection: {str(e)}")

    def get_anomaly_details(self, df, anomalies):
        anomaly_df = df[anomalies].copy()
        return {
            'total_anomalies': len(anomaly_df),
            'anomaly_timestamps': anomaly_df['timestamp'].tolist(),
            'anomaly_ips': anomaly_df['ip_address'].tolist(),
            'anomaly_messages': anomaly_df['message'].tolist()
        }
