"""
Anomaly detection for security findings.
Uses Isolation Forest for detecting anomalous security patterns.
"""
import numpy as np
from typing import List, Dict, Any, Optional
from pathlib import Path
import joblib
import os

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class SecurityAnomalyDetector:
    """Detect anomalous security patterns using Isolation Forest."""
    
    def __init__(self, model_path: Optional[str] = None, contamination: float = 0.1):
        """
        Initialize anomaly detector.
        
        Args:
            model_path: Path to save/load model. Defaults to models/anomaly_detector.pkl
            contamination: Expected proportion of anomalies (0.0 to 0.5)
        """
        self.model_path = model_path or "models/anomaly_detector.pkl"
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self._load_or_initialize()
    
    def _load_or_initialize(self):
        """Load or initialize model."""
        if os.path.exists(self.model_path):
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, dict):
                    self.model = loaded.get('model')
                    self.scaler = loaded.get('scaler', StandardScaler())
                    self.is_trained = loaded.get('is_trained', False)
                else:
                    self.model = loaded
                    self.is_trained = True
                logger.info(f"Loaded anomaly detector from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}. Using new model.")
        else:
            logger.info("Initializing new anomaly detector")
    
    def train(self, X: np.ndarray):
        """
        Train anomaly detection model on normal data.
        
        Args:
            X: Feature matrix (n_samples, n_features)
        """
        if X.size == 0 or len(X) == 0:
            raise ValueError("Training data is empty")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        
        # Save model
        self._save_model()
        self.is_trained = True
        logger.info("Anomaly detector trained successfully")
    
    def detect_anomalies(self, X: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect anomalies in security findings.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            List of anomaly dictionaries with index, score, and severity
        """
        if not self.is_trained:
            logger.warning("Model not trained. Using untrained model for detection.")
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Process results
        anomalies = []
        for idx, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if pred == -1:  # Anomaly detected
                anomalies.append({
                    'index': int(idx),
                    'anomaly_score': float(score),
                    'severity': self._classify_anomaly_severity(score),
                    'is_anomaly': True
                })
        
        return anomalies
    
    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores for all samples (lower = more anomalous).
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Anomaly scores (n_samples,)
        """
        if not self.is_trained:
            logger.warning("Model not trained. Using untrained model.")
        
        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled)
    
    def _classify_anomaly_severity(self, score: float) -> str:
        """
        Classify anomaly severity based on score.
        
        Args:
            score: Anomaly score (lower = more anomalous)
            
        Returns:
            Severity level: 'critical', 'high', 'medium', or 'low'
        """
        # Isolation Forest scores: lower values indicate more anomalous
        # Typical range: -0.5 to 0.5, with anomalies < 0
        if score < -0.5:
            return 'critical'
        elif score < -0.3:
            return 'high'
        elif score < -0.1:
            return 'medium'
        else:
            return 'low'
    
    def _save_model(self):
        """Save model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'contamination': self.contamination
        }
        
        joblib.dump(model_data, self.model_path)
        logger.info(f"Anomaly detector saved to {self.model_path}")

