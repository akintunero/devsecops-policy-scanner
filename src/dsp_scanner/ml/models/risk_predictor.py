"""
Risk prediction model for security findings.
Uses XGBoost for risk score prediction.
"""
import numpy as np
from typing import Tuple, Optional
from pathlib import Path
import joblib
import os

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    # Fallback to scikit-learn
    from sklearn.ensemble import GradientBoostingRegressor

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error

from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class RiskPredictor:
    """ML model for predicting security risk scores."""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize risk predictor.
        
        Args:
            model_path: Path to save/load model. Defaults to models/risk_predictor.pkl
        """
        self.model_path = model_path or "models/risk_predictor.pkl"
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self._load_or_initialize_model()
    
    def _load_or_initialize_model(self):
        """Load existing model or initialize new one."""
        if os.path.exists(self.model_path):
            try:
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, dict):
                    self.model = loaded.get('model')
                    self.scaler = loaded.get('scaler', StandardScaler())
                    self.is_trained = loaded.get('is_trained', False)
                else:
                    # Legacy format
                    self.model = loaded
                    self.is_trained = True
                logger.info(f"Loaded model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}. Initializing new model.")
                self._initialize_model()
        else:
            self._initialize_model()
    
    def _initialize_model(self):
        """Initialize a new model."""
        if XGBOOST_AVAILABLE:
            self.model = xgb.XGBRegressor(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1
            )
            logger.info("Initialized XGBoost risk predictor")
        else:
            # Fallback to scikit-learn
            self.model = GradientBoostingRegressor(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            )
            logger.info("Initialized GradientBoosting risk predictor (XGBoost not available)")
    
    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2):
        """
        Train the risk prediction model.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Target risk scores (n_samples,)
            validation_split: Fraction of data to use for validation
        """
        if X.size == 0 or len(X) == 0:
            raise ValueError("Training data is empty")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=validation_split, random_state=42
        )
        
        # Train model
        if XGBOOST_AVAILABLE and isinstance(self.model, xgb.XGBRegressor):
            self.model.fit(
                X_train, y_train,
                eval_set=[(X_test, y_test)],
                early_stopping_rounds=10,
                verbose=False
            )
        else:
            self.model.fit(X_train, y_train)
        
        # Evaluate
        train_pred = self.model.predict(X_train)
        test_pred = self.model.predict(X_test)
        
        train_r2 = r2_score(y_train, train_pred)
        test_r2 = r2_score(y_test, test_pred)
        train_mae = mean_absolute_error(y_train, train_pred)
        test_mae = mean_absolute_error(y_test, test_pred)
        
        logger.info(f"Training R² score: {train_r2:.4f}")
        logger.info(f"Test R² score: {test_r2:.4f}")
        logger.info(f"Training MAE: {train_mae:.4f}")
        logger.info(f"Test MAE: {test_mae:.4f}")
        
        # Save model
        self._save_model()
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict risk scores.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Predicted risk scores (n_samples,)
        """
        if self.model is None:
            raise ValueError("Model not initialized. Train or load a model first.")
        
        if not self.is_trained:
            logger.warning("Model not trained. Using untrained model for prediction.")
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)
        
        # Ensure predictions are in valid range [0, 100]
        predictions = np.clip(predictions, 0, 100)
        
        return predictions
    
    def predict_with_confidence(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict risk scores with confidence intervals.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            
        Returns:
            Tuple of (predictions, confidence_scores)
        """
        predictions = self.predict(X)
        
        # Calculate confidence using prediction variance
        # For tree-based models, we can use prediction intervals
        if hasattr(self.model, 'predict_proba'):
            # If model supports probability prediction
            proba = self.model.predict_proba(X)
            confidence = np.max(proba, axis=1)
        else:
            # Estimate confidence based on prediction consistency
            # Use a simple heuristic: higher confidence for predictions near 0 or 100
            # Lower confidence for predictions in the middle range
            confidence = 1.0 - np.abs(predictions - 50) / 50.0
            confidence = np.clip(confidence, 0.5, 0.95)  # Clamp between 0.5 and 0.95
        
        return predictions, confidence
    
    def _save_model(self):
        """Save model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }
        
        joblib.dump(model_data, self.model_path)
        logger.info(f"Model saved to {self.model_path}")
    
    def get_feature_importance(self) -> Optional[np.ndarray]:
        """Get feature importance if available."""
        if self.model is None:
            return None
        
        if hasattr(self.model, 'feature_importances_'):
            return self.model.feature_importances_
        elif hasattr(self.model, 'get_feature_importance'):
            return self.model.get_feature_importance()
        else:
            return None

