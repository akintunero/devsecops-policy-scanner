"""
Zero-day vulnerability prediction using ensemble methods.
Combines multiple ML models to predict potential zero-day vulnerabilities.
"""
import os
from typing import Any, Dict, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class ZeroDayPredictor:
    """Predict zero-day vulnerabilities using ensemble of ML models."""

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize zero-day predictor.

        Args:
            model_path: Path to save/load model. Defaults to models/zero_day_predictor.pkl
        """
        self.model_path = model_path or "models/zero_day_predictor.pkl"
        self.model: Any = None
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
                    self.model = loaded
                    self.is_trained = True
                logger.info(f"Loaded zero-day predictor from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}. Initializing new model.")
                self._initialize_model()
        else:
            self._initialize_model()

    def _initialize_model(self):
        """Initialize ensemble model."""
        estimators = [
            ('rf', RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )),
            ('mlp', MLPClassifier(
                hidden_layer_sizes=(50, 25),
                max_iter=500,
                random_state=42
            ))
        ]

        # Add XGBoost if available
        if XGBOOST_AVAILABLE:
            estimators.append(('xgb', xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1
            )))

        self.model = VotingClassifier(
            estimators=estimators,
            voting='soft'  # Use probability voting
        )
        logger.info("Initialized zero-day predictor ensemble")

    def train(self, X: np.ndarray, y: np.ndarray, validation_split: float = 0.2):
        """
        Train zero-day prediction model.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Binary labels (1 = zero-day, 0 = not zero-day)
            validation_split: Fraction of data to use for validation
        """
        if X.size == 0 or len(X) == 0:
            raise ValueError("Training data is empty")

        # Check for class imbalance
        unique, counts = np.unique(y, return_counts=True)
        logger.info(f"Class distribution: {dict(zip(unique, counts))}")

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=validation_split, random_state=42, stratify=y
        )

        # Train model
        self.model.fit(X_train, y_train)

        # Evaluate
        train_pred = self.model.predict(X_train)
        test_pred = self.model.predict(X_test)
        test_proba = self.model.predict_proba(X_test)[:, 1]

        train_acc = np.mean(train_pred == y_train)
        test_acc = np.mean(test_pred == y_test)

        # Calculate AUC-ROC if we have both classes
        if len(np.unique(y_test)) > 1:
            auc_score = roc_auc_score(y_test, test_proba)
            logger.info(f"Test AUC-ROC: {auc_score:.4f}")

        logger.info(f"Training accuracy: {train_acc:.4f}")
        logger.info(f"Test accuracy: {test_acc:.4f}")

        # Detailed classification report
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, test_pred))

        # Save model
        self._save_model()
        self.is_trained = True

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict zero-day probabilities.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Probabilities of zero-day (n_samples,)
        """
        if self.model is None:
            raise ValueError("Model not initialized. Train or load a model first.")

        if not self.is_trained:
            logger.warning("Model not trained. Using untrained model for prediction.")

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Predict probabilities
        probabilities = self.model.predict_proba(X_scaled)[:, 1]  # Probability of zero-day

        return probabilities

    def predict_binary(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """
        Predict binary zero-day classification.

        Args:
            X: Feature matrix (n_samples, n_features)
            threshold: Probability threshold for classification

        Returns:
            Binary predictions (1 = zero-day, 0 = not zero-day)
        """
        probabilities = self.predict(X)
        return (probabilities >= threshold).astype(int)

    def predict_with_confidence(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict zero-day probabilities with confidence scores.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Tuple of (probabilities, confidence_scores)
        """
        probabilities = self.predict(X)

        # Confidence is based on how far from 0.5 the probability is
        # Higher confidence for probabilities near 0 or 1
        confidence = 1.0 - 2.0 * np.abs(probabilities - 0.5)
        confidence = np.clip(confidence, 0.0, 1.0)

        return probabilities, confidence

    def _save_model(self):
        """Save model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }

        joblib.dump(model_data, self.model_path)
        logger.info(f"Zero-day predictor saved to {self.model_path}")

    def get_feature_importance(self) -> Optional[Dict[str, np.ndarray]]:
        """Get feature importance from ensemble models."""
        if self.model is None:
            return None

        importances = {}

        # Get importances from each estimator
        for name, estimator in self.model.named_estimators_.items():
            if hasattr(estimator, 'feature_importances_'):
                importances[name] = estimator.feature_importances_
            elif hasattr(estimator, 'coef_'):
                # For neural networks, use absolute coefficients
                importances[name] = np.abs(estimator.coef_[0])

        return importances if importances else None
