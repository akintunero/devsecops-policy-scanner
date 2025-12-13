"""
Main AI engine for security risk prediction.
Integrates risk prediction, anomaly detection, and zero-day prediction.
"""

from typing import Any, Dict, List, Optional

import numpy as np

from dsp_scanner.core.results import ScanResult
from dsp_scanner.ml.features.feature_extractor import SecurityFeatureExtractor
from dsp_scanner.ml.models.anomaly_detector import SecurityAnomalyDetector
from dsp_scanner.ml.models.risk_predictor import RiskPredictor
from dsp_scanner.ml.models.zero_day_predictor import ZeroDayPredictor
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class AIRiskPredictionEngine:
    """AI-powered risk prediction engine integrating all ML components."""

    def __init__(
        self,
        enable_risk_prediction: bool = True,
        enable_anomaly_detection: bool = True,
        enable_zero_day_prediction: bool = True,
        model_dir: str = "models",
    ):
        """
        Initialize AI risk prediction engine.

        Args:
            enable_risk_prediction: Enable risk score prediction
            enable_anomaly_detection: Enable anomaly detection
            enable_zero_day_prediction: Enable zero-day prediction
            model_dir: Directory to store/load models
        """
        self.enable_risk_prediction = enable_risk_prediction
        self.enable_anomaly_detection = enable_anomaly_detection
        self.enable_zero_day_prediction = enable_zero_day_prediction

        # Initialize feature extractor
        self.feature_extractor = SecurityFeatureExtractor()

        # Initialize models
        self.risk_predictor = None
        self.anomaly_detector = None
        self.zero_day_predictor = None

        if enable_risk_prediction:
            self.risk_predictor = RiskPredictor(
                model_path=f"{model_dir}/risk_predictor.pkl"
            )

        if enable_anomaly_detection:
            self.anomaly_detector = SecurityAnomalyDetector(
                model_path=f"{model_dir}/anomaly_detector.pkl"
            )

        if enable_zero_day_prediction:
            self.zero_day_predictor = ZeroDayPredictor(
                model_path=f"{model_dir}/zero_day_predictor.pkl"
            )

        logger.info("AI Risk Prediction Engine initialized")

    async def analyze(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Perform comprehensive AI analysis on scan results.

        Args:
            scan_result: Scan result to analyze

        Returns:
            Dictionary containing all AI analysis results
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_features(scan_result)
            features = features.reshape(1, -1)  # Reshape for single prediction

            results = {
                "ai_analysis": True,
                "features_extracted": len(features[0]),
                "risk_prediction": {},
                "anomaly_detection": {},
                "zero_day_prediction": {},
                "recommendations": [],
            }

            # Risk prediction
            if self.enable_risk_prediction and self.risk_predictor:
                try:
                    risk_score, confidence = (
                        self.risk_predictor.predict_with_confidence(features)
                    )
                    results["risk_prediction"] = {
                        "predicted_risk_score": float(risk_score[0]),
                        "confidence": float(confidence[0]),
                        "risk_level": self._classify_risk_level(float(risk_score[0])),
                    }
                except Exception as e:
                    logger.warning(f"Risk prediction failed: {e}")
                    results["risk_prediction"] = {"error": str(e)}

            # Anomaly detection
            if self.enable_anomaly_detection and self.anomaly_detector:
                try:
                    anomalies = self.anomaly_detector.detect_anomalies(features)
                    anomaly_scores = self.anomaly_detector.get_anomaly_scores(features)

                    results["anomaly_detection"] = {
                        "anomalies_detected": len(anomalies),
                        "anomalies": anomalies,
                        "anomaly_score": float(anomaly_scores[0]),
                        "is_anomalous": len(anomalies) > 0,
                    }
                except Exception as e:
                    logger.warning(f"Anomaly detection failed: {e}")
                    results["anomaly_detection"] = {"error": str(e)}

            # Zero-day prediction
            if self.enable_zero_day_prediction and self.zero_day_predictor:
                try:
                    zero_day_prob, zero_day_confidence = (
                        self.zero_day_predictor.predict_with_confidence(features)
                    )

                    results["zero_day_prediction"] = {
                        "zero_day_probability": float(zero_day_prob[0]),
                        "confidence": float(zero_day_confidence[0]),
                        "is_potential_zero_day": float(zero_day_prob[0]) > 0.5,
                        "severity": self._classify_zero_day_severity(
                            float(zero_day_prob[0])
                        ),
                    }
                except Exception as e:
                    logger.warning(f"Zero-day prediction failed: {e}")
                    results["zero_day_prediction"] = {"error": str(e)}

            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(
                scan_result, results
            )

            return results

        except Exception as e:
            logger.error(f"AI analysis failed: {e}", exc_info=True)
            return {
                "ai_analysis": False,
                "error": str(e),
                "risk_prediction": {},
                "anomaly_detection": {},
                "zero_day_prediction": {},
                "recommendations": [],
            }

    def _classify_risk_level(self, risk_score: float) -> str:
        """Classify risk level based on score."""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        elif risk_score >= 20:
            return "low"
        else:
            return "minimal"

    def _classify_zero_day_severity(self, probability: float) -> str:
        """Classify zero-day severity based on probability."""
        if probability >= 0.8:
            return "critical"
        elif probability >= 0.6:
            return "high"
        elif probability >= 0.4:
            return "medium"
        else:
            return "low"

    def _generate_recommendations(
        self, scan_result: ScanResult, ai_results: Dict[str, Any]
    ) -> List[str]:
        """Generate AI-powered security recommendations."""
        recommendations = []

        # Risk-based recommendations
        risk_pred = ai_results.get("risk_prediction", {})
        if risk_pred.get("predicted_risk_score", 0) > 70:
            recommendations.append(
                f"🚨 High risk detected (Score: {risk_pred.get('predicted_risk_score', 0):.1f}/100). "
                "Immediate security review recommended."
            )

        # Anomaly-based recommendations
        anomaly_det = ai_results.get("anomaly_detection", {})
        if anomaly_det.get("anomalies_detected", 0) > 0:
            recommendations.append(
                f"⚠️ {anomaly_det.get('anomalies_detected', 0)} anomalous patterns detected. "
                "These may indicate novel security issues requiring investigation."
            )

        # Zero-day recommendations
        zero_day = ai_results.get("zero_day_prediction", {})
        if zero_day.get("is_potential_zero_day", False):
            prob = zero_day.get("zero_day_probability", 0) * 100
            recommendations.append(
                f"🔴 Potential zero-day vulnerability detected ({prob:.1f}% probability). "
                "Immediate isolation and detailed analysis required."
            )

        # Severity-based recommendations
        critical_findings = [
            f for f in scan_result.findings if f.severity.value == "critical"
        ]
        if critical_findings:
            recommendations.append(
                f"🔴 {len(critical_findings)} critical findings require immediate attention."
            )

        # General recommendations
        if not recommendations:
            recommendations.append(
                "✅ Security posture appears acceptable. Continue monitoring."
            )

        return recommendations

    def train_models(
        self,
        training_data: List[ScanResult],
        risk_labels: Optional[np.ndarray] = None,
        zero_day_labels: Optional[np.ndarray] = None,
    ):
        """
        Train all ML models on historical data.

        Args:
            training_data: List of historical scan results
            risk_labels: Risk scores for training (0-100)
            zero_day_labels: Binary labels for zero-day training (0 or 1)
        """
        if not training_data:
            raise ValueError("Training data is empty")

        # Extract features from all training data
        X = np.array(
            [
                self.feature_extractor.extract_features(result)
                for result in training_data
            ]
        )

        logger.info(f"Extracted features from {len(training_data)} scan results")
        logger.info(f"Feature matrix shape: {X.shape}")

        # Train risk predictor
        if (
            self.enable_risk_prediction
            and self.risk_predictor
            and risk_labels is not None
        ):
            logger.info("Training risk predictor...")
            self.risk_predictor.train(X, risk_labels)

        # Train anomaly detector (unsupervised - no labels needed)
        if self.enable_anomaly_detection and self.anomaly_detector:
            logger.info("Training anomaly detector...")
            self.anomaly_detector.train(X)

        # Train zero-day predictor
        if (
            self.enable_zero_day_prediction
            and self.zero_day_predictor
            and zero_day_labels is not None
        ):
            logger.info("Training zero-day predictor...")
            self.zero_day_predictor.train(X, zero_day_labels)

        logger.info("All models trained successfully")
