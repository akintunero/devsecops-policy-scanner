"""
ML-powered security analyzer for advanced threat detection and analysis.
This is a compatibility wrapper around the new AI engine.
"""

from datetime import datetime
from typing import Any, Dict, List

import numpy as np

from dsp_scanner.core.results import ScanResult
from dsp_scanner.ml.ai_engine import AIRiskPredictionEngine
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityAnalyzer:
    """
    AI-powered security analyzer that uses machine learning for advanced
    security analysis, including zero-day detection, pattern recognition,
    and risk prediction.

    This class wraps the new AIRiskPredictionEngine for backward compatibility.
    """

    def __init__(self):
        """Initialize the security analyzer with ML models."""
        # Use the new AI engine
        self.ai_engine = AIRiskPredictionEngine(
            enable_risk_prediction=True,
            enable_anomaly_detection=True,
            enable_zero_day_prediction=True,
        )

        # Keep old attributes for backward compatibility
        self.zero_day_detector = self.ai_engine.zero_day_predictor
        self.risk_predictor = self.ai_engine.risk_predictor
        self.pattern_analyzer = self.ai_engine.anomaly_detector
        self.behavioral_analyzer = None

    async def detect_zero_days(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """
        Detect potential zero-day vulnerabilities using ML models.

        Args:
            scan_result: Scan result containing findings to analyze

        Returns:
            List of potential zero-day vulnerabilities
        """
        try:
            # Use new AI engine
            ai_results = await self.ai_engine.analyze(scan_result)
            zero_day_pred = ai_results.get("zero_day_prediction", {})

            if zero_day_pred.get("is_potential_zero_day", False):
                return [
                    {
                        "title": "Potential Zero-day Vulnerability Detected",
                        "description": (
                            "ML model detected patterns indicating a potential zero-day vulnerability "
                            f"(Probability: {zero_day_pred.get('zero_day_probability', 0) * 100:.1f}%)"
                        ),
                        "confidence_score": zero_day_pred.get("confidence", 0),
                        "severity": zero_day_pred.get("severity", "high"),
                        "detection_time": datetime.utcnow().isoformat(),
                        "recommendations": self._generate_zero_day_recommendations(
                            None
                        ),
                    }
                ]
        except Exception as e:
            logger.error(f"Zero-day detection failed: {str(e)}")

        return []

    async def analyze_patterns(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Analyze infrastructure patterns for potential security issues."""
        try:
            ai_results = await self.ai_engine.analyze(scan_result)
            anomaly_det = ai_results.get("anomaly_detection", {})

            patterns: List[Dict[str, Any]] = []
            for anomaly in anomaly_det.get("anomalies", []):
                patterns.append(
                    {
                        "title": "Anomalous Security Pattern Detected",
                        "description": (
                            "ML model detected an anomalous pattern "
                            f"(Score: {anomaly.get('anomaly_score', 0):.4f})"
                        ),
                        "severity": anomaly.get("severity", "medium"),
                        "anomaly_score": anomaly.get("anomaly_score", 0),
                        "detection_time": datetime.utcnow().isoformat(),
                    }
                )

            # Heuristic fallback: if ML can't produce anomalies (e.g. untrained models)
            # but we do have findings, emit at least one pattern so callers can surface
            # a useful "AI analysis" signal.
            if not patterns and getattr(scan_result, "findings", None):
                joined = "\n".join(
                    [
                        f"{f.title} {f.description} {(f.code_snippet or '')}".lower()
                        for f in scan_result.findings
                    ]
                )
                suspicious = any(
                    term in joined
                    for term in [
                        "privileged",
                        "password",
                        "secret",
                        "token",
                        "0.0.0.0/0",
                        "latest",
                        "curl",
                        "| bash",
                    ]
                )

                patterns.append(
                    {
                        "title": "Potentially Risky Configuration Pattern",
                        "description": (
                            "Heuristic analysis detected patterns that commonly correlate with security risk."
                            if suspicious
                            else "Heuristic analysis found findings worth review."
                        ),
                        "severity": "high" if suspicious else "medium",
                        "anomaly_score": 0.0,
                        "detection_time": datetime.utcnow().isoformat(),
                    }
                )

            return patterns
        except Exception as e:
            logger.error(f"Pattern analysis failed: {str(e)}")
            return []

    async def predict_risks(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """
        Predict potential security risks based on current findings.

        Args:
            scan_result: Scan result to analyze

        Returns:
            List of predicted security risks
        """
        try:
            # Use new AI engine
            ai_results = await self.ai_engine.analyze(scan_result)
            risk_pred = ai_results.get("risk_prediction", {})

            return [
                {
                    "predicted_risk_score": risk_pred.get("predicted_risk_score", 0),
                    "confidence": risk_pred.get("confidence", 0),
                    "risk_level": risk_pred.get("risk_level", "unknown"),
                    "detection_time": datetime.utcnow().isoformat(),
                }
            ]
        except Exception as e:
            logger.error(f"Risk prediction failed: {str(e)}")
            return []

    async def generate_recommendations(
        self, scan_result: ScanResult
    ) -> List[Dict[str, Any]]:
        """
        Generate AI-powered security recommendations.

        Args:
            scan_result: Scan result to analyze

        Returns:
            List of security recommendations
        """
        try:
            # Use new AI engine
            ai_results = await self.ai_engine.analyze(scan_result)
            recommendations = ai_results.get("recommendations", [])

            # Convert to dict format for backward compatibility
            return [
                {"title": rec, "description": rec, "priority": 1}
                for rec in recommendations
            ]
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
            return []

    def _create_zero_day_finding(
        self, finding: Any, features: np.ndarray
    ) -> Dict[str, Any]:
        """Create a zero-day finding entry."""
        return {
            "title": f"Potential Zero-day Vulnerability in {finding.location}",
            "description": (
                "ML model has detected patterns indicating a potential "
                "zero-day vulnerability."
            ),
            "confidence_score": self._calculate_confidence(features),
            "severity": "critical",
            "detection_time": datetime.utcnow().isoformat(),
            "related_finding": finding.id,
            "features": features.tolist(),
            "recommendations": self._generate_zero_day_recommendations(finding),
        }

    @staticmethod
    def _calculate_confidence(features: np.ndarray) -> float:
        """Heuristic confidence score for legacy API compatibility."""
        try:
            # Lower variance -> higher confidence.
            std = float(np.std(features))
            return float(np.clip(1.0 / (1.0 + std), 0.0, 1.0))
        except Exception:
            return 0.5

    @staticmethod
    def _generate_zero_day_recommendations(finding: Any) -> List[str]:
        """Generate recommendations for zero-day findings."""
        return [
            "Immediately isolate affected components",
            "Conduct detailed vulnerability assessment",
            "Implement temporary security controls",
            "Monitor for exploitation attempts",
            "Prepare incident response plan",
        ]
