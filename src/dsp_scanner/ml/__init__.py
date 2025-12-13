"""
Machine Learning modules for DSP Scanner

Uses lazy imports to avoid import-time dependency issues.
"""

from typing import Any

__all__ = [
    "AIRiskPredictionEngine",
    "SecurityAnalyzer",
    "SecurityFeatureExtractor",
    "RiskPredictor",
    "SecurityAnomalyDetector",
    "ZeroDayPredictor",
]


def __getattr__(name: str) -> Any:
    """Lazy import ML modules to avoid import-time dependency failures."""
    if name == "AIRiskPredictionEngine":
        from dsp_scanner.ml.ai_engine import AIRiskPredictionEngine

        return AIRiskPredictionEngine
    if name == "SecurityAnalyzer":
        from dsp_scanner.ml.analyzer import SecurityAnalyzer

        return SecurityAnalyzer
    if name == "SecurityFeatureExtractor":
        from dsp_scanner.ml.features.feature_extractor import SecurityFeatureExtractor

        return SecurityFeatureExtractor
    if name == "SecurityAnomalyDetector":
        from dsp_scanner.ml.models.anomaly_detector import SecurityAnomalyDetector

        return SecurityAnomalyDetector
    if name == "RiskPredictor":
        from dsp_scanner.ml.models.risk_predictor import RiskPredictor

        return RiskPredictor
    if name == "ZeroDayPredictor":
        from dsp_scanner.ml.models.zero_day_predictor import ZeroDayPredictor

        return ZeroDayPredictor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
