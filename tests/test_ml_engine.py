"""
Tests for ML engine components.
"""

import numpy as np
import pytest

from dsp_scanner.core.results import Finding, ScanResult, Severity
from dsp_scanner.ml.ai_engine import AIRiskPredictionEngine
from dsp_scanner.ml.features.feature_extractor import SecurityFeatureExtractor
from dsp_scanner.ml.models.anomaly_detector import SecurityAnomalyDetector
from dsp_scanner.ml.models.risk_predictor import RiskPredictor
from dsp_scanner.ml.models.zero_day_predictor import ZeroDayPredictor


@pytest.fixture
def sample_scan_result():
    """Create a sample scan result for testing."""
    result = ScanResult()

    # Add some test findings
    result.findings.append(
        Finding(
            id="test_1",
            title="Critical Security Issue",
            description="This is a critical security vulnerability",
            severity=Severity.CRITICAL,
            location="test.yaml",
            platform="kubernetes",
            code_snippet="apiVersion: v1\nkind: Pod",
            cvss_score=9.5,
        )
    )

    result.findings.append(
        Finding(
            id="test_2",
            title="Secret Exposure",
            description="Hardcoded password detected",
            severity=Severity.HIGH,
            location="config.yaml",
            platform="kubernetes",
            code_snippet="password: secret123",
        )
    )

    return result


def test_feature_extraction(sample_scan_result):
    """Test feature extraction."""
    extractor = SecurityFeatureExtractor()
    features = extractor.extract_features(sample_scan_result)

    assert features.shape[0] > 0
    assert not np.isnan(features).any()
    assert not np.isinf(features).any()
    assert len(features) == len(extractor.feature_names)


def test_risk_predictor_initialization():
    """Test risk predictor initialization."""
    predictor = RiskPredictor(model_path="models/test_risk_predictor.pkl")
    assert predictor.model is not None


def test_risk_predictor_training():
    """Test risk predictor training."""
    predictor = RiskPredictor(model_path="models/test_risk_predictor.pkl")

    # Generate synthetic training data
    X = np.random.rand(100, 20)
    y = np.random.uniform(0, 100, 100)

    predictor.train(X, y)
    assert predictor.is_trained


def test_risk_predictor_prediction():
    """Test risk predictor prediction."""
    predictor = RiskPredictor(model_path="models/test_risk_predictor.pkl")

    # Train first
    X_train = np.random.rand(100, 20)
    y_train = np.random.uniform(0, 100, 100)
    predictor.train(X_train, y_train)

    # Predict
    X_test = np.random.rand(10, 20)
    predictions = predictor.predict(X_test)

    assert len(predictions) == 10
    assert all(0 <= p <= 100 for p in predictions)


def test_anomaly_detector_initialization():
    """Test anomaly detector initialization."""
    detector = SecurityAnomalyDetector(model_path="models/test_anomaly_detector.pkl")
    assert detector.model is not None


def test_anomaly_detector_training():
    """Test anomaly detector training."""
    detector = SecurityAnomalyDetector(model_path="models/test_anomaly_detector.pkl")

    # Generate synthetic training data
    X = np.random.rand(100, 20)

    detector.train(X)
    assert detector.is_trained


def test_anomaly_detection():
    """Test anomaly detection."""
    detector = SecurityAnomalyDetector(model_path="models/test_anomaly_detector.pkl")

    # Train first
    X_train = np.random.rand(100, 20)
    detector.train(X_train)

    # Detect anomalies
    X_test = np.random.rand(10, 20)
    anomalies = detector.detect_anomalies(X_test)

    assert isinstance(anomalies, list)
    for anomaly in anomalies:
        assert "index" in anomaly
        assert "anomaly_score" in anomaly
        assert "severity" in anomaly


def test_zero_day_predictor_initialization():
    """Test zero-day predictor initialization."""
    predictor = ZeroDayPredictor(model_path="models/test_zero_day_predictor.pkl")
    assert predictor.model is not None


def test_zero_day_predictor_training():
    """Test zero-day predictor training."""
    predictor = ZeroDayPredictor(model_path="models/test_zero_day_predictor.pkl")

    # Generate synthetic training data
    X = np.random.rand(100, 20)
    y = np.random.randint(0, 2, 100)  # Binary labels

    predictor.train(X, y)
    assert predictor.is_trained


def test_zero_day_prediction():
    """Test zero-day prediction."""
    predictor = ZeroDayPredictor(model_path="models/test_zero_day_predictor.pkl")

    # Train first
    X_train = np.random.rand(100, 20)
    y_train = np.random.randint(0, 2, 100)
    predictor.train(X_train, y_train)

    # Predict
    X_test = np.random.rand(10, 20)
    probabilities = predictor.predict(X_test)

    assert len(probabilities) == 10
    assert all(0 <= p <= 1 for p in probabilities)


@pytest.mark.asyncio
async def test_ai_engine_analysis(sample_scan_result):
    """Test AI engine analysis."""
    engine = AIRiskPredictionEngine(
        enable_risk_prediction=True,
        enable_anomaly_detection=True,
        enable_zero_day_prediction=True,
    )

    results = await engine.analyze(sample_scan_result)

    assert "ai_analysis" in results
    assert "risk_prediction" in results
    assert "anomaly_detection" in results
    assert "zero_day_prediction" in results
    assert "recommendations" in results


def test_ai_engine_training():
    """Test AI engine training."""
    engine = AIRiskPredictionEngine()

    # Generate synthetic training data
    training_data = []
    for i in range(50):
        result = ScanResult()
        result.findings.append(
            Finding(
                id=f"test_{i}",
                title="Test Finding",
                description="Test",
                severity=Severity.MEDIUM,
                location="test.yaml",
                platform="kubernetes",
            )
        )
        training_data.append(result)

    risk_labels = np.random.uniform(0, 100, 50)
    zero_day_labels = np.random.randint(0, 2, 50)

    # Should not raise exception
    engine.train_models(training_data, risk_labels, zero_day_labels)
