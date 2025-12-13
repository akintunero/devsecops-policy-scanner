"""Tests for `SecurityAnalyzer` compatibility wrapper.

The current implementation wraps `AIRiskPredictionEngine` (scikit-learn based).
These tests avoid TensorFlow entirely and focus on the wrapper contract.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest

from dsp_scanner.core.results import Finding, ScanResult, Severity

# Gracefully handle ML imports - skip tests if dependencies aren't available
ML_IMPORT_ERROR = None
try:
    from dsp_scanner.ml.analyzer import SecurityAnalyzer
    ML_AVAILABLE = True
except ImportError as e:
    ML_AVAILABLE = False
    ML_IMPORT_ERROR = str(e)
    SecurityAnalyzer = None

# Skip all tests in this module if ML dependencies aren't available
pytestmark = pytest.mark.skipif(
    not ML_AVAILABLE,
    reason=f"ML dependencies not available: {ML_IMPORT_ERROR or 'Unknown error'}"
)


@pytest.fixture
def mock_scan_result() -> ScanResult:
    result = ScanResult()
    result.findings = [
        Finding(
            id="TEST001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            platform="docker",
            location="Dockerfile:1",
            code_snippet="FROM python:latest",
            recommendation="Use specific version",
        ),
        Finding(
            id="TEST002",
            title="Another Finding",
            description="Another description",
            severity=Severity.CRITICAL,
            platform="kubernetes",
            location="deployment.yaml:1",
            code_snippet="privileged: true",
            recommendation="Avoid privileged containers",
        ),
    ]
    return result


@pytest.fixture
def analyzer() -> SecurityAnalyzer:
    # Avoid instantiating real ML models in unit tests.
    engine = Mock()
    engine.zero_day_predictor = Mock()
    engine.risk_predictor = Mock()
    engine.anomaly_detector = Mock()
    engine.analyze = AsyncMock(
        return_value={
            "risk_prediction": {
                "predicted_risk_score": 10.0,
                "confidence": 0.7,
                "risk_level": "low",
            },
            "anomaly_detection": {
                "anomalies": [],
                "anomalies_detected": 0,
                "anomaly_score": 0.0,
                "is_anomalous": False,
            },
            "zero_day_prediction": {
                "zero_day_probability": 0.1,
                "confidence": 0.6,
                "is_potential_zero_day": False,
                "severity": "low",
            },
            "recommendations": [
                "✅ Security posture appears acceptable. Continue monitoring."
            ],
        }
    )

    with patch("dsp_scanner.ml.analyzer.AIRiskPredictionEngine", return_value=engine):
        return SecurityAnalyzer()


@pytest.mark.asyncio
async def test_detect_zero_days_returns_empty_when_not_flagged(
    analyzer, mock_scan_result
):
    analyzer.ai_engine.analyze.return_value = {
        "zero_day_prediction": {
            "is_potential_zero_day": False,
            "zero_day_probability": 0.1,
        },
        "anomaly_detection": {"anomalies": []},
        "risk_prediction": {},
        "recommendations": [],
    }

    zero_days = await analyzer.detect_zero_days(mock_scan_result)
    assert zero_days == []


@pytest.mark.asyncio
async def test_detect_zero_days_returns_item_when_flagged(analyzer, mock_scan_result):
    analyzer.ai_engine.analyze.return_value = {
        "zero_day_prediction": {
            "is_potential_zero_day": True,
            "zero_day_probability": 0.9,
            "confidence": 0.8,
            "severity": "critical",
        },
        "anomaly_detection": {"anomalies": []},
        "risk_prediction": {},
        "recommendations": [],
    }

    zero_days = await analyzer.detect_zero_days(mock_scan_result)
    assert len(zero_days) == 1
    assert "zero-day" in zero_days[0]["title"].lower()
    assert zero_days[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_analyze_patterns_maps_engine_anomalies(analyzer, mock_scan_result):
    analyzer.ai_engine.analyze.return_value = {
        "zero_day_prediction": {},
        "risk_prediction": {},
        "recommendations": [],
        "anomaly_detection": {
            "anomalies": [{"anomaly_score": -0.42, "severity": "high"}],
        },
    }

    patterns = await analyzer.analyze_patterns(mock_scan_result)
    assert len(patterns) == 1
    assert patterns[0]["severity"] == "high"
    assert "anomalous" in patterns[0]["title"].lower()


@pytest.mark.asyncio
async def test_predict_risks_returns_engine_risk_summary(analyzer, mock_scan_result):
    analyzer.ai_engine.analyze.return_value = {
        "risk_prediction": {
            "predicted_risk_score": 72.5,
            "confidence": 0.9,
            "risk_level": "high",
        },
        "anomaly_detection": {},
        "zero_day_prediction": {},
        "recommendations": [],
    }

    risks = await analyzer.predict_risks(mock_scan_result)
    assert len(risks) == 1
    assert risks[0]["predicted_risk_score"] == 72.5
    assert risks[0]["confidence"] == 0.9
    assert risks[0]["risk_level"] == "high"
    assert isinstance(risks[0]["detection_time"], str)


@pytest.mark.asyncio
async def test_generate_recommendations_wraps_strings(analyzer, mock_scan_result):
    analyzer.ai_engine.analyze.return_value = {
        "risk_prediction": {},
        "anomaly_detection": {},
        "zero_day_prediction": {},
        "recommendations": ["Do X", "Do Y"],
    }

    recs = await analyzer.generate_recommendations(mock_scan_result)
    assert recs == [
        {"title": "Do X", "description": "Do X", "priority": 1},
        {"title": "Do Y", "description": "Do Y", "priority": 1},
    ]


@pytest.mark.asyncio
async def test_methods_return_empty_on_engine_error(analyzer, mock_scan_result):
    analyzer.ai_engine.analyze.side_effect = Exception("boom")

    assert await analyzer.detect_zero_days(mock_scan_result) == []
    assert await analyzer.analyze_patterns(mock_scan_result) == []
    assert await analyzer.predict_risks(mock_scan_result) == []
    assert await analyzer.generate_recommendations(mock_scan_result) == []
