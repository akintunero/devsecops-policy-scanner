"""
Tests for the ML-powered security analyzer.
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch
import tensorflow as tf
from datetime import datetime

from dsp_scanner.ml.analyzer import SecurityAnalyzer
from dsp_scanner.core.results import Finding, Severity, ScanResult

@pytest.fixture
def analyzer():
    """Create a security analyzer instance for testing."""
    return SecurityAnalyzer()

@pytest.fixture
def mock_scan_result():
    """Create a mock scan result for testing."""
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
            recommendation="Use specific version"
        ),
        Finding(
            id="TEST002",
            title="Another Finding",
            description="Another description",
            severity=Severity.CRITICAL,
            platform="kubernetes",
            location="deployment.yaml:1",
            code_snippet="privileged: true",
            recommendation="Avoid privileged containers"
        )
    ]
    return result

@pytest.mark.asyncio
async def test_zero_day_detection(analyzer, mock_scan_result):
    """Test zero-day vulnerability detection."""
    # Mock the model prediction
    with patch.object(analyzer, 'zero_day_detector') as mock_detector:
        mock_detector.predict.return_value = np.array([-1, 1])  # -1 indicates anomaly
        
        zero_days = await analyzer.detect_zero_days(mock_scan_result)
        
        assert len(zero_days) == 1
        assert zero_days[0]["severity"] == "critical"
        assert "zero-day" in zero_days[0]["title"].lower()
        assert isinstance(zero_days[0]["confidence_score"], float)
        assert isinstance(zero_days[0]["detection_time"], str)

@pytest.mark.asyncio
async def test_pattern_analysis(analyzer, mock_scan_result):
    """Test infrastructure pattern analysis."""
    with patch.object(analyzer, 'pattern_analyzer') as mock_analyzer:
        mock_analyzer.predict.return_value = np.array([0.8, 0.3])
        
        patterns = await analyzer.analyze_patterns(mock_scan_result)
        
        assert len(patterns) > 0
        assert all(isinstance(p, dict) for p in patterns)
        assert all("confidence_score" in p for p in patterns)

@pytest.mark.asyncio
async def test_risk_prediction(analyzer, mock_scan_result):
    """Test security risk prediction."""
    with patch.object(analyzer, 'risk_predictor') as mock_predictor:
        mock_predictor.predict.return_value = np.array([[0.9, 0.1], [0.4, 0.6]])
        
        risks = await analyzer.predict_risks(mock_scan_result)
        
        assert len(risks) > 0
        assert all(isinstance(r, dict) for r in risks)
        assert all("probability" in r for r in risks)

@pytest.mark.asyncio
async def test_recommendation_generation(analyzer, mock_scan_result):
    """Test AI-powered recommendation generation."""
    recommendations = await analyzer.generate_recommendations(mock_scan_result)
    
    assert len(recommendations) > 0
    assert all(isinstance(r, dict) for r in recommendations)
    assert all("title" in r and "description" in r for r in recommendations)

def test_model_initialization(analyzer):
    """Test ML model initialization."""
    assert analyzer.zero_day_detector is not None
    assert analyzer.pattern_analyzer is not None
    assert analyzer.risk_predictor is not None

def test_fallback_models(analyzer):
    """Test fallback model initialization when pre-trained models fail to load."""
    with patch('tensorflow.keras.models.load_model', side_effect=Exception):
        fallback_analyzer = SecurityAnalyzer()
        
        assert fallback_analyzer.zero_day_detector is not None
        assert fallback_analyzer.pattern_analyzer is not None
        assert isinstance(fallback_analyzer.zero_day_detector, object)

def test_feature_extraction(analyzer, mock_scan_result):
    """Test feature extraction for ML models."""
    features = analyzer._extract_zero_day_features(mock_scan_result)
    
    assert isinstance(features, np.ndarray)
    assert features.shape[0] == len(mock_scan_result.findings)
    assert features.shape[1] > 0  # Should have multiple features per finding

@pytest.mark.asyncio
async def test_confidence_calculation(analyzer):
    """Test confidence score calculation."""
    features = np.array([[0.8, 0.9, 0.7], [0.2, 0.3, 0.1]])
    confidence = analyzer._calculate_confidence(features)
    
    assert isinstance(confidence, float)
    assert 0 <= confidence <= 1

def test_severity_encoding(analyzer):
    """Test severity level encoding."""
    assert analyzer._encode_severity("critical") == 1.0
    assert analyzer._encode_severity("high") == 0.8
    assert analyzer._encode_severity("medium") == 0.5
    assert analyzer._encode_severity("low") == 0.2
    assert analyzer._encode_severity("info") == 0.1
    assert analyzer._encode_severity("unknown") == 0.0

@pytest.mark.asyncio
async def test_behavioral_analysis(analyzer, mock_scan_result):
    """Test behavioral analysis of infrastructure patterns."""
    with patch.object(analyzer, 'behavioral_analyzer') as mock_analyzer:
        mock_analyzer.predict.return_value = np.array([0.7, 0.3])
        
        result = await analyzer._predict_async(
            mock_analyzer,
            np.array([[1, 2], [3, 4]])
        )
        
        assert isinstance(result, np.ndarray)
        assert len(result) == 2

def test_zero_day_recommendations(analyzer):
    """Test recommendation generation for zero-day findings."""
    finding = Finding(
        id="TEST003",
        title="Test Finding",
        description="Test description",
        severity=Severity.CRITICAL,
        platform="kubernetes",
        location="pod.yaml:1",
        code_snippet="sensitive: true",
        recommendation=None
    )
    
    recommendations = analyzer._generate_zero_day_recommendations(finding)
    
    assert isinstance(recommendations, list)
    assert len(recommendations) > 0
    assert all(isinstance(r, str) for r in recommendations)

@pytest.mark.asyncio
async def test_concurrent_analysis(analyzer, mock_scan_result):
    """Test concurrent analysis of multiple findings."""
    # Create multiple findings
    for i in range(10):
        mock_scan_result.findings.append(
            Finding(
                id=f"TEST{i+3:03d}",
                title=f"Finding {i}",
                description=f"Description {i}",
                severity=Severity.HIGH,
                platform="docker",
                location=f"Dockerfile:{i+1}",
                code_snippet=f"RUN command{i}",
                recommendation=None
            )
        )
    
    # Test concurrent processing
    zero_days = await analyzer.detect_zero_days(mock_scan_result)
    patterns = await analyzer.analyze_patterns(mock_scan_result)
    risks = await analyzer.predict_risks(mock_scan_result)
    
    assert len(zero_days) + len(patterns) + len(risks) > 0

@pytest.mark.asyncio
async def test_error_handling(analyzer):
    """Test error handling in ML analysis."""
    # Test with invalid input
    with pytest.raises(Exception):
        await analyzer.detect_zero_days(None)
    
    with pytest.raises(Exception):
        await analyzer.analyze_patterns(None)
    
    with pytest.raises(Exception):
        await analyzer.predict_risks(None)

def test_model_versioning(analyzer):
    """Test ML model versioning and compatibility."""
    # Ensure models are compatible with current feature extraction
    features = analyzer._extract_zero_day_features(mock_scan_result())
    
    if analyzer.zero_day_detector:
        try:
            result = analyzer.zero_day_detector.predict(features)
            assert isinstance(result, np.ndarray)
        except Exception as e:
            pytest.fail(f"Model compatibility test failed: {str(e)}")
