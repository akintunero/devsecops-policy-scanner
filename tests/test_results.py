"""
Tests for the scan results handling module.
"""

import pytest
from datetime import datetime
from typing import Dict, List

from dsp_scanner.core.results import (
    Finding,
    Severity,
    ScanResult,
    ComplianceResult,
    AIAnalysis,
    Recommendation
)

@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        id="TEST001",
        title="Security Issue",
        description="Test security issue",
        severity=Severity.HIGH,
        platform="docker",
        location="Dockerfile:1",
        code_snippet="FROM python:latest",
        recommendation="Use specific version",
        cwe_id="CWE-1",
        cvss_score=7.5,
        references=["https://example.com/vuln"],
        tags=["security", "docker"]
    )

@pytest.fixture
def sample_findings():
    """Create a list of sample findings with different severities."""
    return [
        Finding(
            id="TEST001",
            title="Critical Issue",
            description="Critical security issue",
            severity=Severity.CRITICAL,
            platform="kubernetes",
            location="deployment.yaml:1"
        ),
        Finding(
            id="TEST002",
            title="High Issue",
            description="High security issue",
            severity=Severity.HIGH,
            platform="docker",
            location="Dockerfile:1"
        ),
        Finding(
            id="TEST003",
            title="Medium Issue",
            description="Medium security issue",
            severity=Severity.MEDIUM,
            platform="terraform",
            location="main.tf:1"
        )
    ]

@pytest.fixture
def sample_compliance_result():
    """Create a sample compliance result."""
    return ComplianceResult(
        framework="cis",
        compliant=False,
        score=85.5,
        passed_rules=["rule1", "rule2"],
        failed_rules=["rule3"],
        skipped_rules=["rule4"],
        evidence={
            "rule1": {"status": "pass", "details": "Test passed"},
            "rule3": {"status": "fail", "details": "Test failed"}
        }
    )

@pytest.fixture
def sample_ai_analysis():
    """Create a sample AI analysis result."""
    return AIAnalysis(
        zero_day_risks=[{
            "title": "Potential Zero-day",
            "confidence": 0.85,
            "details": "Suspicious pattern detected"
        }],
        pattern_findings=[{
            "pattern": "insecure-config",
            "occurrences": 3,
            "severity": "high"
        }],
        risk_predictions=[{
            "risk": "data-exposure",
            "probability": 0.75,
            "impact": "high"
        }],
        behavioral_analysis={
            "risk_score": 0.8,
            "anomalies": ["suspicious-access"]
        },
        confidence_scores={
            "zero_day": 0.85,
            "pattern": 0.9,
            "risk": 0.75
        }
    )

def test_finding_creation(sample_finding):
    """Test finding creation and attributes."""
    assert sample_finding.id == "TEST001"
    assert sample_finding.severity == Severity.HIGH
    assert sample_finding.platform == "docker"
    assert isinstance(sample_finding.detected_at, datetime)
    assert sample_finding.cvss_score == 7.5
    assert "security" in sample_finding.tags

def test_finding_severity_comparison():
    """Test severity level comparison."""
    critical = Finding(
        id="CRIT001",
        title="Critical",
        description="Critical issue",
        severity=Severity.CRITICAL,
        platform="docker",
        location="test"
    )
    high = Finding(
        id="HIGH001",
        title="High",
        description="High issue",
        severity=Severity.HIGH,
        platform="docker",
        location="test"
    )
    
    assert critical.severity > high.severity
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO

def test_scan_result_creation():
    """Test scan result initialization."""
    result = ScanResult()
    assert result.scan_id
    assert isinstance(result.timestamp, datetime)
    assert len(result.findings) == 0
    assert isinstance(result.metrics, Dict)

def test_scan_result_add_finding(sample_finding):
    """Test adding findings to scan result."""
    result = ScanResult()
    result.add_finding(sample_finding)
    
    assert len(result.findings) == 1
    assert result.findings[0].id == "TEST001"
    assert "high" in result.metrics["findings_by_severity"]
    assert "docker" in result.metrics["findings_by_platform"]

def test_scan_result_metrics(sample_findings):
    """Test scan result metrics calculation."""
    result = ScanResult()
    for finding in sample_findings:
        result.add_finding(finding)
    
    metrics = result.metrics
    assert metrics["findings_by_severity"]["critical"] == 1
    assert metrics["findings_by_severity"]["high"] == 1
    assert metrics["findings_by_severity"]["medium"] == 1
    assert metrics["total_files_scanned"] >= 0

def test_compliance_results(sample_compliance_result):
    """Test compliance result handling."""
    result = ScanResult()
    result.add_compliance_result("cis", sample_compliance_result)
    
    assert "cis" in result.compliance_results
    assert result.compliance_results["cis"].score == 85.5
    assert len(result.compliance_results["cis"].passed_rules) == 2
    assert len(result.compliance_results["cis"].failed_rules) == 1

def test_ai_analysis_results(sample_ai_analysis):
    """Test AI analysis results handling."""
    result = ScanResult()
    result.ai_analysis = sample_ai_analysis
    
    assert len(result.ai_analysis.zero_day_risks) == 1
    assert len(result.ai_analysis.pattern_findings) == 1
    assert len(result.ai_analysis.risk_predictions) == 1
    assert result.ai_analysis.confidence_scores["zero_day"] == 0.85

def test_scan_result_merge():
    """Test merging multiple scan results."""
    result1 = ScanResult()
    result2 = ScanResult()
    
    finding1 = Finding(
        id="TEST001",
        title="First Issue",
        description="First issue",
        severity=Severity.HIGH,
        platform="docker",
        location="test1"
    )
    finding2 = Finding(
        id="TEST002",
        title="Second Issue",
        description="Second issue",
        severity=Severity.MEDIUM,
        platform="kubernetes",
        location="test2"
    )
    
    result1.add_finding(finding1)
    result2.add_finding(finding2)
    
    result1.merge(result2)
    
    assert len(result1.findings) == 2
    assert "docker" in result1.platforms
    assert "kubernetes" in result1.platforms

def test_scan_result_summary(sample_findings, sample_compliance_result):
    """Test scan result summary generation."""
    result = ScanResult()
    for finding in sample_findings:
        result.add_finding(finding)
    result.add_compliance_result("cis", sample_compliance_result)
    
    summary = result.get_summary()
    
    assert summary["total_findings"] == 3
    assert "findings_by_severity" in summary
    assert "compliance_status" in summary
    assert summary["compliance_status"]["cis"] is False

def test_recommendation_handling():
    """Test handling of security recommendations."""
    recommendation = Recommendation(
        title="Fix Security Issue",
        description="Security fix needed",
        priority=1,
        effort_estimate="2 hours",
        related_findings=["TEST001"],
        remediation_steps=["Step 1", "Step 2"],
        automated_fix="kubectl apply -f fix.yaml",
        impact_analysis={"risk": "low", "downtime": "none"}
    )
    
    result = ScanResult()
    result.recommendations.append(recommendation)
    
    assert len(result.recommendations) == 1
    assert result.recommendations[0].priority == 1
    assert len(result.recommendations[0].remediation_steps) == 2

def test_finding_metadata():
    """Test finding metadata handling."""
    metadata = {
        "source": "automated-scan",
        "confidence": 0.95,
        "related_issues": ["ISSUE-123"],
        "custom_field": "test-value"
    }
    
    finding = Finding(
        id="TEST001",
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        platform="docker",
        location="test",
        metadata=metadata
    )
    
    assert finding.metadata["source"] == "automated-scan"
    assert finding.metadata["confidence"] == 0.95
    assert "ISSUE-123" in finding.metadata["related_issues"]

def test_scan_result_filtering():
    """Test filtering scan results."""
    result = ScanResult()
    findings = [
        Finding(
            id=f"TEST00{i}",
            title=f"Finding {i}",
            description=f"Description {i}",
            severity=Severity.HIGH if i % 2 == 0 else Severity.LOW,
            platform="docker" if i % 2 == 0 else "kubernetes",
            location=f"test{i}"
        )
        for i in range(1, 5)
    ]
    
    for finding in findings:
        result.add_finding(finding)
    
    # Filter by severity
    high_severity = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 2
    
    # Filter by platform
    docker_findings = [f for f in result.findings if f.platform == "docker"]
    assert len(docker_findings) == 2

def test_scan_result_serialization():
    """Test scan result serialization."""
    result = ScanResult()
    finding = Finding(
        id="TEST001",
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        platform="docker",
        location="test"
    )
    result.add_finding(finding)
    
    # Convert to dict
    result_dict = result.get_summary()
    
    assert isinstance(result_dict, dict)
    assert "scan_id" in result_dict
    assert "timestamp" in result_dict
    assert "total_findings" in result_dict
    
    # Verify datetime serialization
    assert isinstance(result_dict["timestamp"], str)
