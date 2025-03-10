"""
Tests for the core scanner functionality.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import asyncio

from dsp_scanner.core.scanner import Scanner
from dsp_scanner.core.results import Finding, Severity, ScanResult
from dsp_scanner.core.policy import Policy

@pytest.fixture
def scanner():
    """Create a scanner instance for testing."""
    return Scanner(enable_ai=True)

@pytest.fixture
def mock_policy():
    """Create a mock policy for testing."""
    policy = Mock(spec=Policy)
    policy.name = "test_policy"
    policy.description = "Test policy"
    policy.platform = "docker"
    policy.severity = "high"
    return policy

@pytest.mark.asyncio
async def test_scan_path_with_no_files(scanner, tmp_path):
    """Test scanning an empty directory."""
    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.findings) == 0

@pytest.mark.asyncio
async def test_scan_path_with_docker_file(scanner, tmp_path):
    """Test scanning a directory with a Dockerfile."""
    # Create test Dockerfile
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""
    FROM python:3.9
    RUN pip install flask
    EXPOSE 8000
    CMD ["python", "app.py"]
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.findings) > 0
    assert any(f.platform == "docker" for f in result.findings)

@pytest.mark.asyncio
async def test_scan_path_with_kubernetes_yaml(scanner, tmp_path):
    """Test scanning a directory with Kubernetes YAML."""
    # Create test Kubernetes deployment
    k8s_file = tmp_path / "deployment.yaml"
    k8s_file.write_text("""
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: test-app
    spec:
      replicas: 1
      template:
        spec:
          containers:
          - name: app
            image: test:latest
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.findings) > 0
    assert any(f.platform == "kubernetes" for f in result.findings)

@pytest.mark.asyncio
async def test_scan_path_with_terraform_file(scanner, tmp_path):
    """Test scanning a directory with Terraform configuration."""
    # Create test Terraform file
    tf_file = tmp_path / "main.tf"
    tf_file.write_text("""
    resource "aws_s3_bucket" "test" {
      bucket = "my-test-bucket"
    }
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.findings) > 0
    assert any(f.platform == "terraform" for f in result.findings)

@pytest.mark.asyncio
async def test_scan_path_with_helm_chart(scanner, tmp_path):
    """Test scanning a directory with Helm chart."""
    # Create test Helm chart
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    chart_yaml = chart_dir / "Chart.yaml"
    chart_yaml.write_text("""
    apiVersion: v2
    name: test-chart
    version: 0.1.0
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.findings) > 0
    assert any(f.platform == "helm" for f in result.findings)

@pytest.mark.asyncio
async def test_scan_with_custom_policy(scanner, mock_policy, tmp_path):
    """Test scanning with a custom policy."""
    # Setup mock policy evaluation
    mock_policy.evaluate.return_value = asyncio.Future()
    mock_policy.evaluate.return_value.set_result({
        "violations": [{
            "title": "Test Violation",
            "description": "Test violation description",
            "severity": "high"
        }]
    })

    # Create test file
    test_file = tmp_path / "Dockerfile"
    test_file.write_text("FROM python:3.9")

    result = await scanner.scan_path(str(tmp_path), policies=[mock_policy])
    assert isinstance(result, ScanResult)
    assert len(result.findings) > 0
    assert any(f.id.startswith("POLICY_") for f in result.findings)

@pytest.mark.asyncio
async def test_scan_with_ai_analysis(scanner, tmp_path):
    """Test scanning with AI analysis enabled."""
    # Create test file with potential security issue
    test_file = tmp_path / "Dockerfile"
    test_file.write_text("""
    FROM python:3.9
    RUN curl http://example.com/script.sh | bash
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert result.ai_analysis is not None
    assert len(result.ai_analysis.pattern_findings) > 0

@pytest.mark.asyncio
async def test_scan_with_compliance_frameworks(scanner, tmp_path):
    """Test scanning with specific compliance frameworks."""
    scanner = Scanner(
        enable_ai=True,
        compliance_frameworks=["cis", "nist"]
    )

    # Create test Kubernetes file
    k8s_file = tmp_path / "pod.yaml"
    k8s_file.write_text("""
    apiVersion: v1
    kind: Pod
    metadata:
      name: test-pod
    spec:
      containers:
      - name: app
        image: test:latest
        securityContext:
          privileged: true
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.compliance_results) > 0
    assert "cis" in result.compliance_results
    assert "nist" in result.compliance_results

@pytest.mark.asyncio
async def test_error_handling(scanner):
    """Test scanner error handling."""
    with pytest.raises(FileNotFoundError):
        await scanner.scan_path("/nonexistent/path")

@pytest.mark.asyncio
async def test_concurrent_scanning(scanner, tmp_path):
    """Test concurrent scanning of multiple files."""
    # Create multiple test files
    for i in range(5):
        file = tmp_path / f"Dockerfile.{i}"
        file.write_text(f"FROM python:3.9\nEXPOSE {8000 + i}")

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert len(result.findings) > 0
    assert result.metrics["total_files_scanned"] == 5

@pytest.mark.asyncio
async def test_severity_threshold_filtering(tmp_path):
    """Test filtering findings based on severity threshold."""
    scanner = Scanner(
        enable_ai=True,
        severity_threshold="high"
    )

    # Create test file with multiple severity issues
    test_file = tmp_path / "Dockerfile"
    test_file.write_text("""
    FROM python:3.9
    RUN curl http://example.com/script.sh | bash
    EXPOSE 22
    USER root
    """)

    result = await scanner.scan_path(str(tmp_path))
    assert isinstance(result, ScanResult)
    assert all(f.severity in [Severity.HIGH, Severity.CRITICAL] 
              for f in result.findings)

def test_scanner_initialization():
    """Test scanner initialization with different configurations."""
    # Test default configuration
    scanner = Scanner()
    assert scanner.enable_ai is True
    assert scanner.compliance_frameworks == ["cis", "nist"]
    assert scanner.severity_threshold == "medium"

    # Test custom configuration
    scanner = Scanner(
        enable_ai=False,
        compliance_frameworks=["hipaa"],
        severity_threshold="high"
    )
    assert scanner.enable_ai is False
    assert scanner.compliance_frameworks == ["hipaa"]
    assert scanner.severity_threshold == "high"

def test_scanner_metrics(scanner, tmp_path):
    """Test scanner metrics collection."""
    # Create test files
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.9")
    
    k8s_file = tmp_path / "deployment.yaml"
    k8s_file.write_text("""
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: test
    """)

    asyncio.run(scanner.scan_path(str(tmp_path)))
    metrics = scanner.get_metrics()
    
    assert metrics["total_files_scanned"] > 0
    assert metrics["total_lines_scanned"] > 0
    assert "scan_duration" in metrics
