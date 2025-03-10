"""
Pytest configuration and shared fixtures.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock
import tempfile
import shutil
import yaml

from dsp_scanner.core.results import Finding, Severity, ScanResult
from dsp_scanner.core.policy import Policy

@pytest.fixture(scope="session")
def test_data_dir(tmp_path_factory):
    """Create a temporary directory for test data."""
    return tmp_path_factory.mktemp("test_data")

@pytest.fixture
def temp_dir():
    """Create a temporary directory for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        id="TEST001",
        title="Test Finding",
        description="Test security issue",
        severity=Severity.HIGH,
        platform="docker",
        location="Dockerfile:1",
        code_snippet="FROM python:latest",
        recommendation="Use specific version"
    )

@pytest.fixture
def sample_findings():
    """Create a list of sample findings for testing."""
    return [
        Finding(
            id="TEST001",
            title="Security Issue",
            description="Test security issue",
            severity=Severity.HIGH,
            platform="docker",
            location="Dockerfile:1",
            code_snippet="FROM python:latest",
            recommendation="Use specific version"
        ),
        Finding(
            id="TEST002",
            title="Compliance Issue",
            description="Test compliance issue",
            severity=Severity.MEDIUM,
            platform="kubernetes",
            location="deployment.yaml:1",
            code_snippet="privileged: true",
            recommendation="Avoid privileged containers"
        ),
        Finding(
            id="TEST003",
            title="Configuration Issue",
            description="Test configuration issue",
            severity=Severity.LOW,
            platform="terraform",
            location="main.tf:1",
            code_snippet='resource "aws_s3_bucket" "test" {}',
            recommendation="Enable versioning"
        )
    ]

@pytest.fixture
def sample_scan_result(sample_findings):
    """Create a sample scan result for testing."""
    result = ScanResult()
    for finding in sample_findings:
        result.add_finding(finding)
    return result

@pytest.fixture
def mock_policy():
    """Create a mock policy for testing."""
    policy = Mock(spec=Policy)
    policy.name = "test_policy"
    policy.description = "Test security policy"
    policy.platform = "docker"
    policy.severity = "high"
    return policy

@pytest.fixture
def sample_dockerfile(temp_dir):
    """Create a sample Dockerfile for testing."""
    content = """
    FROM python:3.9
    WORKDIR /app
    COPY . .
    RUN pip install -r requirements.txt
    EXPOSE 8000
    CMD ["python", "app.py"]
    """
    dockerfile = temp_dir / "Dockerfile"
    dockerfile.write_text(content)
    return dockerfile

@pytest.fixture
def sample_kubernetes_manifest(temp_dir):
    """Create a sample Kubernetes manifest for testing."""
    content = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "test-app"},
        "spec": {
            "replicas": 1,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "app",
                        "image": "test:latest"
                    }]
                }
            }
        }
    }
    manifest = temp_dir / "deployment.yaml"
    manifest.write_text(yaml.dump(content))
    return manifest

@pytest.fixture
def sample_terraform_config(temp_dir):
    """Create a sample Terraform configuration for testing."""
    content = """
    provider "aws" {
        region = "us-west-2"
    }

    resource "aws_s3_bucket" "test" {
        bucket = "test-bucket"
    }
    """
    config = temp_dir / "main.tf"
    config.write_text(content)
    return config

@pytest.fixture
def sample_helm_chart(temp_dir):
    """Create a sample Helm chart for testing."""
    chart_dir = temp_dir / "test-chart"
    chart_dir.mkdir()
    
    # Create Chart.yaml
    chart_yaml = chart_dir / "Chart.yaml"
    chart_yaml.write_text(yaml.dump({
        "apiVersion": "v2",
        "name": "test-chart",
        "version": "0.1.0",
        "description": "A test chart"
    }))
    
    # Create values.yaml
    values_yaml = chart_dir / "values.yaml"
    values_yaml.write_text(yaml.dump({
        "image": {
            "repository": "nginx",
            "tag": "latest"
        }
    }))
    
    # Create templates directory
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir()
    
    # Create deployment template
    deployment = templates_dir / "deployment.yaml"
    deployment.write_text(yaml.dump({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "{{ .Release.Name }}"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "{{ .Release.Name }}",
                        "image": "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
                    }]
                }
            }
        }
    }))
    
    return chart_dir

@pytest.fixture
def mock_ml_model():
    """Create a mock ML model for testing."""
    model = Mock()
    model.predict.return_value = [0.8, 0.2]
    return model

@pytest.fixture
def environment_setup(temp_dir):
    """Set up a complete test environment with all file types."""
    # Create project structure
    (temp_dir / "docker").mkdir()
    (temp_dir / "k8s").mkdir()
    (temp_dir / "terraform").mkdir()
    (temp_dir / "helm").mkdir()
    
    # Copy sample files
    shutil.copy(sample_dockerfile(temp_dir), temp_dir / "docker/Dockerfile")
    shutil.copy(sample_kubernetes_manifest(temp_dir), temp_dir / "k8s/deployment.yaml")
    shutil.copy(sample_terraform_config(temp_dir), temp_dir / "terraform/main.tf")
    shutil.copytree(sample_helm_chart(temp_dir), temp_dir / "helm/test-chart")
    
    return temp_dir

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running"
    )

@pytest.fixture
def mock_scanner_response():
    """Create a mock scanner response for testing."""
    return {
        "findings": [
            {
                "id": "TEST001",
                "title": "Security Issue",
                "severity": "HIGH",
                "platform": "docker"
            }
        ],
        "metrics": {
            "files_scanned": 1,
            "findings_by_severity": {
                "high": 1,
                "medium": 0,
                "low": 0
            }
        }
    }

@pytest.fixture
def mock_opa_client():
    """Create a mock OPA client for testing."""
    client = Mock()
    client.evaluate.return_value = {"result": True}
    return client
