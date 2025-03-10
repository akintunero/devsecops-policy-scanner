"""
Tests for the Helm security scanner.
"""

import pytest
import yaml
from pathlib import Path
from unittest.mock import Mock

from dsp_scanner.scanners.helm import HelmScanner
from dsp_scanner.core.results import Finding, Severity
from dsp_scanner.core.policy import Policy

@pytest.fixture
def scanner():
    """Create a Helm scanner instance for testing."""
    return HelmScanner()

@pytest.fixture
def mock_policy():
    """Create a mock policy for testing."""
    policy = Mock(spec=Policy)
    policy.name = "test_policy"
    policy.description = "Test policy"
    policy.platform = "helm"
    policy.severity = "high"
    return policy

def create_chart_yaml(chart_dir: Path, content: dict) -> Path:
    """Helper to create a test Chart.yaml file."""
    chart_file = chart_dir / "Chart.yaml"
    chart_file.write_text(yaml.dump(content))
    return chart_file

def create_values_yaml(chart_dir: Path, content: dict) -> Path:
    """Helper to create a test values.yaml file."""
    values_file = chart_dir / "values.yaml"
    values_file.write_text(yaml.dump(content))
    return values_file

def create_template(templates_dir: Path, name: str, content: dict) -> Path:
    """Helper to create a test template file."""
    template_file = templates_dir / f"{name}.yaml"
    template_file.write_text(yaml.dump(content))
    return template_file

@pytest.mark.asyncio
async def test_scan_basic_chart(scanner, tmp_path):
    """Test scanning a basic Helm chart."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    
    # Create Chart.yaml
    chart_content = {
        "apiVersion": "v2",
        "name": "test-chart",
        "version": "0.1.0",
        "description": "A test chart"
    }
    create_chart_yaml(chart_dir, chart_content)
    
    # Create values.yaml
    values_content = {
        "image": {
            "repository": "nginx",
            "tag": "latest"
        }
    }
    create_values_yaml(chart_dir, values_content)
    
    result = await scanner.scan(chart_dir)
    
    assert result.findings
    assert result.metrics["total_files_scanned"] > 0

@pytest.mark.asyncio
async def test_scan_chart_with_security_issues(scanner, tmp_path):
    """Test scanning a chart with security issues."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir()
    
    # Create Chart.yaml
    chart_content = {
        "apiVersion": "v1",  # Old API version
        "name": "test-chart",
        "version": "0.1.0"
    }
    create_chart_yaml(chart_dir, chart_content)
    
    # Create deployment template with security issues
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "{{ .Release.Name }}-deployment"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "{{ .Release.Name }}",
                        "image": "{{ .Values.image.repository }}:{{ .Values.image.tag }}",
                        "securityContext": {
                            "privileged": True
                        }
                    }]
                }
            }
        }
    }
    create_template(templates_dir, "deployment", deployment)
    
    result = await scanner.scan(chart_dir)
    
    findings = result.findings
    assert any(f.id == "HELM001" for f in findings)  # Old API version
    assert any("privileged" in f.description.lower() for f in findings)

@pytest.mark.asyncio
async def test_scan_template_injection(scanner, tmp_path):
    """Test scanning for template injection vulnerabilities."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir()
    
    # Create template with potential injection
    configmap = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "{{ .Release.Name }}-config"},
        "data": {
            "config.json": '{{ .Values.config }}'  # Unquoted template variable
        }
    }
    create_template(templates_dir, "configmap", configmap)
    
    result = await scanner.scan(chart_dir)
    
    assert any(f.id == "HELM006" for f in result.findings)  # Template injection

@pytest.mark.asyncio
async def test_scan_values_security(scanner, tmp_path):
    """Test scanning values.yaml for security issues."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    
    values_content = {
        "adminPassword": "supersecret",
        "apiKey": "1234567890",
        "database": {
            "password": "dbpassword"
        }
    }
    create_values_yaml(chart_dir, values_content)
    
    result = await scanner.scan(chart_dir)
    
    assert any(f.id == "HELM003" for f in result.findings)  # Sensitive values

@pytest.mark.asyncio
async def test_scan_secure_chart(scanner, tmp_path):
    """Test scanning a chart with good security practices."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir()
    
    # Create Chart.yaml with current API version
    chart_content = {
        "apiVersion": "v2",
        "name": "secure-chart",
        "version": "1.0.0",
        "description": "A secure chart",
        "maintainers": [
            {"name": "John Doe", "email": "john@example.com"}
        ]
    }
    create_chart_yaml(chart_dir, chart_content)
    
    # Create secure deployment template
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": '{{ include "chart.fullname" . }}'},
        "spec": {
            "template": {
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000
                    },
                    "containers": [{
                        "name": '{{ include "chart.name" . }}',
                        "image": '{{ .Values.image.repository }}:{{ .Values.image.tag | quote }}',
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True
                        }
                    }]
                }
            }
        }
    }
    create_template(templates_dir, "deployment", deployment)
    
    result = await scanner.scan(chart_dir)
    
    # Should have minimal or no findings
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.HIGH for f in result.findings)

@pytest.mark.asyncio
async def test_scan_with_custom_policy(scanner, tmp_path, mock_policy):
    """Test scanning with a custom policy."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    
    # Create basic chart files
    chart_content = {
        "apiVersion": "v2",
        "name": "test-chart",
        "version": "0.1.0"
    }
    create_chart_yaml(chart_dir, chart_content)
    
    # Setup mock policy evaluation
    mock_policy.evaluate.return_value = {
        "violations": [{
            "title": "Custom Policy Violation",
            "description": "Test violation",
            "severity": "high"
        }]
    }
    
    result = await scanner.scan(chart_dir, policies=[mock_policy])
    
    assert any(f.id.startswith("POLICY_") for f in result.findings)
    mock_policy.evaluate.assert_called_once()

@pytest.mark.asyncio
async def test_scan_multiple_templates(scanner, tmp_path):
    """Test scanning multiple templates in a chart."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir()
    
    # Create multiple templates
    templates = {
        "deployment": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "test"}
        },
        "service": {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "test"}
        },
        "ingress": {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"name": "test"}
        }
    }
    
    for name, content in templates.items():
        create_template(templates_dir, name, content)
    
    result = await scanner.scan(chart_dir)
    
    assert result.metrics["total_templates_scanned"] == 3

@pytest.mark.asyncio
async def test_scan_template_security(scanner, tmp_path):
    """Test scanning template security configurations."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    templates_dir = chart_dir / "templates"
    templates_dir.mkdir()
    
    # Create template without security context
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "test"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": "test",
                        "image": "nginx"
                    }]
                }
            }
        }
    }
    create_template(templates_dir, "deployment", deployment)
    
    result = await scanner.scan(chart_dir)
    
    assert any(f.id == "HELM007" for f in result.findings)  # Missing security context

@pytest.mark.asyncio
async def test_error_handling(scanner):
    """Test scanner error handling."""
    with pytest.raises(FileNotFoundError):
        await scanner.scan(Path("/nonexistent/chart"))

def test_chart_data_loading(scanner, tmp_path):
    """Test chart data loading functionality."""
    chart_dir = tmp_path / "test-chart"
    chart_dir.mkdir()
    
    # Create chart files
    chart_content = {
        "apiVersion": "v2",
        "name": "test-chart",
        "version": "1.0.0"
    }
    create_chart_yaml(chart_dir, chart_content)
    
    values_content = {
        "replicaCount": 1,
        "image": {
            "repository": "nginx",
            "tag": "1.19.0"
        }
    }
    create_values_yaml(chart_dir, values_content)
    
    # Test data loading
    chart_data = scanner._load_chart_data(chart_dir)
    
    assert chart_data["metadata"]["name"] == "test-chart"
    assert chart_data["values"]["image"]["repository"] == "nginx"
