"""
Tests for the Kubernetes security scanner.
"""

import pytest
import yaml
from pathlib import Path
from unittest.mock import Mock

from dsp_scanner.scanners.kubernetes import KubernetesScanner
from dsp_scanner.core.results import Finding, Severity
from dsp_scanner.core.policy import Policy

@pytest.fixture
def scanner():
    """Create a Kubernetes scanner instance for testing."""
    return KubernetesScanner()

@pytest.fixture
def mock_policy():
    """Create a mock policy for testing."""
    policy = Mock(spec=Policy)
    policy.name = "test_policy"
    policy.description = "Test policy"
    policy.platform = "kubernetes"
    policy.severity = "high"
    return policy

def create_k8s_file(tmp_path: Path, content: dict) -> Path:
    """Helper to create a test Kubernetes YAML file."""
    k8s_file = tmp_path / "test.yaml"
    k8s_file.write_text(yaml.dump(content))
    return k8s_file

@pytest.mark.asyncio
async def test_scan_basic_pod(scanner, tmp_path):
    """Test scanning a basic Pod manifest."""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test-pod"},
        "spec": {
            "containers": [{
                "name": "test",
                "image": "nginx:latest"
            }]
        }
    }
    
    manifest = create_k8s_file(tmp_path, pod)
    result = await scanner.scan(manifest)
    
    assert result.findings
    assert any(f.id == "K8S002" for f in result.findings)  # No runAsNonRoot
    assert any(f.id == "K8S003" for f in result.findings)  # No resource limits

@pytest.mark.asyncio
async def test_scan_deployment_with_security_issues(scanner, tmp_path):
    """Test scanning a Deployment with security issues."""
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "test-deployment"},
        "spec": {
            "replicas": 1,
            "template": {
                "spec": {
                    "containers": [{
                        "name": "test",
                        "image": "nginx:latest",
                        "securityContext": {
                            "privileged": True
                        },
                        "volumeMounts": [{
                            "name": "host-path",
                            "mountPath": "/host"
                        }]
                    }],
                    "volumes": [{
                        "name": "host-path",
                        "hostPath": {
                            "path": "/"
                        }
                    }]
                }
            }
        }
    }
    
    manifest = create_k8s_file(tmp_path, deployment)
    result = await scanner.scan(manifest)
    
    findings = result.findings
    assert any(f.id == "K8S001" for f in findings)  # Privileged container
    assert any(f.id == "K8S004" for f in findings)  # Host path volume
    assert any(f.id == "K8S005" for f in findings)  # Single replica

@pytest.mark.asyncio
async def test_scan_service_configuration(scanner, tmp_path):
    """Test scanning Service configuration."""
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "test-service"},
        "spec": {
            "type": "LoadBalancer",
            "ports": [{"port": 80}],
            "selector": {"app": "test"}
        }
    }
    
    manifest = create_k8s_file(tmp_path, service)
    result = await scanner.scan(manifest)
    
    assert any(f.id == "K8S006" for f in result.findings)  # External service

@pytest.mark.asyncio
async def test_scan_network_policy(scanner, tmp_path):
    """Test scanning NetworkPolicy configuration."""
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "test-policy"},
        "spec": {
            "podSelector": {},
            "ingress": [{}]  # Empty rule allows all
        }
    }
    
    manifest = create_k8s_file(tmp_path, policy)
    result = await scanner.scan(manifest)
    
    assert any(f.id == "K8S007" for f in result.findings)  # Overly permissive

@pytest.mark.asyncio
async def test_scan_rbac_configuration(scanner, tmp_path):
    """Test scanning RBAC configuration."""
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "test-role"},
        "rules": [{
            "apiGroups": ["*"],
            "resources": ["*"],
            "verbs": ["*"]
        }]
    }
    
    manifest = create_k8s_file(tmp_path, role)
    result = await scanner.scan(manifest)
    
    assert any(f.id == "K8S008" for f in result.findings)  # Overly permissive RBAC

@pytest.mark.asyncio
async def test_scan_secure_pod(scanner, tmp_path):
    """Test scanning a Pod with good security practices."""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "secure-pod",
            "namespace": "prod"
        },
        "spec": {
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "fsGroup": 2000
            },
            "containers": [{
                "name": "secure-container",
                "image": "nginx:1.21",
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True
                },
                "resources": {
                    "limits": {
                        "cpu": "100m",
                        "memory": "128Mi"
                    }
                }
            }]
        }
    }
    
    manifest = create_k8s_file(tmp_path, pod)
    result = await scanner.scan(manifest)
    
    # Should have minimal or no findings
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.HIGH for f in result.findings)

@pytest.mark.asyncio
async def test_scan_with_custom_policy(scanner, tmp_path, mock_policy):
    """Test scanning with a custom policy."""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test-pod"},
        "spec": {"containers": [{"name": "test", "image": "nginx"}]}
    }
    
    manifest = create_k8s_file(tmp_path, pod)
    
    # Setup mock policy evaluation
    mock_policy.evaluate.return_value = {
        "violations": [{
            "title": "Custom Policy Violation",
            "description": "Test violation",
            "severity": "high"
        }]
    }
    
    result = await scanner.scan(manifest, policies=[mock_policy])
    
    assert any(f.id.startswith("POLICY_") for f in result.findings)
    mock_policy.evaluate.assert_called_once()

@pytest.mark.asyncio
async def test_scan_multiple_documents(scanner, tmp_path):
    """Test scanning YAML with multiple documents."""
    content = """
apiVersion: v1
kind: Service
metadata:
  name: test-service
spec:
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  replicas: 1
"""
    
    manifest = tmp_path / "multi.yaml"
    manifest.write_text(content)
    
    result = await scanner.scan(manifest)
    
    assert result.metrics["total_files_scanned"] == 1
    assert result.metrics["total_resources_scanned"] == 2

@pytest.mark.asyncio
async def test_scan_namespace_configuration(scanner, tmp_path):
    """Test scanning namespace configuration."""
    resources = [{
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "test-pod",
            "namespace": "default"  # Using default namespace
        },
        "spec": {
            "containers": [{"name": "test", "image": "nginx"}]
        }
    }]
    
    manifest = create_k8s_file(tmp_path, resources)
    result = await scanner.scan(manifest)
    
    assert any(f.id == "K8S009" for f in result.findings)  # Default namespace

@pytest.mark.asyncio
async def test_error_handling(scanner):
    """Test scanner error handling."""
    with pytest.raises(FileNotFoundError):
        await scanner.scan(Path("/nonexistent/manifest.yaml"))

def test_is_kubernetes_manifest():
    """Test Kubernetes manifest detection."""
    valid_content = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test"}
    }
    
    invalid_content = {
        "name": "test",
        "description": "Not a K8s manifest"
    }
    
    tmp_path = Path("/tmp")
    
    # Test valid manifest
    valid_file = tmp_path / "valid.yaml"
    with patch("pathlib.Path.open") as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = yaml.dump(valid_content)
        assert KubernetesScanner._is_kubernetes_manifest(valid_file)
    
    # Test invalid manifest
    invalid_file = tmp_path / "invalid.yaml"
    with patch("pathlib.Path.open") as mock_open:
        mock_open.return_value.__enter__.return_value.read.return_value = yaml.dump(invalid_content)
        assert not KubernetesScanner._is_kubernetes_manifest(invalid_file)

@pytest.mark.asyncio
async def test_scan_container_images(scanner, tmp_path):
    """Test scanning container image configurations."""
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test-pod"},
        "spec": {
            "containers": [
                {"name": "app", "image": "app:latest"},
                {"name": "sidecar", "image": "proxy:1.0"}
            ],
            "initContainers": [
                {"name": "init", "image": "busybox:latest"}
            ]
        }
    }
    
    manifest = create_k8s_file(tmp_path, pod)
    result = await scanner.scan(manifest)
    
    # Should detect latest tag usage
    assert any(
        f.id == "K8S010" and "app:latest" in f.description 
        for f in result.findings
    )
    assert any(
        f.id == "K8S010" and "busybox:latest" in f.description 
        for f in result.findings
    )
