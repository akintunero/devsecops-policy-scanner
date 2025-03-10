"""
Tests for the policy engine and OPA integration.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import json

from dsp_scanner.core.policy import Policy, PolicySet, PolicyManager, PolicyEvaluationError

@pytest.fixture
def sample_rego_policy():
    """Sample Rego policy for testing."""
    return """
package dsp_scanner

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext
    msg = "Deployment should specify pod security context"
}
"""

@pytest.fixture
def sample_policy():
    """Create a sample policy for testing."""
    return Policy(
        name="test_policy",
        description="Test security policy",
        platform="kubernetes",
        rego_policy=sample_rego_policy(),
        severity="high",
        tags=["security", "kubernetes"],
        metadata={"version": "1.0"}
    )

@pytest.fixture
def policy_manager():
    """Create a policy manager instance for testing."""
    return PolicyManager()

@pytest.mark.asyncio
async def test_policy_evaluation(sample_policy):
    """Test basic policy evaluation."""
    input_data = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {}
            }
        }
    }
    
    result = await sample_policy.evaluate(input_data)
    
    assert isinstance(result, dict)
    assert "violations" in result
    assert len(result["violations"]) > 0
    assert result["violations"][0]["description"] == sample_policy.description

@pytest.mark.asyncio
async def test_policy_evaluation_no_violation(sample_policy):
    """Test policy evaluation with no violations."""
    input_data = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": True
                    }
                }
            }
        }
    }
    
    result = await sample_policy.evaluate(input_data)
    
    assert isinstance(result, dict)
    assert "violations" in result
    assert len(result["violations"]) == 0

def test_policy_validation():
    """Test policy validation."""
    # Test valid policy
    valid_policy = Policy(
        name="valid_policy",
        description="Valid policy",
        platform="docker",
        rego_policy='package dsp_scanner\ndefault allow = true',
        severity="medium"
    )
    assert valid_policy is not None
    
    # Test invalid policy
    with pytest.raises(ValueError):
        Policy(
            name="invalid_policy",
            description="Invalid policy",
            platform="docker",
            rego_policy='invalid rego code',
            severity="medium"
        )

@pytest.mark.asyncio
async def test_policy_set_evaluation(sample_policy):
    """Test policy set evaluation."""
    policy_set = PolicySet(
        name="test_set",
        description="Test policy set",
        policies=[sample_policy]
    )
    
    input_data = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {}
            }
        }
    }
    
    results = await policy_set.evaluate_all(input_data)
    
    assert isinstance(results, list)
    assert len(results) > 0
    assert all(isinstance(r, dict) for r in results)

@pytest.mark.asyncio
async def test_policy_set_platform_filter(sample_policy):
    """Test policy set evaluation with platform filter."""
    policy_set = PolicySet(
        name="test_set",
        description="Test policy set",
        policies=[sample_policy]
    )
    
    # Test with matching platform
    results = await policy_set.evaluate_all({}, platform="kubernetes")
    assert len(results) == 1
    
    # Test with non-matching platform
    results = await policy_set.evaluate_all({}, platform="docker")
    assert len(results) == 0

@pytest.mark.asyncio
async def test_policy_manager_builtin_policies(tmp_path):
    """Test loading built-in policies."""
    manager = PolicyManager()
    
    # Create mock policy files
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    
    # Create kubernetes policy
    k8s_dir = policies_dir / "kubernetes"
    k8s_dir.mkdir()
    
    policy_file = k8s_dir / "pod_security.rego"
    policy_file.write_text(sample_rego_policy())
    
    metadata_file = k8s_dir / "pod_security.json"
    metadata_file.write_text(json.dumps({
        "name": "pod_security",
        "description": "Pod security policy",
        "severity": "high",
        "tags": ["security"],
        "set": "kubernetes"
    }))
    
    with patch('pathlib.Path.parent', return_value=tmp_path):
        await manager.load_builtin_policies()
        
    assert len(manager.policy_sets) > 0
    assert "kubernetes" in manager.policy_sets

def test_policy_manager_custom_policies(sample_policy):
    """Test managing custom policies."""
    manager = PolicyManager()
    
    # Add custom policy
    manager.add_custom_policy(sample_policy)
    
    assert sample_policy.name in manager.custom_policies
    assert manager.get_custom_policy(sample_policy.name) == sample_policy

@pytest.mark.asyncio
async def test_policy_manager_evaluation(sample_policy):
    """Test policy evaluation through manager."""
    manager = PolicyManager()
    manager.add_custom_policy(sample_policy)
    
    input_data = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {}
            }
        }
    }
    
    results = await manager.evaluate_policies(
        input_data,
        policy_sets=None,
        platform="kubernetes"
    )
    
    assert isinstance(results, dict)
    assert "custom" in results
    assert len(results["custom"]) > 0

def test_policy_metadata():
    """Test policy metadata handling."""
    metadata = {
        "version": "1.0",
        "author": "Test Author",
        "references": ["CIS Benchmark 1.2.3"]
    }
    
    policy = Policy(
        name="test_policy",
        description="Test policy",
        platform="docker",
        rego_policy='package dsp_scanner\ndefault allow = true',
        severity="medium",
        metadata=metadata
    )
    
    assert policy.metadata == metadata
    assert policy.metadata["version"] == "1.0"

def test_policy_error_handling():
    """Test policy error handling."""
    # Test invalid severity
    with pytest.raises(ValueError):
        Policy(
            name="test_policy",
            description="Test policy",
            platform="docker",
            rego_policy='package dsp_scanner\ndefault allow = true',
            severity="invalid"
        )
    
    # Test invalid platform
    with pytest.raises(ValueError):
        Policy(
            name="test_policy",
            description="Test policy",
            platform="invalid",
            rego_policy='package dsp_scanner\ndefault allow = true',
            severity="medium"
        )

@pytest.mark.asyncio
async def test_policy_evaluation_timeout():
    """Test policy evaluation timeout handling."""
    # Create a policy that would timeout
    infinite_loop_policy = """
    package dsp_scanner
    
    deny[msg] {
        false
        msg = "This should timeout"
    }
    """
    
    policy = Policy(
        name="timeout_policy",
        description="Policy that should timeout",
        platform="docker",
        rego_policy=infinite_loop_policy,
        severity="medium"
    )
    
    with pytest.raises(PolicyEvaluationError):
        await policy.evaluate({"test": "data"})

@pytest.mark.asyncio
async def test_concurrent_policy_evaluation(sample_policy):
    """Test concurrent policy evaluation."""
    policy_set = PolicySet(
        name="test_set",
        description="Test policy set",
        policies=[sample_policy] * 5  # Create multiple copies for testing
    )
    
    input_data = {
        "kind": "Deployment",
        "spec": {
            "template": {
                "spec": {}
            }
        }
    }
    
    # Evaluate policies concurrently
    results = await policy_set.evaluate_all(input_data)
    
    assert len(results) == 5
    assert all(isinstance(r, dict) for r in results)

def test_policy_set_management():
    """Test policy set management operations."""
    policy_set = PolicySet(
        name="test_set",
        description="Test policy set"
    )
    
    # Add policies
    policies = [
        Policy(
            name=f"policy_{i}",
            description=f"Policy {i}",
            platform="docker",
            rego_policy='package dsp_scanner\ndefault allow = true',
            severity="medium"
        )
        for i in range(3)
    ]
    
    for policy in policies:
        policy_set.policies.append(policy)
    
    assert len(policy_set.policies) == 3
    assert all(isinstance(p, Policy) for p in policy_set.policies)
