# DSP Scanner Policy System

The DSP Scanner Policy System is a flexible and extensible framework for defining and enforcing security policies across multiple platforms. This document explains how the policy system works and how to create custom policies.

## Table of Contents

- [Overview](#overview)
- [Policy Structure](#policy-structure)
- [Supported Platforms](#supported-platforms)
- [Writing Custom Policies](#writing-custom-policies)
- [Policy Evaluation](#policy-evaluation)
- [Compliance Frameworks](#compliance-frameworks)
- [Best Practices](#best-practices)

## Overview

The policy system uses Open Policy Agent (OPA) and the Rego policy language to define and evaluate security policies. Each policy consists of two main components:
- A `.rego` file containing the policy rules
- A `.json` file containing metadata about the policy

### Key Features

- Platform-specific security checks
- Compliance framework mapping
- Severity-based violation reporting
- Customizable policy rules
- Machine learning integration
- Detailed remediation recommendations

## Policy Structure

### Rego Policy File

```rego
package dsp_scanner.<platform>

# Define policy rules
deny[msg] {
    # Rule conditions
    msg = {
        "title": "Rule Title",
        "description": "Description of the violation",
        "severity": "HIGH",
        "platform": "<platform>",
        "recommendation": "How to fix the issue"
    }
}
```

### Metadata JSON File

```json
{
    "name": "policy_name",
    "description": "Policy description",
    "version": "1.0.0",
    "severity": "high",
    "platform": "<platform>",
    "tags": ["security", "compliance"],
    "references": [
        "https://example.com/security-guide"
    ],
    "metadata": {
        "cis_benchmark": ["1.1", "1.2"],
        "nist_controls": ["AC-3", "AC-6"]
    }
}
```

## Supported Platforms

### Docker
- Container security checks
- Image security best practices
- Runtime security controls

### Kubernetes
- Pod security policies
- Network policies
- RBAC configurations
- Resource management

### Terraform
- AWS security best practices
- Infrastructure security
- Cloud resource configuration

### Helm
- Chart security checks
- Template validation
- Values file security

## Writing Custom Policies

### 1. Create Policy Files

Create two files in the appropriate platform directory:
```
policies/
└── <platform>/
    ├── your_policy.rego
    └── your_policy.json
```

### 2. Define Policy Rules

```rego
package dsp_scanner.<platform>

# Import common libraries if needed
import data.lib.security

# Define your policy rules
deny[msg] {
    # Your rule conditions here
    msg := {
        "title": "Security Issue Found",
        "description": "Detailed description",
        "severity": "HIGH",
        "platform": "<platform>",
        "recommendation": "How to fix"
    }
}
```

### 3. Add Metadata

```json
{
    "name": "your_policy",
    "description": "What your policy checks",
    "version": "1.0.0",
    "severity": "high",
    "platform": "<platform>",
    "tags": ["your", "tags"],
    "references": [
        "https://security.example.com"
    ]
}
```

## Policy Evaluation

The policy evaluation process follows these steps:

1. **Platform Detection**
   - Automatically detect the relevant platform
   - Load appropriate policies

2. **Rule Evaluation**
   - Apply platform-specific rules
   - Collect violations

3. **Result Aggregation**
   - Combine findings
   - Calculate severity scores
   - Generate recommendations

4. **Compliance Mapping**
   - Map findings to compliance frameworks
   - Generate compliance reports

## Compliance Frameworks

### Supported Frameworks

- CIS Benchmarks
- NIST 800-53
- HIPAA
- PCI DSS
- SOC 2
- GDPR

### Mapping Example

```rego
# Map policy to compliance frameworks
compliance[framework] {
    framework := {
        "cis": ["1.1", "1.2"],
        "nist": ["AC-3", "AC-6"],
        "hipaa": ["164.308(a)(4)"]
    }
}
```

## Best Practices

### Policy Writing

1. **Clear Naming**
   - Use descriptive policy names
   - Follow naming conventions

2. **Documentation**
   - Document all rules
   - Include examples
   - Explain rationale

3. **Granular Rules**
   - One concern per rule
   - Clear violation messages
   - Specific recommendations

4. **Performance**
   - Optimize rule evaluation
   - Use appropriate data structures
   - Consider caching when possible

### Testing

1. **Unit Tests**
   ```python
   def test_policy_rule():
       # Test policy with various inputs
       assert evaluate_policy(input_data)
   ```

2. **Integration Tests**
   - Test with real configurations
   - Verify compliance mappings
   - Check performance

### Maintenance

1. **Version Control**
   - Track policy changes
   - Document updates
   - Maintain changelog

2. **Regular Updates**
   - Review security standards
   - Update compliance mappings
   - Incorporate feedback

## Advanced Features

### Machine Learning Integration

```python
# Use ML for pattern detection
async def analyze_patterns(config):
    patterns = await ml_analyzer.detect_patterns(config)
    return generate_findings(patterns)
```

### Custom Rules Engine

```python
class CustomRule:
    def __init__(self, rule_config):
        self.config = rule_config
        
    def evaluate(self, target):
        # Custom evaluation logic
        pass
```

### Policy Aggregation

```python
class PolicyAggregator:
    def __init__(self, policies):
        self.policies = policies
        
    async def evaluate_all(self, target):
        results = []
        for policy in self.policies:
            result = await policy.evaluate(target)
            results.append(result)
        return self.aggregate_results(results)
```

## Examples

### Docker Security Policy

```rego
# Check for privileged containers
deny[msg] {
    input.type == "Dockerfile"
    contains(input.content, "privileged")
    msg = {
        "title": "Privileged Container",
        "description": "Container runs in privileged mode",
        "severity": "HIGH"
    }
}
```

### Kubernetes Security Policy

```rego
# Check for containers running as root
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg = {
        "title": "Root Container",
        "description": "Container may run as root",
        "severity": "HIGH"
    }
}
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing new policies or improvements to existing ones.

## Support

For questions and support:
- GitHub Issues: [Create an issue](https://github.com/akintunero/dsp-scanner/issues)
