"""
Main policy entry point for DSP Scanner.
Coordinates the evaluation of all platform-specific policies.
"""

package dsp_scanner.main

import data.dsp_scanner.docker
import data.dsp_scanner.kubernetes
import data.dsp_scanner.terraform.aws as terraform
import data.dsp_scanner.helm

# Aggregate all policy violations
violations[msg] {
    # Docker policy violations
    input.platform == "docker"
    msg := docker.deny[_]
}

violations[msg] {
    # Kubernetes policy violations
    input.platform == "kubernetes"
    msg := kubernetes.deny[_]
}

violations[msg] {
    # Terraform policy violations
    input.platform == "terraform"
    msg := terraform.deny[_]
}

violations[msg] {
    # Helm policy violations
    input.platform == "helm"
    msg := helm.deny[_]
}

# Helper function to determine platform
platform = "docker" {
    input.type == "Dockerfile"
} else = "kubernetes" {
    input.kind == "Pod"
} else = "kubernetes" {
    input.kind == "Deployment"
} else = "kubernetes" {
    input.kind == "Service"
} else = "terraform" {
    input.resource.aws_s3_bucket
} else = "terraform" {
    input.resource.aws_security_group
} else = "helm" {
    input.metadata.apiVersion
    input.templates
}

# Helper function to determine severity level
severity_level = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# Sort violations by severity
sorted_violations[msg] {
    msg := violations[_]
    msg.severity
}

sorted_violations_desc = x {
    x := sort_by_severity(sorted_violations)
}

# Helper function to sort by severity
sort_by_severity(violations) = sorted {
    sorted := sort(violations, lambda a, b: severity_level[a.severity] > severity_level[b.severity])
}

# Check if configuration meets minimum security requirements
is_secure {
    count(violations) == 0
}

# Get summary of violations by severity
violation_summary = summary {
    all_violations := violations
    summary := {
        "total": count(all_violations),
        "by_severity": count_by_severity(all_violations),
        "by_platform": count_by_platform(all_violations)
    }
}

# Helper function to count violations by severity
count_by_severity(violations) = counts {
    counts := {severity: count |
        severity := severity_level[_]
        count := count([v | v := violations[_]; v.severity == severity])
    }
}

# Helper function to count violations by platform
count_by_platform(violations) = counts {
    counts := {platform: count |
        platform := platform
        count := count([v | v := violations[_]; v.platform == platform])
    }
}

# Get compliance status for different frameworks
compliance_status = status {
    status := {
        "cis": is_cis_compliant,
        "nist": is_nist_compliant,
        "hipaa": is_hipaa_compliant,
        "pci": is_pci_compliant
    }
}

# Helper functions for compliance checks
is_cis_compliant {
    not violations[msg] {
        msg.metadata.cis_benchmark
    }
}

is_nist_compliant {
    not violations[msg] {
        msg.metadata.nist_controls
    }
}

is_hipaa_compliant {
    not violations[msg] {
        msg.metadata.hipaa
    }
}

is_pci_compliant {
    not violations[msg] {
        msg.metadata.pci_dss
    }
}

# Get remediation recommendations
remediation_recommendations = recommendations {
    recommendations := [r |
        v := violations[_]
        r := {
            "title": v.title,
            "description": v.description,
            "recommendation": v.recommendation,
            "severity": v.severity,
            "platform": v.platform
        }
    ]
}

# Check for critical security issues that require immediate attention
critical_issues[issue] {
    v := violations[_]
    v.severity == "CRITICAL"
    issue := {
        "title": v.title,
        "description": v.description,
        "location": v.location,
        "platform": v.platform
    }
}

# Generate security score (0-100)
security_score = score {
    total_violations := count(violations)
    weighted_score := sum([weight |
        v := violations[_]
        weight := severity_weight(v.severity)
    ])
    max_score := 100
    score := max(0, max_score - weighted_score)
}

# Helper function for severity weights
severity_weight(severity) = weight {
    weights := {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0
    }
    weight := weights[severity]
}

# Get detailed analysis of security posture
security_analysis = analysis {
    analysis := {
        "score": security_score,
        "summary": violation_summary,
        "compliance": compliance_status,
        "critical_issues": critical_issues,
        "recommendations": remediation_recommendations
    }
}
