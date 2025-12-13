#!/usr/bin/env python3
"""
Enhanced Policy Engine for DevSecOps Policy Scanner
Advanced policy management with severity levels, categories, and dynamic loading
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class Severity(Enum):
    """Policy severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Policy:
    """Policy data structure"""

    key: str
    value: Any
    description: str
    severity: Severity
    category: str
    framework: Optional[str] = None
    control_id: Optional[str] = None
    remediation: Optional[str] = None
    tags: Optional[List[str]] = None


@dataclass
class ScanResult:
    """Scan result data structure"""

    policy: Policy
    compliant: bool
    actual_value: Any
    message: str
    risk_score: float


class EnhancedPolicyEngine:
    """Enhanced policy engine with advanced features"""

    def __init__(self, policy_dir: str = "policies/"):
        self.policy_dir = Path(policy_dir)
        self.policies: List[Policy] = []
        self.logger = logging.getLogger(__name__)
        self.load_policies()

    def load_policies(self) -> None:
        """Load all policies from the policies directory"""
        if not self.policy_dir.exists():
            self.logger.warning(f"Policy directory {self.policy_dir} does not exist")
            return

        for policy_file in self.policy_dir.glob("*.yaml"):
            try:
                with open(policy_file, "r") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, list):
                        for policy_data in data:
                            policy = self._create_policy(policy_data, policy_file.name)
                            if policy:
                                self.policies.append(policy)
                self.logger.info(f"Loaded {len(data)} policies from {policy_file.name}")
            except Exception as e:
                self.logger.error(f"Error loading policies from {policy_file}: {e}")

    def _create_policy(self, data: Dict, filename: str) -> Optional[Policy]:
        """Create a Policy object from dictionary data"""
        try:
            # Extract framework from filename
            framework = filename.replace(".yaml", "").upper()

            # Parse severity
            severity_str = data.get("severity", "medium").lower()
            severity = Severity(severity_str)

            # Create policy object
            policy = Policy(
                key=data["key"],
                value=data["value"],
                description=data["description"],
                severity=severity,
                category=data.get("category", "general"),
                framework=framework,
                control_id=data.get("cis_control") or data.get("owasp_control"),
                remediation=data.get("remediation"),
                tags=data.get("tags", []),
            )
            return policy
        except Exception as e:
            self.logger.error(f"Error creating policy from {data}: {e}")
            return None

    def scan(
        self,
        config: Dict[str, Any],
        severity_filter: Optional[Severity] = None,
        category_filter: Optional[str] = None,
        framework_filter: Optional[str] = None,
    ) -> List[ScanResult]:
        """Scan configuration against policies"""
        results = []

        for policy in self.policies:
            # Apply filters
            if severity_filter and policy.severity != severity_filter:
                continue
            if category_filter and policy.category != category_filter:
                continue
            if framework_filter and policy.framework != framework_filter:
                continue

            # Check compliance
            actual_value = config.get(policy.key)
            compliant = self._check_compliance(policy, actual_value)

            # Calculate risk score
            risk_score = self._calculate_risk_score(policy, compliant)

            # Create result
            result = ScanResult(
                policy=policy,
                compliant=compliant,
                actual_value=actual_value,
                message=self._generate_message(policy, compliant, actual_value),
                risk_score=risk_score,
            )
            results.append(result)

        return results

    def _check_compliance(self, policy: Policy, actual_value: Any) -> bool:
        """Check if a policy is compliant"""
        if actual_value is None:
            return False

        # Handle different value types
        if isinstance(policy.value, bool):
            return actual_value == policy.value
        elif isinstance(policy.value, str):
            return actual_value == policy.value
        elif isinstance(policy.value, (int, float)):
            return actual_value == policy.value
        else:
            return actual_value == policy.value

    def _calculate_risk_score(self, policy: Policy, compliant: bool) -> float:
        """Calculate risk score based on severity and compliance"""
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0,
        }

        base_score = severity_scores.get(policy.severity, 5.0)
        return base_score if not compliant else 0.0

    def _generate_message(
        self, policy: Policy, compliant: bool, actual_value: Any
    ) -> str:
        """Generate human-readable message for scan result"""
        if compliant:
            return f"✅ {policy.description}"
        else:
            return f"❌ {policy.description} (Expected: {policy.value}, Found: {actual_value})"

    def get_policies_by_category(self, category: str) -> List[Policy]:
        """Get all policies in a specific category"""
        return [p for p in self.policies if p.category == category]

    def get_policies_by_severity(self, severity: Severity) -> List[Policy]:
        """Get all policies with a specific severity"""
        return [p for p in self.policies if p.severity == severity]

    def get_policies_by_framework(self, framework: str) -> List[Policy]:
        """Get all policies from a specific framework"""
        return [p for p in self.policies if p.framework == framework]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of loaded policies"""
        total_policies = len(self.policies)
        categories = set(p.category for p in self.policies)
        frameworks = set(p.framework for p in self.policies if p.framework)
        severities = {sev: len(self.get_policies_by_severity(sev)) for sev in Severity}

        return {
            "total_policies": total_policies,
            "categories": list(categories),
            "frameworks": list(frameworks),
            "severity_distribution": severities,
        }

    def export_policies(
        self, format: str = "json", output_file: Optional[str] = None
    ) -> str:
        """Export policies to different formats"""
        if format.lower() == "json":
            data = []
            for policy in self.policies:
                data.append(
                    {
                        "key": policy.key,
                        "value": policy.value,
                        "description": policy.description,
                        "severity": policy.severity.value,
                        "category": policy.category,
                        "framework": policy.framework,
                        "control_id": policy.control_id,
                        "remediation": policy.remediation,
                        "tags": policy.tags,
                    }
                )

            output = json.dumps(data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_file:
            with open(output_file, "w") as f:
                f.write(output)

        return output


def main():
    """Example usage of the enhanced policy engine"""
    # Initialize the policy engine
    engine = EnhancedPolicyEngine()

    # Get summary
    summary = engine.get_summary()
    print("Policy Engine Summary:")
    print(json.dumps(summary, indent=2))

    # Example configuration to scan
    sample_config = {
        "enforce_2fa": False,
        "secret_in_code": True,
        "branch_protection": True,
        "control_plane_https": True,
        "pod_privileged_containers": False,
        "tls_version_minimum": "1.1",
    }

    # Scan configuration
    results = engine.scan(sample_config)

    print(f"\nScan Results ({len(results)} policies checked):")
    for result in results:
        status = "✅ PASS" if result.compliant else "❌ FAIL"
        print(f"{status} [{result.policy.severity.value.upper()}] {result.message}")

    # Export policies
    print("\nExporting policies to JSON...")
    engine.export_policies("json")
    print("Policies exported successfully!")


if __name__ == "__main__":
    main()
