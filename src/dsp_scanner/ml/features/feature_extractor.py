"""
Feature extraction for security risk prediction.
Extracts numerical features from scan results for ML models.
"""

import numpy as np

from dsp_scanner.core.results import ScanResult, Severity


class SecurityFeatureExtractor:
    """Extract features from scan results for ML models."""

    def __init__(self):
        self.feature_names = [
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "info_count",
            "total_findings",
            "avg_code_complexity",
            "max_code_complexity",
            "secret_exposure_count",
            "vulnerability_count",
            "compliance_violation_count",
            "dependency_issue_count",
            "privilege_escalation_count",
            "network_exposure_count",
            "authentication_issue_count",
            "encryption_issue_count",
            "cvss_avg_score",
            "cvss_max_score",
            "finding_diversity_score",
            "platform_diversity_score",
        ]

    def extract_features(self, scan_result: ScanResult) -> np.ndarray:
        """Extract features from scan result."""
        features = []

        # Severity-based features
        features.append(self._count_by_severity(scan_result, Severity.CRITICAL))
        features.append(self._count_by_severity(scan_result, Severity.HIGH))
        features.append(self._count_by_severity(scan_result, Severity.MEDIUM))
        features.append(self._count_by_severity(scan_result, Severity.LOW))
        features.append(self._count_by_severity(scan_result, Severity.INFO))
        features.append(len(scan_result.findings))

        # Code complexity features
        features.append(self._avg_code_complexity(scan_result))
        features.append(self._max_code_complexity(scan_result))

        # Security pattern features
        features.append(self._count_secrets(scan_result))
        features.append(self._count_vulnerabilities(scan_result))
        features.append(self._count_compliance_violations(scan_result))
        features.append(self._count_dependency_issues(scan_result))
        features.append(self._count_privilege_issues(scan_result))
        features.append(self._count_network_exposure(scan_result))
        features.append(self._count_authentication_issues(scan_result))
        features.append(self._count_encryption_issues(scan_result))

        # CVSS score features
        features.append(self._avg_cvss_score(scan_result))
        features.append(self._max_cvss_score(scan_result))

        # Diversity features
        features.append(self._finding_diversity_score(scan_result))
        features.append(self._platform_diversity_score(scan_result))

        return np.array(features, dtype=np.float32)

    def _count_by_severity(self, result: ScanResult, severity: Severity) -> float:
        """Count findings by severity."""
        return float(sum(1 for f in result.findings if f.severity == severity))

    def _avg_code_complexity(self, result: ScanResult) -> float:
        """Calculate average code snippet length as proxy for complexity."""
        if not result.findings:
            return 0.0

        code_lengths = [
            len(f.code_snippet or "") for f in result.findings if f.code_snippet
        ]
        return float(np.mean(code_lengths)) if code_lengths else 0.0

    def _max_code_complexity(self, result: ScanResult) -> float:
        """Calculate maximum code snippet length."""
        if not result.findings:
            return 0.0

        code_lengths = [
            len(f.code_snippet or "") for f in result.findings if f.code_snippet
        ]
        return float(np.max(code_lengths)) if code_lengths else 0.0

    def _count_secrets(self, result: ScanResult) -> float:
        """Count secret exposure findings."""
        secret_keywords = [
            "secret",
            "password",
            "key",
            "token",
            "credential",
            "api_key",
            "private_key",
        ]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in secret_keywords
                )
            )
        )

    def _count_vulnerabilities(self, result: ScanResult) -> float:
        """Count vulnerability findings."""
        vuln_keywords = [
            "vulnerability",
            "cve",
            "exploit",
            "attack",
            "injection",
            "xss",
            "sqli",
        ]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in vuln_keywords
                )
            )
        )

    def _count_compliance_violations(self, result: ScanResult) -> float:
        """Count compliance violation findings."""
        compliance_keywords = [
            "compliance",
            "policy",
            "standard",
            "requirement",
            "violation",
        ]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in compliance_keywords
                )
            )
        )

    def _count_dependency_issues(self, result: ScanResult) -> float:
        """Count dependency-related findings."""
        dep_keywords = [
            "dependency",
            "package",
            "library",
            "module",
            "npm",
            "pip",
            "maven",
        ]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in dep_keywords
                )
            )
        )

    def _count_privilege_issues(self, result: ScanResult) -> float:
        """Count privilege escalation findings."""
        priv_keywords = [
            "privilege",
            "permission",
            "rbac",
            "access control",
            "escalation",
            "sudo",
        ]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in priv_keywords
                )
            )
        )

    def _count_network_exposure(self, result: ScanResult) -> float:
        """Count network exposure findings."""
        network_keywords = [
            "network",
            "port",
            "firewall",
            "exposed",
            "public",
            "internet-facing",
        ]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in network_keywords
                )
            )
        )

    def _count_authentication_issues(self, result: ScanResult) -> float:
        """Count authentication-related findings."""
        auth_keywords = ["authentication", "auth", "login", "session", "jwt", "oauth"]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in auth_keywords
                )
            )
        )

    def _count_encryption_issues(self, result: ScanResult) -> float:
        """Count encryption-related findings."""
        enc_keywords = ["encryption", "encrypt", "ssl", "tls", "cipher", "crypto"]
        return float(
            sum(
                1
                for f in result.findings
                if any(
                    kw in f.description.lower() or kw in f.title.lower()
                    for kw in enc_keywords
                )
            )
        )

    def _avg_cvss_score(self, result: ScanResult) -> float:
        """Calculate average CVSS score."""
        scores = [f.cvss_score for f in result.findings if f.cvss_score is not None]
        return float(np.mean(scores)) if scores else 0.0

    def _max_cvss_score(self, result: ScanResult) -> float:
        """Calculate maximum CVSS score."""
        scores = [f.cvss_score for f in result.findings if f.cvss_score is not None]
        return float(np.max(scores)) if scores else 0.0

    def _finding_diversity_score(self, result: ScanResult) -> float:
        """Calculate diversity of finding types."""
        if not result.findings:
            return 0.0

        # Count unique finding types based on title keywords
        unique_types = set()
        for finding in result.findings:
            # Extract first significant word from title
            words = finding.title.lower().split()
            if words:
                unique_types.add(words[0])

        # Diversity score: ratio of unique types to total findings
        return (
            float(len(unique_types) / len(result.findings)) if result.findings else 0.0
        )

    def _platform_diversity_score(self, result: ScanResult) -> float:
        """Calculate diversity of platforms."""
        if not result.findings:
            return 0.0

        platforms = set(f.platform for f in result.findings)
        return float(len(platforms) / len(result.findings)) if result.findings else 0.0
