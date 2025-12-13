"""
Core results module for handling scan findings and analysis results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import total_ordering
from typing import Any, Dict, List, Optional

_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@total_ordering
class Severity(Enum):
    """Severity levels for security findings.

    Provides ordering so callers/tests can compare severities directly.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def _rank(self) -> int:
        return _SEVERITY_ORDER[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() < other._rank()


@dataclass
class Finding:
    """Represents a security finding from the scan."""

    id: str
    title: str
    description: str
    severity: Severity
    platform: str
    location: str
    code_snippet: str = ""
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceResult:
    """Results of compliance checks against a specific framework."""

    framework: str
    compliant: bool
    score: float
    passed_rules: List[str] = field(default_factory=list)
    failed_rules: List[str] = field(default_factory=list)
    skipped_rules: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIAnalysis:
    """Results from AI-powered security analysis."""

    zero_day_risks: List[Dict[str, Any]] = field(default_factory=list)
    pattern_findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_predictions: List[Dict[str, Any]] = field(default_factory=list)
    behavioral_analysis: Dict[str, Any] = field(default_factory=dict)
    confidence_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class Recommendation:
    """Security recommendation based on findings."""

    title: str
    description: str
    priority: int
    effort_estimate: str
    related_findings: List[str]
    remediation_steps: List[str]
    automated_fix: Optional[str] = None
    impact_analysis: Dict[str, Any] = field(default_factory=dict)


class ScanResult:
    """
    Comprehensive scan result containing all findings, analyses, and recommendations.
    """

    def __init__(self):
        self.scan_id: str = self._generate_scan_id()
        self.timestamp: datetime = datetime.utcnow()
        self.findings: List[Finding] = []
        self.platforms: List[str] = []
        self.compliance_results: Dict[str, ComplianceResult] = {}
        self.ai_analysis: Optional[AIAnalysis] = None
        self.recommendations: List[Recommendation] = []
        self.metrics: Dict[str, Any] = {
            "total_files_scanned": 0,
            "total_lines_scanned": 0,
            "scan_duration": 0,
            "findings_by_severity": {},
            "findings_by_platform": {},
        }
        self.summary: Dict[str, Any] = {}
        self._update_summary()

    def add_finding(self, finding: Finding) -> None:
        """Add a security finding to the results."""
        self.findings.append(finding)
        if finding.platform and finding.platform not in self.platforms:
            self.platforms.append(finding.platform)
        self._update_metrics()

    def add_compliance_result(self, framework: str, result: ComplianceResult) -> None:
        """Add compliance check results for a specific framework."""
        self.compliance_results[framework] = result
        self._update_summary()

    def add_zero_day_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Add zero-day vulnerability findings from AI analysis."""
        if not self.ai_analysis:
            self.ai_analysis = AIAnalysis()
        self.ai_analysis.zero_day_risks.extend(findings)
        self._update_summary()

    def add_pattern_findings(self, patterns: List[Dict[str, Any]]) -> None:
        """Add infrastructure pattern findings from AI analysis."""
        if not self.ai_analysis:
            self.ai_analysis = AIAnalysis()
        self.ai_analysis.pattern_findings.extend(patterns)
        self._update_summary()

    def add_risk_predictions(self, risks: List[Dict[str, Any]]) -> None:
        """Add predicted security risks from AI analysis."""
        if not self.ai_analysis:
            self.ai_analysis = AIAnalysis()
        self.ai_analysis.risk_predictions.extend(risks)
        self._update_summary()

    def set_recommendations(self, recommendations: List[Recommendation]) -> None:
        """Set security recommendations based on findings."""
        self.recommendations = recommendations
        self._update_summary()

    def merge(self, other: "ScanResult") -> None:
        """Merge another scan result into this one."""
        self.findings.extend(other.findings)
        self.platforms.extend(other.platforms)
        self.compliance_results.update(other.compliance_results)

        if other.ai_analysis:
            if not self.ai_analysis:
                self.ai_analysis = AIAnalysis()
            self.ai_analysis.zero_day_risks.extend(other.ai_analysis.zero_day_risks)
            self.ai_analysis.pattern_findings.extend(other.ai_analysis.pattern_findings)
            self.ai_analysis.risk_predictions.extend(other.ai_analysis.risk_predictions)

        self.recommendations.extend(other.recommendations)

        # Update metrics
        for key, value in other.metrics.items():
            if isinstance(value, (int, float)):
                self.metrics[key] = self.metrics.get(key, 0) + value
            elif isinstance(value, dict):
                if key not in self.metrics:
                    self.metrics[key] = {}
                self.metrics[key].update(value)

        self._update_summary()

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results."""
        return self.summary

    def _update_metrics(self) -> None:
        """Update metrics based on current findings."""
        severity_counts: Dict[str, int] = {}
        platform_counts: Dict[str, int] = {}

        for finding in self.findings:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )
            platform_counts[finding.platform] = (
                platform_counts.get(finding.platform, 0) + 1
            )

        self.metrics["findings_by_severity"] = severity_counts
        self.metrics["findings_by_platform"] = platform_counts
        self._update_summary()

    def _update_summary(self) -> None:
        """Update the summary based on current results."""
        self.summary = {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "total_findings": len(self.findings),
            "findings_by_severity": self.metrics["findings_by_severity"],
            "findings_by_platform": self.metrics["findings_by_platform"],
            "compliance_status": {
                framework: result.compliant
                for framework, result in self.compliance_results.items()
            },
            "ai_analysis_performed": bool(self.ai_analysis),
            "total_recommendations": len(self.recommendations),
            "scan_metrics": {
                "files_scanned": self.metrics["total_files_scanned"],
                "lines_scanned": self.metrics["total_lines_scanned"],
                "duration_seconds": self.metrics["scan_duration"],
            },
        }

    @staticmethod
    def _generate_scan_id() -> str:
        """Generate a unique scan ID."""
        import uuid

        return str(uuid.uuid4())
