"""Compliance automation modules.

This package contains:
- the advanced compliance automation system (`automation.py`)
- lightweight per-framework checkers used by `dsp_scanner.core.scanner.Scanner`

The lightweight checkers intentionally use a heuristic scoring model so the
scanner can run without a full control mapping implementation.
"""

from __future__ import annotations

from dsp_scanner.compliance.automation import (
    ComplianceAutomation,
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
    ComplianceReport,
)
from dsp_scanner.core.results import ComplianceResult, ScanResult, Severity


def _basic_score(scan_result: ScanResult) -> float:
    critical = sum(1 for f in scan_result.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in scan_result.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in scan_result.findings if f.severity == Severity.MEDIUM)

    score = 100.0 - critical * 20.0 - high * 10.0 - medium * 3.0
    return max(0.0, min(100.0, score))


def _basic_result(framework: str, scan_result: ScanResult) -> ComplianceResult:
    score = _basic_score(scan_result)
    return ComplianceResult(
        framework=framework,
        compliant=score >= 80.0,
        score=score,
        passed_rules=[],
        failed_rules=[],
        skipped_rules=[],
        evidence={"heuristic": True},
    )


__all__ = [
    "ComplianceAutomation",
    "ComplianceFramework",
    "ComplianceReport",
    "ComplianceControl",
    "ComplianceEvidence",
    "_basic_score",
    "_basic_result",
]
