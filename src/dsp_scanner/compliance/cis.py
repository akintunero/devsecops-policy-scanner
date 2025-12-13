from __future__ import annotations

from dsp_scanner.compliance import _basic_result
from dsp_scanner.core.results import ComplianceResult, ScanResult


class CISComplianceChecker:
    async def check(self, scan_result: ScanResult) -> ComplianceResult:
        return _basic_result("cis", scan_result)
