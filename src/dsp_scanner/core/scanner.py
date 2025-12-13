"""
Core scanner implementation providing the main scanning functionality.
"""

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from dsp_scanner.core.policy import Policy
from dsp_scanner.core.results import ScanResult, Severity
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class Scanner:
    """
    Main scanner class that orchestrates the scanning process across different platforms
    and integrates various analysis capabilities.
    """

    def __init__(
        self,
        enable_ai: bool = True,
        compliance_frameworks: Optional[List[str]] = None,
        severity_threshold: str = "medium",
    ):
        """
        Initialize the scanner with specified configuration.

        Args:
            enable_ai: Enable AI-powered analysis
            compliance_frameworks: List of compliance frameworks to check against
            severity_threshold: Minimum severity level to report
        """
        self.enable_ai = enable_ai
        self.compliance_frameworks = compliance_frameworks or ["cis", "nist"]
        self.severity_threshold = severity_threshold
        # Lazy import to avoid circular dependency
        self.security_analyzer = None
        if enable_ai:
            from dsp_scanner.ml.analyzer import SecurityAnalyzer

            self.security_analyzer = SecurityAnalyzer()

        # populated after a scan
        self._last_metrics: Dict[str, Any] = {}

    async def scan_path(
        self,
        path: str,
        platforms: Optional[List[str]] = None,
        policies: Optional[List[Policy]] = None,
    ) -> ScanResult:
        """
        Scan a path for security issues across specified platforms.

        Args:
            path: Path to scan
            platforms: List of platforms to scan for (docker, kubernetes, terraform, helm)
            policies: Optional list of custom policies to apply

        Returns:
            ScanResult object containing all findings and analysis
        """
        start_time = time.perf_counter()

        path_obj = Path(path)
        if not path_obj.exists():
            raise FileNotFoundError(f"Path does not exist: {path_obj}")

        logger.info(f"Starting scan of {path_obj} for platforms: {platforms}")

        # Detect platforms if not specified
        if not platforms:
            platforms = await self._detect_platforms(path_obj)
            logger.info(f"Detected platforms: {platforms}")

        # Initialize scan result
        scan_result = ScanResult()

        # Run platform-specific scans concurrently
        tasks = []
        for platform in platforms:
            tasks.append(self._scan_platform(path_obj, platform, policies))

        platform_results = await asyncio.gather(*tasks)
        for result in platform_results:
            scan_result.merge(result)

        # Apply severity threshold filtering to findings
        scan_result.findings = self._filter_by_severity_threshold(
            scan_result.findings, self.severity_threshold
        )
        scan_result._update_metrics()  # keep summary/metrics in sync

        # Perform AI analysis if enabled
        if self.enable_ai and self.security_analyzer:
            await self._perform_ai_analysis(scan_result)

        # Check compliance
        await self._check_compliance(scan_result)

        # Generate recommendations
        await self._generate_recommendations(scan_result)

        # Final metrics
        scan_result.metrics["scan_duration"] = time.perf_counter() - start_time
        self._last_metrics = dict(scan_result.metrics)

        logger.info("Scan completed successfully")
        return scan_result

    async def _detect_platforms(self, path: Path) -> List[str]:
        """
        Automatically detect which platforms are present in the given path.
        """
        platforms = set()

        # Check for Docker
        if (
            list(path.rglob("Dockerfile"))
            or list(path.rglob("Dockerfile.*"))
            or list(path.rglob("*.dockerfile"))
            or list(path.rglob("*.Dockerfile"))
        ):
            platforms.add("docker")

        # Check for Kubernetes
        if list(path.rglob("*.yaml")) or list(path.rglob("*.yml")):
            platforms.add("kubernetes")

        # Check for Terraform
        if list(path.rglob("*.tf")) or list(path.rglob("*.tfvars")):
            platforms.add("terraform")

        # Check for Helm
        if list(path.rglob("Chart.yaml")):
            platforms.add("helm")

        return list(platforms)

    async def _scan_platform(
        self,
        path: Path,
        platform: str,
        policies: Optional[List[Policy]] = None,
    ) -> ScanResult:
        """
        Perform platform-specific scanning.
        """
        scanner = self._get_platform_scanner(platform)
        return await scanner.scan(path, policies)

    async def _perform_ai_analysis(self, scan_result: ScanResult) -> None:
        """
        Perform AI-powered security analysis on the scan results.
        """
        if not self.security_analyzer:
            return

        # Analyze for zero-day vulnerabilities
        zero_days = await self.security_analyzer.detect_zero_days(scan_result)
        scan_result.add_zero_day_findings(zero_days)

        # Analyze infrastructure patterns
        patterns = await self.security_analyzer.analyze_patterns(scan_result)
        scan_result.add_pattern_findings(patterns)

        # Predict potential security risks
        risks = await self.security_analyzer.predict_risks(scan_result)
        scan_result.add_risk_predictions(risks)

    async def _check_compliance(self, scan_result: ScanResult) -> None:
        """Check compliance against specified frameworks."""
        for framework in self.compliance_frameworks:
            try:
                compliance_checker = self._get_compliance_checker(framework)
                compliance_result = await compliance_checker.check(scan_result)
                scan_result.add_compliance_result(framework, compliance_result)
            except Exception as e:
                logger.warning(
                    f"Compliance check failed for framework '{framework}': {e}"
                )

    async def _generate_recommendations(self, scan_result: ScanResult) -> None:
        """Generate security recommendations based on scan findings."""
        recommendations: List[Any] = []

        # Generate platform-specific recommendations
        for platform in scan_result.platforms:
            platform_recs = await self._generate_platform_recommendations(
                platform, scan_result
            )
            recommendations.extend(platform_recs)

        # Generate AI-powered recommendations if enabled
        if self.enable_ai and self.security_analyzer:
            ai_recs = await self.security_analyzer.generate_recommendations(scan_result)
            recommendations.extend(ai_recs)

        scan_result.set_recommendations(recommendations)

    async def _generate_platform_recommendations(
        self, platform: str, scan_result: ScanResult
    ) -> List[Any]:
        """Platform-specific recommendations (placeholder).

        This keeps the scanner functional even if a platform doesn't yet have a
        dedicated recommendation engine.
        """
        return []

    @staticmethod
    def _filter_by_severity_threshold(findings: List[Any], threshold: str) -> List[Any]:
        """Filter findings by severity threshold."""
        try:
            threshold_enum = Severity(threshold)
        except Exception:
            threshold_enum = Severity.MEDIUM

        return [
            f
            for f in findings
            if getattr(f, "severity", Severity.INFO) >= threshold_enum
        ]

    def get_metrics(self) -> Dict[str, Any]:
        """Return metrics from the most recent scan."""
        return dict(self._last_metrics)

    def _get_platform_scanner(self, platform: str):
        """
        Get the appropriate scanner for the specified platform.
        """
        scanners = {
            "docker": "DockerScanner",
            "kubernetes": "KubernetesScanner",
            "terraform": "TerraformScanner",
            "helm": "HelmScanner",
        }

        scanner_class = scanners.get(platform)
        if not scanner_class:
            raise ValueError(f"Unsupported platform: {platform}")

        # Import the appropriate scanner dynamically
        module = __import__(
            f"dsp_scanner.scanners.{platform}", fromlist=[scanner_class]
        )
        return getattr(module, scanner_class)()

    def _get_compliance_checker(self, framework: str):
        """
        Get the appropriate compliance checker for the specified framework.
        """
        checkers = {
            "cis": "CISComplianceChecker",
            "nist": "NISTComplianceChecker",
            "hipaa": "HIPAAComplianceChecker",
            "pci": "PCIComplianceChecker",
        }

        checker_class = checkers.get(framework)
        if not checker_class:
            raise ValueError(f"Unsupported compliance framework: {framework}")

        # Import the appropriate checker dynamically
        module = __import__(
            f"dsp_scanner.compliance.{framework}", fromlist=[checker_class]
        )
        return getattr(module, checker_class)()
