"""
Helm security scanner module.
Implements security checks for Helm charts and templates.
"""

import asyncio
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from dsp_scanner.core.policy import Policy
from dsp_scanner.core.results import Finding, ScanResult, Severity
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class HelmScanner:
    """
    Scanner for Helm security checks.
    Analyzes Helm charts and templates for security issues.
    """

    def __init__(self):
        """Initialize the Helm scanner."""
        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0
        self.templates_scanned = 0

    async def scan(
        self, path: Path, policies: Optional[List[Policy]] = None
    ) -> ScanResult:
        """
        Scan Helm charts for security issues.

        Args:
            path: Path to scan
            policies: Optional list of custom policies to apply

        Returns:
            ScanResult containing all findings
        """
        logger.info(f"Starting Helm security scan for {path}")

        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        # Reset per-scan state
        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0
        self.templates_scanned = 0

        # Initialize scan result
        scan_result = ScanResult()
        scan_result.platforms.append("helm")

        try:
            # Find all Helm charts
            charts = self._find_helm_charts(path)

            # Scan each chart
            for chart in charts:
                findings = await self._scan_chart(chart, policies)
                self.findings.extend(findings)

            # Update scan metrics
            scan_result.metrics["total_files_scanned"] = self.files_scanned
            scan_result.metrics["total_lines_scanned"] = self.lines_scanned
            scan_result.metrics["total_templates_scanned"] = self.templates_scanned

            # Add findings to result
            for finding in self.findings:
                scan_result.add_finding(finding)

        except Exception as e:
            logger.error(f"Helm scan failed: {str(e)}")
            raise

        return scan_result

    def _find_helm_charts(self, path: Path) -> List[Path]:
        """Find all Helm charts in the given path.

        In addition to standard charts (Chart.yaml), treat a directory with a
        `templates/` folder as a scan target. This supports partial charts used in tests.
        """
        charts: List[Path] = []

        if path.is_file() and path.name == "Chart.yaml":
            charts.append(path.parent)
        elif path.is_dir():
            # If user points directly at a chart dir, scan it even if Chart.yaml is missing.
            if (
                (path / "Chart.yaml").exists()
                or (path / "templates").exists()
                or (path / "values.yaml").exists()
            ):
                charts.append(path)
            else:
                for chart_file in path.rglob("Chart.yaml"):
                    charts.append(chart_file.parent)
        else:
            for chart_file in path.rglob("Chart.yaml"):
                charts.append(chart_file.parent)

        # De-dupe while preserving order
        seen = set()
        deduped = []
        for c in charts:
            if c not in seen:
                seen.add(c)
                deduped.append(c)

        logger.info(f"Found {len(deduped)} Helm chart(s)")
        return deduped

    async def _scan_chart(
        self, chart_path: Path, policies: Optional[List[Policy]] = None
    ) -> List[Finding]:
        """
        Scan a Helm chart for security issues.

        Args:
            chart_path: Path to Helm chart
            policies: Optional list of custom policies to apply

        Returns:
            List of security findings
        """
        findings = []

        try:
            # Scan Chart.yaml
            chart_yaml = chart_path / "Chart.yaml"
            if chart_yaml.exists():
                self.files_scanned += 1
                findings.extend(await self._scan_chart_yaml(chart_yaml))

            # Scan values.yaml
            values_yaml = chart_path / "values.yaml"
            if values_yaml.exists():
                self.files_scanned += 1
                findings.extend(await self._scan_values_yaml(values_yaml))

            # Scan templates
            templates_dir = chart_path / "templates"
            if templates_dir.exists():
                for template in templates_dir.rglob("*.yaml"):
                    self.files_scanned += 1
                    self.templates_scanned += 1
                    findings.extend(await self._scan_template(template))

            # Apply custom policies if provided
            if policies:
                findings.extend(await self._apply_chart_policies(chart_path, policies))

        except Exception as e:
            logger.error(f"Failed to scan chart {chart_path}: {str(e)}")

        return findings

    async def _scan_chart_yaml(self, chart_yaml: Path) -> List[Finding]:
        """Scan Chart.yaml for security issues."""
        findings = []

        try:
            with chart_yaml.open() as f:
                content = f.read()
                self.lines_scanned += len(content.splitlines())
                chart_data = yaml.safe_load(content)

            # Check for API version
            api_version = chart_data.get("apiVersion")
            if not api_version or api_version == "v1":
                findings.append(
                    Finding(
                        id="HELM001",
                        title="Outdated API version",
                        description="Chart uses outdated API version.",
                        severity=Severity.LOW,
                        platform="helm",
                        location=str(chart_yaml),
                        recommendation="Update to apiVersion: v2 for better features "
                        "and security.",
                    )
                )

            # Check for maintainers
            if not chart_data.get("maintainers"):
                findings.append(
                    Finding(
                        id="HELM002",
                        title="Missing maintainers",
                        description="Chart does not specify maintainers.",
                        severity=Severity.MEDIUM,
                        platform="helm",
                        location=str(chart_yaml),
                        recommendation="Add maintainers section for better accountability.",
                    )
                )

        except Exception as e:
            logger.error(f"Failed to scan Chart.yaml {chart_yaml}: {str(e)}")

        return findings

    async def _scan_values_yaml(self, values_yaml: Path) -> List[Finding]:
        """Scan values.yaml for security issues."""
        findings = []

        try:
            with values_yaml.open() as f:
                content = f.read()
                self.lines_scanned += len(content.splitlines())
                values = yaml.safe_load(content)

            # Check for sensitive data
            findings.extend(self._check_sensitive_values(values, values_yaml))

            # Check for security configurations
            findings.extend(self._check_security_configs(values, values_yaml))

        except Exception as e:
            logger.error(f"Failed to scan values.yaml {values_yaml}: {str(e)}")

        return findings

    async def _scan_template(self, template: Path) -> List[Finding]:
        """Scan a Helm template for security issues."""
        findings = []

        try:
            with template.open() as f:
                content = f.read()
                self.lines_scanned += len(content.splitlines())

            # Check for potential template injection
            findings.extend(self._check_template_injection(content, template))

            # Check for security best practices in templates
            findings.extend(self._check_template_security(content, template))

        except Exception as e:
            logger.error(f"Failed to scan template {template}: {str(e)}")

        return findings

    def _check_sensitive_values(
        self, values: Dict[str, Any], file_path: Path
    ) -> List[Finding]:
        """Check for sensitive data in values."""
        findings = []

        sensitive_patterns = {
            "password": r"(?i)password|passwd|pwd",
            "token": r"(?i)token|api[_-]?key",
            "secret": r"(?i)secret|private[_-]?key",
        }

        def check_dict(d: Dict[str, Any], path: str = ""):
            for k, v in d.items():
                current_path = f"{path}.{k}" if path else k

                # Check key names
                for sensitive_type, pattern in sensitive_patterns.items():
                    if re.search(pattern, k):
                        findings.append(
                            Finding(
                                id="HELM003",
                                title=f"Sensitive {sensitive_type} in values",
                                description=f"Potentially sensitive {sensitive_type} "
                                f"found at '{current_path}'.",
                                severity=Severity.HIGH,
                                platform="helm",
                                location=str(file_path),
                                recommendation="Use external secrets management or "
                                "environment variables.",
                            )
                        )

                # Recurse into nested structures
                if isinstance(v, dict):
                    check_dict(v, current_path)
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        if isinstance(item, dict):
                            check_dict(item, f"{current_path}[{i}]")

        check_dict(values)
        return findings

    def _check_security_configs(
        self, values: Dict[str, Any], file_path: Path
    ) -> List[Finding]:
        """Check for security-related configurations."""
        findings = []

        # Check for privileged containers
        if values.get("securityContext", {}).get("privileged"):
            findings.append(
                Finding(
                    id="HELM004",
                    title="Privileged container configuration",
                    description="Chart allows privileged container execution.",
                    severity=Severity.HIGH,
                    platform="helm",
                    location=str(file_path),
                    recommendation="Avoid running containers in privileged mode.",
                )
            )

        # Check for host path volumes
        volumes = values.get("volumes", [])
        if isinstance(volumes, list):
            for volume in volumes:
                if isinstance(volume, dict) and "hostPath" in volume:
                    findings.append(
                        Finding(
                            id="HELM005",
                            title="Host path volume mount",
                            description="Chart configures host path volume mounts.",
                            severity=Severity.HIGH,
                            platform="helm",
                            location=str(file_path),
                            recommendation="Avoid using host path volumes for better "
                            "security isolation.",
                        )
                    )

        return findings

    def _check_template_injection(self, content: str, template: Path) -> List[Finding]:
        """Check for potential template injection vulnerabilities."""
        findings = []

        # Flag values that are *entirely* a `.Values.*` template expression.
        # This is a conservative heuristic to reduce false positives (e.g. image strings).
        lines = content.splitlines()

        value_expr = re.compile(r"{{\s*\.Values\.[^}]+}}")

        for idx, line in enumerate(lines, start=1):
            if ":" not in line:
                continue

            # Split on the YAML mapping colon (first colon only).
            _, raw_value = line.split(":", 1)
            raw_value = raw_value.strip()

            # Remove surrounding quotes if present.
            if (
                len(raw_value) >= 2
                and raw_value[0] in ("'", '"')
                and raw_value[-1] == raw_value[0]
            ):
                raw_value = raw_value[1:-1].strip()

            if value_expr.fullmatch(raw_value):
                findings.append(
                    Finding(
                        id="HELM006",
                        title="Potential template injection",
                        description="Template value is a raw `.Values.*` expression and may allow injection.",
                        severity=Severity.HIGH,
                        platform="helm",
                        location=f"{template}:{idx}",
                        code_snippet=line.strip(),
                        recommendation="Validate and sanitize values; avoid directly rendering untrusted input.",
                    )
                )

        return findings

    def _check_template_security(self, content: str, template: Path) -> List[Finding]:
        """Check for security best practices in templates."""
        findings = []

        try:
            # Parse YAML documents in template
            docs = list(yaml.safe_load_all(content))

            for doc in docs:
                if not doc:
                    continue

                # Check for security context
                if doc.get("kind") in ["Deployment", "StatefulSet", "DaemonSet"]:
                    spec = doc.get("spec", {}).get("template", {}).get("spec", {})

                    if not spec.get("securityContext"):
                        findings.append(
                            Finding(
                                id="HELM007",
                                title="Missing security context",
                                description="Pod template does not specify security context.",
                                severity=Severity.MEDIUM,
                                platform="helm",
                                location=str(template),
                                recommendation="Add security context with appropriate settings.",
                            )
                        )

                    # Flag privileged containers
                    containers = spec.get("containers", []) + spec.get(
                        "initContainers", []
                    )
                    for c in containers:
                        sc = (c or {}).get("securityContext", {})
                        if sc.get("privileged") is True:
                            findings.append(
                                Finding(
                                    id="HELM008",
                                    title="Privileged container in template",
                                    description="Container is configured as privileged.",
                                    severity=Severity.HIGH,
                                    platform="helm",
                                    location=str(template),
                                    code_snippet=str(sc),
                                    recommendation="Avoid privileged containers; use least privilege.",
                                )
                            )

        except Exception as e:
            logger.error(f"Failed to parse template {template}: {str(e)}")

        return findings

    async def _apply_chart_policies(
        self, chart_path: Path, policies: List[Policy]
    ) -> List[Finding]:
        """Apply custom policies to the chart."""
        findings = []

        try:
            # Load chart metadata
            chart_data = self._load_chart_data(chart_path)

            # Apply policies
            for policy in policies:
                if policy.platform != "helm":
                    continue

                try:
                    result = await policy.evaluate({"chart": chart_data})
                    if asyncio.isfuture(result):
                        result = await result

                    if result.get("violations"):
                        findings.extend(
                            self._convert_policy_violations(
                                result["violations"], chart_path, policy
                            )
                        )
                except Exception as e:
                    logger.error(f"Failed to apply policy {policy.name}: {str(e)}")

        except Exception as e:
            logger.error(f"Failed to apply chart policies: {str(e)}")

        return findings

    def _load_chart_data(self, chart_path: Path) -> Dict[str, Any]:
        """Load all relevant chart data for policy evaluation."""
        templates: List[Dict[str, Any]] = []
        data: Dict[str, Any] = {"metadata": {}, "values": {}, "templates": templates}

        # Load Chart.yaml
        chart_yaml = chart_path / "Chart.yaml"
        if chart_yaml.exists():
            with chart_yaml.open() as f:
                data["metadata"] = yaml.safe_load(f)

        # Load values.yaml
        values_yaml = chart_path / "values.yaml"
        if values_yaml.exists():
            with values_yaml.open() as f:
                data["values"] = yaml.safe_load(f)

        # Load templates
        templates_dir = chart_path / "templates"
        if templates_dir.exists():
            for template in templates_dir.rglob("*.yaml"):
                with template.open() as f:
                    templates.append(
                        {
                            "name": str(template.relative_to(templates_dir)),
                            "content": yaml.safe_load_all(f),
                        }
                    )

        return data

    def _convert_policy_violations(
        self, violations: List[Dict[str, Any]], chart_path: Path, policy: Policy
    ) -> List[Finding]:
        """Convert policy violations to findings."""
        findings = []

        for violation in violations:
            findings.append(
                Finding(
                    id=f"POLICY_{policy.name}",
                    title=violation.get("title", "Policy Violation"),
                    description=violation.get("description", policy.description),
                    severity=Severity(violation.get("severity", policy.severity)),
                    platform="helm",
                    location=str(chart_path),
                    code_snippet=str(violation.get("code_snippet") or ""),
                    recommendation=violation.get(
                        "recommendation", "Follow policy requirements."
                    ),
                )
            )

        return findings
