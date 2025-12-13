"""
Kubernetes security scanner module.
Implements security checks for Kubernetes manifests and configurations.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from dsp_scanner.core.policy import Policy
from dsp_scanner.core.results import Finding, ScanResult, Severity
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class KubernetesScanner:
    """
    Scanner for Kubernetes security checks.
    Analyzes Kubernetes manifests and configurations for security issues.
    """

    def __init__(self):
        """Initialize the Kubernetes scanner."""
        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0
        self.resources_scanned = 0

    async def scan(
        self, path: Path, policies: Optional[List[Policy]] = None
    ) -> ScanResult:
        """Scan Kubernetes manifests for security issues."""

        logger.info(f"Starting Kubernetes security scan for {path}")

        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        # Reset per-scan state (scanner instances may be reused across calls)
        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0
        self.resources_scanned = 0

        # Initialize scan result
        scan_result = ScanResult()
        scan_result.platforms.append("kubernetes")

        try:
            # Find all Kubernetes manifests
            manifests = self._find_kubernetes_manifests(path)

            # Scan each manifest
            for manifest in manifests:
                findings = await self._scan_manifest(manifest, policies)
                self.findings.extend(findings)

            # Update scan metrics
            scan_result.metrics["total_files_scanned"] = self.files_scanned
            scan_result.metrics["total_lines_scanned"] = self.lines_scanned
            scan_result.metrics["total_resources_scanned"] = self.resources_scanned

            # Add findings to result
            for finding in self.findings:
                scan_result.add_finding(finding)

        except Exception as e:
            logger.error(f"Kubernetes scan failed: {str(e)}")
            raise

        return scan_result

    def _find_kubernetes_manifests(self, path: Path) -> List[Path]:
        """Find all Kubernetes manifest files in the given path."""
        manifests = []

        if path.is_file() and self._is_kubernetes_manifest(path):
            manifests.append(path)
        else:
            manifests.extend(
                f for f in path.rglob("*") if self._is_kubernetes_manifest(f)
            )

        logger.info(f"Found {len(manifests)} Kubernetes manifest(s)")
        return manifests

    async def _scan_manifest(
        self, manifest: Path, policies: Optional[List[Policy]] = None
    ) -> List[Finding]:
        """
        Scan a Kubernetes manifest for security issues.

        Args:
            manifest: Path to manifest file
            policies: Optional list of custom policies to apply

        Returns:
            List of security findings
        """
        findings: List[Finding] = []
        self.files_scanned += 1

        try:
            # Parse manifest
            with manifest.open() as f:
                content = f.read()
                self.lines_scanned += len(content.splitlines())

                # Handle multi-document YAML files
                docs = list(yaml.safe_load_all(content))

                # Flatten cases where a document is a list of resources
                resources: List[Dict[str, Any]] = []
                for doc in docs:
                    if not doc:
                        continue
                    if isinstance(doc, list):
                        resources.extend([d for d in doc if isinstance(d, dict)])
                    elif isinstance(doc, dict):
                        resources.append(doc)

                self.resources_scanned += len(resources)

                for resource in resources:
                    # Basic security checks based on resource type
                    resource_type = resource.get("kind")
                    if resource_type:
                        if resource_type == "Pod":
                            findings.extend(
                                self._check_pod_security(resource, manifest)
                            )
                        elif resource_type == "Deployment":
                            findings.extend(
                                self._check_deployment_security(resource, manifest)
                            )
                        elif resource_type == "Service":
                            findings.extend(
                                self._check_service_security(resource, manifest)
                            )
                        elif resource_type == "NetworkPolicy":
                            findings.extend(
                                self._check_network_policy(resource, manifest)
                            )
                        elif resource_type == "Role" or resource_type == "ClusterRole":
                            findings.extend(
                                self._check_rbac_security(resource, manifest)
                            )

                    # Common security checks for all resources
                    findings.extend(self._check_common_security(resource, manifest))

                    # Apply custom policies if provided
                    if policies:
                        policy_findings = await self._apply_policies(
                            resource,
                            manifest,
                            policies,
                        )
                        findings.extend(policy_findings)

        except Exception as e:
            logger.error(f"Failed to scan manifest {manifest}: {str(e)}")

        return findings

    def _check_pod_security(
        self, pod_spec: Dict[str, Any], manifest: Path
    ) -> List[Finding]:
        """Check Pod security configuration."""
        findings: List[Finding] = []

        # Extract Pod spec (handle both Pod and PodTemplate cases)
        spec = pod_spec.get("spec", {})
        if not spec:
            return findings

        # Check privileged containers
        containers = spec.get("containers", []) + spec.get("initContainers", [])
        for container in containers:
            security_context = container.get("securityContext", {})

            if security_context.get("privileged"):
                findings.append(
                    Finding(
                        id="K8S001",
                        title="Privileged container detected",
                        description=f"Container '{container.get('name', 'unknown')}' is "
                        "running in privileged mode.",
                        severity=Severity.HIGH,
                        platform="kubernetes",
                        location=str(manifest),
                        recommendation="Avoid running containers in privileged mode "
                        "unless absolutely necessary.",
                    )
                )

            # Check for root user
            if not security_context.get("runAsNonRoot"):
                findings.append(
                    Finding(
                        id="K8S002",
                        title="Container may run as root",
                        description=f"Container '{container.get('name', 'unknown')}' "
                        "does not enforce non-root user execution.",
                        severity=Severity.MEDIUM,
                        platform="kubernetes",
                        location=str(manifest),
                        recommendation="Set runAsNonRoot: true in container's "
                        "securityContext.",
                    )
                )

            # Check resource limits
            if not container.get("resources", {}).get("limits"):
                findings.append(
                    Finding(
                        id="K8S003",
                        title="Missing resource limits",
                        description=f"Container '{container.get('name', 'unknown')}' "
                        "does not have resource limits defined.",
                        severity=Severity.LOW,
                        platform="kubernetes",
                        location=str(manifest),
                        recommendation="Set resource limits to prevent resource "
                        "exhaustion attacks.",
                    )
                )

        # Check host mounts
        volumes = spec.get("volumes", [])
        for volume in volumes:
            if "hostPath" in volume:
                findings.append(
                    Finding(
                        id="K8S004",
                        title="Host path volume mount detected",
                        description=f"Volume '{volume.get('name', 'unknown')}' mounts "
                        "from host filesystem.",
                        severity=Severity.HIGH,
                        platform="kubernetes",
                        location=str(manifest),
                        recommendation="Avoid using hostPath volumes as they can lead "
                        "to container breakout.",
                    )
                )

        return findings

    def _check_deployment_security(
        self, deployment: Dict[str, Any], manifest: Path
    ) -> List[Finding]:
        """Check Deployment security configuration."""
        findings: List[Finding] = []

        spec = deployment.get("spec", {})
        if not spec:
            return findings

        # Check replica count
        if spec.get("replicas", 1) < 2:
            findings.append(
                Finding(
                    id="K8S005",
                    title="Single replica deployment",
                    description="Deployment runs with only one replica, which could "
                    "affect availability.",
                    severity=Severity.LOW,
                    platform="kubernetes",
                    location=str(manifest),
                    recommendation="Consider running multiple replicas for better "
                    "availability.",
                )
            )

        # Check pod security
        template = spec.get("template", {})
        if template:
            findings.extend(self._check_pod_security(template, manifest))

        return findings

    def _check_service_security(
        self, service: Dict[str, Any], manifest: Path
    ) -> List[Finding]:
        """Check Service security configuration."""
        findings: List[Finding] = []

        spec = service.get("spec", {})
        if not spec:
            return findings

        # Check for external services
        if spec.get("type") in ["LoadBalancer", "NodePort"]:
            findings.append(
                Finding(
                    id="K8S006",
                    title="Externally exposed service",
                    description="Service is exposed externally, which increases "
                    "attack surface.",
                    severity=Severity.MEDIUM,
                    platform="kubernetes",
                    location=str(manifest),
                    recommendation="Consider using an ingress controller or internal "
                    "service type if external access is not required.",
                )
            )

        return findings

    def _check_network_policy(
        self, policy: Dict[str, Any], manifest: Path
    ) -> List[Finding]:
        """Check NetworkPolicy configuration."""
        findings: List[Finding] = []

        spec = policy.get("spec", {})
        if not spec:
            return findings

        # Check for overly permissive policies
        ingress = spec.get("ingress", [])
        for rule in ingress:
            if not rule.get("from"):
                findings.append(
                    Finding(
                        id="K8S007",
                        title="Overly permissive NetworkPolicy",
                        description="NetworkPolicy allows ingress from all sources.",
                        severity=Severity.HIGH,
                        platform="kubernetes",
                        location=str(manifest),
                        recommendation="Restrict network access to necessary sources only.",
                    )
                )

        return findings

    def _check_rbac_security(
        self, rbac: Dict[str, Any], manifest: Path
    ) -> List[Finding]:
        """Check RBAC security configuration."""
        findings = []

        rules = rbac.get("rules", [])
        for rule in rules:
            # Check for overly permissive rules
            if "*" in rule.get("resources", []) or "*" in rule.get("verbs", []):
                findings.append(
                    Finding(
                        id="K8S008",
                        title="Overly permissive RBAC rule",
                        description="RBAC rule grants wildcard access to resources "
                        "or actions.",
                        severity=Severity.HIGH,
                        platform="kubernetes",
                        location=str(manifest),
                        recommendation="Follow principle of least privilege and grant "
                        "specific permissions only.",
                    )
                )

        return findings

    def _check_common_security(
        self, resource: Dict[str, Any], manifest: Path
    ) -> List[Finding]:
        """Check common security configurations."""
        findings = []

        # Check for default namespace
        if resource.get("metadata", {}).get("namespace") == "default":
            findings.append(
                Finding(
                    id="K8S009",
                    title="Resource in default namespace",
                    description="Resource is deployed in the default namespace.",
                    severity=Severity.LOW,
                    platform="kubernetes",
                    location=str(manifest),
                    recommendation="Use explicit namespaces to organize and secure "
                    "resources.",
                )
            )

        # Check for latest tag
        if "containers" in str(resource):
            containers = self._extract_containers(resource)
            for container in containers:
                image = container.get("image", "")
                if image and ":latest" in image:
                    findings.append(
                        Finding(
                            id="K8S010",
                            title="Use of :latest tag",
                            description=(
                                f"Container '{container.get('name', 'unknown')}' uses image '{image}' "
                                "with the :latest tag."
                            ),
                            severity=Severity.MEDIUM,
                            platform="kubernetes",
                            location=str(manifest),
                            code_snippet=image,
                            recommendation="Use specific image tags for better version control and security.",
                        )
                    )

        return findings

    async def _apply_policies(
        self, resource: Dict[str, Any], manifest: Path, policies: List[Policy]
    ) -> List[Finding]:
        """Apply custom policies to the resource."""
        findings = []

        for policy in policies:
            if policy.platform != "kubernetes":
                continue

            try:
                result = await policy.evaluate({"resource": resource})
                if asyncio.isfuture(result):
                    result = await result

                if result.get("violations"):
                    findings.extend(
                        self._convert_policy_violations(
                            result["violations"], manifest, policy
                        )
                    )
            except Exception as e:
                logger.error(f"Failed to apply policy {policy.name}: {str(e)}")

        return findings

    def _convert_policy_violations(
        self, violations: List[Dict[str, Any]], manifest: Path, policy: Policy
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
                    platform="kubernetes",
                    location=str(manifest),
                    code_snippet=str(violation.get("code_snippet") or ""),
                    recommendation=violation.get(
                        "recommendation", "Follow policy requirements."
                    ),
                )
            )

        return findings

    @staticmethod
    def _is_kubernetes_manifest(path: Path) -> bool:
        """Check if a file is a Kubernetes manifest.

        Supports multi-document YAML (---) by accepting any document that contains
        `apiVersion` and `kind`.
        """
        if path.suffix not in [".yaml", ".yml"]:
            return False

        try:
            with path.open() as f:
                content = f.read()

            docs = list(yaml.safe_load_all(content))
            for doc in docs:
                if isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc:
                    return True
                if isinstance(doc, list):
                    for item in doc:
                        if (
                            isinstance(item, dict)
                            and "apiVersion" in item
                            and "kind" in item
                        ):
                            return True
            return False
        except Exception:
            return False

    @staticmethod
    def _extract_containers(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract container specifications from a resource."""
        containers = []

        # Handle Pod template in various resources
        spec = resource.get("spec", {})
        if "template" in spec:
            spec = spec["template"].get("spec", {})

        # Get all containers and init containers
        containers.extend(spec.get("containers", []))
        containers.extend(spec.get("initContainers", []))

        return containers
