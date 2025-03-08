"""
Docker security scanner module.
Implements security checks for Dockerfile and container configurations.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from dsp_scanner.core.results import Finding, Severity, ScanResult
from dsp_scanner.core.policy import Policy
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class DockerScanner:
    """
    Scanner for Docker security checks.
    Analyzes Dockerfiles and container configurations for security issues.
    """

    def __init__(self):
        """Initialize the Docker scanner."""
        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0

    async def scan(
        self,
        path: Path,
        policies: Optional[List[Policy]] = None
    ) -> ScanResult:
        """
        Scan Docker files and configurations for security issues.

        Args:
            path: Path to scan
            policies: Optional list of custom policies to apply

        Returns:
            ScanResult containing all findings
        """
        logger.info(f"Starting Docker security scan for {path}")
        
        # Initialize scan result
        scan_result = ScanResult()
        
        try:
            # Find all Dockerfiles
            dockerfiles = self._find_dockerfiles(path)
            
            # Scan each Dockerfile
            for dockerfile in dockerfiles:
                findings = await self._scan_dockerfile(dockerfile, policies)
                self.findings.extend(findings)
                
            # Find and scan compose files
            compose_files = self._find_compose_files(path)
            for compose_file in compose_files:
                findings = await self._scan_compose_file(compose_file, policies)
                self.findings.extend(findings)
                
            # Update scan metrics
            scan_result.metrics["total_files_scanned"] = self.files_scanned
            scan_result.metrics["total_lines_scanned"] = self.lines_scanned
            
            # Add findings to result
            for finding in self.findings:
                scan_result.add_finding(finding)
                
        except Exception as e:
            logger.error(f"Docker scan failed: {str(e)}")
            raise
            
        return scan_result

    def _find_dockerfiles(self, path: Path) -> List[Path]:
        """Find all Dockerfiles in the given path."""
        dockerfiles = []
        
        if path.is_file() and self._is_dockerfile(path):
            dockerfiles.append(path)
        else:
            dockerfiles.extend(
                f for f in path.rglob("*")
                if self._is_dockerfile(f)
            )
            
        logger.info(f"Found {len(dockerfiles)} Dockerfile(s)")
        return dockerfiles

    def _find_compose_files(self, path: Path) -> List[Path]:
        """Find all Docker Compose files in the given path."""
        compose_files = []
        
        if path.is_file() and self._is_compose_file(path):
            compose_files.append(path)
        else:
            compose_files.extend(
                f for f in path.rglob("*")
                if self._is_compose_file(f)
            )
            
        logger.info(f"Found {len(compose_files)} Docker Compose file(s)")
        return compose_files

    async def _scan_dockerfile(
        self,
        dockerfile: Path,
        policies: Optional[List[Policy]] = None
    ) -> List[Finding]:
        """
        Scan a Dockerfile for security issues.

        Args:
            dockerfile: Path to Dockerfile
            policies: Optional list of custom policies to apply

        Returns:
            List of security findings
        """
        findings = []
        self.files_scanned += 1
        
        try:
            content = dockerfile.read_text()
            lines = content.splitlines()
            self.lines_scanned += len(lines)
            
            # Basic security checks
            findings.extend(self._check_base_image(lines, dockerfile))
            findings.extend(self._check_root_user(lines, dockerfile))
            findings.extend(self._check_sensitive_data(lines, dockerfile))
            findings.extend(self._check_package_management(lines, dockerfile))
            findings.extend(self._check_security_options(lines, dockerfile))
            
            # Apply custom policies if provided
            if policies:
                policy_findings = await self._apply_policies(
                    content,
                    dockerfile,
                    policies
                )
                findings.extend(policy_findings)
                
        except Exception as e:
            logger.error(f"Failed to scan Dockerfile {dockerfile}: {str(e)}")
            
        return findings

    async def _scan_compose_file(
        self,
        compose_file: Path,
        policies: Optional[List[Policy]] = None
    ) -> List[Finding]:
        """
        Scan a Docker Compose file for security issues.

        Args:
            compose_file: Path to Docker Compose file
            policies: Optional list of custom policies to apply

        Returns:
            List of security findings
        """
        findings = []
        self.files_scanned += 1
        
        try:
            with compose_file.open() as f:
                compose_config = yaml.safe_load(f)
                
            if not compose_config:
                return findings
                
            # Check services configuration
            if "services" in compose_config:
                for service_name, service_config in compose_config["services"].items():
                    findings.extend(
                        self._check_compose_service(
                            service_name,
                            service_config,
                            compose_file
                        )
                    )
                    
            # Apply custom policies if provided
            if policies:
                policy_findings = await self._apply_policies(
                    compose_config,
                    compose_file,
                    policies
                )
                findings.extend(policy_findings)
                
        except Exception as e:
            logger.error(f"Failed to scan Compose file {compose_file}: {str(e)}")
            
        return findings

    def _check_base_image(
        self,
        lines: List[str],
        dockerfile: Path
    ) -> List[Finding]:
        """Check base image security."""
        findings = []
        
        for i, line in enumerate(lines):
            if line.strip().startswith("FROM"):
                # Check for latest tag
                if ":latest" in line:
                    findings.append(Finding(
                        id="DOCKER001",
                        title="Use of :latest tag",
                        description="Using the :latest tag is not recommended as it "
                                  "makes image version tracking difficult and can lead "
                                  "to unexpected behavior.",
                        severity=Severity.MEDIUM,
                        platform="docker",
                        location=f"{dockerfile}:{i+1}",
                        code_snippet=line,
                        recommendation="Specify an explicit version tag for the base image."
                    ))
                
                # Check for official images
                image_name = line.split()[1].split(":")[0]
                if "/" in image_name and not image_name.startswith(("gcr.io/", "docker.io/")):
                    findings.append(Finding(
                        id="DOCKER002",
                        title="Non-official base image",
                        description="Using non-official base images may introduce "
                                  "security risks.",
                        severity=Severity.LOW,
                        platform="docker",
                        location=f"{dockerfile}:{i+1}",
                        code_snippet=line,
                        recommendation="Consider using official base images from "
                                    "trusted sources."
                    ))
                    
        return findings

    def _check_root_user(
        self,
        lines: List[str],
        dockerfile: Path
    ) -> List[Finding]:
        """Check for root user usage."""
        findings = []
        has_user = False
        
        for i, line in enumerate(lines):
            if line.strip().startswith("USER"):
                has_user = True
                user = line.split()[1]
                if user == "root":
                    findings.append(Finding(
                        id="DOCKER003",
                        title="Container running as root",
                        description="Running containers as root user is a security risk "
                                  "as it gives unnecessary privileges to the container.",
                        severity=Severity.HIGH,
                        platform="docker",
                        location=f"{dockerfile}:{i+1}",
                        code_snippet=line,
                        recommendation="Use a non-root user for running the container."
                    ))
                    
        if not has_user:
            findings.append(Finding(
                id="DOCKER004",
                title="No USER instruction found",
                description="No USER instruction found in Dockerfile. Container may "
                          "run as root by default.",
                severity=Severity.MEDIUM,
                platform="docker",
                location=str(dockerfile),
                recommendation="Add a USER instruction to run the container as a "
                            "non-root user."
            ))
            
        return findings

    def _check_sensitive_data(
        self,
        lines: List[str],
        dockerfile: Path
    ) -> List[Finding]:
        """Check for sensitive data in Dockerfile."""
        findings = []
        sensitive_patterns = [
            (r"(?i)password\s*=\s*[\'\"]?\w+[\'\"]?", "password"),
            (r"(?i)secret\s*=\s*[\'\"]?\w+[\'\"]?", "secret"),
            (r"(?i)key\s*=\s*[\'\"]?\w+[\'\"]?", "key"),
            (r"(?i)token\s*=\s*[\'\"]?\w+[\'\"]?", "token"),
        ]
        
        for i, line in enumerate(lines):
            for pattern, data_type in sensitive_patterns:
                if re.search(pattern, line):
                    findings.append(Finding(
                        id="DOCKER005",
                        title=f"Sensitive {data_type} found in Dockerfile",
                        description=f"Sensitive {data_type} found in Dockerfile. This "
                                  "poses a security risk as the value will be stored "
                                  "in the image history.",
                        severity=Severity.CRITICAL,
                        platform="docker",
                        location=f"{dockerfile}:{i+1}",
                        code_snippet=line,
                        recommendation=f"Use build arguments or environment variables "
                                    f"to handle sensitive {data_type}s."
                    ))
                    
        return findings

    def _check_package_management(
        self,
        lines: List[str],
        dockerfile: Path
    ) -> List[Finding]:
        """Check package management security."""
        findings = []
        update_found = False
        
        for i, line in enumerate(lines):
            if "apt-get install" in line and "apt-get update" not in line:
                if not update_found:
                    findings.append(Finding(
                        id="DOCKER006",
                        title="Missing apt-get update",
                        description="Installing packages without running apt-get update "
                                  "first may lead to installing outdated packages.",
                        severity=Severity.LOW,
                        platform="docker",
                        location=f"{dockerfile}:{i+1}",
                        code_snippet=line,
                        recommendation="Run 'apt-get update' before installing packages."
                    ))
            elif "apt-get update" in line:
                update_found = True
                
            # Check for version pinning
            if "apt-get install" in line:
                packages = line.split("install")[1].strip().split()
                for package in packages:
                    if not re.search(r"=[\d\.]+", package):
                        findings.append(Finding(
                            id="DOCKER007",
                            title="Package version not pinned",
                            description=f"Package {package} version is not pinned, "
                                      "which may lead to inconsistent builds.",
                            severity=Severity.LOW,
                            platform="docker",
                            location=f"{dockerfile}:{i+1}",
                            code_snippet=line,
                            recommendation="Pin package versions explicitly."
                        ))
                        
        return findings

    def _check_security_options(
        self,
        lines: List[str],
        dockerfile: Path
    ) -> List[Finding]:
        """Check for security-related options."""
        findings = []
        
        # Check for HEALTHCHECK
        if not any(line.strip().startswith("HEALTHCHECK") for line in lines):
            findings.append(Finding(
                id="DOCKER008",
                title="Missing HEALTHCHECK instruction",
                description="No HEALTHCHECK instruction found. This makes it harder "
                          "to monitor container health.",
                severity=Severity.LOW,
                platform="docker",
                location=str(dockerfile),
                recommendation="Add a HEALTHCHECK instruction to monitor container health."
            ))
            
        return findings

    def _check_compose_service(
        self,
        service_name: str,
        service_config: Dict[str, Any],
        compose_file: Path
    ) -> List[Finding]:
        """Check security configuration of a Docker Compose service."""
        findings = []
        
        # Check privileged mode
        if service_config.get("privileged", False):
            findings.append(Finding(
                id="DOCKER009",
                title="Service running in privileged mode",
                description=f"Service '{service_name}' is running in privileged mode, "
                          "which gives extended privileges to the container.",
                severity=Severity.HIGH,
                platform="docker",
                location=str(compose_file),
                recommendation="Avoid using privileged mode unless absolutely necessary."
            ))
            
        # Check port bindings
        if "ports" in service_config:
            for port in service_config["ports"]:
                if isinstance(port, str) and ":" in port:
                    host_port = port.split(":")[0]
                    if host_port == "0.0.0.0":
                        findings.append(Finding(
                            id="DOCKER010",
                            title="Service exposed on all interfaces",
                            description=f"Service '{service_name}' is exposed on all "
                                      "network interfaces.",
                            severity=Severity.MEDIUM,
                            platform="docker",
                            location=str(compose_file),
                            recommendation="Limit port exposure to specific interfaces "
                                        "when possible."
                        ))
                        
        return findings

    async def _apply_policies(
        self,
        content: Any,
        file_path: Path,
        policies: List[Policy]
    ) -> List[Finding]:
        """Apply custom policies to the content."""
        findings = []
        
        for policy in policies:
            if policy.platform != "docker":
                continue
                
            try:
                result = await policy.evaluate({"content": content})
                if result.get("violations"):
                    findings.extend(self._convert_policy_violations(
                        result["violations"],
                        file_path,
                        policy
                    ))
            except Exception as e:
                logger.error(f"Failed to apply policy {policy.name}: {str(e)}")
                
        return findings

    def _convert_policy_violations(
        self,
        violations: List[Dict[str, Any]],
        file_path: Path,
        policy: Policy
    ) -> List[Finding]:
        """Convert policy violations to findings."""
        findings = []
        
        for violation in violations:
            findings.append(Finding(
                id=f"POLICY_{policy.name}",
                title=violation.get("title", "Policy Violation"),
                description=violation.get("description", policy.description),
                severity=Severity(violation.get("severity", policy.severity)),
                platform="docker",
                location=str(file_path),
                code_snippet=violation.get("code_snippet"),
                recommendation=violation.get("recommendation", "Follow policy requirements.")
            ))
            
        return findings

    @staticmethod
    def _is_dockerfile(path: Path) -> bool:
        """Check if a file is a Dockerfile."""
        return (
            path.is_file() and
            (path.name == "Dockerfile" or
             path.name.endswith(".dockerfile") or
             path.name.endswith(".Dockerfile"))
        )

    @staticmethod
    def _is_compose_file(path: Path) -> bool:
        """Check if a file is a Docker Compose file."""
        return (
            path.is_file() and
            (path.name in ["docker-compose.yml", "docker-compose.yaml"] or
             path.name.endswith(".docker-compose.yml") or
             path.name.endswith(".docker-compose.yaml"))
        )
