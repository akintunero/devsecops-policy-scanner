#!/usr/bin/env python3
"""
Advanced Scanning Engine for DevSecOps Policy Scanner
Multi-platform security scanning with intelligent detection
"""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ScanFinding:
    """Security finding data structure"""

    rule_id: str
    severity: str
    message: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 1.0


class AdvancedScanner:
    """Advanced multi-platform security scanner"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.findings: List[ScanFinding] = []

        # Define security patterns
        self.secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'private_key\s*=\s*["\'][^"\']+["\']',
            r'aws_access_key_id\s*=\s*["\'][^"\']+["\']',
            r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']',
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key pattern
            r"sk_live_[0-9a-zA-Z]{24}",  # Stripe Secret Key
            r"ghp_[0-9a-zA-Z]{36}",  # GitHub Personal Access Token
        ]

        # Define weak crypto patterns
        self.weak_crypto_patterns = [
            r"md5\s*\(",
            r"sha1\s*\(",
            r"des\s*\(",
            r"rc4\s*\(",
            r"base64\s*\.\s*decode",
        ]

        # Define injection patterns
        self.injection_patterns = [
            r"exec\s*\(",
            r"eval\s*\(",
            r"system\s*\(",
            r"subprocess\s*\.\s*call",
            r"os\s*\.\s*system",
        ]

    def scan_directory(
        self, directory: str, platforms: Optional[List[str]] = None
    ) -> List[ScanFinding]:
        """Scan a directory for security issues across multiple platforms"""
        directory_path = Path(directory)

        if not directory_path.exists():
            self.logger.error(f"Directory {directory} does not exist")
            return []

        # Determine platforms to scan
        if platforms is None:
            platforms = self._detect_platforms(directory_path)

        self.logger.info(f"Scanning directory {directory} for platforms: {platforms}")

        # Scan each platform
        for platform in platforms:
            if platform == "kubernetes":
                self._scan_kubernetes(directory_path)
            elif platform == "docker":
                self._scan_docker(directory_path)
            elif platform == "terraform":
                self._scan_terraform(directory_path)
            elif platform == "python":
                self._scan_python(directory_path)
            elif platform == "javascript":
                self._scan_javascript(directory_path)
            elif platform == "general":
                self._scan_general_security(directory_path)

        return self.findings

    def _detect_platforms(self, directory: Path) -> List[str]:
        """Detect which platforms are present in the directory"""
        platforms = []

        # Check for Kubernetes manifests
        if list(directory.rglob("*.yaml")) or list(directory.rglob("*.yml")):
            yaml_files = list(directory.rglob("*.yaml")) + list(
                directory.rglob("*.yml")
            )
            for yaml_file in yaml_files[:5]:  # Check first 5 files
                try:
                    with open(yaml_file, "r") as f:
                        content = yaml.safe_load(f)
                        if isinstance(content, dict) and content.get("apiVersion"):
                            platforms.append("kubernetes")
                            break
                except Exception:
                    continue

        # Check for Docker files
        if (directory / "Dockerfile").exists() or (
            directory / "docker-compose.yml"
        ).exists():
            platforms.append("docker")

        # Check for Terraform files
        if list(directory.rglob("*.tf")):
            platforms.append("terraform")

        # Check for Python files
        if list(directory.rglob("*.py")):
            platforms.append("python")

        # Check for JavaScript/Node.js files
        if (directory / "package.json").exists() or list(directory.rglob("*.js")):
            platforms.append("javascript")

        # Always include general security scanning
        platforms.append("general")

        return list(set(platforms))

    def _scan_kubernetes(self, directory: Path):
        """Scan Kubernetes manifests for security issues"""
        self.logger.info("Scanning Kubernetes manifests...")

        yaml_files = list(directory.rglob("*.yaml")) + list(directory.rglob("*.yml"))

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, "r") as f:
                    content = yaml.safe_load(f)

                if not isinstance(content, dict) or not content.get("apiVersion"):
                    continue

                # Check for privileged containers
                if content.get("kind") == "Pod":
                    containers = content.get("spec", {}).get("containers", [])
                    for container in containers:
                        if container.get("securityContext", {}).get("privileged"):
                            self.findings.append(
                                ScanFinding(
                                    rule_id="K8S-001",
                                    severity="critical",
                                    message="Privileged container detected",
                                    file_path=str(yaml_file),
                                    remediation="Remove privileged: true from securityContext",
                                )
                            )

                # Check for secrets in plain text
                if content.get("kind") == "Secret":
                    data = content.get("data", {})
                    for key, value in data.items():
                        if not value:  # Empty or None value
                            self.findings.append(
                                ScanFinding(
                                    rule_id="K8S-002",
                                    severity="high",
                                    message=f"Secret '{key}' has empty value",
                                    file_path=str(yaml_file),
                                    remediation="Ensure all secrets have proper values",
                                )
                            )

                # Check for missing resource limits
                if content.get("kind") in ["Pod", "Deployment", "StatefulSet"]:
                    containers = (
                        content.get("spec", {})
                        .get("template", {})
                        .get("spec", {})
                        .get("containers", [])
                    )
                    for container in containers:
                        if not container.get("resources", {}).get("limits"):
                            self.findings.append(
                                ScanFinding(
                                    rule_id="K8S-003",
                                    severity="medium",
                                    message=f"Container '{container.get('name', 'unknown')}' missing resource limits",
                                    file_path=str(yaml_file),
                                    remediation="Add resource limits to prevent resource exhaustion",
                                )
                            )

                # Check for host network access
                if content.get("kind") == "Pod":
                    if content.get("spec", {}).get("hostNetwork"):
                        self.findings.append(
                            ScanFinding(
                                rule_id="K8S-004",
                                severity="high",
                                message="Host network access enabled",
                                file_path=str(yaml_file),
                                remediation="Disable hostNetwork to isolate pods",
                            )
                        )

            except Exception as e:
                self.logger.warning(f"Error scanning {yaml_file}: {e}")

    def _scan_docker(self, directory: Path):
        """Scan Docker files for security issues"""
        self.logger.info("Scanning Docker files...")

        dockerfile_path = directory / "Dockerfile"
        if dockerfile_path.exists():
            with open(dockerfile_path, "r") as f:
                content = f.read()

            # Check for root user
            if "USER root" in content or "USER 0" in content:
                self.findings.append(
                    ScanFinding(
                        rule_id="DOCKER-001",
                        severity="high",
                        message="Container running as root user",
                        file_path=str(dockerfile_path),
                        remediation="Use non-root user for better security",
                    )
                )

            # Check for latest tag
            if "FROM" in content and ":latest" in content:
                self.findings.append(
                    ScanFinding(
                        rule_id="DOCKER-002",
                        severity="medium",
                        message="Using 'latest' tag in base image",
                        file_path=str(dockerfile_path),
                        remediation="Use specific version tags for reproducibility",
                    )
                )

            # Check for secrets in build context
            for pattern in self.secret_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    self.findings.append(
                        ScanFinding(
                            rule_id="DOCKER-003",
                            severity="critical",
                            message="Potential secret found in Dockerfile",
                            file_path=str(dockerfile_path),
                            line_number=self._get_line_number(content, match.start()),
                            code_snippet=match.group(),
                            remediation="Use build secrets or environment variables instead",
                        )
                    )

    def _scan_terraform(self, directory: Path):
        """Scan Terraform files for security issues"""
        self.logger.info("Scanning Terraform files...")

        tf_files = list(directory.rglob("*.tf"))

        for tf_file in tf_files:
            try:
                with open(tf_file, "r") as f:
                    content = f.read()

                # Check for hardcoded secrets
                for pattern in self.secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self.findings.append(
                            ScanFinding(
                                rule_id="TF-001",
                                severity="critical",
                                message="Hardcoded secret found in Terraform",
                                file_path=str(tf_file),
                                line_number=self._get_line_number(
                                    content, match.start()
                                ),
                                code_snippet=match.group(),
                                remediation="Use Terraform variables or secrets management",
                            )
                        )

                # Check for public access
                if 'cidr_blocks = ["0.0.0.0/0"]' in content:
                    self.findings.append(
                        ScanFinding(
                            rule_id="TF-002",
                            severity="high",
                            message="Public access (0.0.0.0/0) detected",
                            file_path=str(tf_file),
                            remediation="Restrict access to specific IP ranges",
                        )
                    )

            except Exception as e:
                self.logger.warning(f"Error scanning {tf_file}: {e}")

    def _scan_python(self, directory: Path):
        """Scan Python files for security issues"""
        self.logger.info("Scanning Python files...")

        py_files = list(directory.rglob("*.py"))

        for py_file in py_files:
            try:
                with open(py_file, "r") as f:
                    content = f.read()

                # Check for weak crypto
                for pattern in self.weak_crypto_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self.findings.append(
                            ScanFinding(
                                rule_id="PYTHON-001",
                                severity="high",
                                message="Weak cryptographic algorithm detected",
                                file_path=str(py_file),
                                line_number=self._get_line_number(
                                    content, match.start()
                                ),
                                code_snippet=match.group(),
                                remediation="Use strong cryptographic algorithms (AES, SHA-256, etc.)",
                            )
                        )

                # Check for injection vulnerabilities
                for pattern in self.injection_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self.findings.append(
                            ScanFinding(
                                rule_id="PYTHON-002",
                                severity="critical",
                                message="Potential code injection vulnerability",
                                file_path=str(py_file),
                                line_number=self._get_line_number(
                                    content, match.start()
                                ),
                                code_snippet=match.group(),
                                remediation="Avoid using exec/eval with user input",
                            )
                        )

                # Check for hardcoded secrets
                for pattern in self.secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self.findings.append(
                            ScanFinding(
                                rule_id="PYTHON-003",
                                severity="critical",
                                message="Hardcoded secret found in Python code",
                                file_path=str(py_file),
                                line_number=self._get_line_number(
                                    content, match.start()
                                ),
                                code_snippet=match.group(),
                                remediation="Use environment variables or secrets management",
                            )
                        )

            except Exception as e:
                self.logger.warning(f"Error scanning {py_file}: {e}")

    def _scan_javascript(self, directory: Path):
        """Scan JavaScript files for security issues"""
        self.logger.info("Scanning JavaScript files...")

        js_files = list(directory.rglob("*.js")) + list(directory.rglob("*.ts"))

        for js_file in js_files:
            try:
                with open(js_file, "r") as f:
                    content = f.read()

                # Check for eval usage
                if "eval(" in content:
                    self.findings.append(
                        ScanFinding(
                            rule_id="JS-001",
                            severity="critical",
                            message="eval() function usage detected",
                            file_path=str(js_file),
                            remediation="Avoid using eval() for security reasons",
                        )
                    )

                # Check for innerHTML usage
                if ".innerHTML" in content:
                    self.findings.append(
                        ScanFinding(
                            rule_id="JS-002",
                            severity="high",
                            message="innerHTML usage detected (potential XSS)",
                            file_path=str(js_file),
                            remediation="Use textContent or proper sanitization",
                        )
                    )

                # Check for hardcoded secrets
                for pattern in self.secret_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self.findings.append(
                            ScanFinding(
                                rule_id="JS-003",
                                severity="critical",
                                message="Hardcoded secret found in JavaScript",
                                file_path=str(js_file),
                                line_number=self._get_line_number(
                                    content, match.start()
                                ),
                                code_snippet=match.group(),
                                remediation="Use environment variables or secure configuration",
                            )
                        )

            except Exception as e:
                self.logger.warning(f"Error scanning {js_file}: {e}")

    def _scan_general_security(self, directory: Path):
        """Scan for general security issues"""
        self.logger.info("Scanning for general security issues...")

        # Scan all text files for secrets
        text_extensions = [
            ".txt",
            ".md",
            ".json",
            ".yaml",
            ".yml",
            ".env",
            ".conf",
            ".cfg",
        ]

        for ext in text_extensions:
            files = list(directory.rglob(f"*{ext}"))
            for file_path in files:
                try:
                    with open(file_path, "r") as f:
                        content = f.read()

                    # Check for secrets
                    for pattern in self.secret_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            self.findings.append(
                                ScanFinding(
                                    rule_id="GEN-001",
                                    severity="critical",
                                    message="Potential secret found in file",
                                    file_path=str(file_path),
                                    line_number=self._get_line_number(
                                        content, match.start()
                                    ),
                                    code_snippet=match.group(),
                                    remediation="Remove secrets from version control",
                                )
                            )

                except Exception as e:
                    self.logger.warning(f"Error scanning {file_path}: {e}")

    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number from character position"""
        return content[:position].count("\n") + 1

    def get_findings_summary(self) -> Dict[str, Any]:
        """Get summary of findings"""
        total_findings = len(self.findings)
        severity_counts = {}

        for finding in self.findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_findings": total_findings,
            "severity_distribution": severity_counts,
            "platforms_scanned": list(
                set(finding.rule_id.split("-")[0] for finding in self.findings)
            ),
        }

    def export_findings(
        self, format: str = "json", output_file: Optional[str] = None
    ) -> str:
        """Export findings to different formats"""
        if format.lower() == "json":
            data = []
            for finding in self.findings:
                data.append(
                    {
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "message": finding.message,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "code_snippet": finding.code_snippet,
                        "remediation": finding.remediation,
                        "confidence": finding.confidence,
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
    """Example usage of the advanced scanner"""
    scanner = AdvancedScanner()

    # Example: scan current directory
    findings = scanner.scan_directory(".")

    # Print summary
    summary = scanner.get_findings_summary()
    print("Scan Summary:")
    print(json.dumps(summary, indent=2))

    # Print findings
    print(f"\nFound {len(findings)} security issues:")
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.rule_id}: {finding.message}")
        if finding.file_path:
            print(f"  File: {finding.file_path}")
        if finding.remediation:
            print(f"  Fix: {finding.remediation}")
        print()


if __name__ == "__main__":
    main()
