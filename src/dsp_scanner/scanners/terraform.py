"""
Terraform security scanner module.
Implements security checks for Terraform configurations and state files.
"""

import json
import hcl2
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import re

from dsp_scanner.core.results import Finding, Severity, ScanResult
from dsp_scanner.core.policy import Policy
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class TerraformScanner:
    """
    Scanner for Terraform security checks.
    Analyzes Terraform configurations for security issues and compliance violations.
    """

    def __init__(self):
        """Initialize the Terraform scanner."""
        self.findings = []
        self.files_scanned = 0
        self.lines_scanned = 0
        self.resources_scanned = 0

    async def scan(
        self,
        path: Path,
        policies: Optional[List[Policy]] = None
    ) -> ScanResult:
        """
        Scan Terraform configurations for security issues.

        Args:
            path: Path to scan
            policies: Optional list of custom policies to apply

        Returns:
            ScanResult containing all findings
        """
        logger.info(f"Starting Terraform security scan for {path}")
        
        # Initialize scan result
        scan_result = ScanResult()
        
        try:
            # Find all Terraform files
            tf_files = self._find_terraform_files(path)
            
            # Scan each file
            for tf_file in tf_files:
                findings = await self._scan_terraform_file(tf_file, policies)
                self.findings.extend(findings)
                
            # Check for sensitive files
            findings = self._check_sensitive_files(path)
            self.findings.extend(findings)
                
            # Update scan metrics
            scan_result.metrics["total_files_scanned"] = self.files_scanned
            scan_result.metrics["total_lines_scanned"] = self.lines_scanned
            scan_result.metrics["total_resources_scanned"] = self.resources_scanned
            
            # Add findings to result
            for finding in self.findings:
                scan_result.add_finding(finding)
                
        except Exception as e:
            logger.error(f"Terraform scan failed: {str(e)}")
            raise
            
        return scan_result

    def _find_terraform_files(self, path: Path) -> List[Path]:
        """Find all Terraform files in the given path."""
        tf_files = []
        
        if path.is_file() and self._is_terraform_file(path):
            tf_files.append(path)
        else:
            tf_files.extend(
                f for f in path.rglob("*")
                if self._is_terraform_file(f)
            )
            
        logger.info(f"Found {len(tf_files)} Terraform file(s)")
        return tf_files

    async def _scan_terraform_file(
        self,
        tf_file: Path,
        policies: Optional[List[Policy]] = None
    ) -> List[Finding]:
        """
        Scan a Terraform file for security issues.

        Args:
            tf_file: Path to Terraform file
            policies: Optional list of custom policies to apply

        Returns:
            List of security findings
        """
        findings = []
        self.files_scanned += 1
        
        try:
            with tf_file.open() as f:
                content = f.read()
                self.lines_scanned += len(content.splitlines())
                
                # Parse Terraform configuration
                config = hcl2.loads(content)
                
                # Scan resources
                if "resource" in config:
                    for resource_type, resources in config["resource"].items():
                        self.resources_scanned += len(resources)
                        for resource_name, resource in resources.items():
                            findings.extend(self._check_resource_security(
                                resource_type,
                                resource_name,
                                resource,
                                tf_file
                            ))
                            
                # Check provider configurations
                if "provider" in config:
                    findings.extend(self._check_provider_security(
                        config["provider"],
                        tf_file
                    ))
                    
                # Check variables
                if "variable" in config:
                    findings.extend(self._check_variable_security(
                        config["variable"],
                        tf_file
                    ))
                    
                # Apply custom policies if provided
                if policies:
                    policy_findings = await self._apply_policies(
                        config,
                        tf_file,
                        policies
                    )
                    findings.extend(policy_findings)
                    
        except Exception as e:
            logger.error(f"Failed to scan Terraform file {tf_file}: {str(e)}")
            
        return findings

    def _check_resource_security(
        self,
        resource_type: str,
        resource_name: str,
        resource: Dict[str, Any],
        tf_file: Path
    ) -> List[Finding]:
        """Check security configuration of a Terraform resource."""
        findings = []
        
        # AWS-specific checks
        if resource_type.startswith("aws_"):
            findings.extend(self._check_aws_resource(
                resource_type,
                resource_name,
                resource,
                tf_file
            ))
            
        # Azure-specific checks
        elif resource_type.startswith("azurerm_"):
            findings.extend(self._check_azure_resource(
                resource_type,
                resource_name,
                resource,
                tf_file
            ))
            
        # GCP-specific checks
        elif resource_type.startswith("google_"):
            findings.extend(self._check_gcp_resource(
                resource_type,
                resource_name,
                resource,
                tf_file
            ))
            
        return findings

    def _check_aws_resource(
        self,
        resource_type: str,
        resource_name: str,
        resource: Dict[str, Any],
        tf_file: Path
    ) -> List[Finding]:
        """Check AWS resource security configuration."""
        findings = []
        
        # S3 Bucket checks
        if resource_type == "aws_s3_bucket":
            if not resource.get("versioning", {}).get("enabled", False):
                findings.append(Finding(
                    id="TF001",
                    title="S3 bucket versioning disabled",
                    description=f"S3 bucket '{resource_name}' does not have "
                              "versioning enabled.",
                    severity=Severity.MEDIUM,
                    platform="terraform",
                    location=str(tf_file),
                    recommendation="Enable versioning for data protection and "
                                "recovery capabilities."
                ))
                
            if not resource.get("server_side_encryption_configuration"):
                findings.append(Finding(
                    id="TF002",
                    title="S3 bucket encryption disabled",
                    description=f"S3 bucket '{resource_name}' does not have "
                              "server-side encryption configured.",
                    severity=Severity.HIGH,
                    platform="terraform",
                    location=str(tf_file),
                    recommendation="Enable server-side encryption for data at rest."
                ))
                
        # Security Group checks
        elif resource_type == "aws_security_group":
            ingress_rules = resource.get("ingress", [])
            for rule in ingress_rules:
                if "0.0.0.0/0" in str(rule.get("cidr_blocks", [])):
                    findings.append(Finding(
                        id="TF003",
                        title="Open inbound security group rule",
                        description=f"Security group '{resource_name}' allows "
                                  "inbound access from any source.",
                        severity=Severity.HIGH,
                        platform="terraform",
                        location=str(tf_file),
                        recommendation="Restrict inbound access to specific IP ranges."
                    ))
                    
        return findings

    def _check_azure_resource(
        self,
        resource_type: str,
        resource_name: str,
        resource: Dict[str, Any],
        tf_file: Path
    ) -> List[Finding]:
        """Check Azure resource security configuration."""
        findings = []
        
        # Storage Account checks
        if resource_type == "azurerm_storage_account":
            if not resource.get("enable_https_traffic_only", True):
                findings.append(Finding(
                    id="TF004",
                    title="HTTPS-only traffic disabled",
                    description=f"Storage account '{resource_name}' allows "
                              "non-HTTPS traffic.",
                    severity=Severity.HIGH,
                    platform="terraform",
                    location=str(tf_file),
                    recommendation="Enable HTTPS-only traffic for secure data "
                                "transmission."
                ))
                
        # Network Security Group checks
        elif resource_type == "azurerm_network_security_group":
            rules = resource.get("security_rule", [])
            for rule in rules:
                if (rule.get("source_address_prefix") == "*" and
                    rule.get("access") == "Allow"):
                    findings.append(Finding(
                        id="TF005",
                        title="Open inbound NSG rule",
                        description=f"Network security group '{resource_name}' "
                                  "allows inbound access from any source.",
                        severity=Severity.HIGH,
                        platform="terraform",
                        location=str(tf_file),
                        recommendation="Restrict inbound access to specific IP ranges."
                    ))
                    
        return findings

    def _check_gcp_resource(
        self,
        resource_type: str,
        resource_name: str,
        resource: Dict[str, Any],
        tf_file: Path
    ) -> List[Finding]:
        """Check GCP resource security configuration."""
        findings = []
        
        # Cloud Storage Bucket checks
        if resource_type == "google_storage_bucket":
            if not resource.get("uniform_bucket_level_access"):
                findings.append(Finding(
                    id="TF006",
                    title="Uniform bucket-level access disabled",
                    description=f"Storage bucket '{resource_name}' does not have "
                              "uniform bucket-level access enabled.",
                    severity=Severity.MEDIUM,
                    platform="terraform",
                    location=str(tf_file),
                    recommendation="Enable uniform bucket-level access for "
                                "consistent permissions."
                ))
                
        # Firewall Rule checks
        elif resource_type == "google_compute_firewall":
            if "0.0.0.0/0" in str(resource.get("source_ranges", [])):
                findings.append(Finding(
                    id="TF007",
                    title="Open inbound firewall rule",
                    description=f"Firewall rule '{resource_name}' allows inbound "
                              "access from any source.",
                    severity=Severity.HIGH,
                    platform="terraform",
                    location=str(tf_file),
                    recommendation="Restrict inbound access to specific IP ranges."
                ))
                
        return findings

    def _check_provider_security(
        self,
        providers: Dict[str, Any],
        tf_file: Path
    ) -> List[Finding]:
        """Check provider security configuration."""
        findings = []
        
        for provider_name, config in providers.items():
            # Check for hardcoded credentials
            sensitive_keys = ["access_key", "secret_key", "password", "token"]
            for key in sensitive_keys:
                if key in str(config):
                    findings.append(Finding(
                        id="TF008",
                        title="Hardcoded credentials in provider",
                        description=f"Provider '{provider_name}' contains "
                                  f"hardcoded {key}.",
                        severity=Severity.CRITICAL,
                        platform="terraform",
                        location=str(tf_file),
                        recommendation="Use environment variables or secure "
                                    "secret management solutions."
                    ))
                    
        return findings

    def _check_variable_security(
        self,
        variables: Dict[str, Any],
        tf_file: Path
    ) -> List[Finding]:
        """Check variable security configuration."""
        findings = []
        
        for var_name, config in variables.items():
            # Check for sensitive variables without proper protection
            if config.get("sensitive", False) and "default" in config:
                findings.append(Finding(
                    id="TF009",
                    title="Sensitive variable with default value",
                    description=f"Variable '{var_name}' is marked as sensitive "
                              "but contains a default value.",
                    severity=Severity.HIGH,
                    platform="terraform",
                    location=str(tf_file),
                    recommendation="Remove default values for sensitive variables."
                ))
                
        return findings

    def _check_sensitive_files(self, path: Path) -> List[Finding]:
        """Check for sensitive Terraform files."""
        findings = []
        
        sensitive_files = [
            ".terraform",
            "terraform.tfstate",
            "terraform.tfstate.backup",
            ".terraformrc",
            "terraform.rc"
        ]
        
        for sensitive_file in sensitive_files:
            file_path = path / sensitive_file
            if file_path.exists():
                findings.append(Finding(
                    id="TF010",
                    title="Sensitive Terraform file detected",
                    description=f"Sensitive file '{sensitive_file}' found in "
                              "version control.",
                    severity=Severity.CRITICAL,
                    platform="terraform",
                    location=str(file_path),
                    recommendation="Add sensitive files to .gitignore and remove "
                                "from version control."
                ))
                
        return findings

    async def _apply_policies(
        self,
        config: Dict[str, Any],
        tf_file: Path,
        policies: List[Policy]
    ) -> List[Finding]:
        """Apply custom policies to the configuration."""
        findings = []
        
        for policy in policies:
            if policy.platform != "terraform":
                continue
                
            try:
                result = await policy.evaluate({"config": config})
                if result.get("violations"):
                    findings.extend(self._convert_policy_violations(
                        result["violations"],
                        tf_file,
                        policy
                    ))
            except Exception as e:
                logger.error(f"Failed to apply policy {policy.name}: {str(e)}")
                
        return findings

    def _convert_policy_violations(
        self,
        violations: List[Dict[str, Any]],
        tf_file: Path,
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
                platform="terraform",
                location=str(tf_file),
                code_snippet=violation.get("code_snippet"),
                recommendation=violation.get("recommendation", "Follow policy requirements.")
            ))
            
        return findings

    @staticmethod
    def _is_terraform_file(path: Path) -> bool:
        """Check if a file is a Terraform configuration file."""
        return path.is_file() and path.suffix == ".tf"
