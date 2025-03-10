"""
Tests for the Terraform security scanner.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from dsp_scanner.scanners.terraform import TerraformScanner
from dsp_scanner.core.results import Finding, Severity
from dsp_scanner.core.policy import Policy

@pytest.fixture
def scanner():
    """Create a Terraform scanner instance for testing."""
    return TerraformScanner()

@pytest.fixture
def mock_policy():
    """Create a mock policy for testing."""
    policy = Mock(spec=Policy)
    policy.name = "test_policy"
    policy.description = "Test policy"
    policy.platform = "terraform"
    policy.severity = "high"
    return policy

def create_tf_file(tmp_path: Path, content: str) -> Path:
    """Helper to create a test Terraform file."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(content)
    return tf_file

@pytest.mark.asyncio
async def test_scan_basic_aws_config(scanner, tmp_path):
    """Test scanning basic AWS configuration."""
    tf_content = """
    provider "aws" {
        region = "us-west-2"
    }

    resource "aws_s3_bucket" "test" {
        bucket = "my-test-bucket"
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    assert result.findings
    assert any(f.id == "TF001" for f in result.findings)  # Missing versioning
    assert any(f.id == "TF002" for f in result.findings)  # Missing encryption

@pytest.mark.asyncio
async def test_scan_security_group_rules(scanner, tmp_path):
    """Test scanning security group configurations."""
    tf_content = """
    resource "aws_security_group" "test" {
        name = "test-sg"
        
        ingress {
            from_port = 0
            to_port = 65535
            protocol = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
        }
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    assert any(f.id == "TF003" for f in result.findings)  # Open security group

@pytest.mark.asyncio
async def test_scan_azure_storage_account(scanner, tmp_path):
    """Test scanning Azure storage account configuration."""
    tf_content = """
    resource "azurerm_storage_account" "test" {
        name = "teststorage"
        resource_group_name = "test-rg"
        location = "westus2"
        account_tier = "Standard"
        account_replication_type = "LRS"
        enable_https_traffic_only = false
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    assert any(f.id == "TF004" for f in result.findings)  # HTTPS not enforced

@pytest.mark.asyncio
async def test_scan_gcp_storage_bucket(scanner, tmp_path):
    """Test scanning GCP storage bucket configuration."""
    tf_content = """
    resource "google_storage_bucket" "test" {
        name = "test-bucket"
        location = "US"
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    assert any(f.id == "TF006" for f in result.findings)  # Missing uniform access

@pytest.mark.asyncio
async def test_scan_provider_credentials(scanner, tmp_path):
    """Test scanning for hardcoded credentials."""
    tf_content = """
    provider "aws" {
        access_key = "AKIAIOSFODNN7EXAMPLE"
        secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        region = "us-west-2"
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    assert any(f.id == "TF008" for f in result.findings)  # Hardcoded credentials

@pytest.mark.asyncio
async def test_scan_secure_configuration(scanner, tmp_path):
    """Test scanning a secure configuration."""
    tf_content = """
    provider "aws" {
        region = "us-west-2"
    }

    resource "aws_s3_bucket" "secure" {
        bucket = "secure-bucket"
        
        versioning {
            enabled = true
        }
        
        server_side_encryption_configuration {
            rule {
                apply_server_side_encryption_by_default {
                    sse_algorithm = "AES256"
                }
            }
        }
        
        logging {
            target_bucket = aws_s3_bucket.log_bucket.id
            target_prefix = "log/"
        }
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    # Should have minimal or no findings
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)
    assert not any(f.severity == Severity.HIGH for f in result.findings)

@pytest.mark.asyncio
async def test_scan_with_custom_policy(scanner, tmp_path, mock_policy):
    """Test scanning with a custom policy."""
    tf_content = """
    resource "aws_instance" "test" {
        ami = "ami-12345678"
        instance_type = "t2.micro"
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    
    # Setup mock policy evaluation
    mock_policy.evaluate.return_value = {
        "violations": [{
            "title": "Custom Policy Violation",
            "description": "Test violation",
            "severity": "high"
        }]
    }
    
    result = await scanner.scan(tf_file, policies=[mock_policy])
    
    assert any(f.id.startswith("POLICY_") for f in result.findings)
    mock_policy.evaluate.assert_called_once()

@pytest.mark.asyncio
async def test_scan_sensitive_variables(scanner, tmp_path):
    """Test scanning sensitive variables."""
    tf_content = """
    variable "password" {
        type = string
        sensitive = true
        default = "supersecret"
    }

    variable "api_key" {
        type = string
        sensitive = true
        default = "1234567890"
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    assert any(f.id == "TF009" for f in result.findings)  # Sensitive with default

@pytest.mark.asyncio
async def test_scan_sensitive_files(scanner, tmp_path):
    """Test scanning for sensitive Terraform files."""
    # Create sensitive files
    (tmp_path / ".terraform").mkdir()
    (tmp_path / "terraform.tfstate").touch()
    (tmp_path / "terraform.tfvars").write_text('password = "secret"')
    
    result = await scanner.scan(tmp_path)
    
    assert any(f.id == "TF010" for f in result.findings)  # Sensitive files

@pytest.mark.asyncio
async def test_scan_multiple_files(scanner, tmp_path):
    """Test scanning multiple Terraform files."""
    # Create main configuration
    main_tf = """
    provider "aws" {
        region = "us-west-2"
    }
    """
    create_tf_file(tmp_path, main_tf)
    
    # Create variables file
    vars_tf = """
    variable "environment" {
        default = "dev"
    }
    """
    (tmp_path / "variables.tf").write_text(vars_tf)
    
    # Create resources file
    resources_tf = """
    resource "aws_s3_bucket" "test" {
        bucket = "test-bucket"
    }
    """
    (tmp_path / "resources.tf").write_text(resources_tf)
    
    result = await scanner.scan(tmp_path)
    
    assert result.metrics["total_files_scanned"] == 3
    assert result.metrics["total_resources_scanned"] > 0

@pytest.mark.asyncio
async def test_error_handling(scanner):
    """Test scanner error handling."""
    with pytest.raises(FileNotFoundError):
        await scanner.scan(Path("/nonexistent/main.tf"))

def test_is_terraform_file():
    """Test Terraform file detection."""
    assert TerraformScanner._is_terraform_file(Path("main.tf"))
    assert TerraformScanner._is_terraform_file(Path("variables.tf"))
    assert not TerraformScanner._is_terraform_file(Path("main.txt"))

@pytest.mark.asyncio
async def test_scan_resource_dependencies(scanner, tmp_path):
    """Test scanning resource dependencies."""
    tf_content = """
    resource "aws_security_group" "test" {
        name = "test-sg"
    }

    resource "aws_instance" "test" {
        ami = "ami-12345678"
        instance_type = "t2.micro"
        vpc_security_group_ids = [aws_security_group.test.id]
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    # Verify that the scanner can handle resource dependencies
    assert result.metrics["total_resources_scanned"] == 2

@pytest.mark.asyncio
async def test_scan_module_usage(scanner, tmp_path):
    """Test scanning module usage."""
    tf_content = """
    module "vpc" {
        source = "terraform-aws-modules/vpc/aws"
        version = "2.0.0"
        
        name = "my-vpc"
        cidr = "10.0.0.0/16"
    }
    """
    
    tf_file = create_tf_file(tmp_path, tf_content)
    result = await scanner.scan(tf_file)
    
    # Should check module version pinning
    assert not any("version" in f.description and "latest" in f.description 
                  for f in result.findings)
