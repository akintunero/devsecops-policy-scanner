"""
Tests for the command-line interface.
"""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from unittest.mock import Mock, patch
import json
import yaml

from dsp_scanner.cli import app
from dsp_scanner.core.results import Finding, Severity, ScanResult

runner = CliRunner()

@pytest.fixture
def mock_scanner():
    """Create a mock scanner for testing."""
    scanner = Mock()
    scanner.scan_path.return_value = ScanResult()
    return scanner

@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            id="TEST001",
            title="Security Issue",
            description="Test security issue",
            severity=Severity.HIGH,
            platform="docker",
            location="Dockerfile:1",
            code_snippet="FROM python:latest",
            recommendation="Use specific version"
        ),
        Finding(
            id="TEST002",
            title="Compliance Issue",
            description="Test compliance issue",
            severity=Severity.MEDIUM,
            platform="kubernetes",
            location="deployment.yaml:1",
            code_snippet="privileged: true",
            recommendation="Avoid privileged containers"
        )
    ]

def test_version():
    """Test version command."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "DSP Scanner version" in result.stdout

def test_help():
    """Test help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    assert "Options:" in result.stdout

@pytest.mark.asyncio
async def test_basic_scan(tmp_path, mock_scanner):
    """Test basic scan command."""
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.9")
    
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, ["scan", str(dockerfile)])
        
    assert result.exit_code == 0
    mock_scanner.scan_path.assert_called_once_with(str(dockerfile))

@pytest.mark.asyncio
async def test_scan_with_platform_filter(tmp_path, mock_scanner):
    """Test scan with platform filter."""
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--platform", "docker",
            "--platform", "kubernetes"
        ])
        
    assert result.exit_code == 0
    args, kwargs = mock_scanner.scan_path.call_args
    assert "docker" in kwargs.get("platforms", [])
    assert "kubernetes" in kwargs.get("platforms", [])

@pytest.mark.asyncio
async def test_scan_with_compliance_frameworks(tmp_path, mock_scanner):
    """Test scan with compliance frameworks."""
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--compliance", "cis",
            "--compliance", "nist"
        ])
        
    assert result.exit_code == 0
    scanner_instance = mock_scanner
    assert "cis" in scanner_instance.compliance_frameworks
    assert "nist" in scanner_instance.compliance_frameworks

@pytest.mark.asyncio
async def test_scan_with_severity_threshold(tmp_path, mock_scanner):
    """Test scan with severity threshold."""
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--severity", "high"
        ])
        
    assert result.exit_code == 0
    scanner_instance = mock_scanner
    assert scanner_instance.severity_threshold == "high"

@pytest.mark.asyncio
async def test_scan_output_formats(tmp_path, mock_scanner, sample_findings):
    """Test different output formats."""
    # Setup mock scanner with sample findings
    mock_result = ScanResult()
    for finding in sample_findings:
        mock_result.add_finding(finding)
    mock_scanner.scan_path.return_value = mock_result
    
    # Test JSON output
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--format", "json"
        ])
        
    assert result.exit_code == 0
    try:
        json_output = json.loads(result.stdout)
        assert "findings" in json_output
        assert len(json_output["findings"]) == len(sample_findings)
    except json.JSONDecodeError:
        pytest.fail("Invalid JSON output")

@pytest.mark.asyncio
async def test_scan_with_output_file(tmp_path, mock_scanner, sample_findings):
    """Test saving scan results to file."""
    output_file = tmp_path / "report.json"
    
    # Setup mock scanner with sample findings
    mock_result = ScanResult()
    for finding in sample_findings:
        mock_result.add_finding(finding)
    mock_scanner.scan_path.return_value = mock_result
    
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--output", str(output_file),
            "--format", "json"
        ])
        
    assert result.exit_code == 0
    assert output_file.exists()
    
    # Verify file content
    content = json.loads(output_file.read_text())
    assert len(content["findings"]) == len(sample_findings)

def test_validate_policy_command(tmp_path):
    """Test policy validation command."""
    # Create test policy file
    policy_file = tmp_path / "test_policy.rego"
    policy_file.write_text("""
    package dsp_scanner
    
    deny[msg] {
        input.kind == "Deployment"
        msg = "Test policy"
    }
    """)
    
    result = runner.invoke(app, ["validate", str(policy_file)])
    assert result.exit_code == 0
    assert "Policy validation successful" in result.stdout

def test_validate_invalid_policy(tmp_path):
    """Test validation of invalid policy."""
    # Create invalid policy file
    policy_file = tmp_path / "invalid_policy.rego"
    policy_file.write_text("invalid rego code")
    
    result = runner.invoke(app, ["validate", str(policy_file)])
    assert result.exit_code == 1
    assert "Policy validation failed" in result.stdout

def test_init_command(tmp_path):
    """Test initialization command."""
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    
    config_file = tmp_path / ".dsp-scanner.yml"
    assert config_file.exists()
    
    # Verify config content
    config = yaml.safe_load(config_file.read_text())
    assert "scan" in config
    assert "platforms" in config["scan"]
    assert "compliance" in config["scan"]

def test_init_existing_config(tmp_path):
    """Test initialization with existing config."""
    config_file = tmp_path / ".dsp-scanner.yml"
    config_file.write_text("existing: true")
    
    # Test with 'no' to overwrite
    result = runner.invoke(app, ["init", str(tmp_path)], input="n\n")
    assert result.exit_code == 0
    assert yaml.safe_load(config_file.read_text()) == {"existing": True}
    
    # Test with 'yes' to overwrite
    result = runner.invoke(app, ["init", str(tmp_path)], input="y\n")
    assert result.exit_code == 0
    config = yaml.safe_load(config_file.read_text())
    assert "scan" in config

@pytest.mark.asyncio
async def test_scan_with_ai_analysis(tmp_path, mock_scanner):
    """Test scan with AI analysis."""
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--ai"
        ])
        
    assert result.exit_code == 0
    scanner_instance = mock_scanner
    assert scanner_instance.enable_ai is True

@pytest.mark.asyncio
async def test_scan_without_ai_analysis(tmp_path, mock_scanner):
    """Test scan without AI analysis."""
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--no-ai"
        ])
        
    assert result.exit_code == 0
    scanner_instance = mock_scanner
    assert scanner_instance.enable_ai is False

def test_verbose_output(tmp_path, mock_scanner):
    """Test verbose output mode."""
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, [
            "scan",
            str(tmp_path),
            "--verbose"
        ])
        
    assert result.exit_code == 0
    # Verbose output should include more detailed information
    assert "Scan Configuration" in result.stdout

def test_error_handling():
    """Test CLI error handling."""
    # Test with non-existent path
    result = runner.invoke(app, ["scan", "/nonexistent/path"])
    assert result.exit_code == 1
    assert "Error" in result.stdout
    
    # Test with invalid severity level
    result = runner.invoke(app, ["scan", ".", "--severity", "invalid"])
    assert result.exit_code == 1
    assert "Invalid value for '--severity'" in result.stdout

def test_scan_display_format(tmp_path, mock_scanner, sample_findings):
    """Test scan result display formatting."""
    # Setup mock scanner with sample findings
    mock_result = ScanResult()
    for finding in sample_findings:
        mock_result.add_finding(finding)
    mock_scanner.scan_path.return_value = mock_result
    
    with patch('dsp_scanner.cli.Scanner', return_value=mock_scanner):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        
    assert result.exit_code == 0
    # Check for rich text formatting
    assert "[red]" in result.stdout  # High severity
    assert "[yellow]" in result.stdout  # Medium severity
    assert "│" in result.stdout  # Table borders
