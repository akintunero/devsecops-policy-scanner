"""
Basic tests to verify imports and core functionality.
"""

import pytest

def test_imports():
    """Test that all core modules can be imported."""
    try:
        from dsp_scanner.core.scanner import Scanner
        from dsp_scanner.core.results import ScanResult, Finding, Severity
        from dsp_scanner.core.policy import Policy
        from dsp_scanner.cli import app
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")

def test_scanner_creation():
    """Test that Scanner can be instantiated."""
    try:
        from dsp_scanner.core.scanner import Scanner
        scanner = Scanner()
        assert scanner is not None
    except Exception as e:
        pytest.fail(f"Scanner creation failed: {e}")

def test_scan_result_creation():
    """Test that ScanResult can be created."""
    try:
        from dsp_scanner.core.results import ScanResult
        result = ScanResult()
        assert result is not None
        assert hasattr(result, 'findings')
        assert hasattr(result, 'timestamp')
    except Exception as e:
        pytest.fail(f"ScanResult creation failed: {e}")

def test_finding_creation():
    """Test that Finding can be created."""
    try:
        from dsp_scanner.core.results import Finding, Severity
        finding = Finding(
            id="TEST001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            platform="docker",
            location="Dockerfile:1"
        )
        assert finding is not None
        assert finding.id == "TEST001"
        assert finding.severity == Severity.HIGH
    except Exception as e:
        pytest.fail(f"Finding creation failed: {e}")

def test_cli_app_exists():
    """Test that CLI app exists."""
    try:
        from dsp_scanner.cli import app
        assert app is not None
    except Exception as e:
        pytest.fail(f"CLI app import failed: {e}") 