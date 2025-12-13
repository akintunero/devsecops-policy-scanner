"""
Tests for the logging utility.
"""

import json
import logging
from io import StringIO
from unittest.mock import patch

import pytest

from dsp_scanner.utils.logger import (
    CustomFormatter,
    SecurityLogger,
    get_logger,
    setup_logging,
)


@pytest.fixture
def capture_logs():
    """Capture log output for testing."""
    string_io = StringIO()
    handler = logging.StreamHandler(string_io)
    handler.setFormatter(CustomFormatter())

    logger = get_logger("test")
    logger.handlers = []
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    return logger, string_io


@pytest.fixture
def temp_log_file(tmp_path):
    """Create a temporary log file."""
    return tmp_path / "test.log"


def test_custom_formatter():
    """Test custom log formatter."""
    formatter = CustomFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert "ERROR" in formatted
    assert "Test message" in formatted
    assert "\033[31m" in formatted  # Red color for ERROR


def test_formatter_with_dict_message():
    """Test formatter with dictionary message."""
    formatter = CustomFormatter()
    data = {"key": "value", "nested": {"test": True}}
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg=data,
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert "key" in formatted
    assert "value" in formatted
    assert "nested" in formatted


def test_security_logger():
    """Test security logger functionality."""
    logger = SecurityLogger("test_security")
    logger.setLevel(logging.DEBUG)

    # Capture log output
    log_output = StringIO()
    handler = logging.StreamHandler(log_output)
    handler.setFormatter(CustomFormatter())
    logger.addHandler(handler)

    # Test security alert
    logger.security_alert("Security breach detected", severity="critical")
    output = log_output.getvalue()

    assert "SECURITY_ALERT" in output
    assert "critical" in output.lower()
    assert "Security breach detected" in output


def test_security_logger_context():
    """Test security logger with context."""
    logger = SecurityLogger("test_context")
    logger.setLevel(logging.DEBUG)

    log_output = StringIO()
    handler = logging.StreamHandler(log_output)
    handler.setFormatter(CustomFormatter())
    logger.addHandler(handler)

    # Set context and log
    context = {"scan_id": "test-123", "platform": "docker", "file": "Dockerfile"}
    logger.set_scanning_context(context)
    logger.info("Test message with context")

    output = log_output.getvalue()
    assert "scan_id" in output
    assert "docker" in output
    assert "Dockerfile" in output


def test_setup_logging(temp_log_file):
    """Test logging setup configuration."""
    setup_logging(log_file=str(temp_log_file), log_level=logging.DEBUG)

    logger = get_logger("test_setup")
    logger.info("Test log message")

    # Verify file logging
    assert temp_log_file.exists()
    log_content = temp_log_file.read_text()
    assert "Test log message" in log_content


def test_log_rotation(temp_log_file):
    """Test log file rotation."""
    max_size = 1024  # 1KB
    setup_logging(
        log_file=str(temp_log_file),
        log_level=logging.DEBUG,
        max_size=max_size,
        backup_count=2,
    )

    logger = get_logger("test_rotation")

    # Write enough logs to trigger rotation
    large_message = "x" * (max_size // 2)
    for _ in range(5):
        logger.info(large_message)

    # Check for rotated files
    assert temp_log_file.exists()
    assert (temp_log_file.parent / f"{temp_log_file.name}.1").exists()


def test_logger_severity_colors(capture_logs):
    """Test logger severity level colors."""
    logger, string_io = capture_logs

    # Test different severity levels
    logger.debug("Debug message")
    assert "\033[36m" in string_io.getvalue()  # Cyan

    string_io.seek(0)
    string_io.truncate()

    logger.error("Error message")
    assert "\033[31m" in string_io.getvalue()  # Red


def test_structured_logging(capture_logs):
    """Test structured logging output."""
    logger, string_io = capture_logs

    structured_data = {
        "event": "security_scan",
        "findings": [{"severity": "high", "description": "Test finding"}],
        "metadata": {"scanner": "docker", "timestamp": "2023-01-01T00:00:00Z"},
    }

    logger.info(structured_data)
    output = string_io.getvalue()

    # Verify JSON formatting
    try:
        parsed = json.loads(output[output.find("{") : output.rfind("}") + 1])
        assert parsed["event"] == "security_scan"
        assert len(parsed["findings"]) == 1
        assert parsed["metadata"]["scanner"] == "docker"
    except json.JSONDecodeError:
        pytest.fail("Failed to parse structured log output as JSON")


def test_security_alert_formatting(capture_logs):
    """Test security alert message formatting."""
    logger, string_io = capture_logs

    logger.security_alert("Critical vulnerability detected", severity="critical")
    output = string_io.getvalue()

    assert "CRITICAL" in output
    assert "\033[41m" in output  # Red background for critical
    assert "vulnerability" in output


def test_logger_with_exception(capture_logs):
    """Test logging with exception information."""
    logger, string_io = capture_logs

    try:
        raise ValueError("Test error")
    except ValueError as e:
        logger.error("Error occurred", exc_info=e)

    output = string_io.getvalue()
    assert "ValueError" in output
    assert "Test error" in output
    assert "Traceback" in output


def test_logger_context_inheritance():
    """Test logging context inheritance in threads."""
    logger = SecurityLogger("test_inheritance")
    logger.set_scanning_context({"parent": "context"})

    # Simulate child thread/task
    def child_task():
        logger.info("Child message")

    with patch("threading.current_thread") as mock_thread:
        mock_thread.return_value.name = "ChildThread"
        child_task()
        # Context should be preserved
        assert logger.scanning_context.get("parent") == "context"


def test_sensitive_data_masking(capture_logs):
    """Test masking of sensitive data in logs."""
    logger, string_io = capture_logs

    sensitive_data = {"password": "secret123", "api_key": "abcd1234", "user": "admin"}

    logger.info(sensitive_data)
    output = string_io.getvalue()

    # Sensitive fields should be masked
    assert "secret123" not in output
    assert "abcd1234" not in output
    assert "******" in output
    # Non-sensitive fields should be visible
    assert "admin" in output


def test_concurrent_logging(capture_logs):
    """Test logging from multiple concurrent operations."""
    logger, string_io = capture_logs

    import threading

    threads = []
    for i in range(5):
        thread = threading.Thread(
            target=lambda: logger.info(f"Message from thread {i}")
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    output = string_io.getvalue()
    # Verify all messages were logged
    assert output.count("Message from thread") == 5
    # Verify thread safety
    assert output.count("\n") == 5  # No interleaved messages


def test_log_level_filtering(capture_logs):
    """Test log level filtering."""
    logger, string_io = capture_logs
    logger.setLevel(logging.WARNING)

    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")

    output = string_io.getvalue()
    assert "Debug message" not in output
    assert "Info message" not in output
    assert "Warning message" in output
    assert "Error message" in output
