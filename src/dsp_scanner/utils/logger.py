"""
Logging utility for DSP Scanner.
Provides consistent logging functionality across the application.
"""

import json
import logging
import re
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, cast


class CustomFormatter(logging.Formatter):
    """
    Custom formatter with color support and structured logging.
    """

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[41m",  # Red background
        "RESET": "\033[0m",  # Reset
    }

    def __init__(self, include_timestamp: bool = True):
        """
        Initialize the formatter.

        Args:
            include_timestamp: Whether to include timestamp in log messages
        """
        fmt = "%(levelname)s - %(message)s"
        if include_timestamp:
            fmt = "%(asctime)s - " + fmt
        super().__init__(fmt)

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with colors and structure.

        Args:
            record: Log record to format

        Returns:
            Formatted log message
        """
        # Save original values
        orig_levelname = record.levelname
        orig_msg = record.msg

        # Apply color to level name
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"

        # Structure the message if it's a dict or list
        if isinstance(record.msg, (dict, list)):

            def mask(obj):
                if isinstance(obj, dict):
                    masked = {}
                    for k, v in obj.items():
                        if isinstance(k, str) and re.search(
                            r"(?i)(password|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key)$",
                            k,
                        ):
                            masked[k] = "******"
                        else:
                            masked[k] = mask(v)
                    return masked
                if isinstance(obj, list):
                    return [mask(x) for x in obj]
                return obj

            record.msg = json.dumps(mask(record.msg), indent=2)

        # Format the record
        formatted = super().format(record)

        # Restore original values
        record.levelname = orig_levelname
        record.msg = orig_msg

        return formatted


class SecurityLogger(logging.Logger):
    """Custom logger with security-focused features."""

    def __init__(self, name: str):
        super().__init__(name)
        self.scanning_context: dict = {}

    def set_scanning_context(self, context: dict) -> None:
        """Set the current scanning context."""
        self.scanning_context = context

    def _augment_with_context(self, msg):
        if not self.scanning_context:
            return msg

        # Prefer structured context when possible.
        if isinstance(msg, dict):
            return {**msg, "context": self.scanning_context}
        if isinstance(msg, list):
            return {"message": msg, "context": self.scanning_context}

        # Fall back to text.
        return f"{msg} [Context: {json.dumps(self.scanning_context)}]"

    # logging.Logger.info/debug/etc call self._log(), so overriding _log ensures
    # context is attached consistently.
    def _log(self, level, msg, args, **kwargs):  # type: ignore[override]
        msg = self._augment_with_context(msg)
        return super()._log(level, msg, args, **kwargs)

    def security_alert(self, msg: str, severity: str = "high", *args, **kwargs) -> None:
        alert = {
            "type": "SECURITY_ALERT",
            "severity": severity,
            "message": msg,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.critical(alert, *args, **kwargs)


def setup_logging(
    log_file: Optional[str] = None,
    log_level: int = logging.INFO,
    max_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> None:
    """
    Set up application-wide logging configuration.

    Args:
        log_file: Path to log file (optional)
        log_level: Logging level
        max_size: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
    """
    # Register custom logger class
    logging.setLoggerClass(SecurityLogger)

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler with color formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(CustomFormatter())
    root_logger.addHandler(console_handler)

    # File handler if log file specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count
        )
        file_handler.setFormatter(CustomFormatter(include_timestamp=True))
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> SecurityLogger:
    """Get a logger instance with the specified name."""
    # setup_logging() registers SecurityLogger as the logger class.
    return cast(SecurityLogger, logging.getLogger(name))


# Set up default logging configuration
setup_logging()

# Example usage:
# logger = get_logger(__name__)
# logger.info("Starting scan...")
# logger.security_alert("Potential security breach detected!", severity="critical")
