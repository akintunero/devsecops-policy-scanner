"""
Logging utility for DSP Scanner.
Provides consistent logging functionality across the application.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import json
from logging.handlers import RotatingFileHandler

class CustomFormatter(logging.Formatter):
    """
    Custom formatter with color support and structured logging.
    """

    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[41m',  # Red background
        'RESET': '\033[0m'      # Reset
    }

    def __init__(self, include_timestamp: bool = True):
        """
        Initialize the formatter.
        
        Args:
            include_timestamp: Whether to include timestamp in log messages
        """
        fmt = '%(levelname)s - %(message)s'
        if include_timestamp:
            fmt = '%(asctime)s - ' + fmt
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
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"

        # Structure the message if it's a dict or list
        if isinstance(record.msg, (dict, list)):
            record.msg = json.dumps(record.msg, indent=2)

        # Format the record
        formatted = super().format(record)

        # Restore original values
        record.levelname = orig_levelname
        record.msg = orig_msg

        return formatted

class SecurityLogger(logging.Logger):
    """
    Custom logger with security-focused features.
    """

    def __init__(self, name: str):
        """
        Initialize the security logger.
        
        Args:
            name: Logger name
        """
        super().__init__(name)
        self.scanning_context = {}

    def set_scanning_context(self, context: dict) -> None:
        """
        Set the current scanning context.
        
        Args:
            context: Scanning context information
        """
        self.scanning_context = context

    def _log_with_context(
        self,
        level: int,
        msg: str,
        *args,
        **kwargs
    ) -> None:
        """
        Log a message with the current scanning context.
        
        Args:
            level: Log level
            msg: Log message
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        if self.scanning_context:
            if isinstance(msg, (dict, list)):
                if isinstance(msg, dict):
                    msg = {**msg, "context": self.scanning_context}
                else:
                    msg = {"message": msg, "context": self.scanning_context}
            else:
                msg = f"{msg} [Context: {json.dumps(self.scanning_context)}]"
        super().log(level, msg, *args, **kwargs)

    def security_alert(
        self,
        msg: str,
        severity: str = "high",
        *args,
        **kwargs
    ) -> None:
        """
        Log a security alert.
        
        Args:
            msg: Alert message
            severity: Alert severity
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        alert = {
            "type": "SECURITY_ALERT",
            "severity": severity,
            "message": msg,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._log_with_context(logging.CRITICAL, alert, *args, **kwargs)

def setup_logging(
    log_file: Optional[str] = None,
    log_level: int = logging.INFO,
    max_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
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
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(CustomFormatter(include_timestamp=True))
        root_logger.addHandler(file_handler)

def get_logger(name: str) -> SecurityLogger:
    """
    Get a logger instance with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        SecurityLogger instance
    """
    return logging.getLogger(name)

# Set up default logging configuration
setup_logging()

# Example usage:
# logger = get_logger(__name__)
# logger.info("Starting scan...")
# logger.security_alert("Potential security breach detected!", severity="critical")
