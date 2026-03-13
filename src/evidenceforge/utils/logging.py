"""Logging utilities for EvidenceForge."""

import logging
from pathlib import Path
from typing import Any

from evidenceforge.models.config import LoggingConfig


def setup_logging(config: LoggingConfig) -> None:
    """Configure logging based on LoggingConfig.

    Args:
        config: LoggingConfig instance with level, console_level, file settings
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler (warning+ by default)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, config.console_level.upper()))
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler (if configured)
    if config.file:
        file_path = Path(config.file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(getattr(logging, config.level.upper()))
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def redact_secrets(data: dict | Any) -> dict | Any:
    """Redact sensitive values from data for logging.

    Redacts: AWS credentials, API keys, auth tokens, passwords

    Args:
        data: Dict or other data structure to redact

    Returns:
        Redacted copy of data
    """
    if not isinstance(data, dict):
        return data

    redacted = data.copy()
    sensitive_keys = {
        "password",
        "token",
        "secret",
        "key",
        "credential",
        "api_key",
        "access_key",
        "secret_key",
        "auth",
    }

    for key, value in redacted.items():
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            redacted[key] = "***REDACTED***"
        elif isinstance(value, dict):
            redacted[key] = redact_secrets(value)

    return redacted
