"""Logging utilities for EvidenceForge."""

from typing import Any


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
