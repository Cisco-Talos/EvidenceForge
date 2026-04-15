"""Path safety helpers for host-routed emitters."""

from __future__ import annotations

import re
from pathlib import Path

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]")
_DEFAULT_HOST_DIRECTORY = "unknown-host"


def sanitize_host_directory_name(host_fqdn: str) -> str:
    """Sanitize host identifier for safe use as a single directory name."""
    raw = host_fqdn.strip().replace("/", "_").replace("\\", "_")
    sanitized = _UNSAFE_PATH_CHARS.sub("_", raw).strip()
    sanitized = sanitized.lstrip(".")
    if not sanitized or sanitized in {".", ".."}:
        return _DEFAULT_HOST_DIRECTORY
    return sanitized


def host_output_path(base_dir: Path, host_fqdn: str, filename: str) -> Path:
    """Build a safe per-host output path under ``base_dir``."""
    return base_dir / sanitize_host_directory_name(host_fqdn) / filename
