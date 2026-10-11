"""Recognize an untouched scenario scaffold without compiling authored inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml


def scenario_scaffold(description: str) -> dict[str, Any]:
    """Return the shared authoring skeleton, deliberately not a runnable scenario."""
    return {
        "schema_version": "3.0",
        "composition": {},
        "environment": {"description": description, "users": [], "systems": []},
        "time_window": {"start": "2026-01-01T00:00:00Z", "duration": "1h"},
        "baseline_activity": {"description": "", "intensity": "medium", "variation": "low"},
        "output": {
            "logs": [{"format": "windows"}, {"format": "zeek"}],
            "destination": "./output",
        },
    }


def scaffold_fingerprint(data: dict[str, Any]) -> str:
    """Fingerprint authored content independently of editable lifecycle metadata."""
    content = {
        key: value
        for key, value in data.items()
        if key
        not in {
            "name",
            "display_name",
            "status",
            "draft_id",
            "publisher",
            "parents",
            "release_notes",
        }
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def is_starter_draft(source: Path) -> bool:
    """Match a managed receipt and untouched content, including the pre-marker skeleton."""
    try:
        # Only the small managed entrypoint can be a starter; includes are authored content.
        if source.stat().st_size > 1024 * 1024:
            return False
        data = yaml.safe_load(source.read_bytes())
        receipt_path = source.parent.parent / "draft.json"
        if (
            not isinstance(data, dict)
            or data.get("status") != "draft"
            or not receipt_path.is_file()
        ):
            return False
        if not isinstance(data.get("description"), str) or not isinstance(
            data.get("draft_id"), str
        ):
            return False
        UUID(data["draft_id"])
        if receipt_path.stat().st_size > 1024 * 1024:
            return False
        receipt = json.loads(receipt_path.read_bytes())
        if not isinstance(receipt, dict):
            return False
        if (
            receipt.get("draft_id") != data.get("draft_id")
            or receipt.get("entrypoint") != source.relative_to(receipt_path.parent).as_posix()
            or data.get("schema_version") != "3.0"
        ):
            return False
        fingerprint = scaffold_fingerprint(data)
        if "scaffold_sha256" in receipt:
            return receipt["scaffold_sha256"] == fingerprint
        # Older managed scaffolds had no marker and omitted baseline description.
        expected = {
            "description": data.get("description", ""),
            **scenario_scaffold(data.get("description", "")),
        }
        if fingerprint == scaffold_fingerprint(expected):
            return True
        expected["baseline_activity"].pop("description")
        return fingerprint == scaffold_fingerprint(expected)
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        return False
