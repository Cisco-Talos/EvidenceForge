"""Evaluation rule data loading utilities."""

from pathlib import Path
from typing import Any

from evidenceforge.utils.files import load_yaml


def get_rules_directory() -> Path:
    """Get the path to the evaluation rules directory."""
    return Path(__file__).parent


def load_rules_file(name: str) -> dict[str, Any]:
    """Load a YAML rules file from the rules directory."""
    path = get_rules_directory() / name
    if not path.exists():
        return {}
    return load_yaml(path)
