# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""File I/O utilities for EvidenceForge."""

import os
from pathlib import Path

import yaml

from evidenceforge.models.exceptions import ConfigurationError


def load_yaml(path: Path | str) -> dict:
    """Load and parse YAML file safely.

    Args:
        path: Path to YAML file

    Returns:
        Parsed dict structure

    Raises:
        FileNotFoundError: If file doesn't exist
        ConfigurationError: If YAML is invalid
    """
    path = Path(path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in {path}: {e}") from e


def write_yaml(data: dict, path: Path | str) -> None:
    """Write dict to YAML file.

    Args:
        data: Dict to serialize
        path: Output path
    """
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def ensure_directory(path: Path | str) -> Path:
    """Ensure directory exists, creating if needed.

    Args:
        path: Directory path

    Returns:
        Resolved Path object

    Raises:
        PermissionError: If can't create directory
    """
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def validate_output_path(path: Path | str) -> Path:
    """Validate output path is writable.

    Args:
        path: Path to validate

    Returns:
        Resolved Path object

    Raises:
        PermissionError: If path is not writable
    """
    path = Path(path).resolve()

    # Check if parent directory is writable
    if path.exists():
        if not os.access(path, os.W_OK):
            raise PermissionError(f"Path not writable: {path}")
    else:
        # Check parent directory
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        if not os.access(parent, os.W_OK):
            raise PermissionError(f"Parent directory not writable: {parent}")

    return path
