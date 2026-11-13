# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Windows path spelling for bundled resources beyond the legacy path limit."""

import os
from pathlib import Path


def package_resource_path(path: Path) -> Path:
    """Keep bundled data readable without requiring Windows long-path policy changes."""
    if os.name != "nt":
        return path
    absolute = os.path.abspath(path)
    if absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)
