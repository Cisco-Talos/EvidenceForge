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

"""Pre-built persona loading for EvidenceForge."""

import logging
from pathlib import Path

import yaml

from evidenceforge.config import get_personas_directory
from evidenceforge.config.overlay import get_overlay_directory

logger = logging.getLogger(__name__)


def get_builtin_personas_dir() -> Path:
    """Get the path to the pre-built personas directory."""
    return get_personas_directory()


def load_builtin_personas() -> list[dict]:
    """Load all pre-built persona YAML files from the package data directory.

    After loading package personas, checks the overlay directory
    (``get_overlay_directory() / "personas"``) for additional ``.yaml``
    files.  Overlay personas with the same *name* as a package persona
    replace it (a warning is logged); new overlay personas are appended.

    Returns:
        List of persona dicts ready for merging into scenario data.
        Empty list if neither directory exists.
    """
    # -- 1. Package personas -------------------------------------------------
    personas_dir = get_builtin_personas_dir()
    if not personas_dir.exists():
        logger.debug(f"Pre-built personas directory not found: {personas_dir}")
        package_personas: list[dict] = []
    else:
        package_personas = []
        for path in sorted(personas_dir.glob("*.yaml")):
            try:
                with open(path) as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data, dict) and "name" in data:
                    package_personas.append(data)
            except Exception as e:
                logger.warning(f"Failed to load persona {path.name}: {e}")

    # -- 2. Overlay personas -------------------------------------------------
    overlay_dir = get_overlay_directory()
    overlay_personas: list[dict] = []
    if overlay_dir is not None:
        overlay_personas_dir = overlay_dir / "personas"
        if overlay_personas_dir.is_dir():
            for path in sorted(overlay_personas_dir.glob("*.yaml")):
                try:
                    with open(path) as f:
                        data = yaml.safe_load(f)
                    if data and isinstance(data, dict) and "name" in data:
                        overlay_personas.append(data)
                except Exception as e:
                    logger.warning(f"Failed to load overlay persona {path.name}: {e}")

    # -- 3. Merge: overlay fields merged into package on name collision ------
    if overlay_personas:
        from evidenceforge.config.overlay import deep_merge_dict

        overlay_by_name = {p["name"]: p for p in overlay_personas}
        merged: list[dict] = []
        for persona in package_personas:
            name = persona["name"]
            if name in overlay_by_name:
                logger.info(
                    "Overlay persona %r merging fields into package persona",
                    name,
                )
                merged.append(deep_merge_dict(persona, overlay_by_name.pop(name)))
            else:
                merged.append(persona)
        # Append remaining overlay personas (new additions)
        merged.extend(overlay_by_name.values())
        personas = merged
    else:
        personas = package_personas

    logger.debug(f"Loaded {len(personas)} pre-built personas")
    return personas


def merge_builtin_personas(scenario_data: dict) -> dict:
    """Merge pre-built personas into scenario data.

    Inline personas (defined in the scenario YAML) take precedence
    over pre-built ones with the same name.

    Args:
        scenario_data: Raw scenario dict from YAML loading

    Returns:
        Modified scenario_data with merged personas list
    """
    builtin = load_builtin_personas()
    if not builtin:
        return scenario_data

    # Get names of inline personas (these take precedence)
    inline_personas = scenario_data.get("personas") or []
    inline_names = {p["name"] for p in inline_personas if isinstance(p, dict) and "name" in p}

    # Add pre-built personas that aren't overridden by inline ones
    merged = list(inline_personas)
    for persona in builtin:
        if persona["name"] not in inline_names:
            merged.append(persona)

    scenario_data["personas"] = merged
    return scenario_data
