"""Pre-built persona loading for EvidenceForge."""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def get_builtin_personas_dir() -> Path:
    """Get the path to the pre-built personas directory.

    Resolves from package data: evidenceforge/_data/personas/
    Works both in development (editable install) and installed mode.
    """
    return Path(__file__).resolve().parent.parent / "_data" / "personas"


def load_builtin_personas() -> list[dict]:
    """Load all pre-built persona YAML files from the package data directory.

    Returns:
        List of persona dicts ready for merging into scenario data.
        Empty list if the directory doesn't exist.
    """
    personas_dir = get_builtin_personas_dir()
    if not personas_dir.exists():
        logger.debug(f"Pre-built personas directory not found: {personas_dir}")
        return []

    personas = []
    for path in sorted(personas_dir.glob("*.yaml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict) and "name" in data:
                personas.append(data)
        except Exception as e:
            logger.warning(f"Failed to load persona {path.name}: {e}")

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
