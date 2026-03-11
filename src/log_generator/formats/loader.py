"""Format definition loader for EvidenceForge.

This module provides functions to load and cache format definitions from YAML files
in the formats/definitions/ directory.
"""

import logging
from pathlib import Path

from pydantic import ValidationError

from log_generator.models.exceptions import ConfigurationError
from log_generator.utils.files import load_yaml

from .format_def import FormatDefinition

logger = logging.getLogger(__name__)

# Global format cache (in-memory, no TTL)
_format_cache: dict[str, FormatDefinition] = {}


def get_definitions_directory() -> Path:
    """Get the path to the format definitions directory.

    Returns:
        Absolute path to formats/definitions/ directory

    Raises:
        ConfigurationError: If definitions directory does not exist
    """
    # Get package root (src/log_generator)
    package_root = Path(__file__).parent.parent
    definitions_dir = package_root / "formats" / "definitions"

    if not definitions_dir.exists():
        raise ConfigurationError(
            f"Format definitions directory not found: {definitions_dir}"
        )

    return definitions_dir


def load_format(name: str, force_reload: bool = False) -> FormatDefinition:
    """Load a format definition by name.

    Loads from formats/definitions/{name}.yaml and validates against
    FormatDefinition Pydantic model. Results are cached in memory.

    Args:
        name: Format name (e.g., "windows_event", "zeek")
        force_reload: If True, bypass cache and reload from disk

    Returns:
        Validated FormatDefinition instance

    Raises:
        ConfigurationError: If format file not found or invalid

    Example:
        >>> fmt = load_format("windows_event")
        >>> fmt.name
        'windows_event'
        >>> fmt.category
        'host'
    """
    # Check cache first
    if not force_reload and name in _format_cache:
        logger.debug(f"Loaded format '{name}' from cache")
        return _format_cache[name]

    # Load from disk
    definitions_dir = get_definitions_directory()
    format_file = definitions_dir / f"{name}.yaml"

    if not format_file.exists():
        raise ConfigurationError(
            f"Format definition not found: {name} (expected at {format_file})"
        )

    try:
        # Load YAML
        data = load_yaml(format_file)

        # Validate against Pydantic model
        format_def = FormatDefinition(**data)

        # Cache it
        _format_cache[name] = format_def

        logger.info(f"Loaded format definition: {name} (version {format_def.version})")
        return format_def

    except ValidationError as e:
        raise ConfigurationError(
            f"Invalid format definition in {format_file}: {e}"
        ) from e
    except Exception as e:
        raise ConfigurationError(
            f"Failed to load format definition {name}: {e}"
        ) from e


def load_all_formats() -> dict[str, FormatDefinition]:
    """Load all format definitions from the definitions directory.

    Returns:
        Dict mapping format name to FormatDefinition

    Raises:
        ConfigurationError: If any format fails to load
    """
    definitions_dir = get_definitions_directory()
    format_files = list(definitions_dir.glob("*.yaml"))

    if not format_files:
        logger.warning(f"No format definitions found in {definitions_dir}")
        return {}

    formats = {}
    for format_file in format_files:
        name = format_file.stem  # Filename without .yaml
        try:
            formats[name] = load_format(name)
        except ConfigurationError as e:
            logger.error(f"Failed to load format {name}: {e}")
            raise

    logger.info(f"Loaded {len(formats)} format definitions")
    return formats


def get_format(name: str) -> FormatDefinition | None:
    """Get a cached format definition without loading.

    Args:
        name: Format name

    Returns:
        FormatDefinition if cached, None otherwise
    """
    return _format_cache.get(name)


def clear_cache() -> None:
    """Clear the format definition cache.

    Useful for testing or when format definitions are updated at runtime.
    """
    global _format_cache
    _format_cache.clear()
    logger.debug("Cleared format definition cache")
