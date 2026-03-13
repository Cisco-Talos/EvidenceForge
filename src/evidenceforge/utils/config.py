"""Configuration loading utilities for EvidenceForge."""

import os
import re
from pathlib import Path

import yaml
from dotenv import find_dotenv, load_dotenv
from pydantic import ValidationError

from log_generator.models.config import AppConfig
from log_generator.models.exceptions import ConfigurationError


def interpolate_env_vars(yaml_content: str) -> str:
    """Replace ${VAR} and ${VAR:-default} with environment variable values.

    Pattern: ${VAR_NAME} or ${VAR_NAME:-default_value}
    - ${VAR_NAME}: Replace with os.environ.get(VAR_NAME, "")
    - ${VAR_NAME:-default}: Replace with os.environ.get(VAR_NAME, default)

    Args:
        yaml_content: YAML content string with ${VAR} placeholders

    Returns:
        String with environment variables interpolated
    """
    pattern = r"\$\{([^}:]+)(?::-([^}]*))?\}"

    def replace(match):
        var_name = match.group(1)
        default = match.group(2)
        return os.environ.get(var_name, default or "")

    return re.sub(pattern, replace, yaml_content)


def load_yaml_with_interpolation(path: Path) -> dict:
    """Load YAML file and interpolate environment variables.

    Args:
        path: Path to YAML file

    Returns:
        Dict with environment variables interpolated

    Raises:
        ConfigurationError: If file can't be loaded or YAML is invalid
    """
    try:
        with open(path, encoding="utf-8") as f:
            yaml_content = f.read()

        # Interpolate env vars
        interpolated = interpolate_env_vars(yaml_content)

        # Parse YAML
        data = yaml.safe_load(interpolated)
        return data or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in {path}: {e}") from e
    except Exception as e:
        raise ConfigurationError(f"Failed to load {path}: {e}") from e


def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dicts, override wins on conflicts.

    Args:
        base: Base dict
        override: Override dict (wins on conflicts)

    Returns:
        Merged dict
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(
    config_path: Path | str | None = None, env_file: Path | str | None = None
) -> AppConfig:
    """Load configuration from multiple sources.

    Precedence (later overrides earlier):
    1. Default values in AppConfig model
    2. System config: ~/.config/log-generator/config.yaml (if exists)
    3. .env file (search from CWD upward, stop at first found)
    4. Project config: ./config.yaml or specified config_path
    5. Command-line arguments (not handled here, merged in CLI)

    Args:
        config_path: Path to config file (default: ./config.yaml)
        env_file: Path to .env file (default: search upward from CWD)

    Returns:
        Validated AppConfig instance

    Raises:
        ConfigurationError: If config is invalid or files can't be loaded
    """
    # Start with defaults (empty dict, Pydantic will use model defaults)
    config_data = {}

    # 1. Load system-wide config (optional)
    system_config = Path.home() / ".config" / "log-generator" / "config.yaml"
    if system_config.exists():
        config_data = load_yaml_with_interpolation(system_config)

    # 2. Load .env file (optional, search upward)
    if env_file:
        load_dotenv(env_file)
    else:
        # Search upward from CWD
        dotenv_path = find_dotenv(usecwd=True)
        if dotenv_path:
            load_dotenv(dotenv_path)

    # 3. Load project config (optional)
    if config_path:
        project_config = Path(config_path)
    else:
        project_config = Path("config.yaml")

    if project_config.exists():
        project_data = load_yaml_with_interpolation(project_config)
        config_data = deep_merge(config_data, project_data)

    # 4. Validate against Pydantic model
    try:
        return AppConfig(**config_data)
    except ValidationError as e:
        raise ConfigurationError(f"Invalid configuration: {e}") from e
