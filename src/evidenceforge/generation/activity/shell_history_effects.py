# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical classification of shell commands that destroy Bash history.

The shell-command producer records this classification on the canonical occurrence. The
Bash history emitter applies the same function to the same canonical command, so rendered
history and ground truth cannot disagree about which entries a clear destroys.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay
from evidenceforge.models.exceptions import ConfigurationError

HistoryEffect = Literal["destroy_prior"]

_PATH = get_activity_directory() / "shell_history_effects.yaml"
_CACHED_PATTERNS: tuple[re.Pattern[str], ...] | None = None


def _merge_shell_history_effects(default: dict[str, Any], overlay: dict[str, Any]) -> dict:
    """Append overlay patterns after the packaged patterns, keeping first occurrences."""
    patterns = list(default.get("destroy_prior_patterns", []))
    for pattern in overlay.get("destroy_prior_patterns", []):
        if pattern not in patterns:
            patterns.append(pattern)
    return {**default, "destroy_prior_patterns": patterns}


def _destroy_prior_patterns() -> tuple[re.Pattern[str], ...]:
    """Load and compile the destructive-command patterns once."""
    global _CACHED_PATTERNS
    if _CACHED_PATTERNS is None:
        data = load_with_overlay(
            _PATH, "activity/shell_history_effects.yaml", _merge_shell_history_effects
        )
        raw = data.get("destroy_prior_patterns")
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ConfigurationError(
                "shell_history_effects.yaml destroy_prior_patterns must be a list of regexes"
            )
        try:
            _CACHED_PATTERNS = tuple(re.compile(item) for item in raw)
        except re.error as error:
            raise ConfigurationError(
                f"shell_history_effects.yaml has an invalid pattern: {error}"
            ) from error
    return _CACHED_PATTERNS


def bash_history_effect(command: str) -> HistoryEffect | None:
    """Return the history effect of one Bash command line, if any."""
    if any(pattern.search(command) for pattern in _destroy_prior_patterns()):
        return "destroy_prior"
    return None
