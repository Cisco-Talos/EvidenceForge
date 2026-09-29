"""Destinations shared by the desktop skill installer and its Settings preview."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

SkillScope = Literal["global", "workspace"]
SkillAgent = Literal["all", "chatgpt", "claude"]
CanonicalAgent = Literal["chatgpt", "claude"]


def skill_targets(
    scope: SkillScope, agent: SkillAgent, workspace: Path
) -> list[tuple[CanonicalAgent, Path]]:
    """Return the CLI-equivalent target directories for a desktop installation."""
    root = Path.home() if scope == "global" else workspace
    targets: list[tuple[CanonicalAgent, Path]] = []
    if agent in {"all", "claude"}:
        targets.append(("claude", root / ".claude" / "commands"))
    if agent in {"all", "chatgpt"}:
        targets.append(("chatgpt", root / ".agents" / "skills"))
    return targets
