"""Classify existing Codex sandbox warnings without adding a startup probe."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LinuxSandboxNotice(BaseModel):
    """A likely Linux sandbox prerequisite reported by Codex."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: Literal["bubblewrap_missing", "user_namespace_restricted"] = Field(
        description="Sandbox prerequisite identified by an existing Codex warning"
    )


def linux_sandbox_notice(message: str) -> LinuxSandboxNotice | None:
    """Recognize bubblewrap setup failures while ignoring unrelated warnings."""
    text = message.casefold()
    if "bubblewrap" not in text and "bwrap" not in text:
        return None
    if any(word in text for word in ("user namespace", "userns", "apparmor")) and any(
        word in text
        for word in (
            "needs access",
            "could not",
            "cannot",
            "can't",
            "unable",
            "failed",
            "not permitted",
            "permission denied",
            "restricted",
            "not working",
            "not supported",
        )
    ):
        return LinuxSandboxNotice(code="user_namespace_restricted")
    if any(word in text for word in ("could not find", "cannot find", "not found", "missing")):
        return LinuxSandboxNotice(code="bubblewrap_missing")
    return None
