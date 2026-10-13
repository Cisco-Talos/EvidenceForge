"""Derive and verify authoring permissions from the canonical artifact lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from evidenceforge.artifacts.lifecycle import _safe_path, inspect_artifact, safe_relative
from evidenceforge.studio.codex import CodexUnavailableError

# Hooks, plugins and external tools can execute outside the command sandbox. Keep the
# authoring transport's capabilities local; MCP servers are disabled per thread below.
CHAT_CONFIG = (
    "features.apps=false",
    "features.plugins=false",
    "features.hooks=false",
    "features.multi_agent=false",
    "features.browser_use=false",
    "features.computer_use=false",
    "features.code_mode=false",
)


class ChatAccess(BaseModel):
    """File-backed discussion/authoring state; never persisted as artifact authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["discussion", "draft"]
    source: Path
    directory: Path
    version: str | None = None
    based_on_version: str | None = None

    @property
    def sandbox(self) -> dict[str, Any]:
        """Return a policy that never grants the encompassing library write access."""
        if self.mode == "discussion":
            return {"type": "readOnly", "networkAccess": False}
        return {
            "type": "workspaceWrite",
            "writableRoots": [str(self.directory)],
            "networkAccess": False,
            "excludeTmpdirEnvVar": True,
            "excludeSlashTmp": True,
        }

    @property
    def instructions(self) -> str:
        """Explain the enforced boundary and the manual new-draft workflow."""
        if self.mode == "discussion":
            return (
                " This is a read-only discussion of this exact source. Read and explain it; "
                "do not edit it, its original draft, dependencies or configuration. If the user "
                "requests changes, explain that they must select New draft in Studio and open "
                "a new conversation on that draft. Do not create a draft, continue an earlier "
                "draft, change file permissions or request broader write access."
            )
        return (
            f" Edit only the active draft at {str(self.source)!r} and companions inside "
            f"{str(self.directory)!r}. Old paths in conversation history are read-only history. "
            "Never edit published releases, completed drafts or other library items. "
            "Use the current absolute source path rather than a path copied from history."
            " Do not run new-draft again, allocate another draft_id, or move only its YAML; "
            "retain draft.json and all companion files."
        )


def chat_access(source: Path) -> ChatAccess:
    """Allow writes only within the verified owning container of an active draft."""
    source = _safe_path(source)
    info = inspect_artifact(source)  # Includes the complete receipt for releases.
    metadata = info.get("lifecycle") or {}
    if metadata.get("status") == "draft":
        from evidenceforge.artifacts.lifecycle import assert_mutable

        assert_mutable(source)
        for parent in source.parents:
            marker = parent / "draft.json"
            if not marker.is_file():
                continue
            _safe_path(marker)
            draft = json.loads(marker.read_bytes())
            entry = draft.get("entrypoint") if isinstance(draft, dict) else None
            if not isinstance(entry, str):
                raise CodexUnavailableError("Invalid draft receipt; recover into a new draft")
            entrypoint = parent / safe_relative(entry)
            if entrypoint.resolve() != source or draft.get("draft_id") != metadata["draft_id"]:
                raise CodexUnavailableError("Draft identity changed; refresh before authoring")
            if (
                parent.name != metadata["draft_id"]
                or parent.parent.parent.name not in {"scenario", "industry", "organization"}
                or parent.parent.parent.parent.name != "drafts"
                or parent.parent.parent.parent.parent.name != "artifacts"
                or parent.parent.parent.parent.parent.parent.name != ".eforge"
                or not source.is_relative_to(parent / "source")
            ):
                raise CodexUnavailableError(
                    "Draft is outside its managed container; use New draft before authoring"
                )
            parents = metadata.get("parents") or []
            return ChatAccess(
                mode="draft",
                source=source,
                directory=parent.resolve(),
                based_on_version=parents[-1].get("version") if parents else None,
            )
    # Legacy sources can be discussed and explicitly adopted using Studio's New draft action.
    return ChatAccess(
        mode="discussion", source=source, directory=source.parent, version=metadata.get("version")
    )


def verify_chat_permissions(response: dict[str, Any], access: ChatAccess) -> None:
    """Fail closed if Codex ignored or widened the requested session boundary."""
    policy = response.get("sandbox") or {}
    valid = response.get("approvalPolicy") == "never"
    valid = valid and response.get("cwd") == str(access.directory)
    if access.mode == "discussion":
        valid = valid and policy.get("type") == "readOnly" and policy.get("networkAccess") is False
    else:
        valid = (
            valid
            and policy.get("type") == "workspaceWrite"
            and policy.get("networkAccess") is False
            and policy.get("excludeTmpdirEnvVar") is True
            and policy.get("excludeSlashTmp") is True
            and (
                {Path(root).resolve() for root in policy.get("writableRoots", [])}
                | {access.directory}
            )
            == {access.directory}
        )
    if not valid:
        raise CodexUnavailableError(
            "Codex did not confirm the required file protection. No message was sent. "
            "Check your Codex version and managed permissions before retrying."
        )


def isolated_chat_config(effective: dict[str, Any], access: ChatAccess) -> dict[str, Any]:
    """Disable indirect mutation capabilities, including configured MCP servers."""
    if not isinstance(effective.get("layers"), list):
        raise CodexUnavailableError(
            "Codex cannot inspect tool isolation; update Codex before chatting"
        )
    configurations = [effective.get("config") or {}] + [
        layer.get("config") or {} for layer in effective["layers"]
    ]
    servers = {
        name: {"enabled": False}
        for configuration in configurations
        for name in (configuration.get("mcp_servers") or {})
    }
    return {
        "mcp_servers": servers,
        "features": {item.split(".")[1].split("=")[0]: False for item in CHAT_CONFIG},
        "sandbox_workspace_write": {
            "writable_roots": [str(access.directory)] if access.mode == "draft" else [],
            "network_access": False,
            "exclude_tmpdir_env_var": True,
            "exclude_slash_tmp": True,
        },
    }
