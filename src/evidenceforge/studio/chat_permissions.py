"""Derive and verify authoring permissions from the canonical artifact lifecycle."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge._windows_cleanup import remove_temporary_tree
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

# Sandboxed commands cannot write the platform temporary directory, and Python's tempfile
# then silently falls back to the working directory: the draft. Each draft conversation gets
# its own writable scratch folder outside the draft, and the shell's temp variables name it.
SCRATCH_ROOT = Path(".eforge", "tmp", "chat")
TEMP_VARIABLES = ("TMPDIR", "TEMP", "TMP")
_CONVERSATION_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class ChatAccess(BaseModel):
    """File-backed discussion/authoring state; never persisted as artifact authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    mode: Literal["discussion", "draft"]
    source: Path
    directory: Path
    version: str | None = None
    based_on_version: str | None = None
    scratch: Path | None = Field(default=None, exclude=True)

    @property
    def writable_roots(self) -> list[Path]:
        """Return the only folders a draft conversation's commands may write."""
        if self.mode == "discussion":
            return []
        return [self.directory] + ([self.scratch] if self.scratch is not None else [])

    @property
    def sandbox(self) -> dict[str, Any]:
        """Return a policy that never grants the encompassing library write access."""
        if self.mode == "discussion":
            return {"type": "readOnly", "networkAccess": False}
        return {
            "type": "workspaceWrite",
            "writableRoots": [str(root) for root in self.writable_roots],
            "networkAccess": False,
            "excludeTmpdirEnvVar": True,
            "excludeSlashTmp": True,
        }

    @property
    def instructions(self) -> str:
        """Explain the enforced boundary and the manual new-draft workflow."""
        validation = (
            " Run scenario checks with eforge validate --no-record so validation does not "
            "write project-level receipts outside this conversation's writable scope. "
            "Studio's Validate action retains validation provenance through its helper."
        )
        if self.mode == "discussion":
            return (
                " This is a read-only discussion of this exact source. Read and explain it; "
                "do not edit it, its original draft, dependencies or configuration. If the user "
                "requests changes, explain that they must select New draft in Studio and open "
                "a new conversation on that draft. Do not create a draft, continue an earlier "
                "draft, change file permissions or request broader write access." + validation
            )
        return (
            f" Edit only the active draft at {str(self.source)!r} and companions inside "
            f"{str(self.directory)!r}. Old paths in conversation history are read-only history. "
            "Never edit published releases, completed drafts or other library items. "
            "Use the current absolute source path rather than a path copied from history."
            " Do not run new-draft again, allocate another draft_id, or move only its YAML; "
            "retain draft.json and all companion files."
            + (
                f" Put temporary and scratch files in {str(self.scratch)!r}, never in the "
                "draft; TMPDIR, TEMP and TMP already name it."
                if self.scratch is not None
                else ""
            )
            + validation
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


def scratch_directory(workspace: Path, conversation_id: str) -> Path:
    """Return a conversation's scratch folder inside the workspace's private state area."""
    if not _CONVERSATION_ID.fullmatch(conversation_id):
        raise CodexUnavailableError("Conversation identity is invalid; start a new conversation")
    return workspace / SCRATCH_ROOT / conversation_id


def with_scratch(access: ChatAccess, workspace: Path, conversation_id: str) -> ChatAccess:
    """Create the draft conversation's scratch folder and add it to its writable roots."""
    if access.mode == "discussion":
        return access
    scratch = scratch_directory(workspace, conversation_id)
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_path(scratch)
    return access.model_copy(update={"scratch": scratch.resolve()})


def remove_scratch(workspace: Path, conversation_id: str) -> None:
    """Delete one conversation's scratch folder; its contents are disposable."""
    scratch = scratch_directory(workspace, conversation_id)
    if scratch.is_symlink():
        scratch.unlink()
        return
    if not scratch.exists():
        return
    _safe_path(scratch)
    remove_temporary_tree(scratch)


def prune_scratch(workspace: Path, live: set[str]) -> None:
    """Delete scratch folders left by conversations removed through any path."""
    root = workspace / SCRATCH_ROOT
    if not root.is_dir() or root.is_symlink():
        return
    for entry in root.iterdir():
        if entry.name not in live and _CONVERSATION_ID.fullmatch(entry.name):
            remove_scratch(workspace, entry.name)


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
            == {root.resolve() for root in access.writable_roots}
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
    config: dict[str, Any] = {
        "mcp_servers": servers,
        "features": {item.split(".")[1].split("=")[0]: False for item in CHAT_CONFIG},
        "sandbox_workspace_write": {
            "writable_roots": [str(root) for root in access.writable_roots],
            "network_access": False,
            "exclude_tmpdir_env_var": True,
            "exclude_slash_tmp": True,
        },
    }
    if access.scratch is not None:
        # Override only the "set" table so the user's inherit/include/exclude rules survive.
        policy = (effective.get("config") or {}).get("shell_environment_policy") or {}
        assigned = policy.get("set") if isinstance(policy, dict) else None
        config["shell_environment_policy.set"] = {
            **(assigned if isinstance(assigned, dict) else {}),
            **{name: str(access.scratch) for name in TEMP_VARIABLES},
        }
    return config
