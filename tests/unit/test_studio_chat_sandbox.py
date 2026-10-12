"""Exercise native Codex restrictions without contacting a model or modifying user files."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.studio.chat_permissions import (
    CHAT_CONFIG,
    ChatAccess,
    isolated_chat_config,
    verify_chat_permissions,
)
from evidenceforge.studio.codex import CodexClient

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("EFORGE_NATIVE_CODEX_BIN") or sys.platform not in {"darwin", "linux"},
        reason="Native Codex sandbox probe requires EFORGE_NATIVE_CODEX_BIN on macOS/Linux",
    ),
]


async def test_resumed_discussion_and_scoped_draft_cannot_modify_protected_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve()
    monkeypatch.setenv("CODEX_HOME", str(root / "codex-home"))
    monkeypatch.delenv("EFORGE_DESKTOP_CODEX_BIN", raising=False)
    (root / "codex-home").mkdir()
    workspace = root / "workspace"
    workspace.mkdir()
    published = workspace / "release"
    published.mkdir()
    source = published / "scenario.yaml"
    source.write_text("published bytes")
    completed = workspace / "completed-draft.yaml"
    completed.write_text("historical draft bytes")
    revision = workspace / "new-draft"
    revision.mkdir()
    replacement = root / "replacement.yaml"
    replacement.write_text("replacement bytes")
    original_mode = source.stat().st_mode

    async def event(method: str, params: dict[str, Any]) -> None:
        return None

    async def request(request_id: int | str, method: str, params: dict[str, Any]) -> None:
        raise AssertionError("The native probe must not ask for an approval")

    client = CodexClient(
        Path(os.environ["EFORGE_NATIVE_CODEX_BIN"]), event, request, config_overrides=CHAT_CONFIG
    )

    async def execute(access: ChatAccess, command: list[str]) -> dict[str, Any]:
        return await client.call(
            "command/exec",
            {"command": command, "cwd": str(access.directory), "sandboxPolicy": access.sandbox},
        )

    try:
        # An old session starts with access to the whole workspace. Resume must tighten
        # that exact thread, rather than relying on permissions selected at creation time.
        initial = await client.call(
            "thread/start",
            {"cwd": str(workspace), "sandbox": "workspace-write", "approvalPolicy": "never"},
        )
        await client.call(
            "thread/name/set", {"threadId": initial["thread"]["id"], "name": "Sandbox probe"}
        )
        await client.call("thread/unsubscribe", {"threadId": initial["thread"]["id"]})
        discussion = ChatAccess(mode="discussion", source=source, directory=published)
        effective = await client.call("config/read", {"cwd": str(published), "includeLayers": True})
        resumed = await client.call(
            "thread/resume",
            {
                "threadId": initial["thread"]["id"],
                "cwd": str(published),
                "sandbox": "read-only",
                "approvalPolicy": "never",
                "config": isolated_chat_config(effective, discussion),
            },
        )
        verify_chat_permissions(resumed, discussion)
        assert resumed["thread"]["id"] == initial["thread"]["id"]
        for target in (source, completed):
            commands = [
                ["chmod", "777", str(target)],
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('changed')",
                    str(target),
                ],
                ["rm", str(target)],
                ["mv", str(replacement), str(target)],
            ]
            for command in commands:
                result = await execute(discussion, command)
                assert result["exitCode"] != 0, (command, result)
        read = await execute(discussion, ["cat", str(source)])
        assert read["exitCode"] == 0 and read["stdout"] == "published bytes", read
        access = ChatAccess(mode="draft", source=revision / "scenario.yaml", directory=revision)
        effective = await client.call("config/read", {"cwd": str(revision), "includeLayers": True})
        created = await client.call(
            "thread/start",
            {
                "cwd": str(revision),
                "sandbox": "workspace-write",
                "approvalPolicy": "never",
                "config": isolated_chat_config(effective, access),
            },
        )
        verify_chat_permissions(created, access)
        result = await execute(
            access,
            [
                sys.executable,
                "-c",
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('new draft bytes')",
                str(access.source),
            ],
        )
        assert result["exitCode"] == 0 and access.source.read_text() == "new draft bytes"
        for target in (source, completed):
            for command in (
                ["chmod", "777", str(target)],
                ["rm", str(target)],
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('changed')",
                    str(target),
                ],
            ):
                result = await execute(access, command)
                assert result["exitCode"] != 0, (command, result)
            alias = revision / (target.stem + "-alias")
            alias.symlink_to(target)
            result = await execute(
                access,
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('changed')",
                    str(alias),
                ],
            )
            assert result["exitCode"] != 0, result
            alias.unlink()
            result = await execute(
                access,
                [
                    sys.executable,
                    "-c",
                    "import os,sys;os.link(sys.argv[1],sys.argv[2]);open(sys.argv[2],'w').write('changed')",
                    str(target),
                    str(alias),
                ],
            )
            assert result["exitCode"] != 0, result
        assert source.read_text() == "published bytes" and source.stat().st_mode == original_mode
        assert completed.read_text() == "historical draft bytes"
    finally:
        await client.stop()
