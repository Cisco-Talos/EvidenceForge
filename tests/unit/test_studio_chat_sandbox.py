"""Exercise native Codex restrictions without contacting a model or modifying user files."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

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
        not os.environ.get("EFORGE_NATIVE_CODEX_BIN")
        or sys.platform not in {"darwin", "linux", "win32"},
        reason="Native Codex sandbox probe requires EFORGE_NATIVE_CODEX_BIN on macOS/Linux/Windows",
    ),
]


async def test_resumed_discussion_and_scoped_draft_cannot_modify_protected_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    root = tmp_path.resolve()
    codex_home = root / "codex-home"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.delenv("EFORGE_DESKTOP_CODEX_BIN", raising=False)
    codex_home.mkdir(mode=0o700)
    if sys.platform == "win32":
        # Pytest's 0700 tree is inaccessible to the legacy sandbox's separate
        # logon account before its command runner can apply the command policy.
        # Use inherited workspace ACLs for disposable authored fixtures only;
        # Codex credentials and the actual retained runtime stay private.
        parent = Path(os.environ.get("RUNNER_TEMP", str(Path.cwd() / "build")))
        root = parent / f"eforge sandbox workspace {uuid4().hex}"
        root.mkdir(parents=True)
        root = root.resolve()
        request.addfinalizer(lambda: shutil.rmtree(root))
        subprocess.run(["icacls", str(root)], check=True)
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
    if sys.platform == "win32":
        from evidenceforge.studio.runtime import discover_codex

        binary = discover_codex(Path(os.environ["EFORGE_NATIVE_CODEX_BIN"]))
        assert binary is not None
        mxc = subprocess.run(
            [
                binary,
                "-c",
                'windows.sandbox="mxc"',
                "sandbox",
                "--include-managed-config",
                "--permission-profile",
                ":workspace",
                "-C",
                str(workspace),
                "--",
                "cmd.exe",
                "/d",
                "/c",
                "echo",
                "MXC_OK",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        print(f"Native MXC compatibility: {mxc.returncode}: {mxc.stdout} {mxc.stderr}")
        if mxc.returncode == 0:
            assert "MXC_OK" in mxc.stdout
            (codex_home / "config.toml").write_text('[windows]\nsandbox = "mxc"\n')
        else:
            subprocess.run(
                [
                    binary,
                    "sandbox",
                    "setup",
                    "--elevated",
                    "--current-user",
                    "--codex-home",
                    str(codex_home),
                ],
                check=True,
                timeout=180,
            )

    def protect_command(target: Path) -> list[str]:
        return (
            ["icacls", str(target), "/grant", "*S-1-1-0:F"]
            if sys.platform == "win32"
            else ["chmod", "777", str(target)]
        )

    def remove_command(target: Path) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import pathlib,sys;pathlib.Path(sys.argv[1]).unlink()",
            str(target),
        ]

    async def event(method: str, params: dict[str, Any]) -> None:
        return None

    async def request(request_id: int | str, method: str, params: dict[str, Any]) -> None:
        raise AssertionError("The native probe must not ask for an approval")

    client = CodexClient(
        Path(os.environ["EFORGE_NATIVE_CODEX_BIN"]), event, request, config_overrides=CHAT_CONFIG
    )

    async def execute(access: ChatAccess, command: list[str]) -> dict[str, Any]:
        print(f"Native sandbox {access.mode} in {access.directory}: {command!r}", flush=True)
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
        if sys.platform == "win32":
            baseline = await execute(discussion, ["cmd.exe", "/d", "/c", "ver"])
            assert baseline["exitCode"] == 0, baseline
        packaged_cli = os.environ.get("EFORGE_NATIVE_STUDIO_CLI")
        if packaged_cli:
            result = await execute(discussion, [packaged_cli, "version"])
            assert result["exitCode"] == 0, result
        for target in (source, completed):
            commands = [
                protect_command(target),
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('changed')",
                    str(target),
                ],
                remove_command(target),
                [
                    sys.executable,
                    "-c",
                    "import os,sys;os.replace(sys.argv[1],sys.argv[2])",
                    str(replacement),
                    str(target),
                ],
            ]
            for command in commands:
                result = await execute(discussion, command)
                assert result["exitCode"] != 0, (command, result)
        read = await execute(
            discussion,
            [
                sys.executable,
                "-c",
                "import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text(),end='')",
                str(source),
            ],
        )
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
        if packaged_cli:
            result = await execute(access, [packaged_cli, "version"])
            assert result["exitCode"] == 0, result
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
                protect_command(target),
                remove_command(target),
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
