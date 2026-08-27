"""Fake executables exercise provider success, failure, interview, and isolation paths."""

import os
from pathlib import Path

import pytest

from experiments.scenario_agent_acceptance.adapters import UnsupportedTranscriptError
from experiments.scenario_agent_acceptance.models import AgentName, NormalizedEvent
from experiments.scenario_agent_acceptance.runner import (
    DEFAULT_TIMEOUT_SECONDS,
    _ambient_accesses,
    _claude_command,
    _codex_command,
    _provider_run,
    _provider_version,
    _transcript_violations,
)


def test_default_timeout_is_a_long_running_session_safety_bound() -> None:
    assert DEFAULT_TIMEOUT_SECONDS == 45 * 60


def test_provider_commands_use_compatible_isolation_flags(tmp_path: Path) -> None:
    codex = _codex_command(tmp_path, "prompt")
    claude = _claude_command("prompt")

    assert "--approve-for-me" in codex
    assert "--sandbox" not in codex
    assert '{"mcpServers":{}}' in claude


def _fake_executable(directory: Path, name: str, body: str) -> Path:
    executable = directory / name
    executable.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _environment(bin_dir: Path) -> dict[str, str]:
    return {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin"}


@pytest.mark.parametrize(
    ("agent", "version", "events"),
    (
        (
            AgentName.CODEX,
            "codex-cli 0.147.0",
            "printf '%s\\n' "
            '\'{"type":"thread.started","thread_id":"fake"}\' '
            '\'{"type":"item.completed","item":{"type":"agent_message",'
            '"text":"done"}}\' '
            '\'{"type":"turn.completed","usage":{"input_tokens":1}}\'',
        ),
        (
            AgentName.CLAUDE,
            "2.1.205 (Claude Code)",
            "printf '%s\\n' "
            '\'{"type":"system","session_id":"fake"}\' '
            '\'{"type":"assistant","message":{"content":[{"type":"text",'
            '"text":"done"}]}}\' '
            '\'{"type":"result","usage":{"input_tokens":1}}\'',
        ),
    ),
)
def test_fake_provider_success_and_version(
    tmp_path: Path, agent: AgentName, version: str, events: str
) -> None:
    body = f'if [ "$1" = "--version" ]; then echo "{version}"; exit 0; fi\n{events}'
    _fake_executable(tmp_path, agent.value, body)
    env = _environment(tmp_path)

    assert _provider_version(agent, env) == version
    normalized, exit_code = _provider_run(
        agent,
        workspace=tmp_path,
        prompt="controlled prompt",
        transcript=tmp_path / f"{agent.value}.jsonl",
        env=env,
        timeout=5,
    )

    assert exit_code == 0
    assert any(event.output == "done" for event in normalized)


def test_fake_provider_supports_scripted_interview_turns(tmp_path: Path) -> None:
    events = (
        "printf '%s\\n' "
        '\'{"type":"thread.started","thread_id":"ephemeral"}\' '
        '\'{"type":"item.completed","item":{"type":"agent_message",'
        '"text":"One question?"}}\' '
        '\'{"type":"turn.completed","usage":{}}\''
    )
    _fake_executable(tmp_path, "codex", events)
    env = _environment(tmp_path)

    first, _ = _provider_run(
        AgentName.CODEX,
        workspace=tmp_path,
        prompt="turn one",
        transcript=tmp_path / "turn-1.jsonl",
        env=env,
        timeout=5,
    )
    second, _ = _provider_run(
        AgentName.CODEX,
        workspace=tmp_path,
        prompt="prior answer plus turn two",
        transcript=tmp_path / "turn-2.jsonl",
        env=env,
        timeout=5,
    )

    assert any(event.output == "One question?" for event in first)
    assert any(event.output == "One question?" for event in second)


def test_fake_provider_failure_and_malformed_transcript(tmp_path: Path) -> None:
    _fake_executable(tmp_path, "codex", 'echo \'{"type":"future.event"}\'; exit 7')

    with pytest.raises(UnsupportedTranscriptError):
        _provider_run(
            AgentName.CODEX,
            workspace=tmp_path,
            prompt="fail",
            transcript=tmp_path / "malformed.jsonl",
            env=_environment(tmp_path),
            timeout=5,
        )


def test_isolation_negative_controls_detect_ambient_and_network_access(tmp_path: Path) -> None:
    events = [
        NormalizedEvent(
            sequence=0,
            kind="tool_call",
            tool="Bash",
            input={"command": "cat /etc/passwd; curl https://example.test"},
        )
    ]

    assert _ambient_accesses(events, tmp_path) == ["/etc/passwd"]
    assert _transcript_violations(events) == ["cat /etc/passwd; curl https://example.test"]
