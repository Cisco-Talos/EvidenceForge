"""Transcript adapter tests and malformed-event negative controls."""

from pathlib import Path

import pytest

from experiments.scenario_agent_acceptance.adapters import (
    UnsupportedTranscriptError,
    parse_claude,
    parse_codex,
)


def test_codex_adapter_normalizes_session_tools_and_usage(tmp_path: Path) -> None:
    transcript = tmp_path / "codex.jsonl"
    transcript.write_text(
        "\n".join(
            (
                '{"type":"thread.started","thread_id":"thread-1"}',
                '{"type":"turn.started"}',
                '{"type":"item.completed","item":{"type":"command_execution",'
                '"command":"eforge validate scenario.yaml --json","aggregated_output":"ok"}}',
                '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}',
                '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":3}}',
            )
        )
        + "\n",
        encoding="utf-8",
    )

    events = parse_codex(transcript)

    assert events[0].session_id == "thread-1"
    assert any(event.tool == "shell" for event in events)
    assert events[-1].usage == {"input_tokens": 10, "output_tokens": 3}


def test_claude_adapter_normalizes_read_and_usage(tmp_path: Path) -> None:
    transcript = tmp_path / "claude.jsonl"
    transcript.write_text(
        "\n".join(
            (
                '{"type":"system","session_id":"session-1"}',
                '{"type":"assistant","message":{"content":['
                '{"type":"tool_use","name":"Read","input":{"file_path":"scenario.yaml"}},'
                '{"type":"text","text":"done"}]}}',
                '{"type":"result","usage":{"input_tokens":20,"output_tokens":5},'
                '"total_cost_usd":0.01}',
            )
        )
        + "\n",
        encoding="utf-8",
    )

    events = parse_claude(transcript)

    assert events[0].session_id == "session-1"
    assert events[1].input["file_path"] == "scenario.yaml"
    assert events[-1].usage["total_cost_usd"] == 0.01


@pytest.mark.parametrize(
    "content",
    (
        "not json\n",
        '{"type":"future.event"}\n',
        '{"missing":"type"}\n',
    ),
)
def test_codex_adapter_rejects_unknown_or_malformed_events(tmp_path: Path, content: str) -> None:
    transcript = tmp_path / "invalid.jsonl"
    transcript.write_text(content, encoding="utf-8")

    with pytest.raises(UnsupportedTranscriptError):
        parse_codex(transcript)
