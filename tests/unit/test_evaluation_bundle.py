"""Streaming integrity and container-input contracts for evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import (
    verify_generation_bundle,
    write_generation_manifest,
    write_resolved_scenario,
)
from evidenceforge.evaluation.bundle import verify_evaluation_bundle
from evidenceforge.evaluation.json_stream import JsonStreamReader
from evidenceforge.evaluation.parsers.email_artifacts import EmailArtifactsParser
from evidenceforge.evaluation.storage import EvaluationWorkspace, evaluation_workspace
from evidenceforge.models.exceptions import EvaluationError, SchemaValidationError


def _bundle(root: Path, files: int = 30) -> Path:
    scenario = Path(__file__).parents[1] / "fixtures/scenarios/minimal.yaml"
    compiled = compile_scenario(scenario)
    data = root / "data"
    data.mkdir()
    for number in range(files):
        (data / f"events-{number}.json").write_text('{"event":1}\n')
    write_resolved_scenario(compiled, root)
    write_generation_manifest(compiled, root, output_target="default", formats=["zeek_conn"])
    return root


@pytest.mark.parametrize("budget", [1, 256 * 1024 * 1024])
def test_streaming_verifier_matches_authoritative_metadata(tmp_path: Path, budget: int) -> None:
    root = _bundle(tmp_path)
    expected = verify_generation_bundle(root)
    actual = verify_evaluation_bundle(root, memory_budget_bytes=budget)
    expected["files"] = {}
    assert actual == expected


@pytest.mark.slow
def test_streaming_verifier_exceeds_old_file_count_limit(tmp_path: Path) -> None:
    root = _bundle(tmp_path, files=10_005)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    result = verify_evaluation_bundle(root, memory_budget_bytes=64 * 1024, scratch_dir=scratch)
    assert result["files"] == {}
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("defect", ["changed", "missing", "unexpected", "symlink"])
def test_streaming_verifier_rejects_every_owned_file_defect(tmp_path: Path, defect: str) -> None:
    root = _bundle(tmp_path)
    target = root / "data/events-29.json"
    if defect == "changed":
        target.write_text("changed")
    elif defect == "missing":
        target.unlink()
    elif defect == "unexpected":
        (root / "data/unexpected.json").write_text("extra")
    else:
        target.unlink()
        target.symlink_to(root / "data/events-0.json")
    with pytest.raises(SchemaValidationError, match="hash verification failed|symlink"):
        verify_evaluation_bundle(root, memory_budget_bytes=1)


def test_scratch_failure_is_actionable_and_does_not_delete_parent_files(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    unrelated = root / "keep-me"
    unrelated.write_text("unrelated")
    with pytest.raises(EvaluationError, match="scratch storage"):
        verify_evaluation_bundle(root, memory_budget_bytes=1, scratch_dir=root / "missing")
    assert unrelated.read_text() == "unrelated"


@pytest.mark.parametrize("tail", ["", ",broken", " trailing"])
def test_email_container_is_validated_before_publishing_rows(tmp_path: Path, tail: str) -> None:
    path = tmp_path / "ARTIFACTS_MANIFEST.json"
    document = json.dumps({"email": {"messages": [{"message_id": "<one@example.test>"}]}})
    path.write_text(document + tail)
    workspace = EvaluationWorkspace(1, tmp_path)
    try:
        with evaluation_workspace(workspace):
            records = list(EmailArtifactsParser().parse_file(path))
            assert len(records) == 1
            assert bool(records[0].parse_errors) == bool(tail)
            if not tail:
                assert records[0].fields["message_id"] == "<one@example.test>"
    finally:
        workspace.close()
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.slow
def test_large_email_container_preserves_per_message_protection(tmp_path: Path) -> None:
    path = tmp_path / "ARTIFACTS_MANIFEST.json"
    message = {"message_id": "<one@example.test>", "subject": "x" * 1_000_000}
    with path.open("w") as stream:
        stream.write('{"email":{"messages":[')
        encoded = json.dumps(message)
        for number in range(18):
            if number:
                stream.write(",")
            stream.write(encoded)
        stream.write("]}}")
    assert path.stat().st_size > 16 * 1024 * 1024
    workspace = EvaluationWorkspace(1024 * 1024, tmp_path)
    try:
        with evaluation_workspace(workspace):
            count = 0
            for record in EmailArtifactsParser().parse_file(path):
                assert not record.parse_errors
                count += 1
            assert count == 18
            assert workspace.spilled
    finally:
        workspace.close()
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("document", ['{"a":1', '{"a":1,}', '{"a":1} trailing'])
def test_stream_reader_rejects_malformed_containers(document: str) -> None:
    from io import StringIO

    reader = JsonStreamReader(StringIO(document))
    with pytest.raises(ValueError):
        list(reader.object_items())
        if reader.peek():
            raise ValueError("trailing input")


@pytest.mark.parametrize("number", ["12.5", "1e+3", "-2.5e-3"])
def test_stream_reader_preserves_numbers_split_across_chunks(number: str) -> None:
    from io import StringIO

    class TinyChunks(StringIO):
        def read(self, size: int = -1) -> str:
            return super().read(min(size, 1) if size >= 0 else 1)

    document = '{"value":' + number + "}"
    reader = JsonStreamReader(TinyChunks(document))
    assert dict(reader.object_items()) == json.loads(document)
    assert not reader.peek()
