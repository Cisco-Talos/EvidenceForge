"""Captured run identities remain independent of mutable authored files and catalog labels."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from evidenceforge.artifacts.run_source import captured_scenario
from evidenceforge.composition.models import GenerationManifestDocument
from evidenceforge.desktop.state import GenerationJob
from evidenceforge.studio.jobs import job_summary


def _input(path: Path, artifact: dict[str, object] | None = None) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"scenario": {"name": "test-1", "version": "1.0"}, "provenance": {}}
    if artifact is not None:
        data["provenance"]["artifact"] = {"kind": "scenario", "name": "test-1", **artifact}
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(root: Path, resolved_sha256: str) -> str:
    manifest = GenerationManifestDocument(
        kind="evidenceforge.generation-manifest",
        schema_version="1.0",
        created_at="2026-10-12T12:00:00Z",
        evidenceforge_version="2.2.0a2",
        runtime={},
        scenario="test-1",
        generation_seed=42,
        output_target="generic",
        formats=[],
        oob_hosts=[],
        overrides={},
        selected_packs=[],
        compiled_sha256="a" * 64,
        resolved_file_sha256=resolved_sha256,
        files={},
    )
    path = root / "GENERATION_MANIFEST.json"
    path.write_text(manifest.model_dump_json(), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("artifact", "status", "version"),
    [
        ({"status": "published", "publisher": "team", "version": "1.0.0"}, "published", "1.0.0"),
        ({"status": "draft", "draft_id": "draft-identity"}, "draft", None),
        (None, "legacy", None),
    ],
)
def test_generation_summary_uses_captured_identity_instead_of_current_version(
    tmp_path: Path, artifact: dict[str, object] | None, status: str, version: str | None
) -> None:
    frozen = tmp_path / "inputs" / "RESOLVED_SCENARIO.yaml"
    digest = _input(frozen, artifact)
    current = tmp_path / "source" / "scenario.yaml"
    _input(current, {"status": "published", "publisher": "team", "version": "9.0.0"})
    job = GenerationJob(
        id="run",
        scenario=current,
        output_root=tmp_path / "run",
        progress_file=tmp_path / "progress.jsonl",
        log_file=tmp_path / "generation.log",
        started_at=1,
        status="queued",
        input_snapshot=frozen,
        input_sha256=digest,
    )
    summary = job_summary(json.loads(job.model_dump_json()))
    assert summary["scenario_source"]["name"] == "test-1"
    assert summary["scenario_source"]["status"] == status
    assert summary["scenario_source"]["version"] == version
    current.unlink()
    assert (
        job_summary(json.loads(job.model_dump_json()))["scenario_source"]
        == summary["scenario_source"]
    )


def test_imported_bundle_identity_requires_unchanged_registered_manifest_and_resolved_bytes(
    tmp_path: Path,
) -> None:
    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    digest = _input(resolved, {"status": "published", "publisher": "team", "version": "1.0.0"})
    manifest_digest = _manifest(tmp_path, digest)
    source = captured_scenario(tmp_path, manifest_sha256=manifest_digest)
    assert source is not None and source.version == "1.0.0"
    _input(resolved, {"status": "published", "publisher": "team", "version": "9.0.0"})
    unverified = captured_scenario(tmp_path, manifest_sha256=manifest_digest)
    assert unverified is not None and unverified.status == "unknown" and unverified.version is None
    _manifest(tmp_path, hashlib.sha256(resolved.read_bytes()).hexdigest())
    assert captured_scenario(tmp_path, manifest_sha256=manifest_digest) is None


def test_identity_cache_reuses_verified_bytes_but_rejects_changed_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frozen = tmp_path / "RESOLVED_SCENARIO.yaml"
    digest = _input(frozen, {"status": "draft", "draft_id": "captured"})
    original = Path.read_bytes
    reads = 0

    def read(path: Path) -> bytes:
        nonlocal reads
        if path == frozen:
            reads += 1
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read)
    first = captured_scenario(tmp_path / "missing-run", frozen, digest)
    assert first is not None and first.draft_id == "captured"
    assert captured_scenario(tmp_path / "missing-run", frozen, digest) == first
    assert reads == 1
    frozen.write_text("scenario: {name: changed}\n", encoding="utf-8")
    assert captured_scenario(tmp_path / "missing-run", frozen, digest) is None
    assert reads == 2


def test_missing_oversize_and_malformed_sources_never_guess_a_release_version(
    tmp_path: Path,
) -> None:
    frozen = tmp_path / "RESOLVED_SCENARIO.yaml"
    assert captured_scenario(tmp_path, frozen, "a" * 64) is None
    frozen.write_text("[invalid yaml", encoding="utf-8")
    assert (
        captured_scenario(tmp_path, frozen, hashlib.sha256(frozen.read_bytes()).hexdigest()) is None
    )
    with frozen.open("wb") as handle:
        handle.truncate(64 * 1024**2 + 1)
    assert captured_scenario(tmp_path, frozen, "a" * 64) is None
