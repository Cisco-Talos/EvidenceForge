"""Queued generations retain the exact authored dependency closure."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from evidenceforge.composition.compiler import compile_scenario
from evidenceforge.desktop.controller import _worker_tick
from evidenceforge.desktop.job_store import ControlIntent
from evidenceforge.studio import jobs as jobs_module
from evidenceforge.studio.imports import dependency_health
from evidenceforge.studio.jobs import StudioJobStore, queue_studio_generation
from evidenceforge.studio.settings import StudioSettings
from evidenceforge.studio.store import StudioStore
from tests.unit.test_studio_imports import _pack, _write
from tests.unit.test_studio_service import _paths, _scenario


def test_queued_snapshot_survives_nested_include_pack_and_overlay_deletion(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "frozen", valid=True)
    data = yaml.safe_load(source.read_text())
    data.pop("version")
    data.pop("description")
    data["scenario_version"] = "2.0"
    data["includes"] = ["fragments/first.yaml"]
    data["composition"] = {
        "industries": [
            {
                "source": "project",
                "publisher": "evidenceforge",
                "name": "healthcare",
                "version": "1.0.0",
            }
        ]
    }
    _write(source, data)
    _write(source.parent / "fragments/first.yaml", {"includes": ["nested.yaml"]})
    _write(
        source.parent / "fragments/nested.yaml", {"description": "Original included description"}
    )
    pack = _pack(workspace, "industry", "healthcare")
    overlay = _write(workspace / ".eforge/config/activity/dns_registry.yaml", {"domains": []})
    paths = _paths(tmp_path / "app")
    store = StudioStore(paths.database_file)
    try:
        jobs = StudioJobStore(store, paths.state / "jobs")
        job = queue_studio_generation(jobs, source, workspace, StudioSettings(workspace=workspace))
        assert job.input_snapshot is not None
        before = compile_scenario(job.input_snapshot)
        assert job.scenario == source
        assert job.command[job.command.index("generate") + 1] == str(job.input_snapshot)
        assert job.dependency_sha256 == dependency_health(source, workspace).fingerprint
        assert job.compiled_sha256 == before.digests["compiled_sha256"]
        assert before.scenario.description == "Original included description"
        assert before.selected_packs[0].digest == pack.digest
        source.unlink()
        shutil.rmtree(source.parent / "fragments")
        shutil.rmtree(pack.root)
        overlay.unlink()
        reopened = StudioJobStore(store, jobs.directory).load_generations()[0]
        after = compile_scenario(reopened.input_snapshot)
        assert before.model_dump() == after.model_dump()
        # The real deterministic CLI validates only the frozen input after removal.
        result = subprocess.run(
            [
                *job.command[: job.command.index("generate")],
                "validate",
                str(job.input_snapshot),
                "--project-root",
                str(workspace),
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        job.progress_file.parent.mkdir(parents=True, exist_ok=True)
        generation = subprocess.run(
            job.command, capture_output=True, text=True, check=False, timeout=30
        )
        assert generation.returncode == 0, generation.stdout + generation.stderr
        generated = compile_scenario(job.output_root / "RESOLVED_SCENARIO.yaml")
        assert generated.selected_packs == before.selected_packs
        assert generated.effective_config == before.effective_config
    finally:
        store.close()


@pytest.mark.parametrize(
    "change", ["missing", "tampered", "symlink", "redirected", "empty-command", "truncated-command"]
)
def test_controller_refuses_changed_snapshot_before_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "tamper", valid=True)
    store = StudioStore(_paths(tmp_path / "app").database_file)
    try:
        jobs = StudioJobStore(store, tmp_path / "state")
        job = queue_studio_generation(jobs, source, workspace, StudioSettings(workspace=workspace))
        assert job.input_snapshot is not None
        if change == "missing":
            job.input_snapshot.unlink()
        elif change == "tampered":
            job.input_snapshot.write_text("changed")
        elif change == "symlink":
            other = tmp_path / "other.yaml"
            shutil.copyfile(job.input_snapshot, other)
            job.input_snapshot.unlink()
            job.input_snapshot.symlink_to(other)
        elif change == "redirected":
            job.command[job.command.index("generate") + 1] = str(source)
            jobs.save_generation(job)
        else:
            job.command = [] if change == "empty-command" else ["eforge", "generate"]
            jobs.save_generation(job)

        def unexpected_launch(*args: object, **kwargs: object) -> tuple[int, float]:
            raise AssertionError("A changed snapshot must never start a process")

        monkeypatch.setattr("evidenceforge.desktop.controller._start_process", unexpected_launch)
        _worker_tick(jobs, ControlIntent(action="open"))
        saved = jobs.load_generations()[0]
        assert saved.status == "failed"
        assert saved.pid == 0
        assert "Saved generation inputs" in saved.status_message
    finally:
        store.close()


def test_mid_capture_change_does_not_publish_job_or_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "changed", valid=True)
    real_compile = compile_scenario

    def changing_compile(path: Path, *, project_root: Path, context: Path | None = None) -> object:
        result = real_compile(path, project_root=project_root, context=context)
        path.write_text(path.read_text() + "\n# changed while compiling\n")
        return result

    monkeypatch.setattr(jobs_module, "compile_scenario", changing_compile)
    store = StudioStore(_paths(tmp_path / "app").database_file)
    try:
        jobs = StudioJobStore(store, tmp_path / "state")
        with pytest.raises(ValueError, match="changed while queuing"):
            queue_studio_generation(jobs, source, workspace, StudioSettings(workspace=workspace))
        assert jobs.load_generations() == []
        assert not (workspace / "runs").exists()
        assert not (jobs.directory / "inputs").exists()
    finally:
        store.close()


def test_paused_queued_job_reopens_with_captured_inputs_and_new_run_uses_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "waiting", valid=True)
    paths = _paths(tmp_path / "app")
    monkeypatch.setattr(
        "evidenceforge.desktop.controller._start_process", lambda *args, **kwargs: (0, 0.0)
    )
    store = StudioStore(paths.database_file)
    jobs = StudioJobStore(store, paths.state / "jobs")
    settings = StudioSettings(workspace=workspace)
    first = queue_studio_generation(jobs, source, workspace, settings)
    _worker_tick(jobs, ControlIntent(action="pause"))
    assert jobs.load_generations()[0].status == "paused"
    source.write_text(source.read_text().replace("Minimal test scenario", "Changed scenario"))
    second = queue_studio_generation(jobs, source, workspace, settings)
    assert first.source_sha256 != second.source_sha256
    assert first.input_sha256 != second.input_sha256
    store.close()
    reopened = StudioStore(paths.database_file)
    try:
        restored = StudioJobStore(reopened, jobs.directory)
        # Resuming one held job does not replace its command or frozen identity.
        _worker_tick(restored, ControlIntent(action="resume", resume_generation_id=first.id))
        record = next(job for job in restored.load_generations() if job.id == first.id)
        assert record.status == "queued"
        assert record.input_sha256 == first.input_sha256
        assert record.command == first.command
        assert hashlib.sha256(record.input_snapshot.read_bytes()).hexdigest() == first.input_sha256
    finally:
        reopened.close()


def test_snapshot_embeds_declaring_file_relative_email_corpus(tmp_path: Path) -> None:
    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.utils.assets import load_email_corpus_yaml

    workspace = tmp_path / "workspace"
    source = workspace / "scenarios/mail/scenario.yaml"
    raw = yaml.safe_load(Path("tests/fixtures/scenarios/northstar-health-pack.yaml").read_text())
    raw["includes"] = ["fragments/email.yaml"]
    _write(source, raw)
    _write(
        source.parent / "fragments/email.yaml",
        {"environment": {"email": {"corpus": "messages.yaml"}}},
    )
    corpus = _write(
        source.parent / "fragments/messages.yaml",
        {"messages": [{"id": "notice", "subject": "Original notice", "body": "Read this."}]},
    )
    store = StudioStore(_paths(tmp_path / "app").database_file)
    try:
        jobs = StudioJobStore(store, tmp_path / "state")
        job = queue_studio_generation(jobs, source, workspace, StudioSettings(workspace=workspace))
        corpus.unlink()
        source.unlink()
        (source.parent / "fragments/email.yaml").unlink()
        compiled = compile_scenario(job.input_snapshot)
        assert compiled.scenario.environment.email is not None
        reference = compiled.scenario.environment.email.corpus
        assert reference is not None and reference.startswith("embedded:")
        with effective_config_scope(compiled.effective_config):
            content = load_email_corpus_yaml(tmp_path / "not-present", reference)
        assert content["messages"][0]["subject"] == "Original notice"
    finally:
        store.close()


def test_snapshot_write_failure_cleans_only_unpublished_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    source = _scenario(workspace, "write-failure", valid=True)
    before = source.read_bytes()
    unrelated = workspace / "runs/keep-me/evidence.txt"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("preserve")
    store = StudioStore(_paths(tmp_path / "app").database_file)
    try:
        jobs = StudioJobStore(store, tmp_path / "state")

        def failed_write(compiled: object, directory: Path) -> Path:
            directory.mkdir(parents=True)
            (directory / ".temporary-input").write_text("partial")
            raise OSError("Snapshot write failed")

        monkeypatch.setattr(jobs_module, "write_resolved_scenario", failed_write)
        with pytest.raises(OSError, match="Snapshot write failed"):
            queue_studio_generation(jobs, source, workspace, StudioSettings(workspace=workspace))
        assert jobs.load_generations() == []
        assert list((jobs.directory / "inputs").iterdir()) == []
        assert not list((workspace / "runs").rglob(".eforge-desktop-job.json"))
        assert source.read_bytes() == before
        assert unrelated.read_text() == "preserve"
    finally:
        store.close()
