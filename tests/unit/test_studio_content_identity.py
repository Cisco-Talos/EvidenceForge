# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A run's content identity survives publishing its draft unchanged."""

import hashlib
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import create_draft, publish
from evidenceforge.artifacts.run_source import captured_scenario
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import (
    compiled_content_identity,
    content_identity,
    write_resolved_scenario,
)
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.desktop.state import GenerationJob
from evidenceforge.studio.contexts import context_path
from evidenceforge.studio.service import create_app
from tests.unit.test_studio_service import _paths

HEADERS = {"X-EForge-Token": "identity"}


def _draft(workspace: Path) -> Path:
    workspace.mkdir(parents=True, exist_ok=True)
    original = workspace / "scenario.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", original)
    set_publisher(
        workspace,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    return create_draft(original, project_root=workspace)


def _captured_run(draft: Path, workspace: Path, inputs: Path) -> tuple[Path, str]:
    compiled = compile_scenario(
        draft, project_root=workspace, context=context_path(draft, workspace)
    )
    snapshot = write_resolved_scenario(compiled, inputs)
    return snapshot, hashlib.sha256(snapshot.read_bytes()).hexdigest()


def test_content_identity_draft_run_and_unchanged_release_match(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    draft = _draft(workspace)
    snapshot, sha = _captured_run(draft, workspace, workspace / "run-inputs")
    run = captured_scenario(workspace / "output", snapshot, sha)
    release = publish(draft, project_root=workspace, accept_warnings=True)
    released = compile_scenario(
        release, project_root=workspace, context=context_path(release, workspace)
    )

    assert run is not None and run.status == "draft" and run.content_identity
    assert release.read_bytes() != snapshot.read_bytes()
    assert compiled_content_identity(released) == run.content_identity


def test_content_identity_ignores_pack_provenance_but_not_content() -> None:
    document = {
        "scenario": {"name": "s", "generation_seed": 1},
        "effective_config": {"logging": {}},
        "assets": {"corpora/a": "body"},
        "provenance": {
            "selected_packs": [
                {"name": "tech", "version": "1.0.0", "source": "path", "location": "a"}
            ]
        },
    }
    relocated = {
        **document,
        "provenance": {
            "selected_packs": [
                {"name": "tech", "version": "1.0.0", "source": "package", "location": "b"}
            ]
        },
    }
    edited = {**document, "scenario": {"name": "s", "generation_seed": 2}}

    assert content_identity(document) == content_identity(relocated)
    assert content_identity(document) != content_identity(edited)
    assert content_identity({"scenario": "not a mapping"}) is None


def test_snapshot_reports_current_identity_only_for_runs_with_other_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = (tmp_path / "workspace").resolve()
    draft = _draft(workspace)
    snapshot, sha = _captured_run(draft, workspace, workspace / "run-inputs")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    paths = _paths(tmp_path / "private")
    app = create_app(paths, "identity")
    with TestClient(app) as client:
        first = client.get("/v1/bootstrap", headers=HEADERS).json()
        item = next(entry for entry in first["items"] if entry["path"] == str(draft))
        assert first["content_identities"] == {}
        app.state.studio.jobs.save_generation(
            GenerationJob(
                id="draft-run",
                scenario=draft,
                output_root=workspace / "runs" / "draft-run",
                progress_file=paths.state / "jobs" / "draft-run.jsonl",
                log_file=paths.state / "jobs" / "draft-run.log",
                started_at=1,
                submitted_at=1,
                status="completed",
                workspace=workspace,
                source_sha256="captured-before-an-edit",
                dependency_sha256="captured-dependencies",
                input_snapshot=snapshot,
                input_sha256=sha,
            )
        )
        current = client.get("/v1/bootstrap", headers=HEADERS).json()

    job = next(entry for entry in current["jobs"] if entry["id"] == "draft-run")
    assert job["scenario_source"]["content_identity"]
    assert current["content_identities"][item["id"]] == job["scenario_source"]["content_identity"]
