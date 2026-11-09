"""CI reuse rejects mismatched, unsuccessful, untrusted and incomplete evidence."""

from __future__ import annotations

import hashlib
import io
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.request import Request

import pytest
from scripts import ci_evidence as ci
from scripts.ci_shards import ShardReport


@pytest.fixture
def evidence(monkeypatch: pytest.MonkeyPatch) -> ci.Evidence:
    monkeypatch.setenv("GITHUB_REPOSITORY", "testing/project")
    monkeypatch.setenv("CI_RUNNER", "ubuntu-latest")
    monkeypatch.setattr(ci, "source_digest", lambda reference="HEAD": "b" * 64)
    monkeypatch.setattr(ci.subprocess, "run", lambda *args, **kwargs: None)
    return ci.Evidence(
        repository="testing/project",
        check_id="routine-ubuntu-latest-plain-0",
        kind="routine",
        fingerprint="a" * 64,
        source_digest="b" * 64,
        source_sha="c" * 40,
        runner_label="ubuntu-latest",
        run_id=10,
        attempt=1,
        job_id=20,
        requirements=["Run routine shard"],
        shard=ShardReport(
            tier="routine",
            index=0,
            count=1,
            inventory=["one"],
            selected=["one"],
            outcomes={"one": "passed"},
            exit_code=0,
        ),
    )


def origin(evidence: ci.Evidence) -> tuple[dict[str, Any], dict[str, Any]]:
    run = {
        "repository": {"full_name": evidence.repository},
        "head_repository": {"full_name": evidence.repository},
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_sha": evidence.source_sha,
    }
    job = {
        "run_id": 10,
        "conclusion": "success",
        "labels": ["ubuntu-latest"],
        "completed_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
        "steps": [{"name": "Run routine shard", "conclusion": "success"}],
    }
    return run, job


def test_valid_origin_is_accepted(evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch) -> None:
    run, job = origin(evidence)
    monkeypatch.setattr(ci, "api", lambda path: job if "/jobs/" in path else run)
    ci.verify_origin(evidence, evidence.fingerprint, evidence.check_id, evidence.kind)


@pytest.mark.parametrize(
    "damage",
    [
        "fork",
        "missing-repo",
        "workflow",
        "failed",
        "cancelled",
        "step",
        "expired",
        "future",
        "runner",
        "source",
        "profile",
    ],
)
def test_invalid_origins_are_rejected(
    evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    run, job = origin(evidence)
    expected = evidence.fingerprint
    if damage == "fork":
        run["head_repository"]["full_name"] = "untrusted/fork"
    elif damage == "missing-repo":
        run["head_repository"] = None
    elif damage == "workflow":
        run["path"] = ".github/workflows/unrelated.yml"
    elif damage in {"failed", "cancelled"}:
        job["conclusion"] = damage
    elif damage == "step":
        job["steps"][0]["conclusion"] = "skipped"
    elif damage == "expired":
        job["completed_at"] = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    elif damage == "future":
        job["completed_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif damage == "runner":
        job["labels"] = ["windows-latest"]
    elif damage == "source":
        run["head_sha"] = "d" * 40
    else:
        expected = "d" * 64
    monkeypatch.setattr(ci, "api", lambda path: job if "/jobs/" in path else run)
    with pytest.raises(ValueError):
        ci.verify_origin(evidence, expected, evidence.check_id, evidence.kind)


def test_pr_evidence_must_match_the_actual_tested_merge_parents(
    evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, job = origin(evidence)
    run.update(
        event="pull_request",
        head_sha="d" * 40,
        pull_requests=[{"head": {"sha": "d" * 40}, "base": {"sha": "e" * 40}}],
    )
    monkeypatch.setattr(ci, "api", lambda path: job if "/jobs/" in path else run)
    monkeypatch.setattr(ci, "git", lambda *args: "e" * 40 + " " + "d" * 40)
    ci.verify_origin(evidence, evidence.fingerprint, evidence.check_id, evidence.kind)
    monkeypatch.setattr(ci, "git", lambda *args: "f" * 40 + " " + "d" * 40)
    with pytest.raises(ValueError, match="tested merge"):
        ci.verify_origin(evidence, evidence.fingerprint, evidence.check_id, evidence.kind)


def test_merged_pr_with_cleared_metadata_requires_equivalent_head_inputs(
    evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, job = origin(evidence)
    run.update(event="pull_request", head_sha="d" * 40, pull_requests=[])
    monkeypatch.setattr(ci, "api", lambda path: job if "/jobs/" in path else run)
    monkeypatch.setattr(ci, "git", lambda *args: "e" * 40 + " " + "d" * 40)
    ci.verify_origin(evidence, evidence.fingerprint, evidence.check_id, evidence.kind)
    monkeypatch.setattr(
        ci,
        "source_digest",
        lambda reference="HEAD": "f" * 64 if reference == "d" * 40 else "b" * 64,
    )
    with pytest.raises(ValueError, match="authenticated PR head"):
        ci.verify_origin(evidence, evidence.fingerprint, evidence.check_id, evidence.kind)


@pytest.mark.parametrize("damage", ["absent", "outcomes", "failed", "coverage"])
def test_incomplete_shard_cannot_skip_execution(evidence: ci.Evidence, damage: str) -> None:
    assert evidence.shard is not None
    damaged = evidence.model_copy(deep=True)
    if damage == "absent":
        damaged = damaged.model_copy(update={"shard": None})
    elif damage == "coverage":
        damaged = damaged.model_copy(update={"check_id": "routine-ubuntu-latest-cov-0"})
    elif damage == "outcomes":
        damaged.shard.outcomes = {}
    else:
        damaged.shard.exit_code = 1
    with pytest.raises(ValueError):
        ci.validate_shard(damaged)


def archive(evidence: ci.Evidence, extra: dict[str, bytes] | None = None) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        bundle.writestr("evidence.json", evidence.model_dump_json())
        for name, data in (extra or {}).items():
            bundle.writestr(name, data)
    return stream.getvalue()


def test_archive_paths_and_coverage_hashes_are_verified(
    evidence: ci.Evidence, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="unexpected paths"):
        ci.unpack_evidence(archive(evidence, {"../outside": b"invalid"}), tmp_path)
    hashed = evidence.model_copy(update={"coverage_sha256": hashlib.sha256(b"real").hexdigest()})
    with pytest.raises(ValueError, match="coverage bytes"):
        ci.unpack_evidence(archive(hashed, {"coverage.data": b"other"}), tmp_path)
    assert not (tmp_path / "coverage.data").exists()


def test_artifact_redirect_does_not_forward_api_credentials() -> None:
    request = Request(
        "https://api.github.com/repos/testing/project/actions/artifacts/1/zip",
        headers={"Authorization": "Bearer test-token"},
    )
    redirected = ci.ArtifactRedirect().redirect_request(
        request, io.BytesIO(), 302, "Found", Message(), "https://storage.example/artifact.zip"
    )
    assert redirected is not None
    assert redirected.get_header("Authorization") is None
    assert request.get_header("Authorization") == "Bearer test-token"


@pytest.mark.parametrize("uploader_matches", [True, False])
def test_verified_reuse_preserves_the_executed_producer(
    evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, uploader_matches: bool
) -> None:
    raw = archive(evidence)
    run, job = origin(evidence)
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(ci, "fingerprint", lambda *args: evidence.fingerprint)
    monkeypatch.setattr(
        ci,
        "source_digest",
        lambda reference="HEAD": (
            "d" * 64 if reference == "f" * 40 and not uploader_matches else "b" * 64
        ),
    )

    def api(path: str, *, binary: bool = False) -> Any:
        if path.endswith("/zip"):
            return raw
        if "/artifacts?" in path:
            return {
                "artifacts": [
                    {
                        "id": 30,
                        "expired": False,
                        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                        "workflow_run": {
                            "id": 10,
                            "repository_id": 1,
                            "head_repository_id": 1,
                            "head_sha": "f" * 40,
                        },
                    }
                ]
            }
        return job if "/jobs/" in path else run

    monkeypatch.setattr(ci, "api", api)
    assert ci.resolve(evidence.check_id, evidence.kind, tmp_path / "restored") is uploader_matches
    if not uploader_matches:
        assert not (tmp_path / "restored/evidence.json").exists()
        assert "reused=false" in output.read_text()
        return
    restored = ci.Evidence.model_validate_json((tmp_path / "restored/evidence.json").read_bytes())
    assert restored.job_id == 20
    assert restored.run_id == 10
    assert "reused=true" in output.read_text()


def test_missing_permissions_fall_back_to_execution(
    evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "outputs"))
    monkeypatch.setattr(ci, "fingerprint", lambda *args: evidence.fingerprint)

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise subprocess.CalledProcessError(1, "gh")

    monkeypatch.setattr(ci, "api", unavailable)
    assert not ci.resolve(evidence.check_id, evidence.kind, tmp_path / "fresh")
    assert "reused=false" in (tmp_path / "outputs").read_text()


def test_record_identifies_active_native_job_when_multiple_callers_share_a_run(
    evidence: ci.Evidence, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for key, value in {
        "CI_JOB_NAME": "Native recovery (ubuntu-latest)",
        "RUNNER_NAME": "active-runner",
        "GITHUB_RUN_ID": "10",
        "GITHUB_RUN_ATTEMPT": "1",
    }.items():
        monkeypatch.setenv(key, value)
    common = {
        "name": "release-ci / Native recovery (ubuntu-latest)",
        "status": "in_progress",
        "runner_name": "active-runner",
        "labels": ["ubuntu-latest"],
    }
    jobs = [
        {**common, "id": 1, "status": "completed"},
        {**common, "id": 2, "status": "queued"},
        {**common, "id": 3},
    ]
    monkeypatch.setattr(ci, "api", lambda path: {"jobs": jobs})
    monkeypatch.setattr(ci, "fingerprint", lambda *args: evidence.fingerprint)
    monkeypatch.setattr(ci, "git", lambda *args: evidence.source_sha)
    monkeypatch.setattr(ci.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    (tmp_path.parent / (tmp_path.name + ".profile")).write_text(evidence.fingerprint)
    ci.record("recovery-ubuntu-latest", "recovery", tmp_path)
    recorded = ci.Evidence.model_validate_json((tmp_path / "evidence.json").read_bytes())
    assert recorded.job_id == 3


def test_environment_drift_cannot_record_or_reupload_results(
    evidence: ci.Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(ci, "fingerprint", lambda *args: "d" * 64)
    (tmp_path.parent / (tmp_path.name + ".profile")).write_text(evidence.fingerprint)
    with pytest.raises(ValueError, match="environment changed"):
        ci.record(evidence.check_id, evidence.kind, tmp_path)


@pytest.mark.parametrize(
    ("kind", "tool"),
    [("routine", "uv"), ("studio", "node"), ("studio", "rustc"), ("portability", "resume")],
)
def test_actual_toolchain_changes_invalidate_the_result_fingerprint(
    evidence: ci.Evidence,
    monkeypatch: pytest.MonkeyPatch,
    kind: ci.KINDS,
    tool: str,
) -> None:
    for key, value in {
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos26",
        "ImageVersion": "test-image",
    }.items():
        monkeypatch.setenv(key, value)
    changed = False

    def version(command: list[str], **kwargs: Any) -> str:
        name = "resume" if command[:2] == ["uv", "run"] else command[0]
        if name == "resume":
            assert "--locked" in command and "3.13" in command
        return "new-version" if changed and name == tool else "old-version"

    monkeypatch.setattr(ci.subprocess, "check_output", version)
    before = ci.fingerprint(evidence.check_id, kind)
    changed = True
    assert ci.fingerprint(evidence.check_id, kind) != before


def test_shard_group_cannot_omit_an_entire_platform(evidence: ci.Evidence, tmp_path: Path) -> None:
    report = ShardReport(
        tier="routine",
        index=0,
        count=1,
        inventory=["one"],
        selected=["one"],
        outcomes={"one": "passed"},
        exit_code=0,
    )
    (tmp_path / "evidence.json").write_text(
        evidence.model_copy(update={"shard": report}).model_dump_json()
    )
    with pytest.raises(ValueError, match="missing a required group"):
        ci.validate_group(
            tmp_path, {"routine-ubuntu-latest-plain", "routine-windows-latest-plain"}, count=1
        )


def test_documentation_equivalence_still_invalidates_code_and_lock_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ci, "ROOT", tmp_path)

    def git(*arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=tmp_path, check=True, capture_output=True)

    git("init")
    git("config", "user.name", "CI Tests")
    git("config", "user.email", "ci@example.test")
    git("config", "commit.gpgsign", "false")
    (tmp_path / "uv.lock").write_text("locked one")
    (tmp_path / "CHANGELOG.md").write_text("old notes")
    git("add", ".")
    git("commit", "-m", "initial")
    first = ci.source_digest()
    (tmp_path / "CHANGELOG.md").write_text("new release notes")
    git("add", ".")
    git("commit", "-m", "notes")
    assert ci.source_digest() == first
    (tmp_path / "uv.lock").write_text("locked two")
    git("add", ".")
    git("commit", "-m", "dependency")
    assert ci.source_digest() != first
