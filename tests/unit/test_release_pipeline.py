"""Release provenance, artifact completeness, and recoverable publication contracts."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml
from scripts import release_pipeline as release
from scripts.sync_studio_version import synchronize

from tests.unit.test_studio_version import release_tree


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    root.mkdir()
    release_tree(root, "2.2.0")
    synchronize(root)
    (root / "CHANGELOG.md").write_text("## v2.2.0 (2026-10-09)\n\nChanges for testing.\n")
    for command in (
        ["git", "init", "-b", "dev"],
        ["git", "config", "user.name", "Test"],
        ["git", "config", "user.email", "test@example.invalid"],
        ["git", "add", "."],
        ["git", "commit", "-m", "test: release snapshot"],
        ["git", "init", "--bare", str(tmp_path / "origin.git")],
        ["git", "remote", "add", "origin", str(tmp_path / "origin.git")],
        ["git", "push", "origin", "dev"],
    ):
        release.run(root, command)
    return root


def tag_snapshot(root: Path, version: str, *, annotated: bool = True, push_dev: bool = True) -> str:
    release_tree(root, version)
    synchronize(root)
    (root / "CHANGELOG.md").write_text(f"## v{version} (2026-10-09)\n\nChanges.\n")
    release.run(root, ["git", "add", "."])
    release.run(root, ["git", "commit", "-m", f"chore: bump version to {version}"])
    if push_dev:
        release.run(root, ["git", "push", "origin", "dev"])
    tag = f"v{version}"
    command = ["git", "tag", "-a", tag, "-m", "Release"] if annotated else ["git", "tag", tag]
    release.run(root, command)
    release.run(root, ["git", "push", "origin", tag])
    return tag


@pytest.mark.parametrize("version", ["2.2.0a1", "2.2.0b2", "2.2.0rc1"])
def test_annotated_prerelease_on_dev_has_exact_identity(repository: Path, version: str) -> None:
    tag = tag_snapshot(repository, version)
    plan = release.prepare(repository, "push", f"refs/tags/{tag}")
    assert plan.version == version and plan.tag == tag and plan.prerelease
    assert plan.sha == release.run(repository, ["git", "rev-parse", "HEAD"])


def test_stable_main_push_and_release_pr_validate_without_writes(repository: Path) -> None:
    assert not release.prepare(repository, "push", "refs/heads/main").prerelease
    assert not release.prepare(repository, "pull_request", "refs/pull/1/merge").prerelease
    assert release.run(repository, ["git", "tag", "--list"]) == ""


def test_prerelease_requires_annotated_tag(repository: Path) -> None:
    tag = tag_snapshot(repository, "2.2.0a1", annotated=False)
    with pytest.raises(ValueError, match="must be annotated"):
        release.prepare(repository, "push", f"refs/tags/{tag}")


def test_prerelease_requires_dev_ancestry(repository: Path) -> None:
    tag = tag_snapshot(repository, "2.2.0a1", push_dev=False)
    with pytest.raises(ValueError, match="reachable from origin/dev"):
        release.prepare(repository, "push", f"refs/tags/{tag}")


@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/tags/v2.2.0a2", "refs/heads/dev"])
def test_rejects_wrong_release_entry(repository: Path, ref: str) -> None:
    tag_snapshot(repository, "2.2.0a1")
    with pytest.raises(ValueError):
        release.prepare(repository, "push", ref)


def test_existing_stable_tag_retries_exact_commit_but_blocks_release_pr(repository: Path) -> None:
    release.run(repository, ["git", "tag", "-a", "v2.2.0", "-m", "Release"])
    release.run(repository, ["git", "push", "origin", "v2.2.0"])
    assert release.prepare(repository, "push", "refs/heads/main").tag == "v2.2.0"
    with pytest.raises(ValueError, match="already exists"):
        release.prepare(repository, "pull_request", "refs/pull/1/merge")
    (repository / "extra.txt").write_text("later commit")
    release.run(repository, ["git", "add", "."])
    release.run(repository, ["git", "commit", "-m", "test: later snapshot"])
    with pytest.raises(ValueError, match="another commit"):
        release.prepare(repository, "push", "refs/heads/main")


def test_requires_matching_changelog_and_studio_versions(repository: Path) -> None:
    (repository / "CHANGELOG.md").write_text("## Unreleased\n")
    with pytest.raises(ValueError, match="nonempty"):
        release.prepare(repository, "push", "refs/heads/main")
    (repository / "desktop-ui/package.json").write_text('{"version": "0.1.0"}')
    with pytest.raises(ValueError, match="Studio version metadata differs"):
        release.prepare(repository, "push", "refs/heads/main")


def test_dirty_source_never_becomes_a_release_snapshot(repository: Path) -> None:
    (repository / "CHANGELOG.md").write_text(
        "## v2.2.0 (2026-10-09)\n\nUncommitted release notes.\n"
    )
    with pytest.raises(ValueError, match="clean committed snapshot"):
        release.prepare(repository, "push", "refs/heads/main")


@pytest.fixture
def plan() -> release.ReleasePlan:
    return release.ReleasePlan(version="2.2.0a1", tag="v2.2.0a1", sha="a" * 40, prerelease=True)


@pytest.fixture
def assets(tmp_path: Path, plan: release.ReleasePlan) -> Path:
    directory = tmp_path / "artifacts"
    directory.mkdir()
    image = directory / plan.dmg_name
    image.write_bytes(b"verified installer fixture")
    (directory / f"{image.name}.sha256").write_text(
        f"{hashlib.sha256(image.read_bytes()).hexdigest()}  {image.name}\n"
    )
    return directory


@pytest.mark.parametrize("damage", ["missing", "corrupt", "extra", "filename", "empty"])
def test_artifacts_fail_closed(assets: Path, plan: release.ReleasePlan, damage: str) -> None:
    image = assets / plan.dmg_name
    checksum = assets / f"{plan.dmg_name}.sha256"
    if damage == "missing":
        checksum.unlink()
    elif damage == "corrupt":
        image.write_bytes(b"corrupted")
    elif damage == "extra":
        (assets / "unexpected.dmg").write_bytes(b"extra")
    elif damage == "filename":
        checksum.write_text(checksum.read_text().replace(plan.dmg_name, "other.dmg"))
    else:
        image.write_bytes(b"")
    with pytest.raises(ValueError):
        release.verify_assets(assets, plan)


@pytest.fixture
def github(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, plan: release.ReleasePlan
) -> dict[str, Any]:
    state: dict[str, Any] = {"release": None, "commands": [], "fail": None, "tag_sha": plan.sha}
    uploaded = tmp_path / "uploaded"
    uploaded.mkdir()

    def fake_run(root: Path, command: list[str]) -> str:
        state["commands"].append(command)
        if state["fail"] and state["fail"] in command:
            raise subprocess.CalledProcessError(1, command)
        if command[:2] == ["gh", "api"]:
            return json.dumps(state["release"]) if state["release"] else ""
        if command[:3] == ["gh", "release", "create"]:
            notes = Path(command[command.index("--notes-file") + 1]).read_text()
            state["release"] = {
                "body": notes,
                "draft": True,
                "prerelease": "--prerelease" in command,
            }
        elif command[:3] == ["gh", "release", "upload"]:
            shutil.copyfile(command[4], uploaded / Path(command[4]).name)
        elif command[:3] == ["gh", "release", "download"]:
            destination = Path(command[command.index("--dir") + 1])
            for path in uploaded.iterdir():
                shutil.copyfile(path, destination / path.name)
            if state.get("corrupt_download"):
                (destination / plan.dmg_name).write_bytes(b"transfer corruption")
        elif command[:3] == ["gh", "release", "edit"]:
            state["release"]["draft"] = False
        elif command[:2] == ["git", "push"]:
            state["tag_sha"] = plan.sha
        return ""

    monkeypatch.setattr(release, "run", fake_run)
    monkeypatch.setattr(release, "remote_tag", lambda root, tag: state["tag_sha"])
    state["uploaded"] = uploaded
    return state


def test_publishes_only_after_upload_and_download_verification(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    (tmp_path / "CHANGELOG.md").write_text("## v2.2.0a1 (2026-10-09)\n\nAlpha changes.\n")
    release.publish(tmp_path, assets, plan, "testing/project")
    commands = github["commands"]
    assert commands[-1][:3] == ["gh", "release", "edit"]
    assert "--latest=false" in commands[-1] and "--prerelease=true" in commands[-1]
    assert sum(command[:3] == ["gh", "release", "upload"] for command in commands) == 2
    assert "--draft" in next(command for command in commands if "create" in command)
    assert any(command[:3] == ["gh", "release", "download"] for command in commands)


def test_authentication_failure_never_creates_release(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    github["fail"] = "api"
    with pytest.raises(subprocess.CalledProcessError):
        release.publish(tmp_path, assets, plan, "testing/project")
    assert not any("create" in command for command in github["commands"])


def test_upload_failure_leaves_draft_unpublished(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    (tmp_path / "CHANGELOG.md").write_text("## v2.2.0a1 (2026-10-09)\n\nAlpha changes.\n")
    github["fail"] = "upload"
    with pytest.raises(subprocess.CalledProcessError):
        release.publish(tmp_path, assets, plan, "testing/project")
    assert github["release"]["draft"]
    assert not any("edit" in command for command in github["commands"])


def test_corrupt_uploaded_installer_prevents_publication(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    (tmp_path / "CHANGELOG.md").write_text("## v2.2.0a1 (2026-10-09)\n\nAlpha changes.\n")
    github["corrupt_download"] = True
    with pytest.raises(ValueError, match="checksum"):
        release.publish(tmp_path, assets, plan, "testing/project")
    assert github["release"]["draft"]
    assert not any("edit" in command for command in github["commands"])


def test_stable_publication_creates_tag_after_verifying_build_and_marks_latest(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    stable = plan.model_copy(update={"version": "2.2.0", "tag": "v2.2.0", "prerelease": False})
    for path in assets.iterdir():
        path.rename(path.with_name(path.name.replace(plan.version, stable.version)))
    checksum = assets / f"{stable.dmg_name}.sha256"
    checksum.write_text(checksum.read_text().replace(plan.version, stable.version))
    (tmp_path / "CHANGELOG.md").write_text("## v2.2.0 (2026-10-09)\n\nStable changes.\n")
    github["tag_sha"] = None
    release.publish(tmp_path, assets, stable, "testing/project")
    commands = github["commands"]
    assert any("tag" in command and "-a" in command for command in commands)
    assert "--latest=true" in commands[-1] and "--prerelease=false" in commands[-1]


def test_partial_draft_retry_uploads_only_missing_asset(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    github["release"] = {"body": plan.marker, "draft": True, "prerelease": True, "assets": [{}]}
    shutil.copyfile(assets / plan.dmg_name, github["uploaded"] / plan.dmg_name)
    release.publish(tmp_path, assets, plan, "testing/project")
    uploads = [command for command in github["commands"] if "upload" in command]
    assert len(uploads) == 1 and uploads[0][4].endswith(".sha256")


def test_foreign_release_is_not_adopted(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    github["release"] = {"body": "A manual release", "draft": True, "prerelease": True}
    with pytest.raises(ValueError, match="not an owned"):
        release.publish(tmp_path, assets, plan, "testing/project")
    assert not any("edit" in command or "upload" in command for command in github["commands"])


@pytest.mark.parametrize("published", [False, True])
def test_retry_preserves_existing_complete_assets(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any], published: bool
) -> None:
    github["release"] = {
        "body": plan.marker,
        "prerelease": True,
        "draft": not published,
        "assets": [{"name": path.name} for path in assets.iterdir()],
    }
    for path in assets.iterdir():
        shutil.copyfile(path, github["uploaded"] / path.name)
    release.publish(tmp_path, assets, plan, "testing/project")
    assert not any("upload" in command or "create" in command for command in github["commands"])
    assert any("edit" in command for command in github["commands"]) is not published


def test_draft_with_other_build_bytes_is_never_replaced(
    tmp_path: Path, assets: Path, plan: release.ReleasePlan, github: dict[str, Any]
) -> None:
    github["release"] = {"body": plan.marker, "prerelease": True, "draft": True, "assets": [{}]}
    (github["uploaded"] / plan.dmg_name).write_bytes(b"older build")
    with pytest.raises(ValueError, match="Draft asset differs"):
        release.publish(tmp_path, assets, plan, "testing/project")
    assert not any("upload" in command or "edit" in command for command in github["commands"])


def test_workflow_joins_all_gates_and_pins_the_build_commit() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    triggers = workflow[True]  # PyYAML treats YAML 1.1 'on' as a boolean.
    assert triggers["push"] == {"branches": ["main"], "tags": ["v*"]}
    assert triggers["workflow_dispatch"]["inputs"]["tag"]["required"] is True
    jobs = workflow["jobs"]
    assert jobs["publish-release"]["needs"] == [
        "validate-release-version",
        "release-ci",
        "release-slow",
        "build-installers",
    ]
    assert jobs["release-ci"]["with"]["release-coverage"] is True
    source = "${{ needs.validate-release-version.outputs.sha }}"
    for job in ("release-ci", "release-slow"):
        assert jobs[job]["with"]["source-ref"] == source
        assert jobs[job]["if"] == "github.event_name != 'pull_request'"
    assert jobs["validate-release-version"]["steps"][0]["with"]["ref"] == (
        "${{ inputs.tag || github.sha }}"
    )
    for path in ("ci.yml", "release-slow.yml"):
        called = yaml.safe_load((root / ".github/workflows" / path).read_text())
        for job in called["jobs"].values():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("actions/checkout@"):
                    assert step["with"]["ref"] == "${{ inputs.source-ref || github.sha }}"
    for job in ("validate-release-version", "build-installers", "publish-release"):
        commands = "\n".join(step.get("run", "") for step in jobs[job]["steps"])
        assert 'GITHUB_EVENT_NAME="$RELEASE_EVENT" GITHUB_REF="$RELEASE_REF"' in commands
    for job in ("build-installers", "publish-release"):
        assert (
            jobs[job]["steps"][0]["with"]["ref"]
            == "${{ needs.validate-release-version.outputs.sha }}"
        )
    build = "\n".join(step.get("run", "") for step in jobs["build-installers"]["steps"])
    assert "--build-app --release" in build and "--skip-dmg" not in build
    assert "hdiutil verify" in build and "verify_studio_macos.py" in build
