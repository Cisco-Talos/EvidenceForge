"""Bounded repository cleanup and prevention of renewed project-state tracking."""

import subprocess
from pathlib import Path

import pytest
import yaml
from scripts.check_eforge_cleanup import git, is_eforge_cleanup

IGNORE = "# Local state\n.eforge/\n!.eforge/\n.eforge/*\n!.eforge/packs/\n.env\n"


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    git(tmp_path, "init")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    git(tmp_path, "config", "core.autocrlf", "false")
    state = tmp_path / ".eforge" / "packs"
    state.mkdir(parents=True)
    (state / "pack.yaml").write_text("name: local\n", encoding="utf-8")
    (state / "pack.lock.yaml").write_text("lock: local\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(IGNORE, encoding="utf-8")
    git(tmp_path, "add", "--force", ".")
    git(tmp_path, "commit", "-m", "test: tracked local state")
    base = git(tmp_path, "rev-parse", "HEAD").strip()
    git(tmp_path, "rm", "--cached", "-r", ".eforge")
    (tmp_path / ".gitignore").write_text("# Local state\n.eforge/\n.env\n", encoding="utf-8")
    return tmp_path, base


def commit(root: Path) -> None:
    git(root, "add", ".")
    git(root, "commit", "-m", "chore: clean local state")


def test_cleanup_preserves_local_files_and_qualifies_once(repository: tuple[Path, str]) -> None:
    root, base = repository
    commit(root)
    assert is_eforge_cleanup(root, base)
    assert (root / ".eforge/packs/pack.yaml").read_text(encoding="utf-8") == "name: local\n"
    assert not is_eforge_cleanup(root, git(root, "rev-parse", "HEAD").strip())


@pytest.mark.parametrize(
    "path",
    ["src/evidenceforge/engine.py", "pyproject.toml", "uv.lock", "CHANGELOG.md", "README.md"],
)
def test_product_or_version_changes_require_release(
    repository: tuple[Path, str], path: str
) -> None:
    root, base = repository
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("product change\n", encoding="utf-8")
    commit(root)
    assert not is_eforge_cleanup(root, base)


@pytest.mark.parametrize("path", [".eforge/packs/pack.yaml", ".eforge/new.yaml"])
def test_retained_or_added_state_does_not_qualify(repository: tuple[Path, str], path: str) -> None:
    root, base = repository
    destination = root / path
    destination.write_text("new state\n", encoding="utf-8")
    git(root, "add", "--force", path)
    commit(root)
    assert not is_eforge_cleanup(root, base)


@pytest.mark.parametrize("extra", ["!.eforge/packs/\n", "src/\n", "!.env\n"])
def test_other_ignore_changes_do_not_qualify(repository: tuple[Path, str], extra: str) -> None:
    root, base = repository
    with (root / ".gitignore").open("a", encoding="utf-8") as stream:
        stream.write(extra)
    commit(root)
    assert not is_eforge_cleanup(root, base)


def test_guard_bootstrap_files_can_accompany_cleanup(repository: tuple[Path, str]) -> None:
    root, base = repository
    for path in ("scripts/check_eforge_cleanup.py", "tests/unit/test_eforge_cleanup.py"):
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("# Guard bootstrap\n", encoding="utf-8")
    commit(root)
    assert is_eforge_cleanup(root, base)


def test_missing_base_fails_closed(repository: tuple[Path, str]) -> None:
    root, _ = repository
    commit(root)
    with pytest.raises(subprocess.CalledProcessError):
        is_eforge_cleanup(root, "a" * 40)
    assert not is_eforge_cleanup(root, "0" * 40)
    assert not is_eforge_cleanup(root, "--invalid")


def test_project_state_is_not_tracked_and_old_exceptions_are_ignored() -> None:
    root = Path(__file__).resolve().parents[2]
    assert not git(root, "ls-files", "--", ".eforge")
    for path in (
        ".eforge/config/activity/custom.yaml",
        ".eforge/packs/organization/meridian-healthcare-solutions/1.0.0/pack.yaml",
        ".eforge/packs/davidjbianco/organization/meridian-healthcare-solutions/1.1.0/pack.yaml",
    ):
        assert git(root, "check-ignore", "--no-index", path).strip() == path


def test_every_publishing_job_requires_non_cleanup_scope() -> None:
    root = Path(__file__).resolve().parents[2]
    jobs = yaml.safe_load((root / ".github/workflows/release.yml").read_text())["jobs"]
    for name in ("validate-release-version", "publish-release", "release-ci", "release-slow"):
        if name in jobs:
            assert "release-scope" in jobs[name]["needs"]
            assert "needs.release-scope.outputs.cleanup != 'true'" in jobs[name]["if"]
    assert jobs["release-scope"]["permissions"] == {"contents": "read"}
