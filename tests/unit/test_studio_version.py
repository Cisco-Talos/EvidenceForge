"""Shared product release identity and cross-ecosystem prerelease contracts."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from scripts.sync_studio_version import studio_version, synchronize


def release_tree(root: Path, version: str) -> None:
    files = {
        "pyproject.toml": f'[project]\nversion = "{version}"\n',
        "src/evidenceforge/__init__.py": f'__version__ = "{version}"\n',
        "uv.lock": f'[[package]]\nname = "evidence-forge"\nversion = "{version}"\n',
        "desktop-ui/package.json": '{"name": "desktop-ui", "version": "0.1.0"}\n',
        "desktop-ui/package-lock.json": json.dumps(
            {
                "version": "0.1.0",
                "packages": {"": {"version": "0.1.0"}, "node_modules/vite": {"version": "8.0.1"}},
            },
            indent=2,
        )
        + "\n",
        "desktop-ui/src-tauri/tauri.conf.json": '{"version": "0.1.0"}\n',
        "desktop-ui/src-tauri/Cargo.toml": '[package]\nname = "evidenceforge-studio"\nversion = "0.1.0"\n',
        "desktop-ui/src-tauri/Cargo.lock": '[[package]]\nname = "evidenceforge-studio"\nversion = "0.1.0"\n\n[[package]]\nname = "tauri"\nversion = "2.12.0"\n',
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.2.0", "2.2.0"),
        ("2.2.0a0", "2.2.0-alpha.0"),
        ("2.2.0a1", "2.2.0-alpha.1"),
        ("2.2.0a12", "2.2.0-alpha.12"),
        ("2.2.0b2", "2.2.0-beta.2"),
        ("2.2.0rc1", "2.2.0-rc.1"),
    ],
)
def test_studio_release_sync_preserves_engine_and_dependency_versions(
    tmp_path: Path, version: str, expected: str
) -> None:
    release_tree(tmp_path, version)
    assert synchronize(tmp_path) == version
    assert synchronize(tmp_path, check=True) == version
    assert json.loads((tmp_path / "desktop-ui/package.json").read_text())["version"] == expected
    lock = json.loads((tmp_path / "desktop-ui/package-lock.json").read_text())
    assert lock["version"] == expected
    assert lock["packages"][""]["version"] == expected
    assert lock["packages"]["node_modules/vite"]["version"] == "8.0.1"
    assert f'version = "{expected}"' in (tmp_path / "desktop-ui/src-tauri/Cargo.toml").read_text()
    assert (
        json.loads((tmp_path / "desktop-ui/src-tauri/tauri.conf.json").read_text())["version"]
        == expected
    )
    assert f'version = "{expected}"' in (tmp_path / "desktop-ui/src-tauri/Cargo.lock").read_text()
    assert (
        'name = "tauri"\nversion = "2.12.0"'
        in (tmp_path / "desktop-ui/src-tauri/Cargo.lock").read_text()
    )
    assert f'__version__ = "{version}"' in (tmp_path / "src/evidenceforge/__init__.py").read_text()


def test_studio_release_check_rejects_drift_without_writes(tmp_path: Path) -> None:
    release_tree(tmp_path, "2.2.0")
    before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    with pytest.raises(ValueError, match="Studio version metadata differs"):
        synchronize(tmp_path, check=True)
    assert all(path.read_bytes() == content for path, content in before.items())


def test_studio_release_sync_rejects_engine_drift_before_writes(tmp_path: Path) -> None:
    release_tree(tmp_path, "2.2.0")
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "evidence-forge"\nversion = "2.1.2"\n')
    with pytest.raises(ValueError, match="uv.lock version"):
        synchronize(tmp_path)
    assert json.loads((tmp_path / "desktop-ui/package.json").read_text())["version"] == "0.1.0"


@pytest.mark.parametrize(
    "version",
    [
        "2.0.0-rc1",
        "2.0",
        "2.0.0.dev1",
        "2.2.0a",
        "2.2.0b",
        "2.2.0rc",
        "2.2.0-alpha.1",
        "2.2.0beta1",
        "2.2.0a01",
        "02.2.0a1",
        "2.2.0a1+local",
    ],
)
def test_studio_version_rejects_noncanonical_release_versions(version: str) -> None:
    with pytest.raises(ValueError, match="must be X.Y.Z, X.Y.ZaN, X.Y.ZbN or X.Y.ZrcN"):
        studio_version(version)


@pytest.fixture(params=["validate-release-version", "publish-release"])
def release_guard_script(request: pytest.FixtureRequest) -> str:
    workflow = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
    steps = yaml.safe_load(workflow.read_text())["jobs"][request.param]["steps"]
    command = next(step["run"] for step in steps if step.get("name") == "Read release version")
    return command.removeprefix("python - <<'PY'\n").removesuffix("PY\n")


@pytest.mark.parametrize("version", ["2.2.0", "2.2.0a1", "2.2.0b2", "2.2.0rc1"])
def test_release_workflow_guard_accepts_prereleases_and_preserves_tag_identity(
    tmp_path: Path, release_guard_script: str, version: str
) -> None:
    release_tree(tmp_path, version)
    output = tmp_path / "github-output"
    result = subprocess.run(
        [sys.executable, "-c", release_guard_script],
        cwd=tmp_path,
        env={**os.environ, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_text().splitlines() == [f"version={version}", f"tag=v{version}"]


@pytest.mark.parametrize("version", ["2.2.0a", "2.2.0-alpha.1", "2.2.0a01"])
def test_release_workflow_guard_rejects_noncanonical_prereleases(
    tmp_path: Path, release_guard_script: str, version: str
) -> None:
    release_tree(tmp_path, version)
    output = tmp_path / "github-output"
    result = subprocess.run(
        [sys.executable, "-c", release_guard_script],
        cwd=tmp_path,
        env={**os.environ, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "version must be" in result.stdout
    assert not output.exists()


@pytest.mark.parametrize("relative", ["src/evidenceforge/__init__.py", "uv.lock"])
def test_release_workflow_guard_rejects_prerelease_version_drift(
    tmp_path: Path, release_guard_script: str, relative: str
) -> None:
    release_tree(tmp_path, "2.2.0a1")
    path = tmp_path / relative
    path.write_text(path.read_text().replace("2.2.0a1", "2.2.0a2"))
    output = tmp_path / "github-output"
    result = subprocess.run(
        [sys.executable, "-c", release_guard_script],
        cwd=tmp_path,
        env={**os.environ, "GITHUB_OUTPUT": str(output)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "does not match pyproject.toml" in result.stdout
    assert not output.exists()
