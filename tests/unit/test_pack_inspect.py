# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Archive validation preserves its public contract alongside lifecycle inspection."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.artifacts.lifecycle import create_new_draft, inspect_artifact, publish
from evidenceforge.artifacts.portable import export_release, read_archive
from evidenceforge.cli.commands import app
from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import PackRepository
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.composition.releases import build_efpack, validate_efpack

runner = CliRunner()


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    repository = PackRepository(tmp_path)
    pack = repository.resolve(
        PackReference(
            source="package",
            publisher="evidenceforge",
            name="metrolink-specialty-care",
            version="1.0.0",
        ),
        expected_type="organization",
    )
    path = tmp_path / "release.efpack"
    build_efpack(repository, pack, path)
    return path


@pytest.mark.parametrize("command", ["inspect", "inspect-legacy"])
def test_legacy_archive_text_and_json_contract(archive: Path, command: str) -> None:
    before = archive.read_bytes()
    validated = validate_efpack(archive)
    text = runner.invoke(app, ["pack", command, str(archive)])
    result = runner.invoke(app, ["pack", command, str(archive), "--json"])

    assert text.exit_code == 0, text.output
    assert text.output == "✓ Valid .efpack for evidenceforge/metrolink-specialty-care\n"
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "valid": True,
        "root": validated.root,
        "members": list(validated.members),
    }
    assert archive.read_bytes() == before
    assert not (archive.parent / ".eforge").exists()


@pytest.mark.parametrize(
    "case,error",
    [
        ("nonzip", "invalid .efpack ZIP archive"),
        ("missing", "No such file"),
        ("manifest", ".efpack is missing efpack.yaml"),
        ("traversal", "unsafe archive entry"),
        ("tamper", "hash mismatch"),
    ],
)
def test_invalid_archive_json_and_exit_contract(archive: Path, case: str, error: str) -> None:
    if case == "nonzip":
        archive.write_bytes(b"not a ZIP archive")
    elif case == "missing":
        archive.unlink()
    else:
        with zipfile.ZipFile(archive) as source:
            files = {name: source.read(name) for name in source.namelist()}
        if case == "manifest":
            del files["efpack.yaml"]
        elif case == "traversal":
            files["../outside.txt"] = b"unsafe"
        else:
            name = next(name for name in files if name.endswith("/pack.yaml"))
            files[name] += b"\n# modified\n"
        with zipfile.ZipFile(archive, "w") as destination:
            for name, content in files.items():
                destination.writestr(name, content)

    for arguments in (["--json"], []):
        result = runner.invoke(app, ["pack", "inspect", str(archive), *arguments])
        assert result.exit_code == 2, result.output
        if arguments:
            payload = json.loads(result.output)
            assert set(payload) == {"valid", "error"}
            assert payload["valid"] is False
            assert error in payload["error"]
        else:
            assert "Error:" in result.output and error in result.output
    assert not (archive.parent / "outside.txt").exists()
    assert not (archive.parent / ".eforge").exists()


def test_legacy_archive_accepts_other_filenames_and_read_only_symlinks(archive: Path) -> None:
    expected = json.loads(runner.invoke(app, ["pack", "inspect", str(archive), "--json"]).output)
    renamed = archive.with_name("received-release")
    archive.rename(renamed)
    link = archive.with_name("linked.efpack")
    link.symlink_to(renamed)

    for path in (renamed, link):
        result = runner.invoke(app, ["pack", "inspect", str(path), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == expected

    # The richer lifecycle path keeps its existing link protection.
    result = runner.invoke(app, ["pack", "inspect-artifact", str(link), "--json"])
    assert result.exit_code == 1, result.output
    assert "symbolic links" in json.loads(result.output)["error"]


def test_detailed_legacy_archive_inspection_remains_available(archive: Path) -> None:
    result = runner.invoke(app, ["pack", "inspect-artifact", str(archive), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == inspect_artifact(archive)
    assert json.loads(result.output)["lifecycle"]["status"] == "published"


def test_legacy_manifest_takes_precedence_over_a_receipt_named_companion(archive: Path) -> None:
    with zipfile.ZipFile(archive) as source:
        files = {name: source.read(name) for name in source.namelist()}
    document = yaml.safe_load(files["efpack.yaml"])
    files["release.json"] = b'{"description": "legacy companion"}'
    document["files"]["release.json"] = hashlib.sha256(files["release.json"]).hexdigest()
    files["efpack.yaml"] = yaml.safe_dump(document).encode()
    with zipfile.ZipFile(archive, "w") as destination:
        for name, content in files.items():
            destination.writestr(name, content)
    validated = validate_efpack(archive)
    result = runner.invoke(app, ["pack", "inspect", str(archive), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "valid": True,
        "root": validated.root,
        "members": list(validated.members),
    }


@pytest.mark.parametrize("kind", ["industry", "organization"])
def test_draft_release_reference_and_portable_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "unused-home")
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    draft = create_new_draft(
        kind,
        "example",
        description="Inspection contract fixture",
        project_root=tmp_path,
        display_name="Friendly title",
    )
    release = publish(draft, project_root=tmp_path)
    archive = export_release(release, tmp_path / "new.efpack")
    reference = f"testing:{kind}:example@1.0.0"

    for source, path in (
        (str(draft), draft),
        (str(release), release),
        (str(archive), archive),
        (reference, release),
    ):
        result = runner.invoke(
            app,
            ["pack", "inspect-artifact", source, "--project-root", str(tmp_path), "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["kind"] == kind and payload["name"] == "example"
        assert payload["display_name"] == "Friendly title"
        assert payload == inspect_artifact(path)
        if source == str(draft):
            assert payload["lifecycle"]["status"] == "draft"
            assert "version" not in payload["lifecycle"]
        else:
            assert payload["lifecycle"]["status"] == "published"
            assert payload["lifecycle"]["version"] == "1.0.0"

    receipt, _files = read_archive(archive)
    result = runner.invoke(app, ["pack", "inspect", str(archive), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "valid": True,
        "root": receipt.model_dump(mode="json"),
        "members": [receipt.model_dump(mode="json")],
    }
    with zipfile.ZipFile(archive) as source:
        files = {name: source.read(name) for name in source.namelist()}
    files[receipt.entrypoint] += b"\n# modified\n"
    with zipfile.ZipFile(archive, "w") as destination:
        for name, content in files.items():
            destination.writestr(name, content)
    result = runner.invoke(app, ["pack", "inspect", str(archive), "--json"])
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["valid"] is False and "modified" in payload["error"]
