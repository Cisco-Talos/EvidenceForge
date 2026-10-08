"""Properties use authored files and exact captured inputs without a GUI database."""

from __future__ import annotations

import json
import shutil
from hashlib import sha256
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge import __version__
from evidenceforge.artifacts.bundle_properties import inspect_bundle_properties
from evidenceforge.artifacts.lifecycle import (
    ArtifactError,
    create_draft,
    create_new_draft,
    inspect_artifact,
    publish,
    set_release_notes,
)
from evidenceforge.artifacts.portable import export_release, import_release
from evidenceforge.artifacts.properties import (
    MetadataEdit,
    check_artifact,
    edit_metadata,
    inspect_properties,
)
from evidenceforge.cli import app
from evidenceforge.composition.publisher import PublisherIdentity, set_publisher
from evidenceforge.schema import update_top_level


@pytest.fixture
def properties_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "empty-home")
    set_publisher(
        tmp_path,
        PublisherIdentity(publisher="testing", publisher_display_name="Tests"),
        scope="project",
        force=False,
    )
    return tmp_path


def scenario_draft(project: Path) -> Path:
    original = project / "original.yaml"
    shutil.copyfile("tests/fixtures/scenarios/minimal.yaml", original)
    return create_draft(original, project_root=project)


@pytest.mark.parametrize(
    "kind, name, version",
    [("industry", "healthcare", "1.0.0"), ("organization", "northstar-health", "1.1.0")],
)
def test_pack_properties_ignore_ancestor_runtime_release_metadata(
    properties_project: Path, kind: str, name: str, version: str
) -> None:
    runtime = properties_project / "runtime"
    runtime.mkdir()
    marker = runtime / "release.json"
    marker.write_text('{"runtime_id":"packaged-python","schema_version":1}')
    original = Path("src/evidenceforge/config/packs/evidenceforge") / kind / name / version
    folder = runtime / "lib/python/site-packages/packs" / kind / name / version
    shutil.copytree(original, folder)
    source = folder / "pack.yaml"
    before = source.read_bytes()
    properties = inspect_properties(source, project_root=properties_project)
    assert properties.name == name and properties.schema_version == "2.0"
    assert properties.validated_with is None
    draft = create_draft(source, project_root=properties_project)
    assert inspect_artifact(draft)["lifecycle"]["status"] == "draft"
    assert source.read_bytes() == before
    assert json.loads(marker.read_bytes())["runtime_id"] == "packaged-python"


@pytest.mark.parametrize("kind", ["scenario", "industry", "organization"])
def test_properties_edits_validation_and_portable_release(
    properties_project: Path, kind: str
) -> None:
    project = properties_project
    draft = (
        scenario_draft(project)
        if kind == "scenario"
        else create_new_draft(kind, "example", description="Example", project_root=project)
    )
    before = inspect_artifact(draft)
    edit_metadata(
        draft,
        MetadataEdit(
            display_name="Friendly title",
            description="Reviewed overview",
            release_notes="Initial release",
        ),
        project_root=project,
        expected_digest=before["digest"],
    )
    info = inspect_properties(draft, project_root=project)
    assert info.display_name == "Friendly title" and info.description == "Reviewed overview"
    assert info.validated_with is None
    checked = check_artifact(draft, project_root=project)
    assert checked["valid"]
    assert (
        inspect_properties(draft, project_root=project).validated_with.evidenceforge_version
        == __version__
    )
    set_release_notes(draft, "Reviewed notes")
    assert inspect_properties(draft, project_root=project).validated_with is None
    release = publish(draft, project_root=project, accept_warnings=True)
    released = inspect_properties(release, project_root=project)
    assert released.validated_with.evidenceforge_version == __version__
    assert released.lifecycle.release_notes == "Reviewed notes"
    with pytest.raises(ArtifactError, match="immutable"):
        edit_metadata(
            release,
            MetadataEdit(description="Changed"),
            project_root=project,
            expected_digest=released.digest,
        )
    archive = project / ("example.efscenario" if kind == "scenario" else "example.efpack")
    export_release(release, archive)
    imported = import_release(archive, project_root=project / "no-studio")
    portable = inspect_properties(imported, project_root=project / "no-studio")
    assert portable.validated_with == released.validated_with
    assert portable.digest == released.digest


def test_properties_stale_save_preserves_source(properties_project: Path) -> None:
    draft = scenario_draft(properties_project)
    old = inspect_artifact(draft)["digest"]
    set_release_notes(draft, "Other editor")
    before = draft.read_bytes()
    with pytest.raises(ArtifactError, match="changed after review"):
        edit_metadata(
            draft,
            MetadataEdit(display_name="Wrong"),
            project_root=properties_project,
            expected_digest=old,
        )
    assert draft.read_bytes() == before


def test_metadata_edit_preserves_include_owners_and_comments(properties_project: Path) -> None:
    draft = scenario_draft(properties_project)
    include = draft.parent / "title.yaml"
    include.write_text("# Keep this comment\ndisplay_name: Old title\ndescription: Old overview\n")
    source = draft.read_bytes()
    draft.write_bytes(
        update_top_level(source, {"includes": ["title.yaml"]}, remove={"description"})
    )
    before = inspect_artifact(draft)
    edit_metadata(
        draft,
        MetadataEdit(display_name="New title", description="New overview"),
        project_root=properties_project,
        expected_digest=before["digest"],
    )
    assert "# Keep this comment" in include.read_text()
    assert "New title" in include.read_text()
    assert not any(line.startswith("description:") for line in draft.read_text().splitlines())
    assert inspect_properties(draft, project_root=properties_project).description == "New overview"


def test_configuration_change_invalidates_validation(properties_project: Path) -> None:
    draft = scenario_draft(properties_project)
    assert check_artifact(draft, project_root=properties_project)["valid"]
    overlay = properties_project / ".eforge/config/activity/network_params.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text("dns_ttl_values: [60, 120]\n")
    assert inspect_properties(draft, project_root=properties_project).validated_with is None


def test_notes_history_distinguishes_current_draft_missing_and_published_ancestors(
    properties_project: Path,
) -> None:
    draft = scenario_draft(properties_project)
    set_release_notes(draft, "First notes")
    release = publish(draft, project_root=properties_project, accept_warnings=True)
    newer = create_draft(
        release, project_root=properties_project, publisher="new-publisher", name="forked"
    )
    set_release_notes(newer, "Draft notes")
    info = inspect_properties(newer, project_root=properties_project)
    assert any(entry.version == "1.0.0" and entry.notes == "First notes" for entry in info.history)
    assert any(entry.status == "draft" and entry.notes == "Draft notes" for entry in info.history)
    shutil.rmtree(release.parent.parent)
    missing = inspect_properties(newer, project_root=properties_project)
    assert any(entry.version == "1.0.0" and not entry.available for entry in missing.history)


def test_cli_properties_edit_and_check_without_studio(properties_project: Path) -> None:
    runner = CliRunner()
    draft = scenario_draft(properties_project)
    common = ["--project-root", str(properties_project), "--json"]
    result = runner.invoke(app, ["scenario", "properties", str(draft), *common])
    assert result.exit_code == 0, result.output
    info = json.loads(result.stdout)
    changes = properties_project / "changes.json"
    changes.write_text(json.dumps({"display_name": "CLI title", "release_notes": "CLI notes"}))
    result = runner.invoke(
        app,
        [
            "scenario",
            "edit-properties",
            str(draft),
            "--changes",
            str(changes),
            "--expected-digest",
            info["digest"],
            *common,
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["scenario", "check", str(draft), *common])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["validated_with"]["evidenceforge_version"] == __version__


def test_bundle_data_size_excludes_metadata_and_checkpoints(tmp_path: Path) -> None:
    (tmp_path / "data/host").mkdir(parents=True)
    (tmp_path / "data/host/conn.log").write_bytes(b"log data")
    (tmp_path / "GROUND_TRUTH.md").write_bytes(b"metadata")
    (tmp_path / ".eforge-generation").mkdir()
    (tmp_path / ".eforge-generation/checkpoint").write_bytes(b"checkpoint")
    (tmp_path / "data/host/external.log").symlink_to(tmp_path / "GROUND_TRUTH.md")
    info = inspect_bundle_properties(tmp_path)
    assert info.data_bytes == 8 and info.data_files == 1
    assert info.size_bytes == 26 and not info.complete
    assert info.findings


@pytest.mark.parametrize(
    "files, expected",
    [
        (["host/windows_event_security.xml"], ["windows_event_security"]),
        (["host/windows_event_sysmon.xml"], ["windows_event_sysmon"]),
        (
            ["host/windows_event_security.xml", "host/windows_event_sysmon.xml"],
            ["windows_event_security", "windows_event_sysmon"],
        ),
        (["host/ecar.json"], ["ecar"]),
        (["sensor/conn.json", "sensor/dns.json"], ["zeek_conn", "zeek_dns"]),
        (
            ["sensor/smb_files.json", "sensor/smb_mapping.json"],
            ["zeek_smb_files", "zeek_smb_mapping"],
        ),
        (
            ["host/windows_event_security_snare.log", "host/windows_event_sysmon_snare.log"],
            ["windows_event_security", "windows_event_sysmon"],
        ),
        (["host/2024/syslog.log", "sensor/2024/cisco_asa.log"], ["cisco_asa", "syslog"]),
        (["host/bash_history/user.history"], ["bash_history"]),
        ([], []),
    ],
)
@pytest.mark.parametrize("complete", [True, False])
def test_bundle_log_types_describe_present_files_instead_of_selected_groups(
    tmp_path: Path, files: list[str], expected: list[str], complete: bool
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    for name in files:
        path = data / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"log data")
    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved.write_text("scenario:\n  name: test\n")
    if complete:
        (tmp_path / "GENERATION_MANIFEST.json").write_text(
            json.dumps(
                {
                    "kind": "evidenceforge.generation-manifest",
                    "schema_version": "1.0",
                    "created_at": "2026-10-08T12:00:00Z",
                    "scenario": "test",
                    "evidenceforge_version": "2.1.2",
                    "runtime": {},
                    "generation_seed": 7,
                    "output_target": "default",
                    "formats": ["windows", "zeek", "ecar"],
                    "oob_hosts": [],
                    "overrides": {},
                    "selected_packs": [],
                    "compiled_sha256": "a" * 64,
                    "resolved_file_sha256": sha256(resolved.read_bytes()).hexdigest(),
                    "files": {},
                }
            )
        )
    info = inspect_bundle_properties(tmp_path)
    assert info.log_types == expected
    assert info.unrecognized_data_files == 0
    assert info.formats == (["windows", "zeek", "ecar"] if complete else [])
    assert info.complete is complete


def test_bundle_log_type_inspection_does_not_read_records_or_follow_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "conn.json").write_bytes(b"log data")
    (data / "other.bin").write_bytes(b"unknown data")
    (data / "dns.json").symlink_to(data / "conn.json")
    (data / "linked-directory").symlink_to(data, target_is_directory=True)
    (data / "windows_event_sysmon.xml").write_bytes(b"")

    def no_log_reads(*args: object, **kwargs: object) -> None:
        pytest.fail("Inspecting log types must not read log records")

    monkeypatch.setattr(Path, "open", no_log_reads)
    info = inspect_bundle_properties(tmp_path)
    assert info.log_types == ["windows_event_sysmon", "zeek_conn"]
    assert info.data_files == 3
    assert info.unrecognized_data_files == 1
