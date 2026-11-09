"""Docker's offline checker uses invented records and fixed technical labels."""

import ast
import json
from pathlib import Path

import pytest
from scripts import macos_remote_docker_review as review

from tests.support.platforms import requires_posix_reference
from tests.unit.test_macos_remote_process_reference import ROOT
from tests.unit.test_macos_remote_process_review import artifact_set as code_artifact_set
from tests.unit.test_macos_remote_process_review import records


def docker_records() -> tuple[list[dict], list[dict], list[dict]]:
    rows, images = records()
    images[0]["role"], images[1]["role"] = "BACKEND", "GPU"
    root = rows[1]["event"]["exec"]
    root["args"] = [images[0]["paths"][0]]
    root["env"] = ["EFORGE_REFERENCE_RUN=" + ROOT, "ZDOTDIR=" + ROOT + "/shell", "SHELL=/bin/zsh"]
    controls = [
        {"kind": "launch", "ok": True, "pid": root["target"]["audit_token"]["pid"]},
        {"kind": "ended", "terminated": True, "forced": False},
        {"kind": "engine", "server": {"Os": "linux", "Arch": "arm64"}},
    ]
    return rows, images, controls


@requires_posix_reference
def test_native_graph_matches_application_control_and_linux_guest_stays_separate() -> None:
    rows, images, controls = docker_records()
    result = review.relationships(rows, images, ROOT, controls)
    for name in (
        "all_rows_explained",
        "exact_execution_edges",
        "wire_shapes_match",
        "launch_control_matches",
        "ordinary_exit_control",
        "linux_guest_engine_control",
    ):
        assert result[name] is True
    assert result["selected_image_exec_counts"] == {"BACKEND": 1, "GPU": 1, "UNKNOWN": 0}
    assert ROOT not in json.dumps(result)


@requires_posix_reference
def test_wrong_launch_object_cannot_become_a_positive_control() -> None:
    rows, images, controls = docker_records()
    controls[0]["pid"] += 1
    controls[1]["forced"] = True
    result = review.relationships(rows, images, ROOT, controls)
    assert not result["launch_control_matches"] and not result["ordinary_exit_control"]


@requires_posix_reference
def test_native_signalled_exit_is_preserved_as_an_observation() -> None:
    rows, images, controls = docker_records()
    rows[-1]["event"]["exit"]["stat"] = 15
    result = review.relationships(rows, images, ROOT, controls)
    assert result["exit_wait_kinds"] == {"NORMAL": 1, "SIGNALLED": 1, "OTHER": 0}


def test_offline_reviewer_supports_the_target_python39() -> None:
    ast.parse(Path(review.__file__).read_text(), feature_version=(3, 9))


def test_unknown_manifest_role_cannot_escape_as_a_private_output_label() -> None:
    rows, images, controls = docker_records()
    images[0]["role"] = "PRIVATE_CANARY"
    with pytest.raises(ValueError, match="IMAGE_ROLE"):
        review.relationships(rows, images, ROOT, controls)


@requires_posix_reference
@pytest.mark.parametrize("corruption", ["none", "code_hash", "public_file", "capture_failure"])
def test_private_docker_artifacts_and_capture_provenance_are_checked(
    tmp_path: Path, corruption: str
) -> None:
    work = code_artifact_set(tmp_path)
    (work / "shell").mkdir(mode=0o700)
    rows, images, controls = docker_records()
    rows = json.loads(json.dumps(rows).replace(ROOT, str(work)))
    (work / "native.ndjson").write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    (work / "controls.json").write_text(json.dumps(controls))
    for name in review.docker.CODE_FILES:
        path = work / "code" / name
        path.write_bytes(b"invented Docker reference source")
        path.chmod(0o600)
    report = json.loads((work / "REPORT.json").read_text())
    report.update(
        initial_stopped_control=True,
        empty_before_quit=True,
        engine_ready_control=True,
        ordinary_quit_request=True,
        stopped_control=True,
        original_running_restored=True,
    )
    (work / "REPORT.json").write_text(json.dumps(report))
    manifest = json.loads((work / "manifest.json").read_text())
    manifest.update(
        images=images,
        report=report,
        native_sha256=review.support.digest(work / "native.ndjson"),
        controls_sha256=review.support.digest(work / "controls.json"),
    )
    manifest["provenance"]["code_sha256"] = {
        name: review.support.digest(work / "code" / name) for name in review.docker.CODE_FILES
    }
    if corruption == "code_hash":
        (work / "code/docker_reference.py").write_bytes(b"changed")
    elif corruption == "public_file":
        (work / "controls.json").chmod(0o644)
    elif corruption == "capture_failure":
        report["cleanup"] = False
        (work / "REPORT.json").write_text(json.dumps(report))
    (work / "manifest.json").write_text(json.dumps(manifest))
    if corruption == "none":
        result = review.review(work)
        assert result["launch_control_matches"] and result["stream_complete_control"]
        assert result["shell_isolation_control"]
    else:
        with pytest.raises(ValueError):
            review.review(work)
