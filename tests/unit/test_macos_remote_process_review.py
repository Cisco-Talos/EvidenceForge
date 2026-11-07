"""Offline process reference checks use independently invented native records."""

import ast
import json
from copy import deepcopy
from pathlib import Path

import pytest
from scripts import macos_remote_process_review as review

from tests.support.platforms import requires_posix_reference
from tests.unit.test_macos_endpoint_security_contracts import _record
from tests.unit.test_macos_remote_process_reference import ROOT, experiment


def records() -> tuple[list[dict], list[dict]]:
    graph, simple = experiment()
    rows = []
    for item in simple:
        if item["global_seq_num"] == 3:
            continue  # unrelated launchd child was discarded before persistence
        family = {9: "exec", 11: "fork", 15: "exit"}[item["event_type"]]
        value = _record(11, family)
        value.update({key: entry for key, entry in item.items() if key != "event"})
        value["event"][family].update(item["event"][family])
        if family == "exec":
            value["event"][family]["image_cputype"] = 16777228
        rows.append(value)
    root = next(item for item in rows if item["global_seq_num"] == 2)["event"]["exec"]
    root["args"].append("--force-disable-user-env")
    root["env"] = ["ZDOTDIR=" + ROOT + "/shell", "VSCODE_CLI=1"]
    return rows, graph.images


def test_independent_graph_review_checks_shapes_edges_and_controls_without_values() -> None:
    rows, images = records()
    result = review.relationships(rows, images, ROOT)
    for name in (
        "wire_shapes_match",
        "all_rows_explained",
        "exact_execution_edges",
        "ordered_source_sequences",
        "all_execs_arm64",
        "main_birth_observed",
        "main_exit_observed",
        "shell_isolation_control",
    ):
        assert result[name] is True, name
    assert result["open_lifetimes"] == 0
    assert result["role_exec_counts"]["MAIN"] == 1
    assert result["role_exec_counts"]["GPU"] == 1
    assert ROOT not in json.dumps(result)


def test_unrelated_ancestral_child_cannot_pass_independent_ownership_review() -> None:
    rows, images = records()
    graph, simple = experiment()
    unrelated = deepcopy(rows[0])
    unrelated.update(simple[2])
    rows.insert(2, unrelated)
    result = review.relationships(rows, images, ROOT)
    assert not result["all_rows_explained"] and not result["exact_execution_edges"]


def test_unmeasured_main_birth_and_censored_helper_are_reported_without_invention() -> None:
    rows, images = records()
    rows = [item for item in rows if item["global_seq_num"] not in {1, 6}]
    result = review.relationships(rows, images, ROOT)
    assert not result["main_birth_observed"]
    assert result["main_exit_observed"]
    assert result["open_lifetimes"] == 1


def test_unrecognized_wire_fields_and_lost_shell_isolation_fail_closed() -> None:
    rows, images = records()
    value = rows[1]["event"]["exec"]
    value["PRIVATE_CANARY"] = "PRIVATE_CANARY"
    value["env"] = []
    result = review.relationships(rows, images, ROOT)
    assert not result["wire_shapes_match"] and not result["shell_isolation_control"]
    assert "PRIVATE_CANARY" not in json.dumps(result)


def test_offline_checker_is_python39_compatible() -> None:
    ast.parse(Path(review.__file__).read_text(), feature_version=(3, 9))


def artifact_set(tmp_path: Path) -> Path:
    work = tmp_path / "vscode-run-invented"
    work.mkdir(mode=0o700)
    for name in ("code", "workspace", "extensions"):
        (work / name).mkdir(mode=0o700)
    extension = work / "extensions/evidenceforge.native-reference-0.0.1"
    extension.mkdir(mode=0o700)

    def write(path: Path, value: bytes) -> None:
        path.write_bytes(value)
        path.chmod(0o600)

    rows, images = records()
    rows = json.loads(json.dumps(rows).replace(ROOT, str(work)))
    write(work / "native.ndjson", b"\n".join(json.dumps(row).encode() for row in rows) + b"\n")
    controls = [
        {"kind": "launch", "ok": True},
        {"kind": "ended", "terminated": True, "forced": False},
    ]
    write(work / "controls.json", json.dumps(controls).encode())
    for name in review.capture.CODE_FILES:
        write(work / "code" / name, b"independently invented source or binary")
    write(
        extension / "reference.json", json.dumps({"root": str(work), "nonce": "invented"}).encode()
    )
    for name, fields in (
        ("workflow-control.json", {"saved": True, "second": True}),
        ("second-window.json", {"ready": True}),
        ("save-control.json", {"saved": True}),
    ):
        write(work / name, json.dumps(dict(fields, nonce="invented")).encode())
    write(work / "workspace/example.txt", b"reference save complete\n")
    report = dict.fromkeys(
        (
            "collector_ready",
            "app_launch_control",
            "save_control",
            "second_window_control",
            "ordinary_quit",
            "cleanup",
            "installed_code_unchanged",
        ),
        True,
    )
    report.update(error="NONE", stream_sequence_gaps=0, stream_sequence_reordered=False)
    write(work / "REPORT.json", json.dumps(report).encode())
    manifest = {
        "root": str(work),
        "images": images,
        "report": report,
        "native_sha256": review.support.digest(work / "native.ndjson"),
        "controls_sha256": review.support.digest(work / "controls.json"),
        "provenance": {
            "code_sha256": {
                name: review.support.digest(work / "code" / name)
                for name in review.capture.CODE_FILES
            }
        },
    }
    write(work / "manifest.json", json.dumps(manifest).encode())
    return work


@requires_posix_reference
@pytest.mark.parametrize("damage", ["native_hash", "permissions", "missing_source", "nonce"])
def test_artifact_authentication_rejects_tampering_and_incomplete_provenance(
    tmp_path: Path, damage: str
) -> None:
    work = artifact_set(tmp_path)
    assert review.review(work)["workflow_controls_match"]
    if damage == "native_hash":
        with (work / "native.ndjson").open("ab") as output:
            output.write(b"{}\n")
    elif damage == "permissions":
        (work / "controls.json").chmod(0o644)
    elif damage == "missing_source":
        path = work / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["provenance"]["code_sha256"].pop("vscode_extension.js")
        path.write_text(json.dumps(manifest))
    else:
        (work / "second-window.json").write_text(json.dumps({"nonce": "OTHER", "ready": True}))
    with pytest.raises(ValueError):
        review.review(work)
