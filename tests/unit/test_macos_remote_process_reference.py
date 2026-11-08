"""The app graph uses invented native records, not installed apps or local logs."""

import ast
import json
from copy import deepcopy
from pathlib import Path

import pytest
from scripts import macos_remote_process_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _file, _process

ROOT = "/private/tmp/invented-code-reference/run"
MAIN = "/Applications/Invented Code.app/Contents/MacOS/Code"
HELPER = "/Applications/Invented Code.app/Contents/Helpers/Worker"


def image(path: str, inode: int, hash_char: str) -> dict:
    return {
        "paths": [path],
        "dev": 123,
        "ino": inode,
        "cdhash": hash_char * 40,
        "signing_id": "invented." + str(inode),
        "team_id": "INVENTED00",
    }


def process(pid: int, executable: dict, *, version: int = 1) -> dict:
    value = _process(11, pid)
    value["audit_token"]["pidversion"] = version
    value["executable"] = _file(executable["paths"][0])
    value["executable"]["stat"]["st_ino"] = executable["ino"]
    for name in ("cdhash", "signing_id", "team_id"):
        value[name] = executable[name]
    return value


def row(sequence: int, kind: int, actor: dict, payload: dict) -> dict:
    return {
        "global_seq_num": sequence,
        "seq_num": sequence,
        "version": 11,
        "event_type": kind,
        "process": actor,
        "event": {{9: "exec", 11: "fork", 15: "exit"}[kind]: payload},
    }


def experiment() -> tuple[kit.Graph, list[dict]]:
    main_image = image(MAIN, 3001, "a")
    helper_image = image(HELPER, 3002, "b")
    launcher_image = image("/sbin/launchd", 8000, "c")
    launcher = process(1, launcher_image)
    before = process(100, launcher_image)
    main = process(100, main_image, version=10)
    child = process(200, main_image)
    helper = process(200, helper_image, version=100)
    unrelated = process(999, launcher_image)
    rows = [
        row(1, 11, launcher, {"child": before}),
        row(
            2,
            9,
            before,
            {
                "target": main,
                "args": [
                    MAIN,
                    "--user-data-dir=" + ROOT + "/profile",
                    "--extensions-dir=" + ROOT + "/extensions",
                    ROOT + "/workspace",
                ],
            },
        ),
        row(3, 11, launcher, {"child": unrelated}),
        row(4, 11, main, {"child": child}),
        row(5, 9, child, {"target": helper, "args": [HELPER, "--type=gpu-process"]}),
        row(6, 15, helper, {"stat": 0}),
        row(7, 15, main, {"stat": 0}),
    ]
    return kit.Graph([main_image, helper_image], ROOT), rows


def test_graph_binds_root_profile_and_exact_fork_exec_exit_edges() -> None:
    graph, rows = experiment()
    for value in rows:
        graph.accept(json.dumps(value).encode())
    assert sorted(graph.rows) == [1, 2, 4, 5, 6, 7]
    assert graph.role_exec_counts["MAIN"] == graph.role_exec_counts["GPU"] == 1
    assert len(graph.births) == len(graph.closed) == 2
    assert graph.sequence_gaps == 0 and not graph.reordered and graph.unknown_images == 0


def test_ancestral_launchd_never_becomes_a_dispatch_owner_for_unrelated_children() -> None:
    graph, rows = experiment()
    for value in rows[:3]:
        graph.accept(json.dumps(value).encode())
    assert kit.identity(rows[0]["process"]) not in graph.known
    assert kit.identity(rows[2]["event"]["fork"]["child"]) not in graph.known
    assert 3 not in graph.rows


@pytest.mark.parametrize("change", ["profile", "duplicate", "file_object", "signer"])
def test_unrelated_same_app_start_does_not_authenticate_the_reference(change: str) -> None:
    graph, rows = experiment()
    value = deepcopy(rows[1])
    payload = value["event"]["exec"]
    if change == "profile":
        payload["args"][1] += "-other"
    elif change == "duplicate":
        payload["args"].append(payload["args"][1])
    elif change == "file_object":
        payload["target"]["executable"]["stat"]["st_ino"] += 1
    else:
        payload["target"]["team_id"] = "INVENTED_PRIVATE_CANARY"
    graph.accept(json.dumps(value).encode())
    assert graph.main is None and not graph.rows and not graph.known


def test_reused_pid_with_a_different_execution_cannot_join_an_owned_graph() -> None:
    graph, rows = experiment()
    for value in rows[:2]:
        graph.accept(json.dumps(value).encode())
    value = deepcopy(rows[3])
    value["process"]["audit_token"]["pidversion"] += 1
    graph.accept(json.dumps(value).encode())
    assert value["global_seq_num"] not in graph.rows


def test_authentication_diagnostics_expose_only_fixed_counts_for_exact_profile() -> None:
    graph, rows = experiment()
    value = deepcopy(rows[1])
    value["event"]["exec"]["target"]["cdhash"] = "PRIVATE_CANARY"
    graph.accept(json.dumps(value).encode())
    assert graph.main is None and not graph.rows
    assert graph.authentication_checks["profile"] == 1
    assert graph.authentication_checks["cdhash"] == 0
    assert "PRIVATE_CANARY" not in json.dumps(graph.authentication_checks)
    value["event"]["exec"]["args"][1] += "-other"
    before = dict(graph.authentication_checks)
    value["global_seq_num"] += 1
    graph.accept(json.dumps(value).encode())
    assert graph.authentication_checks == before


def test_same_process_exec_does_not_require_adjacent_global_pid_versions() -> None:
    graph, rows = experiment()
    for value in rows[:5]:
        graph.accept(json.dumps(value).encode())
    assert graph.role_exec_counts["GPU"] == 1


def test_standalone_graph_parses_in_target_python_39() -> None:
    ast.parse(Path(kit.__file__).read_text(), feature_version=(3, 9))


def test_signature_comparison_preserves_bytes_across_hex_case_and_rejects_bad_shapes() -> None:
    graph, rows = experiment()
    value = rows[1]
    value["event"]["exec"]["target"]["cdhash"] = "A" * 40
    graph.accept(json.dumps(value).encode())
    assert graph.main is not None
    assert graph.authentication_checks["cdhash"] == 0
    assert graph.authentication_checks["cdhash_bytes"] == 1
    for invalid in (None, "a" * 39, "g" * 40, "a " * 20):
        assert kit.cdhash_bytes(invalid) is None
