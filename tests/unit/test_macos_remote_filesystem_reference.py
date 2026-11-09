"""Second-host reference filtering uses invented data and no local native calls."""

import ast
import json
from copy import deepcopy
from datetime import datetime

import pytest
from scripts import macos_remote_filesystem_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _file, _process

IMAGE = "/private/tmp/invented-reference/filesystem-probe"
ROOT = "/private/tmp/invented-reference/run/scratch"
CANARY = "INVENTED_PRIVATE_DO_NOT_EXPORT"


def tracker() -> kit.Tracker:
    process = _process(11)
    stamp = datetime.fromisoformat(process["start_time"].replace("Z", "+00:00"))
    return kit.Tracker(
        {
            "kind": "ready",
            "token": list(process["audit_token"].values()),
            "start_sec": int(stamp.timestamp()),
            "start_usec": stamp.microsecond,
            "image": {"dev": 123, "ino": 9001},
            "root": {"dev": 123, "ino": 700},
        },
        IMAGE,
        ROOT,
    )


def row(family: str = "close", name: str = "alpha") -> dict:
    process = _process(11)
    process["executable"] = _file(IMAGE)
    target = _file(ROOT + "/" + name)
    parent = _file(ROOT)
    parent["stat"]["st_ino"] = 700
    payloads = {
        "close": {"target": target, "modified": True, "was_mapped_writable": False},
        "create": {"destination_type": 0, "destination": {"existing_file": target}, "acl": None},
        "rename": {
            "source": target,
            "destination_type": 1,
            "destination": {"new_path": {"dir": parent, "filename": "fresh"}},
        },
        "unlink": {"target": target, "parent_dir": parent},
        "exit": {"stat": 0},
    }
    return {
        "version": 11,
        "schema_version": 1,
        "event_type": kit.EVENT_TYPES[family],
        "action_type": 1,
        "global_seq_num": 100,
        "process": process,
        "event": {family: payloads[family]},
    }


@pytest.mark.parametrize("family", kit.FAMILIES)
def test_filter_retains_only_controlled_execution_and_fixed_scratch_operations(family: str) -> None:
    state = tracker()
    assert state.accept(json.dumps(row(family)).encode())
    assert state.retained == 1 and state.counts[family] == 1
    assert state.versions == {11}


@pytest.mark.parametrize("change", ["token", "birth", "inode", "image", "truncated", "ambient"])
def test_same_pid_or_path_is_insufficient_to_admit_native_rows(change: str) -> None:
    state = tracker()
    value = row()
    if change == "token":
        value["process"]["audit_token"]["pidversion"] += 1
    elif change == "birth":
        value["process"]["start_time"] = "2026-10-19T12:30:00.000000Z"
    elif change == "inode":
        value["process"]["executable"]["stat"]["st_ino"] += 1
    elif change == "image":
        value["process"]["executable"]["path"] += "-other"
    elif change == "truncated":
        value["process"]["executable"]["path_truncated"] = True
    else:
        value["process"]["audit_token"]["pid"] += 1
    value["private"] = CANARY
    assert not state.accept(json.dumps(value).encode())
    assert state.records == [] and state.retained_bytes == 0
    assert CANARY not in repr(state)


@pytest.mark.parametrize("family", ["create", "close", "rename", "unlink"])
def test_filter_rejects_files_outside_exact_scratch_names(family: str) -> None:
    state = tracker()
    value = row(family, "alpha-outside")
    assert not state.accept(json.dumps(value).encode())
    assert not state.records


def test_rename_requires_exact_destination_directory_object() -> None:
    state = tracker()
    value = row("rename")
    value["event"]["rename"]["destination"]["new_path"]["dir"]["stat"]["st_ino"] = 999
    assert not state.accept(json.dumps(value).encode())
    value["event"]["rename"]["destination"] = {"existing_file": _file(ROOT + "/victim")}
    value["event"]["rename"]["destination_type"] = 0
    assert state.accept(json.dumps(value).encode())


def test_readiness_and_exit_require_positive_control_evidence() -> None:
    state = tracker()
    value = row("close", "ready")
    value["event"]["close"]["modified"] = False
    assert state.accept(json.dumps(value).encode()) and not state.ready
    value["event"]["close"]["modified"] = True
    assert state.accept(json.dumps(value).encode()) and state.ready
    value = row("exit")
    value["event"]["exit"]["stat"] = 256
    assert state.accept(json.dumps(value).encode()) and not state.exited
    value["event"]["exit"]["stat"] = 0
    assert state.accept(json.dumps(value).encode()) and state.exited


@pytest.mark.parametrize("raw", [b'{"key":1,"key":2}', b'{"value":NaN}', b"[]", b"bad"])
def test_bad_json_fails_with_fixed_error_without_echoing_native_text(raw: bytes) -> None:
    with pytest.raises(kit.RemoteReferenceError, match="^JSON$"):
        kit.decode(raw)


def test_retention_limits_fail_without_persisting_the_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tracker()
    assert state.accept(json.dumps(row()).encode())
    monkeypatch.setattr(kit, "MAX_RETAINED_RECORDS", 1)
    with pytest.raises(kit.RemoteReferenceError, match="^RETAINED_LIMIT$"):
        state.accept(json.dumps(row()).encode())
    assert state.retained == 1 and len(state.records) == 1


def test_stream_gaps_are_measured_before_intentional_filtering() -> None:
    state = tracker()
    first = row()
    first["process"]["audit_token"]["pid"] += 1
    assert not state.accept(json.dumps(first).encode())
    second = deepcopy(first)
    second["global_seq_num"] = 101
    assert not state.accept(json.dumps(second).encode())
    third = row()
    third["global_seq_num"] = 103
    assert state.accept(json.dumps(third).encode())
    assert state.global_gaps == 1 and state.retained == 1


def test_standalone_source_parses_on_reference_hosts_python_39() -> None:
    ast.parse(kit.Path(kit.__file__).read_text(), feature_version=(3, 9))
