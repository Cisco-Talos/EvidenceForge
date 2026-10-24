# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored wire examples, with no public or personal captured records."""

import json
from copy import deepcopy

import pytest
from pydantic import ValidationError

from evidenceforge.formats.macos_endpoint_security import (
    ESAuditToken,
    ESExecEvent,
    ESForkEvent,
    ESRenameEvent,
    ESRenameNew,
    decode_endpoint_security_record,
)

_TIME = "2026-10-19T12:30:00.123456789Z"


def _file(path: str = "/usr/local/bin/example") -> dict[str, object]:
    return {
        "path": path,
        "path_truncated": False,
        "stat": {
            "st_dev": 123,
            "st_mode": 33261,
            "st_nlink": 1,
            "st_ino": 9001,
            "st_uid": 501,
            "st_gid": 20,
            "st_rdev": 0,
            "st_atimespec": _TIME,
            "st_mtimespec": _TIME,
            "st_ctimespec": _TIME,
            "st_birthtimespec": _TIME,
            "st_size": 4096,
            "st_blocks": 8,
            "st_blksize": 4096,
            "st_flags": 0,
            "st_gen": 0,
        },
    }


def _token(version: int, pid: int) -> dict[str, int] | list[int]:
    values = {
        "auid": 501,
        "euid": 501,
        "egid": 20,
        "ruid": 501,
        "rgid": 20,
        "pid": pid,
        "asid": 100001,
        "pidversion": pid + 10000,
    }
    return list(values.values()) if version == 10 else values


def _process(version: int, pid: int = 1200, ppid: int = 1190) -> dict[str, object]:
    result: dict[str, object] = {
        "audit_token": _token(version, pid),
        "parent_audit_token": _token(version, ppid),
        "responsible_audit_token": _token(version, 1100),
        "ppid": ppid,
        "original_ppid": ppid,
        "group_id": 1190,
        "session_id": 1100,
        "codesigning_flags": 0,
        "is_platform_binary": False,
        "is_es_client": False,
        "executable": _file(),
        "tty": None,
        "start_time": "2026-10-19T12:29:59.123456Z",
        "signing_id": None,
        "team_id": None,
        "cdhash": "0" * 40,
    }
    if version in {10, 11}:
        result["cs_validation_category"] = 0
    return result


def _record(version: int = 10, family: str = "fork") -> dict[str, object]:
    process = _process(version)
    if family == "fork":
        event = {"child": _process(version, 1201, 1200)}
    elif family == "exec":
        target = _process(version)
        token = target["audit_token"]
        assert isinstance(token, dict)
        token["pidversion"] += 1
        target["executable"] = _file("/usr/bin/id")
        event = {
            "target": target,
            "script": None,
            "cwd": _file("/Users/alex"),
            "args": ["id", "-u"],
            "env": [],
            "fds": [{"fd": 0, "fdtype": 1}],
            "last_fd": 0,
            "image_cputype": 16777228,
            "image_cpusubtype": 0,
        }
        if version in {9, 11}:
            event["dyld_exec_path"] = "/usr/bin/id"
        if version == 11:
            event["entitlements"] = None
    elif family == "exit":
        event = {"stat": 256}
    elif family == "create":
        event = {
            "destination_type": 0,
            "destination": {"existing_file": _file("/tmp/example")},
            "acl": None,
        }
    else:
        event = {
            "source": _file("/tmp/old"),
            "destination_type": 1,
            "destination": {"new_path": {"dir": _file("/tmp"), "filename": "new"}},
        }
    return {
        "schema_version": 1,
        "version": version,
        "event_type": {"exec": 9, "fork": 11, "create": 13, "exit": 15, "rename": 25}[family],
        "action_type": 1,
        "action": {"result": {"result_type": 0, "result": {"auth": 0}}},
        "time": _TIME,
        "mach_time": 24000000,
        "seq_num": 7,
        "global_seq_num": 19,
        "thread": {"thread_id": 90001},
        "process": process,
        "event": {family: event},
    }


@pytest.mark.parametrize(
    ("version", "family"),
    [
        (6, "fork"),
        (6, "exec"),
        (6, "create"),
        (6, "rename"),
        (9, "exec"),
        (9, "exit"),
        (10, "fork"),
        (11, "fork"),
        (11, "exec"),
        (11, "exit"),
    ],
)
def test_versioned_native_record_roundtrips_without_new_fields(version: int, family: str) -> None:
    fields = _record(version, family)
    record = decode_endpoint_security_record(json.dumps(fields))
    assert json.loads(record.to_ndjson()) == fields
    assert record.time.endswith("123456789Z")
    assert record.action_type == 1  # Observation, not an authorization callback stream.
    with pytest.raises(ValidationError):
        record.version = 10


def test_exec_preserves_pre_and_post_identity_and_cpu_metadata() -> None:
    record = decode_endpoint_security_record(json.dumps(_record(9, "exec")))
    assert isinstance(record.event, ESExecEvent)
    before, after = record.process.audit_token, record.event.exec.target.audit_token
    assert isinstance(before, ESAuditToken) and isinstance(after, ESAuditToken)
    assert before.pid == after.pid
    assert before.pidversion != after.pidversion
    assert record.event.exec.target.start_time == record.process.start_time
    assert record.event.exec.image_cputype == 16777228
    assert record.event.exec.target.executable.path != record.process.executable.path
    assert "dyld_exec_path" in record.event.exec.model_fields_set


def test_array_audit_tokens_preserve_parent_and_responsible_roles() -> None:
    record = decode_endpoint_security_record(json.dumps(_record()))
    assert isinstance(record.event, ESForkEvent)
    child = record.event.fork.child
    assert child.audit_token != child.parent_audit_token
    assert child.parent_audit_token == record.process.audit_token
    assert child.responsible_audit_token != child.parent_audit_token
    assert isinstance(child.audit_token, tuple) and len(child.audit_token) == 8


def test_rename_variants_preserve_directory_name_instead_of_fabricating_existing_file() -> None:
    fields = _record(6, "rename")
    record = decode_endpoint_security_record(json.dumps(fields))
    assert isinstance(record.event, ESRenameEvent)
    assert isinstance(record.event.rename, ESRenameNew)
    assert record.event.rename.destination.new_path.filename == "new"
    fields["event"]["rename"]["destination_type"] = 0
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))
    fields["event"]["rename"]["destination"] = {"existing_file": _file("/tmp/replaced")}
    assert json.loads(decode_endpoint_security_record(json.dumps(fields)).to_ndjson()) == fields


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 11),
        ("version", "10"),
        ("version", True),
        ("schema_version", 2),
        ("schema_version", True),
        ("action_type", 0),
        ("action_type", True),
        ("event_type", 15),
        ("event_type", 9),
        ("event_type", 25),
        ("event_type", 999),
        ("seq_num", -1),
        ("global_seq_num", "19"),
        ("mach_time", 1 << 64),
        ("time", "2026-02-30T12:30:00.123456789Z"),
        ("time", "2026-10-19T12:30:00.123456Z"),
        ("future_field", "unsupported"),
    ],
)
def test_unsupported_version_family_and_invalid_native_values_are_rejected(
    field: str, value: object
) -> None:
    fields = _record()
    fields[field] = value
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


@pytest.mark.parametrize(
    "mutation",
    [
        "old_token",
        "token_width",
        "token_bool",
        "missing_category",
        "null_category",
        "content_hash",
        "null_signing_absent",
        "stat_fraction",
        "stat_time",
        "notification_auth_bool",
    ],
)
def test_process_optional_and_required_wire_fields_are_not_conflated(mutation: str) -> None:
    fields = _record()
    process = fields["process"]
    if mutation == "old_token":
        process["audit_token"] = _token(9, 1200)
    elif mutation == "token_width":
        process["audit_token"].pop()
    elif mutation == "token_bool":
        process["audit_token"][0] = True
    elif mutation == "missing_category":
        del process["cs_validation_category"]
    elif mutation == "null_category":
        process["cs_validation_category"] = None
    elif mutation == "content_hash":
        process["cdhash"] = "a" * 64
    elif mutation == "null_signing_absent":
        del process["signing_id"]
    elif mutation == "stat_fraction":
        process["executable"]["stat"]["st_size"] = 1.5
    elif mutation == "stat_time":
        process["executable"]["stat"]["st_birthtimespec"] = "2026-10-19T99:00:00.000000000Z"
    else:
        fields["action"]["result"]["result"]["auth"] = False
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


def test_historical_profiles_reject_future_fields_and_null_dyld() -> None:
    fields = _record(6, "exec")
    fields["event"]["exec"]["dyld_exec_path"] = "/usr/bin/id"
    with pytest.raises(ValidationError, match="dyld path presence"):
        decode_endpoint_security_record(json.dumps(fields))
    fields = _record(9, "exec")
    fields["event"]["exec"]["dyld_exec_path"] = None
    with pytest.raises(ValidationError, match="string dyld path"):
        decode_endpoint_security_record(json.dumps(fields))
    fields = _record(9, "exit")
    changed = deepcopy(fields)
    changed["process"]["cs_validation_category"] = 0
    with pytest.raises(ValidationError, match="category presence"):
        decode_endpoint_security_record(json.dumps(changed))
    assert json.loads(decode_endpoint_security_record(json.dumps(fields)).to_ndjson()) == fields


def test_exec_pipe_descriptor_retains_its_separate_native_identity() -> None:
    fields = _record(6, "exec")
    fields["event"]["exec"]["fds"].append({"fd": 1, "fdtype": 6, "pipe": {"pipe_id": 12345}})
    record = decode_endpoint_security_record(json.dumps(fields))
    assert json.loads(record.to_ndjson()) == fields
    fields["event"]["exec"]["fds"][-1]["fdtype"] = 1
    with pytest.raises(ValidationError, match="pipe descriptor"):
        decode_endpoint_security_record(json.dumps(fields))
