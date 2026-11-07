"""Private reference review logic is verified only with invented relationships."""

import ast
import json
from copy import deepcopy
from pathlib import Path

import pytest
from scripts import macos_remote_filesystem_review as review

from tests.unit.test_macos_endpoint_security_contracts import _file
from tests.unit.test_macos_remote_filesystem_reference import IMAGE, ROOT, row, tracker


@pytest.mark.parametrize("phase", ["BEFORE", "AFTER", "UNCHANGED", "UNMATCHED", "UNMEASURED"])
def test_stat_phase_returns_only_fixed_labels_for_invented_before_after_controls(
    phase: str,
) -> None:
    before = {
        "dev": 1,
        "ino": 2,
        "size": 128,
        "mtime_sec": 0,
        "mtime_nsec": 123,
        "ctime_sec": 0,
        "ctime_nsec": 123,
    }
    after = before | {"size": 160, "mtime_nsec": 456, "ctime_nsec": 456}
    selected = after if phase == "AFTER" else before
    if phase == "UNCHANGED":
        after = before
    if phase == "UNMATCHED":
        selected = before | {"size": 192}
    if phase == "UNMEASURED":
        before = {"dev": 1, "ino": 2}
    native = {
        "st_dev": selected["dev"],
        "st_ino": selected["ino"],
        "st_size": selected["size"],
        "st_mtimespec": f"1970-01-01T00:00:00.{selected['mtime_nsec']:09d}Z",
        "st_ctimespec": f"1970-01-01T00:00:00.{selected['ctime_nsec']:09d}Z",
    }
    assert review.stat_phase(native, before, after) == phase


def experiment() -> tuple[list[dict], list[dict]]:
    control = tracker().control
    control["kind"] = "ready"
    objects = {
        name: {"dev": 123, "ino": 1000 + index}
        for index, name in enumerate(("alpha", "victim", "candidate"))
    }
    alpha, victim, candidate = (objects[name] for name in ("alpha", "victim", "candidate"))
    pairs = [
        (None, None, alpha),
        (alpha, alpha, alpha),
        (alpha, None, alpha),
        (None, None, victim),
        (None, None, candidate),
        (candidate, victim, candidate),
        (alpha, alpha, None),
        (candidate, candidate, None),
    ]
    controls = [control]
    for index, (before, replaced, after) in enumerate(pairs):
        controls.append(
            {
                "kind": "step",
                "step": index,
                "ok": True,
                "before": before,
                "replaced": replaced,
                "after": after,
            }
        )
    controls.append({"kind": "done"})

    def native_file(name: str, identity: str, *, size: int = 3) -> dict:
        value = _file(ROOT + "/" + name)
        value["stat"]["st_ino"] = objects[identity]["ino"]
        value["stat"]["st_size"] = size
        return value

    records = []
    for name in objects:
        value = row("create", name)
        value["event"]["create"]["destination"]["existing_file"] = native_file(name, name, size=0)
        records.append(value)
    for name, modified in (
        ("alpha", True),
        ("alpha", False),
        ("victim", True),
        ("candidate", True),
    ):
        value = row("close", name)
        value["event"]["close"]["target"] = native_file(name, name)
        value["event"]["close"]["modified"] = modified
        records.append(value)
    for name in ("alpha", "candidate"):
        value = row("rename", name)
        value["event"]["rename"]["source"] = native_file(name, name)
        if name == "candidate":
            value["event"]["rename"]["destination_type"] = 0
            value["event"]["rename"]["destination"] = {
                "existing_file": native_file("victim", "victim")
            }
        records.append(value)
    for name, identity in (("fresh", "alpha"), ("victim", "candidate")):
        value = row("unlink", name)
        value["event"]["unlink"]["target"] = native_file(name, identity)
        value["event"]["unlink"]["target"]["stat"]["st_nlink"] = 0
        records.append(value)
    records.append(row("exit"))
    for index, value in enumerate(records):
        value["time"] = "2026-10-19T12:30:00.123456789Z"
        value["mach_time"] = index + 1
        value["seq_num"] = index
        value["thread"] = {"thread_id": 1}
        value["action"] = {"result": {"result_type": 0, "result": {"auth": 0}}}
    return controls, records


def test_reference_checks_operation_identity_without_exporting_observed_values() -> None:
    controls, records = experiment()
    result = review.relationships(controls, records, IMAGE, ROOT)
    for name in (
        "controls_complete",
        "v11_shapes_match",
        "actors_match_control",
        "create_identities_match",
        "close_identities_match",
        "rename_identities_match",
        "unlink_identities_match",
        "normal_exit_matched",
    ):
        assert result[name] is True, name
    assert result["create_size_phase"] == ["EMPTY_BEFORE_WRITE"] * 3
    assert result["replacement_destination_identity"] == "REPLACED_FILE"
    assert result["unlink_link_phase"] == ["AFTER_REMOVAL"] * 2
    assert result["read_close_modified"] == "UNMODIFIED"
    assert result["write_closes_modified"] == "MODIFIED"
    assert IMAGE not in json.dumps(result) and ROOT not in json.dumps(result)


def test_same_path_with_wrong_file_object_fails_close_relationship() -> None:
    controls, records = experiment()
    close = next(item for item in records if "close" in item["event"])
    close["event"]["close"]["target"]["stat"]["st_ino"] += 999
    assert not review.relationships(controls, records, IMAGE, ROOT)["close_identities_match"]


def test_wrong_execution_and_unrecognized_fields_remain_visible_as_failed_checks() -> None:
    controls, records = experiment()
    corrupted = deepcopy(records)
    corrupted[0]["process"]["audit_token"]["pidversion"] += 1
    corrupted[0]["INVENTED_PRIVATE_CANARY"] = "INVENTED_PRIVATE_CANARY"
    result = review.relationships(controls, corrupted, IMAGE, ROOT)
    assert not result["actors_match_control"] and not result["v11_shapes_match"]
    assert "INVENTED_PRIVATE_CANARY" not in json.dumps(result)
    diagnostic = review.shape_diagnostics(corrupted)
    assert diagnostic["envelope_keys"] is False
    assert "INVENTED_PRIVATE_CANARY" not in json.dumps(diagnostic)


def test_exact_modified_close_field_types_and_null_acl_are_required() -> None:
    controls, records = experiment()
    close = next(item for item in records if "close" in item["event"])
    assert review.row_shape(close)
    close["event"]["close"]["modified"] = 1
    assert not review.row_shape(close)
    create = records[0]
    create["event"]["create"]["acl"] = "INVENTED_OTHER"
    assert not review.row_shape(create)


def test_checker_uses_reference_hosts_python_syntax() -> None:
    ast.parse(Path(review.__file__).read_text(), feature_version=(3, 9))


def test_calendar_check_does_not_require_python_311_fractional_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = review.datetime

    class Python39DateTime:
        @staticmethod
        def fromisoformat(_value: str) -> None:
            raise ValueError("Python 3.9 rejects nine fractional digits")

        strptime = original.strptime

    monkeypatch.setattr(review, "datetime", Python39DateTime)
    assert review.native_time("2000-02-29T12:00:00.123456789Z", 9)
    assert not review.native_time("2001-02-29T12:00:00.123456789Z", 9)
