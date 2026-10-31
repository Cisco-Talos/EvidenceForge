# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented v11 subset examples; no captured log records or private fixtures."""

import json

import pytest
from pydantic import ValidationError

from evidenceforge.formats.macos_endpoint_security import (
    ESAuditToken,
    ESExecV11,
    decode_endpoint_security_record,
)
from tests.unit.test_macos_endpoint_security_contracts import _record


@pytest.mark.parametrize("family", ["fork", "exec", "exit"])
def test_v11_preserves_original_headers_named_tokens_and_category(family: str) -> None:
    fields = _record(11, family)
    record = decode_endpoint_security_record(json.dumps(fields))
    assert json.loads(record.to_ndjson()) == fields
    assert record.version == 11
    assert isinstance(record.process.audit_token, ESAuditToken)
    assert record.process.cs_validation_category == 0
    if family == "exec":
        assert type(record.event.exec) is ESExecV11
        assert record.event.exec.entitlements is None
        assert "entitlements" in record.event.exec.model_fields_set


@pytest.mark.parametrize(
    "value",
    [[], "", False, 0, {"invented.entitlement": 1}, {"invented.entitlement": {"nested": True}}],
)
def test_v11_does_not_admit_unreviewed_nonnull_entitlements(value: object) -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["entitlements"] = value
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


def test_v11_preserves_nonempty_boolean_entitlements_without_coercion() -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["entitlements"] = {"invented.enabled": True, "invented.disabled": False}
    record = decode_endpoint_security_record(json.dumps(fields))
    assert json.loads(record.to_ndjson()) == fields
    assert dict(record.event.exec.entitlements) == fields["event"]["exec"]["entitlements"]
    fields["event"]["exec"]["entitlements"]["invented.enabled"] = False
    assert dict(record.event.exec.entitlements)["invented.enabled"] is True


def test_v11_preserves_reviewed_string_arrays_without_retaining_mutable_values() -> None:
    fields = _record(11, "exec")
    values = {
        "invented.enabled": True,
        "invented.items": ["example.one", "example.two"],
        "invented.empty": [],
    }
    fields["event"]["exec"]["entitlements"] = values
    record = decode_endpoint_security_record(json.dumps(fields))
    assert json.loads(record.to_ndjson()) == fields
    values["invented.items"].append("mutated")
    assert dict(record.event.exec.entitlements)["invented.items"] == ("example.one", "example.two")


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"invented.identity": "example.vendor"},
        {"invented.enabled": True, "invented.identity": "false", "invented.items": ["example.one"]},
    ],
)
def test_v11_preserves_empty_and_scalar_string_objects_distinct_from_null(values: dict) -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["entitlements"] = values
    record = decode_endpoint_security_record(json.dumps(fields))
    assert record.event.exec.entitlements is not None
    assert json.loads(record.to_ndjson()) == fields
    if "invented.identity" in values:
        assert type(dict(record.event.exec.entitlements)["invented.identity"]) is str


@pytest.mark.parametrize(
    "values",
    [
        {"invented.array": [1]},
        {"invented.array": [True]},
        {"invented.array": [None]},
        {"invented.array": [["nested"]]},
        {"invented.array": [{"nested": "text"}]},
        {"invented.array": ["\0"]},
        {"invented.array": ["x" * 16385]},
        {"invented.array": ["x"] * 129},
        {"invented.scalar": "\0"},
        {"invented.scalar": "x" * 16385},
        {"invented.scalar": None},
    ],
)
def test_v11_does_not_coerce_or_expand_unreviewed_array_shapes(values: object) -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["entitlements"] = values
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


@pytest.mark.parametrize(
    "values",
    [
        {f"invented.{index}": ["x"] * 128 for index in range(32)},
        {f"invented.{index}": ["x" * 10000] * 16 for index in range(8)},
    ],
)
def test_v11_entitlement_object_enforces_aggregate_node_and_text_bounds(values: dict) -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["entitlements"] = values
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


@pytest.mark.parametrize("field", ["entitlements", "dyld_exec_path", "script"])
def test_v11_exec_requires_observed_nullable_and_path_members(field: str) -> None:
    fields = _record(11, "exec")
    del fields["event"]["exec"][field]
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


@pytest.mark.parametrize("version", [6, 9])
def test_historical_exec_does_not_silently_accept_v11_entitlements(version: int) -> None:
    fields = _record(version, "exec")
    fields["event"]["exec"]["entitlements"] = None
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


@pytest.mark.parametrize("family", ["create", "rename"])
def test_v11_does_not_promote_historical_file_event_families(family: str) -> None:
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(_record(11, family)))


@pytest.mark.parametrize("family", ["fork", "exec", "exit"])
@pytest.mark.parametrize("change", ["array", "category_missing", "category_null", "full_hash"])
def test_v11_snapshot_constraints_apply_to_every_process_view(family: str, change: str) -> None:
    fields = _record(11, family)
    snapshots = [fields["process"]]
    if family == "fork":
        snapshots.append(fields["event"]["fork"]["child"])
    elif family == "exec":
        snapshots.append(fields["event"]["exec"]["target"])
    for process in snapshots:
        if change == "array":
            process["audit_token"] = list(process["audit_token"].values())
        elif change == "category_missing":
            del process["cs_validation_category"]
        elif change == "category_null":
            process["cs_validation_category"] = None
        else:
            process["cdhash_full"] = "ab" * 32
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))


def test_v11_rejects_unknown_null_fields_and_preserves_absence_in_older_codecs() -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["invented_unknown_nullable"] = None
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(fields))
    for version in (6, 9):
        native = decode_endpoint_security_record(json.dumps(_record(version, "exec")))
        assert "entitlements" not in json.loads(native.to_ndjson())["event"]["exec"]
