# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""eslogger's Foundation JSON spelling: escaped solidus and non-schema key order."""

import json

import pytest

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.unit.test_macos_endpoint_security_contracts import _record

_FAMILIES = ["fork", "exec", "exit", "create", "close", "rename", "unlink"]


def _keys(raw: str) -> list[str]:
    return list(json.loads(raw))


@pytest.mark.parametrize("family", _FAMILIES)
def test_native_spelling_escapes_every_solidus(family: str) -> None:
    raw = decode_endpoint_security_record(json.dumps(_record(11, family))).to_ndjson()
    assert "/" not in raw.replace("\\/", "")
    assert "\\/" in raw


@pytest.mark.parametrize("family", _FAMILIES)
def test_native_spelling_roundtrips_values_and_model(family: str) -> None:
    fields = _record(11, family)
    record = decode_endpoint_security_record(json.dumps(fields))
    raw = record.to_ndjson()
    assert raw.endswith("\n") and raw.count("\n") == 1
    assert json.loads(raw) == fields
    assert decode_endpoint_security_record(raw) == record


def test_native_spelling_is_deterministic_per_record() -> None:
    record = decode_endpoint_security_record(json.dumps(_record(11, "exec")))
    assert record.to_ndjson() == record.to_ndjson()
    assert decode_endpoint_security_record(record.to_ndjson()).to_ndjson() == record.to_ndjson()


def test_native_key_order_is_not_a_fixed_schema_order() -> None:
    orders = set()
    for mach_time in range(1, 41):
        fields = _record(11, "fork")
        fields["mach_time"] = mach_time
        orders.add(tuple(_keys(decode_endpoint_security_record(json.dumps(fields)).to_ndjson())))
    schema_order = tuple(_record(11, "fork"))
    assert len(orders) > 1
    assert orders != {schema_order}


def test_native_spelling_preserves_array_and_entitlement_order() -> None:
    fields = _record(11, "exec")
    fields["event"]["exec"]["entitlements"] = {
        f"invented.entitlement.{index}": index % 2 == 0 for index in range(8)
    }
    record = decode_endpoint_security_record(json.dumps(fields))
    native = json.loads(record.to_ndjson())
    assert list(native["event"]["exec"]["entitlements"]) == list(
        fields["event"]["exec"]["entitlements"]
    )
    assert native["event"]["exec"]["args"] == fields["event"]["exec"]["args"]
