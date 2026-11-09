# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Legacy lock repair cannot rewrite source-planner occurrence times."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.windows import (
    _FROZEN_TIMING_MARKER,
    WindowsEventEmitter,
    _enforce_windows_lock_dwell_after_normalization,
    _repair_windows_lock_lifecycle_rows,
)


def _cycles() -> list[dict[str, object]]:
    at = datetime(2026, 11, 2, 18, tzinfo=UTC)
    rows: list[dict[str, object]] = []
    for minutes in (20, 40):
        for event_id, offset in ((4800, 0), (4624, 599.7), (4801, 600)):
            rows.append(
                {
                    "EventID": event_id,
                    "TimeCreated": at + timedelta(minutes=minutes, seconds=offset),
                    "Computer": "LOCK-HOST.example.test",
                    "TargetUserSid": "S-1-5-21-1-2-3-1101",
                    "TargetUserName": "operator",
                    "TargetDomainName": "EXAMPLE",
                    "TargetLogonId": "0x1234",
                    "SessionId": 2,
                    "LogonType": 7,
                    "_TimingFinalized": _FROZEN_TIMING_MARKER,
                }
            )
    # Each source lifecycle is valid in occurrence time. Producers/admissions
    # need not arrive in that order, including across deferred source groups.
    return [rows[index] for index in (3, 1, 2, 0, 4, 5)]


def test_frozen_lock_and_reauth_survive_nonchronological_admission() -> None:
    rows = _cycles()
    original = deepcopy(rows)
    assert _repair_windows_lock_lifecycle_rows(list(enumerate(rows)), {}) == set()
    assert rows == original


def test_frozen_unlock_is_not_shifted_by_legacy_delivery_state() -> None:
    rows = _cycles()
    unlock = rows[2]
    original = unlock["TimeCreated"]
    prior = {("LOCK-HOST.example.test", "0x1234", "2"): datetime(2026, 11, 2, 18, 40, tzinfo=UTC)}
    _enforce_windows_lock_dwell_after_normalization(unlock, prior)
    assert unlock["TimeCreated"] == original
    assert prior == {}


def test_mixed_raw_compatibility_rows_cannot_retime_frozen_siblings() -> None:
    rows = _cycles()
    for index in (0, 4, 5):
        rows[index].pop("_TimingFinalized")
    frozen = {index: deepcopy(rows[index]) for index in (1, 2, 3)}
    _repair_windows_lock_lifecycle_rows(list(enumerate(rows)), {})
    assert {index: rows[index] for index in frozen} == frozen


@pytest.mark.parametrize("spooled", [False, True])
def test_frozen_lock_output_preserves_source_times_in_memory_and_spool(
    tmp_path: Path, spooled: bool
) -> None:
    rows = _cycles()
    output = tmp_path / "security.xml"
    emitter = WindowsEventEmitter(load_format("windows_event_security"), output)
    for row in rows:
        emitter.emit_event(deepcopy(row))
    # Raw admission strips private markers. Model the trusted marker installed
    # by canonical rendering after the ordinary source-field normalization.
    for row in emitter._event_dicts:
        row["_TimingFinalized"] = _FROZEN_TIMING_MARKER
    if spooled:
        emitter._spool_event_dicts_unlocked()
    emitter.close()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    actual: list[tuple[int, datetime]] = []
    for event in ElementTree.parse(output).getroot():
        kind = int(event.findtext("e:System/e:EventID", namespaces=ns))
        stamp = event.find("e:System/e:TimeCreated", ns)
        assert stamp is not None
        actual.append((kind, datetime.fromisoformat(stamp.attrib["SystemTime"])))
    expected = sorted(
        [(row["EventID"], row["TimeCreated"]) for row in rows], key=lambda item: item[1]
    )
    assert actual == expected
