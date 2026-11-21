# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Legacy lock repair cannot rewrite source-planner occurrence times."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.windows import (
    _FROZEN_TIMING_MARKER,
    WindowsEventEmitter,
    _enforce_windows_lock_dwell_after_normalization,
    _repair_windows_lock_lifecycle_rows,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


def test_canonical_lock_bundle_preserves_rendered_dwell_after_later_session_activity(
    tmp_path: Path,
) -> None:
    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    system = System(hostname="LOCK-HOST", ip="10.0.0.20", os="Windows 11", type="workstation")
    user = User(username="operator", full_name="Operator", email="operator@example.test")
    state = StateManager()
    state.set_current_time(start)
    state.register_session(
        logon_id="0x1234",
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=start,
    )
    output = tmp_path / "security.xml"
    emitter = WindowsEventEmitter(load_format("windows_event_security"), output)
    generator = ActivityGenerator(state, {"windows_event_security": emitter})
    identity = state.get_session_identity("0x1234")
    assert identity is not None
    planner = generator.dispatcher.source_timing_planner
    assert planner is not None
    key = ("windows_security", identity.lifecycle_group_id)
    planner._latest_session_start_times[key] = start
    planner._latest_session_dependent_times[key] = start + timedelta(minutes=25)

    generator.generate_workstation_lock(user, system, start + timedelta(minutes=5), "0x1234")
    generator.generate_workstation_unlock(user, system, start + timedelta(minutes=15), "0x1234")
    emitter.close()

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    times: dict[int, datetime] = {}
    for event in ElementTree.parse(output).getroot():
        kind = int(event.findtext("e:System/e:EventID", namespaces=ns))
        if kind not in {4624, 4800, 4801}:
            continue
        stamp = event.find("e:System/e:TimeCreated", ns)
        assert stamp is not None
        times[kind] = datetime.fromisoformat(stamp.attrib["SystemTime"])
    assert times[4800] < times[4624] < times[4801]
    assert 599 < (times[4801] - times[4800]).total_seconds() < 601
    assert times[4801] < start + timedelta(minutes=16)


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
