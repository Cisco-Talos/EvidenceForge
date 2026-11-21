# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Windows process creators remain separate from new-process tokens."""

import json
import xml.etree.ElementTree as ET
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.actions.windows_process_security import (
    prepare_windows_process_creation_security,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario
from tests.integration.test_ground_truth_reconciliation import _scenario
from tests.unit.test_process_lifetimes import _windows_process_family


@pytest.mark.parametrize("case", ["unknown_creator", "unknown_sid", "linux", "mismatched_pid"])
def test_creator_policy_preserves_unknown_platforms_and_rejects_wrong_actor(case: str) -> None:
    start = datetime(2024, 3, 18, 13, 0, tzinfo=UTC)
    creator = ProcessIdentity(
        hostname="WIN-01",
        object_id="actor",
        pid=10,
        parent_pid=0,
        image="services.exe",
        command_line="services.exe",
        principal="SYSTEM",
        logon_id="0x3e7",
        started_at=start,
        lifecycle_group_id="actor-group",
    )
    event = OccurrenceBuilder(
        timestamp=start,
        event_type="process_create",
        src_host=HostContext(
            hostname="WIN-01",
            ip="10.0.0.1",
            os="Windows 11",
            os_category="linux" if case == "linux" else "windows",
            system_type="workstation",
        ),
        auth=AuthContext(username="analyst", user_sid="S-1-5-21-1-2-3-1001", logon_id="0x123"),
        process=ProcessContext(
            pid=11,
            parent_pid=10,
            image="userinit.exe",
            command_line="userinit.exe",
            username="analyst",
            logon_id="0x123",
        ),
    )
    before_auth, before_process = replace(event.auth), replace(event.process)
    if case == "mismatched_pid":
        with pytest.raises(StateError, match="host/parent"):
            prepare_windows_process_creation_security(
                event, creator=replace(creator, pid=99), sid_for=lambda _: "S-1-5-18"
            )
    else:
        prepare_windows_process_creation_security(
            event,
            creator=None if case == "unknown_creator" else creator,
            sid_for=lambda _: "S-1-0-0" if case == "unknown_sid" else "S-1-5-18",
        )
    assert event.auth == before_auth and event.process == before_process


def _family() -> tuple:
    family = _windows_process_family()
    generator, state, system, user, _luid, _parent, _child, emitter = family
    generator.sid_registry.update(
        {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
            user.username: "S-1-5-21-1-2-3-1001",
        }
    )
    plan = state.plan_process_materialization(
        system=system.hostname,
        parent_pid=0,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        logon_id="0x3e7",
        lifecycle_group_id="creator-token-test:service-root",
        start_time=datetime(2024, 3, 18, 12, 59, tzinfo=UTC),
    )
    root, _receipt = generator._lifecycle_authority.materialize_process(plan)
    emitted: list = []
    emitter.emit.side_effect = emitted.append
    return (*family, root, emitted)


def test_system_service_create_preserves_scm_creator_and_service_token() -> None:
    generator, _state, system, _user, _luid, _parent, _child, _emitter, root, emitted = _family()
    pid = generator.generate_system_process(
        system=system,
        time=datetime(2024, 3, 18, 13, 1, tzinfo=UTC),
        process_name=r"C:\Windows\System32\svchost.exe",
        command_line="svchost.exe -k LocalService -p",
        parent_pid=root.pid,
        username="LOCAL SERVICE",
    )
    event = next(
        e for e in emitted if e.event_type == "system_process_create" and e.process.pid == pid
    )
    assert event.auth.username == "LOCAL SERVICE" and event.process.logon_id == "0x3e5"
    assert event.auth.subject_username == "SYSTEM"
    assert event.auth.subject_sid == "S-1-5-18" and event.auth.subject_logon_id == "0x3e7"
    assert event.process.target_security_context is not None
    target = event.process.target_security_context
    assert (target.username, target.user_sid, target.logon_id) == (
        "LOCAL SERVICE",
        "S-1-5-19",
        "0x3e5",
    )


def test_existing_windows_bootstrap_create_uses_its_actual_actor_token() -> None:
    generator, state, system, user, luid, _parent, _child, _emitter, root, emitted = _family()
    session = state.get_session(luid)
    assert session is not None
    plan = state.plan_process_materialization(
        system=system.hostname,
        parent_pid=root.pid,
        image=r"C:\Windows\System32\userinit.exe",
        command_line="userinit.exe",
        username=user.username,
        integrity_level="Medium",
        os_category="windows",
        logon_id=luid,
        lifecycle_group_id="creator-token-test:user-bootstrap",
        start_time=datetime(2024, 3, 18, 13, 1, tzinfo=UTC),
        require_session=True,
        auth_session_id=session.session_id,
        auth_logon_type=session.logon_type,
    )
    process, _receipt = generator._lifecycle_authority.materialize_process(plan)
    generator._emit_windows_session_process_create(
        system=system,
        session=session,
        pid=process.pid,
        event_username=user.username,
        event_logon_id=luid,
        integrity_level="Medium",
    )
    event = next(
        e for e in emitted if e.event_type == "process_create" and e.process.pid == process.pid
    )
    assert event.auth.username == user.username and event.process.logon_id == luid
    assert event.auth.subject_username == "SYSTEM" and event.auth.subject_logon_id == "0x3e7"
    assert event.process.target_security_context is not None
    target = event.process.target_security_context
    assert (target.username, target.user_sid, target.logon_id) == (
        user.username,
        "S-1-5-21-1-2-3-1001",
        luid,
    )


def test_same_context_creation_keeps_null_target_and_child_identity() -> None:
    generator, state, system, user, luid, parent_pid, _child, _emitter, _root, emitted = _family()
    pid = generator.generate_process(
        user=user,
        system=system,
        time=datetime(2024, 3, 18, 13, 1, tzinfo=UTC),
        logon_id=luid,
        process_name=r"C:\Tools\Probe.exe",
        command_line="Probe.exe --once",
        parent_pid=parent_pid,
        require_exact_parent=True,
        suppress_command_file_effect=True,
    )
    event = next(e for e in emitted if e.event_type == "process_create" and e.process.pid == pid)
    assert event.auth.subject_username == user.username and event.auth.subject_logon_id == luid
    assert event.process.target_security_context is None
    process = state.get_process(system.hostname, pid)
    assert process is not None and process.username == user.username and process.logon_id == luid


def test_native_new_credentials_creator_and_target_keep_their_own_logons(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {"type": "logon", "logon_type": 9, "source_ip": "10.0.10.99"},
            {
                "type": "process",
                "process_name": r"C:\Windows\System32\cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
        ],
        formats=["ecar", "windows_event_security", "windows_event_sysmon"],
    )
    data = scenario.model_dump(mode="json")
    data["environment"]["domain"] = "corp.example"
    data["environment"]["users"].append(
        {"username": "bob", "full_name": "Bob Example", "email": "bob@example.org"}
    )
    data["storyline"][0]["actor"] = "bob"
    GenerationEngine(Scenario.model_validate(data), tmp_path).generate()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    security = []
    for path in tmp_path.rglob("windows_event_security.xml"):
        for event in ET.parse(path).getroot().findall("e:Event", ns):
            fields = {
                entry.get("Name"): entry.text or ""
                for entry in event.findall("e:EventData/e:Data", ns)
            }
            security.append((event.findtext("e:System/e:EventID", namespaces=ns), fields))
    logon = next(
        fields
        for event_id, fields in security
        if event_id == "4624" and fields.get("LogonType") == "9"
    )
    child = next(
        fields
        for event_id, fields in security
        if event_id == "4688"
        and fields.get("TargetLogonId") == logon["TargetLogonId"]
        and fields["NewProcessName"].lower().endswith("\\cmd.exe")
    )
    assert child["SubjectLogonId"] == logon["SubjectLogonId"]
    assert child["SubjectLogonId"] != child["TargetLogonId"]
    assert child["TargetUserName"] == "alice"
    pid = int(child["NewProcessId"], 16)
    sysmon = []
    for path in tmp_path.rglob("windows_event_sysmon.xml"):
        for event in ET.parse(path).getroot().findall("e:Event", ns):
            if event.findtext("e:System/e:EventID", namespaces=ns) == "1":
                sysmon.append(
                    {
                        entry.get("Name"): entry.text or ""
                        for entry in event.findall("e:EventData/e:Data", ns)
                    }
                )
    native_child = next(fields for fields in sysmon if fields.get("ProcessId") == str(pid))
    assert native_child["LogonId"] == child["TargetLogonId"]
    ecar = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    endpoint_child = next(
        row
        for row in ecar
        if row.get("object") == "PROCESS"
        and row.get("action") == "CREATE"
        and row.get("pid") == pid
    )
    assert endpoint_child["properties"]["logon_id"] == child["TargetLogonId"]
