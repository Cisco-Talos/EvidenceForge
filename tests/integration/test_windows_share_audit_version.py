# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Modern share audit XML carries the version matching its native payload shape."""

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.windows import WindowsEventEmitter

_NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}


@pytest.mark.parametrize("exact", [False, True])
@pytest.mark.parametrize("event_id, version", [(5140, "1"), (5145, "0")])
def test_share_audit_header_matches_current_supported_payload(
    tmp_path: Path, exact: bool, event_id: int, version: str
) -> None:
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"), tmp_path, source_finalization=exact
    )
    event = {
        "EventID": event_id,
        "EventRecordID": 1234,
        "Level": 0,
        "TimeCreated": datetime(2026, 11, 2, 13, tzinfo=UTC),
        "Computer": "FILE-01.example.test",
        "ExecutionProcessID": 4,
        "ExecutionThreadID": 8,
        "SubjectUserSid": "S-1-5-21-111111111-222222222-333333333-1001",
        "SubjectUserName": "alice",
        "SubjectDomainName": "EXAMPLE",
        "SubjectLogonId": "0x1234",
        "ObjectType": "File",
        "IpAddress": "10.0.0.10",
        "IpPort": 54321,
        "ShareName": r"\\*\Research",
        "ShareLocalPath": r"\??\C:\Shares\Research",
        "RelativeTargetName": "manifest.json",
        "AccessMask": "0x1",
        "AccessList": "%%4416",
        "AccessReason": "%%4416: %%1801 D:(A;;FA;;;WD)",
    }
    try:
        rendered = emitter._render_event(event, exact_candidate=exact)
    finally:
        emitter.close()
    row = ET.fromstring(rendered)
    assert row.findtext("w:System/w:Version", namespaces=_NS) == version
    provider = row.find("w:System/w:Provider", _NS)
    assert provider is not None and provider.attrib["Name"] == "Microsoft-Windows-Security-Auditing"
    fields = {item.attrib["Name"]: item.text for item in row.findall("w:EventData/w:Data", _NS)}
    assert fields["AccessMask"] == "0x1" and fields["AccessList"] == "%%4416"
    assert fields["ShareName"] == r"\\*\Research"
    assert fields["ShareLocalPath"] == r"\??\C:\Shares\Research"
    assert ("RelativeTargetName" in fields) is (event_id == 5145)
