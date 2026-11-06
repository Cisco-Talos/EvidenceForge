# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Task principal XML separates registration API enums from schema values."""

from datetime import UTC, datetime
from xml.etree import ElementTree

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.models.scenario import User


@pytest.mark.parametrize(
    ("principal", "expected", "machine", "elevated"),
    [
        ("SYSTEM", "NT AUTHORITY\\SYSTEM", True, True),
        ("local service", "NT AUTHORITY\\LOCAL SERVICE", True, False),
        ("NETWORK SERVICE", "NT AUTHORITY\\NETWORK SERVICE", True, False),
        ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\SYSTEM", True, True),
        ("S-1-5-18", "S-1-5-18", True, True),
        ("S-1-5-19", "S-1-5-19", True, False),
        ("S-1-5-20", "S-1-5-20", True, False),
        ("operator", "EXAMPLE\\operator", False, False),
        (".\\operator", ".\\operator", False, False),
        ("operator@example.test", "operator@example.test", False, False),
        ("EXAMPLE\\managed$", "EXAMPLE\\managed$", False, False),
        ("S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1101", False, False),
        ("NT AUTHORITY\\custom", "NT AUTHORITY\\custom", False, False),
    ],
)
def test_task_principal_schema_and_sibling_identity_forms(
    principal: str, expected: str, machine: bool, elevated: bool
) -> None:
    actor = User(username="creator", full_name="Creator", email="creator@example.test")
    xml = ActivityGenerator._build_scheduled_task_xml(
        task_name="\\Ops\\Health & Status",
        command="C:\\Program Files\\Ops\\health.exe",
        arguments='--query "a&b<c"',
        actor=actor,
        host=HostContext(
            hostname="TASK-HOST",
            ip="192.0.2.1",
            os="Windows Server 2025",
            os_category="windows",
            system_type="server",
            netbios_domain="EXAMPLE",
        ),
        time=datetime(2026, 11, 2, 17, tzinfo=UTC),
        schedule={"type": "HOURLY"},
        principal_name=principal,
    )
    root = ElementTree.fromstring(xml)
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    node = root.find("t:Principals/t:Principal", ns)
    assert node is not None
    assert node.findtext("t:UserId", namespaces=ns) == expected
    method = node.findtext("t:LogonType", namespaces=ns)
    assert method is None if machine else method == "Password"
    assert all(
        element.text in {"S4U", "Password", "InteractiveToken", "InteractiveTokenOrPassword"}
        for element in root.findall(".//t:LogonType", ns)
    )
    assert node.findtext("t:RunLevel", namespaces=ns) == (
        "HighestAvailable" if elevated else "LeastPrivilege"
    )
    assert root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns) == '--query "a&b<c"'
    assert root.findtext("t:RegistrationInfo/t:URI", namespaces=ns) == "\\Ops\\Health & Status"
