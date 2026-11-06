# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Connect probes and explicit application probing have distinct payload intent."""

from datetime import UTC, datetime

import pytest

from evidenceforge.generation.actions.scanner_probe import (
    NmapCommandProbePlanner,
    NmapCommandProbeRequest,
    nmap_probe_application_semantics,
)
from evidenceforge.generation.activity.network_params import nmap_command_probe_config
from evidenceforge.models import System, User


@pytest.mark.parametrize(
    "service,expected_response",
    [("ssh", 120), ("mysql", 120), ("http", 0), ("ssl", 0), ("smb", 0), ("", 0)],
)
def test_connect_probe_has_no_client_payload_and_only_passive_server_banner(
    service: str, expected_response: int
) -> None:
    state, detected, duration, orig, resp = nmap_probe_application_semantics(
        "SF",
        service,
        0.3,
        100,
        120,
        application_probe=False,
        server_first_services=frozenset(nmap_command_probe_config().server_first_services),
    )
    assert state == "RSTO"
    assert duration == 0.3
    assert orig == 0
    assert resp == expected_response
    assert detected == (service if expected_response else "")


@pytest.mark.parametrize("state", ["REJ", "S0"])
@pytest.mark.parametrize("application_probe", [True, False])
def test_failed_probe_never_claims_application_payload(state: str, application_probe: bool) -> None:
    assert nmap_probe_application_semantics(
        state,
        "http",
        1.0,
        100,
        200,
        application_probe=application_probe,
        server_first_services=frozenset(),
    ) == (state, "", 1.0, 0, 0)


def test_explicit_application_probe_retains_its_own_payload() -> None:
    assert nmap_probe_application_semantics(
        "SF", "http", 0.4, 150, 200, application_probe=True, server_first_services=frozenset()
    ) == ("SF", "http", 0.4, 150, 200)


@pytest.mark.parametrize(
    "option,expected",
    [
        ("", False),
        ("-sV", True),
        ("-sR", True),
        ("-A", True),
        ("-sC", True),
        ("--script=http-title", True),
        ("--data-string 192.0.2.40", True),
        ("--data-length=32", True),
        ("--datadir=/tmp/nmap", False),
    ],
)
def test_command_plan_preserves_application_options_and_excludes_option_operands(
    option: str, expected: bool
) -> None:
    request = NmapCommandProbeRequest(
        user=User(username="user", full_name="User", email="user@corp.test"),
        system=System(hostname="client", ip="10.0.0.1", os="Linux", type="workstation"),
        time=datetime(2026, 11, 2, tzinfo=UTC),
        pid=123,
        process_name="nmap",
        command_line=f"nmap -Pn -sT -p22 {option} 10.0.0.2",
    )
    plan = NmapCommandProbePlanner(nmap_command_probe_config()).plan(request, {})
    assert plan is not None
    assert plan.application_probe is expected
    assert [target.ip for target in plan.targets] == ["10.0.0.2"]
