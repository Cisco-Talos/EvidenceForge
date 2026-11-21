# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Configured finite reports share completion semantics across Linux entry paths."""

from datetime import UTC, datetime, timedelta
from random import Random

import pytest
from pydantic import ValidationError

from evidenceforge.generation.activity import process_lifetimes
from evidenceforge.generation.activity.process_helpers import (
    _linux_foreground_lifetime,
    _macos_foreground_lifetime,
)
from evidenceforge.generation.engine.baseline import _linux_sudo_command_runtime
from tests.unit.test_process_lifetimes import _linux_interactive_shell


@pytest.mark.parametrize(
    ("command", "minimum"),
    [("vmstat 1 5", 4), ("/usr/bin/vmstat -n 2 4", 6), ("vmstat -w -t 3 1", 0)],
)
def test_linux_finite_reports_include_waits(command: str, minimum: int) -> None:
    bounds = _linux_foreground_lifetime("/usr/bin/vmstat", command)
    assert bounds is not None
    assert minimum < bounds[0] <= bounds[1] < minimum + 1
    sudo_runtime = _linux_sudo_command_runtime(command, Random(42)).total_seconds()
    assert bounds[0] <= sudo_runtime <= bounds[1]


@pytest.mark.parametrize("session_kind", ["interactive", "ssh"])
def test_finite_reports_reserve_the_foreground_until_sampling_completes(
    session_kind: str,
) -> None:
    generator, state, system, user, logon_id, shell_pid, _events = _linux_interactive_shell(
        session_kind=session_kind
    )
    start = datetime(2024, 3, 18, 13, tzinfo=UTC)
    pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/vmstat",
        command_line="vmstat 2 4",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    process = state.get_process(system.hostname, pid)
    assert process is not None
    close = generator.foreground_process_termination_time(system.hostname, pid)
    assert close is not None
    assert timedelta(seconds=6) < close - process.start_time < timedelta(seconds=7)


def test_finite_report_policy_is_linux_specific_and_unwraps_env() -> None:
    assert _linux_foreground_lifetime("/usr/bin/env", "env LC_ALL=C vmstat 2 4") == (
        6.05,
        6.95,
    )
    assert _macos_foreground_lifetime("/usr/bin/vmstat", "vmstat 2 4") == (1.0, 8.0)


@pytest.mark.parametrize(
    "command",
    [
        "vmstat",
        "vmstat 1",
        "vmstat -y 1 5",
        "vmstat -S M 1 5",
        "vmstat 0 5",
        "vmstat 1 0",
        "vmstat 1 5 | head",
        "vmstat 1 5 &",
        "vmstat '$delay' 5",
    ],
)
def test_unqualified_report_forms_keep_the_configured_fallback(command: str) -> None:
    assert _linux_foreground_lifetime("/usr/bin/vmstat", command) == (1.0, 8.0)


def test_frozen_lifetime_table_keeps_legacy_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    table = process_lifetimes.load_process_lifetimes()
    legacy = table.model_copy(
        update={"rules": tuple(r for r in table.rules if r.id != "linux-vmstat-finite-reports")}
    )
    monkeypatch.setattr(process_lifetimes, "load_process_lifetimes", lambda: legacy)
    assert _linux_foreground_lifetime("/usr/bin/vmstat", "vmstat 1 5") == (1.0, 8.0)
    assert _linux_sudo_command_runtime("vmstat 1 5", Random(42)) > timedelta(seconds=5)


def test_report_policy_can_qualify_another_grammar_without_executable_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table = process_lifetimes.load_process_lifetimes()
    data = table.model_dump(mode="json")
    data["rules"].insert(
        0,
        {
            "id": "controlled-report-fixture",
            "when": [{"executables": ["sample-reporter"], "platforms": ["linux"]}],
            "lifetime": "requested-reports",
            "seconds": [1, 8],
            "report_schedule": {
                "first_report_immediate": False,
                "options": ["--quiet"],
                "completion_seconds": [0.1, 0.4],
            },
        },
    )
    configured = process_lifetimes.ProcessLifetimeTable.model_validate(data)
    monkeypatch.setattr(process_lifetimes, "load_process_lifetimes", lambda: configured)
    assert _linux_foreground_lifetime("sample-reporter", "sample-reporter --quiet 2 4") == (
        8.1,
        8.4,
    )


def test_report_schedule_requires_an_explicit_qualified_rule() -> None:
    with pytest.raises(ValidationError, match="report_schedule"):
        process_lifetimes.LifetimeRule.model_validate(
            {
                "id": "missing-schedule",
                "when": [{"executables": ["vmstat"]}],
                "lifetime": "requested-reports",
                "seconds": [1, 8],
            }
        )
