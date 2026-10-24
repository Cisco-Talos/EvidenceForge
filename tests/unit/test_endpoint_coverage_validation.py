# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Endpoint coverage reflects effective sources rather than OS format bundles."""

from pathlib import Path

import pytest

from evidenceforge.models import Scenario
from evidenceforge.utils import load_yaml
from evidenceforge.validation import ScenarioValidator
from evidenceforge.validation.schema import ValidationIssue


def _scenario(scenarios_dir: Path, os_name: str, *formats: str) -> Scenario:
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["environment"]["systems"][0].update(
        os=os_name, architecture="arm64" if os_name.startswith("macOS") else "x64"
    )
    data["output"]["logs"] = [{"format": name} for name in formats]
    return Scenario.model_validate(data)


def _coverage_notes(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    return [issue for issue in issues if "no observable host endpoint source" in issue.message]


@pytest.mark.parametrize("os_name", ["Windows 11", "Ubuntu Linux 24.04", "macOS 26"])
def test_network_only_storyline_has_endpoint_note_without_format_warnings(
    scenarios_dir: Path, os_name: str
) -> None:
    data = _scenario(scenarios_dir, os_name, "zeek_conn").model_dump()
    data["storyline"] = [
        {
            "id": "network-only",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Connect to an external service",
            "events": [{"type": "connection", "dst_ip": "203.0.113.10", "dst_port": 443}],
        }
    ]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    notes = _coverage_notes(issues)
    assert len(notes) == 1
    assert notes[0].severity == "info"
    assert notes[0].field_path == "environment.systems.0"
    assert not [issue for issue in issues if issue.severity in {"warning", "error"}]


@pytest.mark.parametrize(
    "os_name, source_format",
    [
        ("Windows 11", "ecar"),
        ("Windows 11", "windows_event_security"),
        ("Windows 11", "windows_event_sysmon"),
        ("Windows 11", "windows"),
        ("Ubuntu Linux 24.04", "ecar"),
        ("Ubuntu Linux 24.04", "syslog"),
        ("Ubuntu Linux 24.04", "bash_history"),
        ("macOS 26", "ecar"),
        ("macOS 26", "bash_history"),
        ("macOS 26", "zsh_history"),
        ("macOS 26", "macos_unified_log"),
        ("macOS 26", "macos_endpoint_security"),
    ],
)
def test_each_applicable_endpoint_source_counts_without_requiring_sibling_formats(
    scenarios_dir: Path, os_name: str, source_format: str
) -> None:
    issues = ScenarioValidator(_scenario(scenarios_dir, os_name, source_format)).validate()

    assert not _coverage_notes(issues)
    assert not any("log formats in output" in issue.message for issue in issues)
    assert not any("expects formats" in issue.message for issue in issues)
    assert not any(issue.severity == "error" for issue in issues)


@pytest.mark.parametrize("os_name", ["Windows 11", "Ubuntu Linux 24.04", "macOS 26"])
@pytest.mark.parametrize(
    "override, observable",
    [
        ({"enabled": False}, False),
        ({"missingness": 1.0}, False),
        ({"missingness": 0.5}, True),
        ({"capabilities": []}, False),
        ({"capabilities": ["coherent_actor", "source_endpoint"]}, False),
        ({"capabilities": ["network"]}, True),
        ({"format_missingness": {"ecar": 1.0}}, False),
        ({"windows": [{"start": "2024-01-16T10:00:00Z"}]}, False),
        ({"windows": [{"start": "2024-01-15T10:30:00Z"}]}, True),
        ({"windows": []}, False),
    ],
)
def test_endpoint_coverage_uses_effective_collection_on_the_exact_host(
    scenarios_dir: Path, os_name: str, override: dict[str, object], observable: bool
) -> None:
    data = _scenario(scenarios_dir, os_name, "ecar").model_dump()
    data["environment"]["systems"].append(
        dict(data["environment"]["systems"][0], hostname="TEST-02", ip="10.0.0.2")
    )
    data["environment"]["network"]["segments"][0]["systems"].append("TEST-02")
    data["environment"]["observation_overrides"] = [{"source_instance": "ecar:test-01", **override}]

    notes = _coverage_notes(ScenarioValidator(Scenario.model_validate(data)).validate())

    assert len(notes) == (0 if observable else 1)
    if notes:
        assert notes[0].field_path == "environment.systems.0"
        assert "TEST-01" in notes[0].message


@pytest.mark.parametrize(
    "os_name, source_format",
    [
        ("Ubuntu Linux 24.04", "bash_history"),
        ("Ubuntu Linux 24.04", "syslog"),
        ("macOS 26", "zsh_history"),
        ("macOS 26", "macos_unified_log"),
        ("macOS 26", "macos_endpoint_security"),
    ],
)
def test_limited_endpoint_source_does_not_imply_general_process_execution_coverage(
    scenarios_dir: Path, os_name: str, source_format: str
) -> None:
    data = _scenario(scenarios_dir, os_name, source_format).model_dump()
    data["storyline"] = [
        {
            "id": "process-only",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Run a process",
            "events": [{"type": "process", "process_name": "/usr/bin/id"}],
        }
    ]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    assert not _coverage_notes(issues)
    process_issues = [issue for issue in issues if "authored process execution" in issue.message]
    assert len(process_issues) == 1
    assert process_issues[0].severity == "warning"
    assert process_issues[0].field_path == "storyline.0.events.0"


@pytest.mark.parametrize(
    "source_format, expected_warning",
    [("ecar", False), ("windows_event_security", False), ("windows_event_sysmon", True)],
)
def test_service_evidence_requires_the_specific_windows_source_capability(
    scenarios_dir: Path, source_format: str, expected_warning: bool
) -> None:
    data = _scenario(scenarios_dir, "Windows 11", source_format).model_dump()
    data["storyline"] = [
        {
            "id": "service-only",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Install a service",
            "events": [
                {
                    "type": "service_installed",
                    "service_name": "test-service",
                    "service_file_name": r"C:\Windows\test.exe",
                }
            ],
        }
    ]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    assert not _coverage_notes(issues)
    assert (
        any("authored service installation" in issue.message for issue in issues)
        is expected_warning
    )


def test_native_source_gate_still_rejects_an_ineligible_mac(scenarios_dir: Path) -> None:
    issues = ScenarioValidator(
        _scenario(scenarios_dir, "macOS", "macos_endpoint_security")
    ).validate()

    assert any(
        issue.severity == "error" and "Native ES requires" in issue.message for issue in issues
    )
    assert len(_coverage_notes(issues)) == 1


@pytest.mark.parametrize(
    "os_name, source_format",
    [
        ("Windows 11", "windows_event_security"),
        ("Windows 11", "windows_event_sysmon"),
        ("Windows 11", "ecar"),
        ("Ubuntu Linux 24.04", "ecar"),
        ("macOS 26", "ecar"),
    ],
)
def test_one_capable_process_source_does_not_require_other_os_formats(
    scenarios_dir: Path, os_name: str, source_format: str
) -> None:
    data = _scenario(scenarios_dir, os_name, source_format).model_dump()
    data["storyline"] = [
        {
            "id": "process-only",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Run a process",
            "events": [
                {
                    "type": "process",
                    "process_name": (
                        r"C:\Windows\System32\whoami.exe"
                        if os_name.startswith("Windows")
                        else "/usr/bin/id"
                    ),
                }
            ],
        }
    ]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    assert not [issue for issue in issues if issue.severity in {"error", "warning"}]


@pytest.mark.parametrize("os_name", ["Windows 11", "Ubuntu Linux 24.04", "macOS 26"])
@pytest.mark.parametrize("override", [{"enabled": False}, {"capabilities": ["network"]}])
def test_another_hosts_process_collection_cannot_cover_the_authored_host(
    scenarios_dir: Path, os_name: str, override: dict[str, object]
) -> None:
    data = _scenario(scenarios_dir, os_name, "ecar").model_dump()
    data["environment"]["systems"].append(
        dict(data["environment"]["systems"][0], hostname="TEST-02", ip="10.0.0.2")
    )
    data["environment"]["network"]["segments"][0]["systems"].append("TEST-02")
    data["environment"]["observation_overrides"] = [{"source_instance": "ecar:test-01", **override}]
    data["red_herrings"] = [
        {
            "id": "unobserved-process",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Run a process with no process collection on this host",
            "explanation": "A legitimate diagnostic command",
            "events": [{"type": "process", "process_name": "whoami"}],
        }
    ]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    findings = [issue for issue in issues if "authored process execution" in issue.message]
    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert findings[0].field_path == "red_herrings.0.events.0"


@pytest.mark.parametrize(
    "os_name, source_format, expected_warning",
    [
        ("Ubuntu Linux 24.04", "ecar", False),
        ("Ubuntu Linux 24.04", "syslog", False),
        ("Ubuntu Linux 24.04", "bash_history", True),
        ("macOS 26", "ecar", False),
        ("macOS 26", "macos_unified_log", True),
        ("macOS 26", "macos_endpoint_security", True),
    ],
)
def test_ssh_session_visibility_requires_receiver_session_evidence(
    scenarios_dir: Path, os_name: str, source_format: str, expected_warning: bool
) -> None:
    data = _scenario(scenarios_dir, os_name, source_format).model_dump()
    data["storyline"] = [
        {
            "id": "remote-session",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Open an SSH session",
            "events": [{"type": "ssh_session", "source_ip": "10.0.0.2"}],
        }
    ]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    findings = [
        issue for issue in issues if "authored SSH authentication/session evidence" in issue.message
    ]
    assert bool(findings) is expected_warning
    if findings:
        assert findings[0].field_path == "storyline.0.events.0"


def test_web_access_is_application_evidence_without_endpoint_collection(
    scenarios_dir: Path,
) -> None:
    data = _scenario(scenarios_dir, "Ubuntu Linux 24.04", "web_access").model_dump()
    data["environment"]["systems"][0]["roles"] = ["web_server"]

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    assert len(_coverage_notes(issues)) == 1
    assert not [issue for issue in issues if issue.severity in {"warning", "error"}]


@pytest.mark.parametrize("os_name, host_type", [("macOS", "workstation"), ("macOS 26", "server")])
def test_unavailable_workspace_profile_does_not_count_as_observable_endpoint_collection(
    scenarios_dir: Path, os_name: str, host_type: str
) -> None:
    data = _scenario(scenarios_dir, os_name, "macos_unified_log").model_dump()
    data["environment"]["systems"][0]["type"] = host_type

    issues = ScenarioValidator(Scenario.model_validate(data)).validate()

    assert len(_coverage_notes(issues)) == 1


def test_incorrect_output_format_keeps_its_original_compatibility_error(
    scenarios_dir: Path,
) -> None:
    issues = ScenarioValidator(_scenario(scenarios_dir, "macOS 26", "syslog")).validate()

    assert any(issue.severity == "error" and "requires linux" in issue.message for issue in issues)


def test_invalid_selection_does_not_invent_an_endpoint_coverage_finding(
    scenarios_dir: Path,
) -> None:
    issues = ScenarioValidator(_scenario(scenarios_dir, "Windows 11", "unknown_format")).validate()

    assert any("Unknown output format" in issue.message for issue in issues)
    assert not _coverage_notes(issues)
