"""Important facts require relevant source capabilities and paths at preflight."""

from pathlib import Path

import pytest

from evidenceforge.models.scenario import NetworkSegment, SourceObservationOverride
from evidenceforge.validation import ScenarioValidator
from evidenceforge.validation.evidence_reachability import analyze_evidence_reachability
from tests.integration.test_ground_truth_reconciliation import _download, _scenario


def test_flow_evidence_cannot_prove_authored_http_status(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path, [{**_download(), "status_code": 403}], formats=["ecar", "zeek_conn"]
    )
    findings = analyze_evidence_reachability(scenario)
    missing = next(item for item in findings if item.behavior_id == "typed_fact_http_result")
    assert missing.severity == "warning"
    assert "action" in missing.message
    assert "http result" in missing.message
    assert "export" in missing.suggestion


@pytest.mark.parametrize(
    "restriction", ["topology", "loss", "disabled", "window", "encryption", "https", "capability"]
)
def test_certain_loss_of_an_important_fact_remains_a_warning(
    tmp_path: Path, restriction: str
) -> None:
    scenario = _scenario(tmp_path, [{**_download(), "status_code": 403}], formats=["zeek"])
    scenario.version = "2.0"
    override = {"source_instance": "zeek:client-tap"}
    if restriction == "topology":
        scenario.environment.network.segments.append(
            NetworkSegment(name="other", cidr="10.0.99.0/24", exposure="internal", systems=[])
        )
        scenario.environment.network.sensors[0].monitoring_segments = ["other"]
    elif restriction in {"encryption", "https"}:
        scenario.storyline[0].events[0].service = "https" if restriction == "https" else "ssl"
    else:
        override.update(
            {"missingness": 1}
            if restriction == "loss"
            else {"enabled": False}
            if restriction == "disabled"
            else {"windows": []}
            if restriction == "window"
            else {"capabilities": []}
        )
        scenario.environment.observation_overrides = [
            SourceObservationOverride.model_validate(override)
        ]
    missing = next(
        item
        for item in analyze_evidence_reachability(scenario)
        if item.behavior_id == "typed_fact_http_result"
    )
    assert missing.severity == "warning"
    assert "client-tap" in missing.message
    assert any(
        word in missing.message
        for word in ["topology", "loss", "disabled", "window", "encrypted", "capability"]
    )


def test_probabilistic_loss_is_informational(tmp_path: Path) -> None:
    scenario = _scenario(tmp_path, [{**_download(), "status_code": 403}], formats=["zeek"])
    scenario.version = "2.0"
    scenario.environment.observation_overrides = [
        SourceObservationOverride(source_instance="zeek:client-tap", missingness=0.5)
    ]
    findings = [
        item
        for item in analyze_evidence_reachability(scenario)
        if item.behavior_id == "typed_fact_http_result"
    ]
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "probabilistic" in findings[0].message


def test_unrequested_firewall_does_not_produce_a_finding(tmp_path: Path) -> None:
    scenario = _scenario(tmp_path, [_download()], formats=["ecar"])
    issues = ScenarioValidator(scenario).validate()
    generic = [
        issue
        for issue in issues
        if "DHCP broadcast" in issue.message or "no firewall sensor" in issue.message
    ]
    assert not any("no firewall sensor" in issue.message for issue in generic)
    assert all(issue.severity == "info" for issue in generic)


def test_process_network_consequence_is_assessed_without_generation(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {
                "type": "process",
                "process_name": "/usr/bin/curl",
                "command_line": "curl https://download.example.net/tool",
            }
        ],
        formats=["ecar"],
    )
    findings = analyze_evidence_reachability(scenario)
    assert not any(item.behavior_id == "typed_fact_transport" for item in findings)


@pytest.mark.parametrize("formats", [["ecar"], ["windows"], ["ecar", "windows", "syslog"]])
def test_optional_authentication_sources_do_not_require_other_platforms(
    tmp_path: Path, formats: list[str]
) -> None:
    scenario = _scenario(tmp_path, [{"type": "logon", "logon_type": 2}], formats=formats)
    assert not any(
        item.behavior_id == "typed_fact_authentication"
        for item in analyze_evidence_reachability(scenario)
    )


@pytest.mark.parametrize("image", ["/usr/sbin/php-fpm8.3", "/tmp/cache-maint"])
def test_unknown_explicit_linux_paths_are_not_compared_to_fallback_guesses(
    tmp_path: Path, image: str
) -> None:
    scenario = _scenario(tmp_path, [{"type": "process", "process_name": image}], formats=["ecar"])
    scenario.environment.systems[0].os = "Linux Ubuntu 24.04"
    assert not any(
        "differs from configured canonical path" in issue.message
        for issue in ScenarioValidator(scenario).validate()
    )


def test_authored_dhcp_fact_requires_a_sensor_on_its_broadcast_segment(tmp_path: Path) -> None:
    scenario = _scenario(tmp_path, [{"type": "dhcp_lease"}], formats=["zeek"])
    scenario.environment.network.sensors[0].placement = "tap"
    missing = next(
        item
        for item in analyze_evidence_reachability(scenario)
        if item.behavior_id == "typed_fact_dhcp_lease"
    )
    assert missing.severity == "warning"
    assert "topology exclusion" in missing.message
    scenario.environment.network.sensors[0].placement = "span"
    assert not any(
        item.behavior_id == "typed_fact_dhcp_lease" and item.severity == "warning"
        for item in analyze_evidence_reachability(scenario)
    )
