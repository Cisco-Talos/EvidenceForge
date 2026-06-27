import random
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from evidenceforge.generation.actions.browser_session import (
    BrowserSessionActionBundle,
    BrowserSessionRequest,
)
from evidenceforge.generation.network_identities import ScenarioNetworkResolver
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    BaselineActivity,
    ConnectionProfile,
    Environment,
    OutputSpec,
    Scenario,
    TimeWindow,
    TrafficAffinity,
    TrafficEndpoint,
    TrafficSuppression,
    WebRequestProfile,
    WebRouteProfile,
    WeightedHttpMethodProfile,
)
from evidenceforge.validation.schema import ScenarioValidator


def _minimal_scenario(**environment_overrides) -> Scenario:
    environment = {
        "description": "Test environment",
        "users": [
            {
                "username": "alice",
                "full_name": "Alice Example",
                "email": "alice@example.test",
                "groups": ["science"],
                "persona": None,
                "primary_system": "WS-01",
            }
        ],
        "systems": [
            {
                "hostname": "WS-01",
                "ip": "10.0.0.10",
                "os": "Windows 11",
                "type": "workstation",
                "assigned_user": "alice",
            }
        ],
    }
    environment.update(environment_overrides)
    return Scenario(
        name="identity-test",
        description="x",
        environment=Environment.model_validate(environment),
        time_window=TimeWindow(
            start=datetime(2026, 1, 1, tzinfo=UTC),
            duration="2h",
        ),
        baseline_activity=BaselineActivity(
            description="Normal",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(logs=[{"format": "zeek"}], destination="./out"),
    )


def test_network_identity_resolver_overrides_package_dns() -> None:
    scenario = _minimal_scenario(
        network_identities=[
            {
                "id": "google_override",
                "hosts": ["www.google.com"],
                "ips": ["203.0.113.60"],
                "tags": ["web", "test"],
            }
        ]
    )

    resolved = ScenarioNetworkResolver.from_scenario(scenario).resolve_host(
        "www.google.com",
        src_host="WS-01",
    )

    assert resolved.ip == "203.0.113.60"
    assert resolved.identity_id == "google_override"
    assert resolved.tags == ("web", "test")


def test_network_identity_duplicate_hosts_are_rejected() -> None:
    with pytest.raises(ValidationError, match="host 'partner.example.test' is used by both"):
        _minimal_scenario(
            network_identities=[
                {"id": "a", "hosts": ["Partner.Example.Test"], "ips": ["203.0.113.60"]},
                {"id": "b", "hosts": ["partner.example.test"], "ips": ["203.0.113.61"]},
            ]
        )


def test_network_identity_stable_fallback_does_not_mutate_package_dns() -> None:
    scenario = _minimal_scenario()
    resolver = ScenarioNetworkResolver.from_scenario(scenario)

    first = resolver.resolve_host("unknown-partner.example.test", src_host="WS-01")
    second = resolver.resolve_host("unknown-partner.example.test", src_host="WS-01")

    assert first.ip == second.ip
    assert first.source == "stable_fallback"
    assert first.identity_id is None


def test_traffic_affinity_requires_direction_endpoint() -> None:
    with pytest.raises(ValidationError, match="outbound traffic affinities require destination"):
        TrafficAffinity(name="bad", kind="web", direction="outbound")

    affinity = TrafficAffinity(
        name="ok",
        kind="web",
        direction="outbound",
        destination=TrafficEndpoint(identity="partner", port=443, service="ssl"),
    )
    assert affinity.destination is not None


def test_traffic_affinity_rejects_mismatched_profiles() -> None:
    with pytest.raises(ValidationError, match="web traffic affinities use request_profile"):
        TrafficAffinity(
            name="bad_web",
            kind="web",
            direction="outbound",
            destination=TrafficEndpoint(host="partner.example.test"),
            connection_profile=ConnectionProfile(),
        )

    with pytest.raises(
        ValidationError, match="connection traffic affinities use connection_profile"
    ):
        TrafficAffinity(
            name="bad_connection",
            kind="connection",
            direction="outbound",
            destination=TrafficEndpoint(host="partner.example.test"),
            request_profile=WebRequestProfile(),
        )


def test_traffic_suppression_schema_accepts_identity_domain_and_tag_selectors() -> None:
    suppression = TrafficSuppression(
        direction="outbound",
        kind="web",
        identities=["partner"],
        domains=["partner.example.test"],
        tags=["partner"],
        factor=0.25,
    )

    assert suppression.factor == 0.25


def test_route_profile_keeps_method_and_status_owned_by_route() -> None:
    profile = WebRequestProfile(
        routes=[
            WebRouteProfile(
                path="/api/items/{id}",
                weight=1,
                methods={
                    "POST": WeightedHttpMethodProfile(
                        statuses={"201": 1.0},
                        request_body_bytes=[100, 100],
                        response_body_bytes=[200, 200],
                        content_type="application/json",
                    )
                },
            )
        ]
    )

    class FakeExecutor:
        def __init__(self) -> None:
            self.state_manager = StateManager()
            self.calls = []

        def generate_connection(self, **kwargs):
            self.calls.append(kwargs)
            return "C123"

    executor = FakeExecutor()
    BrowserSessionActionBundle(
        request=BrowserSessionRequest(
            src_ip="10.0.0.10",
            dst_ip="203.0.113.60",
            time=datetime(2026, 1, 1, 13, tzinfo=UTC),
            hostname="partner.example.com",
            dst_port=443,
            service="ssl",
            route_profile=profile,
        ),
        executor=executor,
        rng=random.Random(1),
    ).execute()

    assert executor.calls
    http = executor.calls[0]["http"]
    assert http.method == "POST"
    assert http.status_code == 201
    assert http.request_body_len == 100
    assert http.response_body_len == 200
    assert http.resp_mime_types == ["application/json"]


def test_validator_does_not_warn_for_raw_ip_endpoint() -> None:
    scenario = _minimal_scenario()
    scenario.baseline_activity.traffic_affinities = [
        TrafficAffinity(
            name="raw_ip",
            kind="connection",
            direction="outbound",
            destination=TrafficEndpoint(ip="203.0.113.60", port=8443, service="ssl"),
        )
    ]

    issues = ScenarioValidator(scenario).validate()

    assert not any("deterministic synthetic IP" in issue.message for issue in issues)


def test_validator_warns_for_undeclared_custom_domain() -> None:
    scenario = _minimal_scenario()
    scenario.baseline_activity.traffic_affinities = [
        TrafficAffinity(
            name="partner",
            kind="web",
            direction="outbound",
            destination=TrafficEndpoint(host="partner.example.test", port=443, service="ssl"),
        )
    ]

    issues = ScenarioValidator(scenario).validate()

    assert any(
        issue.severity == "warning"
        and "partner.example.test" in issue.message
        and "deterministic synthetic IP" in issue.message
        for issue in issues
    )


def test_validator_warns_for_declared_host_ip_mismatch() -> None:
    scenario = _minimal_scenario(
        network_identities=[
            {
                "id": "partner",
                "hosts": ["partner.example.test"],
                "ips": ["203.0.113.60"],
            }
        ]
    )
    scenario.baseline_activity.traffic_affinities = [
        TrafficAffinity(
            name="partner",
            kind="connection",
            direction="outbound",
            destination=TrafficEndpoint(
                host="partner.example.test",
                ip="203.0.113.61",
                port=8443,
                service="ssl",
            ),
        )
    ]

    issues = ScenarioValidator(scenario).validate()

    assert any(
        issue.severity == "warning"
        and "declared with IP" in issue.message
        and "203.0.113.61" in issue.message
        for issue in issues
    )
