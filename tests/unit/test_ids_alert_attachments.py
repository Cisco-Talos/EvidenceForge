# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Edge-case coverage for canonical IDS attachments and filter state."""

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    FileTransferContext,
    HttpContext,
    IdsAlertPlan,
    IdsAlertPolicyContext,
    IdsDetectionFilterContext,
    IdsEventFilterContext,
)
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    SignaturePredicate,
)
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.ids_alert import (
    IdsAlertActionBundle,
    IdsAlertRequest,
    ids_alert_matches_transaction,
    normalize_ids_alerts,
)
from evidenceforge.generation.activity.ids_signatures import (
    reset_ids_signatures_cache,
    signature_by_sid,
    signature_matches_inspection_visibility,
)
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.ids_filtering import IdsAlertCandidate, IdsAlertFilterEngine
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)
from evidenceforge.models.scenario import (
    BeaconEventSpec,
    ConnectionEventSpec,
    DgaQueriesEventSpec,
    DhcpLeaseEventSpec,
    DnsQueryEventSpec,
    DnsTunnelEventSpec,
    PortScanEventSpec,
    RdpSessionEventSpec,
    SshSessionEventSpec,
    WebScanEventSpec,
)
from evidenceforge.validation import ScenarioValidator
from tests.network_factories import network_plan

T0 = datetime(2026, 8, 3, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _planned_transaction(
    *,
    conn_state: str = "SF",
    service: str = "http",
    proto: str = "tcp",
    dst_port: int | None = None,
    orig_payload: int = 200,
    resp_payload: int = 500,
    resp_packets: int = 3,
) -> NetworkTransactionPlan:
    """Return a sealed transaction for IDS predicate tests."""

    duration = None if conn_state in {"S0", "REJ"} else 1.0
    close = None if duration is None else T0 + timedelta(seconds=duration)
    phases = [("transport_start", T0)]
    if close is not None:
        phases.append(("transport_close", close))
    return NetworkTransactionPlan(
        stable_id="ids-transaction",
        hostname="web.example.test",
        outcome="success" if conn_state == "SF" else "failure",
        phase_times=tuple(phases),
        started_at=T0,
        closed_at=close,
        src_ip="198.51.100.20",
        src_port=52000,
        dst_ip="10.0.0.20",
        dst_port=dst_port if dst_port is not None else 80 if service == "http" else 443,
        protocol=proto,
        service=service,
        zeek_uid="CidsPredicate",
        conn_id="connection-1",
        duration=duration,
        conn_state=conn_state,
        history="ShADadfF" if conn_state == "SF" else "S",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(
                orig_payload, 2 if orig_payload else 1, orig_payload + 80
            ),
            resp=DirectionalTrafficLedger(
                resp_payload,
                resp_packets,
                resp_payload + (resp_packets * 40 if resp_packets else 0),
            ),
        ),
    )


def test_payload_signature_requires_cleartext_or_explicit_decryption() -> None:
    """Opaque TLS cannot produce content-signature evidence."""

    signature = {"inspection": "payload_cleartext"}

    assert signature_matches_inspection_visibility(signature, "http")
    assert not signature_matches_inspection_visibility(signature, "ssl")
    assert signature_matches_inspection_visibility(signature, "ssl", payload_decrypted=True)


def test_signature_bundle_carries_validated_upload_predicate() -> None:
    """Configured content semantics should survive as immutable canonical truth."""

    signature = signature_by_sid(2012647)
    assert signature is not None
    alert = IdsAlertActionBundle(
        IdsAlertRequest(
            signature=signature,
            time=T0,
            src_ip="198.51.100.20",
            dst_ip="10.0.0.20",
            dst_port=80,
            proto="tcp",
            rng=random.Random(7),
        )
    ).execute()

    assert alert.predicate is not None
    assert alert.predicate.semantic_claim == "upload_request"
    assert alert.predicate.http_methods == ("POST", "PUT", "PATCH")
    assert alert.predicate.requires_http_body


def test_http_content_predicate_uses_application_port_set_not_generation_default() -> None:
    """HTTP_PORTS-style rules may match a request away from their preferred target port."""

    signature = signature_by_sid(2024317)
    assert signature is not None
    alert = IdsAlertActionBundle(
        IdsAlertRequest(
            signature=signature,
            time=T0,
            src_ip="198.51.100.20",
            dst_ip="10.0.0.20",
            dst_port=80,
            proto="tcp",
            rng=random.Random(9),
        )
    ).execute()

    assert alert.predicate is not None
    assert alert.predicate.destination_port == 0
    assert ids_alert_matches_transaction(
        alert,
        _planned_transaction(service="http"),
        http=HttpContext(method="GET", user_agent="${jndi:ldap://example.test/a}"),
    )


def test_upload_signature_requires_successful_body_bearing_http_method() -> None:
    """An upload alert cannot survive failed transport, GET, or an empty request body."""

    signature = signature_by_sid(2012647)
    assert signature is not None
    alert = IdsAlertActionBundle(
        IdsAlertRequest(
            signature=signature,
            time=T0,
            src_ip="198.51.100.20",
            dst_ip="10.0.0.20",
            dst_port=80,
            proto="tcp",
            rng=random.Random(8),
        )
    ).execute()
    post = HttpContext(method="POST", request_body_len=128, response_body_len=64)
    get = HttpContext(method="GET", request_body_len=0, response_body_len=64)

    assert not ids_alert_matches_transaction(
        alert,
        _planned_transaction(conn_state="S0", orig_payload=0, resp_payload=0, resp_packets=0),
        http=post,
    )
    assert not ids_alert_matches_transaction(alert, _planned_transaction(), http=get)
    assert ids_alert_matches_transaction(alert, _planned_transaction(), http=post)


def test_response_and_scan_predicates_distinguish_payload_free_attempts() -> None:
    """Response claims require response evidence while scan metadata may fire on S0."""

    response_alert = IdsAlertPlan(
        sid=1,
        message="response claim",
        classification="misc-activity",
        predicate=SignaturePredicate(
            transport_protocol="tcp",
            destination_port=80,
            phase="response",
            payload_direction="resp",
            minimum_payload_bytes=1,
            requires_response=True,
            semantic_claim="response_content",
        ),
    )
    scan_alert = IdsAlertPlan(
        sid=2,
        message="scan",
        classification="attempted-recon",
        predicate=SignaturePredicate(
            transport_protocol="tcp",
            destination_port=80,
            semantic_claim="scan",
        ),
    )
    no_response = _planned_transaction(
        conn_state="S0",
        orig_payload=0,
        resp_payload=0,
        resp_packets=0,
    )

    assert not ids_alert_matches_transaction(response_alert, no_response)
    assert ids_alert_matches_transaction(scan_alert, no_response)


def test_stun_success_signature_requires_and_renders_response_payload(tmp_path: Path) -> None:
    """STUN success alerts require a response and render the responder packet tuple."""

    signature = signature_by_sid(2024392)
    assert signature is not None
    alert = IdsAlertActionBundle(
        IdsAlertRequest(
            signature=signature,
            time=T0,
            src_ip="10.0.0.8",
            dst_ip="198.51.100.20",
            dst_port=3478,
            proto="udp",
            rng=random.Random(12),
        )
    ).execute()
    assert alert.predicate is not None
    assert alert.predicate.payload_direction == "resp"
    assert alert.predicate.requires_response
    assert not ids_alert_matches_transaction(
        alert,
        _planned_transaction(
            proto="udp",
            service="stun",
            dst_port=3478,
            conn_state="S0",
            orig_payload=64,
            resp_payload=0,
            resp_packets=0,
        ),
    )
    assert ids_alert_matches_transaction(
        alert,
        _planned_transaction(
            proto="udp",
            service="stun",
            dst_port=3478,
            orig_payload=64,
            resp_payload=64,
            resp_packets=1,
        ),
    )

    output_path = tmp_path / "snort_alert.log"
    emitter = SnortEmitter(load_format("snort_alert"), output_path)
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.8",
            src_port=52000,
            dst_ip="198.51.100.20",
            dst_port=3478,
            protocol="udp",
        ),
        ids_alerts=(alert,),
    )
    emitter.emit(event)
    emitter.close()

    assert "198.51.100.20:3478 -> 10.0.0.8:52000" in output_path.read_text(encoding="utf-8")


def test_file_download_signature_requires_matching_response_file_mime() -> None:
    """Response-file rules require a response artifact of the claimed family."""

    signature = signature_by_sid(2000428)
    assert signature is not None
    alert = IdsAlertActionBundle(
        IdsAlertRequest(
            signature=signature,
            time=T0,
            src_ip="10.0.0.8",
            dst_ip="198.51.100.20",
            dst_port=80,
            proto="tcp",
            rng=random.Random(11),
        )
    ).execute()
    transaction = _planned_transaction(resp_payload=4096)
    wrong_file = FileTransferContext(mime_type="image/png", is_orig=False)
    upload = FileTransferContext(mime_type="application/zip", is_orig=True)
    download = FileTransferContext(mime_type="application/zip", is_orig=False)

    assert not ids_alert_matches_transaction(alert, transaction, http=HttpContext())
    assert not ids_alert_matches_transaction(
        alert, transaction, http=HttpContext(), file_transfers=(wrong_file,)
    )
    assert not ids_alert_matches_transaction(
        alert, transaction, http=HttpContext(), file_transfers=(upload,)
    )
    assert ids_alert_matches_transaction(
        alert, transaction, http=HttpContext(), file_transfers=(download,)
    )


def test_domain_signature_requires_matching_tls_server_name() -> None:
    """A named-domain IDS claim must be observable on the exact TLS flow."""
    signature = signature_by_sid(2025712)
    assert signature is not None
    alert = IdsAlertActionBundle(
        IdsAlertRequest(
            signature=signature,
            time=T0,
            src_ip="10.0.0.8",
            dst_ip="198.51.100.20",
            dst_port=443,
            proto="tcp",
            rng=random.Random(11),
        )
    ).execute()
    transaction = _planned_transaction(dst_port=443, service="ssl")

    assert ids_alert_matches_transaction(
        alert, transaction, ssl=SimpleNamespace(server_name="api.ipify.org")
    )
    assert not ids_alert_matches_transaction(
        alert, transaction, ssl=SimpleNamespace(server_name="api.hubspot.com")
    )
    assert not ids_alert_matches_transaction(alert, transaction, ssl=None)


def test_snort_response_predicate_renders_responder_packet_direction(tmp_path: Path) -> None:
    """Response-side IDS evidence renders server-to-client packet endpoints."""

    output_path = tmp_path / "snort_alert.log"
    emitter = SnortEmitter(load_format("snort_alert"), output_path)
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.8",
            src_port=52000,
            dst_ip="198.51.100.20",
            dst_port=80,
            protocol="tcp",
        ),
        ids_alerts=(
            IdsAlertPlan(
                sid=2000428,
                message="ZIP response",
                classification="policy-violation",
                predicate=SignaturePredicate(
                    transport_protocol="tcp",
                    destination_port=80,
                    phase="response",
                    payload_direction="resp",
                    minimum_payload_bytes=1,
                    requires_response=True,
                    semantic_claim="response_content",
                ),
            ),
        ),
    )

    emitter.emit(event)
    emitter.close()

    line = output_path.read_text(encoding="utf-8")
    assert "198.51.100.20:80 -> 10.0.0.8:52000" in line


def test_cleartext_content_predicate_rejects_opaque_tls() -> None:
    """A payload-content alert cannot inspect an opaque encrypted transaction."""

    alert = IdsAlertPlan(
        sid=3,
        message="content",
        classification="policy-violation",
        predicate=SignaturePredicate(
            transport_protocol="tcp",
            destination_port=443,
            phase="application",
            payload_direction="orig",
            minimum_payload_bytes=1,
            application_protocol="tls",
            inspection="payload_cleartext",
            semantic_claim="request_content",
        ),
    )

    assert not ids_alert_matches_transaction(
        alert,
        _planned_transaction(service="ssl"),
        ssl=object(),
    )


def _scenario(*events: object) -> Scenario:
    return Scenario(
        version="1.0",
        name="ids-test",
        description="IDS attachment validation",
        environment=Environment(
            description="test",
            users=[User(username="alice", full_name="Alice", email="alice@example.test")],
            systems=[
                System(
                    hostname="ws-01",
                    ip="10.0.0.8",
                    os="Windows 11",
                    type="workstation",
                )
            ],
        ),
        time_window=TimeWindow(start=T0, duration="1h"),
        baseline_activity=BaselineActivity(description="test", intensity="low", variation="low"),
        output=OutputSpec(destination="./output", logs=[{"format": "snort_alert"}]),
        storyline=[
            StorylineEvent(
                id="ids-1",
                time=T0.isoformat(),
                actor="alice",
                system="ws-01",
                activity="test",
                events=list(events),
            )
        ],
    )


def _candidate(
    seconds: float,
    policy: IdsAlertPolicyContext | None,
    *,
    sid: int = 2028401,
    sensor: str = "ids-01",
    src_ip: str = "10.0.0.8",
    dst_ip: str = "2001:db8::20",
) -> IdsAlertCandidate:
    return IdsAlertCandidate(
        sensor=sensor,
        timestamp=T0 + timedelta(seconds=seconds),
        gid=1,
        sid=sid,
        src_ip=src_ip,
        dst_ip=dst_ip,
        policy=policy,
    )


def test_connection_and_beacon_accept_multiple_ids_alerts() -> None:
    attachments = [
        {"sid": 2028401},
        {
            "sid": 2002910,
            "policy": {
                "detection_filter": {"track": "by_src", "count": 5, "seconds": 60},
                "event_filter": {
                    "type": "limit",
                    "track": "by_src",
                    "count": 1,
                    "seconds": 300,
                },
            },
        },
    ]
    connection = ConnectionEventSpec(dst_ip="198.51.100.10", ids_alerts=attachments)
    beacon = BeaconEventSpec(
        dst_ip="198.51.100.10",
        interval="2m",
        duration="45m",
        ids_alerts=attachments,
    )
    assert [item.sid for item in connection.ids_alerts] == [2028401, 2002910]
    assert [item.sid for item in beacon.ids_alerts] == [2028401, 2002910]


def _transport_owner_specs(ids_alerts: list[dict[str, object]]) -> list[object]:
    """Return one valid instance of every IDS-attachable typed transport owner."""

    return [
        ConnectionEventSpec(dst_ip="198.51.100.10", ids_alerts=ids_alerts),
        BeaconEventSpec(
            dst_ip="198.51.100.10",
            interval="1m",
            count=2,
            ids_alerts=ids_alerts,
        ),
        SshSessionEventSpec(ids_alerts=ids_alerts),
        RdpSessionEventSpec(ids_alerts=ids_alerts),
        DhcpLeaseEventSpec(ids_alerts=ids_alerts),
        PortScanEventSpec(target_ips=["198.51.100.10"], ids_alerts=ids_alerts),
        DnsQueryEventSpec(query="missing.example.test", rcode="NXDOMAIN", ids_alerts=ids_alerts),
        WebScanEventSpec(
            dst_ip="198.51.100.10",
            rate=1,
            count=2,
            preset="nikto",
            ids_alerts=ids_alerts,
        ),
        DgaQueriesEventSpec(interval="1s", count=2, ids_alerts=ids_alerts),
        DnsTunnelEventSpec(
            base_domain="tunnel.example.test",
            interval="1s",
            count=2,
            ids_alerts=ids_alerts,
        ),
    ]


def test_every_transport_owner_accepts_shared_multi_sid_policy_schema() -> None:
    attachments = [
        {"sid": 2028401},
        {
            "sid": 2002910,
            "policy": {
                "detection_filter": {"track": "by_src", "count": 2, "seconds": 30},
                "event_filter": {
                    "type": "both",
                    "track": "by_dst",
                    "count": 3,
                    "seconds": 60,
                },
            },
        },
    ]
    for spec in _transport_owner_specs(attachments):
        assert [item.sid for item in spec.ids_alerts] == [2028401, 2002910]


def test_every_transport_owner_rejects_duplicate_sid() -> None:
    with pytest.raises(ValidationError, match="duplicate SID"):
        _transport_owner_specs([{"sid": 384}, {"sid": 384}])


def test_non_transport_event_rejects_ids_alerts() -> None:
    from evidenceforge.models.scenario import ProcessEventSpec

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ProcessEventSpec(process_name="whoami.exe", ids_alerts=[{"sid": 384}])


@pytest.mark.parametrize("model", [ConnectionEventSpec, BeaconEventSpec])
def test_ids_alerts_reject_duplicate_sid(model: type) -> None:
    kwargs = {"dst_ip": "198.51.100.10", "ids_alerts": [{"sid": 384}, {"sid": 384}]}
    if model is BeaconEventSpec:
        kwargs.update(interval="1m", duration="2m")
    with pytest.raises(ValidationError, match="duplicate SID"):
        model(**kwargs)


@pytest.mark.parametrize(
    "bad_value",
    [0, -1, 1.5, True, 2_147_483_648],
)
def test_filter_counts_and_windows_are_bounded_strict_positive_integers(
    bad_value: object,
) -> None:
    with pytest.raises(ValidationError):
        ConnectionEventSpec(
            dst_ip="198.51.100.10",
            ids_alerts=[
                {
                    "sid": 384,
                    "policy": {
                        "event_filter": {
                            "type": "limit",
                            "track": "by_src",
                            "count": bad_value,
                            "seconds": 60,
                        }
                    },
                }
            ],
        )


@pytest.mark.parametrize(
    "policy",
    [
        {},
        {"event_filter": {"type": "bogus", "track": "by_src", "count": 1, "seconds": 1}},
        {"event_filter": {"type": "limit", "track": "host", "count": 1, "seconds": 1}},
        {
            "event_filter": {
                "type": "limit",
                "track": "by_src",
                "count": 1,
                "seconds": 1,
                "unknown": True,
            }
        },
    ],
)
def test_policy_rejects_empty_invalid_and_unknown_fields(policy: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ConnectionEventSpec(
            dst_ip="198.51.100.10",
            ids_alerts=[{"sid": 384, "policy": policy}],
        )


def test_explicit_every_is_accepted() -> None:
    spec = ConnectionEventSpec(
        dst_ip="198.51.100.10",
        ids_alerts=[{"sid": 384, "policy": "every"}],
    )
    assert spec.ids_alerts[0].policy == "every"


def test_signature_policy_is_inherited_and_every_replaces_it() -> None:
    import random

    signature = signature_by_sid(2002910)
    assert signature is not None
    base = dict(
        signature=signature,
        time=T0,
        src_ip="198.51.100.1",
        dst_ip="10.0.0.8",
        dst_port=5800,
        proto="tcp",
        rng=random.Random(1),
    )
    inherited = IdsAlertActionBundle(IdsAlertRequest(**base)).execute()
    explicit_every = IdsAlertActionBundle(IdsAlertRequest(**base, policy="every")).execute()
    assert inherited.policy is not None
    assert inherited.policy.event_filter is not None
    assert inherited.policy.event_filter.type == "both"
    assert explicit_every.policy is None


def test_signature_overlay_replaces_policy_and_cache_reset_reloads(
    tmp_path,
    monkeypatch,
) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity" / "ids_signatures.yaml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text(
        """signatures:
  - sid: 2002910
    alert_policy:
      event_filter: {type: limit, track: by_dst, count: 2, seconds: 30}
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_ids_signatures_cache()
    try:
        signature = signature_by_sid(2002910)
        assert signature is not None
        assert signature["alert_policy"]["event_filter"]["type"] == "limit"
        overlay.write_text(
            """signatures:
  - sid: 2002910
    alert_policy: every
""",
            encoding="utf-8",
        )
        assert signature_by_sid(2002910)["alert_policy"] != "every"
        reset_ids_signatures_cache()
        assert signature_by_sid(2002910)["alert_policy"] == "every"
    finally:
        reset_ids_signatures_cache()


def test_validator_rejects_unknown_sid() -> None:
    scenario = _scenario(
        ConnectionEventSpec(dst_ip="198.51.100.10", ids_alerts=[{"sid": 2_000_000_000}])
    )
    issues = ScenarioValidator(scenario).validate()
    assert any(
        issue.severity == "error" and "Unknown IDS signature" in issue.message for issue in issues
    )


def test_validator_allows_identical_but_rejects_conflicting_effective_policy() -> None:
    common = {"event_filter": {"type": "limit", "track": "by_src", "count": 1, "seconds": 60}}
    identical = _scenario(
        ConnectionEventSpec(
            dst_ip="198.51.100.10", ids_alerts=[{"sid": 2028401, "policy": common}]
        ),
        ConnectionEventSpec(
            dst_ip="198.51.100.11", ids_alerts=[{"sid": 2028401, "policy": common}]
        ),
    )
    assert not any(
        "conflicting effective" in issue.message
        for issue in ScenarioValidator(identical).validate()
    )

    conflicting = _scenario(
        ConnectionEventSpec(
            dst_ip="198.51.100.10", ids_alerts=[{"sid": 2028401, "policy": common}]
        ),
        ConnectionEventSpec(
            dst_ip="198.51.100.11", ids_alerts=[{"sid": 2028401, "policy": "every"}]
        ),
    )
    assert any(
        issue.severity == "error" and "conflicting effective" in issue.message
        for issue in ScenarioValidator(conflicting).validate()
    )


def test_validator_warns_on_signature_port_and_direction_mismatch() -> None:
    scenario = _scenario(
        ConnectionEventSpec(
            dst_ip="198.51.100.10",
            dst_port=443,
            ids_alerts=[{"sid": 2002910}],
        )
    )
    issues = ScenarioValidator(scenario).validate()
    warnings = [issue.message for issue in issues if issue.severity == "warning"]
    assert any("destination port" in message for message in warnings)
    assert any("direction" in message for message in warnings)


@pytest.mark.parametrize(
    "spec",
    [
        SshSessionEventSpec(source_ip="198.51.100.10", ids_alerts=[{"sid": 2028401}]),
        RdpSessionEventSpec(source_ip="198.51.100.10", ids_alerts=[{"sid": 2028401}]),
        DhcpLeaseEventSpec(ids_alerts=[{"sid": 2028401}]),
        DnsQueryEventSpec(
            query="missing.example.test",
            rcode="NXDOMAIN",
            ids_alerts=[{"sid": 2028401}],
        ),
        PortScanEventSpec(
            target_ips=["198.51.100.10"],
            ports=[22, 80],
            ids_alerts=[{"sid": 2028401}],
        ),
        WebScanEventSpec(
            dst_ip="198.51.100.10",
            dst_port=80,
            rate=1,
            count=1,
            preset="nikto",
            ids_alerts=[{"sid": 2028401}],
        ),
    ],
)
def test_validator_uses_transport_owner_protocol_and_ports_for_warnings(spec: object) -> None:
    warnings = [
        issue.message
        for issue in ScenarioValidator(_scenario(spec)).validate()
        if issue.severity == "warning" and "IDS SID" in issue.message
    ]
    assert any("protocol" in message or "destination port" in message for message in warnings)


def test_detection_filter_suppresses_warmup_then_stays_above_rolling_threshold() -> None:
    policy = IdsAlertPolicyContext(
        detection_filter=IdsDetectionFilterContext(track="by_src", count=2, seconds=60)
    )
    engine = IdsAlertFilterEngine()
    assert [engine.admit(_candidate(second, policy)) for second in (0, 1, 2, 60)] == [
        False,
        False,
        True,
        True,
    ]


@pytest.mark.parametrize(
    ("filter_type", "expected"),
    [
        ("limit", [True, True, False, True]),
        ("threshold", [False, True, False, True]),
        ("both", [False, True, False, False]),
    ],
)
def test_event_filters_follow_snort_window_semantics(
    filter_type: str,
    expected: list[bool],
) -> None:
    policy = IdsAlertPolicyContext(
        event_filter=IdsEventFilterContext(
            type=filter_type,
            track="by_dst",
            count=2,
            seconds=60,
        )
    )
    engine = IdsAlertFilterEngine()
    times = (0, 1, 2, 60) if filter_type != "both" else (0, 1, 2, 59)
    assert [engine.admit(_candidate(second, policy)) for second in times] == expected


def test_exact_boundary_equal_timestamps_and_independent_tracking_keys() -> None:
    policy = IdsAlertPolicyContext(
        event_filter=IdsEventFilterContext(type="limit", track="by_src", count=1, seconds=60)
    )
    engine = IdsAlertFilterEngine()
    assert engine.admit(_candidate(0, policy))
    assert not engine.admit(_candidate(0, policy))
    assert engine.admit(_candidate(0, policy, src_ip="10.0.0.9"))
    assert engine.admit(_candidate(0, policy, sensor="ids-02"))
    assert engine.admit(_candidate(0, policy, sid=384))
    assert engine.admit(_candidate(60, policy))


def test_combined_filters_count_only_detection_admitted_matches() -> None:
    policy = IdsAlertPolicyContext(
        detection_filter=IdsDetectionFilterContext(track="by_src", count=2, seconds=60),
        event_filter=IdsEventFilterContext(type="threshold", track="by_dst", count=2, seconds=60),
    )
    engine = IdsAlertFilterEngine()
    assert [engine.admit(_candidate(second, policy)) for second in range(5)] == [
        False,
        False,
        False,
        True,
        False,
    ]


def test_snort_emitter_sorts_before_filtering_and_cleans_spool(tmp_path) -> None:
    policy = IdsAlertPolicyContext(
        event_filter=IdsEventFilterContext(type="threshold", track="by_src", count=2, seconds=60)
    )
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"),
        output_path=tmp_path,
        sensor_hostnames=["ids-01"],
    )
    for second in (2, 0, 1):
        event = OccurrenceBuilder(
            timestamp=T0 + timedelta(seconds=second),
            event_type="connection",
            network=network_plan(
                src_ip="10.0.0.8",
                src_port=50000 + second,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="tcp",
            ),
            ids_alerts=[
                IdsAlertPlan(
                    sid=2028401,
                    message="test signature",
                    classification="misc-activity",
                    policy=policy,
                )
            ],
            storyline_cluster_id="beacon-1",
        )
        event._sensor_hostnames_by_format = {"snort_alert": ["ids-01"]}
        emitter.emit(event)
    spool_path = emitter._spool_path
    assert spool_path is not None and spool_path.exists()
    emitter.close()
    assert not spool_path.exists()
    lines = (tmp_path / "ids-01" / "snort_alert.log").read_text().splitlines()
    assert len(lines) == 1
    assert "10.0.0.8:50001" in lines[0]
    assert emitter.ids_alert_summary["beacon-1"][2028401]["candidate"] == 3
    assert emitter.ids_alert_summary["beacon-1"][2028401]["emitted"] == 1
    assert emitter.ids_alert_summary["beacon-1"][2028401]["policy_filtered"] == 2


def test_snort_multiple_sids_are_independent(tmp_path) -> None:
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"),
        output_path=tmp_path / "snort.log",
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="2001:db8::1",
            src_port=55555,
            dst_ip="2001:db8::2",
            dst_port=443,
            protocol="tcp",
        ),
        ids_alerts=[
            IdsAlertPlan(sid=1001, message="first", classification="misc-activity"),
            IdsAlertPlan(sid=1002, message="second", classification="misc-activity"),
        ],
    )
    emitter.emit(event)
    emitter.close()
    output = (tmp_path / "snort.log").read_text()
    assert "[1:1001:1]" in output
    assert "[1:1002:1]" in output


def test_snort_requires_both_network_and_ids_context() -> None:
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"),
        output_path=Path("unused.log"),
    )
    tuple_only = OccurrenceBuilder(
        timestamp=T0,
        event_type="dhcp_lease",
        network=network_plan(
            src_ip="10.0.0.8",
            src_port=68,
            dst_ip="10.0.0.1",
            dst_port=67,
            protocol="udp",
        ),
    )
    ids_only = OccurrenceBuilder(
        timestamp=T0,
        event_type="custom",
        ids_alerts=[IdsAlertPlan(sid=1001, message="test", classification="misc-activity")],
    )
    dhcp_alert = OccurrenceBuilder(
        timestamp=T0,
        event_type="dhcp_lease",
        network=tuple_only.network,
        ids_alerts=[IdsAlertPlan(sid=1001, message="test", classification="misc-activity")],
    )
    assert not emitter.can_handle(tuple_only)
    assert not emitter.can_handle(ids_only)
    assert emitter.can_handle(dhcp_alert)


def test_authored_plural_ids_context_overrides_automatic_same_sid() -> None:
    automatic = IdsAlertPlan(sid=1001, message="automatic", classification="misc-activity")
    authored = IdsAlertPlan(
        sid=1001,
        message="authored",
        classification="misc-activity",
        origin="authored_attachment",
        policy=IdsAlertPolicyContext(
            event_filter=IdsEventFilterContext(type="limit", track="by_src", count=1, seconds=60)
        ),
    )
    assert normalize_ids_alerts([automatic, authored]) == (authored,)


def test_authored_same_sid_precedence_records_authored_origin(tmp_path) -> None:
    authored = IdsAlertPlan(
        sid=1001,
        message="authored",
        classification="misc-activity",
        origin="authored_attachment",
    )
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"), output_path=tmp_path / "snort.log"
    )
    emitter.emit(
        OccurrenceBuilder(
            timestamp=T0,
            event_type="connection",
            network=network_plan(
                src_ip="10.0.0.8",
                src_port=50000,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="tcp",
            ),
            ids_alerts=(authored,),
        )
    )
    emitter.close()

    summary = emitter.ids_evaluation_summary["__direct__"]["1:1001"]
    assert summary["origins"] == {"authored_attachment": 1}
    assert "authored" in (tmp_path / "snort.log").read_text()


def test_raw_snort_entry_is_included_without_output_change(tmp_path) -> None:
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"), output_path=tmp_path / "snort.log"
    )
    raw = {
        "timestamp": T0,
        "gid": 1,
        "sid": 77,
        "rev": 2,
        "message": "raw alert",
        "classification": "misc-activity",
        "priority": 3,
        "protocol": "udp",
        "src_ip": "2001:db8::1",
        "src_port": 53,
        "dst_ip": "2001:db8::2",
        "dst_port": 53000,
    }
    emitter.emit_raw(raw)
    emitter.close()

    assert "[1:77:2] raw alert" in (tmp_path / "snort.log").read_text()
    summary = emitter.ids_evaluation_summary["__direct__"]["1:77"]
    assert summary["candidate"] == summary["emitted"] == 1
    assert summary["origins"] == {"raw": 1}


def test_snort_sensor_filter_counters_are_independent(tmp_path) -> None:
    policy = IdsAlertPolicyContext(
        event_filter=IdsEventFilterContext(type="limit", track="by_src", count=1, seconds=60)
    )
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"),
        output_path=tmp_path,
        sensor_hostnames=["inside", "outside"],
    )
    for second in (0, 1):
        event = OccurrenceBuilder(
            timestamp=T0 + timedelta(seconds=second),
            event_type="connection",
            network=network_plan(
                src_ip="10.0.0.8",
                src_port=50000,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="tcp",
            ),
            ids_alerts=[
                IdsAlertPlan(
                    sid=2028401,
                    message="test",
                    classification="misc-activity",
                    policy=policy,
                )
            ],
            storyline_cluster_id="multi-sensor",
        )
        event._sensor_hostnames_by_format = {"snort_alert": ["inside", "outside"]}
        emitter.emit(event)
    emitter.close()
    assert len((tmp_path / "inside" / "snort_alert.log").read_text().splitlines()) == 1
    assert len((tmp_path / "outside" / "snort_alert.log").read_text().splitlines()) == 1
    totals = emitter.ids_alert_summary["multi-sensor"][2028401]
    assert totals["candidate"] == 4
    assert totals["emitted"] == 2
    assert totals["policy_filtered"] == 2
    evaluation = emitter.ids_evaluation_summary
    for sensor in ("inside", "outside"):
        summary = evaluation[sensor]["1:2028401"]
        assert summary["candidate"] == 2
        assert summary["emitted"] == 1
        assert summary["policy_filtered"] == 1


def test_snort_spool_is_removed_when_final_rendering_fails(tmp_path, monkeypatch) -> None:
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"),
        output_path=tmp_path / "snort.log",
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.8",
            src_port=50000,
            dst_ip="198.51.100.10",
            dst_port=443,
            protocol="tcp",
        ),
        ids_alerts=[IdsAlertPlan(sid=1001, message="test", classification="misc-activity")],
    )
    emitter.emit(event)
    spool_path = emitter._spool_path
    assert spool_path is not None and spool_path.exists()

    def fail_render(_event_data):
        raise RuntimeError("render failed")

    monkeypatch.setattr(emitter, "_render_alert", fail_render)
    with pytest.raises(RuntimeError, match="render failed"):
        emitter.close()
    assert not spool_path.exists()


def test_no_ids_sensor_creates_no_candidate_totals_or_output(tmp_path) -> None:
    emitter = SnortEmitter(format_def=load_format("snort_alert"), output_path=tmp_path)
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.8",
            src_port=50000,
            dst_ip="198.51.100.10",
            dst_port=443,
            protocol="tcp",
        ),
        ids_alerts=[IdsAlertPlan(sid=1001, message="test", classification="misc-activity")],
        storyline_cluster_id="no-sensor",
    )
    emitter.emit(event)
    emitter.close()
    assert emitter.ids_alert_summary == {}
    assert not list(tmp_path.rglob("snort_alert.log"))


def test_threaded_and_non_threaded_snort_are_byte_equivalent(tmp_path) -> None:
    def generate(output_path: Path, *, threaded: bool) -> bytes:
        emitter = SnortEmitter(
            format_def=load_format("snort_alert"),
            output_path=output_path,
            threaded=threaded,
        )
        for second in (4, 0, 2, 1, 3):
            event = OccurrenceBuilder(
                timestamp=T0 + timedelta(seconds=second),
                event_type="connection",
                network=network_plan(
                    src_ip="10.0.0.8",
                    src_port=50000 + second,
                    dst_ip="198.51.100.10",
                    dst_port=443,
                    protocol="tcp",
                ),
                ids_alerts=[IdsAlertPlan(sid=1001, message="test", classification="misc-activity")],
            )
            emitter.emit(event)
        emitter.barrier_flush()
        emitter.close()
        return output_path.read_bytes()

    plain = generate(tmp_path / "plain.log", threaded=False)
    threaded = generate(tmp_path / "threaded.log", threaded=True)
    assert threaded == plain


def test_multi_day_candidates_remain_out_of_memory_buffers(tmp_path) -> None:
    policy = IdsAlertPolicyContext(
        event_filter=IdsEventFilterContext(type="limit", track="by_src", count=1, seconds=86_400)
    )
    emitter = SnortEmitter(
        format_def=load_format("snort_alert"),
        output_path=tmp_path / "multi-day.log",
    )
    for minute in range(4_000):
        event = OccurrenceBuilder(
            timestamp=T0 + timedelta(minutes=minute),
            event_type="connection",
            network=network_plan(
                src_ip="10.0.0.8",
                src_port=50000 + minute % 1000,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="tcp",
            ),
            ids_alerts=[
                IdsAlertPlan(
                    sid=1001,
                    message="test",
                    classification="misc-activity",
                    policy=policy,
                )
            ],
        )
        emitter.emit(event)
    assert emitter._writers == {}
    assert emitter._spool_connection is not None
    count = emitter._spool_connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
    assert count == 4_000
    emitter.close()
    assert len((tmp_path / "multi-day.log").read_text().splitlines()) == 3


def test_ids_documentation_and_skill_reference_stay_in_parity() -> None:
    paths = (
        PROJECT_ROOT / "docs" / "reference" / "scenario-reference.md",
        PROJECT_ROOT / "commands" / "eforge" / "references" / "scenario-reference.md",
        PROJECT_ROOT / "docs" / "reference" / "EVIDENCE_FORMATS.md",
        PROJECT_ROOT / "commands" / "eforge" / "references" / "evidence-network-ids.md",
    )
    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert "ids_alerts" in content
        assert "policy" in content
        assert "does not" in content
        assert "dhcp_lease" in content
        assert "dns_tunnel" in content
        assert "email" in content
        if "evidence" in path.name.lower():
            assert "ids_evaluation" in content
