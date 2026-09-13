"""Joint packet-admission and Kerberos processing windows."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, KerberosContext
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.activity.timing_profiles import TimingWindow, get_timing_window
from evidenceforge.generation.source_timing import SourceTimingPlanner, endpoint_event_render_key
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import StateError
from tests.network_factories import network_plan

_START = datetime(2026, 4, 11, 16, 21, 28, 53618, tzinfo=UTC)
_FORMAT = "windows_event_security"
_WFP_KEY = "windows.wfp_connection"


def _events(
    *,
    protocol: str = "udp",
    duration_us: int = 12_000,
    event_type: str = "kerberos_service",
    source_port: int = 51837,
) -> tuple[OccurrenceBuilder, OccurrenceBuilder]:
    host = HostContext(
        hostname="dc01",
        ip="192.168.1.10",
        os="Windows Server 2022",
        os_category="windows",
        system_type="domain_controller",
    )
    transport = network_plan(
        src_ip="192.168.2.107",
        src_port=source_port,
        dst_ip=host.ip,
        dst_port=88,
        protocol=protocol,
        service="kerberos",
        source_visible_start_time=_START,
        source_visible_close_time=_START + timedelta(microseconds=duration_us),
        conn_state="SF",
    )
    lifecycle = ActionLifecycleContext(
        group_id=transport.stable_id, canonical_start=_START, phase="dependent"
    )
    wfp = OccurrenceBuilder(
        timestamp=_START,
        event_type="wfp_connection",
        src_host=host,
        network=transport,
        lifecycle=lifecycle,
    )
    kdc = OccurrenceBuilder(
        timestamp=_START - timedelta(milliseconds=50),
        event_type=event_type,
        dst_host=host,
        network=transport,
        lifecycle=lifecycle,
        kerberos=KerberosContext(
            target_username="wkstn007$",
            target_domain="HALCYONTRUST.ORG",
            service_name="host/dc01",
            source_ip="::ffff:192.168.2.107",
            source_port=source_port,
        ),
    )
    return wfp, kdc


def _close(planner: SourceTimingPlanner, wfp: OccurrenceBuilder) -> datetime:
    assert wfp.network is not None and wfp.network.closed_at is not None
    assert wfp.src_host is not None
    return planner._runtime_endpoint_clock_time(
        wfp.network.closed_at,
        hostname=wfp.src_host.hostname,
        os_category=wfp.src_host.os_category,
    )


def _admit_with_candidate(
    planner: SourceTimingPlanner, wfp: OccurrenceBuilder, preferred: datetime
) -> datetime:
    original = planner._windows_wfp_time_inside_transport

    def place(
        event: OccurrenceBuilder,
        *,
        source_instance: str,
        hostname: str,
        preferred: datetime,
    ) -> datetime:
        return original(
            event, source_instance=source_instance, hostname=hostname, preferred=candidate
        )

    candidate = preferred
    with patch.object(planner, "_windows_wfp_time_inside_transport", side_effect=place):
        planner.plan_event(wfp, _FORMAT)
    planner.record_admitted_source_event(wfp, _FORMAT)
    assert wfp.source_timing is not None
    return wfp.source_timing.finalized_times[_WFP_KEY]


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize(
    "event_type", ["kerberos_tgt", "kerberos_service", "kerberos_preauth_failed"]
)
def test_two_microsecond_kdc_window_is_repaired_before_wfp_admission(
    protocol: str, event_type: str
) -> None:
    planner = SourceTimingPlanner()
    wfp, kdc = _events(protocol=protocol, event_type=event_type)
    transport = wfp.network
    close = _close(planner, wfp)
    permit = _admit_with_candidate(planner, wfp, close - timedelta(microseconds=2))
    planner.plan_event(kdc, _FORMAT)
    assert kdc.source_timing is not None and kdc.dst_host is not None
    audit = kdc.source_timing.finalized_times[endpoint_event_render_key(_FORMAT, "dc01")]
    assert _START <= permit < audit < close
    assert close - permit >= timedelta(microseconds=1003)
    assert wfp.network is transport and kdc.network is transport


def test_permit_candidate_with_existing_processing_headroom_is_unchanged() -> None:
    planner = SourceTimingPlanner()
    wfp, _ = _events()
    candidate = _START + timedelta(milliseconds=4)
    assert _admit_with_candidate(planner, wfp, candidate) == candidate


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_pair_of_kdc_audits_fits_after_one_admitted_permit(protocol: str) -> None:
    planner = SourceTimingPlanner()
    wfp, tgt = _events(protocol=protocol, event_type="kerberos_tgt")
    tgs = replace(tgt, event_type="kerberos_service", source_timing=None)
    close = _close(planner, wfp)
    permit = _admit_with_candidate(planner, wfp, close - timedelta(microseconds=2))
    previous = permit
    for event in (tgt, tgs):
        planner.plan_event(event, _FORMAT)
        planner.record_admitted_source_event(event, _FORMAT)
        assert event.source_timing is not None
        timestamp = event.source_timing.finalized_times[endpoint_event_render_key(_FORMAT, "dc01")]
        assert previous < timestamp < close
        previous = timestamp


@pytest.mark.parametrize("seed", [42, 137])
@pytest.mark.parametrize("profile", ["complete", "enterprise_standard"])
@pytest.mark.parametrize("duration_us", [6_000, 12_000, 180_000])
def test_repaired_permits_retain_population_variation_and_clock_bounds(
    seed: int, profile: str, duration_us: int
) -> None:
    permits: set[datetime] = set()
    for ordinal in range(20):
        planner = SourceTimingPlanner(
            profile,
            timing_runtime=TimingRuntime(
                reference_time=_START - timedelta(days=3), generation_seed=seed
            ),
        )
        wfp, kdc = _events(duration_us=duration_us, source_port=51800 + ordinal)
        close = _close(planner, wfp)
        permit = _admit_with_candidate(planner, wfp, close + timedelta(milliseconds=5))
        planner.plan_event(kdc, _FORMAT)
        assert kdc.source_timing is not None
        floor = planner._runtime_endpoint_clock_time(_START, hostname="dc01", os_category="windows")
        assert (
            floor
            <= permit
            < kdc.source_timing.finalized_times[endpoint_event_render_key(_FORMAT, "dc01")]
            < close
        )
        permits.add(permit)
    assert len(permits) >= 15


@pytest.mark.parametrize("minimum_ms", [0, 1, 5])
def test_joint_window_uses_configured_kdc_delay_bounds(minimum_ms: int) -> None:
    def configured(key: str, **defaults: object) -> TimingWindow:
        if key == "windows.kerberos_after_wfp":
            return TimingWindow(minimum_ms, minimum_ms + 15, "after", "source_latency")
        return get_timing_window(key, **defaults)

    planner = SourceTimingPlanner()
    wfp, kdc = _events(duration_us=30_000)
    close = _close(planner, wfp)
    with patch("evidenceforge.generation.source_timing.get_timing_window", side_effect=configured):
        permit = _admit_with_candidate(planner, wfp, close - timedelta(microseconds=2))
        planner.plan_event(kdc, _FORMAT)
    assert kdc.source_timing is not None
    audit = kdc.source_timing.finalized_times[endpoint_event_render_key(_FORMAT, "dc01")]
    assert close - permit >= timedelta(microseconds=2 * (minimum_ms * 1000 + 3))
    assert (
        timedelta(milliseconds=minimum_ms)
        < audit - permit
        < timedelta(milliseconds=minimum_ms + 15, microseconds=1)
    )


def test_latest_permit_leaves_two_sampleable_delays_for_each_pair_member() -> None:
    tgt_delays: set[int] = set()
    tgs_delays: set[int] = set()
    for ordinal in range(80):
        planner = SourceTimingPlanner()
        wfp, tgt = _events(event_type="kerberos_tgt", source_port=51800 + ordinal)
        tgs = replace(tgt, event_type="kerberos_service", source_timing=None)
        close = _close(planner, wfp)
        preferred = close - timedelta(microseconds=2006)
        permit = _admit_with_candidate(planner, wfp, preferred)
        assert permit == preferred
        for event in (tgt, tgs):
            planner.plan_event(event, _FORMAT)
            assert event.source_timing is not None
        tgt_time = tgt.source_timing.finalized_times[endpoint_event_render_key(_FORMAT, "dc01")]
        # Force the published predecessor to the latest valid TGT time, testing
        # the sibling-order repair with the smallest remaining paired window.
        planner.record_admitted_source_event(tgt, _FORMAT)
        assert tgt.lifecycle is not None
        planner._latest_session_dependent_times[("windows_security", tgt.lifecycle.group_id)] = (
            close - timedelta(microseconds=1004)
        )
        tgs = replace(tgs, source_timing=None)
        planner.plan_event(tgs, _FORMAT)
        assert tgs.source_timing is not None
        tgs_time = tgs.source_timing.finalized_times[endpoint_event_render_key(_FORMAT, "dc01")]
        assert permit < tgt_time < tgs_time < close
        tgt_delays.add((tgt_time - permit) // timedelta(microseconds=1))
        tgs_delays.add((close - tgs_time) // timedelta(microseconds=1))
    assert tgt_delays == {1001, 1002}
    assert len(tgs_delays) > 2


@pytest.mark.parametrize("duration_us", [0, 2006, 2007])
def test_infeasible_wfp_window_rejects_without_admitting_or_mutating_transport(
    duration_us: int,
) -> None:
    planner = SourceTimingPlanner()
    wfp, _ = _events(duration_us=duration_us)
    transport = wfp.network
    with pytest.raises(StateError, match="WFP source window"):
        _admit_with_candidate(planner, wfp, _START + timedelta(seconds=1))
    assert wfp.network is transport
    assert not planner._admitted_windows_transport_transactions


def test_process_visibility_floor_cannot_be_moved_back_to_make_kdc_space() -> None:
    planner = SourceTimingPlanner()
    wfp, _ = _events()
    wfp.timestamp = _START + timedelta(microseconds=10_500)
    with pytest.raises(StateError, match="WFP source window cannot fit"):
        _admit_with_candidate(planner, wfp, _close(planner, wfp))


@pytest.mark.parametrize("minimum_ms,maximum_ms", [(0, 0), (1, 1)])
def test_unsampleable_profile_is_an_explicit_error(minimum_ms: int, maximum_ms: int) -> None:
    planner = SourceTimingPlanner()
    wfp, _ = _events()
    original = get_timing_window

    def configured(key: str, **defaults: object) -> TimingWindow:
        if key == "windows.kerberos_after_wfp":
            return TimingWindow(minimum_ms, maximum_ms, "after", "source_latency")
        return original(key, **defaults)

    with (
        patch("evidenceforge.generation.source_timing.get_timing_window", side_effect=configured),
        pytest.raises(StateError, match="two whole-microsecond delays"),
    ):
        _admit_with_candidate(planner, wfp, _START)


@pytest.mark.parametrize("variant", ["outbound", "dns", "other-port", "icmp"])
def test_non_kdc_wfp_candidates_do_not_reserve_ticket_processing(variant: str) -> None:
    planner = SourceTimingPlanner()
    wfp, _ = _events()
    assert wfp.network is not None and wfp.src_host is not None
    if variant == "outbound":
        wfp.src_host = replace(wfp.src_host, hostname="wkstn007", ip=wfp.network.src_ip)
    elif variant == "dns":
        wfp.network = replace(wfp.network, service="dns", dst_port=53)
    elif variant == "other-port":
        wfp.network = replace(wfp.network, dst_port=389)
    else:
        wfp.network = replace(wfp.network, protocol="icmp")
    candidate = _close(planner, wfp) - timedelta(microseconds=2)
    assert _admit_with_candidate(planner, wfp, candidate) == candidate


@pytest.mark.parametrize("mismatch", ["absent", "host", "tuple", "transaction"])
def test_kdc_only_consumes_an_exact_admitted_permit(mismatch: str) -> None:
    planner = SourceTimingPlanner()
    wfp, kdc = _events()
    if mismatch != "absent":
        _admit_with_candidate(planner, wfp, _START + timedelta(milliseconds=4))
    assert kdc.network is not None and kdc.lifecycle is not None
    if mismatch == "host":
        assert kdc.dst_host is not None
        kdc.dst_host = replace(kdc.dst_host, hostname="dc02", ip="192.168.1.11")
    elif mismatch == "tuple":
        kdc.network = replace(kdc.network, src_port=60000)
    elif mismatch == "transaction":
        kdc.lifecycle = replace(kdc.lifecycle, group_id="another-transaction")
    assert kdc.dst_host is not None
    preferred = _START - timedelta(milliseconds=20)
    assert (
        planner._windows_kdc_time_after_wfp(
            kdc,
            source_instance=f"windows_security:{kdc.dst_host.hostname}",
            hostname=kdc.dst_host.hostname,
            preferred=preferred,
        )
        == preferred
    )


def test_admitted_kdc_transport_requires_its_immutable_close() -> None:
    planner = SourceTimingPlanner()
    wfp, kdc = _events()
    _admit_with_candidate(planner, wfp, _START + timedelta(milliseconds=4))
    assert kdc.network is not None
    kdc.network = replace(kdc.network, closed_at=None, duration=None)
    with pytest.raises(StateError, match="missing its canonical close"):
        planner.plan_event(kdc, _FORMAT)


@pytest.mark.parametrize("mismatch", ["absent", "host", "tuple", "transaction"])
def test_unobserved_transport_preserves_existing_paired_ticket_order(mismatch: str) -> None:
    planner = SourceTimingPlanner()
    wfp, kdc = _events()
    if mismatch != "absent":
        _admit_with_candidate(planner, wfp, _START + timedelta(milliseconds=4))
    assert kdc.network is not None and kdc.lifecycle is not None and kdc.dst_host is not None
    if mismatch == "host":
        kdc.dst_host = replace(kdc.dst_host, hostname="dc02", ip="192.168.1.11")
    elif mismatch == "tuple":
        kdc.network = replace(kdc.network, src_port=60000)
    elif mismatch == "transaction":
        kdc.lifecycle = replace(kdc.lifecycle, group_id="another-transaction")
    # An unobserved transport supplies no source-local WFP timing fence. Its
    # observed tickets retain the existing source-dependent ordering policy.
    previous = _close(planner, wfp) + timedelta(milliseconds=1)
    planner._latest_session_dependent_times[("windows_security", kdc.lifecycle.group_id)] = previous
    repaired = previous + timedelta(milliseconds=2)
    with patch.object(planner, "_sample_after_floor", return_value=repaired) as sample:
        actual = planner._apply_runtime_session_constraints(
            kdc,
            family="windows_security",
            source_instance=f"windows_security:{kdc.dst_host.hostname}",
            hostname=kdc.dst_host.hostname,
            preferred=previous,
        )
    assert actual == repaired
    sample.assert_called_once()
    assert sample.call_args.kwargs["relationship_key"] == "windows_security.session.dependent_order"


def test_kdc_preparation_cancels_and_retries_with_live_timing_parity() -> None:
    live = SourceTimingPlanner()
    wfp, kdc = _events()
    live.plan_event(wfp, _FORMAT)
    live.record_admitted_source_event(wfp, _FORMAT)
    live.plan_event(kdc, _FORMAT)
    live.record_admitted_source_event(kdc, _FORMAT)
    staged = SourceTimingPlanner()
    before = (
        staged.state_digest(),
        staged.census(estimate_bytes=True),
        staged.timing_runtime.audit.snapshot(),
    )
    with staged.prepared_planning() as cancelled:
        other_wfp, other_kdc = _events()
        cancelled.plan_event(other_wfp, _FORMAT)
        cancelled.record_admitted_source_event(other_wfp, _FORMAT)
        cancelled.plan_event(other_kdc, _FORMAT)
        cancelled.record_admitted_source_event(other_kdc, _FORMAT)
    cancelled.cancel()
    cancelled.cancel()
    assert before == (
        staged.state_digest(),
        staged.census(estimate_bytes=True),
        staged.timing_runtime.audit.snapshot(),
    )
    with staged.prepared_planning() as retry:
        other_wfp, other_kdc = _events()
        retry.plan_event(other_wfp, _FORMAT)
        retry.record_admitted_source_event(other_wfp, _FORMAT)
        retry.plan_event(other_kdc, _FORMAT)
        retry.record_admitted_source_event(other_kdc, _FORMAT)
    with retry.claimed_commit():
        retry.commit_no_fail()
    assert wfp.source_timing == other_wfp.source_timing
    assert kdc.source_timing == other_kdc.source_timing
    assert staged.state_digest() == live.state_digest()
    assert staged.timing_runtime.audit.snapshot() == live.timing_runtime.audit.snapshot()
