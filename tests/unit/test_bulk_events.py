# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for bulk/periodic event types and shared timing engine."""

import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from evidenceforge.generation.engine.storyline import (
    StorylineMixin,
    _c2_http_response_size,
    _effective_rate_interval,
    _is_c2_http_request,
    _iter_dns_tunnel_ticks,
    _iter_periodic_ticks,
    _iter_shuffled_port_scan_pairs,
    _observed_web_scan_status,
    _port_scan_connection_profile,
    _scan_target_exposes_port,
    _web_scan_connection_profile,
    _web_scan_path_allows_referrer,
)
from evidenceforge.models import System, User
from evidenceforge.models.scenario import (
    BeaconEventSpec,
    CredentialSprayEventSpec,
    DgaQueriesEventSpec,
    DnsQueryEventSpec,
    DnsTunnelEventSpec,
    ExplicitCredentialsEventSpec,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    PortScanEventSpec,
    WebScanEventSpec,
    WorkstationLockEventSpec,
    WorkstationUnlockEventSpec,
    _PeriodicEventBase,
)

# ── _PeriodicEventBase validation ─────────────────────────────────────────


class TestPeriodicEventBase:
    """Test shared timing field validation on _PeriodicEventBase."""

    def _make(self, **kw):
        """Helper: create a concrete _PeriodicEventBase with a dummy type.

        _PeriodicEventBase isn't a standalone event type, but BeaconEventSpec
        inherits it and adds its own constraints. We test the base validators
        via BeaconEventSpec to avoid needing a stub class.
        """
        defaults = {"dst_ip": "1.2.3.4", "interval": "5m", "duration": "1h", "action": "deny"}
        defaults.update(kw)
        return BeaconEventSpec(**defaults)

    def test_exactly_one_termination_duration(self):
        spec = self._make(duration="1h")
        assert spec.duration == "1h"
        assert spec.count is None
        assert spec.end_time is None

    def test_exactly_one_termination_count(self):
        spec = self._make(duration=None, count=50)
        assert spec.count == 50

    def test_exactly_one_termination_end_time(self):
        spec = self._make(duration=None, end_time="2026-04-20T12:00:00Z")
        assert spec.end_time is not None

    def test_rejects_multiple_terminations(self):
        with pytest.raises(ValidationError, match="Exactly one"):
            self._make(duration="1h", count=50)

    def test_rejects_no_termination(self):
        with pytest.raises(ValidationError, match="Exactly one"):
            self._make(duration=None, count=None, end_time=None)

    def test_rejects_interval_and_rate_together(self):
        with pytest.raises(ValidationError, match="mutually exclusive"):
            self._make(interval="5m", rate=10.0)

    def test_rejects_neither_interval_nor_rate(self):
        with pytest.raises(ValidationError, match="Either interval or rate"):
            self._make(interval=None, rate=None)

    def test_rejects_zero_interval(self):
        with pytest.raises(ValidationError, match="greater than 0"):
            self._make(interval="0s")

    def test_rejects_zero_duration(self):
        with pytest.raises(ValidationError, match="greater than 0"):
            self._make(duration="0s")

    def test_rejects_negative_count(self):
        with pytest.raises(ValidationError):
            self._make(duration=None, count=0)

    def test_rejects_negative_rate(self):
        """Rate must be positive (tested via a type that accepts rate)."""
        with pytest.raises(ValidationError, match="greater than 0"):
            # BeaconEventSpec rejects rate, so test the validator directly
            # by temporarily using the base validation path
            _PeriodicEventBase(interval=None, rate=-5.0, duration="1h")

    def test_jitter_bounds(self):
        with pytest.raises(ValidationError):
            self._make(jitter=-0.1)
        with pytest.raises(ValidationError):
            self._make(jitter=1.5)

    def test_jitter_default(self):
        # Base class default is 0.2; concrete subclasses override with event-type defaults
        spec = self._make()
        assert 0.0 <= spec.jitter <= 1.0


# ── BeaconEventSpec ───────────────────────────────────────────────────────


class TestBeaconEventSpec:
    def test_defaults(self):
        spec = BeaconEventSpec(dst_ip="1.2.3.4", interval="5m", duration="1h")
        assert spec.type == "beacon"
        assert spec.action == "allow"
        assert spec.dst_port == 443
        assert spec.protocol == "tcp"
        assert spec.jitter == 0.15  # Beacons are deliberately tight

    def test_deny_action(self):
        spec = BeaconEventSpec(dst_ip="1.2.3.4", interval="30m", count=10, action="deny")
        assert spec.action == "deny"
        assert spec.count == 10

    def test_all_connection_fields(self):
        spec = BeaconEventSpec(
            dst_ip="1.2.3.4",
            dst_port=8080,
            hostname="evil.com",
            service="http",
            source_ip="10.0.0.5",
            protocol="tcp",
            method="GET",
            uri="/callback",
            status_code=200,
            user_agent="Mozilla/5.0",
            orig_bytes=500,
            resp_bytes=1000,
            conn_state="SF",
            response_body_len=1000,
            interval="5m",
            duration="2h",
            action="allow",
        )
        assert spec.hostname == "evil.com"
        assert spec.orig_bytes == 500

    def test_rejects_rate(self):
        with pytest.raises(ValidationError, match="interval"):
            BeaconEventSpec(dst_ip="1.2.3.4", rate=10.0, duration="1h")

    def test_requires_interval(self):
        with pytest.raises(ValidationError, match="interval"):
            BeaconEventSpec(dst_ip="1.2.3.4", duration="1h")

    def test_hostname_validation(self):
        with pytest.raises(ValidationError):
            BeaconEventSpec(
                dst_ip="1.2.3.4",
                hostname="http://evil.com",
                interval="5m",
                duration="1h",
            )

    def test_blocked_c2_import_removed(self):
        with pytest.raises(ImportError):
            from evidenceforge.models.scenario import BlockedC2EventSpec  # noqa: F401


# ── DnsQueryEventSpec ─────────────────────────────────────────────────────


class TestDnsQueryEventSpec:
    def test_defaults(self):
        spec = DnsQueryEventSpec(query="evil.com", answer="1.2.3.4")
        assert spec.type == "dns_query"
        assert spec.qtype == "A"
        assert spec.rcode == "NOERROR"
        assert spec.answer == "1.2.3.4"

    def test_nxdomain_no_answer(self):
        spec = DnsQueryEventSpec(query="random.xyz", rcode="NXDOMAIN")
        assert spec.answer is None

    def test_servfail_no_answer(self):
        spec = DnsQueryEventSpec(query="timeout.com", rcode="SERVFAIL")
        assert spec.answer is None

    def test_refused_no_answer(self):
        spec = DnsQueryEventSpec(query="blocked.com", rcode="REFUSED")
        assert spec.answer is None

    def test_noerror_requires_answer(self):
        with pytest.raises(ValidationError, match="answer is required"):
            DnsQueryEventSpec(query="evil.com", rcode="NOERROR")

    def test_answer_list(self):
        spec = DnsQueryEventSpec(query="cdn.example.com", answer=["1.2.3.4", "5.6.7.8"])
        assert spec.answer == ["1.2.3.4", "5.6.7.8"]

    def test_valid_qtypes(self):
        for qt in ("A", "AAAA", "TXT", "CNAME", "MX", "NULL", "SRV", "PTR"):
            spec = DnsQueryEventSpec(query="test.com", qtype=qt, rcode="NXDOMAIN")
            assert spec.qtype == qt

    def test_invalid_qtype(self):
        with pytest.raises(ValidationError, match="qtype"):
            DnsQueryEventSpec(query="test.com", qtype="INVALID", rcode="NXDOMAIN")

    def test_case_insensitive_qtype(self):
        spec = DnsQueryEventSpec(query="test.com", qtype="txt", rcode="NXDOMAIN")
        assert spec.qtype == "TXT"

    def test_case_insensitive_rcode(self):
        spec = DnsQueryEventSpec(query="test.com", rcode="nxdomain")
        assert spec.rcode == "NXDOMAIN"

    def test_invalid_rcode(self):
        with pytest.raises(ValidationError, match="rcode"):
            DnsQueryEventSpec(query="test.com", rcode="BADCODE")

    def test_ttl_optional(self):
        spec = DnsQueryEventSpec(query="test.com", answer="1.2.3.4")
        assert spec.ttl is None

    def test_ttl_explicit(self):
        spec = DnsQueryEventSpec(query="test.com", answer="1.2.3.4", ttl=300)
        assert spec.ttl == 300

    def test_source_ip_optional(self):
        spec = DnsQueryEventSpec(query="test.com", rcode="NXDOMAIN")
        assert spec.source_ip is None


# ── _iter_periodic_ticks ──────────────────────────────────────────────────


class TestIterPeriodicTicks:
    def test_count_based(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        ticks = list(_iter_periodic_ticks(start, 60.0, None, 5, 0.0, rng))
        assert len(ticks) == 5

    def test_duration_based(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        ticks = list(_iter_periodic_ticks(start, 60.0, 300.0, None, 0.0, rng))
        # duration=300s, interval=60s → ticks at t=0,60,120,180,240,300 → 6 ticks
        assert len(ticks) == 6

    def test_zero_jitter_exact_spacing(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        ticks = list(_iter_periodic_ticks(start, 60.0, None, 4, 0.0, rng))
        for i, tick in enumerate(ticks):
            expected = start + timedelta(seconds=60.0 * i)
            assert tick == expected, f"tick {i}: {tick} != {expected}"

    def test_jitter_within_bounds(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        interval = 60.0
        jitter = 0.2
        ticks = list(_iter_periodic_ticks(start, interval, None, 100, jitter, rng))
        assert len(ticks) == 100
        for i, tick in enumerate(ticks):
            nominal = start + timedelta(seconds=interval * i)
            max_offset = timedelta(seconds=jitter * interval)
            # Tick should be within jitter window of nominal (clamped to >= start)
            assert tick >= start
            assert tick <= nominal + max_offset

    def test_single_tick(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        ticks = list(_iter_periodic_ticks(start, 60.0, None, 1, 0.0, rng))
        assert len(ticks) == 1
        assert ticks[0] == start

    def test_dns_tunnel_ticks_include_natural_gaps(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        ticks = list(_iter_dns_tunnel_ticks(start, 2.0, 900.0, None, 0.25, rng))
        intervals = [
            (later - earlier).total_seconds()
            for earlier, later in zip(ticks, ticks[1:], strict=False)
        ]

        assert len(ticks) < 451
        assert max(intervals) > 8.0
        assert sum(interval < 3.0 for interval in intervals) < len(intervals) * 0.82
        assert len({round(interval, 1) for interval in intervals}) > 20

    def test_duration_shorter_than_interval(self):
        rng = random.Random(42)
        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        # duration=30s, interval=60s → only tick at t=0 (0 <= 30)
        ticks = list(_iter_periodic_ticks(start, 60.0, 30.0, None, 0.0, rng))
        assert len(ticks) == 1

    def test_beacon_count_contract_uses_exact_periodic_ticks(self, monkeypatch):
        """Beacon handling must not inherit DNS-tunnel skip/pause pacing."""
        from types import SimpleNamespace
        from unittest.mock import Mock

        from evidenceforge.generation.engine import storyline
        from evidenceforge.generation.engine.storyline import StorylineMixin
        from evidenceforge.models.scenario import System, User

        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        expected_ticks = [start + timedelta(seconds=60 * i) for i in range(5)]

        engine = object.__new__(StorylineMixin)
        system = System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
        actor = User(username="alice", full_name="Alice Example", email="alice@example.com")
        engine.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[system]))
        engine.state_manager = Mock()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        engine.activity_generator = Mock()
        engine.activity_generator._ip_to_system = {system.ip: system}
        engine.activity_generator._proxy_routes = {}
        engine.activity_generator._proxy_mode = "transparent"

        periodic = Mock(return_value=iter(expected_ticks))
        monkeypatch.setattr(storyline, "_iter_periodic_ticks", periodic)
        monkeypatch.setattr(
            storyline,
            "_iter_dns_tunnel_ticks",
            Mock(side_effect=AssertionError("generic beacons must not use DNS tunnel pacing")),
        )

        spec = BeaconEventSpec(
            dst_ip="203.0.113.10",
            interval="60s",
            count=5,
            action="allow",
            jitter=0.0,
        )

        malicious_event = engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=system,
            time=start,
            activity="C2 beacon",
            explicit_types={"beacon"},
        )

        periodic.assert_called_once()
        assert engine.activity_generator.generate_connection.call_count == 5
        assert malicious_event["attempt_count"] == 5

    def test_service_backed_beacon_uses_installed_service_process(self, monkeypatch):
        """A SYSTEM beacon after service persistence should not fall back to svchost."""
        from unittest.mock import Mock

        from evidenceforge.generation.engine import storyline

        start = datetime(2026, 4, 16, 16, 30, 0, tzinfo=UTC)
        system = System(
            hostname="DC-01",
            ip="10.0.2.10",
            os="Windows Server 2019",
            type="server",
            roles=["domain_controller"],
        )
        actor = User(username="SYSTEM", full_name="SYSTEM", email="system@example.com")

        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[system]))
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        engine.state_manager = Mock()
        engine.state_manager.get_processes_on_system.return_value = []
        engine.activity_generator = Mock()
        engine.activity_generator._ip_to_system = {system.ip: system}
        engine.activity_generator._proxy_routes = {}
        engine.activity_generator._proxy_mode = "transparent"
        engine.activity_generator._get_system_pid.return_value = 700
        engine.activity_generator.generate_process.return_value = 4242

        engine._record_storyline_service_install(
            system=system,
            service_name="HealthMonitorSvc",
            service_file_name=r"C:\Windows\System32\HealthMonitorSvc.exe",
            service_account="LocalSystem",
            time=start - timedelta(minutes=10),
        )
        monkeypatch.setattr(storyline, "_iter_periodic_ticks", Mock(return_value=iter([start])))

        spec = BeaconEventSpec(
            dst_ip="45.33.32.30",
            dst_port=443,
            hostname="cdn-assets-update.com",
            service="http",
            method="GET",
            uri="/api/v2/checkin",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36"
            ),
            interval="10m",
            count=1,
            action="allow",
            jitter=0.0,
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=system,
            time=start,
            activity="Allowed HTTPS beacon from DC-01",
            explicit_types={"beacon"},
        )

        engine.activity_generator.generate_process.assert_called_once()
        process_kwargs = engine.activity_generator.generate_process.call_args.kwargs
        assert process_kwargs["process_name"] == r"C:\Windows\System32\HealthMonitorSvc.exe"
        assert process_kwargs["parent_pid"] == 700
        assert process_kwargs["logon_id"] == "0x3e7"

        connection_kwargs = engine.activity_generator.generate_connection.call_args.kwargs
        assert connection_kwargs["pid"] == 4242
        assert connection_kwargs["process_image"] == r"C:\Windows\System32\HealthMonitorSvc.exe"

    def test_v2_status_beacon_gets_c2_http_texture(self, monkeypatch):
        """Beacon activity should not render /v2/status as stable text/html page traffic."""
        from unittest.mock import Mock

        from evidenceforge.generation.engine import storyline

        start = datetime(2026, 4, 16, 16, 30, 0, tzinfo=UTC)
        system = System(hostname="DC-01", ip="10.0.2.10", os="Windows Server 2019", type="server")
        actor = User(username="SYSTEM", full_name="SYSTEM", email="system@example.com")

        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[system]))
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        engine.state_manager = Mock()
        engine.activity_generator = Mock()
        engine.activity_generator._ip_to_system = {system.ip: system}
        engine.activity_generator._proxy_routes = {}
        engine.activity_generator._proxy_mode = "transparent"
        monkeypatch.setattr(storyline, "_iter_periodic_ticks", Mock(return_value=iter([start])))

        spec = BeaconEventSpec(
            dst_ip="45.33.32.30",
            dst_port=443,
            hostname="api.example.net",
            service="http",
            method="GET",
            uri="/v2/status",
            interval="10m",
            count=1,
            action="allow",
            jitter=0.0,
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=system,
            time=start,
            activity="HTTPS beacon from DC-01",
            explicit_types={"beacon"},
        )

        http = engine.activity_generator.generate_connection.call_args.kwargs["http"]
        assert http.response_body_len != 54_400
        assert http.resp_mime_types[0] in {
            "application/json",
            "text/plain",
            "application/octet-stream",
        }


class TestC2HttpTexture:
    def test_v2_paths_are_c2_even_without_spec_description(self):
        assert _is_c2_http_request(
            description=None,
            technique=None,
            uri="/v2/status",
            activity=None,
        )

    def test_c2_status_response_sizes_have_multiple_bands(self):
        sizes = [
            _c2_http_response_size(random.Random(seed), method="GET", uri="/v2/status")
            for seed in range(50)
        ]

        assert min(sizes) < 2_000
        assert max(sizes) > 18_000
        assert len({size // 1000 for size in sizes}) > 10


class TestEffectiveRateInterval:
    def test_count_based_rate_stays_exact(self):
        rng = random.Random(42)
        interval = _effective_rate_interval(10.0, 100, rng)
        assert interval == 0.1

    def test_duration_based_rate_gets_campaign_drift(self):
        rng = random.Random(42)
        interval = _effective_rate_interval(10.0, None, rng)
        assert interval != 0.1
        assert (1.0 / interval) >= 8.2
        assert (1.0 / interval) <= 11.8

    @pytest.mark.parametrize("rate", [0.0, -1.0, float("inf"), float("nan")])
    def test_invalid_rate_rejected(self, rate):
        with pytest.raises(ValueError, match="positive finite"):
            _effective_rate_interval(rate, None, random.Random(42))

    def test_duration_based_rate_drift_varies_by_campaign(self):
        intervals = {
            _effective_rate_interval(10.0, None, random.Random(seed)) for seed in range(10)
        }
        assert len(intervals) > 1


class TestWebScanConnectionProfile:
    def test_profile_includes_failed_connection_outcomes(self):
        rng = random.Random(42)
        states = {_web_scan_connection_profile(rng)[0] for _ in range(200)}
        assert "SF" in states
        assert states & {"S0", "RSTO", "RSTR"}

    def test_s0_profile_has_no_response_bytes(self):
        class S0Rng(random.Random):
            def choices(self, population, weights=None, k=1):
                return ["S0"]

        state, _duration, _orig_bytes, resp_bytes = _web_scan_connection_profile(S0Rng(42))
        assert state == "S0"
        assert resp_bytes == 0

    def test_tls_profile_has_wide_duration_and_byte_distribution(self):
        rng = random.Random(42)
        samples = []
        for _ in range(400):
            sample = _web_scan_connection_profile(rng, is_tls=True)
            if sample[0] == "SF":
                samples.append(sample)
        durations = [sample[1] for sample in samples]
        resp_bytes = [sample[3] for sample in samples]
        assert max(durations) - min(durations) > 4.0
        assert max(resp_bytes) - min(resp_bytes) > 6000

    def test_scan_statuses_have_sparse_runtime_drift(self):
        rng = random.Random(42)
        statuses = [
            _observed_web_scan_status({"uri": "/admin", "status": 404}, rng) for _ in range(300)
        ]
        assert 404 in statuses
        assert set(statuses) & {403, 429, 500}

    def test_referrer_only_allowed_for_crawl_like_successes(self):
        assert _web_scan_path_allows_referrer({"uri": "/", "status": 200})
        assert not _web_scan_path_allows_referrer({"uri": "/.git/HEAD", "status": 404})
        assert not _web_scan_path_allows_referrer({"uri": "/wp-admin/", "status": 404})
        assert not _web_scan_path_allows_referrer(
            {"uri": "/robots.txt", "status": 200, "ids": {"sid": 1}}
        )


class TestPortScanPairIteration:
    def test_iter_shuffled_port_scan_pairs_covers_product_once(self):
        targets = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
        ports = [22, 80, 443, 3389]

        pairs = list(_iter_shuffled_port_scan_pairs(targets, ports, random.Random(17)))

        assert len(pairs) == len(targets) * len(ports)
        assert set(pairs) == {(target, port) for target in targets for port in ports}
        assert pairs != [(target, port) for target in targets for port in ports]

    def test_iter_shuffled_port_scan_pairs_is_lazy_generator(self):
        targets = [f"10.0.0.{index}" for index in range(1, 5001)]
        ports = list(range(1, 5001))

        iterator = _iter_shuffled_port_scan_pairs(targets, ports, random.Random(23))
        first_pairs = [next(iterator) for _ in range(8)]

        assert len(first_pairs) == 8
        assert len(set(first_pairs)) == 8
        assert all(target in targets for target, _port in first_pairs)
        assert all(port in ports for _target, port in first_pairs)


class TestPortScanConnectionProfile:
    def test_profile_uses_target_services_for_open_ports(self):
        rng = random.Random(7)
        target = System(
            hostname="WEB-01",
            ip="10.0.0.20",
            os="Ubuntu 22.04",
            type="server",
            services=["apache2", "ssh"],
            roles=["web_server"],
        )

        assert _scan_target_exposes_port(target, 80, external=True)
        assert not _scan_target_exposes_port(target, 22, external=True)
        assert _scan_target_exposes_port(
            System(
                hostname="APP-01",
                ip="10.0.0.21",
                os="Ubuntu 22.04",
                type="server",
                services=[],
                roles=["web_server"],
            ),
            80,
            external=True,
        )
        denied, conn_state, service, _duration, _orig_bytes, _resp_bytes = (
            _port_scan_connection_profile(
                rng,
                port=80,
                target_system=target,
                external=True,
                default_deny_state="S0",
            )
        )

        assert not denied
        assert conn_state in {"SF", "RSTO", "RSTR"}
        assert service == "http"

    def test_profile_includes_filtered_and_rejected_closed_ports(self):
        rng = random.Random(42)
        target = System(
            hostname="DB-01",
            ip="10.0.0.30",
            os="Ubuntu 22.04",
            type="server",
            services=["mysql"],
            roles=["database"],
        )
        samples = [
            _port_scan_connection_profile(
                rng,
                port=3389,
                target_system=target,
                external=False,
                default_deny_state="S0",
            )
            for _ in range(120)
        ]

        assert all(sample[0] for sample in samples)
        assert {sample[1] for sample in samples} >= {"S0", "REJ"}


class TestPortScanTargetResolution:
    def test_external_target_segment_uses_inferred_segment_members(self):
        """External segment scans should work when segment.systems is omitted."""
        from unittest.mock import Mock

        start = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        web = System(
            hostname="WEB-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        proxy = System(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        network = NetworkConfig(
            public_cidrs=["203.14.220.0/28"],
            segments=[
                NetworkSegment(name="dmz", cidr="10.10.3.0/24", exposure="both"),
            ],
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw-perimeter",
                    monitoring_segments=["dmz"],
                    log_formats=["cisco_asa"],
                )
            ],
        )

        class Visibility:
            _vip_to_real_ip = {"203.14.220.10": "10.10.3.10"}

            @staticmethod
            def get_public_inbound_address(ip: str) -> str | None:
                return "203.14.220.10" if ip == "10.10.3.10" else None

        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[web, proxy], network=network)
        )
        engine.dispatcher = SimpleNamespace(visibility_engine=Visibility())
        engine.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
        engine.activity_generator = Mock()
        engine.activity_generator._ip_to_system = {web.ip: web, proxy.ip: proxy}

        spec = PortScanEventSpec(
            source_ip="185.70.41.45",
            target_segment="dmz",
            target_count=8,
            ports=[80],
            scan_rate=10,
        )
        event = engine._execute_typed_event(
            spec=spec,
            actor=User(username="apache", full_name="Apache", email="apache@example.com"),
            system=web,
            time=start,
            activity="External DMZ scan",
            explicit_types={"port_scan"},
        )

        assert event["target_count"] == 1
        assert event["total_connections"] == 1
        connection_kwargs = engine.activity_generator.generate_connection.call_args.kwargs
        assert connection_kwargs["src_ip"] == "185.70.41.45"
        assert connection_kwargs["dst_ip"] == "203.14.220.10"


# ── WebScanEventSpec ──────────────────────────────────────────────────────


class TestWebScanEventSpec:
    def test_defaults(self):
        spec = WebScanEventSpec(dst_ip="10.0.0.5", rate=10.0, duration="1h", preset="nikto")
        assert spec.type == "web_scan"
        assert spec.dst_port == 80
        assert spec.rate == 10.0
        assert spec.preset == "nikto"

    def test_custom_paths(self):
        spec = WebScanEventSpec(
            dst_ip="10.0.0.5",
            rate=5.0,
            count=20,
            paths=[{"uri": "/test", "method": "GET", "status": 404}],
        )
        assert spec.paths is not None
        assert len(spec.paths) == 1

    def test_preset_and_paths(self):
        spec = WebScanEventSpec(
            dst_ip="10.0.0.5",
            rate=10.0,
            duration="30m",
            preset="dirb",
            paths=[{"uri": "/custom", "method": "GET", "status": 200}],
        )
        assert spec.preset == "dirb"
        assert spec.paths is not None

    def test_rejects_interval(self):
        with pytest.raises(ValidationError, match="rate"):
            WebScanEventSpec(dst_ip="10.0.0.5", interval="5s", duration="1h", preset="nikto")

    def test_requires_rate(self):
        with pytest.raises(ValidationError, match="rate"):
            WebScanEventSpec(dst_ip="10.0.0.5", duration="1h", preset="nikto")

    def test_requires_paths_or_preset(self):
        with pytest.raises(ValidationError, match="preset or paths"):
            WebScanEventSpec(dst_ip="10.0.0.5", rate=10.0, duration="1h")

    def test_hostname_validation(self):
        with pytest.raises(ValidationError):
            WebScanEventSpec(
                dst_ip="10.0.0.5",
                hostname="http://evil.com",
                rate=10.0,
                duration="1h",
                preset="nikto",
            )


# ── CredentialSprayEventSpec ──────────────────────────────────────────────


class TestCredentialSprayEventSpec:
    def test_defaults(self):
        spec = CredentialSprayEventSpec(
            target_accounts=["admin", "jsmith"], interval="2s", count=100
        )
        assert spec.type == "credential_spray"
        assert spec.pattern == "spray"
        assert spec.logon_type == 3
        assert spec.success is None

    def test_brute_force_pattern(self):
        spec = CredentialSprayEventSpec(
            target_accounts=["admin"],
            pattern="brute_force",
            interval="1s",
            count=50,
        )
        assert spec.pattern == "brute_force"

    def test_stuffing_pattern(self):
        spec = CredentialSprayEventSpec(
            target_accounts=["user1", "user2", "user3"],
            pattern="stuffing",
            interval="500ms",
            duration="5m",
        )
        assert spec.pattern == "stuffing"

    def test_success_field(self):
        spec = CredentialSprayEventSpec(
            target_accounts=["admin", "jsmith"],
            interval="2s",
            count=100,
            success={"account": "jsmith", "after": 50},
        )
        assert spec.success["account"] == "jsmith"
        assert spec.success["after"] == 50

    def test_success_account_must_be_in_targets(self):
        with pytest.raises(ValidationError, match="must be in target_accounts"):
            CredentialSprayEventSpec(
                target_accounts=["admin"],
                interval="2s",
                count=50,
                success={"account": "nobody", "after": 10},
            )

    def test_success_after_must_be_positive(self):
        with pytest.raises(ValidationError, match="after must be"):
            CredentialSprayEventSpec(
                target_accounts=["admin"],
                interval="2s",
                count=50,
                success={"account": "admin", "after": 0},
            )

    def test_rejects_rate(self):
        with pytest.raises(ValidationError, match="interval"):
            CredentialSprayEventSpec(target_accounts=["admin"], rate=10.0, duration="1h")

    def test_requires_interval(self):
        with pytest.raises(ValidationError, match="interval"):
            CredentialSprayEventSpec(target_accounts=["admin"], duration="1h")

    def test_requires_target_accounts(self):
        with pytest.raises(ValidationError):
            CredentialSprayEventSpec(target_accounts=[], interval="2s", count=50)

    def test_empty_target_accounts_rejected(self):
        with pytest.raises(ValidationError):
            CredentialSprayEventSpec(target_accounts=[], interval="2s", count=50)


# ── Web Scan Presets Config ───────────────────────────────────────────────


class TestWebScanPresets:
    def test_load_presets(self):
        from evidenceforge.config.web_scan_presets import list_preset_names, load_web_scan_presets

        data = load_web_scan_presets()
        assert "presets" in data
        names = list_preset_names()
        assert "nikto" in names
        assert "dirb" in names
        assert "gobuster" in names
        assert "sqlmap" in names
        assert "nmap_http" in names

    def test_get_preset(self):
        from evidenceforge.config.web_scan_presets import get_preset

        nikto = get_preset("nikto")
        assert nikto is not None
        assert "paths" in nikto
        assert len(nikto["paths"]) > 10
        assert "user_agent" in nikto
        assert "default_rate" in nikto
        assert "max_effective_rate" in nikto

    def test_presets_have_positive_effective_rate_cap(self):
        from evidenceforge.config.web_scan_presets import get_preset, list_preset_names

        for name in list_preset_names():
            preset = get_preset(name)
            assert preset is not None
            assert 0 < preset["max_effective_rate"] <= preset["default_rate"]

    def test_nikto_rate_cap_limits_repeated_probe_cycles(self):
        from evidenceforge.config.web_scan_presets import get_preset

        nikto = get_preset("nikto")
        assert nikto is not None
        assert nikto["max_effective_rate"] <= 0.35

    def test_web_scan_paths_are_shuffled_between_passes(self):
        import inspect

        from evidenceforge.generation.engine.storyline import StorylineMixin

        source = inspect.getsource(StorylineMixin)
        assert "rng.shuffle(path_sequence)" in source
        assert "skip_count = rng.randint" in source

    @pytest.mark.parametrize("value", [0, -0.1, "bad", float("inf"), float("nan"), True])
    def test_parse_positive_finite_rate_rejects_invalid_values(self, value):
        from evidenceforge.config.web_scan_presets import parse_positive_finite_rate

        assert parse_positive_finite_rate(value) is None

    @pytest.mark.parametrize("value", [1, 0.5, "2.5"])
    def test_parse_positive_finite_rate_accepts_valid_values(self, value):
        from evidenceforge.config.web_scan_presets import parse_positive_finite_rate

        assert parse_positive_finite_rate(value) == float(value)

    def test_get_unknown_preset(self):
        from evidenceforge.config.web_scan_presets import get_preset

        assert get_preset("nonexistent") is None

    def test_merge_presets_ignores_non_dict_overlay_presets(self, caplog):
        import logging

        from evidenceforge.config.web_scan_presets import _merge_presets

        default = {"presets": {"nikto": {"paths": ["/admin"]}}}

        with caplog.at_level(logging.WARNING, logger="evidenceforge.config.web_scan_presets"):
            result_list = _merge_presets(default, {"presets": ["bad"]})
        assert result_list == default
        assert "invalid structure" in caplog.text

        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="evidenceforge.config.web_scan_presets"):
            result_str = _merge_presets(default, {"presets": "bad"})
        assert result_str == default
        assert "invalid structure" in caplog.text

    def test_merge_presets_handles_non_dict_default_presets(self, caplog):
        import logging

        from evidenceforge.config.web_scan_presets import _merge_presets

        with caplog.at_level(logging.WARNING, logger="evidenceforge.config.web_scan_presets"):
            merged = _merge_presets(
                {"presets": "bad-default"}, {"presets": {"nikto": {"paths": []}}}
            )

        assert merged["presets"] == {"nikto": {"paths": []}}
        assert "invalid structure" in caplog.text


# ── DgaQueriesEventSpec ───────────────────────────────────────────────────


class TestDgaQueriesEventSpec:
    def test_defaults(self):
        spec = DgaQueriesEventSpec(interval="30s", count=100)
        assert spec.type == "dga_queries"
        assert spec.length_range == (8, 15)
        assert spec.tld == ".com"
        assert spec.seed is None

    def test_custom_params(self):
        spec = DgaQueriesEventSpec(
            interval="10s",
            duration="1h",
            length_range=(12, 24),
            charset="abcdef",
            tld=".net",
            seed=42,
            rcode_distribution={"NXDOMAIN": 0.9, "NOERROR": 0.1},
            answer_ip="1.2.3.4",
        )
        assert spec.length_range == (12, 24)
        assert spec.charset == "abcdef"
        assert spec.seed == 42

    def test_length_range_min_gt_max(self):
        with pytest.raises(ValidationError, match="minimum must be <= maximum"):
            DgaQueriesEventSpec(interval="30s", count=100, length_range=(20, 5))

    def test_length_range_max_gt_63(self):
        with pytest.raises(ValidationError, match="63"):
            DgaQueriesEventSpec(interval="30s", count=100, length_range=(1, 64))

    def test_rcode_distribution_bad_sum(self):
        with pytest.raises(ValidationError, match="sum to"):
            DgaQueriesEventSpec(
                interval="30s",
                count=100,
                rcode_distribution={"NXDOMAIN": 0.5, "NOERROR": 0.3},
                answer_ip="1.2.3.4",
            )

    def test_rcode_distribution_invalid_key(self):
        with pytest.raises(ValidationError, match="Invalid rcode"):
            DgaQueriesEventSpec(
                interval="30s",
                count=100,
                rcode_distribution={"BADCODE": 1.0},
            )

    def test_noerror_requires_answer_ip(self):
        with pytest.raises(ValidationError, match="answer_ip is required"):
            DgaQueriesEventSpec(
                interval="30s",
                count=100,
                rcode_distribution={"NXDOMAIN": 0.9, "NOERROR": 0.1},
            )

    def test_nxdomain_only_no_answer_ip(self):
        spec = DgaQueriesEventSpec(
            interval="30s",
            count=100,
            rcode_distribution={"NXDOMAIN": 1.0},
        )
        assert spec.answer_ip is None

    def test_rejects_rate(self):
        with pytest.raises(ValidationError, match="interval"):
            DgaQueriesEventSpec(rate=10.0, duration="1h")

    def test_deterministic_seed(self):
        """Same seed should produce same validation result."""
        s1 = DgaQueriesEventSpec(interval="30s", count=10, seed=42)
        s2 = DgaQueriesEventSpec(interval="30s", count=10, seed=42)
        assert s1.seed == s2.seed


# ── DnsTunnelEventSpec ────────────────────────────────────────────────────


class TestDnsTunnelEventSpec:
    def test_defaults(self):
        spec = DnsTunnelEventSpec(base_domain="tunnel.evil.com", interval="5s", duration="1h")
        assert spec.type == "dns_tunnel"
        assert spec.encoding == "hex"
        assert spec.qtype == "TXT"
        assert spec.label_length == 30
        assert spec.payload_size == 256

    def test_custom_params(self):
        spec = DnsTunnelEventSpec(
            base_domain="exfil.bad.com",
            encoding="base64",
            qtype="CNAME",
            label_length=50,
            payload="secret data here",
            interval="10s",
            count=50,
        )
        assert spec.encoding == "base64"
        assert spec.qtype == "CNAME"
        assert spec.payload == "secret data here"

    def test_invalid_qtype(self):
        with pytest.raises(ValidationError, match="qtype"):
            DnsTunnelEventSpec(
                base_domain="tunnel.evil.com",
                qtype="A",
                interval="5s",
                duration="1h",
            )

    def test_label_length_bounds(self):
        with pytest.raises(ValidationError):
            DnsTunnelEventSpec(
                base_domain="tunnel.evil.com",
                label_length=0,
                interval="5s",
                duration="1h",
            )
        with pytest.raises(ValidationError):
            DnsTunnelEventSpec(
                base_domain="tunnel.evil.com",
                label_length=64,
                interval="5s",
                duration="1h",
            )

    def test_case_insensitive_qtype(self):
        spec = DnsTunnelEventSpec(
            base_domain="tunnel.evil.com",
            qtype="txt",
            interval="5s",
            count=10,
        )
        assert spec.qtype == "TXT"

    def test_rejects_rate(self):
        with pytest.raises(ValidationError, match="interval"):
            DnsTunnelEventSpec(base_domain="tunnel.evil.com", rate=10.0, duration="1h")

    def test_encodings(self):
        for enc in ("base32", "base64", "hex"):
            spec = DnsTunnelEventSpec(
                base_domain="tunnel.evil.com",
                encoding=enc,
                interval="5s",
                count=10,
            )
            assert spec.encoding == enc

    def test_payload_size_upper_bound(self):
        with pytest.raises(ValidationError, match="payload_size"):
            DnsTunnelEventSpec(
                base_domain="tunnel.evil.com",
                interval="5s",
                count=10,
                payload_size=(1024 * 1024) + 1,
            )

    def test_payload_upper_bound(self):
        with pytest.raises(ValidationError, match="payload"):
            DnsTunnelEventSpec(
                base_domain="tunnel.evil.com",
                interval="5s",
                count=10,
                payload="a" * ((1024 * 1024) + 1),
            )

    def test_hex_labels_reserve_metadata_before_accounting_payload(self):
        engine = object.__new__(StorylineMixin)
        captured_dns = []

        def capture_connection(**kwargs):
            captured_dns.append(kwargs["dns"])

        engine.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
        engine.activity_generator = SimpleNamespace(
            _dns_server_ips=["10.0.0.53"],
            generate_connection=capture_connection,
        )
        spec = DnsTunnelEventSpec(
            base_domain="tunnel.example.test",
            encoding="hex",
            label_length=14,
            payload="ABCD",
            interval="1s",
            count=2,
        )

        event = engine._execute_typed_event(
            spec=spec,
            actor=User(username="attacker", full_name="Attacker", email="a@example.com"),
            system=System(hostname="WS-01", ip="10.0.0.10", os="Windows 10", type="workstation"),
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            activity="DNS exfiltration",
            explicit_types={"dns_tunnel"},
        )

        visible_payload = b""
        for dns_ctx in captured_dns:
            raw_label = bytes.fromhex(dns_ctx.query.split(".", 1)[0])
            visible_payload += raw_label[2:-4]
        assert visible_payload == b"AB"
        assert event["bytes_exfiltrated"] == len(visible_payload)

    def test_tiny_hex_labels_do_not_report_truncated_payload_as_exfiltrated(self):
        engine = object.__new__(StorylineMixin)
        captured_dns = []

        def capture_connection(**kwargs):
            captured_dns.append(kwargs["dns"])

        engine.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
        engine.activity_generator = SimpleNamespace(
            _dns_server_ips=["10.0.0.53"],
            generate_connection=capture_connection,
        )
        spec = DnsTunnelEventSpec(
            base_domain="tunnel.example.test",
            encoding="hex",
            label_length=8,
            payload="ABCD",
            interval="1s",
            count=1,
        )

        event = engine._execute_typed_event(
            spec=spec,
            actor=User(username="attacker", full_name="Attacker", email="a@example.com"),
            system=System(hostname="WS-01", ip="10.0.0.10", os="Windows 10", type="workstation"),
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            activity="DNS exfiltration",
            explicit_types={"dns_tunnel"},
        )

        raw_label = bytes.fromhex(captured_dns[0].query.split(".", 1)[0])
        assert b"ABCD" not in raw_label
        assert event["bytes_exfiltrated"] == 0

    def test_dns_tunnel_generation_uses_natural_pacing_and_variable_labels(self):
        engine = object.__new__(StorylineMixin)
        captured = []

        def capture_connection(**kwargs):
            captured.append((kwargs["time"], kwargs["dns"]))

        engine.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
        engine.activity_generator = SimpleNamespace(
            _dns_server_ips=["10.0.0.53"],
            generate_connection=capture_connection,
        )
        spec = DnsTunnelEventSpec(
            base_domain="tunnel.example.test",
            encoding="hex",
            label_length=30,
            payload_size=512,
            interval="2s",
            duration="15m",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=User(username="attacker", full_name="Attacker", email="a@example.com"),
            system=System(hostname="WS-01", ip="10.0.0.10", os="Windows 10", type="workstation"),
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            activity="DNS exfiltration",
            explicit_types={"dns_tunnel"},
        )

        intervals = [
            (later[0] - earlier[0]).total_seconds()
            for earlier, later in zip(captured, captured[1:], strict=False)
        ]
        label_lengths = {len(dns.query.split(".", 1)[0]) for _ts, dns in captured}
        label_depths = {len(dns.query.split(".")) for _ts, dns in captured}

        assert len(captured) < 451
        assert max(intervals) > 8.0
        assert len(label_lengths) > 1
        assert len(label_depths) > 1

    def test_dns_tunnel_generation_adds_benign_txt_collisions_from_other_hosts(self):
        engine = object.__new__(StorylineMixin)
        captured = []

        source = System(hostname="APP-01", ip="10.0.0.10", os="Ubuntu Server", type="server")
        peers = [
            System(hostname="WS-01", ip="10.0.0.20", os="Windows 10", type="workstation"),
            System(hostname="MAIL-01", ip="10.0.0.30", os="Ubuntu Server", type="server"),
        ]

        def capture_connection(**kwargs):
            captured.append(kwargs)

        engine.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
        engine.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[source, *peers]))
        engine.activity_generator = SimpleNamespace(
            _dns_server_ips=["10.0.0.53"],
            generate_connection=capture_connection,
        )
        spec = DnsTunnelEventSpec(
            base_domain="tunnel.example.test",
            encoding="hex",
            label_length=30,
            payload_size=128,
            interval="2s",
            duration="1m",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=User(username="attacker", full_name="Attacker", email="a@example.com"),
            system=source,
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            activity="DNS exfiltration",
            explicit_types={"dns_tunnel"},
        )

        benign_txt = [
            item
            for item in captured
            if item["dns"].query_type == "TXT"
            and not item["dns"].query.endswith("tunnel.example.test")
        ]
        benign_sources = {item["src_ip"] for item in benign_txt}

        assert len(benign_txt) >= 12
        assert benign_sources <= {peer.ip for peer in peers}
        assert len(benign_sources) > 1

    def test_dns_tunnel_generation_skews_ttls_and_expands_answer_vocabulary(self):
        engine = object.__new__(StorylineMixin)
        captured = []

        def capture_connection(**kwargs):
            captured.append(kwargs["dns"])

        engine.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
        engine.activity_generator = SimpleNamespace(
            _dns_server_ips=["10.0.0.53"],
            generate_connection=capture_connection,
        )
        spec = DnsTunnelEventSpec(
            base_domain="tunnel.example.test",
            encoding="hex",
            label_length=30,
            payload_size=2048,
            interval="2s",
            count=140,
        )

        engine._execute_typed_event(
            spec=spec,
            actor=User(username="attacker", full_name="Attacker", email="a@example.com"),
            system=System(hostname="WS-01", ip="10.0.0.10", os="Windows 10", type="workstation"),
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            activity="DNS exfiltration",
            explicit_types={"dns_tunnel"},
        )

        noerror_dns = [dns for dns in captured if dns.answers and dns.TTLs]
        ttl_counts = Counter(int(dns.TTLs[0]) for dns in noerror_dns)
        answers = [dns.answers[0] for dns in noerror_dns]

        assert len(noerror_dns) > 90
        assert len(ttl_counts) >= 3
        assert ttl_counts.most_common(1)[0][1] > len(noerror_dns) * 0.35
        assert all("{" not in answer and "}" not in answer for answer in answers)
        assert not any(
            answer.startswith(("status=", "node=", "cdn=", "cache=", "edge-", "ack."))
            or "ttl=30" in answer
            for answer in answers
        )


# ── ExplicitCredentialsEventSpec ──────────────────────────────────────────


class TestExplicitCredentialsEventSpec:
    def test_defaults(self):
        spec = ExplicitCredentialsEventSpec(target_username="admin")
        assert spec.type == "explicit_credentials"
        assert spec.target_username == "admin"
        assert spec.target_server is None
        assert spec.process_name is None
        assert spec.source_ip is None

    def test_all_fields(self):
        spec = ExplicitCredentialsEventSpec(
            target_username="svc_backup",
            target_server="FILE-SRV-01",
            process_name=r"C:\Windows\System32\runas.exe",
            source_ip="10.0.1.5",
        )
        assert spec.target_server == "FILE-SRV-01"
        assert spec.process_name == r"C:\Windows\System32\runas.exe"

    def test_requires_target_username(self):
        with pytest.raises(ValidationError):
            ExplicitCredentialsEventSpec()


# ── WorkstationLockEventSpec / WorkstationUnlockEventSpec ─────────────────


class TestWorkstationLockUnlockEventSpec:
    def test_lock_defaults(self):
        spec = WorkstationLockEventSpec()
        assert spec.type == "workstation_lock"

    def test_unlock_defaults(self):
        spec = WorkstationUnlockEventSpec()
        assert spec.type == "workstation_unlock"
