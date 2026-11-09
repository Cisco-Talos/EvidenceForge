# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plain syslog producers keep transport control separate from application data."""

import random
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from evidenceforge.generation.engine import baseline as baseline_module
from evidenceforge.generation.engine.baseline import BaselineMixin, _CanonicalSyslogRoute
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _baseline(protocol: str) -> tuple[SimpleNamespace, _CanonicalSyslogRoute]:
    sender = System(hostname="MAC-01", ip="10.0.0.1", os="macOS 27", type="workstation")
    receiver = System(hostname="MAC-02", ip="10.0.0.2", os="macOS 27", type="workstation")
    route = _CanonicalSyslogRoute(sender=sender, receiver=receiver, protocol=protocol)
    baseline = SimpleNamespace(
        scenario=SimpleNamespace(environment=SimpleNamespace(systems=[sender, receiver])),
        activity_generator=SimpleNamespace(
            generate_connection=Mock(), timing_runtime=TimingRuntime.compatibility_default()
        ),
        state_manager=Mock(),
        _system_pids={},
        _baseline_network_close_bound_seconds=Mock(return_value=6.0),
        _baseline_pass_admits=Mock(return_value=True),
        _canonical_syslog_routes=lambda: {sender.hostname: route},
    )
    baseline._syslog_forwarder_identity = lambda host: BaselineMixin._syslog_forwarder_identity(
        baseline, host
    )
    return baseline, route


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_health_transport_has_no_application_backchannel(protocol: str) -> None:
    baseline, route = _baseline(protocol)
    assert BaselineMixin._emit_rsyslog_health_transport(
        baseline, current_hour=T0, sender=route.sender, time=T0, route=route
    )
    kwargs = baseline.activity_generator.generate_connection.call_args.kwargs
    assert kwargs["proto"] == protocol
    assert kwargs["orig_bytes"] > 0
    assert kwargs["resp_bytes"] == 0
    assert kwargs["process_image"] == "/usr/sbin/syslogd"
    assert kwargs["pid"] == -1 and kwargs["suppress_source_pid_inference"] is True


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_central_relay_has_same_simplex_contract(protocol: str) -> None:
    baseline, _route = _baseline(protocol)
    rng = random.Random(11)
    rng.random = Mock(return_value=0.1)
    with patch.object(baseline_module, "_get_rng", return_value=rng):
        BaselineMixin._generate_lateral_movement_noise(baseline, T0)
    calls = baseline.activity_generator.generate_connection.call_args_list
    assert len(calls) == 1
    assert calls[0].kwargs["service"] == "syslog"
    assert calls[0].kwargs["resp_bytes"] == 0
    assert calls[0].kwargs["orig_bytes"] > 0


@pytest.mark.parametrize(
    "os,role,image",
    [
        ("Ubuntu 22.04", "rsyslogd", "/usr/sbin/rsyslogd"),
        ("macOS 27", "syslogd", "/usr/sbin/syslogd"),
        ("Windows 11", "svchost_net_svc", r"C:\Windows\System32\svchost.exe"),
    ],
)
def test_forwarder_process_defaults_are_os_aware(os: str, role: str, image: str) -> None:
    baseline, route = _baseline("tcp")
    sender = route.sender.model_copy(update={"os": os})
    baseline._system_pids = {sender.hostname: {role: 451}}
    assert BaselineMixin._syslog_forwarder_identity(baseline, sender) == (451, image)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_profile_syslog_budget_is_simplex_without_changing_other_services(protocol: str) -> None:
    syslog_rng = random.Random(51)
    control_rng = random.Random(51)
    outgoing, incoming = baseline_module._profile_connection_payload_bytes(
        {"proto": protocol, "service": "syslog"}, syslog_rng
    )
    control_out, control_in = baseline_module._profile_connection_payload_bytes(
        {"proto": protocol, "service": "dns"}, control_rng
    )
    assert outgoing == control_out > 0
    assert incoming == 0 and control_in > 0
    assert syslog_rng.getstate() == control_rng.getstate()
