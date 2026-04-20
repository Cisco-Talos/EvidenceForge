# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for realism quick-win fixes.

1. RFC 5737 documentation IP exclusion
2. ASA connection ID non-round start
3. PAT port gaps (non-sequential)
4. Snort microsecond timestamps
5. ASA chronological sort on flush
"""

import random
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import IdsContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import (
    NatRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)

T0 = datetime(2024, 6, 15, 14, 0, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Fix 1: RFC 5737 documentation IP exclusion
# ---------------------------------------------------------------------------


def test_generate_external_ip_excludes_rfc5737():
    """External IPs must not fall in RFC 5737 TEST-NET ranges."""
    from unittest.mock import MagicMock

    from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

    # Use a rigged RNG that would produce RFC 5737 IPs without the exclusion
    rfc5737_prefixes = [
        (203, 0, 113),  # TEST-NET-3
        (198, 51, 100),  # TEST-NET-2
        (192, 0, 2),  # TEST-NET-1
    ]

    for first, second, third in rfc5737_prefixes:
        call_count = 0

        def rigged_randint(lo, hi, _f=first, _s=second, _t=third):
            nonlocal call_count
            call_count += 1
            cycle = (call_count - 1) % 4
            if cycle == 0:
                return _f
            elif cycle == 1:
                return _s
            elif cycle == 2:
                return _t
            else:
                return 50  # Last octet

        rng = MagicMock()
        rng.randint = rigged_randint
        # The function should loop and never return an RFC 5737 IP.
        # To avoid infinite loop, patch to return a valid IP after rejection.
        attempts = [0]
        saved_rigged = rigged_randint

        def mixed_randint(lo, hi, _f=first, _s=second, _t=third, _att=attempts, _orig=saved_rigged):
            _att[0] += 1
            if _att[0] <= 8:  # First two attempts: rigged RFC 5737
                return _orig(lo, hi)
            # After rejection, return a normal IP
            cycle = (_att[0] - 1) % 4
            if cycle == 0:
                return 44  # Safe first octet
            elif cycle == 1:
                return 100
            elif cycle == 2:
                return 200
            else:
                return 50

        rng.randint = mixed_randint
        obj = MagicMock(spec=[])
        obj._org_cidr_networks = []
        ip = EmitterSetupMixin._generate_external_client_ip(obj, rng)
        assert not ip.startswith(f"{first}.{second}.{third}."), (
            f"RFC 5737 IP {ip} should have been excluded"
        )

    # Also verify with normal random that no RFC 5737 IPs appear in a large sample
    rng = random.Random(42)
    obj = MagicMock(spec=[])
    obj._org_cidr_networks = []
    for _ in range(5000):
        ip = EmitterSetupMixin._generate_external_client_ip(obj, rng)
        assert not ip.startswith("203.0.113."), f"RFC 5737 TEST-NET-3: {ip}"
        assert not ip.startswith("198.51.100."), f"RFC 5737 TEST-NET-2: {ip}"
        assert not ip.startswith("192.0.2."), f"RFC 5737 TEST-NET-1: {ip}"


# ---------------------------------------------------------------------------
# Fix 2: ASA connection ID non-round start
# ---------------------------------------------------------------------------


def test_asa_conn_id_not_round():
    """ASA connection IDs should use timestamp-based monotonic values."""
    from datetime import datetime

    fmt = load_format("cisco_asa")
    emitter = CiscoAsaEmitter(
        format_def=fmt,
        output_path=pytest.importorskip("pathlib").Path("/tmp/test_asa_conn"),
        sensor_hostnames=["fw01"],
    )
    ts1 = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    ts2 = datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC)
    first_id = emitter._next_conn_id("fw01", ts1)
    assert first_id > 0, "Connection ID should be positive"

    second_id = emitter._next_conn_id("fw01", ts2)
    assert second_id > first_id, "Later timestamps should produce higher IDs"

    # Different sensor should get a different starting ID
    other_id = emitter._next_conn_id("fw02")
    assert other_id != first_id, "Different sensors should get different starting IDs"


# ---------------------------------------------------------------------------
# Fix 3: PAT port gaps
# ---------------------------------------------------------------------------


def _make_nat_engine():
    """Create a NetworkVisibilityEngine with a dynamic PAT rule."""
    segments = [
        NetworkSegment(name="workstations", cidr="10.0.10.0/24"),
        NetworkSegment(name="servers", cidr="10.0.20.0/24"),
        NetworkSegment(name="dmz", cidr="172.16.0.0/24"),
    ]
    systems = [
        System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
        System(hostname="SRV-01", ip="10.0.20.5", os="Windows Server 2019", type="server"),
    ]
    nat_rules = [
        NatRule(type="dynamic_pat", src=["workstations"], mapped_ip="198.51.100.1"),
    ]
    sensors = [
        NetworkSensor(
            name="fw01",
            hostname="fw01",
            type="firewall",
            monitoring_segments=["workstations", "servers", "dmz"],
            log_formats=["cisco_asa"],
            nat_rules=nat_rules,
        ),
    ]
    config = NetworkConfig(segments=segments, sensors=sensors)
    return NetworkVisibilityEngine(config, systems)


def test_pat_ports_have_gaps():
    """PAT port allocations should have non-sequential gaps."""
    engine = _make_nat_engine()
    ports = []
    for i in range(10):
        result = engine.compute_nat(
            src_ip="10.0.10.50",
            dst_ip="8.8.8.8",
            src_port=40000 + i,
            dst_port=443,
        )
        assert result is not None, f"NAT should match for workstation IP (iteration {i})"
        ports.append(result.mapped_src_port)

    # Check that not all gaps are exactly 1
    gaps = [ports[i + 1] - ports[i] for i in range(len(ports) - 1)]
    assert not all(g == 1 for g in gaps), (
        f"All PAT port gaps are exactly 1 — should have varied gaps. Ports: {ports}"
    )
    # All gaps should be in [1, 255] (realistic PAT allocation)
    assert all(1 <= g <= 255 for g in gaps), f"PAT port gaps out of range [1,255]: {gaps}"


def test_pat_port_start_not_round():
    """PAT port counters should not start at a round number like 10000."""
    engine = _make_nat_engine()
    result = engine.compute_nat(
        src_ip="10.0.10.50",
        dst_ip="8.8.8.8",
        src_port=40000,
        dst_port=443,
    )
    assert result is not None
    assert result.mapped_src_port != 10000, "PAT port should not start at round 10000"
    assert 1024 <= result.mapped_src_port < 51024, (
        f"PAT port {result.mapped_src_port} out of expected range [1024, 51024)"
    )


# ---------------------------------------------------------------------------
# Fix 4: Snort microsecond timestamps
# ---------------------------------------------------------------------------


def test_snort_timestamp_has_microseconds(tmp_path):
    """Snort alert timestamps should have non-zero microseconds."""
    fmt = load_format("snort_alert")
    emitter = SnortEmitter(
        format_def=fmt,
        output_path=tmp_path / "snort_alert.log",
    )

    # Emit several events with different timestamps
    for i in range(5):
        ts = T0 + timedelta(seconds=i * 60)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            ids=IdsContext(
                sid=2000000 + i,
                message=f"Test alert {i}",
                classification="Attempted Information Leak",
                priority=2,
            ),
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=40000 + i,
                dst_ip="192.168.1.1",
                dst_port=80,
                protocol="TCP",
            ),
        )
        emitter.emit(event)

    emitter.flush()

    output = (tmp_path / "snort_alert.log").read_text()
    lines = [line for line in output.strip().split("\n") if line.strip()]
    assert len(lines) >= 5, f"Expected at least 5 alert lines, got {len(lines)}"

    # Check that at least some timestamps have non-zero millisecond part
    zero_ms_count = 0
    for line in lines:
        # Format: MM/DD-HH:MM:SS.mmm
        ts_part = line.split("[")[0].strip()
        ms_part = ts_part.split(".")[-1]
        if ms_part == "000":
            zero_ms_count += 1

    assert zero_ms_count < len(lines), (
        "All Snort timestamps end in .000 — microsecond jitter is not working"
    )


# ---------------------------------------------------------------------------
# Fix 5: ASA chronological sort on flush
# ---------------------------------------------------------------------------


def test_asa_output_sorted(tmp_path):
    """ASA output lines should be chronologically sorted after flush."""
    fmt = load_format("cisco_asa")
    emitter = CiscoAsaEmitter(
        format_def=fmt,
        output_path=tmp_path,
        sensor_hostnames=["fw01"],
    )
    emitter._segment_config = [
        {"name": "workstations", "cidr": "10.0.10.0/24"},
        {"name": "servers", "cidr": "10.0.20.0/24"},
    ]
    emitter._sensor_interfaces = {
        "fw01": {
            "workstations": "inside",
            "servers": "inside",
            "_default": "outside",
        }
    }

    # Emit events that will produce out-of-order lines (Built at T, Teardown at T+duration)
    # The Teardown for the first connection lands AFTER the Built for the second connection
    for i in range(5):
        ts = T0 + timedelta(seconds=i * 10)
        event = SecurityEvent(
            timestamp=ts,
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=40000 + i,
                dst_ip="8.8.8.8",
                dst_port=443,
                protocol="TCP",
                duration=30.0 + i * 5,  # 30-50 seconds — teardowns interleave with later builts
                orig_bytes=1000,
                resp_bytes=2000,
            ),
        )
        emitter.emit(event)

    emitter.flush()

    output_file = tmp_path / "fw01" / "cisco_asa.log"
    assert output_file.exists(), "ASA output file should exist"
    lines = [line for line in output_file.read_text().strip().split("\n") if line.strip()]
    assert len(lines) >= 10, (
        f"Expected at least 10 ASA lines (5 Built + 5 Teardown), got {len(lines)}"
    )

    # Verify lines are in chronological order (by timestamp, not lexicographic)
    def _extract_ts(line):
        gt = line.find(">")
        return line[gt + 1 : gt + 16] if gt >= 0 else ""

    for i in range(len(lines) - 1):
        assert _extract_ts(lines[i]) <= _extract_ts(lines[i + 1]), (
            f"ASA output not chronologically sorted at line {i}:\n  {lines[i]}\n  {lines[i + 1]}"
        )
