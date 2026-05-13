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

"""Unit tests for Cisco ASA firewall emitter."""

import re
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import FirewallContext, NatContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter


@pytest.fixture
def asa_emitter(tmp_path):
    """Create an ASA emitter for testing."""
    fmt = load_format("cisco_asa")
    emitter = CiscoAsaEmitter(
        format_def=fmt,
        output_path=tmp_path,
        sensor_hostnames=["fw01"],
    )
    emitter._segment_config = [
        {"name": "workstations", "cidr": "10.0.10.0/24"},
        {"name": "servers", "cidr": "10.0.20.0/24"},
        {"name": "dmz", "cidr": "172.16.0.0/24"},
    ]
    emitter._sensor_interfaces = {
        "fw01": {
            "workstations": "inside",
            "servers": "inside",
            "dmz": "dmz",
            "_default": "outside",
        }
    }
    return emitter


T0 = datetime(2024, 6, 15, 14, 23, 5, tzinfo=UTC)


def _make_connection_event(
    src_ip="10.0.10.50",
    src_port=54321,
    dst_ip="203.0.113.50",
    dst_port=443,
    protocol="tcp",
    duration=83.5,
    orig_bytes=1024,
    resp_bytes=4096,
    conn_state="SF",
    firewall=None,
    nat=None,
    timestamp=None,
):
    """Create a connection SecurityEvent for testing."""
    event = SecurityEvent(
        timestamp=timestamp or T0,
        event_type="connection",
        network=NetworkContext(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            duration=duration,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            conn_state=conn_state,
        ),
        firewall=firewall,
        nat=nat,
    )
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw01"]}
    return event


class TestCanHandle:
    def test_handles_connection_with_network(self, asa_emitter):
        event = _make_connection_event()
        assert asa_emitter.can_handle(event) is True

    def test_rejects_non_connection(self, asa_emitter):
        event = SecurityEvent(timestamp=T0, event_type="process")
        assert asa_emitter.can_handle(event) is False

    def test_rejects_connection_without_network(self, asa_emitter):
        event = SecurityEvent(timestamp=T0, event_type="connection")
        assert asa_emitter.can_handle(event) is False


class TestInterfaceResolution:
    def test_internal_ip_resolves_to_inside(self, asa_emitter):
        assert asa_emitter._resolve_interface("10.0.10.50", "fw01") == "inside"

    def test_server_ip_resolves_to_inside(self, asa_emitter):
        assert asa_emitter._resolve_interface("10.0.20.10", "fw01") == "inside"

    def test_dmz_ip_resolves_to_dmz(self, asa_emitter):
        assert asa_emitter._resolve_interface("172.16.0.5", "fw01") == "dmz"

    def test_external_ip_resolves_to_outside(self, asa_emitter):
        assert asa_emitter._resolve_interface("203.0.113.50", "fw01") == "outside"

    def test_unknown_sensor_uses_default(self, asa_emitter):
        assert asa_emitter._resolve_interface("203.0.113.50", "unknown") == "outside"


class TestConnectionIdCounter:
    def test_monotonically_increasing(self, asa_emitter):
        from datetime import datetime

        ts1 = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        ts2 = datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC)
        id1 = asa_emitter._next_conn_id("fw01", ts1)
        id2 = asa_emitter._next_conn_id("fw01", ts2)
        assert id2 > id1

    def test_per_sensor_counters(self, asa_emitter):
        from datetime import datetime

        ts = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        id_fw01 = asa_emitter._next_conn_id("fw01", ts)
        id_fw02 = asa_emitter._next_conn_id("fw02", ts)
        # Different sensors get different sequence bits
        assert id_fw01 != id_fw02

    def test_no_duplicates_for_same_timestamp_burst(self, asa_emitter):
        from datetime import datetime

        ts = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        ids = [asa_emitter._next_conn_id("fw01", ts) for _ in range(5000)]
        assert len(ids) == len(set(ids))

    def test_no_duplicates_across_adjacent_second_bursts(self, asa_emitter):
        ts = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        first_second_ids = [asa_emitter._next_conn_id("fw01", ts) for _ in range(20)]
        next_second_ids = [
            asa_emitter._next_conn_id("fw01", ts + timedelta(seconds=1)) for _ in range(20)
        ]

        assert set(first_second_ids).isdisjoint(next_second_ids)

    def test_connection_ids_are_not_epoch_shaped(self, asa_emitter):
        conn_id = asa_emitter._next_conn_id("fw01", T0)
        assert conn_id < 1_000_000_000
        assert not str(conn_id).endswith("000")

    def test_connection_id_terminal_digits_vary(self, asa_emitter):
        ids = [
            asa_emitter._next_conn_id("fw01", T0 + timedelta(seconds=offset))
            for offset in range(60)
        ]
        terminal_digits = {conn_id % 10 for conn_id in ids}
        assert len(terminal_digits) >= 8

    def test_sorted_output_preserves_stateful_connection_ids(self, asa_emitter, tmp_path):
        late_event = _make_connection_event(
            timestamp=T0 + timedelta(seconds=30),
            src_port=50001,
            duration=1.0,
        )
        early_event = _make_connection_event(
            timestamp=T0,
            src_port=50000,
            duration=1.0,
        )

        asa_emitter.emit(late_event)
        asa_emitter.emit(early_event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        built_lines = [
            line for line in output.splitlines() if "Built outbound TCP connection" in line
        ]
        built_ids = []
        for line in built_lines:
            match = re.search(r"connection (\d+) for", line)
            assert match is not None
            built_ids.append(int(match.group(1)))

        assert built_lines == sorted(built_lines)
        assert len(built_ids) == len(set(built_ids))
        assert abs(built_ids[0] - built_ids[1]) < 2000

    def test_barrier_flush_does_not_normalize_existing_file(self, asa_emitter, monkeypatch):
        calls: list[str] = []

        def record_normalization() -> None:
            calls.append("normalized")

        monkeypatch.setattr(
            asa_emitter,
            "_normalize_visible_connection_ids",
            record_normalization,
        )

        asa_emitter.emit(_make_connection_event())
        asa_emitter.flush()

        assert calls == []

    def test_close_normalizes_connection_ids_once(self, asa_emitter, monkeypatch):
        calls: list[str] = []

        def record_normalization() -> None:
            calls.append("normalized")

        monkeypatch.setattr(
            asa_emitter,
            "_normalize_visible_connection_ids",
            record_normalization,
        )

        asa_emitter.emit(_make_connection_event())
        asa_emitter.close()

        assert calls == ["normalized"]


class TestPermitRecords:
    def test_tcp_produces_built_and_teardown(self, asa_emitter, tmp_path):
        """A permitted TCP connection should produce both Built and Teardown records."""
        event = _make_connection_event(protocol="tcp")
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 2

        # First line: Built
        assert "%ASA-6-302013:" in lines[0]
        assert "Built outbound TCP connection" in lines[0]
        assert "inside:10.0.10.50/54321" in lines[0]
        assert "outside:203.0.113.50/443" in lines[0]

        # Second line: Teardown
        assert "%ASA-6-302014:" in lines[1]
        assert "Teardown TCP connection" in lines[1]
        assert "duration 0:01:23" in lines[1]
        byte_match = re.search(r"bytes (\d+)", lines[1])
        assert byte_match is not None
        assert int(byte_match.group(1)) > 5120
        assert "SYN Timeout" not in lines[1]

    def test_teardown_after_collection_end_is_suppressed(self, asa_emitter, tmp_path):
        """A slice ending before connection close should show a dangling Built record."""
        asa_emitter._output_end_time = T0 + timedelta(seconds=10)
        event = _make_connection_event(protocol="tcp", duration=83.5)

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 1
        assert "%ASA-6-302013:" in lines[0]
        assert "%ASA-6-302014:" not in output

    def test_nat_teardown_after_collection_end_is_suppressed(self, asa_emitter, tmp_path):
        """Dynamic NAT should not remain perfectly paired when connection close is out of slice."""
        asa_emitter._output_end_time = T0 + timedelta(seconds=10)
        event = _make_connection_event(
            protocol="tcp",
            duration=83.5,
            nat=NatContext(
                nat_type="dynamic_pat",
                mapped_src_ip="198.51.100.10",
                mapped_src_port=62001,
                mapped_dst_ip="203.0.113.50",
                mapped_dst_port=443,
            ),
        )

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        assert "%ASA-6-302013:" in output
        assert "%ASA-6-305011:" in output
        assert "%ASA-6-302014:" not in output
        assert "%ASA-6-305012:" not in output

    def test_teardown_byte_count_is_not_exact_zeek_payload_sum(self, asa_emitter, tmp_path):
        """ASA teardown accounting should not exactly mirror Zeek payload bytes."""
        event = _make_connection_event(protocol="tcp", orig_bytes=1024, resp_bytes=4096)

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        teardown = next(line for line in output.splitlines() if "%ASA-6-302014:" in line)
        byte_match = re.search(r"bytes (\d+)", teardown)
        assert byte_match is not None
        assert int(byte_match.group(1)) != 5120

    def test_same_interface_permit_is_not_rendered_as_perimeter_flow(self, asa_emitter, tmp_path):
        """ASA should not mirror same-interface internal permits by default."""
        event = _make_connection_event(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            dst_port=88,
            protocol="tcp",
        )

        asa_emitter.emit(event)
        asa_emitter.flush()

        assert not (tmp_path / "fw01" / "cisco_asa.log").exists()

    def test_same_interface_deny_is_not_rendered_as_perimeter_flow(self, asa_emitter, tmp_path):
        """ASA should not mirror same-interface internal denies by default."""
        event = _make_connection_event(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            dst_port=88,
            protocol="tcp",
        )
        event.firewall = FirewallContext(
            action="deny",
            msg_id=106023,
            connection_id=0,
            src_interface="",
            dst_interface="",
            access_group="inside_access_in",
        )

        asa_emitter.emit(event)
        asa_emitter.flush()

        assert not (tmp_path / "fw01" / "cisco_asa.log").exists()

    def test_syn_timeout_requires_handshake_only_connection(self, asa_emitter, tmp_path):
        """SYN Timeout should not be used for connections with payload bytes."""
        event = _make_connection_event(
            protocol="tcp",
            duration=0.1,
            orig_bytes=0,
            resp_bytes=0,
        )
        event.network.conn_state = "S0"
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        teardown = [line for line in output.splitlines() if "%ASA-6-302014:" in line][0]
        assert "SYN Timeout" in teardown
        assert "bytes 0" in teardown

    def test_udp_produces_built_and_teardown(self, asa_emitter, tmp_path):
        """A permitted UDP connection should use 302015/302016."""
        event = _make_connection_event(protocol="udp", dst_port=53)
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 2
        assert "%ASA-6-302015:" in lines[0]
        assert "Built outbound UDP connection" in lines[0]
        assert "%ASA-6-302016:" in lines[1]

    def test_icmp_produces_built_and_teardown(self, asa_emitter, tmp_path):
        """ICMP connections should use 302020/302021."""
        event = _make_connection_event(protocol="icmp", src_port=0, dst_port=8, duration=0.5)
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 2
        assert "%ASA-6-302020:" in lines[0]
        assert "Built outbound ICMP connection" in lines[0]
        assert "%ASA-6-302021:" in lines[1]

    def test_inbound_icmp_keeps_foreign_and_local_addresses_directional(
        self, asa_emitter, tmp_path
    ):
        """Inbound ICMP faddr is the outside source; gaddr/laddr are local destination."""
        event = _make_connection_event(
            protocol="icmp",
            src_ip="203.0.113.50",
            src_port=0,
            dst_ip="172.16.0.5",
            dst_port=8,
            duration=0.5,
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        built_line = next(line for line in output.splitlines() if "%ASA-6-302020:" in line)
        assert "Built inbound ICMP connection" in built_line
        assert "faddr outside:203.0.113.50/8" in built_line
        assert "gaddr dmz:172.16.0.5/0" in built_line
        assert "laddr dmz:172.16.0.5/0" in built_line

    def test_inbound_direction_for_external_source(self, asa_emitter, tmp_path):
        """External source -> internal destination should be 'inbound'."""
        event = _make_connection_event(
            src_ip="203.0.113.50",
            src_port=54321,
            dst_ip="172.16.0.5",
            dst_port=80,
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        assert "Built inbound TCP connection" in output

    def test_permit_uses_firewall_context_connection_id_and_interfaces(self, asa_emitter, tmp_path):
        """Context-owned ASA fields override emitter-derived fallback fields."""
        event = _make_connection_event(
            firewall=FirewallContext(
                action="permit",
                msg_id=302013,
                connection_id=424242,
                src_interface="vpn",
                dst_interface="egress",
            )
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        assert "TCP connection 424242" in output
        assert "vpn:10.0.10.50/54321" in output
        assert "egress:203.0.113.50/443" in output


class TestDenyRecords:
    def test_deny_produces_single_record(self, asa_emitter, tmp_path):
        """A denied connection should produce a single 106023 record."""
        event = _make_connection_event(
            src_ip="198.51.100.1",
            dst_ip="10.0.10.50",
            dst_port=445,
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=0,
                src_interface="outside",
                dst_interface="inside",
                access_group="outside_access_in",
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 1
        assert "%ASA-4-106023:" in lines[0]
        assert "Deny tcp src outside:198.51.100.1/54321" in lines[0]
        assert "dst inside:10.0.10.50/445" in lines[0]
        assert 'by access-group "outside_access_in"' in lines[0]

    def test_icmp_deny_includes_type_code(self, asa_emitter, tmp_path):
        """ICMP deny should include (type N, code N) in the message."""
        event = _make_connection_event(
            src_ip="198.51.100.1",
            dst_ip="10.0.10.50",
            protocol="icmp",
            src_port=0,
            dst_port=8,
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=0,
                src_interface="outside",
                dst_interface="inside",
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        assert "(type 8, code 0)" in output
        assert "Deny icmp" in output

    def test_outside_private_deny_without_static_mapping_is_suppressed(self, asa_emitter, tmp_path):
        """Outside scanners should not be logged against unmapped private DMZ targets."""
        event = _make_connection_event(
            src_ip="198.51.100.1",
            dst_ip="172.16.0.77",
            dst_port=443,
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=0,
                src_interface="outside",
                dst_interface="dmz",
                access_group="outside_access_in",
            ),
        )

        asa_emitter.emit(event)
        asa_emitter.flush()

        assert not (tmp_path / "fw01" / "cisco_asa.log").exists()

    def test_deny_uses_firewall_context_message_id_and_interfaces(self, asa_emitter, tmp_path):
        """Deny records keep canonical firewall context metadata when provided."""
        event = _make_connection_event(
            src_ip="10.0.10.50",
            dst_ip="203.0.113.53",
            dst_port=53,
            firewall=FirewallContext(
                action="deny",
                msg_id=106100,
                connection_id=0,
                src_interface="inside",
                dst_interface="internet",
                access_group="inside_dns_policy",
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        assert "%ASA-4-106100:" in output
        assert "Deny tcp src inside:10.0.10.50/54321" in output
        assert "dst internet:203.0.113.53/53" in output
        assert 'by access-group "inside_dns_policy"' in output


class TestSyslogFormat:
    def test_syslog_header_format(self, asa_emitter, tmp_path):
        """Output should match ASA syslog format: <pri>timestamp hostname %ASA-sev-msgid: message."""
        event = _make_connection_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        first_line = output.strip().split("\n")[0]
        # Priority for severity 6: 20*8+6 = 166
        assert first_line.startswith("<166>")
        assert "fw01 %ASA-6-302013:" in first_line

    def test_deny_severity_is_4(self, asa_emitter, tmp_path):
        """Deny records should use severity 4 (warning)."""
        event = _make_connection_event(
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=0,
                src_interface="outside",
                dst_interface="inside",
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        # Priority for severity 4: 20*8+4 = 164
        assert "<164>" in output
        assert "%ASA-4-106023:" in output


class TestFormatDefinition:
    def test_cisco_asa_format_loads(self):
        """The cisco_asa format definition should load successfully."""
        fmt = load_format("cisco_asa")
        assert fmt.name == "cisco_asa"
        assert fmt.category == "network"

    def test_format_has_required_fields(self):
        fmt = load_format("cisco_asa")
        field_names = {f.name for f in fmt.fields}
        assert "timestamp" in field_names
        assert "hostname" in field_names
        assert "severity" in field_names
        assert "msg_id" in field_names
        assert "message" in field_names


class TestThreatDetection:
    """Tests for automatic 733100 threat detection alerts."""

    def _make_deny_event(self, src_ip, dst_ip, dst_port, timestamp):
        return _make_connection_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            timestamp=timestamp,
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=0,
                src_interface="outside",
                dst_interface="inside",
                access_group="outside_access_in",
            ),
        )

    def _get_output_lines(self, tmp_path):
        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        return [line for line in output.strip().split("\n") if line]

    def test_threat_detection_fires_on_burst(self, asa_emitter, tmp_path):
        """Rapid deny burst exceeding both thresholds should produce a 733100."""
        from datetime import timedelta

        # Lower thresholds for testing
        asa_emitter._td_burst_threshold = 5
        asa_emitter._td_avg_threshold = 3
        asa_emitter._td_burst_window = 10
        asa_emitter._td_avg_window = 30

        # Generate 100 denies in 10 seconds (10/sec burst, 10/sec avg >> thresholds)
        for i in range(100):
            event = self._make_deny_event(
                "198.51.100.1",
                "10.0.10.50",
                445,
                T0 + timedelta(seconds=i * 0.1),
            )
            asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        threat_lines = [line for line in lines if "733100" in line]
        assert len(threat_lines) >= 1
        assert "[Scanning] drop rate-1 exceeded" in threat_lines[0]
        assert "Cumulative total count is" in threat_lines[0]

    def test_threat_detection_requires_both_rates(self, asa_emitter, tmp_path):
        """If burst is high but average is below threshold, no 733100 should fire."""
        from datetime import timedelta

        asa_emitter._td_burst_threshold = 5
        asa_emitter._td_avg_threshold = 50  # Very high average threshold
        asa_emitter._td_burst_window = 10
        asa_emitter._td_avg_window = 60

        # 20 denies in 2 seconds (burst = 10/sec, avg over 60s = 0.33/sec)
        for i in range(20):
            event = self._make_deny_event(
                "198.51.100.1",
                "10.0.10.50",
                445,
                T0 + timedelta(seconds=i * 0.1),
            )
            asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        threat_lines = [line for line in lines if "733100" in line]
        assert len(threat_lines) == 0

    def test_threat_detection_refires_after_cooldown(self, asa_emitter, tmp_path):
        """Sustained burst should produce multiple 733100 alerts after cooldown."""
        from datetime import timedelta

        asa_emitter._td_burst_threshold = 5
        asa_emitter._td_avg_threshold = 3
        asa_emitter._td_burst_window = 10
        asa_emitter._td_avg_window = 30
        asa_emitter._td_cooldown = 10  # Short cooldown for testing

        # Generate 500 denies over 30 seconds (16.7/sec)
        for i in range(500):
            event = self._make_deny_event(
                "198.51.100.1",
                "10.0.10.50",
                445,
                T0 + timedelta(seconds=i * 0.06),
            )
            asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        threat_lines = [line for line in lines if "733100" in line]
        assert len(threat_lines) >= 2  # Should re-fire after cooldown

    def test_threat_detection_separate_per_source_ip(self, asa_emitter, tmp_path):
        """Different source IPs should each get their own 733100 alerts."""
        from datetime import timedelta

        asa_emitter._td_burst_threshold = 5
        asa_emitter._td_avg_threshold = 3
        asa_emitter._td_burst_window = 10
        asa_emitter._td_avg_window = 30

        # 100 denies from IP A, 100 from IP B, interleaved
        for i in range(100):
            for src_ip in ["198.51.100.1", "198.51.100.2"]:
                event = self._make_deny_event(
                    src_ip,
                    "10.0.10.50",
                    445,
                    T0 + timedelta(seconds=i * 0.1),
                )
                asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        threat_lines = [line for line in lines if "733100" in line]
        # Both source IPs should trigger their own alerts
        assert len(threat_lines) >= 2

    def test_threat_detection_disabled_when_rate_zero(self, asa_emitter, tmp_path):
        """Setting threshold to 0 should disable threat detection entirely."""
        from datetime import timedelta

        asa_emitter._td_burst_threshold = 0  # Disabled

        # Massive burst that would normally trigger
        for i in range(200):
            event = self._make_deny_event(
                "198.51.100.1",
                "10.0.10.50",
                445,
                T0 + timedelta(seconds=i * 0.05),
            )
            asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        threat_lines = [line for line in lines if "733100" in line]
        assert len(threat_lines) == 0

    def test_threat_detection_prunes_old_timestamps(self, asa_emitter):
        """Deny timestamp state should stay bounded to configured tracking windows."""
        from datetime import timedelta

        asa_emitter._td_burst_window = 10
        asa_emitter._td_avg_window = 30
        asa_emitter._td_burst_threshold = 9999
        asa_emitter._td_avg_threshold = 9999

        for i in range(120):
            event = self._make_deny_event(
                "198.51.100.1",
                "10.0.10.50",
                445,
                T0 + timedelta(seconds=i),
            )
            asa_emitter.emit(event)

        key = ("fw01", "198.51.100.1")
        assert key in asa_emitter._deny_timestamps
        # max_window=30 seconds, inclusive cutoff allows at most 31 one-second events
        assert len(asa_emitter._deny_timestamps[key]) <= 31


class TestNatRecords:
    """Tests for NAT translation records (305011/305012) emitted alongside connection logs."""

    def _make_nat_event(
        self,
        action="permit",
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.1",
        mapped_src_port=12345,
        mapped_dst_ip="203.0.113.50",
        mapped_dst_port=443,
        protocol="tcp",
        include_nat=True,
    ):
        from evidenceforge.events.contexts import NatContext

        fw = FirewallContext(
            action=action,
            msg_id=302013 if action == "permit" else 106023,
            connection_id=100,
            src_interface="inside",
            dst_interface="outside",
        )
        nat = (
            NatContext(
                nat_type=nat_type,
                mapped_src_ip=mapped_src_ip,
                mapped_src_port=mapped_src_port,
                mapped_dst_ip=mapped_dst_ip,
                mapped_dst_port=mapped_dst_port,
            )
            if include_nat
            else None
        )
        return _make_connection_event(protocol=protocol, firewall=fw, nat=nat)

    def _get_output_lines(self, tmp_path):
        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        return [line for line in output.strip().split("\n") if line]

    def test_built_with_nat_shows_mapped_ips_in_parens(self, asa_emitter, tmp_path):
        """Built line parenthesized addresses should use NAT-mapped IPs, not real ones."""
        event = self._make_nat_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        # The Built line should show mapped source in parens
        assert "(198.51.100.1/12345)" in output
        # Should NOT show the real pre-NAT source in parens
        assert "(10.0.10.50/54321)" not in output

    def test_built_without_nat_parens_match_real(self, asa_emitter, tmp_path):
        """Without NatContext, parenthesized addresses should match the real IPs."""
        event = _make_connection_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "cisco_asa.log").read_text()
        # Parens should reflect the real IPs since there is no NAT
        assert "(10.0.10.50/54321)" in output
        assert "(203.0.113.50/443)" in output

    def test_305011_emitted_for_nat_permit(self, asa_emitter, tmp_path):
        """A permitted connection with NatContext should emit a 305011 Built translation record."""
        event = self._make_nat_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        nat_built_lines = [line for line in lines if "305011" in line]
        assert len(nat_built_lines) >= 1
        assert (
            "Built dynamic TCP translation from inside:10.0.10.50/54321 to outside:198.51.100.1/12345"
            in nat_built_lines[0]
        )

    def test_305012_emitted_for_nat_teardown(self, asa_emitter, tmp_path):
        """A permitted connection with NatContext should emit a 305012 Teardown translation record."""
        event = self._make_nat_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        nat_teardown_lines = [line for line in lines if "305012" in line]
        assert len(nat_teardown_lines) >= 1
        assert "Teardown dynamic TCP translation" in nat_teardown_lines[0]

    def test_no_305011_for_deny(self, asa_emitter, tmp_path):
        """Deny events should not produce 305011 NAT records, even if NatContext is present."""
        event = self._make_nat_event(action="deny")
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        nat_lines = [line for line in lines if "305011" in line]
        assert len(nat_lines) == 0

    def test_no_305011_without_nat(self, asa_emitter, tmp_path):
        """Permit events without NatContext should not produce 305011 records."""
        event = self._make_nat_event(include_nat=False)
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        nat_lines = [line for line in lines if "305011" in line]
        assert len(nat_lines) == 0

    def test_static_nat_does_not_emit_per_flow_xlate_lifecycle(self, asa_emitter, tmp_path):
        """Static NAT mappings are configuration state, not per-flow xlate churn."""
        event = self._make_nat_event(nat_type="static")
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        nat_lines = [line for line in lines if "305011" in line or "305012" in line]
        assert nat_lines == []

    def test_305011_protocol_variations(self, asa_emitter, tmp_path):
        """NAT built messages should reflect the correct protocol for UDP and ICMP."""
        for proto in ("udp", "icmp"):
            # Use a fresh emitter for each protocol to avoid cross-contamination
            fmt = load_format("cisco_asa")
            sub_dir = tmp_path / f"nat_{proto}"
            sub_dir.mkdir()
            emitter = CiscoAsaEmitter(
                format_def=fmt,
                output_path=sub_dir,
                sensor_hostnames=["fw01"],
            )
            emitter._segment_config = asa_emitter._segment_config
            emitter._sensor_interfaces = asa_emitter._sensor_interfaces

            event = self._make_nat_event(protocol=proto)
            emitter.emit(event)
            emitter.flush()

            output = (sub_dir / "fw01" / "cisco_asa.log").read_text()
            nat_built_lines = [line for line in output.strip().split("\n") if "305011" in line]
            assert len(nat_built_lines) >= 1, f"No 305011 line for {proto}"
            assert f"Built dynamic {proto.upper()} translation" in nat_built_lines[0]

    def test_inbound_static_nat_suppresses_xlate_lifecycle(self, asa_emitter, tmp_path):
        """Inbound static NAT should keep mapping in 302013/302014, not 305011/305012."""
        from evidenceforge.events.contexts import NatContext

        event = _make_connection_event(
            src_ip="203.0.113.99",
            src_port=54321,
            dst_ip="203.0.113.5",  # Public VIP
            dst_port=443,
            firewall=FirewallContext(
                action="permit",
                msg_id=302013,
                connection_id=100,
                src_interface="outside",
                dst_interface="dmz",
            ),
            nat=NatContext(
                nat_type="static",
                mapped_src_ip="203.0.113.99",  # unchanged - no source translation
                mapped_src_port=54321,  # unchanged
                mapped_dst_ip="172.16.0.5",  # real DMZ server
                mapped_dst_port=443,
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()
        lines = self._get_output_lines(tmp_path)
        assert [line for line in lines if "305011" in line or "305012" in line] == []
        assert any("Built inbound TCP connection" in line for line in lines)
        assert any("Teardown TCP connection" in line for line in lines)

    def test_syn_timeout_teardown_duration_is_realistic(self, asa_emitter, tmp_path):
        """SYN Timeout teardown rows should not all render as zero-second waits."""
        event = _make_connection_event(
            conn_state="S0",
            duration=0.0,
            orig_bytes=0,
            resp_bytes=0,
            firewall=FirewallContext(
                action="permit",
                msg_id=302013,
                connection_id=100,
                src_interface="outside",
                dst_interface="inside",
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        teardown = next(line for line in lines if "302014" in line)
        assert "SYN Timeout" in teardown
        assert "duration 0:00:00" not in teardown

        built = next(line for line in lines if "302013" in line)
        built_ts = datetime.strptime(built[5:20], "%b %d %H:%M:%S").replace(year=2024)
        teardown_ts = datetime.strptime(teardown[5:20], "%b %d %H:%M:%S").replace(year=2024)
        match = re.search(r"duration 0:00:(\d{2})", teardown)
        assert match is not None
        assert int((teardown_ts - built_ts).total_seconds()) == int(match.group(1))
