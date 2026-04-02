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

from datetime import UTC, datetime

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import FirewallContext, NetworkContext
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
    firewall=None,
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
        ),
        firewall=firewall,
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
        id1 = asa_emitter._next_conn_id("fw01")
        id2 = asa_emitter._next_conn_id("fw01")
        assert id2 == id1 + 1

    def test_per_sensor_counters(self, asa_emitter):
        id_fw01 = asa_emitter._next_conn_id("fw01")
        id_fw02 = asa_emitter._next_conn_id("fw02")
        # Both start from the same base
        assert id_fw01 == id_fw02


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
        assert "bytes 5120" in lines[1]

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
