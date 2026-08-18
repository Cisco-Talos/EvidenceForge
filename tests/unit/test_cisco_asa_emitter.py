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
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import FirewallContext, NatContext
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTuple,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from tests.network_factories import network_plan


@pytest.fixture
def asa_emitter(tmp_path):
    """Create an ASA emitter for testing."""
    fmt = load_format("cisco_asa")
    emitter = CiscoAsaEmitter(
        format_def=fmt,
        output_path=tmp_path,
        sensor_hostnames=["fw01"],
    )
    emitter.configure_output_target("sof-elk")
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
    """Create a connection OccurrenceBuilder for testing."""
    event = OccurrenceBuilder(
        timestamp=timestamp or T0,
        event_type="connection",
        network=network_plan(
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
        event = OccurrenceBuilder(timestamp=T0, event_type="process")
        assert asa_emitter.can_handle(event) is False

    def test_rejects_connection_without_network(self, asa_emitter):
        event = OccurrenceBuilder(timestamp=T0, event_type="connection")
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

    def test_visible_connection_id_mapping_includes_hidden_volume_gaps(self):
        """Final visible ASA IDs should not expose a tiny bounded increment pattern."""
        lines = []
        for index in range(80):
            ts = T0 + timedelta(seconds=index * 17)
            temp_id = 1_000_000 + index
            line = (
                f"<166>{ts:%b} {ts.day:2d} {ts:%H:%M:%S} fw01 "
                f"%ASA-6-302013: Built outbound TCP connection {temp_id} for "
                f"inside:10.0.10.50/{50000 + index} "
                f"(10.0.10.50/{50000 + index}) to outside:203.0.113.50/443 "
                "(203.0.113.50/443)"
            )
            lines.append((2024, line))

        mapping = CiscoAsaEmitter._build_connection_id_mapping(lines, "fw01")
        visible_ids = [mapping[str(1_000_000 + index)] for index in range(80)]
        gaps = [
            current - previous
            for previous, current in zip(visible_ids, visible_ids[1:], strict=False)
        ]

        assert visible_ids == sorted(visible_ids)
        assert any(gap > 5 for gap in gaps)
        assert len(set(gaps)) >= 20

    def test_exact_publication_freezes_matching_built_and_teardown_ids(
        self,
        asa_emitter: CiscoAsaEmitter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed first render cannot pair a retained Built row with a new teardown ID."""

        batch = ExactPublicationAuthority(capacity=1).issue_batch()
        event = _make_connection_event()
        original = asa_emitter._emit_teardown
        fail_before = True

        def fail_first_teardown(*args, **kwargs):
            nonlocal fail_before
            if fail_before:
                fail_before = False
                raise RuntimeError("teardown failed before publication")
            return original(*args, **kwargs)

        monkeypatch.setattr(asa_emitter, "_emit_teardown", fail_first_teardown)
        with pytest.raises(RuntimeError, match="teardown failed"):
            batch.publish(lambda: asa_emitter.emit(event))
        assert len(asa_emitter._writers) == 1
        writer = next(iter(asa_emitter._writers.values()))
        assert writer.event_count == 0

        batch.publish(lambda: asa_emitter.emit(event))
        batch.release_no_fail()
        assert writer._sorted_writer is not None
        assert writer._sorted_writer.event_count == 2
        asa_emitter.close()
        lines = writer.output_path.read_text(encoding="utf-8").splitlines()
        built_line = next(line for line in lines if "Built" in line)
        teardown_line = next(line for line in lines if "Teardown" in line)
        built_id = re.search(r"Built .* connection (\d+)", built_line)
        teardown_id = re.search(r"Teardown .* connection (\d+)", teardown_line)
        assert built_id is not None
        assert teardown_id is not None
        assert built_id.group(1) == teardown_id.group(1)

    def test_connection_id_mapping_preserves_same_second_file_order(self, tmp_path):
        """Same-second rows should keep the order already present in the final log file."""
        path = tmp_path / "cisco_asa.log"
        lines = [
            (
                "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP "
                "connection 1000010 for inside:10.0.10.50/50010 "
                "(10.0.10.50/50010) to outside:203.0.113.50/443 "
                "(203.0.113.50/443)"
            ),
            (
                "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP "
                "connection 1000001 for inside:10.0.10.51/50001 "
                "(10.0.10.51/50001) to outside:203.0.113.51/443 "
                "(203.0.113.51/443)"
            ),
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        mapping = CiscoAsaEmitter._connection_id_mapping(
            [("fw01|2024", SimpleNamespace(output_path=path))],
            "fw01",
        )
        visible_ids = [mapping["1000010"], mapping["1000001"]]

        assert visible_ids == sorted(visible_ids)

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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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
        assert int(byte_match.group(1)) == 5120
        assert "SYN Timeout" not in lines[1]

    def test_unobserved_boundary_teardown_keeps_only_built(self, asa_emitter, tmp_path):
        """A post-cutoff ASA close is absent rather than shifted into the window."""

        event = _make_connection_event(protocol="tcp")
        event.network_observations = (
            NetworkSensorObservation(
                sensor_identity="fw01",
                path_role="perimeter",
                capture_profile="default",
                tuple_view=NetworkTuple(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="203.0.113.50",
                    dst_port=443,
                    protocol="tcp",
                ),
                connection_uid="CBoundary1",
                connection_ids=(),
                file_ids=(),
                local_orig=True,
                local_resp=False,
                observed_start_time=T0,
                observed_close_time=T0 + timedelta(minutes=10),
                traffic=NetworkTrafficLedger(),
                visible_formats=frozenset({"cisco_asa"}),
                firewall_teardown_reason="TCP FINs",
                firewall_teardown_time=T0 + timedelta(minutes=10),
                firewall_teardown_observed=False,
            ),
        )
        event.network_observations_planned = True

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 1
        assert "Built outbound TCP connection" in lines[0]

    def test_connection_crossing_year_boundary_keeps_id_pairing(self, asa_emitter, tmp_path):
        """Built and teardown rows split by year should keep the same connection ID."""
        event = _make_connection_event(
            timestamp=datetime(2024, 12, 31, 23, 59, 30, tzinfo=UTC),
            duration=90,
        )
        asa_emitter.emit(event)
        asa_emitter.close()

        built = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text(encoding="utf-8")
        teardown = (tmp_path / "fw01" / "2025" / "cisco_asa.log").read_text(encoding="utf-8")
        built_id = re.search(r"connection (\d+) for", built)
        teardown_id = re.search(r"connection (\d+) for", teardown)

        assert built_id is not None
        assert teardown_id is not None
        assert built_id.group(1) == teardown_id.group(1)

    def test_output_admission_is_not_owned_by_emitter(self, asa_emitter, tmp_path):
        """Direct emission renders the full lifecycle; dispatcher owns window admission."""
        asa_emitter._output_end_time = T0 + timedelta(seconds=10)
        event = _make_connection_event(protocol="tcp", duration=83.5)

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 2
        assert "%ASA-6-302013:" in lines[0]
        assert "%ASA-6-302014:" in output

    def test_nat_output_admission_is_not_owned_by_emitter(self, asa_emitter, tmp_path):
        """Direct NAT emission leaves lifecycle admission to the dispatcher."""
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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        assert "%ASA-6-302013:" in output
        assert "%ASA-6-305011:" in output
        assert "%ASA-6-302014:" in output
        assert "%ASA-6-305012:" in output

    def test_teardown_byte_count_uses_canonical_transfer_total(self, asa_emitter, tmp_path):
        """ASA renders canonical transfer accounting without emitter-local variance."""
        event = _make_connection_event(protocol="tcp", orig_bytes=1024, resp_bytes=4096)

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        teardown = next(line for line in output.splitlines() if "%ASA-6-302014:" in line)
        byte_match = re.search(r"bytes (\d+)", teardown)
        assert byte_match is not None
        assert int(byte_match.group(1)) == 5120

    def test_sensor_accounting_is_projected_without_rebuilding_canonical_plan(
        self,
        asa_emitter,
        tmp_path,
    ):
        """ASA source-local byte views do not re-enter canonical transaction validation."""

        event = _make_connection_event(protocol="tcp", orig_bytes=1000, resp_bytes=1000)
        event.network_observations = (
            NetworkSensorObservation(
                sensor_identity="fw01",
                path_role="source_side",
                capture_profile="well_synced",
                tuple_view=NetworkTuple(
                    src_ip=event.network.src_ip,
                    src_port=event.network.src_port,
                    dst_ip=event.network.dst_ip,
                    dst_port=event.network.dst_port,
                    protocol=event.network.protocol,
                ),
                connection_uid="CAsaProjection1",
                connection_ids=(),
                file_ids=(),
                local_orig=True,
                local_resp=False,
                observed_start_time=T0,
                observed_close_time=T0 + timedelta(seconds=1),
                traffic=NetworkTrafficLedger(
                    orig=DirectionalTrafficLedger(
                        payload_bytes=1000,
                        packets=1,
                        ip_bytes=2000,
                    ),
                    resp=DirectionalTrafficLedger(
                        payload_bytes=1000,
                        packets=1,
                        ip_bytes=2000,
                    ),
                ),
                visible_formats=frozenset({"cisco_asa"}),
                firewall_teardown_reason="TCP FINs",
                firewall_teardown_time=T0 + timedelta(seconds=1),
            ),
        )
        event.network_observations_planned = True

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        teardown = next(line for line in output.splitlines() if "%ASA-6-302014:" in line)
        assert "duration 0:00:01 bytes 4000 TCP FINs" in teardown

    def test_successful_tcp_teardown_uses_fin_reason(self, asa_emitter, tmp_path):
        """ASA teardown reason should agree with a normal Zeek SF/FIN close."""
        event = _make_connection_event(protocol="tcp", conn_state="SF")

        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        teardown = next(line for line in output.splitlines() if "%ASA-6-302014:" in line)
        assert "TCP FINs" in teardown
        assert "TCP Reset" not in teardown

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

        assert not (tmp_path / "fw01" / "2024" / "cisco_asa.log").exists()

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

        assert not (tmp_path / "fw01" / "2024" / "cisco_asa.log").exists()

    def test_syn_timeout_requires_handshake_only_connection(self, asa_emitter, tmp_path):
        """SYN Timeout should not be used for connections with payload bytes."""
        event = _make_connection_event(
            protocol="tcp",
            duration=0.1,
            orig_bytes=0,
            resp_bytes=0,
        )
        event.network = replace(event.network, conn_state="S0")
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        teardown = [line for line in output.splitlines() if "%ASA-6-302014:" in line][0]
        assert "SYN Timeout" in teardown
        assert "bytes 0" in teardown

    def test_udp_produces_built_and_teardown(self, asa_emitter, tmp_path):
        """A permitted UDP connection should use 302015/302016."""
        event = _make_connection_event(protocol="udp", dst_port=53)
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 2
        assert "%ASA-6-302020:" in lines[0]
        assert "Built outbound ICMP connection" in lines[0]
        assert "faddr 203.0.113.50/8" in lines[0]
        assert "gaddr 10.0.10.50/0" in lines[0]
        assert "laddr 10.0.10.50/0" in lines[0]
        assert "faddr outside:" not in lines[0]
        assert "%ASA-6-302021:" in lines[1]
        assert "faddr 203.0.113.50/8" in lines[1]
        assert "gaddr 10.0.10.50/0" in lines[1]
        assert "laddr 10.0.10.50/0" in lines[1]
        assert "faddr outside:" not in lines[1]

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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        built_line = next(line for line in output.splitlines() if "%ASA-6-302020:" in line)
        assert "Built inbound ICMP connection" in built_line
        assert "faddr 203.0.113.50/8" in built_line
        assert "gaddr 172.16.0.5/0" in built_line
        assert "laddr 172.16.0.5/0" in built_line
        assert "faddr outside:" not in built_line
        assert "gaddr dmz:" not in built_line
        assert "laddr dmz:" not in built_line

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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        assert "Built inbound TCP connection" in output

    @pytest.mark.parametrize(
        ("protocol", "src_ip", "dst_ip", "expected"),
        [
            ("tcp", "172.16.0.5", "10.0.20.10", "inbound"),
            ("udp", "10.0.20.10", "172.16.0.5", "outbound"),
            ("icmp", "172.16.0.5", "10.0.20.10", "inbound"),
        ],
    )
    def test_direction_uses_interface_security_relationship(
        self, asa_emitter, tmp_path, protocol, src_ip, dst_ip, expected
    ):
        """DMZ/inside direction follows security levels for every protocol family."""
        event = _make_connection_event(
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=8 if protocol == "icmp" else 443,
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        assert f"Built {expected} {protocol.upper()} connection" in output

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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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
                deny_hash_a="0x2a1b",
                deny_hash_b="0x031f",
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        lines = [line for line in output.strip().split("\n") if line]
        assert len(lines) == 1
        assert "%ASA-4-106023:" in lines[0]
        assert "Deny tcp src outside:198.51.100.1/54321" in lines[0]
        assert "dst inside:10.0.10.50/445" in lines[0]
        assert 'by access-group "outside_access_in"' in lines[0]
        assert "[0x2a1b, 0x031f]" in lines[0]

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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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

        assert not (tmp_path / "fw01" / "2024" / "cisco_asa.log").exists()

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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        # Priority for severity 4: 20*8+4 = 164
        assert "<164>" in output
        assert "%ASA-4-106023:" in output

    def test_emit_raw_invalid_pri_and_severity_falls_back_without_crash(
        self, asa_emitter, tmp_path
    ):
        """Raw ASA records with invalid pri/severity should render with default severity."""
        asa_emitter.emit_raw(
            {
                "timestamp": T0,
                "hostname": "fw01",
                "severity": "x",
                "msg_id": 302013,
                "message": "Built inbound TCP connection",
                "pri": "x",
            }
        )
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        first_line = output.strip().split("\n")[0]
        assert first_line.startswith("<166>")
        assert "fw01 %ASA-6-302013:" in first_line

    def test_emit_raw_out_of_range_severity_is_bounded(self, asa_emitter, tmp_path):
        """Raw ASA severity must stay in the source-native 0-7 syslog range."""
        asa_emitter.emit_raw(
            {
                "timestamp": T0,
                "hostname": "fw01",
                "severity": 99,
                "msg_id": 302013,
                "message": "Built inbound TCP connection",
            }
        )
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        first_line = output.strip().split("\n")[0]
        assert first_line.startswith("<167>")
        assert "fw01 %ASA-7-302013:" in first_line


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
        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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
        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        return [line for line in output.strip().split("\n") if line]

    def test_built_with_nat_shows_mapped_ips_in_parens(self, asa_emitter, tmp_path):
        """Built line parenthesized addresses should use NAT-mapped IPs, not real ones."""
        event = self._make_nat_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
        # The Built line should show mapped source in parens
        assert "(198.51.100.1/12345)" in output
        # Should NOT show the real pre-NAT source in parens
        assert "(10.0.10.50/54321)" not in output

    def test_built_without_nat_parens_match_real(self, asa_emitter, tmp_path):
        """Without NatContext, parenthesized addresses should match the real IPs."""
        event = _make_connection_event()
        asa_emitter.emit(event)
        asa_emitter.flush()

        output = (tmp_path / "fw01" / "2024" / "cisco_asa.log").read_text()
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

    @pytest.mark.parametrize(
        ("protocol", "connection_msg_id"),
        [("tcp", "302013"), ("udp", "302015")],
    )
    def test_dynamic_translation_wraps_connection_lifecycle(
        self,
        asa_emitter,
        tmp_path,
        protocol,
        connection_msg_id,
    ):
        """Dynamic xlate allocation must precede connection state and outlive it."""
        event = self._make_nat_event(protocol=protocol)
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        message_ids = [
            line.split("%ASA-6-", maxsplit=1)[1].split(":", maxsplit=1)[0] for line in lines
        ]
        assert message_ids == [
            "305011",
            connection_msg_id,
            str(int(connection_msg_id) + 1),
            "305012",
        ]

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
            emitter.configure_output_target("sof-elk")
            emitter._segment_config = asa_emitter._segment_config
            emitter._sensor_interfaces = asa_emitter._sensor_interfaces

            event = self._make_nat_event(protocol=proto)
            emitter.emit(event)
            emitter.flush()

            output = (sub_dir / "fw01" / "2024" / "cisco_asa.log").read_text()
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

    def test_inbound_static_nat_real_tuple_renders_public_vip_in_parens(
        self,
        asa_emitter,
        tmp_path,
    ):
        """ASA should show the public VIP even when the canonical tuple is post-NAT."""
        from evidenceforge.events.contexts import NatContext

        event = _make_connection_event(
            src_ip="93.18.207.241",
            src_port=60814,
            dst_ip="172.16.0.5",
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
                mapped_src_ip="93.18.207.241",
                mapped_src_port=60814,
                mapped_dst_ip="172.16.0.5",
                mapped_dst_port=443,
                pre_nat_dst_ip="203.0.113.5",
                pre_nat_dst_port=443,
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        built_line = next(line for line in lines if "Built inbound TCP connection" in line)
        assert "outside:93.18.207.241/60814 (93.18.207.241/60814)" in built_line
        assert "dmz:172.16.0.5/443 (203.0.113.5/443)" in built_line
        assert "dmz:172.16.0.5/443 (172.16.0.5/443)" not in built_line

    def test_planned_inbound_icmp_renders_distinct_global_and_local_addresses(
        self,
        asa_emitter,
        tmp_path,
    ):
        """ASA ICMP projection consumes the observation-owned NAT address roles."""

        event = _make_connection_event(
            src_ip="198.51.100.25",
            src_port=0,
            dst_ip="203.0.113.5",
            dst_port=8,
            protocol="icmp",
            duration=1.0,
            firewall=FirewallContext(
                action="permit",
                msg_id=302020,
                connection_id=100,
                src_interface="outside",
                dst_interface="inside",
            ),
            nat=NatContext(
                nat_type="static",
                mapped_src_ip="198.51.100.25",
                mapped_src_port=0,
                mapped_dst_ip="10.0.20.5",
                mapped_dst_port=8,
            ),
        )
        event.network_observations = (
            NetworkSensorObservation(
                sensor_identity="fw01",
                path_role="destination_side",
                capture_profile="well_synced",
                tuple_view=NetworkTuple(
                    src_ip="198.51.100.25",
                    src_port=0,
                    dst_ip="203.0.113.5",
                    dst_port=8,
                    protocol="icmp",
                ),
                connection_uid="CInboundIcmp1",
                connection_ids=(),
                file_ids=(),
                local_orig=False,
                local_resp=True,
                observed_start_time=T0,
                observed_close_time=T0 + timedelta(seconds=1),
                traffic=NetworkTrafficLedger(),
                visible_formats=frozenset({"cisco_asa"}),
                firewall_teardown_time=T0 + timedelta(seconds=1),
                nat=NatSensorObservation(
                    nat_type="static",
                    direction="destination",
                    local_ip="10.0.20.5",
                    local_port=8,
                    global_ip="203.0.113.5",
                    global_port=8,
                    built_time=T0,
                    teardown_time=None,
                ),
            ),
        )
        event.network_observations_planned = True

        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        lifecycle = [line for line in lines if "302020" in line or "302021" in line]
        assert len(lifecycle) == 2
        assert all("gaddr 203.0.113.5/0 laddr 10.0.20.5/0" in line for line in lifecycle)

    def test_planned_dynamic_pat_tears_down_with_syn_timeout(
        self,
        asa_emitter,
        tmp_path,
    ):
        """ASA connection and PAT records consume the same planned close time."""

        event = self._make_nat_event()
        event.network = replace(
            event.network,
            duration=None,
            closed_at=None,
            phase_times=(("transport_start", event.network.started_at),),
            conn_state="S0",
            traffic=NetworkTrafficLedger(),
        )
        event.network_observations = (
            NetworkSensorObservation(
                sensor_identity="fw01",
                path_role="source_side",
                capture_profile="well_synced",
                tuple_view=NetworkTuple(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="203.0.113.50",
                    dst_port=443,
                    protocol="tcp",
                ),
                connection_uid="CNatTimeout1",
                connection_ids=(),
                file_ids=(),
                local_orig=True,
                local_resp=False,
                observed_start_time=T0,
                observed_close_time=None,
                traffic=NetworkTrafficLedger(),
                visible_formats=frozenset({"cisco_asa"}),
                firewall_teardown_reason="SYN Timeout",
                firewall_teardown_time=T0 + timedelta(seconds=30),
                nat=NatSensorObservation(
                    nat_type="dynamic_pat",
                    direction="source",
                    local_ip="10.0.10.50",
                    local_port=54321,
                    global_ip="198.51.100.1",
                    global_port=12345,
                    built_time=T0,
                    teardown_time=T0 + timedelta(seconds=30),
                ),
            ),
        )
        event.network_observations_planned = True

        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        connection_teardown = next(line for line in lines if "302014" in line)
        nat_teardown = next(line for line in lines if "305012" in line)
        assert "duration 0:00:30" in connection_teardown
        assert "duration 0:00:30" in nat_teardown

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
        assert int(match.group(1)) == 30
        assert int((teardown_ts - built_ts).total_seconds()) == int(match.group(1))

    def test_syn_timeout_releases_dynamic_translation_after_connection(
        self,
        asa_emitter,
        tmp_path,
    ):
        """A zero-duration S0 flow must retain its xlate until the SYN timeout."""
        event = self._make_nat_event()
        event = replace(
            event,
            network=replace(
                event.network,
                conn_state="S0",
                duration=0.0,
                closed_at=event.network.started_at,
                traffic=NetworkTrafficLedger(
                    orig=DirectionalTrafficLedger(0, 0, 0),
                    resp=DirectionalTrafficLedger(0, 0, 0),
                ),
            ),
        )
        asa_emitter.emit(event)
        asa_emitter.flush()

        lines = self._get_output_lines(tmp_path)
        message_ids = [
            line.split("%ASA-6-", maxsplit=1)[1].split(":", maxsplit=1)[0] for line in lines
        ]
        assert message_ids == ["305011", "302013", "302014", "305012"]
        teardown = next(line for line in lines if "302014" in line)
        release = next(line for line in lines if "305012" in line)
        assert teardown[5:20] == release[5:20]
        assert "duration 0:00:30" in teardown
        assert "duration 0:00:30" in release
