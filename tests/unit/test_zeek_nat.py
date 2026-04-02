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

"""Tests for per-sensor NAT IP swapping in Zeek conn emitters."""

import json
from datetime import UTC, datetime

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter

T0 = datetime(2024, 6, 15, 14, 23, 5, tzinfo=UTC)


def _make_conn_event_data(
    sensor_hostnames=None,
    nat_swaps_by_sensor=None,
    src_ip="10.0.10.50",
    src_port=54321,
    dst_ip="203.0.113.50",
    dst_port=443,
):
    """Build a Zeek conn event_data dict with optional NAT swap metadata."""
    data = {
        "ts": T0.timestamp(),
        "uid": "CTest123",
        "id.orig_h": src_ip,
        "id.orig_p": src_port,
        "id.resp_h": dst_ip,
        "id.resp_p": dst_port,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.5,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "conn_state": "SF",
        "history": "ShADad",
    }
    if sensor_hostnames is not None:
        data["_sensor_hostnames"] = sensor_hostnames
    if nat_swaps_by_sensor is not None:
        data["_nat_swaps_by_sensor"] = nat_swaps_by_sensor
    return data


def _read_conn_json(base_path, sensor_hostname):
    """Read the first JSON record from a sensor's conn.json output."""
    path = base_path / sensor_hostname / "conn.json"
    assert path.exists(), f"Expected output at {path}"
    with open(path) as f:
        return json.loads(f.readline())


class TestZeekNatSwaps:
    """Verify that _nat_swaps_by_sensor causes IP/port field substitution per sensor."""

    def test_inside_sensor_sees_real_ips(self, tmp_path):
        """A sensor NOT listed in _nat_swaps_by_sensor should see the original IPs."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek"],
            nat_swaps_by_sensor={"outside-zeek": {"src_ip": "198.51.100.1"}},
        )
        emitter.emit_event(event_data)
        emitter.close()

        record = _read_conn_json(tmp_path, "inside-zeek")
        assert record["id.orig_h"] == "10.0.10.50"
        assert record["id.orig_p"] == 54321

    def test_outside_sensor_sees_mapped_src_ip(self, tmp_path):
        """A sensor listed in _nat_swaps_by_sensor should see the NAT-mapped source IP."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            nat_swaps_by_sensor={"outside-zeek": {"src_ip": "198.51.100.1", "src_port": 12345}},
        )
        emitter.emit_event(event_data)
        emitter.close()

        inside_record = _read_conn_json(tmp_path, "inside-zeek")
        outside_record = _read_conn_json(tmp_path, "outside-zeek")

        # Inside sensor sees real source IP
        assert inside_record["id.orig_h"] == "10.0.10.50"
        # Outside sensor sees NAT-mapped source IP
        assert outside_record["id.orig_h"] == "198.51.100.1"

    def test_outside_sensor_sees_mapped_src_port(self, tmp_path):
        """A sensor with src_port in its NAT swap should see the mapped source port."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            nat_swaps_by_sensor={"outside-zeek": {"src_ip": "198.51.100.1", "src_port": 12345}},
        )
        emitter.emit_event(event_data)
        emitter.close()

        inside_record = _read_conn_json(tmp_path, "inside-zeek")
        outside_record = _read_conn_json(tmp_path, "outside-zeek")

        # Inside sensor sees real source port
        assert inside_record["id.orig_p"] == 54321
        # Outside sensor sees NAT-mapped source port
        assert outside_record["id.orig_p"] == 12345

    def test_dst_ip_swapped_for_inbound_static_nat(self, tmp_path):
        """A NAT swap with dst_ip should replace id.resp_h for the post-NAT sensor."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            nat_swaps_by_sensor={"outside-zeek": {"dst_ip": "198.51.100.80"}},
        )
        emitter.emit_event(event_data)
        emitter.close()

        inside_record = _read_conn_json(tmp_path, "inside-zeek")
        outside_record = _read_conn_json(tmp_path, "outside-zeek")

        # Inside sensor sees real destination IP
        assert inside_record["id.resp_h"] == "203.0.113.50"
        # Outside sensor sees NAT-mapped destination IP
        assert outside_record["id.resp_h"] == "198.51.100.80"

    def test_no_swap_when_no_nat_metadata(self, tmp_path):
        """Without _nat_swaps_by_sensor, all sensors see identical real IPs."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            # No _nat_swaps_by_sensor
        )
        emitter.emit_event(event_data)
        emitter.close()

        inside_record = _read_conn_json(tmp_path, "inside-zeek")
        outside_record = _read_conn_json(tmp_path, "outside-zeek")

        assert inside_record["id.orig_h"] == "10.0.10.50"
        assert outside_record["id.orig_h"] == "10.0.10.50"
        assert inside_record["id.resp_h"] == "203.0.113.50"
        assert outside_record["id.resp_h"] == "203.0.113.50"
