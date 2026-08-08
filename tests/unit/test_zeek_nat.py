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

"""Tests for observation-owned per-sensor NAT projection in Zeek emitters."""

import json
from datetime import UTC, datetime, timedelta

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTuple,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_smtp import ZeekSmtpEmitter

T0 = datetime(2024, 6, 15, 14, 23, 5, tzinfo=UTC)


def _make_conn_event_data(
    sensor_hostnames=None,
    observations=None,
    src_ip="10.0.10.50",
    src_port=54321,
    dst_ip="203.0.113.50",
    dst_port=443,
):
    """Build Zeek conn render data with optional frozen sensor observations."""
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
    if observations is not None:
        data["_network_sensor_observations"] = {
            observation.sensor_identity: observation for observation in observations
        }
        data["_network_observations_planned"] = True
        data["_canonical_network_start"] = T0
    return data


def _observation(
    sensor: str,
    *,
    src_ip: str = "10.0.10.50",
    src_port: int = 54321,
    dst_ip: str = "203.0.113.50",
    dst_port: int = 443,
    visible_format: str = "zeek_conn",
    local_resp: bool = False,
) -> NetworkSensorObservation:
    """Return one immutable sensor view for a rendered NAT test."""

    return NetworkSensorObservation(
        sensor_identity=sensor,
        path_role="source_side" if sensor == "inside-zeek" else "destination_side",
        capture_profile="well_synced",
        tuple_view=NetworkTuple(src_ip, src_port, dst_ip, dst_port, "tcp"),
        connection_uid=f"C{sensor.replace('-', '')}",
        connection_ids=(),
        file_ids=(),
        local_orig=True,
        local_resp=local_resp,
        observed_start_time=T0,
        observed_close_time=T0 + timedelta(seconds=1.5),
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(100, 1, 140),
            resp=DirectionalTrafficLedger(200, 1, 240),
        ),
        visible_formats=frozenset({visible_format}),
    )


def _read_conn_json(base_path, sensor_hostname):
    """Read the first JSON record from a sensor's conn.json output."""
    path = base_path / sensor_hostname / "conn.json"
    assert path.exists(), f"Expected output at {path}"
    with open(path) as f:
        return json.loads(f.readline())


def _read_smtp_json(base_path, sensor_hostname):
    """Read the first JSON record from a sensor's smtp.json output."""
    path = base_path / sensor_hostname / "smtp.json"
    assert path.exists(), f"Expected output at {path}"
    with open(path) as f:
        return json.loads(f.readline())


class TestZeekNatObservations:
    """Verify that frozen observations project the source-local NAT view."""

    def test_inside_sensor_sees_real_ips(self, tmp_path):
        """An inside observation retains the canonical source tuple."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek"],
            observations=[_observation("inside-zeek")],
        )
        emitter.emit_event(event_data)
        emitter.close()

        record = _read_conn_json(tmp_path, "inside-zeek")
        assert record["id.orig_h"] == "10.0.10.50"
        assert record["id.orig_p"] == 54321

    def test_outside_sensor_sees_mapped_src_ip(self, tmp_path):
        """Inside and outside observations may expose different source addresses."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            observations=[
                _observation("inside-zeek"),
                _observation("outside-zeek", src_ip="198.51.100.1", src_port=12345),
            ],
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
        """The source-local tuple owns the corresponding translated source port."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            observations=[
                _observation("inside-zeek"),
                _observation("outside-zeek", src_ip="198.51.100.1", src_port=12345),
            ],
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
        """An inbound observation projects the post-NAT destination."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
            observations=[
                _observation("inside-zeek"),
                _observation("outside-zeek", dst_ip="198.51.100.80"),
            ],
        )
        emitter.emit_event(event_data)
        emitter.close()

        inside_record = _read_conn_json(tmp_path, "inside-zeek")
        outside_record = _read_conn_json(tmp_path, "outside-zeek")

        # Inside sensor sees real destination IP
        assert inside_record["id.resp_h"] == "203.0.113.50"
        # Outside sensor sees NAT-mapped destination IP
        assert outside_record["id.resp_h"] == "198.51.100.80"

    def test_nat_does_not_add_conn_or_file_only_fields_to_smtp(self, tmp_path):
        """NAT rendering must not leak unrelated Zeek fields into smtp.log rows."""
        fmt = load_format("zeek_smtp")
        emitter = ZeekSmtpEmitter(fmt, tmp_path, sensor_hostnames=["outside-zeek"])

        event_data = {
            "ts": T0.timestamp(),
            "uid": "CTestSmtp123",
            "id.orig_h": "198.51.100.10",
            "id.orig_p": 52525,
            "id.resp_h": "10.0.10.25",
            "id.resp_p": 25,
            "trans_depth": 1,
            "helo": "mx.example.test",
            "mailfrom": "sender@example.test",
            "rcptto": ["user@example.test"],
            "last_reply": "250 2.0.0 queued",
            "path": [],
            "tls": False,
            "date": "Mon, 18 Mar 2024 12:00:00 +0000",
            "from": "<sender@example.test>",
            "to": ["<user@example.test>"],
            "cc": [],
            "msg_id": "<message@example.test>",
            "subject": "Test",
            "user_agent": "Postfix",
            "fuids": [],
            "_sensor_hostnames": ["outside-zeek"],
            "_network_sensor_observations": {
                "outside-zeek": _observation(
                    "outside-zeek",
                    src_ip="198.51.100.10",
                    src_port=52525,
                    dst_ip="203.0.113.25",
                    dst_port=25,
                    visible_format="zeek_smtp",
                    local_resp=True,
                )
            },
            "_network_observations_planned": True,
            "_canonical_network_start": T0,
        }
        emitter.emit_event(event_data)
        emitter.close()

        record = _read_smtp_json(tmp_path, "outside-zeek")
        assert record["id.resp_h"] == "203.0.113.25"
        assert "local_resp" not in record
        assert "tx_hosts" not in record
        assert "rx_hosts" not in record

    def test_no_swap_when_no_nat_metadata(self, tmp_path):
        """The direct raw adapter retains its supplied tuple without an observation plan."""
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, tmp_path, sensor_hostnames=["inside-zeek", "outside-zeek"])

        event_data = _make_conn_event_data(
            sensor_hostnames=["inside-zeek", "outside-zeek"],
        )
        emitter.emit_event(event_data)
        emitter.close()

        inside_record = _read_conn_json(tmp_path, "inside-zeek")
        outside_record = _read_conn_json(tmp_path, "outside-zeek")

        assert inside_record["id.orig_h"] == "10.0.10.50"
        assert outside_record["id.orig_h"] == "10.0.10.50"
        assert inside_record["id.resp_h"] == "203.0.113.50"
        assert outside_record["id.resp_h"] == "203.0.113.50"
