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

"""Tests for ZeekMultiplexEmitter per-sensor directory routing."""

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier, Thread

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import DnsContext, HttpContext, NetworkContext, X509Context
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter
from evidenceforge.generation.emitters.zeek_x509 import ZeekX509Emitter


class TestPerSensorDirectoryRouting:
    """Verify that Zeek emitters route output to per-sensor subdirectories."""

    def test_two_sensors_create_two_subdirs(self):
        """Emitting to 2 sensor hostnames creates files in 2 subdirs."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["fw01", "fw02"])

            event_data = {
                "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                "uid": "CTest123456789ab",
                "id.orig_h": "10.0.0.1",
                "id.orig_p": 50000,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 443,
                "proto": "tcp",
                "conn_state": "SF",
                "_sensor_hostnames": ["fw01", "fw02"],
            }
            emitter.emit_event(event_data)
            emitter.close()

            assert (base / "fw01" / "conn.json").exists()
            assert (base / "fw02" / "conn.json").exists()

            # Raw emitter input remains canonical; sensor-local IDs are planned upstream.
            with open(base / "fw01" / "conn.json") as f:
                line1 = json.loads(f.readline())
            with open(base / "fw02" / "conn.json") as f:
                line2 = json.loads(f.readline())
            assert line1["uid"] == "CTest123456789ab"
            assert line2["uid"] == line1["uid"]
            assert line1["uid"].startswith("C")
            assert line2["uid"].startswith("C")

    def test_x509_sensor_timing_uses_parent_connection_uid(self):
        """X.509 certificate rows should share flow-keyed sensor timing with files.log."""
        x509_fmt = load_format("zeek_x509")
        files_fmt = load_format("zeek_files")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            x509_emitter = ZeekX509Emitter(x509_fmt, base, sensor_hostnames=["core", "dmz"])
            files_emitter = ZeekFilesEmitter(files_fmt, base, sensor_hostnames=["core", "dmz"])

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    zeek_uid="CMySpecificUID123",
                    conn_state="SF",
                    duration=2.0,
                ),
                x509=X509Context(
                    fuid="Fabcdef1234567890",
                    fingerprint="a" * 40,
                    certificate_serial="01",
                    certificate_subject="CN=example.com",
                    certificate_issuer="CN=Example CA",
                    certificate_not_valid_before=1700000000.0,
                    certificate_not_valid_after=1730000000.0,
                ),
            )
            event._sensor_hostnames_by_format = {
                "zeek_x509": ["core", "dmz"],
                "zeek_files": ["core", "dmz"],
            }

            x509_emitter.emit(event)
            files_emitter.emit(event)
            x509_emitter.close()
            files_emitter.close()

            rows = {
                sensor: {
                    "x509": json.loads((base / sensor / "x509.json").read_text()),
                    "files": json.loads((base / sensor / "files.json").read_text()),
                }
                for sensor in ("core", "dmz")
            }

            assert rows["core"]["x509"]["id"] == rows["core"]["files"]["fuid"]
            assert rows["dmz"]["x509"]["id"] == rows["dmz"]["files"]["fuid"]
            core_gap = rows["core"]["files"]["ts"] - rows["core"]["x509"]["ts"]
            dmz_gap = rows["dmz"]["files"]["ts"] - rows["dmz"]["x509"]["ts"]
            assert abs(dmz_gap - core_gap) <= 0.000001

    def test_emitter_preserves_lossless_accounting_without_observation_plan(self):
        """Emitters do not invent source-local timing, identity, or accounting."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "duration": 12.5,
                    "orig_bytes": 23124,
                    "resp_bytes": 80921,
                    "orig_pkts": 52,
                    "resp_pkts": 74,
                    "orig_ip_bytes": 25204,
                    "resp_ip_bytes": 83881,
                    "conn_state": "SF",
                    "history": "ShADadfF",
                    "missed_bytes": 0,
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            for field in (
                "uid",
                "ts",
                "id.orig_h",
                "id.orig_p",
                "id.resp_h",
                "id.resp_p",
                "proto",
                "duration",
                "orig_pkts",
                "resp_pkts",
                "orig_ip_bytes",
                "resp_ip_bytes",
            ):
                assert core[field] == dmz[field]
            assert core["orig_bytes"] == dmz["orig_bytes"] == 23124
            assert core["resp_bytes"] == dmz["resp_bytes"] == 80921
            for row in (core, dmz):
                assert row["orig_ip_bytes"] >= row["orig_bytes"] + (40 * row["orig_pkts"])
                assert row["resp_ip_bytes"] >= row["resp_bytes"] + (40 * row["resp_pkts"])

    def test_sensor_observation_preserves_icmp_echo_accounting(self):
        """ICMP echo payload and IP-byte accounting should not vary by sensor."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestIcmp1234567",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 8,
                    "id.resp_h": "10.0.0.2",
                    "id.resp_p": 0,
                    "proto": "icmp",
                    "service": "icmp",
                    "duration": 0.04,
                    "orig_bytes": 120,
                    "resp_bytes": 120,
                    "orig_pkts": 1,
                    "resp_pkts": 1,
                    "orig_ip_bytes": 148,
                    "resp_ip_bytes": 148,
                    "conn_state": "SF",
                    "history": "Dd",
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            assert core["uid"] == dmz["uid"]
            assert core["ts"] == dmz["ts"]
            for row in (core, dmz):
                assert row["orig_bytes"] == row["resp_bytes"] == 120
                assert row["orig_ip_bytes"] == row["resp_ip_bytes"] == 148
                assert row["orig_ip_bytes"] - row["orig_bytes"] == 28
                assert row["resp_ip_bytes"] - row["resp_bytes"] == 28
            assert dmz["duration"] == core["duration"]

    @pytest.mark.parametrize("conn_duration", [0.024625, 0.024925])
    def test_dns_emitter_does_not_synthesize_sensor_observation(self, conn_duration):
        """Direct DNS emission preserves canonical source timing and accounting."""
        conn_fmt = load_format("zeek_conn")
        dns_fmt = load_format("zeek_dns")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            conn_emitter = ZeekEmitter(conn_fmt, base, sensor_hostnames=["core", "dmz"])
            dns_emitter = ZeekDnsEmitter(dns_fmt, base, sensor_hostnames=["core", "dmz"])
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=41710,
                    dst_ip="10.0.0.53",
                    dst_port=53,
                    protocol="udp",
                    service="dns",
                    zeek_uid="CTestDns1234567",
                    duration=conn_duration,
                    orig_bytes=80,
                    resp_bytes=177,
                    orig_pkts=1,
                    resp_pkts=1,
                    orig_ip_bytes=108,
                    resp_ip_bytes=205,
                    conn_state="SF",
                    history="Dd",
                    ip_proto=17,
                ),
                dns=DnsContext(
                    query="updates.example.com",
                    answers=["10.0.0.20"],
                    TTLs=[300.0],
                    trans_id=4242,
                    rtt=0.024625,
                ),
            )
            event._sensor_hostnames_by_format = {
                "zeek_conn": ["core", "dmz"],
                "zeek_dns": ["core", "dmz"],
            }

            conn_emitter.emit(event)
            dns_emitter.emit(event)
            conn_emitter.close()
            dns_emitter.close()

            core_conn = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz_conn = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])
            core_dns = json.loads((base / "core" / "dns.json").read_text().splitlines()[0])
            dmz_dns = json.loads((base / "dmz" / "dns.json").read_text().splitlines()[0])

            for field in (
                "orig_bytes",
                "resp_bytes",
                "orig_pkts",
                "resp_pkts",
                "orig_ip_bytes",
                "resp_ip_bytes",
                "history",
            ):
                assert core_conn[field] == dmz_conn[field]
            assert dmz_conn["duration"] == core_conn["duration"]
            assert dmz_dns["rtt"] == core_dns["rtt"]
            assert core_dns["rtt"] <= core_conn["duration"]
            assert dmz_dns["rtt"] <= dmz_conn["duration"]
            assert dmz_conn["duration"] - core_conn["duration"] == pytest.approx(
                dmz_dns["rtt"] - core_dns["rtt"],
                abs=0.000001,
            )
            assert core_dns["query"] == dmz_dns["query"] == "updates.example.com"
            assert core_dns["answers"] == dmz_dns["answers"] == ["10.0.0.20"]

    def test_udp_dns_ip_bytes_use_valid_header_accounting(self):
        """UDP DNS rows should not render impossible IP-header deltas."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "conn.json"
            emitter = ZeekEmitter(fmt, output_file)

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestDns1234567",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 41710,
                    "id.resp_h": "10.0.0.53",
                    "id.resp_p": 53,
                    "proto": "udp",
                    "service": "dns",
                    "duration": 0.02,
                    "orig_bytes": 80,
                    "resp_bytes": 177,
                    "orig_pkts": 1,
                    "resp_pkts": 1,
                    "orig_ip_bytes": 113,
                    "resp_ip_bytes": 211,
                    "conn_state": "SF",
                    "history": "Dd",
                }
            )
            emitter.close()

            row = json.loads(output_file.read_text().splitlines()[0])
            assert row["orig_ip_bytes"] - row["orig_bytes"] == 28
            assert row["resp_ip_bytes"] - row["resp_bytes"] == 28

    def test_non_finite_numeric_timestamp_does_not_crash_multi_sensor_emit(self):
        """Raw Zeek timestamps may be NaN or infinity; multi-sensor drift must not crash."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            for idx, ts in enumerate((float("nan"), float("inf"), float("-inf"))):
                emitter.emit_event(
                    {
                        "ts": ts,
                        "uid": f"CTestNonFinite{idx}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 50000 + idx,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "conn_state": "SF",
                        "_sensor_hostnames": ["core", "dmz"],
                    }
                )
            emitter.close()

            for sensor in ("core", "dmz"):
                assert len((base / sensor / "conn.json").read_text().splitlines()) == 3

    def test_emitter_does_not_invent_flow_capture_texture(self):
        """Raw direct emission leaves sensor clock projection to the planner."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])
            ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

            for idx in range(40):
                emitter.emit_event(
                    {
                        "ts": ts,
                        "uid": f"CTestSpread{idx:06d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 50000 + idx,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "duration": 1.0,
                        "orig_bytes": 1000,
                        "resp_bytes": 4000,
                        "orig_pkts": 5,
                        "resp_pkts": 7,
                        "conn_state": "SF",
                        "_sensor_hostnames": ["core", "dmz"],
                    }
                )
            emitter.close()

            core_rows = [
                json.loads(line) for line in (base / "core" / "conn.json").read_text().splitlines()
            ]
            dmz_rows = [
                json.loads(line) for line in (base / "dmz" / "conn.json").read_text().splitlines()
            ]
            core_by_port = {row["id.orig_p"]: row for row in core_rows}
            dmz_by_port = {row["id.orig_p"]: row for row in dmz_rows}
            offsets = [
                round(dmz_by_port[port]["ts"] - core_by_port[port]["ts"], 6)
                for port in sorted(core_by_port)
            ]

            assert set(offsets) == {0.0}

    def test_raw_lossless_conn_metrics_remain_canonical_across_sensors(self):
        """Lossless direct rows retain canonical accounting across sensors."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])
            ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

            for idx in range(40):
                emitter.emit_event(
                    {
                        "ts": ts,
                        "uid": f"CTestMetric{idx:06d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 51000 + idx,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "duration": 2.5 + (idx / 100),
                        "orig_bytes": 2000 + idx,
                        "resp_bytes": 8000 + idx,
                        "orig_pkts": 10,
                        "resp_pkts": 20,
                        "orig_ip_bytes": 2400 + idx,
                        "resp_ip_bytes": 8800 + idx,
                        "conn_state": "SF",
                        "history": "ShADadfF",
                        "missed_bytes": 0,
                        "_sensor_hostnames": ["core", "dmz"],
                    }
                )
            emitter.close()

            core_rows = [
                json.loads(line) for line in (base / "core" / "conn.json").read_text().splitlines()
            ]
            dmz_rows = [
                json.loads(line) for line in (base / "dmz" / "conn.json").read_text().splitlines()
            ]
            core_by_port = {row["id.orig_p"]: row for row in core_rows}
            dmz_by_port = {row["id.orig_p"]: row for row in dmz_rows}
            compared_fields = (
                "duration",
                "orig_bytes",
                "resp_bytes",
                "orig_pkts",
                "resp_pkts",
                "orig_ip_bytes",
                "resp_ip_bytes",
                "conn_state",
                "history",
                "missed_bytes",
            )
            cloned = [
                port
                for port, core in core_by_port.items()
                if all(core[field] == dmz_by_port[port][field] for field in compared_fields)
            ]

            assert cloned == sorted(core_by_port)

    def test_raw_lossless_tcp_durations_are_not_rewritten(self):
        """The emitter preserves canonical long-flow durations exactly."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])
            ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

            for idx in range(60):
                emitter.emit_event(
                    {
                        "ts": ts,
                        "uid": f"CTestLongSsh{idx:05d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 52000 + idx,
                        "id.resp_h": "10.0.0.20",
                        "id.resp_p": 22,
                        "proto": "tcp",
                        "service": "ssh",
                        "duration": 900.0 + idx,
                        "orig_bytes": 32000 + idx,
                        "resp_bytes": 109000 + idx,
                        "orig_pkts": 210,
                        "resp_pkts": 320,
                        "orig_ip_bytes": 40400 + idx,
                        "resp_ip_bytes": 121800 + idx,
                        "conn_state": "SF",
                        "history": "ShADadfF",
                        "_sensor_hostnames": ["core", "dmz"],
                    }
                )
            emitter.close()

            core_rows = [
                json.loads(line) for line in (base / "core" / "conn.json").read_text().splitlines()
            ]
            dmz_rows = [
                json.loads(line) for line in (base / "dmz" / "conn.json").read_text().splitlines()
            ]
            core_by_port = {row["id.orig_p"]: row for row in core_rows}
            dmz_by_port = {row["id.orig_p"]: row for row in dmz_rows}
            deltas = [
                round(dmz_by_port[port]["duration"] - core_by_port[port]["duration"], 6)
                for port in sorted(core_by_port)
            ]

            assert set(deltas) == {0.0}

    def test_second_sensor_observation_skips_huge_numeric_jitter(self):
        """Huge raw numeric counters should not crash multi-sensor Zeek jitter."""
        fmt = load_format("zeek_conn")
        huge_value = 10**400
        huge_ip_bytes = huge_value * 41
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestHuge1234567",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "duration": huge_value,
                    "orig_bytes": huge_value,
                    "resp_bytes": huge_value,
                    "orig_pkts": huge_value,
                    "resp_pkts": huge_value,
                    "orig_ip_bytes": huge_ip_bytes,
                    "resp_ip_bytes": huge_ip_bytes,
                    "conn_state": "SF",
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            assert core["uid"] == dmz["uid"]
            for row in (core, dmz):
                assert row["duration"] == huge_value
                assert row["orig_bytes"] == huge_value
                assert row["resp_bytes"] == huge_value
                assert row["orig_pkts"] == huge_value
                assert row["resp_pkts"] == huge_value
                assert row["orig_ip_bytes"] == huge_ip_bytes
                assert row["resp_ip_bytes"] == huge_ip_bytes

    def test_second_sensor_observation_preserves_http_body_lengths(self):
        """HTTP body sizes are transaction facts, not per-sensor packet-counter jitter."""
        fmt = load_format("zeek_http")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekHttpEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 80,
                    "trans_depth": 1,
                    "method": "GET",
                    "host": "example.com",
                    "uri": "/index.html",
                    "request_body_len": 1024,
                    "response_body_len": 65536,
                    "status_code": 200,
                    "status_msg": "OK",
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "http.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "http.json").read_text().splitlines()[0])

            assert core["host"] == dmz["host"]
            assert core["uri"] == dmz["uri"]
            assert core["uid"] == dmz["uid"]
            assert core["ts"] == dmz["ts"]
            assert core["request_body_len"] == dmz["request_body_len"] == 1024
            assert core["response_body_len"] == dmz["response_body_len"] == 65536

    def test_conn_observation_clamps_to_http_body_floors(self):
        """Per-sensor conn jitter must not make conn bytes smaller than http body bytes."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestBodyFloor12",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "duration": 0.25,
                    "orig_bytes": 900,
                    "resp_bytes": 63_000,
                    "orig_pkts": 8,
                    "resp_pkts": 60,
                    "orig_ip_bytes": 1060,
                    "resp_ip_bytes": 64_200,
                    "conn_state": "SF",
                    "_http_request_body_len": 1024,
                    "_http_response_body_len": 65536,
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            for sensor in ("core", "dmz"):
                row = json.loads((base / sensor / "conn.json").read_text().splitlines()[0])
                assert row["orig_bytes"] >= 1024
                assert row["resp_bytes"] >= 65536
                assert row["orig_ip_bytes"] >= row["orig_bytes"] + (20 * row["orig_pkts"])
                assert row["resp_ip_bytes"] >= row["resp_bytes"] + (20 * row["resp_pkts"])

    def test_conn_observation_uses_http_flow_body_floor_for_reused_connections(self):
        """A parent HTTP conn row must cover later same-UID transaction body bytes."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["dmz"])

            emitter.emit(
                SecurityEvent(
                    timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    event_type="connection",
                    network=NetworkContext(
                        src_ip="10.0.0.1",
                        src_port=50000,
                        dst_ip="8.8.8.8",
                        dst_port=80,
                        protocol="tcp",
                        service="http",
                        zeek_uid="CTestHttpFlowFloor",
                        duration=0.25,
                        orig_bytes=900,
                        resp_bytes=63_000,
                        orig_pkts=8,
                        resp_pkts=60,
                        orig_ip_bytes=1060,
                        resp_ip_bytes=64_200,
                        conn_state="SF",
                    ),
                    http=HttpContext(
                        method="GET",
                        host="portal.example",
                        uri="/",
                        response_body_len=4096,
                        flow_response_body_len=65_536,
                        flow_transaction_count=3,
                    ),
                )
            )
            emitter.close()

            row = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])
            assert row["resp_bytes"] >= 65_536

    def test_lossless_conn_observation_keeps_http_backed_accounting(self):
        """Lossless direct rows keep HTTP body and traffic accounting identical."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestHttpClone12",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "duration": 0.25,
                    "orig_bytes": 1400,
                    "resp_bytes": 70_000,
                    "orig_pkts": 8,
                    "resp_pkts": 60,
                    "orig_ip_bytes": 1720,
                    "resp_ip_bytes": 72_400,
                    "conn_state": "SF",
                    "history": "ShADadfF",
                    "missed_bytes": 0,
                    "_http_request_body_len": 1024,
                    "_http_response_body_len": 65536,
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            assert dmz["orig_bytes"] == core["orig_bytes"]
            assert dmz["resp_bytes"] == core["resp_bytes"]
            accounting_fields = (
                "duration",
                "orig_pkts",
                "resp_pkts",
                "orig_ip_bytes",
                "resp_ip_bytes",
            )
            assert all(dmz[field] == core[field] for field in accounting_fields)
            for row in (core, dmz):
                assert row["orig_bytes"] >= 1024
                assert row["resp_bytes"] >= 65536
                assert row["orig_ip_bytes"] >= row["orig_bytes"] + (20 * row["orig_pkts"])
                assert row["resp_ip_bytes"] >= row["resp_bytes"] + (20 * row["resp_pkts"])

    def test_missed_bytes_alone_does_not_trigger_emitter_loss_synthesis(self):
        """Capture loss must be an explicit planner decision, not an emitter inference."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestHttpLoss12",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "duration": 1800.0,
                    "orig_bytes": 1400,
                    "resp_bytes": 70_000,
                    "orig_pkts": 8,
                    "resp_pkts": 60,
                    "orig_ip_bytes": 1720,
                    "resp_ip_bytes": 72_400,
                    "conn_state": "SF",
                    "history": "ShADadfF",
                    "missed_bytes": 256,
                    "_http_request_body_len": 1024,
                    "_http_response_body_len": 65536,
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            assert dmz["orig_bytes"] == core["orig_bytes"]
            assert dmz["resp_bytes"] == core["resp_bytes"]
            assert dmz["duration"] == core["duration"]
            assert dmz["missed_bytes"] == core["missed_bytes"] == 256
            for row in (core, dmz):
                assert row["orig_bytes"] >= 1024
                assert row["resp_bytes"] >= 65536
                assert row["orig_ip_bytes"] >= row["orig_bytes"] + (20 * row["orig_pkts"])
                assert row["resp_ip_bytes"] >= row["resp_bytes"] + (20 * row["resp_pkts"])

    def test_bulk_proxy_flow_sensor_accounting_stays_near_canonical_bytes(self):
        """Bulk client-to-proxy rows should not drift by megabytes across sensors."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["core", "dmz"])

            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTestBulkProxy12",
                    "id.orig_h": "10.10.1.35",
                    "id.orig_p": 50872,
                    "id.resp_h": "10.10.3.20",
                    "id.resp_p": 8080,
                    "proto": "tcp",
                    "duration": 925.5,
                    "orig_bytes": 2_200_000,
                    "resp_bytes": 326_500_000,
                    "orig_pkts": 1800,
                    "resp_pkts": 223_700,
                    "orig_ip_bytes": 2_272_000,
                    "resp_ip_bytes": 335_448_000,
                    "conn_state": "SF",
                    "history": "ShADadfF",
                    "missed_bytes": 308,
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])
            core_total = core["orig_ip_bytes"] + core["resp_ip_bytes"]
            dmz_total = dmz["orig_ip_bytes"] + dmz["resp_ip_bytes"]
            allowed_delta = max(65_536, core["missed_bytes"] + dmz["missed_bytes"] + 8192)

            assert dmz["orig_bytes"] == core["orig_bytes"]
            assert dmz["resp_bytes"] == core["resp_bytes"]
            assert abs(dmz_total - core_total) <= allowed_delta
            assert abs(dmz_total - core_total) < 1_000_000
            assert dmz["duration"] == core["duration"]
            for row in (core, dmz):
                assert row["orig_ip_bytes"] >= row["orig_bytes"] + (20 * row["orig_pkts"])
                assert row["resp_ip_bytes"] >= row["resp_bytes"] + (20 * row["resp_pkts"])

    def test_single_sensor_single_subdir(self):
        """Single sensor creates a single subdirectory."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["sensor-1"])
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                    "_sensor_hostnames": ["sensor-1"],
                }
            )
            emitter.close()
            assert (base / "sensor-1" / "conn.json").exists()

    def test_no_sensors_no_directory_mode_output(self):
        """No sensors configured means no directory-mode sensor output."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=[])
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                }
            )
            emitter.close()
            assert not (base / "conn.json").exists()
            assert not (base / "zeek_conn.json").exists()
            assert not list(base.rglob("*.json"))

    def test_ssl_emitter_sensor_filenames(self):
        """SSL emitter uses ssl.json in sensor dirs."""
        fmt = load_format("zeek_ssl")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekSslEmitter(fmt, base, sensor_hostnames=["fw01"])
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "version": "TLSv12",
                    "cipher": "TLS_AES_128_GCM_SHA256",
                    "server_name": "example.com",
                    "resumed": True,
                    "established": True,
                    "ssl_history": "CsiI",
                    "_sensor_hostnames": ["fw01"],
                }
            )
            emitter.close()
            assert (base / "fw01" / "ssl.json").exists()


class TestDirectFileMode:
    """Backward compat: passing a file path directly still works."""

    def test_file_path_writes_directly(self):
        """Output path with extension → writes to that exact file."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "my_output.json"
            emitter = ZeekEmitter(fmt, output_file)
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                }
            )
            emitter.close()
            assert output_file.exists()
            with open(output_file) as f:
                data = json.loads(f.readline())
            assert data["uid"] == "CTest123456789ab"


class TestWriterBuffering:
    """Test _SingleZeekWriter buffer behavior."""

    def test_auto_flush_on_buffer_full(self):
        """Buffer auto-flushes when reaching capacity."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test.json"
            # Small buffer of 5 events
            emitter = ZeekEmitter(fmt, output_file, buffer_size=5)
            for i in range(10):
                emitter.emit_event(
                    {
                        "ts": datetime(2024, 1, 15, 10, 0, i, tzinfo=UTC),
                        "uid": f"CTest{i:013d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 50000 + i,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "conn_state": "SF",
                    }
                )
            emitter.close()
            with open(output_file) as f:
                lines = [line for line in f if line.strip()]
            assert len(lines) == 10

    def test_close_sorts_by_zeek_timestamp_across_flushes(self):
        """Out-of-order Zeek events should be written chronologically on close."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test.json"
            emitter = ZeekEmitter(fmt, output_file, buffer_size=1)
            for second in (30, 10, 20):
                emitter.emit_event(
                    {
                        "ts": datetime(2024, 1, 15, 10, 0, second, tzinfo=UTC),
                        "uid": f"CTest{second:013d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 50000 + second,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "conn_state": "SF",
                    }
                )

            emitter.close()

            records = [json.loads(line) for line in output_file.read_text().splitlines()]
            assert [record["id.orig_p"] for record in records] == [50010, 50020, 50030]

    def test_close_sorts_each_sensor_by_zeek_timestamp(self):
        """Per-sensor Zeek outputs sort independently by rendered ts."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, buffer_size=1, sensor_hostnames=["s1", "s2"])
            for second in (30, 10, 20):
                emitter.emit_event(
                    {
                        "ts": datetime(2024, 1, 15, 10, 0, second, tzinfo=UTC),
                        "uid": f"CTest{second:013d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 50000 + second,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "conn_state": "SF",
                        "_sensor_hostnames": ["s1", "s2"],
                    }
                )

            emitter.close()

            for sensor in ("s1", "s2"):
                records = [
                    json.loads(line)
                    for line in (base / sensor / "conn.json").read_text().splitlines()
                ]
                timestamps = [record["ts"] for record in records]
                assert timestamps == sorted(timestamps)

    def test_flush_empty_no_file(self):
        """Flushing with empty buffer doesn't create file."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test.json"
            emitter = ZeekEmitter(fmt, output_file)
            emitter.flush()
            emitter.close()
            assert not output_file.exists()


class TestEmitterLifecycle:
    """Test flush, close, and event_count."""

    def test_event_count_aggregates(self):
        """event_count sums across all sensor writers."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["s1", "s2"])
            for i in range(3):
                emitter.emit_event(
                    {
                        "ts": datetime(2024, 1, 15, 10, 0, i, tzinfo=UTC),
                        "uid": f"CTest{i:013d}",
                        "id.orig_h": "10.0.0.1",
                        "id.orig_p": 50000,
                        "id.resp_h": "8.8.8.8",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "conn_state": "SF",
                        "_sensor_hostnames": ["s1", "s2"],
                    }
                )
            emitter.close()
            # Each event goes to 2 sensors → 6 total writes
            assert emitter.event_count == 6

    def test_close_flushes_all(self):
        """close() flushes all writers to disk."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            emitter = ZeekEmitter(fmt, base, sensor_hostnames=["s1"])
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                    "_sensor_hostnames": ["s1"],
                }
            )
            # Don't manually flush — close should handle it
            emitter.close()
            assert (base / "s1" / "conn.json").exists()
            with open(base / "s1" / "conn.json") as f:
                assert len(f.readlines()) == 1


class TestSensorHostnameResolution:
    """Test hostname vs name fallback in NetworkSensor."""

    def test_sensor_with_hostname(self):
        """NetworkSensor.hostname used as directory name."""
        from evidenceforge.models.scenario import NetworkSensor

        sensor = NetworkSensor(
            type="network",
            name="core-switch-tap",
            hostname="fw01",
            monitoring_segments=["workstations"],
        )
        assert sensor.hostname == "fw01"

    def test_sensor_without_hostname_falls_back_to_name(self):
        """Empty hostname falls back to name."""
        from evidenceforge.models.scenario import NetworkSensor

        sensor = NetworkSensor(
            type="network", name="core-switch-tap", monitoring_segments=["workstations"]
        )
        dirname = sensor.hostname or sensor.name
        assert dirname == "core-switch-tap"


class TestThreadSafety:
    """Verify concurrent access doesn't lose events."""

    def test_concurrent_writes_no_loss(self):
        """Multiple threads writing to same sensor don't lose events."""
        fmt = load_format("zeek_conn")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "test.json"
            emitter = ZeekEmitter(fmt, output_file, buffer_size=10)

            num_threads = 4
            events_per_thread = 25
            barrier = Barrier(num_threads)

            def write_events(thread_id):
                barrier.wait()
                for i in range(events_per_thread):
                    emitter.emit_event(
                        {
                            "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                            "uid": f"C{thread_id:02d}{i:015d}",
                            "id.orig_h": "10.0.0.1",
                            "id.orig_p": 50000,
                            "id.resp_h": "8.8.8.8",
                            "id.resp_p": 443,
                            "proto": "tcp",
                            "conn_state": "SF",
                        }
                    )

            threads = [Thread(target=write_events, args=(t,)) for t in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            emitter.close()

            with open(output_file) as f:
                lines = [line for line in f if line.strip()]
            assert len(lines) == num_threads * events_per_thread
