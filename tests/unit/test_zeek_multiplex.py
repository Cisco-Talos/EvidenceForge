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

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter


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

            # Each independent sensor gets its own deterministic UID space.
            with open(base / "fw01" / "conn.json") as f:
                line1 = json.loads(f.readline())
            with open(base / "fw02" / "conn.json") as f:
                line2 = json.loads(f.readline())
            assert line1["uid"] != "CTest123456789ab"
            assert line2["uid"] != line1["uid"]  # Independent sensors have unique UIDs
            assert line1["uid"].startswith("C")
            assert line2["uid"].startswith("C")

    def test_second_sensor_observation_preserves_lossless_packetization(self):
        """Lossless multi-sensor rows keep canonical packet counts and bytes."""
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
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            for field in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"):
                assert core[field] == dmz[field]
            assert core["uid"] != dmz["uid"]
            assert core["ts"] != dmz["ts"]
            assert abs(core["ts"] - dmz["ts"]) <= 0.005
            assert core["orig_bytes"] == dmz["orig_bytes"] == 23124
            assert core["resp_bytes"] == dmz["resp_bytes"] == 80921
            assert core["orig_pkts"] == dmz["orig_pkts"] == 52
            assert core["resp_pkts"] == dmz["resp_pkts"] == 74
            assert core["duration"] == dmz["duration"] == 12.5
            assert core["orig_ip_bytes"] == dmz["orig_ip_bytes"]
            assert core["resp_ip_bytes"] == dmz["resp_ip_bytes"]
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
                    "_allow_sensor_observation_variance": True,
                    "_sensor_hostnames": ["core", "dmz"],
                }
            )
            emitter.close()

            core = json.loads((base / "core" / "conn.json").read_text().splitlines()[0])
            dmz = json.loads((base / "dmz" / "conn.json").read_text().splitlines()[0])

            assert core["uid"] != dmz["uid"]
            assert core["ts"] != dmz["ts"]
            for row in (core, dmz):
                assert row["orig_bytes"] == row["resp_bytes"] == 120
                assert row["orig_ip_bytes"] == row["resp_ip_bytes"] == 148
                assert row["orig_ip_bytes"] - row["orig_bytes"] == 28
                assert row["resp_ip_bytes"] - row["resp_bytes"] == 28

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

    def test_sensor_timestamp_offsets_vary_by_flow(self):
        """Cross-sensor timestamps should not collapse into one fixed offset band."""
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

            assert max(offsets) - min(offsets) > 0.0005
            assert len(set(offsets)) > 30
            assert max(abs(offset) for offset in offsets) <= 0.005

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
            assert core["uid"] != dmz["uid"]
            assert core["ts"] != dmz["ts"]
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

    def test_no_sensors_flat_output(self):
        """No sensors configured → flat output using _flat_filename."""
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
            assert (base / "zeek_conn.json").exists()

    def test_ssl_emitter_sensor_filenames(self):
        """SSL emitter uses ssl.json in sensor dirs, zeek_ssl.json for flat."""
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
