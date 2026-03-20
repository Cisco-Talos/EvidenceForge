"""Tests for SecurityEvent fan-out across multiple Zeek emitters."""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    FileTransferContext, HttpContext, NetworkContext, SslContext,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter


class TestSslFanOut:
    """SSL connection produces correlated conn + ssl entries."""

    def test_ssl_connection_produces_conn_and_ssl(self):
        """Single event with network+ssl → both conn.json and ssl.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            conn_emitter = ZeekEmitter(load_format("zeek_conn"), base, sensor_hostnames=["s1"])
            ssl_emitter = ZeekSslEmitter(load_format("zeek_ssl"), base, sensor_hostnames=["s1"])

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                event_type="connection",
                network=NetworkContext(
                    src_ip='10.0.10.50', src_port=54321, dst_ip='93.184.216.34',
                    dst_port=443, protocol='tcp', service='ssl',
                    zeek_uid='CTestFanout12345',
                    conn_state='SF', history='ShADadfF',
                    duration=2.5, orig_bytes=1024, resp_bytes=4096,
                    orig_pkts=10, resp_pkts=8,
                    orig_ip_bytes=1500, resp_ip_bytes=4500, ip_proto=6,
                ),
                ssl=SslContext(
                    version='TLSv12',
                    cipher='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    server_name='www.example.com',
                    resumed=False, established=True, ssl_history='CsiI',
                ),
                _sensor_hostnames_by_format={'zeek_conn': ['s1'], 'zeek_ssl': ['s1'], 'zeek_http': ['s1'], 'zeek_files': ['s1']},
            )

            # Simulate dispatcher fan-out
            if conn_emitter.can_handle(event):
                conn_emitter.emit(event)
            if ssl_emitter.can_handle(event):
                ssl_emitter.emit(event)

            conn_emitter.close()
            ssl_emitter.close()

            # Both files should exist
            assert (base / "s1" / "conn.json").exists()
            assert (base / "s1" / "ssl.json").exists()

            # UIDs should match
            with open(base / "s1" / "conn.json") as f:
                conn_data = json.loads(f.readline())
            with open(base / "s1" / "ssl.json") as f:
                ssl_data = json.loads(f.readline())

            assert conn_data['uid'] == ssl_data['uid'] == 'CTestFanout12345'


class TestHttpFilesFanOut:
    """HTTP connection with file produces conn + http + files entries."""

    def test_http_files_fanout(self):
        """Single event with network+http+file_transfer → three correlated files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            conn_emitter = ZeekEmitter(load_format("zeek_conn"), base, sensor_hostnames=["s1"])
            http_emitter = ZeekHttpEmitter(load_format("zeek_http"), base, sensor_hostnames=["s1"])
            files_emitter = ZeekFilesEmitter(load_format("zeek_files"), base, sensor_hostnames=["s1"])

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                event_type="connection",
                network=NetworkContext(
                    src_ip='10.0.10.50', src_port=54321, dst_ip='93.184.216.34',
                    dst_port=80, protocol='tcp', service='http',
                    zeek_uid='CTestHttpFiles01',
                    conn_state='SF', duration=1.0,
                    orig_bytes=512, resp_bytes=2048,
                    orig_pkts=5, resp_pkts=4,
                    orig_ip_bytes=800, resp_ip_bytes=2400, ip_proto=6,
                ),
                http=HttpContext(
                    method='GET', host='example.com', uri='/page.html',
                    version='1.1', user_agent='Mozilla/5.0',
                    request_body_len=0, response_body_len=2048,
                    status_code=200, status_msg='OK', tags=[],
                    resp_fuids=['FTestFile01234567'],
                    resp_mime_types=['text/html'],
                ),
                file_transfer=FileTransferContext(
                    fuid='FTestFile01234567', source='HTTP',
                    depth=0, analyzers=[], mime_type='text/html',
                    seen_bytes=2048, total_bytes=2048,
                    is_orig=False, missing_bytes=0, overflow_bytes=0,
                    timedout=False,
                ),
                _sensor_hostnames_by_format={'zeek_conn': ['s1'], 'zeek_ssl': ['s1'], 'zeek_http': ['s1'], 'zeek_files': ['s1']},
            )

            for emitter in [conn_emitter, http_emitter, files_emitter]:
                if emitter.can_handle(event):
                    emitter.emit(event)
                emitter.close()

            # All three files should exist
            assert (base / "s1" / "conn.json").exists()
            assert (base / "s1" / "http.json").exists()
            assert (base / "s1" / "files.json").exists()

            with open(base / "s1" / "conn.json") as f:
                conn_data = json.loads(f.readline())
            with open(base / "s1" / "http.json") as f:
                http_data = json.loads(f.readline())
            with open(base / "s1" / "files.json") as f:
                files_data = json.loads(f.readline())

            # UID consistency
            assert conn_data['uid'] == http_data['uid'] == files_data['uid'] == 'CTestHttpFiles01'

            # File cross-reference: files fuid appears in http resp_fuids
            assert files_data['fuid'] == 'FTestFile01234567'
            assert 'FTestFile01234567' in http_data['resp_fuids']


class TestNoFanOutWithoutContext:
    """Only conn.log emitted when no SSL/HTTP/files context present."""

    def test_network_only_no_ssl_http_files(self):
        """Event with only NetworkContext → only conn emitter handles it."""
        conn_emitter = ZeekEmitter(load_format("zeek_conn"), Path("/tmp/test.json"))
        ssl_emitter = ZeekSslEmitter(load_format("zeek_ssl"), Path("/tmp/test.json"))
        http_emitter = ZeekHttpEmitter(load_format("zeek_http"), Path("/tmp/test.json"))
        files_emitter = ZeekFilesEmitter(load_format("zeek_files"), Path("/tmp/test.json"))

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            event_type="connection",
            network=NetworkContext(
                src_ip='10.0.0.1', src_port=50000, dst_ip='8.8.8.8',
                dst_port=443, protocol='tcp', zeek_uid='CTest123456789ab',
            ),
        )

        assert conn_emitter.can_handle(event) is True
        assert ssl_emitter.can_handle(event) is False
        assert http_emitter.can_handle(event) is False
        assert files_emitter.can_handle(event) is False


class TestMultiSensorFanOut:
    """Fan-out writes to multiple sensor directories."""

    def test_two_sensors_both_receive(self):
        """Both sensors get correlated conn + ssl records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            conn_emitter = ZeekEmitter(load_format("zeek_conn"), base, sensor_hostnames=["fw01", "fw02"])
            ssl_emitter = ZeekSslEmitter(load_format("zeek_ssl"), base, sensor_hostnames=["fw01", "fw02"])

            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                event_type="connection",
                network=NetworkContext(
                    src_ip='10.0.0.1', src_port=50000, dst_ip='8.8.8.8',
                    dst_port=443, protocol='tcp', zeek_uid='CMultiSensor1234',
                    conn_state='SF', ip_proto=6,
                ),
                ssl=SslContext(version='TLSv13', cipher='TLS_AES_256_GCM_SHA384'),
                _sensor_hostnames_by_format={'zeek_conn': ['fw01', 'fw02'], 'zeek_ssl': ['fw01', 'fw02']},
            )

            conn_emitter.emit(event)
            ssl_emitter.emit(event)
            conn_emitter.close()
            ssl_emitter.close()

            # Both sensor dirs have both log types
            for sensor in ['fw01', 'fw02']:
                assert (base / sensor / "conn.json").exists()
                assert (base / sensor / "ssl.json").exists()
                with open(base / sensor / "conn.json") as f:
                    assert json.loads(f.readline())['uid'] == 'CMultiSensor1234'
