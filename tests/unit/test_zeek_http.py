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

"""Tests for Zeek http.log emitter."""

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HttpContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter


class TestHttpFormatAccuracy:
    """Verify http.log output matches real Zeek sample data."""

    def test_format_matches_sample(self):
        """Field names and types match sample_data/Zeek-JSON/http.log."""
        real = json.loads(
            '{"ts":1427847279.587877,"uid":"CN1WJj4XVGDD9RJ6Dk",'
            '"id.orig_h":"192.168.0.53","id.orig_p":4366,'
            '"id.resp_h":"192.168.0.1","id.resp_p":8080,'
            '"trans_depth":1,"method":"SUBSCRIBE",'
            '"host":"192.168.0.1:8080","uri":"/WANCommonInterfaceConfig",'
            '"version":"1.1","user_agent":"Mozilla/4.0 (compatible; UPnP/1.0; Windows 9x)",'
            '"request_body_len":0,"response_body_len":0,'
            '"status_code":200,"status_msg":"OK","tags":[]}'
        )
        assert isinstance(real["tags"], list)
        assert isinstance(real["trans_depth"], int)
        assert isinstance(real["status_code"], int)
        assert isinstance(real["request_body_len"], int)

    def test_emitter_output_fields(self):
        """Emitter produces all required http.log fields."""
        fmt = load_format("zeek_http")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "http.json"
            emitter = ZeekHttpEmitter(fmt, output)
            emitter.emit_event(
                {
                    "ts": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                    "uid": "CTest123456789ab",
                    "id.orig_h": "10.0.0.1",
                    "id.orig_p": 50000,
                    "id.resp_h": "93.184.216.34",
                    "id.resp_p": 80,
                    "trans_depth": 1,
                    "method": "GET",
                    "host": "example.com",
                    "uri": "/index.html",
                    "version": "1.1",
                    "user_agent": "Mozilla/5.0",
                    "request_body_len": 0,
                    "response_body_len": 2048,
                    "status_code": 200,
                    "status_msg": "OK",
                    "tags": [],
                }
            )
            emitter.close()

            with open(output) as f:
                data = json.loads(f.readline())

            assert data["method"] == "GET"
            assert data["host"] == "example.com"
            assert data["uri"] == "/index.html"
            assert data["status_code"] == 200
            assert data["tags"] == []
            assert data["request_body_len"] == 0
            assert data["response_body_len"] == 2048

    def test_tags_is_array(self):
        """tags field should be a JSON array, not a string."""
        fmt = load_format("zeek_http")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "http.json"
            emitter = ZeekHttpEmitter(fmt, output)
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
                    "uri": "/",
                    "request_body_len": 0,
                    "response_body_len": 0,
                    "status_code": 200,
                    "status_msg": "OK",
                    "tags": ["VIA_PROXY"],
                }
            )
            emitter.close()
            with open(output) as f:
                data = json.loads(f.readline())
            assert isinstance(data["tags"], list)
            assert data["tags"] == ["VIA_PROXY"]

    def test_resp_fuids_is_array(self):
        """resp_fuids field should be a JSON array when present."""
        fmt = load_format("zeek_http")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "http.json"
            emitter = ZeekHttpEmitter(fmt, output)
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
                    "uri": "/",
                    "request_body_len": 0,
                    "response_body_len": 1000,
                    "status_code": 200,
                    "status_msg": "OK",
                    "tags": [],
                    "resp_fuids": ["FheZAo1hKNan3xnZCd"],
                    "resp_mime_types": ["text/html"],
                }
            )
            emitter.close()
            with open(output) as f:
                data = json.loads(f.readline())
            assert isinstance(data["resp_fuids"], list)
            assert data["resp_fuids"] == ["FheZAo1hKNan3xnZCd"]

    def test_optional_fields_omitted_when_empty(self):
        """Optional fields like referrer, resp_fuids omitted when None."""
        fmt = load_format("zeek_http")
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "http.json"
            emitter = ZeekHttpEmitter(fmt, output)
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
                    "uri": "/",
                    "request_body_len": 0,
                    "response_body_len": 0,
                    "status_code": 200,
                    "status_msg": "OK",
                    # No tags, referrer, resp_fuids, resp_mime_types
                }
            )
            emitter.close()
            with open(output) as f:
                data = json.loads(f.readline())
            assert "referrer" not in data
            assert "resp_fuids" not in data
            assert "resp_mime_types" not in data


class TestHttpCanHandle:
    """Verify can_handle() filtering."""

    def test_accepts_connection_with_http(self):
        fmt = load_format("zeek_http")
        emitter = ZeekHttpEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1", src_port=50000, dst_ip="8.8.8.8", dst_port=80, protocol="tcp"
            ),
            http=HttpContext(method="GET", host="example.com", uri="/"),
        )
        assert emitter.can_handle(event) is True

    def test_rejects_without_http_context(self):
        fmt = load_format("zeek_http")
        emitter = ZeekHttpEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1", src_port=50000, dst_ip="8.8.8.8", dst_port=80, protocol="tcp"
            ),
        )
        assert emitter.can_handle(event) is False

    def test_accepts_application_layer_transactions(self):
        fmt = load_format("zeek_http")
        emitter = ZeekHttpEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=50000,
                dst_ip="8.8.8.8",
                dst_port=80,
                protocol="tcp",
                service="http",
                application_layer_only=True,
            ),
            http=HttpContext(method="GET", host="example.com", uri="/app.js", trans_depth=2),
        )
        assert emitter.can_handle(event) is True

    def test_conn_emitter_rejects_application_layer_transactions(self):
        fmt = load_format("zeek_conn")
        emitter = ZeekEmitter(fmt, Path("/tmp/test.json"))
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=50000,
                dst_ip="8.8.8.8",
                dst_port=80,
                protocol="tcp",
                service="http",
                application_layer_only=True,
            ),
            http=HttpContext(method="GET", host="example.com", uri="/app.js", trans_depth=2),
        )
        assert emitter.can_handle(event) is False


class TestHttpRenderTiming:
    """Verify http.log uses analyzer/request timing, not cloned conn start time."""

    def test_emit_offsets_http_timestamp_from_connection_timestamp(self, tmp_path):
        fmt = load_format("zeek_http")
        output = tmp_path / "http.json"
        emitter = ZeekHttpEmitter(fmt, output, buffer_size=1)
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=base_ts,
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=50000,
                dst_ip="93.184.216.34",
                dst_port=80,
                protocol="tcp",
                service="http",
                zeek_uid="ChttpTiming1234",
            ),
            http=HttpContext(method="GET", host="example.com", uri="/"),
        )

        emitter.emit(event)
        emitter.close()

        data = json.loads(output.read_text().splitlines()[0])
        assert data["ts"] > base_ts.timestamp()
        offset_us = round((data["ts"] - base_ts.timestamp()) * 1_000_000)
        assert offset_us % 1000 != 0

    def test_emit_preserves_same_uid_transaction_timestamp_order(self, tmp_path, monkeypatch):
        """Per-request analyzer jitter must not reorder same-UID transaction depths."""
        fmt = load_format("zeek_http")
        output = tmp_path / "http.json"
        emitter = ZeekHttpEmitter(fmt, output, buffer_size=1)
        base_ts = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        deltas = [timedelta(milliseconds=450), timedelta(milliseconds=1)]

        monkeypatch.setattr(
            "evidenceforge.generation.emitters.zeek_http.sample_packet_timing_delta",
            lambda *_args, **_kwargs: deltas.pop(0),
        )

        def make_event(timestamp: datetime, trans_depth: int, uri: str) -> SecurityEvent:
            return SecurityEvent(
                timestamp=timestamp,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.0.1",
                    src_port=50000,
                    dst_ip="93.184.216.34",
                    dst_port=80,
                    protocol="tcp",
                    service="http",
                    zeek_uid="ChttpTiming1234",
                ),
                http=HttpContext(
                    method="GET",
                    host="example.com",
                    uri=uri,
                    trans_depth=trans_depth,
                ),
            )

        emitter.emit(make_event(base_ts, 1, "/"))
        emitter.emit(make_event(base_ts + timedelta(milliseconds=100), 2, "/app.js"))
        emitter.close()

        rows = [json.loads(line) for line in output.read_text().splitlines()]
        assert [row["trans_depth"] for row in rows] == [1, 2]
        assert rows[1]["ts"] > rows[0]["ts"]
