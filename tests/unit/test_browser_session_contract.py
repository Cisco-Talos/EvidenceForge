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

"""HTTP/browser-session contract tests."""

import random
from collections.abc import Callable
from datetime import UTC, datetime

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HttpContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.browser_session import (
    BrowserSessionActionBundle,
    BrowserSessionRequest,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.browsing_session import BrowsingRequest
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System


class _CollectorEmitter:
    """Minimal emitter that records events matching a predicate."""

    def __init__(self, predicate: Callable[[SecurityEvent], bool]) -> None:
        self._predicate = predicate
        self.events: list[SecurityEvent] = []

    def can_handle(self, event: SecurityEvent) -> bool:
        """Return whether this collector should record the event."""

        return self._predicate(event)

    def emit(self, event: SecurityEvent) -> None:
        """Record one event."""

        self.events.append(event)


def _activity_generator_with_collectors() -> tuple[
    ActivityGenerator,
    StateManager,
    _CollectorEmitter,
    _CollectorEmitter,
    _CollectorEmitter,
]:
    state_manager = StateManager()
    conn_emitter = _CollectorEmitter(
        lambda event: (
            event.event_type == "connection"
            and event.network is not None
            and not event.network.application_layer_only
        )
    )
    http_emitter = _CollectorEmitter(
        lambda event: event.event_type == "connection" and event.http is not None
    )
    files_emitter = _CollectorEmitter(
        lambda event: event.event_type == "connection" and event.file_transfer is not None
    )
    emitters = {
        "zeek_conn": conn_emitter,
        "zeek_http": http_emitter,
        "zeek_files": files_emitter,
    }
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
    return (
        ActivityGenerator(state_manager, emitters, dispatcher=dispatcher),
        state_manager,
        conn_emitter,
        http_emitter,
        files_emitter,
    )


def test_browser_session_reuses_parent_http_uid_for_same_host_subresources(monkeypatch):
    """Browser-session subresources should render as later transactions on the same UID."""

    def fake_browsing_session(**_kwargs) -> list[BrowsingRequest]:
        return [
            BrowsingRequest(
                time_offset_ms=0,
                hostname="portal.example.com",
                path="/",
                method="GET",
                content_type="text/html",
                referrer="",
                trans_depth=1,
                is_page_load=True,
                response_body_len=4096,
                request_body_len=0,
                status_code=200,
            ),
            BrowsingRequest(
                time_offset_ms=120,
                hostname="portal.example.com",
                path="/assets/app.js",
                method="GET",
                content_type="application/javascript",
                referrer="http://portal.example.com/",
                trans_depth=2,
                is_page_load=False,
                response_body_len=8192,
                request_body_len=0,
                status_code=200,
            ),
        ]

    monkeypatch.setattr(
        "evidenceforge.generation.actions.browser_session."
        "browsing_session.generate_browsing_session",
        fake_browsing_session,
    )
    generator, state_manager, conn_emitter, http_emitter, _files_emitter = (
        _activity_generator_with_collectors()
    )
    timestamp = datetime(2026, 2, 22, 12, 32, 37, tzinfo=UTC)
    source = System(
        hostname="WS-01",
        ip="10.0.0.5",
        os="Windows 11",
        type="workstation",
    )
    state_manager.set_current_time(timestamp)

    result = BrowserSessionActionBundle(
        request=BrowserSessionRequest(
            src_ip=source.ip,
            dst_ip="93.184.216.34",
            time=timestamp,
            hostname="portal.example.com",
            dst_port=80,
            proto="tcp",
            service="http",
            source_system=source,
            domain_tags=("web",),
            source_os="windows",
            user_agent="Mozilla/5.0",
            emit_dns_on_page_load=False,
        ),
        executor=generator,
        rng=random.Random(7),
    ).execute_with_result()

    assert result.request_count == 2
    assert len(conn_emitter.events) == 1
    assert len(http_emitter.events) == 2
    first_http, second_http = http_emitter.events
    assert first_http.network.zeek_uid == second_http.network.zeek_uid
    assert second_http.network.src_port == first_http.network.src_port
    assert second_http.network.application_layer_only is True
    assert [event.http.trans_depth for event in http_emitter.events] == [1, 2]


def test_caller_http_large_download_attaches_zeek_file_transfer():
    """Large caller-provided HTTP response bodies should get files.log metadata."""

    generator, state_manager, _conn_emitter, http_emitter, files_emitter = (
        _activity_generator_with_collectors()
    )
    timestamp = datetime(2026, 2, 22, 12, 32, 37, tzinfo=UTC)
    state_manager.set_current_time(timestamp)
    response_body_len = 131_952_082

    uid = generator.generate_connection(
        "10.0.0.5",
        "93.184.216.34",
        timestamp,
        dst_port=80,
        proto="tcp",
        service="http",
        duration=12.0,
        orig_bytes=800,
        resp_bytes=response_body_len,
        conn_state="SF",
        http=HttpContext(
            method="GET",
            host="update.dbeaver.io",
            uri="/files/dbeaver-ce-latest-x86_64-setup.exe",
            user_agent="Mozilla/5.0",
            response_body_len=response_body_len,
            status_code=200,
            status_msg="OK",
            resp_mime_types=["application/x-msdownload"],
        ),
        emit_dns=False,
    )

    assert uid
    assert len(http_emitter.events) == 1
    assert len(files_emitter.events) == 1
    event = http_emitter.events[0]
    assert event is files_emitter.events[0]
    assert event.file_transfer is not None
    assert event.file_transfer.source == "HTTP"
    assert event.file_transfer.mime_type == "application/x-msdownload"
    assert event.file_transfer.analyzers == ["SHA1"]
    assert event.file_transfer.sha1
    assert event.file_transfer.seen_bytes == response_body_len
    assert event.http.resp_fuids == [event.file_transfer.fuid]
    assert event.http.resp_mime_types == [event.file_transfer.mime_type]
