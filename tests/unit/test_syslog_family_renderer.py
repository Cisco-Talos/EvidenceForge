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

"""Tests for shared syslog-family rendering helpers."""

from datetime import UTC, datetime

from evidenceforge.generation.emitters.syslog_family import (
    make_syslog_family_route_key,
    render_rfc3164_syslog,
    rfc3164_timestamp_sort_key,
    sanitize_syslog_family_route_key,
    syslog_family_writer_path,
    syslog_priority,
)


def test_render_rfc3164_syslog_uses_bsd_timestamp_and_pid() -> None:
    line = render_rfc3164_syslog(
        pri=86,
        timestamp=datetime(2026, 3, 8, 12, 0, 1, tzinfo=UTC),
        hostname="linux-01",
        app_name="sshd",
        pid=1234,
        message="Accepted password for alice",
    )

    assert line == "<86>Mar  8 12:00:01 linux-01 sshd[1234]: Accepted password for alice"


def test_render_rfc3164_syslog_omits_empty_pid() -> None:
    line = render_rfc3164_syslog(
        pri=30,
        timestamp=datetime(2026, 3, 18, 12, 0, 1, tzinfo=UTC),
        hostname="linux-01",
        app_name="systemd",
        pid=None,
        message="Started service.",
    )

    assert line == "<30>Mar 18 12:00:01 linux-01 systemd: Started service."


def test_syslog_priority_clamps_facility_and_severity() -> None:
    assert syslog_priority(10, 6) == 86
    assert syslog_priority(99, 99) == 191


def test_year_route_key_writes_source_year_path(tmp_path) -> None:
    route_key = make_syslog_family_route_key(
        "fw01",
        datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        direct_file_mode=False,
    )
    safe_route_key = sanitize_syslog_family_route_key(route_key)
    path = syslog_family_writer_path(
        base_dir=tmp_path,
        safe_route_key=safe_route_key,
        log_filename="cisco_asa.log",
        direct_file_path=None,
        flat_filename="cisco_asa.log",
    )

    assert path == tmp_path / "fw01" / "2026" / "cisco_asa.log"


def test_rfc3164_timestamp_sort_key_handles_single_digit_day() -> None:
    assert rfc3164_timestamp_sort_key("<86>Mar  8 12:00:01 host app: one") < (
        rfc3164_timestamp_sort_key("<86>Mar 18 12:00:01 host app: two")
    )
