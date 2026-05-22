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

from evidenceforge.generation.emitters.syslog import SyslogEmitter
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


def test_normalize_sshd_child_pids_preserves_session_mapping_and_monotonicity() -> None:
    lines = [
        "<86>1 2024-03-18T12:37:10.283139Z app sshd 839794 - - Connection from 10.0.1.10 port 50000 on 10.0.2.10 port 22",
        "<86>1 2024-03-18T12:37:11.001000Z app sshd 839794 - - Accepted password for admin from 10.0.1.10 port 50000 ssh2",
        "<86>1 2024-03-18T12:45:43.059582Z app sshd 838687 - - Connection from 10.0.1.11 port 50001 on 10.0.2.10 port 22",
        "<86>1 2024-03-18T12:45:44.100000Z app sshd 838687 - - Accepted password for admin from 10.0.1.11 port 50001 ssh2",
    ]

    normalized = SyslogEmitter._normalize_sshd_child_pids_for_lines(lines, "app.example")

    pids = [int(line.split(" sshd ")[1].split(" ")[0]) for line in normalized]
    assert pids[0] == pids[1]
    assert pids[2] == pids[3]
    assert pids[2] > pids[0]


def test_normalize_sshd_child_pids_does_not_let_orphan_closes_rewrite_session_open() -> None:
    lines = [
        "<86>1 2024-03-18T15:51:34.963802Z app sshd 784323 - - Connection from 10.0.1.33 port 63690 on 10.0.2.10 port 22",
        "<86>1 2024-03-18T15:51:35.491983Z app sshd 784323 - - Accepted publickey for user from 10.0.1.33 port 63690 ssh2",
        "<86>1 2024-03-18T15:52:24.705921Z app sshd 784329 - - pam_unix(sshd:session): session closed for user other",
        "<86>1 2024-03-18T15:54:22.189035Z app sshd 784327 - - Connection from 10.0.1.31 port 63843 on 10.0.2.10 port 22",
        "<86>1 2024-03-18T15:54:23.876283Z app sshd 784327 - - Accepted password for user from 10.0.1.31 port 63843 ssh2",
    ]

    normalized = SyslogEmitter._normalize_sshd_child_pids_for_lines(lines, "app.example")

    pids = [int(line.split(" sshd ")[1].split(" ")[0]) for line in normalized]
    assert pids == [784323, 784323, 784329, 784327, 784327]


def test_backfill_missing_logind_pam_openers_adds_native_opener() -> None:
    lines = [
        "<30>1 2024-03-18T12:00:00.000000Z app unattended-upgr 100 - - Packages checked",
        "<86>1 2024-03-18T12:00:10.000000Z app systemd-logind 456 - - New session 42 of user ubuntu.",
    ]

    normalized = SyslogEmitter._backfill_missing_logind_pam_openers_for_lines(
        lines,
        "app.example",
    )

    assert len(normalized) == 3
    assert any(
        "pam_unix(" in line and "session opened for user ubuntu(uid=1000)" in line
        for line in normalized
    )
    pam_index = next(i for i, line in enumerate(normalized) if "pam_unix(" in line)
    logind_index = next(i for i, line in enumerate(normalized) if "systemd-logind" in line)
    assert pam_index < logind_index


def test_backfill_missing_logind_pam_openers_preserves_existing_opener() -> None:
    lines = [
        "<86>1 2024-03-18T12:00:05.000000Z app login 1234 - - pam_unix(login:session): session opened for user admin(uid=1001) by LOGIN(uid=0)",
        "<86>1 2024-03-18T12:00:10.000000Z app systemd-logind 456 - - New session 42 of user admin.",
    ]

    normalized = SyslogEmitter._backfill_missing_logind_pam_openers_for_lines(
        lines,
        "app.example",
    )

    assert normalized == lines


def test_normalize_sshd_child_pids_skips_oversized_pid_without_crashing() -> None:
    huge_pid = "9" * 5000
    lines = [
        f"<86>1 2024-03-18T12:37:10.283139Z app sshd {huge_pid} - - Connection from 10.0.1.10 port 50000 on 10.0.2.10 port 22",
        "<86>1 2024-03-18T12:37:11.001000Z app sshd 100 - - Accepted password for admin from 10.0.1.10 port 50000 ssh2",
    ]

    normalized = SyslogEmitter._normalize_sshd_child_pids_for_lines(lines, "app.example")

    assert normalized[0] == lines[0]
    assert " sshd 100 " in normalized[1]
