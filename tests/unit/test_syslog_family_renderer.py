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

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext, SyslogContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.syslog import (
    SyslogEmitter,
    _fallback_linux_uid,
    _linux_uid_collision_repaired,
)
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


def test_syslog_pam_uid_collision_repair_keeps_named_users_distinct() -> None:
    """Syslog-only PAM backfills should not alias named users to ubuntu(uid=1000)."""
    lines = [
        "<86>1 2024-03-18T12:00:00.000000Z host login 100 - - "
        "pam_unix(login:session): session opened for user ubuntu(uid=1000) by LOGIN(uid=0)",
        "<86>1 2024-03-18T12:00:01.000000Z host CRON 101 - - "
        "pam_unix(cron:session): session opened for user lina.nguyen(uid=1000) by (uid=0)",
    ]

    repaired = _linux_uid_collision_repaired(lines, "host")

    assert "ubuntu(uid=1000)" in repaired[0]
    assert "lina.nguyen(uid=1000)" not in repaired[1]
    assert "lina.nguyen(uid=" in repaired[1]
    assert _fallback_linux_uid("lina.nguyen") != 1000


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


def test_syslog_close_preserves_canonical_sshd_child_pids(tmp_path) -> None:
    """Source rendering must not rewrite canonical sshd process identities."""
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, threaded=False)
    host = HostContext(
        hostname="app",
        ip="10.0.2.10",
        os="Ubuntu 24.04",
        os_category="linux",
        system_type="server",
        fqdn="app.example",
    )
    rows = [
        (datetime(2024, 3, 18, 12, 37, 10, tzinfo=UTC), 839794, "10.0.1.10", 50000),
        (datetime(2024, 3, 18, 12, 45, 43, tzinfo=UTC), 838687, "10.0.1.11", 50001),
    ]
    for timestamp, pid, source_ip, source_port in rows:
        emitter.emit(
            SecurityEvent(
                timestamp=timestamp,
                event_type="syslog",
                src_host=host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=pid,
                    facility=10,
                    severity=6,
                    message=(
                        f"Connection from {source_ip} port {source_port} on 10.0.2.10 port 22"
                    ),
                ),
            )
        )
    emitter.close()

    lines = (tmp_path / "app.example" / "syslog.log").read_text().splitlines()
    pids = [int(line.split(" sshd ")[1].split(" ")[0]) for line in lines]
    assert pids == [839794, 838687]


def test_normalize_logind_session_ids_preserves_monotonic_canonical_ids() -> None:
    """Canonical SSH session IDs must survive syslog finalization for eCAR joins."""
    lines = [
        "<86>1 2024-03-18T13:23:51.023330Z DB-PROD-01 systemd-logind 29479 - - New session 18495 of user aisha.johnson.",
        "<86>1 2024-03-18T13:23:58.501845Z DB-PROD-01 systemd-logind 29479 - - New session 18505 of user aisha.johnson.",
        "<86>1 2024-03-18T13:33:52.571996Z DB-PROD-01 systemd-logind 29479 - - Removed session 18505.",
        "<86>1 2024-03-18T13:46:21.216183Z DB-PROD-01 systemd-logind 29479 - - Removed session 18495.",
    ]

    normalized = SyslogEmitter._normalize_logind_session_ids_for_lines(
        lines,
        "DB-PROD-01.meridianhcs.local",
    )

    assert normalized == lines


def test_normalize_logind_session_ids_repairs_backward_new_session() -> None:
    """Out-of-order generator paths still need final source-native monotonicity."""
    lines = [
        "<86>1 2024-03-18T12:04:40.000000Z linux01 systemd-logind 22523 - - New session 7616 of user root.",
        "<86>1 2024-03-18T12:10:09.000000Z linux01 systemd-logind 22523 - - New session 7608 of user admin.",
        "<86>1 2024-03-18T12:12:00.000000Z linux01 systemd-logind 22523 - - Removed session 7616.",
    ]

    normalized = SyslogEmitter._normalize_logind_session_ids_for_lines(
        lines,
        "linux01.example.test",
    )

    new_sessions = [
        int(line.split("New session ", 1)[1].split(" ", 1)[0])
        for line in normalized
        if "New session" in line
    ]
    removed_session = int(normalized[2].split("Removed session ", 1)[1].rstrip("."))
    assert new_sessions == sorted(new_sessions)
    assert new_sessions[0] == 7616
    assert new_sessions[1] > 7616
    assert removed_session == 7616


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
    assert any(" app login " in line for line in normalized if "pam_unix(" in line)
    assert not any("pam_unix(cron:session)" in line for line in normalized)


def test_backfill_missing_logind_pam_openers_never_labels_human_logind_as_cron() -> None:
    lines = [
        "<86>1 2024-03-18T15:06:10.442818Z WS-LNGUYEN-01 systemd-logind 33515 - - New session 20798 of user lina.nguyen.",
    ]

    normalized = SyslogEmitter._backfill_missing_logind_pam_openers_for_lines(
        lines,
        "WS-LNGUYEN-01.meridianhcs.local",
    )

    pam_line = next(line for line in normalized if "pam_unix(" in line)
    assert "pam_unix(login:session)" in pam_line
    assert " CRON " not in pam_line
    assert "pam_unix(cron:session)" not in pam_line


def test_backfill_missing_logind_pam_openers_ignores_future_openers() -> None:
    lines = [
        "<86>1 2024-03-18T12:00:45.000000Z app sudo 1234 - - pam_unix(sudo:session): session opened for user admin(uid=1001) by (uid=0)",
        "<86>1 2024-03-18T12:00:10.000000Z app systemd-logind 456 - - New session 42 of user admin.",
    ]

    normalized = SyslogEmitter._backfill_missing_logind_pam_openers_for_lines(
        lines,
        "app.example",
    )

    pam_openers = [line for line in normalized if "session opened for user admin(uid=1001)" in line]
    assert len(pam_openers) == 2


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


def test_normalize_sudo_session_lifecycles_preserves_non_rfc5424_order() -> None:
    lines = [
        "<86>Nov  1 00:00:00 host sudo[2001]: 2023-NOV sentinel",
        "<86>Apr  1 00:00:00 host sudo[2002]: 2024-APR sentinel",
    ]

    normalized = SyslogEmitter._normalize_sudo_session_lifecycles_for_lines(lines)

    assert normalized == lines
