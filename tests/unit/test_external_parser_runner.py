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

"""Tests for external parser runner discovery."""

from __future__ import annotations

from pathlib import Path

from evidenceforge.external_parsers.runner import (
    SOF_ELK_CISCO_ASA_VALIDATOR,
    SOF_ELK_SYSLOG_VALIDATOR,
    SOF_ELK_WEB_ACCESS_VALIDATOR,
    SOF_ELK_ZEEK_VALIDATOR,
    detect_external_parser_plan,
    group_logs_for_progress,
    unsupported_summary,
)


def test_detect_external_parser_plan_selects_zeek_validator_and_warns_unsupported(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "sensor-a").mkdir(parents=True)
    (data_dir / "sensor-a" / "conn.json").write_text("{}\n", encoding="utf-8")
    (data_dir / "sensor-a" / "http.json").write_text("{}\n", encoding="utf-8")
    (data_dir / "win-01.example.test").mkdir()
    (data_dir / "win-01.example.test" / "windows_event_security.xml").write_text(
        "<Events />\n",
        encoding="utf-8",
    )
    (data_dir / "linux-01.example.test" / "bash_history").mkdir(parents=True)
    (data_dir / "linux-01.example.test" / "2026").mkdir(parents=True)
    (data_dir / "linux-01.example.test" / "bash_history" / "alice.bash_history").write_text(
        "whoami\n",
        encoding="utf-8",
    )
    (data_dir / "fw-01.example.test" / "2026").mkdir(parents=True)
    (data_dir / "fw-01.example.test" / "2026" / "cisco_asa.log").write_text(
        "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7 "
        "for inside:10.0.10.5/54321 to outside:198.51.100.10/443\n",
        encoding="utf-8",
    )
    (data_dir / "web-01.example.test").mkdir()
    (data_dir / "web-01.example.test" / "web_access.log").write_text(
        '198.51.100.25 - - [15/Jun/2026:14:23:05 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    (data_dir / "linux-01.example.test" / "2026" / "syslog.log").write_text(
        "<30>Jun 15 14:23:05 linux-01 sshd[1234]: Accepted password for alice "
        "from 198.51.100.25 port 54321 ssh2\n",
        encoding="utf-8",
    )

    plan = detect_external_parser_plan(data_dir)

    assert plan.validators == (
        SOF_ELK_ZEEK_VALIDATOR,
        SOF_ELK_CISCO_ASA_VALIDATOR,
        SOF_ELK_WEB_ACCESS_VALIDATOR,
        SOF_ELK_SYSLOG_VALIDATOR,
    )
    assert {(log.logtype, log.subtype) for log in plan.supported_logs} == {
        ("firewall", "cisco_asa"),
        ("syslog", "linux"),
        ("web", "access"),
        ("zeek", "conn"),
        ("zeek", "http"),
    }
    assert unsupported_summary(plan.unsupported_logs) == {
        "bash history": ["bash_history"],
        "windows events": ["security"],
    }


def test_group_logs_for_progress_uses_host_logtype_subtype_levels(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    (data_dir / "sensor-a").mkdir(parents=True)
    (data_dir / "sensor-a" / "dns.json").write_text("{}\n", encoding="utf-8")
    (data_dir / "sensor-a" / "ssl.json").write_text("{}\n", encoding="utf-8")
    (data_dir / "sensor-b").mkdir()
    (data_dir / "sensor-b" / "dns.json").write_text("{}\n", encoding="utf-8")

    plan = detect_external_parser_plan(data_dir)
    grouped = group_logs_for_progress(plan.logs)

    assert set(grouped) == {"sensor-a", "sensor-b"}
    assert set(grouped["sensor-a"]) == {"zeek"}
    assert set(grouped["sensor-a"]["zeek"]) == {"dns", "ssl"}
    assert set(grouped["sensor-b"]["zeek"]) == {"dns"}


def test_detect_external_parser_plan_reports_unknown_log_files(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "mystery.log").write_text("hello\n", encoding="utf-8")

    plan = detect_external_parser_plan(data_dir)

    assert plan.validators == ()
    assert unsupported_summary(plan.unsupported_logs) == {"unknown": ["mystery.log"]}
