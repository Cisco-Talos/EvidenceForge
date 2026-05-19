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

"""Focused renderer/layout tests for output targets."""

from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.syslog import SyslogEmitter


def test_default_syslog_target_writes_rfc5424_flat_host_file(tmp_path: Path) -> None:
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.configure_output_target("default")

    emitter.emit_raw(_syslog_event())
    emitter.close()

    output_path = tmp_path / "linux01.example.test" / "syslog.log"
    assert output_path.exists()
    assert not (tmp_path / "linux01.example.test" / "2026" / "syslog.log").exists()
    assert output_path.read_text(encoding="utf-8").startswith(
        "<86>1 2026-06-15T14:23:05Z linux01 sshd 1234 - - Accepted password"
    )


def test_sof_elk_syslog_target_writes_rfc3164_year_partitioned_file(tmp_path: Path) -> None:
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.configure_output_target("sof-elk")

    emitter.emit_raw(_syslog_event())
    emitter.close()

    output_path = tmp_path / "linux01.example.test" / "2026" / "syslog.log"
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8").startswith(
        "<86>Jun 15 14:23:05 linux01 sshd[1234]: Accepted password"
    )


def test_default_cisco_asa_target_writes_flat_sensor_file(tmp_path: Path) -> None:
    emitter = CiscoAsaEmitter(
        load_format("cisco_asa"),
        tmp_path,
        sensor_hostnames=["fw01"],
    )
    emitter.configure_output_target("default")

    emitter.emit_event(_asa_event())
    emitter.close()

    output_path = tmp_path / "fw01" / "cisco_asa.log"
    assert output_path.exists()
    assert not (tmp_path / "fw01" / "2026" / "cisco_asa.log").exists()
    assert "%ASA-6-302013: Built outbound TCP connection 7" in output_path.read_text(
        encoding="utf-8"
    )


def test_sof_elk_cisco_asa_target_writes_year_partitioned_sensor_file(tmp_path: Path) -> None:
    emitter = CiscoAsaEmitter(
        load_format("cisco_asa"),
        tmp_path,
        sensor_hostnames=["fw01"],
    )
    emitter.configure_output_target("sof-elk")

    emitter.emit_event(_asa_event())
    emitter.close()

    output_path = tmp_path / "fw01" / "2026" / "cisco_asa.log"
    assert output_path.exists()
    assert "%ASA-6-302013: Built outbound TCP connection 7" in output_path.read_text(
        encoding="utf-8"
    )


def _syslog_event() -> dict[str, object]:
    return {
        "timestamp": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "hostname": "linux01",
        "app_name": "sshd",
        "pid": 1234,
        "facility": 10,
        "severity": 6,
        "message": "Accepted password for alice from 198.51.100.25 port 54321 ssh2",
        "_host_fqdn": "linux01.example.test",
    }


def _asa_event() -> dict[str, object]:
    return {
        "timestamp": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "hostname": "fw01",
        "severity": 6,
        "msg_id": 302013,
        "message": "Built outbound TCP connection 7 for inside:10.0.10.5/54321 "
        "to outside:198.51.100.10/443",
        "pri": 166,
        "_sensor_hostnames": ["fw01"],
    }
