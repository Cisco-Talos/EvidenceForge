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
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter


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


def test_splunk_syslog_target_uses_default_rfc5424_flat_host_file(tmp_path: Path) -> None:
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)
    emitter.configure_output_target("splunk")

    emitter.emit_raw(_syslog_event())
    emitter.close()

    output_path = tmp_path / "linux01.example.test" / "syslog.log"
    assert output_path.exists()
    assert not (tmp_path / "linux01.example.test" / "2026" / "syslog.log").exists()
    assert output_path.read_text(encoding="utf-8").startswith(
        "<86>1 2026-06-15T14:23:05Z linux01 sshd 1234 - - Accepted password"
    )


def test_host_scoped_emitter_without_host_writes_no_root_file(tmp_path: Path) -> None:
    emitter = SyslogEmitter(load_format("syslog"), tmp_path, buffer_size=10)

    event = dict(_syslog_event())
    event.pop("_host_fqdn")
    emitter.emit_event(event)
    emitter.close()

    assert not (tmp_path / "syslog.log").exists()
    assert not list(tmp_path.rglob("*.log"))


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


def test_firewall_sensor_emitter_without_sensor_writes_no_root_file(tmp_path: Path) -> None:
    emitter = CiscoAsaEmitter(load_format("cisco_asa"), tmp_path)

    event = dict(_asa_event())
    event.pop("_sensor_hostnames")
    emitter.emit_event(event)
    emitter.close()

    assert not (tmp_path / "cisco_asa.log").exists()
    assert not list(tmp_path.rglob("*.log"))


def test_ids_sensor_emitter_without_sensor_writes_no_root_file(tmp_path: Path) -> None:
    emitter = SnortEmitter(load_format("snort_alert"), tmp_path)

    emitter.emit_event(_snort_event())
    emitter.close()

    assert not (tmp_path / "snort_alert.log").exists()
    assert not list(tmp_path.rglob("*.log"))


def test_splunk_cisco_asa_target_keeps_flat_native_asa_syslog(tmp_path: Path) -> None:
    emitter = CiscoAsaEmitter(
        load_format("cisco_asa"),
        tmp_path,
        sensor_hostnames=["fw01"],
    )
    emitter.configure_output_target("splunk")

    emitter.emit_event(_asa_event())
    emitter.close()

    output_path = tmp_path / "fw01" / "cisco_asa.log"
    assert output_path.exists()
    assert not (tmp_path / "fw01" / "2026" / "cisco_asa.log").exists()
    assert "%ASA-6-302013: Built outbound TCP connection 7" in output_path.read_text(
        encoding="utf-8"
    )


def test_zeek_directory_target_without_sensors_writes_no_log(tmp_path: Path) -> None:
    emitter = ZeekEmitter(load_format("zeek_conn"), tmp_path, buffer_size=10)

    emitter.emit_event(_zeek_conn_event())
    emitter.close()

    assert not (tmp_path / "conn.json").exists()
    assert not (tmp_path / "zeek_conn.json").exists()
    assert not list(tmp_path.rglob("*.json"))


def test_windows_security_without_host_writes_no_root_file(tmp_path: Path) -> None:
    emitter = WindowsEventEmitter(load_format("windows_event_security"), tmp_path, buffer_size=10)

    event = dict(_security_log_clear_event())
    event.pop("Computer")
    emitter.emit_event(event)
    emitter.close()

    assert not (tmp_path / "windows_event_security.xml").exists()
    assert not list(tmp_path.rglob("*.xml"))


def test_sysmon_without_host_writes_no_root_file(tmp_path: Path) -> None:
    emitter = SysmonEventEmitter(load_format("windows_event_sysmon"), tmp_path, buffer_size=10)

    event = dict(_sysmon_terminate_event())
    event.pop("Computer")
    emitter.emit_event(event)
    emitter.close()

    assert not (tmp_path / "windows_event_sysmon.xml").exists()
    assert not list(tmp_path.rglob("*.xml"))


def test_splunk_windows_security_target_writes_line_delimited_xml_events(
    tmp_path: Path,
) -> None:
    emitter = WindowsEventEmitter(load_format("windows_event_security"), tmp_path, buffer_size=10)
    emitter.configure_output_target("splunk")

    emitter.emit_event(_security_log_clear_event())
    emitter.close()

    output_path = tmp_path / "win01.example.test" / "windows_event_security.xml"
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("<Event ")
    assert "<Events>" not in lines[0]
    assert "</Events>" not in lines[0]
    assert "<EventID>1102</EventID>" in lines[0]


def test_splunk_sysmon_target_writes_line_delimited_xml_events(tmp_path: Path) -> None:
    emitter = SysmonEventEmitter(load_format("windows_event_sysmon"), tmp_path, buffer_size=10)
    emitter.configure_output_target("splunk")

    emitter.emit_event(_sysmon_terminate_event())
    emitter.close()

    output_path = tmp_path / "win01.example.test" / "windows_event_sysmon.xml"
    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("<Event ")
    assert "<Events>" not in lines[0]
    assert "</Events>" not in lines[0]
    assert "<EventID>5</EventID>" in lines[0]


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


def _security_log_clear_event() -> dict[str, object]:
    return {
        "EventID": 1102,
        "TimeCreated": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "Computer": "win01.example.test",
        "Channel": "Security",
        "Level": 4,
        "ExecutionProcessID": 772,
        "ExecutionThreadID": 1148,
        "SubjectUserSid": "S-1-5-21-111-222-333-500",
        "SubjectUserName": "alice",
        "SubjectDomainName": "EXAMPLE",
        "SubjectLogonId": "0x1234",
    }


def _zeek_conn_event() -> dict[str, object]:
    return {
        "ts": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "uid": "C1",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 49152,
        "id.resp_h": "198.51.100.10",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.234,
        "orig_bytes": 512,
        "resp_bytes": 4096,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADadfF",
        "orig_pkts": 10,
        "orig_ip_bytes": 1024,
        "resp_pkts": 8,
        "resp_ip_bytes": 8192,
        "ip_proto": 6,
    }


def _sysmon_terminate_event() -> dict[str, object]:
    return {
        "EventID": 5,
        "TimeCreated": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "UtcTime": "2026-06-15 14:23:05.000",
        "Computer": "win01.example.test",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "ExecutionProcessID": 3900,
        "ExecutionThreadID": 3904,
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": 4242,
        "Image": r"C:\Windows\System32\cmd.exe",
        "User": r"EXAMPLE\alice",
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


def _snort_event() -> dict[str, object]:
    return {
        "timestamp": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "gid": 1,
        "sid": 1000001,
        "rev": 1,
        "message": "Synthetic IDS alert",
        "classification": "attempted-recon",
        "priority": 2,
        "protocol": "TCP",
        "src_ip": "198.51.100.25",
        "src_port": 44444,
        "dst_ip": "10.0.0.5",
        "dst_port": 443,
    }
