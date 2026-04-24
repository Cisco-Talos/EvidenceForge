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

"""Tests for evaluation log parsers."""

from pathlib import Path

GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"


class TestWindowsEventParser:
    def test_parses_all_events(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))
        assert len(records) == 3

    def test_extracts_event_ids(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))
        event_ids = [r.fields["EventID"] for r in records]
        assert event_ids == [4624, 4688, 4634]

    def test_extracts_timestamps(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))
        assert all(r.timestamp is not None for r in records)
        assert records[0].timestamp.hour == 10
        assert records[0].timestamp.minute == 15

    def test_extracts_computer_name(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))
        assert all(r.fields["Computer"] == "WS-ANALYST-01" for r in records)

    def test_extracts_eventdata_fields(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))
        logon = records[0]
        assert logon.fields["TargetUserName"] == "jsmith"
        assert logon.fields["IpAddress"] == "10.0.10.50"
        assert logon.fields["LogonType"] == 3

    def test_no_parse_errors(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))
        assert all(len(r.parse_errors) == 0 for r in records)

    def test_rejects_doctype_and_entity_declarations(self, tmp_path):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        payload = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<!DOCTYPE foo [<!ENTITY xxe "boom">]>
<System><EventID>4624</EventID></System>
<EventData><Data Name="TargetUserName">&xxe;</Data></EventData>
</Event>
</Events>
"""
        path = tmp_path / "windows_event_security.xml"
        path.write_text(payload, encoding="utf-8")

        records = list(parser.parse_file(path))

        assert len(records) == 1
        assert records[0].fields == {}
        assert records[0].parse_errors
        assert "DOCTYPE and ENTITY declarations are not allowed" in records[0].parse_errors[0]

    def test_parse_file_streams_without_reading_full_content(self, monkeypatch):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()

        def _fail_read_text(*_args, **_kwargs):
            raise AssertionError("parse_file should not call Path.read_text()")

        monkeypatch.setattr(Path, "read_text", _fail_read_text)

        records = list(parser.parse_file(GOOD_FIXTURES / "windows_event_security.xml"))

        assert len(records) == 3

    def test_can_parse_correct_file(self):
        from evidenceforge.evaluation.parsers.windows import WindowsEventParser

        parser = WindowsEventParser()
        assert parser.can_parse(Path("windows_event_security.xml"))
        assert not parser.can_parse(Path("zeek_conn.json"))


class TestZeekConnParser:
    def test_parses_all_records(self):
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))
        assert len(records) == 3

    def test_extracts_fields(self):
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))
        first = records[0]
        assert first.fields["id.orig_h"] == "10.0.10.50"
        assert first.fields["id.resp_p"] == 443
        assert first.fields["proto"] == "tcp"
        assert first.fields["conn_state"] == "SF"

    def test_extracts_timestamps(self):
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))
        assert all(r.timestamp is not None for r in records)

    def test_no_parse_errors(self):
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))
        assert all(len(r.parse_errors) == 0 for r in records)


class TestEcarParser:
    def test_parses_all_records(self):
        from evidenceforge.evaluation.parsers.ecar import EcarParser

        parser = EcarParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "ecar.json"))
        assert len(records) == 3

    def test_flattens_properties(self):
        from evidenceforge.evaluation.parsers.ecar import EcarParser

        parser = EcarParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "ecar.json"))
        process = records[0]
        assert process.fields["object"] == "PROCESS"
        assert process.fields["command_line"] == "cmd.exe /c ipconfig"
        assert process.fields["image_path"] == "C:\\Windows\\System32\\cmd.exe"

    def test_extracts_timestamps(self):
        from evidenceforge.evaluation.parsers.ecar import EcarParser

        parser = EcarParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "ecar.json"))
        assert all(r.timestamp is not None for r in records)


class TestSyslogParser:
    def test_parses_all_lines(self):
        from evidenceforge.evaluation.parsers.syslog import SyslogParser

        parser = SyslogParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "syslog.log"))
        assert len(records) == 3

    def test_extracts_fields(self):
        from evidenceforge.evaluation.parsers.syslog import SyslogParser

        parser = SyslogParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "syslog.log"))
        first = records[0]
        assert first.fields["hostname"] == "SRV-WEB-01"
        assert first.fields["app_name"] == "sshd"
        assert first.fields["pid"] == 12345
        assert "Accepted publickey" in first.fields["message"]

    def test_extracts_timestamps(self):
        from evidenceforge.evaluation.parsers.syslog import SyslogParser

        parser = SyslogParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "syslog.log"))
        assert all(r.timestamp is not None for r in records)


class TestSnortAlertParser:
    def test_parses_all_alerts(self):
        from evidenceforge.evaluation.parsers.snort import SnortAlertParser

        parser = SnortAlertParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "snort_alert.alert"))
        assert len(records) == 2

    def test_extracts_fields(self):
        from evidenceforge.evaluation.parsers.snort import SnortAlertParser

        parser = SnortAlertParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "snort_alert.alert"))
        first = records[0]
        assert first.fields["sid"] == 2013382
        assert first.fields["priority"] == 1
        assert first.fields["protocol"] == "TCP"
        assert first.fields["src_ip"] == "203.0.113.50"
        assert first.fields["src_port"] == 443
        assert first.fields["dst_ip"] == "10.0.10.50"
        assert first.fields["dst_port"] == 54321


class TestWebAccessParser:
    def test_parses_all_lines(self):
        from evidenceforge.evaluation.parsers.web import WebAccessParser

        parser = WebAccessParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "web_access.log"))
        assert len(records) == 3

    def test_extracts_fields(self):
        from evidenceforge.evaluation.parsers.web import WebAccessParser

        parser = WebAccessParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "web_access.log"))
        first = records[0]
        assert first.fields["client_ip"] == "10.0.10.50"
        assert first.fields["username"] == "jsmith"
        assert first.fields["method"] == "GET"
        assert first.fields["path"] == "/dashboard"
        assert first.fields["status_code"] == 200

    def test_handles_missing_username(self):
        from evidenceforge.evaluation.parsers.web import WebAccessParser

        parser = WebAccessParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "web_access.log"))
        second = records[1]
        assert "username" not in second.fields  # "-" is excluded

    def test_extracts_timestamps(self):
        from evidenceforge.evaluation.parsers.web import WebAccessParser

        parser = WebAccessParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "web_access.log"))
        assert all(r.timestamp is not None for r in records)


class TestBashHistoryParser:
    def test_parses_all_commands(self):
        from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser

        parser = BashHistoryParser()
        history_file = GOOD_FIXTURES / "bash_history" / "SRV-WEB-01" / "admin.history"
        records = list(parser.parse_file(history_file))
        assert len(records) == 3

    def test_extracts_metadata_from_path(self):
        from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser

        parser = BashHistoryParser()
        history_file = GOOD_FIXTURES / "bash_history" / "SRV-WEB-01" / "admin.history"
        records = list(parser.parse_file(history_file))
        assert all(r.fields["hostname"] == "SRV-WEB-01" for r in records)
        assert all(r.fields["username"] == "admin" for r in records)

    def test_extracts_commands(self):
        from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser

        parser = BashHistoryParser()
        history_file = GOOD_FIXTURES / "bash_history" / "SRV-WEB-01" / "admin.history"
        records = list(parser.parse_file(history_file))
        commands = [r.fields["command"] for r in records]
        assert "whoami" in commands
        assert "ls -la /var/log" in commands

    def test_extracts_timestamps(self):
        from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser

        parser = BashHistoryParser()
        history_file = GOOD_FIXTURES / "bash_history" / "SRV-WEB-01" / "admin.history"
        records = list(parser.parse_file(history_file))
        assert all(r.timestamp is not None for r in records)


class TestParserDiscovery:
    def test_discovers_all_formats_in_good_fixtures(self):
        from evidenceforge.evaluation.parsers import discover_log_files

        files = discover_log_files(GOOD_FIXTURES)
        assert "windows_event_security" in files
        assert "zeek_conn" in files
        assert "ecar" in files
        assert "syslog" in files
        assert "snort_alert" in files
        assert "web_access" in files
        assert "bash_history" in files

    def test_skips_symlinked_sensor_directories(self, tmp_path):
        """Symlinked subdirectories should be skipped during discovery."""
        from evidenceforge.evaluation.parsers import discover_log_files

        # Create a real file inside the output dir
        safe_conn = tmp_path / "zeek_conn.json"
        safe_conn.write_text('{"ts": 1.0}\n', encoding="utf-8")

        # Create an outside directory and symlink it in
        outside_dir = tmp_path.parent / "outside_sensor"
        outside_dir.mkdir(exist_ok=True)
        (outside_dir / "conn.json").write_text('{"ts": 2.0}\n', encoding="utf-8")

        sensor_link = tmp_path / "zeek-fw01"
        try:
            sensor_link.symlink_to(outside_dir, target_is_directory=True)
        except OSError:
            return  # symlinks not supported on this platform

        files = discover_log_files(tmp_path)
        all_paths = [p for paths in files.values() for p in paths]
        assert all(p.resolve().is_relative_to(tmp_path.resolve()) for p in all_paths)

    def test_skips_symlinked_top_level_files(self, tmp_path):
        """Symlinked files at the top level should be skipped."""
        from evidenceforge.evaluation.parsers import discover_log_files

        outside_file = tmp_path.parent / "outside_conn.json"
        outside_file.write_text('{"ts": 3.0}\n', encoding="utf-8")

        linked_file = tmp_path / "zeek_conn.json"
        try:
            linked_file.symlink_to(outside_file)
        except OSError:
            return  # symlinks not supported on this platform

        files = discover_log_files(tmp_path)
        assert "zeek_conn" not in files

    def test_all_parsers_registered(self):
        from evidenceforge.evaluation.parsers import _PARSER_CLASSES

        # 7 original + 12 new Zeek parsers + cisco_asa + proxy_access
        assert len(_PARSER_CLASSES) == 21
