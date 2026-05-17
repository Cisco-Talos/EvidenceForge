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

"""Tests for non-Zeek SOF-ELK external parser harnesses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidenceforge.external_parsers.sof_elk_sources import (
    CISCO_ASA_SPEC,
    EVENTS_OUTPUT_FILENAME,
    SYSLOG_SPEC,
    WEB_ACCESS_SPEC,
    WINDOWS_SECURITY_SNARE_SPEC,
    WINDOWS_SYSMON_SNARE_SPEC,
    SofElkSourceManifest,
    SofElkSourceSpec,
    StagedSourceLog,
    build_sof_elk_source_configs,
    stage_source_logs,
    validate_source_parsed_output,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_REPORT_FILENAME,
    SofElkParserError,
)


def test_stage_source_logs_preserves_sensor_subdirectories(tmp_path: Path) -> None:
    source_root = tmp_path / "generated"
    source_dir = source_root / "fw-01.example.test" / "2026"
    source_dir.mkdir(parents=True)
    (source_dir / "cisco_asa.log").write_text(
        "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7 "
        "for inside:10.0.10.5/54321 to outside:198.51.100.10/443\n",
        encoding="utf-8",
    )

    manifest = stage_source_logs(source_root, tmp_path / "stage", CISCO_ASA_SPEC)

    assert manifest.expected_counts == {"cisco_asa": 1}
    assert {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs} == {
        Path("syslog/2026/fw-01.example.test/cisco_asa.log")
    }


def test_stage_source_logs_preserves_web_access_subdirectories(tmp_path: Path) -> None:
    source_root = tmp_path / "generated"
    source_dir = source_root / "web-01.example.test"
    source_dir.mkdir(parents=True)
    (source_dir / "web_access.log").write_text(
        '198.51.100.25 - - [15/Jun/2026:14:23:05 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )

    manifest = stage_source_logs(source_root, tmp_path / "stage", WEB_ACCESS_SPEC)

    assert manifest.expected_counts == {"web_access": 1}
    assert {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs} == {
        Path("httpd/web-01.example.test/web_access.log")
    }


def test_stage_source_logs_preserves_syslog_subdirectories(tmp_path: Path) -> None:
    source_root = tmp_path / "generated"
    source_dir = source_root / "linux-01.example.test" / "2026"
    source_dir.mkdir(parents=True)
    (source_dir / "syslog.log").write_text(
        "<30>Jun 15 14:23:05 linux-01 sshd[1234]: Accepted password for alice "
        "from 198.51.100.25 port 54321 ssh2\n",
        encoding="utf-8",
    )

    manifest = stage_source_logs(source_root, tmp_path / "stage", SYSLOG_SPEC)

    assert manifest.expected_counts == {"syslog": 1}
    assert {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs} == {
        Path("syslog/2026/linux-01.example.test/syslog.log")
    }


def test_stage_source_logs_preserves_windows_snare_year_subdirectories(tmp_path: Path) -> None:
    source_root = tmp_path / "generated"
    source_dir = source_root / "win-01.example.test" / "2026"
    source_dir.mkdir(parents=True)
    (source_dir / "windows_event_security_snare.log").write_text(
        "<86>Jun 15 14:23:05 win-01.example.test win-01.example.test\tMSWinEventLog\t"
        "0\tSecurity\t100\tMon Jun 15 14:23:05 2026\t4624\t"
        "Microsoft-Windows-Security-Auditing\talice\tN/A\tSuccess Audit\t"
        "win-01.example.test\tLogon\tAn account was successfully logged on.:  "
        "Account Name: alice  \n",
        encoding="utf-8",
    )

    manifest = stage_source_logs(source_root, tmp_path / "stage", WINDOWS_SECURITY_SNARE_SPEC)

    assert manifest.expected_counts == {"windows_event_security_snare": 1}
    assert {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs} == {
        Path("syslog/2026/win-01.example.test/windows_event_security_snare.log")
    }


def test_build_sof_elk_source_configs_requests_sof_elk_syslog_input(tmp_path: Path) -> None:
    config = build_sof_elk_source_configs(tmp_path, CISCO_ASA_SPEC)

    assert "/runtime-config/filebeat-inputs/*.yml" in config.filebeat_config.read_text(
        encoding="utf-8"
    )
    assert config.sof_elk_filebeat_inputs == ("syslog.yml",)
    assert not (config.filebeat_inputs_dir / "syslog.yml").exists()
    assert 'copy => { "message" => "[event][original]" }' in (
        config.pipeline_dir / "0001-capture-original.conf"
    ).read_text(encoding="utf-8")
    assert f"/parsed-output/{EVENTS_OUTPUT_FILENAME}" in (
        config.pipeline_dir / "9999-output-jsonl.conf"
    ).read_text(encoding="utf-8")
    assert config.sof_elk_filter_files == CISCO_ASA_SPEC.filter_files
    for filter_file in CISCO_ASA_SPEC.filter_files:
        assert not (config.pipeline_dir / filter_file).exists()


def test_build_sof_elk_source_configs_requests_sof_elk_syslog_filters(tmp_path: Path) -> None:
    config = build_sof_elk_source_configs(tmp_path, SYSLOG_SPEC)

    assert config.sof_elk_filebeat_inputs == ("syslog.yml",)
    assert config.sof_elk_filter_files == SYSLOG_SPEC.filter_files
    assert not (config.filebeat_inputs_dir / "syslog.yml").exists()
    for filter_file in SYSLOG_SPEC.filter_files:
        assert not (config.pipeline_dir / filter_file).exists()


def test_build_sof_elk_source_configs_requests_sof_elk_snare_filters(tmp_path: Path) -> None:
    config = build_sof_elk_source_configs(tmp_path, WINDOWS_SYSMON_SNARE_SPEC)

    assert config.sof_elk_filebeat_inputs == ("syslog.yml",)
    assert "1010-preprocess-snare.conf" in config.sof_elk_filter_files
    assert "6010-snare.conf" in config.sof_elk_filter_files
    for filter_file in WINDOWS_SYSMON_SNARE_SPEC.filter_files:
        assert not (config.pipeline_dir / filter_file).exists()


def test_build_sof_elk_source_configs_requests_sof_elk_httpdlog_input(tmp_path: Path) -> None:
    config = build_sof_elk_source_configs(tmp_path, WEB_ACCESS_SPEC)

    assert config.sof_elk_filebeat_inputs == ("httpdlog.yml",)
    assert not (config.filebeat_inputs_dir / "httpdlog.yml").exists()
    assert config.sof_elk_filter_files == WEB_ACCESS_SPEC.filter_files
    for filter_file in WEB_ACCESS_SPEC.filter_files:
        assert not (config.pipeline_dir / filter_file).exists()


def test_validate_source_parsed_output_accepts_cisco_asa_parse(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        CISCO_ASA_SPEC,
        Path("syslog/2026/fw-01/cisco_asa.log"),
        "cisco_asa.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_cisco_asa_event()
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    events = validate_source_parsed_output(manifest, parsed_dir)

    assert len(events) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_source_parsed_output_reports_cisco_asa_parser_context(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path,
        CISCO_ASA_SPEC,
        Path("syslog/2026/fw-01/cisco_asa.log"),
        "cisco_asa.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_cisco_asa_event()
    event["tags"] = ["filebeat", "_grokparsefail_6018-01"]
    event["message"] = "not a real ASA message"
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    with pytest.raises(SofElkParserError, match="_grokparsefail_6018-01"):
        validate_source_parsed_output(manifest, parsed_dir)

    report = json.loads((parsed_dir / FAILURE_REPORT_FILENAME).read_text(encoding="utf-8"))
    assert report["failure_tag_counts"]["cisco_asa"]["_grokparsefail_6018-01"] == 1
    sample = report["sample_failures"][0]
    assert sample["event_original"].startswith("<166>Jun 15")
    assert sample["message"] == "not a real ASA message"
    assert sample["log_file_path"] == "/logstash/syslog/2026/fw-01/cisco_asa.log"


def test_validate_source_parsed_output_accepts_web_access_parse(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        WEB_ACCESS_SPEC,
        Path("httpd/web-01/web_access.log"),
        "web_access.log",
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_web_access_event()
    tags = event["tags"]
    assert isinstance(tags, list)
    tags.append("_grokparsefail_8110-01")
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    events = validate_source_parsed_output(manifest, parsed_dir)

    assert len(events) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_source_parsed_output_reports_web_access_parser_context(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path,
        WEB_ACCESS_SPEC,
        Path("httpd/web-01/web_access.log"),
        "web_access.log",
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_web_access_event()
    event["tags"] = ["filebeat", "_grokparsefailure_6100-01"]
    event["message"] = "not a real access log"
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    with pytest.raises(SofElkParserError, match="_grokparsefailure_6100-01"):
        validate_source_parsed_output(manifest, parsed_dir)

    report = json.loads((parsed_dir / FAILURE_REPORT_FILENAME).read_text(encoding="utf-8"))
    assert report["failure_tag_counts"]["web_access"]["_grokparsefailure_6100-01"] == 1
    sample = report["sample_failures"][0]
    assert sample["event_original"].startswith("198.51.100.25")
    assert sample["message"] == "not a real access log"
    assert sample["log_file_path"] == "/logstash/httpd/web-01/web_access.log"


def test_validate_source_parsed_output_accepts_syslog_parse(tmp_path: Path) -> None:
    manifest = _manifest(
        tmp_path,
        SYSLOG_SPEC,
        Path("syslog/2026/linux-01/syslog.log"),
        "syslog.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_syslog_event()
    tags = event["tags"]
    assert isinstance(tags, list)
    tags.append("_grokparsefail_6018-01")
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    events = validate_source_parsed_output(manifest, parsed_dir)

    assert len(events) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_source_parsed_output_reports_syslog_parser_context(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path,
        SYSLOG_SPEC,
        Path("syslog/2026/linux-01/syslog.log"),
        "syslog.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_syslog_event()
    event["tags"] = ["filebeat", "_grokparsefailure_1100-01"]
    event["message"] = "not a parsed syslog row"
    log = event["log"]
    assert isinstance(log, dict)
    del log["syslog"]
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    with pytest.raises(SofElkParserError, match="_grokparsefailure_1100-01"):
        validate_source_parsed_output(manifest, parsed_dir)

    report = json.loads((parsed_dir / FAILURE_REPORT_FILENAME).read_text(encoding="utf-8"))
    assert report["failure_tag_counts"]["syslog"]["_grokparsefailure_1100-01"] == 1
    sample = report["sample_failures"][0]
    assert sample["event_original"].startswith("<30>Jun 15")
    assert sample["message"] == "not a parsed syslog row"
    assert sample["log_file_path"] == "/logstash/syslog/2026/linux-01/syslog.log"


def test_validate_source_parsed_output_accepts_windows_security_snare_parse(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path,
        WINDOWS_SECURITY_SNARE_SPEC,
        Path("syslog/2026/win-01/windows_event_security_snare.log"),
        "windows_event_security_snare.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_windows_snare_event(
        path="/logstash/syslog/2026/win-01/windows_event_security_snare.log",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_id=4624,
    )
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    events = validate_source_parsed_output(manifest, parsed_dir)

    assert len(events) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_source_parsed_output_accepts_optional_windows_snare_enrichment_tag(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path,
        WINDOWS_SYSMON_SNARE_SPEC,
        Path("syslog/2026/win-01/windows_event_sysmon_snare.log"),
        "windows_event_sysmon_snare.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_windows_snare_event(
        path="/logstash/syslog/2026/win-01/windows_event_sysmon_snare.log",
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
    )
    event["tags"] = ["filebeat", "process_archive", "snare_log", "_grokparsefail_6010-01"]
    tags = event["tags"]
    assert isinstance(tags, list)
    tags.append("parse_done")
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    events = validate_source_parsed_output(manifest, parsed_dir)

    assert len(events) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_source_parsed_output_keeps_unparsed_windows_snare_tag_fatal(
    tmp_path: Path,
) -> None:
    manifest = _manifest(
        tmp_path,
        WINDOWS_SYSMON_SNARE_SPEC,
        Path("syslog/2026/win-01/windows_event_sysmon_snare.log"),
        "windows_event_sysmon_snare.log",
        source_year=2026,
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_windows_snare_event(
        path="/logstash/syslog/2026/win-01/windows_event_sysmon_snare.log",
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        event_id=1,
    )
    event["tags"] = ["filebeat", "process_archive", "snare_log", "_grokparsefail_6010-01"]
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    with pytest.raises(SofElkParserError, match="_grokparsefail_6010-01"):
        validate_source_parsed_output(manifest, parsed_dir)

    report = json.loads((parsed_dir / FAILURE_REPORT_FILENAME).read_text(encoding="utf-8"))
    assert report["failure_tag_counts"]["windows_event_sysmon_snare"]["_grokparsefail_6010-01"] == 1
    sample = report["sample_failures"][0]
    assert sample["winlog_provider_name"] == "Microsoft-Windows-Sysmon"
    assert sample["winlog_channel"] == "Microsoft-Windows-Sysmon/Operational"


def _fake_sof_elk_dir(tmp_path: Path, spec: SofElkSourceSpec) -> Path:
    sof_elk_dir = tmp_path / f"sof-elk-{spec.format_name}"
    (sof_elk_dir / "lib" / "filebeat_inputs").mkdir(parents=True)
    (sof_elk_dir / "configfiles").mkdir()
    (sof_elk_dir / "configfiles" / "0000-input-beats.conf").write_text(
        'input { beats { port => 5044 tags => [ "process_archive", "filebeat" ] } }\n',
        encoding="utf-8",
    )
    (sof_elk_dir / "lib" / "filebeat_inputs" / spec.filebeat_input).write_text(
        f"- type: filestream\n  paths:\n    - /logstash/{spec.staged_directory}/**\n",
        encoding="utf-8",
    )
    for filter_file in spec.filter_files:
        (sof_elk_dir / "configfiles" / filter_file).write_text(
            "filter { }\n",
            encoding="utf-8",
        )
    return sof_elk_dir


def _manifest(
    tmp_path: Path,
    spec: SofElkSourceSpec,
    staged_relative: Path,
    source_name: str,
    source_year: int | None = None,
) -> SofElkSourceManifest:
    staged = tmp_path / "logstash" / staged_relative
    staged.parent.mkdir(parents=True)
    staged.write_text("raw\n", encoding="utf-8")
    return SofElkSourceManifest(
        spec=spec,
        logstash_root=tmp_path / "logstash",
        logs=(
            StagedSourceLog(
                source=tmp_path / source_name,
                staged=staged,
                record_count=1,
                source_year=source_year,
            ),
        ),
    )


def _parsed_cisco_asa_event() -> dict[str, object]:
    return {
        "tags": ["filebeat", "process_archive", "got_cisco", "parse_done"],
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/2026/fw-01/cisco_asa.log"},
            "syslog": {
                "hostname": "fw01",
                "appname": "%asa-6-302013",
            },
        },
        "event": {
            "original": (
                "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP "
                "connection 7 for inside:10.0.10.5/54321 to outside:198.51.100.10/443"
            )
        },
        "cisco": {"asa": {"action": "built", "connection_id": "7"}},
        "source": {"ip": "10.0.10.5", "port": 54321},
        "destination": {"ip": "198.51.100.10", "port": 443},
        "network": {"transport": "tcp"},
        "@timestamp": "2026-06-15T14:23:05.000Z",
    }


def _parsed_web_access_event() -> dict[str, object]:
    return {
        "tags": ["filebeat", "process_archive", "parse_done"],
        "labels": {"type": "httpdlog"},
        "log": {"file": {"path": "/logstash/httpd/web-01/web_access.log"}},
        "event": {
            "original": (
                "198.51.100.25 - - [15/Jun/2026:14:23:05 +0000] "
                '"GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
            )
        },
        "source": {"ip": "198.51.100.25"},
        "http": {
            "request": {"method": "GET"},
            "response": {"status_code": 200},
        },
        "url": {"path": "/index.html"},
        "user_agent": {"original": "Mozilla/5.0"},
    }


def _parsed_syslog_event() -> dict[str, object]:
    return {
        "tags": ["filebeat", "process_archive"],
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/2026/linux-01/syslog.log"},
            "syslog": {
                "hostname": "linux-01",
                "appname": "sshd",
            },
        },
        "event": {
            "original": (
                "<30>Jun 15 14:23:05 linux-01 sshd[1234]: Accepted password for alice "
                "from 198.51.100.25 port 54321 ssh2"
            )
        },
        "message": "Accepted password for alice from 198.51.100.25 port 54321 ssh2",
        "source": {"ip": "198.51.100.25", "port": 54321},
        "ssh": {"auth_result": "accepted", "login_method": "password"},
        "user": {"name": "alice"},
        "@timestamp": "2026-06-15T14:23:05.000Z",
    }


def _parsed_windows_snare_event(
    *,
    path: str,
    provider: str,
    channel: str,
    event_id: int,
) -> dict[str, object]:
    return {
        "tags": ["filebeat", "process_archive", "snare_log", "parse_done"],
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": path},
            "syslog": {
                "hostname": "win-01",
                "appname": provider,
            },
        },
        "event": {
            "original": (
                "<86>Jun 15 14:23:05 win-01 win-01\tMSWinEventLog\t0\t"
                f"{channel}\t100\tMon Jun 15 14:23:05 2026\t{event_id}\t"
                f"{provider}\talice\tN/A\tSuccess Audit\twin-01\tLogon\t"
                "An account was successfully logged on.:  Account Name: alice  "
            ),
            "provider": provider,
        },
        "host": {"hostname": "win-01"},
        "winlog": {
            "event_id": event_id,
            "provider_name": provider,
            "channel": channel,
            "computer_name": "win-01",
        },
        "message": "An account was successfully logged on.",
        "@timestamp": "2026-06-15T14:23:05.000Z",
    }


def _write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(f"{json.dumps(event, sort_keys=True)}\n" for event in events),
        encoding="utf-8",
    )
