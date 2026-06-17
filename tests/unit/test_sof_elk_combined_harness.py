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

"""Tests for the combined SOF-ELK external parser harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidenceforge.external_parsers.runner import (
    SOF_ELK_CISCO_ASA_VALIDATOR,
    SOF_ELK_SYSLOG_VALIDATOR,
    SOF_ELK_WEB_ACCESS_VALIDATOR,
    SOF_ELK_ZEEK_VALIDATOR,
)
from evidenceforge.external_parsers.sof_elk import (
    build_sof_elk_configs,
    stage_sof_elk_logs,
    validate_sof_elk_output,
)
from evidenceforge.external_parsers.sof_elk_sources import SOF_ELK_SOURCE_SPECS
from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_REPORT_FILENAME,
    SOF_ELK_FILTER_FILES,
    SofElkParserError,
)


def test_stage_sof_elk_logs_combines_all_supported_families(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    data_dir = _combined_data_dir(fixtures_dir, tmp_path)

    manifest = stage_sof_elk_logs(data_dir, tmp_path / "stage", _all_validators())

    assert manifest.expected_counts == {
        "zeek_conn": 2,
        "zeek_dns": 2,
        "cisco_asa": 1,
        "web_access": 1,
        "syslog": 1,
    }
    staged = {log.staged.relative_to(manifest.logstash_root) for log in manifest.staged_logs}
    assert Path("zeek/sensor-a/conn.log") in staged
    assert Path("syslog/2026/fw-01/cisco_asa.log") in staged
    assert Path("httpd/web-01/web_access.log") in staged
    assert Path("syslog/2026/linux-01/syslog.log") in staged


def test_build_sof_elk_configs_uses_one_pipeline_and_all_inputs(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    data_dir = _combined_data_dir(fixtures_dir, tmp_path)
    manifest = stage_sof_elk_logs(data_dir, tmp_path / "stage", _all_validators())
    config = build_sof_elk_configs(tmp_path, manifest)

    input_dir = config.filebeat_inputs_dir
    assert config.sof_elk_filebeat_inputs == ("zeek.yml", "syslog.yml", "httpdlog.yml")
    assert not (input_dir / "zeek.yml").exists()
    assert (input_dir / "evidenceforge-zeek.yml").exists()
    assert not (input_dir / "syslog.yml").exists()
    assert not (input_dir / "httpdlog.yml").exists()
    assert 'path => "/parsed-output/%{[labels][type]}.jsonl"' in (
        config.pipeline_dir / "9999-output-jsonl.conf"
    ).read_text(encoding="utf-8")
    assert "6018-cisco_asa.conf" in config.sof_elk_filter_files
    assert "6100-httpd.conf" in config.sof_elk_filter_files
    assert "6015-sshd.conf" in config.sof_elk_filter_files
    assert not (config.pipeline_dir / "6018-cisco_asa.conf").exists()
    assert not (config.pipeline_dir / "6100-httpd.conf").exists()
    assert not (config.pipeline_dir / "6015-sshd.conf").exists()


def test_validate_sof_elk_output_writes_one_consolidated_failure_report(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    data_dir = _combined_data_dir(fixtures_dir, tmp_path)
    manifest = stage_sof_elk_logs(data_dir, tmp_path / "stage", _all_validators())
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_conn.jsonl",
        [_parsed_conn("CYkWjM24bFJsDt1234"), _parsed_conn("DZlXkN35cGKtEu5678")],
    )
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [
            _parsed_dns("DZlXkN35cGKtEu5678", "www.example.com", with_answers=True),
            _parsed_dns("DQsVmE1aY4JnZq0002", "missing.example.com"),
        ],
    )
    _write_jsonl(
        parsed_dir / "syslog.jsonl",
        [_parsed_cisco_asa_event(), _parsed_syslog_event(failed=True)],
    )
    _write_jsonl(parsed_dir / "httpdlog.jsonl", [_parsed_web_access_event()])

    with pytest.raises(SofElkParserError, match="_grokparsefailure_6015-01"):
        validate_sof_elk_output(manifest, parsed_dir)

    report = json.loads((parsed_dir / FAILURE_REPORT_FILENAME).read_text(encoding="utf-8"))
    assert report["expected_counts"] == {
        "cisco_asa": 1,
        "syslog": 1,
        "web_access": 1,
        "zeek_conn": 2,
        "zeek_dns": 2,
    }
    assert report["observed_counts"] == report["expected_counts"]
    assert report["failure_count"] == 1
    assert report["failure_tag_counts"]["syslog"]["_grokparsefailure_6015-01"] == 1
    assert "cisco_asa" in report["log_support"]
    assert "web_access" in report["log_support"]
    assert "zeek_conn" in report["parsed_outputs"]
    assert "syslog" in report["parsed_outputs"]
    assert report["sample_failures"][0]["event_original"].startswith("<30>Jun 15")


def test_validate_sof_elk_output_ignores_parsed_sshd_pam_session_overlap(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    data_dir = _combined_data_dir(fixtures_dir, tmp_path)
    manifest = stage_sof_elk_logs(data_dir, tmp_path / "stage", _all_validators())
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_conn.jsonl",
        [_parsed_conn("CYkWjM24bFJsDt1234"), _parsed_conn("DZlXkN35cGKtEu5678")],
    )
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [
            _parsed_dns("DZlXkN35cGKtEu5678", "www.example.com", with_answers=True),
            _parsed_dns("DQsVmE1aY4JnZq0002", "missing.example.com"),
        ],
    )
    _write_jsonl(
        parsed_dir / "syslog.jsonl",
        [_parsed_cisco_asa_event(), _parsed_syslog_pam_session_event()],
    )
    _write_jsonl(parsed_dir / "httpdlog.jsonl", [_parsed_web_access_event()])

    events_by_type = validate_sof_elk_output(manifest, parsed_dir)

    assert events_by_type["syslog"][0]["pam"]["event"] == "opened"
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_sof_elk_output_ignores_parsed_pam_auth_failure_enrichment_miss(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    data_dir = _combined_data_dir(fixtures_dir, tmp_path)
    manifest = stage_sof_elk_logs(data_dir, tmp_path / "stage", _all_validators())
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_conn.jsonl",
        [_parsed_conn("CYkWjM24bFJsDt1234"), _parsed_conn("DZlXkN35cGKtEu5678")],
    )
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [
            _parsed_dns("DZlXkN35cGKtEu5678", "www.example.com", with_answers=True),
            _parsed_dns("DQsVmE1aY4JnZq0002", "missing.example.com"),
        ],
    )
    _write_jsonl(
        parsed_dir / "syslog.jsonl",
        [_parsed_cisco_asa_event(), _parsed_syslog_pam_auth_failure_event(parsed=True)],
    )
    _write_jsonl(parsed_dir / "httpdlog.jsonl", [_parsed_web_access_event()])

    events_by_type = validate_sof_elk_output(manifest, parsed_dir)

    assert events_by_type["syslog"][0]["pam"]["sessiontype"] == "auth"
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_sof_elk_output_keeps_unparsed_pam_auth_failure_tag_fatal(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    data_dir = _combined_data_dir(fixtures_dir, tmp_path)
    manifest = stage_sof_elk_logs(data_dir, tmp_path / "stage", _all_validators())
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_conn.jsonl",
        [_parsed_conn("CYkWjM24bFJsDt1234"), _parsed_conn("DZlXkN35cGKtEu5678")],
    )
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [
            _parsed_dns("DZlXkN35cGKtEu5678", "www.example.com", with_answers=True),
            _parsed_dns("DQsVmE1aY4JnZq0002", "missing.example.com"),
        ],
    )
    _write_jsonl(
        parsed_dir / "syslog.jsonl",
        [_parsed_cisco_asa_event(), _parsed_syslog_pam_auth_failure_event(parsed=False)],
    )
    _write_jsonl(parsed_dir / "httpdlog.jsonl", [_parsed_web_access_event()])

    with pytest.raises(SofElkParserError, match="_grokparsefail_6016-02"):
        validate_sof_elk_output(manifest, parsed_dir)


def _all_validators() -> tuple[str, ...]:
    return (
        SOF_ELK_ZEEK_VALIDATOR,
        SOF_ELK_CISCO_ASA_VALIDATOR,
        SOF_ELK_WEB_ACCESS_VALIDATOR,
        SOF_ELK_SYSLOG_VALIDATOR,
    )


def _combined_data_dir(fixtures_dir: Path, tmp_path: Path) -> Path:
    data_dir = tmp_path / "data"
    source_zeek = fixtures_dir / "external_parser" / "zeek" / "sensor-a"
    zeek_dir = data_dir / "sensor-a"
    zeek_dir.mkdir(parents=True)
    for name in ("conn.json", "dns.json"):
        (zeek_dir / name).write_text((source_zeek / name).read_text(encoding="utf-8"))

    (data_dir / "fw-01" / "2026").mkdir(parents=True)
    (data_dir / "fw-01" / "2026" / "cisco_asa.log").write_text(
        "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7 "
        "for inside:10.0.10.5/54321 to outside:198.51.100.10/443\n",
        encoding="utf-8",
    )
    (data_dir / "web-01").mkdir()
    (data_dir / "web-01" / "web_access.log").write_text(
        '198.51.100.25 - - [15/Jun/2026:14:23:05 +0000] "GET /index.html HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    (data_dir / "linux-01" / "2026").mkdir(parents=True)
    (data_dir / "linux-01" / "2026" / "syslog.log").write_text(
        "<30>Jun 15 14:23:05 linux-01 sshd[1234]: Accepted password for alice "
        "from 198.51.100.25 port 54321 ssh2\n",
        encoding="utf-8",
    )
    return data_dir


def _fake_sof_elk_dir(tmp_path: Path) -> Path:
    sof_elk_dir = tmp_path / "sof-elk"
    (sof_elk_dir / "configfiles").mkdir(parents=True)
    (sof_elk_dir / "lib" / "filebeat_inputs").mkdir(parents=True)
    (sof_elk_dir / "configfiles" / "0000-input-beats.conf").write_text(
        'input { beats { port => 5044 tags => [ "process_archive", "filebeat" ] } }\n',
        encoding="utf-8",
    )
    for filter_file in set(SOF_ELK_FILTER_FILES) | {
        filter_file for spec in SOF_ELK_SOURCE_SPECS for filter_file in spec.filter_files
    }:
        (sof_elk_dir / "configfiles" / filter_file).write_text(
            "filter { }\n",
            encoding="utf-8",
        )
    for input_file, watched_path in {
        "zeek.yml": "/logstash/zeek/**/conn.*",
        "syslog.yml": "/logstash/syslog/**",
        "httpdlog.yml": "/logstash/httpd/**",
    }.items():
        (sof_elk_dir / "lib" / "filebeat_inputs" / input_file).write_text(
            f"- type: filestream\n  paths:\n    - {watched_path}\n",
            encoding="utf-8",
        )
    return sof_elk_dir


def _parsed_conn(session_id: str) -> dict[str, object]:
    return {
        "tags": ["filebeat", "zeek", "zeek_json"],
        "labels": {"type": "zeek_conn"},
        "zeek": {"session_id": session_id, "connection": {"state": "SF"}},
        "source": {"ip": "10.0.10.50", "port": 54321, "bytes": 1024, "packets": 10},
        "destination": {"ip": "93.184.216.34", "port": 443, "bytes": 4096, "packets": 8},
        "network": {"transport": "tcp"},
    }


def _parsed_dns(
    session_id: str,
    question_name: str,
    *,
    with_answers: bool = False,
) -> dict[str, object]:
    event: dict[str, object] = {
        "tags": ["filebeat", "zeek", "zeek_json", "dns_record"],
        "labels": {"type": "zeek_dns"},
        "zeek": {"session_id": session_id},
        "source": {"ip": "10.0.10.51", "port": 12345},
        "destination": {"ip": "10.0.20.10", "port": 53},
        "network": {"transport": "udp"},
        "dns": {
            "question": {"name": question_name, "type": "A"},
            "response": {"code": "NOERROR"},
        },
    }
    if with_answers:
        event["dns"] = {
            "question": {"name": question_name, "type": "A"},
            "response": {"code": "NOERROR"},
            "answers": {"data": "93.184.216.34", "ttl": 3600, "ip": "93.184.216.34"},
        }
    return event


def _parsed_cisco_asa_event() -> dict[str, object]:
    return {
        "tags": [
            "filebeat",
            "process_archive",
            "got_cisco",
            "parse_done",
        ],
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/2026/fw-01/cisco_asa.log"},
            "syslog": {"hostname": "fw01", "appname": "%asa-6-302013"},
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
        "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
        "url": {"path": "/index.html"},
    }


def _parsed_syslog_event(*, failed: bool) -> dict[str, object]:
    tags = ["filebeat", "process_archive", "_grokparsefail_6018-01"]
    if failed:
        tags.append("_grokparsefailure_6015-01")
    return {
        "tags": tags,
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/2026/linux-01/syslog.log"},
            "syslog": {"hostname": "linux-01", "appname": "sshd"},
        },
        "event": {
            "original": (
                "<30>Jun 15 14:23:05 linux-01 sshd[1234]: Accepted password for alice "
                "from 198.51.100.25 port 54321 ssh2"
            )
        },
        "message": "Accepted password for alice from 198.51.100.25 port 54321 ssh2",
        "@timestamp": "2026-06-15T14:23:05.000Z",
    }


def _parsed_syslog_pam_session_event() -> dict[str, object]:
    message = "pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)"
    return {
        "tags": [
            "filebeat",
            "process_archive",
            "_grokparsefail_6018-01",
            "_grokparsefailure_6015-01",
            "got_pam",
            "parse_done",
        ],
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/2026/linux-01/syslog.log"},
            "syslog": {"hostname": "linux-01", "appname": "sshd"},
        },
        "event": {"original": f"<86>Jun 15 14:23:05 linux-01 sshd[1234]: {message}"},
        "message": message,
        "pam": {
            "module": "pam_unix",
            "service": "sshd",
            "sessiontype": "session",
            "event": "opened",
        },
        "@timestamp": "2026-06-15T14:23:05.000Z",
    }


def _parsed_syslog_pam_auth_failure_event(*, parsed: bool) -> dict[str, object]:
    message = (
        "pam_unix(login:auth): authentication failure; logname=LOGIN uid=0 euid=0 "
        "tty=/dev/tty1 ruser= rhost=  user=alice"
    )
    tags = ["filebeat", "process_archive", "_grokparsefail_6016-02"]
    event: dict[str, object] = {
        "tags": tags,
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/2026/linux-01/syslog.log"},
            "syslog": {"hostname": "linux-01", "appname": "login"},
        },
        "event": {"original": f"<84>Jun 15 14:23:05 linux-01 login[1234]: {message}"},
        "message": message,
        "@timestamp": "2026-06-15T14:23:05.000Z",
    }
    if parsed:
        tags.extend(("got_pam", "parse_done"))
        event["pam"] = {
            "module": "pam_unix",
            "service": "login",
            "sessiontype": "auth",
        }
    return event


def _write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(f"{json.dumps(event, sort_keys=True)}\n" for event in events),
        encoding="utf-8",
    )
