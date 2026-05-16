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

"""Tests for the SOF-ELK Zeek external parser harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidenceforge.config import get_formats_directory
from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_REPORT_FILENAME,
    SOF_ELK_FILTER_FILES,
    ZEEK_LOG_SPECS,
    DnsExpectation,
    SofElkParserError,
    StagedLog,
    ZeekStageManifest,
    build_sof_elk_zeek_configs,
    stage_zeek_logs,
    validate_parsed_output,
)
from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes


def test_zeek_log_specs_cover_all_format_definitions() -> None:
    zeek_formats = {path.stem for path in get_formats_directory().glob("zeek_*.yaml")}
    harness_formats = {spec.log_type for spec in ZEEK_LOG_SPECS}

    assert harness_formats == zeek_formats


def test_zeek_log_specs_cover_all_emittable_zeek_formats() -> None:
    zeek_emitters = {
        format_name for format_name in _build_emitter_classes() if format_name.startswith("zeek_")
    }
    harness_formats = {spec.log_type for spec in ZEEK_LOG_SPECS}

    assert harness_formats == zeek_emitters


def test_stage_zeek_logs_preserves_sensor_subdirectories(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    source_root = fixtures_dir / "external_parser" / "zeek"

    manifest = stage_zeek_logs(source_root, tmp_path)

    staged_paths = {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs}
    assert staged_paths == {
        Path("zeek/sensor-a/conn.log"),
        Path("zeek/sensor-a/dns.log"),
    }
    assert manifest.expected_counts == {"zeek_conn": 2, "zeek_dns": 2}
    assert manifest.dns_expectations[("DZlXkN35cGKtEu5678", "www.example.com")] == (
        DnsExpectation(answers=True, ttls=True)
    )


def test_stage_zeek_logs_adapts_flat_generated_files_for_sof_elk(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "generated"
    source_root.mkdir()
    fixture_root = fixtures_dir / "external_parser" / "zeek" / "sensor-a"
    (source_root / "zeek_conn.json").write_text(
        (fixture_root / "conn.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (source_root / "zeek_dns.json").write_text(
        (fixture_root / "dns.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    manifest = stage_zeek_logs(source_root, tmp_path / "stage")

    staged_paths = {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs}
    assert staged_paths == {
        Path("zeek/default/conn.log"),
        Path("zeek/default/dns.log"),
    }
    assert manifest.expected_counts == {"zeek_conn": 2, "zeek_dns": 2}


def test_validate_parsed_output_reports_validator_scope_progress(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    manifest = stage_zeek_logs(fixtures_dir / "external_parser" / "zeek", tmp_path / "stage")
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_conn.jsonl",
        [
            _with_log_path(_parsed_conn("CYkWjM24bFJsDt1234"), "/logstash/zeek/sensor-a/conn.log"),
            _with_log_path(_parsed_conn("DZlXkN35cGKtEu5678"), "/logstash/zeek/sensor-a/conn.log"),
        ],
    )
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [
            _with_log_path(
                _parsed_dns("DZlXkN35cGKtEu5678", "www.example.com", with_answers=True),
                "/logstash/zeek/sensor-a/dns.log",
            ),
            _with_log_path(
                _parsed_dns("DQsVmE1aY4JnZq0002", "missing.example.com", with_answers=False),
                "/logstash/zeek/sensor-a/dns.log",
            ),
        ],
    )
    progress_events: list[tuple[str, dict[str, object]]] = []

    def progress_callback(event_type: str, data: dict[str, object]) -> None:
        progress_events.append((event_type, data))

    validate_parsed_output(manifest, parsed_dir, progress_callback=progress_callback)

    scopes = [
        data for event_type, data in progress_events if event_type == "validator_scope_progress"
    ]
    assert scopes[-1] == {
        "host": "sensor-a",
        "host_completed": 4,
        "host_total": 4,
        "logtype": "zeek",
        "logtype_completed": 4,
        "logtype_total": 4,
        "subtype": "dns",
        "subtype_completed": 2,
        "subtype_total": 2,
    }


def test_stage_zeek_logs_adapts_all_generated_zeek_flat_files(tmp_path: Path) -> None:
    source_root = tmp_path / "generated"
    source_root.mkdir()
    for spec in ZEEK_LOG_SPECS:
        (source_root / spec.source_names[-1]).write_text(
            '{"ts": 1742036200.0}\n',
            encoding="utf-8",
        )

    manifest = stage_zeek_logs(source_root, tmp_path / "stage")

    staged_paths = {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs}
    assert staged_paths == {Path("zeek/default") / spec.staged_name for spec in ZEEK_LOG_SPECS}
    assert manifest.expected_counts == {spec.log_type: 1 for spec in ZEEK_LOG_SPECS}


def test_stage_zeek_logs_keeps_corrupt_dns_for_external_parser(tmp_path: Path) -> None:
    source_dir = tmp_path / "source" / "sensor-a"
    source_dir.mkdir(parents=True)
    (source_dir / "dns.json").write_text(
        '{"ts":"1742036200.000000","uid":"BROKEN",\n',
        encoding="utf-8",
    )

    manifest = stage_zeek_logs(tmp_path / "source", tmp_path / "stage")

    assert manifest.expected_counts == {"zeek_dns": 1}
    assert manifest.dns_expectations == {}
    assert (manifest.logstash_root / "zeek" / "sensor-a" / "dns.log").exists()


def test_build_sof_elk_zeek_configs_reuses_sof_elk_filebeat_input(tmp_path: Path) -> None:
    sof_elk_dir = tmp_path / "sof-elk"
    (sof_elk_dir / "lib" / "filebeat_inputs").mkdir(parents=True)
    (sof_elk_dir / "configfiles").mkdir()
    (sof_elk_dir / "lib" / "filebeat_inputs" / "zeek.yml").write_text(
        "- type: filestream\n  paths:\n    - /logstash/zeek/**/conn.*\n",
        encoding="utf-8",
    )
    for filter_file in SOF_ELK_FILTER_FILES:
        (sof_elk_dir / "configfiles" / filter_file).write_text(
            "filter { }\n",
            encoding="utf-8",
        )

    pipeline_dir, filebeat_config = build_sof_elk_zeek_configs(sof_elk_dir, tmp_path)

    assert "/usr/share/filebeat/inputs.d/*.yml" in filebeat_config.read_text(encoding="utf-8")
    assert (
        (filebeat_config.parent / "filebeat-inputs" / "zeek.yml")
        .read_text(encoding="utf-8")
        .startswith("- type: filestream")
    )
    supplemental_inputs = (
        filebeat_config.parent / "filebeat-inputs" / "evidenceforge-zeek.yml"
    ).read_text(encoding="utf-8")
    assert "type: zeek_ntp" in supplemental_inputs
    assert "/logstash/zeek/**/reporter.*" in supplemental_inputs
    assert 'path => "/parsed-output/%{[labels][type]}.jsonl"' in (
        pipeline_dir / "9999-output-jsonl.conf"
    ).read_text(encoding="utf-8")
    for filter_file in SOF_ELK_FILTER_FILES:
        assert (pipeline_dir / filter_file).exists()


def test_validate_parsed_output_accepts_expected_sof_elk_fields(
    fixtures_dir: Path,
    tmp_path: Path,
) -> None:
    manifest = stage_zeek_logs(fixtures_dir / "external_parser" / "zeek", tmp_path / "stage")
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_conn.jsonl",
        [
            _parsed_conn("CYkWjM24bFJsDt1234"),
            _parsed_conn("DZlXkN35cGKtEu5678"),
        ],
    )
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [
            _parsed_dns("DZlXkN35cGKtEu5678", "www.example.com", with_answers=True),
            _parsed_dns("DQsVmE1aY4JnZq0002", "missing.example.com", with_answers=False),
        ],
    )

    events_by_type = validate_parsed_output(manifest, parsed_dir)

    assert len(events_by_type["zeek_conn"]) == 2
    assert len(events_by_type["zeek_dns"]) == 2


@pytest.mark.parametrize(
    "tag",
    ["_jsonparsefailure", "_dateparsefailure", "_rubyexception"],
)
def test_validate_parsed_output_reports_fatal_parser_tags(
    tmp_path: Path,
    tag: str,
) -> None:
    manifest = ZeekStageManifest(
        logstash_root=tmp_path / "logstash",
        logs=(
            StagedLog(
                source=tmp_path / "conn.json",
                staged=tmp_path / "logstash" / "zeek" / "sensor" / "conn.log",
                log_type="zeek_conn",
                record_count=1,
            ),
        ),
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    failed_event = _parsed_conn("BROKEN")
    failed_event["tags"] = ["zeek", tag]
    _write_jsonl(parsed_dir / "zeek_conn.jsonl", [failed_event])

    with pytest.raises(SofElkParserError, match=tag) as excinfo:
        validate_parsed_output(manifest, parsed_dir)

    report_path = parsed_dir / FAILURE_REPORT_FILENAME
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert str(report_path) in str(excinfo.value)
    assert "failure_messages" not in report
    assert report["failure_tag_counts"]["zeek_conn"][tag] == 1
    assert report["sample_failures"][0]["zeek_session_id"] == "BROKEN"


def test_validate_parsed_output_ignores_optional_dns_answer_ip_extraction_tag(
    tmp_path: Path,
) -> None:
    manifest = ZeekStageManifest(
        logstash_root=tmp_path / "logstash",
        logs=(
            StagedLog(
                source=tmp_path / "dns.json",
                staged=tmp_path / "logstash" / "zeek" / "sensor" / "dns.log",
                log_type="zeek_dns",
                record_count=1,
            ),
        ),
        dns_expectations={
            ("DNS1", "licdn.com"): DnsExpectation(answers=True, ttls=True),
        },
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_dns("DNS1", "licdn.com", with_answers=True)
    tags = event["tags"]
    assert isinstance(tags, list)
    tags.append("_grokparsefail_6200-01")
    dns = event["dns"]
    assert isinstance(dns, dict)
    question = dns["question"]
    answers = dns["answers"]
    assert isinstance(question, dict)
    assert isinstance(answers, dict)
    question["type"] = "NS"
    answers["data"] = ["ns1.licdn.com", "ns2.licdn.com"]
    answers["ttl"] = [60.0, 60.0]
    _write_jsonl(parsed_dir / "zeek_dns.jsonl", [event])

    events_by_type = validate_parsed_output(manifest, parsed_dir)

    assert len(events_by_type["zeek_dns"]) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_parsed_output_reports_unclassified_grokparsefail_tags(
    tmp_path: Path,
) -> None:
    manifest = ZeekStageManifest(
        logstash_root=tmp_path / "logstash",
        logs=(
            StagedLog(
                source=tmp_path / "dns.json",
                staged=tmp_path / "logstash" / "zeek" / "sensor" / "dns.log",
                log_type="zeek_dns",
                record_count=1,
            ),
        ),
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    failed_event = _parsed_dns("DNS1", "www.example.com", with_answers=True)
    tags = failed_event["tags"]
    assert isinstance(tags, list)
    tags.append("_grokparsefail_6200-01")
    tags.append("_grokparsefail_6200-99")
    _write_jsonl(parsed_dir / "zeek_dns.jsonl", [failed_event])

    with pytest.raises(SofElkParserError, match="_grokparsefail_6200-99"):
        validate_parsed_output(manifest, parsed_dir)

    report = json.loads((parsed_dir / FAILURE_REPORT_FILENAME).read_text(encoding="utf-8"))
    assert "_grokparsefail_6200-01" not in report["failure_tag_counts"]["zeek_dns"]
    assert report["failure_tag_counts"]["zeek_dns"]["_grokparsefail_6200-99"] == 1
    assert report["sample_failures"][0]["tags"] == ["_grokparsefail_6200-99"]
    assert report["dns_failure_qtype_counts"]["A"] == 1


def test_validate_parsed_output_reports_dns_answer_loss(tmp_path: Path) -> None:
    manifest = ZeekStageManifest(
        logstash_root=tmp_path / "logstash",
        logs=(
            StagedLog(
                source=tmp_path / "dns.json",
                staged=tmp_path / "logstash" / "zeek" / "sensor" / "dns.log",
                log_type="zeek_dns",
                record_count=1,
            ),
        ),
        dns_expectations={
            ("DNS1", "www.example.com"): DnsExpectation(answers=True, ttls=True),
        },
    )
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    _write_jsonl(
        parsed_dir / "zeek_dns.jsonl",
        [_parsed_dns("DNS1", "www.example.com", with_answers=False)],
    )

    with pytest.raises(SofElkParserError, match="dns.answers.data"):
        validate_parsed_output(manifest, parsed_dir)


def _write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(f"{json.dumps(event, sort_keys=True)}\n" for event in events),
        encoding="utf-8",
    )


def _with_log_path(event: dict[str, object], path: str) -> dict[str, object]:
    event["log"] = {"file": {"path": path}}
    return event


def _parsed_conn(session_id: str) -> dict[str, object]:
    return {
        "tags": ["filebeat", "zeek", "zeek_json"],
        "labels": {"type": "zeek_conn"},
        "zeek": {
            "session_id": session_id,
            "connection": {"state": "SF"},
        },
        "source": {
            "ip": "10.0.10.50",
            "port": 54321,
            "bytes": 1024,
            "packets": 10,
        },
        "destination": {
            "ip": "93.184.216.34",
            "port": 443,
            "bytes": 4096,
            "packets": 8,
        },
        "network": {"transport": "tcp"},
    }


def _parsed_dns(
    session_id: str,
    question_name: str,
    *,
    with_answers: bool,
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
            "answers": {"data": "93.184.216.34", "ttl": 3600},
        }
    return event
