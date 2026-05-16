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
    SofElkSourceManifest,
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
    source_dir = source_root / "fw-01.example.test"
    source_dir.mkdir(parents=True)
    (source_dir / "cisco_asa.log").write_text(
        "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7 "
        "for inside:10.0.10.5/54321 to outside:198.51.100.10/443\n",
        encoding="utf-8",
    )

    manifest = stage_source_logs(source_root, tmp_path / "stage", CISCO_ASA_SPEC)

    assert manifest.expected_counts == {"cisco_asa": 1}
    assert {log.staged.relative_to(manifest.logstash_root) for log in manifest.logs} == {
        Path("syslog/fw-01.example.test/cisco_asa.log")
    }


def test_build_sof_elk_source_configs_reuses_sof_elk_syslog_input(tmp_path: Path) -> None:
    sof_elk_dir = tmp_path / "sof-elk"
    (sof_elk_dir / "lib" / "filebeat_inputs").mkdir(parents=True)
    (sof_elk_dir / "configfiles").mkdir()
    (sof_elk_dir / "configfiles" / "0000-input-beats.conf").write_text(
        'input { beats { port => 5044 tags => [ "process_archive", "filebeat" ] } }\n',
        encoding="utf-8",
    )
    (sof_elk_dir / "lib" / "filebeat_inputs" / "syslog.yml").write_text(
        "- type: filestream\n  paths:\n    - /logstash/syslog/**\n",
        encoding="utf-8",
    )
    for filter_file in CISCO_ASA_SPEC.filter_files:
        (sof_elk_dir / "configfiles" / filter_file).write_text(
            "filter { }\n",
            encoding="utf-8",
        )

    pipeline_dir, filebeat_config = build_sof_elk_source_configs(
        sof_elk_dir,
        tmp_path,
        CISCO_ASA_SPEC,
    )

    assert "/usr/share/filebeat/inputs.d/*.yml" in filebeat_config.read_text(encoding="utf-8")
    assert (filebeat_config.parent / "filebeat-inputs" / "syslog.yml").exists()
    assert 'copy => { "message" => "[event][original]" }' in (
        pipeline_dir / "0001-capture-original.conf"
    ).read_text(encoding="utf-8")
    assert f"/parsed-output/{EVENTS_OUTPUT_FILENAME}" in (
        pipeline_dir / "9999-output-jsonl.conf"
    ).read_text(encoding="utf-8")
    for filter_file in CISCO_ASA_SPEC.filter_files:
        assert (pipeline_dir / filter_file).exists()


def test_validate_source_parsed_output_accepts_cisco_asa_parse(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    parsed_dir = tmp_path / "parsed"
    parsed_dir.mkdir()
    event = _parsed_cisco_asa_event()
    tags = event["tags"]
    assert isinstance(tags, list)
    tags.append("_grokparsefailure_1100-03")
    _write_jsonl(parsed_dir / EVENTS_OUTPUT_FILENAME, [event])

    events = validate_source_parsed_output(manifest, parsed_dir)

    assert len(events) == 1
    assert not (parsed_dir / FAILURE_REPORT_FILENAME).exists()


def test_validate_source_parsed_output_reports_cisco_asa_parser_context(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
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
    assert sample["log_file_path"] == "/logstash/syslog/fw-01/cisco_asa.log"


def _manifest(tmp_path: Path) -> SofElkSourceManifest:
    staged = tmp_path / "logstash" / "syslog" / "fw-01" / "cisco_asa.log"
    staged.parent.mkdir(parents=True)
    staged.write_text("raw\n", encoding="utf-8")
    return SofElkSourceManifest(
        spec=CISCO_ASA_SPEC,
        logstash_root=tmp_path / "logstash",
        logs=(
            StagedSourceLog(
                source=tmp_path / "cisco_asa.log",
                staged=staged,
                record_count=1,
            ),
        ),
    )


def _parsed_cisco_asa_event() -> dict[str, object]:
    return {
        "tags": ["filebeat", "process_archive", "got_cisco", "parse_done"],
        "labels": {"type": "syslog"},
        "log": {
            "file": {"path": "/logstash/syslog/fw-01/cisco_asa.log"},
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
    }


def _write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(f"{json.dumps(event, sort_keys=True)}\n" for event in events),
        encoding="utf-8",
    )
