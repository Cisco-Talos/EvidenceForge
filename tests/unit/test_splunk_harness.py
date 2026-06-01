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

"""Tests for the Splunk external parser harness."""

from __future__ import annotations

from pathlib import Path

import pytest

from evidenceforge.external_parsers import splunk_runtime
from evidenceforge.external_parsers.compose_runtime import ComposeCommand
from evidenceforge.external_parsers.errors import SplunkHarnessError
from evidenceforge.external_parsers.splunk import (
    SPLUNK_SOURCE_SPECS,
    CimMode,
    SplunkStageManifest,
    _internal_issue_search,
    _metadata_validation_search,
    _required_field_validation_search,
    _search_result_rows,
    build_splunk_configs,
    stage_splunk_logs,
)
from evidenceforge.external_parsers.splunk_runtime import create_splunk_compose_run
from tests.external_parser.sample_data import write_splunk_multifamily_dataset


def test_stage_splunk_logs_detects_supported_and_v1_unsupported_logs(tmp_path: Path) -> None:
    data_dir = _splunk_data_dir(tmp_path)

    staged_logs, unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")

    assert {log.format_name for log in staged_logs} == {
        "zeek_conn",
        "windows_event_security",
        "windows_event_sysmon",
        "syslog",
        "cisco_asa",
        "web_access",
        "proxy_access",
        "ecar",
    }
    assert {log.format_name for log in unsupported} == {"bash_history", "snort_alert"}
    assert {log.sourcetype for log in staged_logs} >= {
        "bro:conn:json",
        "XmlWinEventLog:Security",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "syslog",
        "cisco:asa",
        "access_combined",
        "evidenceforge:proxy:w3c",
        "evidenceforge:ecar:json",
    }
    proxy_log = next(log for log in staged_logs if log.format_name == "proxy_access")
    assert proxy_log.record_count == 1
    windows_security = next(
        log for log in staged_logs if log.format_name == "windows_event_security"
    )
    assert windows_security.host == "win01.example.test"
    assert windows_security.staged.relative_to(tmp_path / "stage" / "data") == Path(
        "win01_example_test/windows_event_security.xml"
    )


def test_stage_splunk_logs_accepts_multifamily_parser_sample(tmp_path: Path) -> None:
    data_dir = write_splunk_multifamily_dataset(tmp_path / "data")

    staged_logs, unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")

    assert {log.format_name: log.record_count for log in staged_logs} == {
        spec.format_name: 1 for spec in SPLUNK_SOURCE_SPECS
    }
    assert not unsupported
    assert not any(log.staged.parent == tmp_path / "stage" / "data" for log in staged_logs)


def test_build_splunk_configs_writes_generated_app_and_supplied_apps(
    tmp_path: Path,
) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, _unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")
    supplied_app = tmp_path / "Splunk_TA_windows"
    (supplied_app / "default").mkdir(parents=True)
    (supplied_app / "default" / "props.conf").write_text("[source::dummy]\n", encoding="utf-8")

    config = build_splunk_configs(tmp_path, staged_logs, splunk_apps=(supplied_app,))

    inputs = config.inputs_conf.read_text(encoding="utf-8")
    props = config.props_conf.read_text(encoding="utf-8")
    transforms = config.transforms_conf.read_text(encoding="utf-8")
    indexes = config.indexes_conf.read_text(encoding="utf-8")
    server = config.server_conf.read_text(encoding="utf-8")
    assert "[monitor:///evidenceforge-data/win01_example_test/windows_event_security.xml]" in inputs
    assert "host = win01.example.test" in inputs
    assert "sourcetype = XmlWinEventLog:Security" in inputs
    assert "[XmlWinEventLog:Security]" in props
    assert "[bro:conn:json]" in props
    assert "EXTRACT-evidenceforge-asa" in props
    assert "[evidenceforge_proxy_comment_drop]" in transforms
    assert "[eforge]" in indexes
    assert "allowRemoteLogin = always" in server
    assert config.supplied_app_count == 1
    assert (config.supplied_apps_dir / "Splunk_TA_windows" / "default" / "props.conf").exists()


def test_splunk_runtime_requires_explicit_license_acceptance(tmp_path: Path) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, _unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")
    config = build_splunk_configs(tmp_path, staged_logs)

    with pytest.raises(SplunkHarnessError, match="requires explicit Splunk license"):
        create_splunk_compose_run(
            work_dir=tmp_path,
            generated_config=config,
            staged_data_dir=tmp_path / "stage" / "data",
            parsed_dir=tmp_path / "parsed",
            pipeline_log_dir=tmp_path / "pipeline-logs",
            search_results_dir=tmp_path / "search-results",
            runtime=None,
            accept_splunk_license=False,
        )


def test_splunk_runtime_mounts_apps_without_overriding_splunk_etc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, _unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")
    config = build_splunk_configs(tmp_path, staged_logs)
    monkeypatch.setattr(
        splunk_runtime,
        "find_compose_runtime",
        lambda _runtime: ComposeCommand(runtime="docker", command=("docker", "compose")),
    )

    compose_run = create_splunk_compose_run(
        work_dir=tmp_path,
        generated_config=config,
        staged_data_dir=tmp_path / "stage" / "data",
        parsed_dir=tmp_path / "parsed",
        pipeline_log_dir=tmp_path / "pipeline-logs",
        search_results_dir=tmp_path / "search-results",
        runtime=None,
        accept_splunk_license=True,
    )

    compose_yaml = compose_run.compose_file.read_text(encoding="utf-8")
    assert 'platform: "linux/amd64"' in compose_yaml
    assert "/opt/splunk/etc/apps/evidenceforge_parser_validation" in compose_yaml
    assert 'target: "/opt/splunk/etc"' not in compose_yaml
    assert 'target: "/opt/splunk/var"' not in compose_yaml


def test_splunk_validation_search_builders_include_core_checks(tmp_path: Path) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, _unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")

    metadata = _metadata_validation_search(("syslog", "cisco:asa"))
    fields = _required_field_validation_search(staged_logs)
    internal = _internal_issue_search()

    assert "empty_raw" in metadata
    assert "missing_time" in metadata
    assert "missing_host" in metadata
    assert "missing_source" in metadata
    assert 'sourcetype="syslog"' in fields
    assert "'app'" in fields
    assert "'asa_msg_id'" in fields
    assert "DateParserVerbose" in internal
    assert "LineBreakingProcessor" in internal
    assert "_raw" in internal


def test_splunk_validation_uses_ta_normalized_windows_sourcetype(tmp_path: Path) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")
    manifest = SplunkStageManifest(
        data_root=tmp_path / "stage" / "data",
        logs=staged_logs,
        unsupported_logs=unsupported,
        cim_mode=CimMode.REQUIRE,
        supplied_app_count=1,
    )

    assert manifest.expected_sourcetype_counts["XmlWinEventLog"] == 2
    assert "XmlWinEventLog:Security" not in manifest.expected_sourcetype_counts

    fields = _required_field_validation_search(
        staged_logs,
        use_supplied_app_sourcetypes=True,
    )

    assert 'sourcetype IN ("XmlWinEventLog"' in fields
    assert 'sourcetype="XmlWinEventLog"' in fields


def test_splunk_search_result_rows_ignore_export_info_messages() -> None:
    rows = [
        {"messages": [{"type": "INFO", "text": "No matching fields exist."}], "lastrow": True},
        {"result": {"component": "TailReader", "message": "real warning"}},
    ]

    assert _search_result_rows(rows) == [
        {"result": {"component": "TailReader", "message": "real warning"}}
    ]


def _splunk_data_dir(tmp_path: Path) -> Path:
    data_dir = tmp_path / "data"
    (data_dir / "sensor-a").mkdir(parents=True)
    (data_dir / "sensor-a" / "conn.json").write_text(
        '{"ts": 1781533385.0, "uid": "C1", "id.orig_h": "10.0.0.1"}\n',
        encoding="utf-8",
    )
    (data_dir / "win01.example.test").mkdir()
    (data_dir / "win01.example.test" / "windows_event_security.xml").write_text(
        "<Event><System><EventID>4624</EventID><Computer>win01.example.test</Computer>"
        "</System></Event>\n",
        encoding="utf-8",
    )
    (data_dir / "win01.example.test" / "windows_event_sysmon.xml").write_text(
        "<Event><System><EventID>1</EventID><Computer>win01.example.test</Computer>"
        "</System></Event>\n",
        encoding="utf-8",
    )
    (data_dir / "linux01.example.test").mkdir()
    (data_dir / "linux01.example.test" / "syslog.log").write_text(
        "<86>1 2026-06-15T14:23:05Z linux01 sshd 1234 - - Accepted password\n",
        encoding="utf-8",
    )
    (data_dir / "fw01").mkdir()
    (data_dir / "fw01" / "cisco_asa.log").write_text(
        "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7\n",
        encoding="utf-8",
    )
    (data_dir / "web01").mkdir()
    (data_dir / "web01" / "web_access.log").write_text(
        '198.51.100.25 - - [15/Jun/2026:14:23:05 +0000] "GET / HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n',
        encoding="utf-8",
    )
    (data_dir / "proxy01").mkdir()
    (data_dir / "proxy01" / "proxy_access.log").write_text(
        "#Fields: date time c-ip cs-username cs-method cs-uri cs-version sc-status "
        "sc-bytes cs-bytes time-taken cs-host cs(User-Agent) cs(Referer) "
        "rs(Content-Type) s-cache-result x-proxy-action\n"
        "2026-06-15 14:23:05 10.0.0.5 alice GET http://example.test/ HTTP/1.1 "
        "200 512 128 10 example.test Mozilla/5.0 - text/html MISS forward\n",
        encoding="utf-8",
    )
    (data_dir / "endpoint01").mkdir()
    (data_dir / "endpoint01" / "ecar.json").write_text(
        '{"event_type": "PROCESS", "action": "CREATE"}\n',
        encoding="utf-8",
    )
    (data_dir / "sensor-a" / "snort_alert.log").write_text("[**] alert\n", encoding="utf-8")
    (data_dir / "linux01.example.test" / "bash_history").mkdir()
    (data_dir / "linux01.example.test" / "bash_history" / "alice.bash_history").write_text(
        "whoami\n",
        encoding="utf-8",
    )
    return data_dir
