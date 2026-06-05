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

import json
from pathlib import Path

import pytest

from evidenceforge.external_parsers import splunk_runtime
from evidenceforge.external_parsers.compose_runtime import ComposeCommand
from evidenceforge.external_parsers.errors import SplunkHarnessError
from evidenceforge.external_parsers.splunk import (
    CIM_EXPECTATIONS_BY_FORMAT,
    SPLUNK_SOURCE_SPECS,
    CimMode,
    SplunkStageManifest,
    _cim_dataset_failures,
    _cim_dataset_validation_search,
    _cim_expected_count_search,
    _cim_search_namespace,
    _field_failures,
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
        "apache:access:json",
        "evidenceforge:ecar:json",
    }
    proxy_log = next(log for log in staged_logs if log.format_name == "proxy_access")
    assert proxy_log.record_count == 1
    assert proxy_log.sourcetype == "apache:access:json"
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
    eventtypes = config.eventtypes_conf.read_text(encoding="utf-8")
    tags = config.tags_conf.read_text(encoding="utf-8")
    indexes = config.indexes_conf.read_text(encoding="utf-8")
    server = config.server_conf.read_text(encoding="utf-8")
    metadata = (config.app_dir / "metadata" / "default.meta").read_text(encoding="utf-8")
    assert "[monitor:///evidenceforge-data/win01_example_test/windows_event_security.xml]" in inputs
    assert "host = win01.example.test" in inputs
    assert "sourcetype = XmlWinEventLog:Security" in inputs
    assert "crcSalt = <SOURCE>\n" in inputs
    assert "crcSalt = <SOURCE>XmlWinEventLog" not in inputs
    assert "sourcetype = apache:access:json" in inputs
    assert "[XmlWinEventLog:Security]" in props
    assert "[apache:access:json]" in props
    assert "KV_MODE = json" in props
    assert "[source::.../proxy_access.log]" in props
    assert "EVAL-category = if(isnull(url_category)" in props
    assert "[bro:conn:json]" in props
    assert "FIELDALIAS-evidenceforge-zeek-src = id.orig_h AS src" in props
    assert "EXTRACT-evidenceforge-asa" in props
    assert "[evidenceforge_proxy_comment_drop]" in transforms
    assert "[evidenceforge_proxy_access]" in eventtypes
    assert 'source="*proxy_access.log"' in eventtypes
    assert "[eventtype=evidenceforge_proxy_access]" in tags
    assert "proxy = enabled" in tags
    assert "[eforge]" in indexes
    assert "allowRemoteLogin = always" in server
    assert "export = system" in metadata
    assert config.supplied_app_count == 1
    assert config.supplied_app_names == ("Splunk_TA_windows",)
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


def test_splunk_cim_dataset_search_builders_check_models_and_fields() -> None:
    expectation = CIM_EXPECTATIONS_BY_FORMAT["windows_event_security"]

    search = _cim_dataset_validation_search(expectation, sourcetype="XmlWinEventLog")

    assert "| datamodel Authentication Authentication search" in search
    assert '| search sourcetype="XmlWinEventLog" source="XmlWinEventLog:Security"' in search
    assert 'rex field=_raw "<EventID>(?<cim_event_id>\\d+)</EventID>"' in search
    assert "index=eforge" not in search
    assert "missing_user" in search
    assert "missing_src" in search
    assert "'Authentication.user'" in search
    assert "'user'" in search
    assert '"unknown"' in search
    assert '"0"' in search


def test_splunk_cim_uses_event_family_expected_counts() -> None:
    windows = CIM_EXPECTATIONS_BY_FORMAT["windows_event_security"]
    sysmon = CIM_EXPECTATIONS_BY_FORMAT["windows_event_sysmon"]

    windows_search = _cim_expected_count_search(windows, sourcetype="XmlWinEventLog")
    sysmon_search = _cim_expected_count_search(sysmon, sourcetype="XmlWinEventLog")
    sysmon_cim_search = _cim_dataset_validation_search(sysmon, sourcetype="XmlWinEventLog")

    assert windows_search is not None
    assert "tag=authentication" in windows_search
    assert 'NOT (action=success user="*$")' in windows_search
    assert sysmon_search is not None
    assert 'cim_event_id IN ("1","5")' in sysmon_search
    assert 'cim_event_id IN ("1","5")' in sysmon_cim_search


def test_splunk_cim_dest_port_is_conditional_for_icmp() -> None:
    zeek = CIM_EXPECTATIONS_BY_FORMAT["zeek_conn"]
    asa = CIM_EXPECTATIONS_BY_FORMAT["cisco_asa"]

    zeek_search = _cim_dataset_validation_search(zeek, sourcetype="bro:conn:json")
    asa_search = _cim_dataset_validation_search(asa, sourcetype="cisco:asa")

    assert "missing_dest_port" in zeek_search
    assert '!="icmp"' in zeek_search
    assert "missing_dest_port" in asa_search
    assert '!="icmp"' in asa_search


def test_splunk_cim_proxy_search_filters_proxy_source() -> None:
    expectation = CIM_EXPECTATIONS_BY_FORMAT["proxy_access"]

    search = _cim_dataset_validation_search(expectation, sourcetype="apache:access:json")

    assert "| datamodel Web Proxy search" in search
    assert '| search sourcetype="apache:access:json" source="*proxy_access.log"' in search
    assert "missing_category" in search
    assert "'Web.category'" in search
    assert "'Proxy.category'" not in search


def test_splunk_cim_uses_supplied_zeek_app_namespace_when_available(tmp_path: Path) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")
    expectation = CIM_EXPECTATIONS_BY_FORMAT["zeek_conn"]
    manifest = SplunkStageManifest(
        data_root=tmp_path / "stage" / "data",
        logs=staged_logs,
        unsupported_logs=unsupported,
        cim_mode=CimMode.REQUIRE,
        supplied_app_count=1,
        supplied_app_names=("Splunk_TA_zeek",),
    )

    assert _cim_search_namespace(expectation, manifest) == "Splunk_TA_zeek"


def test_splunk_cim_dataset_failures_report_count_and_field_gaps() -> None:
    expectation = CIM_EXPECTATIONS_BY_FORMAT["windows_event_security"]
    rows = [
        {
            "result": {
                "cim_count": "1",
                "missing_user": "0",
                "missing_src": "1",
                "missing_dest": "0",
                "missing_action": "0",
                "missing_app": "0",
            }
        }
    ]

    failures = _cim_dataset_failures(expectation, rows, expected_count=2)

    assert failures == [
        "windows_event_security: expected 2 event(s) in CIM Authentication.Authentication, got 1",
        "windows_event_security: 1 CIM Authentication.Authentication event(s) missing/invalid src",
    ]


def test_splunk_search_result_rows_ignore_export_info_messages() -> None:
    rows = [
        {"messages": [{"type": "INFO", "text": "No matching fields exist."}], "lastrow": True},
        {"result": {"component": "TailReader", "message": "real warning"}},
    ]

    assert _search_result_rows(rows) == [
        {"result": {"component": "TailReader", "message": "real warning"}}
    ]


def test_splunk_field_failures_ignore_preview_rows_and_custom_ecar(tmp_path: Path) -> None:
    data_dir = _splunk_data_dir(tmp_path)
    staged_logs, _unsupported = stage_splunk_logs(data_dir, tmp_path / "stage")

    search = _required_field_validation_search(staged_logs)

    assert "missing_ecar" not in search
    assert (
        _field_failures(
            [
                {"preview": True, "result": {"sourcetype": "x", "missing_anything": "7"}},
                {"preview": False, "result": {"sourcetype": "x", "missing_anything": "0"}},
            ]
        )
        == []
    )


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
        json.dumps(
            {
                "timestamp": "2026-06-15T14:23:05.000000Z",
                "client": "198.51.100.25",
                "server": "www.example.test",
                "dest_port": 80,
                "ident": "-",
                "user": "-",
                "http_method": "GET",
                "uri_path": "/",
                "uri_query": "",
                "http_version": "HTTP/1.1",
                "status": 200,
                "http_referrer": "",
                "http_user_agent": "Mozilla/5.0",
                "bytes_in": 0,
                "bytes_out": 512,
                "response_time_microseconds": 23000,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (data_dir / "proxy01").mkdir()
    (data_dir / "proxy01" / "proxy_access.log").write_text(
        json.dumps(
            {
                "timestamp": "2026-06-15T14:23:05.000000Z",
                "client": "10.0.0.5",
                "server": "example.test",
                "dest_port": 80,
                "ident": "-",
                "user": "alice",
                "http_method": "GET",
                "uri_path": "/",
                "uri_query": "",
                "http_version": "HTTP/1.1",
                "status": 200,
                "http_referrer": "",
                "http_user_agent": "Mozilla/5.0",
                "bytes_in": 128,
                "bytes_out": 512,
                "response_time_microseconds": 10000,
                "http_content_type": "text/html",
                "cache_result": "MISS",
                "proxy_action": "forward",
                "url_category": "Business/Economy",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
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
