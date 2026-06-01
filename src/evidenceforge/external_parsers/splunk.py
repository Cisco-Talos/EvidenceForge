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

"""Splunk external parser harness for generated EvidenceForge data."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import zipfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from evidenceforge.external_parsers.errors import SplunkHarnessError, SplunkParserError
from evidenceforge.external_parsers.sof_elk_zeek import ZEEK_LOG_SPECS
from evidenceforge.external_parsers.splunk_runtime import (
    SPLUNK_APP_NAME,
    SPLUNK_INDEX,
    SplunkComposeRun,
    SplunkGeneratedConfig,
    create_splunk_compose_run,
    export_search,
    finalize_splunk_compose,
    observed_sourcetype_counts,
    reset_splunk_run_directories,
    run_splunk_compose,
)
from evidenceforge.output_targets import OutputTarget, read_output_target_marker

JsonObject = dict[str, Any]
ProgressCallback = Callable[[str, dict[str, Any]], None]

SPLUNK_VALIDATOR_NAME = "Splunk"
SPLUNK_FAILURE_REPORT_FILENAME = "splunk_parser_failures.json"


class CimMode(StrEnum):
    """CIM validation activation mode."""

    AUTO = "auto"
    REQUIRE = "require"
    OFF = "off"


@dataclass(frozen=True)
class SplunkSourceSpec:
    """A generated EvidenceForge source that can be staged into Splunk."""

    format_name: str
    logtype: str
    subtype: str
    source_names: tuple[str, ...]
    sourcetype: str
    required_fields: tuple[str, ...] = ()
    skip_comment_records: bool = False
    root_host: str = "evidenceforge-source"
    supplied_app_sourcetype: str | None = None


@dataclass(frozen=True)
class StagedSplunkLog:
    """A generated source file staged for Splunk file monitoring."""

    source: Path
    staged: Path
    host: str
    format_name: str
    logtype: str
    subtype: str
    sourcetype: str
    record_count: int


@dataclass(frozen=True)
class SplunkCimExpectation:
    """Expected CIM data-model placement for one generated source family."""

    format_name: str
    data_model: str
    object_name: str
    required_fields: tuple[str, ...]
    source_filter: str | None = None


@dataclass(frozen=True)
class SplunkStageManifest:
    """Manifest for all generated logs staged into one Splunk run."""

    data_root: Path
    logs: tuple[StagedSplunkLog, ...]
    unsupported_logs: tuple[StagedSplunkLog, ...]
    cim_mode: CimMode
    supplied_app_count: int

    @property
    def expected_counts(self) -> dict[str, int]:
        """Return expected event counts by EvidenceForge format name."""
        counts: Counter[str] = Counter()
        for log in self.logs:
            counts[log.format_name] += log.record_count
        return dict(sorted(counts.items()))

    @property
    def expected_sourcetype_counts(self) -> dict[str, int]:
        """Return expected event counts by the indexed Splunk sourcetype."""
        counts: Counter[str] = Counter()
        use_supplied_app_sourcetypes = self.supplied_app_count > 0
        for log in self.logs:
            spec = SPLUNK_SOURCE_SPECS_BY_FORMAT[log.format_name]
            counts[
                _validation_sourcetype(
                    spec,
                    use_supplied_app_sourcetypes=use_supplied_app_sourcetypes,
                )
            ] += log.record_count
        return dict(sorted(counts.items()))


@dataclass(frozen=True)
class SplunkValidationResult:
    """Summary returned by a successful Splunk parser run."""

    manifest: SplunkStageManifest
    output_dir: Path
    pipeline_log_dir: Path
    search_results_dir: Path
    observed_counts: dict[str, int]
    cim_status: str


ZEEK_SPLUNK_SOURCETYPES: dict[str, str] = {
    "zeek_conn": "bro:conn:json",
    "zeek_dns": "bro:dns:json",
    "zeek_http": "bro:http:json",
    "zeek_ssl": "bro:ssl:json",
    "zeek_files": "bro:files:json",
    "zeek_dhcp": "bro:dhcp:json",
    "zeek_ntp": "bro:ntp:json",
    "zeek_weird": "bro:weird:json",
    "zeek_x509": "bro:x509:json",
    "zeek_ocsp": "bro:ocsp:json",
    "zeek_pe": "bro:pe:json",
    "zeek_packet_filter": "bro:packet_filter:json",
    "zeek_reporter": "bro:reporter:json",
}

SPLUNK_SOURCE_SPECS: tuple[SplunkSourceSpec, ...] = (
    *(
        SplunkSourceSpec(
            format_name=spec.log_type,
            logtype="zeek",
            subtype=spec.staged_name.removesuffix(".log"),
            source_names=spec.source_names,
            sourcetype=ZEEK_SPLUNK_SOURCETYPES[spec.log_type],
            required_fields=("ts",),
            root_host="zeek-sensor",
        )
        for spec in ZEEK_LOG_SPECS
    ),
    SplunkSourceSpec(
        "windows_event_security",
        "windows events",
        "security_xml",
        ("windows_event_security.xml",),
        "XmlWinEventLog:Security",
        required_fields=("EventID", "Computer"),
        root_host="windows-event-source",
        supplied_app_sourcetype="XmlWinEventLog",
    ),
    SplunkSourceSpec(
        "windows_event_sysmon",
        "windows events",
        "sysmon_xml",
        ("windows_event_sysmon.xml",),
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        required_fields=("EventID", "Computer"),
        root_host="windows-event-source",
        supplied_app_sourcetype="XmlWinEventLog",
    ),
    SplunkSourceSpec(
        "syslog",
        "syslog",
        "linux",
        ("syslog.log",),
        "syslog",
        required_fields=("app",),
        root_host="syslog-source",
    ),
    SplunkSourceSpec(
        "cisco_asa",
        "firewall",
        "cisco_asa",
        ("cisco_asa.log",),
        "cisco:asa",
        required_fields=("asa_msg_id",),
        root_host="cisco-asa-source",
    ),
    SplunkSourceSpec(
        "web_access",
        "web",
        "access",
        ("web_access.log",),
        "access_combined",
        required_fields=("src_ip", "http_method", "status"),
        root_host="web-source",
    ),
    SplunkSourceSpec(
        "proxy_access",
        "proxy",
        "access",
        ("proxy_access.log",),
        "evidenceforge:proxy:w3c",
        required_fields=("src_ip", "http_method", "status"),
        skip_comment_records=True,
        root_host="proxy-source",
    ),
    SplunkSourceSpec(
        "ecar",
        "ecar",
        "ecar",
        ("ecar.json",),
        "evidenceforge:ecar:json",
        required_fields=("event_type",),
        root_host="ecar-source",
    ),
)
SPLUNK_SOURCE_SPECS_BY_FORMAT = {spec.format_name: spec for spec in SPLUNK_SOURCE_SPECS}
SPLUNK_SOURCE_SPECS_BY_NAME = {
    source_name: spec for spec in SPLUNK_SOURCE_SPECS for source_name in spec.source_names
}
SPLUNK_UNSUPPORTED_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("snort_alert.log", "ids", "snort", "snort_alert"),
)
_SAFE_STAGE_PART_PATTERN = re.compile(r"[^A-Za-z0-9_-]+")
CIM_EXPECTATIONS: tuple[SplunkCimExpectation, ...] = (
    SplunkCimExpectation(
        format_name="windows_event_security",
        data_model="Authentication",
        object_name="Authentication",
        required_fields=("user", "src", "dest", "action", "app"),
        source_filter="XmlWinEventLog:Security",
    ),
    SplunkCimExpectation(
        format_name="windows_event_sysmon",
        data_model="Endpoint",
        object_name="Processes",
        required_fields=("process", "process_name", "dest", "user"),
        source_filter="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    ),
    SplunkCimExpectation(
        format_name="zeek_conn",
        data_model="Network_Traffic",
        object_name="All_Traffic",
        required_fields=("src", "dest", "dest_port", "transport", "action"),
    ),
    SplunkCimExpectation(
        format_name="zeek_http",
        data_model="Web",
        object_name="Web",
        required_fields=("src", "dest", "url", "http_method", "status"),
    ),
    SplunkCimExpectation(
        format_name="cisco_asa",
        data_model="Network_Traffic",
        object_name="All_Traffic",
        required_fields=("src", "dest", "dest_port", "transport", "action"),
    ),
    SplunkCimExpectation(
        format_name="web_access",
        data_model="Web",
        object_name="Web",
        required_fields=("src", "url", "http_method", "status"),
    ),
)
CIM_EXPECTATIONS_BY_FORMAT = {
    expectation.format_name: expectation for expectation in CIM_EXPECTATIONS
}


def _noop_progress(_event_type: str, _data: dict[str, Any]) -> None:
    return


def run_splunk_parser(
    source_root: Path,
    work_dir: Path,
    *,
    cim_mode: CimMode = CimMode.AUTO,
    splunk_apps: tuple[Path, ...] = (),
    accept_splunk_license: bool = False,
    timeout_seconds: int = 180,
    runtime: str | None = None,
    progress_callback: ProgressCallback = _noop_progress,
) -> SplunkValidationResult:
    """Run Splunk against generated EvidenceForge logs and validate indexed output."""
    work_dir = work_dir.resolve()
    reset_splunk_run_directories(work_dir)
    staging_dir = work_dir / "stage"
    parsed_dir = work_dir / "parsed"
    pipeline_log_dir = work_dir / "pipeline-logs"
    search_results_dir = work_dir / "search-results"

    progress_callback("validator_step", {"description": "Staging files"})
    staged_logs, unsupported = stage_splunk_logs(source_root, staging_dir)
    progress_callback("validator_step", {"description": "Building Splunk app config"})
    generated_config = build_splunk_configs(
        work_dir,
        staged_logs,
        splunk_apps=splunk_apps,
    )
    if cim_mode == CimMode.REQUIRE and generated_config.supplied_app_count == 0:
        raise SplunkHarnessError(
            "CIM validation was required, but no --splunk-app paths were supplied"
        )
    manifest = SplunkStageManifest(
        data_root=staging_dir / "data",
        logs=staged_logs,
        unsupported_logs=unsupported,
        cim_mode=cim_mode,
        supplied_app_count=generated_config.supplied_app_count,
    )
    compose_run = create_splunk_compose_run(
        work_dir=work_dir,
        generated_config=generated_config,
        staged_data_dir=manifest.data_root,
        parsed_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        search_results_dir=search_results_dir,
        runtime=runtime,
        accept_splunk_license=accept_splunk_license,
    )
    try:
        run_splunk_compose(
            compose_run,
            expected_sourcetype_counts=manifest.expected_sourcetype_counts,
            timeout_seconds=timeout_seconds,
            progress_callback=progress_callback,
        )
        progress_callback("validator_step", {"description": "Validating Splunk search output"})
        observed_counts, cim_status = validate_splunk_output(manifest, compose_run)
    except SplunkParserError:
        progress_callback("validator_done", {"description": "Splunk failed"})
        raise
    finally:
        finalize_splunk_compose(compose_run)

    progress_callback("validator_done", {"description": "Splunk complete"})
    return SplunkValidationResult(
        manifest=manifest,
        output_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        search_results_dir=search_results_dir,
        observed_counts=observed_counts,
        cim_status=cim_status,
    )


def stage_splunk_logs(
    source_root: Path,
    staging_root: Path,
) -> tuple[tuple[StagedSplunkLog, ...], tuple[StagedSplunkLog, ...]]:
    """Copy Splunk-supported generated files into a monitored staging tree."""
    source_root = source_root.resolve()
    data_root = staging_root.resolve() / "data"
    data_root.mkdir(parents=True, exist_ok=True)
    logs: list[StagedSplunkLog] = []
    unsupported: list[StagedSplunkLog] = []
    seen: set[Path] = set()
    staged_paths: set[Path] = set()

    for spec in SPLUNK_SOURCE_SPECS:
        for source_name in spec.source_names:
            for source in sorted(source_root.rglob(source_name)):
                if source in seen:
                    continue
                seen.add(source)
                relative = source.relative_to(source_root)
                staged_relative = _staged_relative_path(relative, staged_paths)
                staged = data_root / staged_relative
                staged.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, staged)
                logs.append(
                    StagedSplunkLog(
                        source=source,
                        staged=staged,
                        host=_host_for_log_path(source_root, source, spec),
                        format_name=spec.format_name,
                        logtype=spec.logtype,
                        subtype=spec.subtype,
                        sourcetype=spec.sourcetype,
                        record_count=_count_records(
                            staged, skip_comments=spec.skip_comment_records
                        ),
                    )
                )

    for filename, logtype, subtype, format_name in SPLUNK_UNSUPPORTED_PATTERNS:
        for source in sorted(source_root.rglob(filename)):
            if source in seen:
                continue
            relative = source.relative_to(source_root)
            unsupported.append(
                StagedSplunkLog(
                    source=source,
                    staged=data_root / relative,
                    host=_host_for_path(source_root, source),
                    format_name=format_name,
                    logtype=logtype,
                    subtype=subtype,
                    sourcetype="",
                    record_count=_count_records(source),
                )
            )

    for source in sorted(source_root.rglob("*.bash_history")):
        if source in seen:
            continue
        relative = source.relative_to(source_root)
        unsupported.append(
            StagedSplunkLog(
                source=source,
                staged=data_root / relative,
                host=_host_for_path(source_root, source),
                format_name="bash_history",
                logtype="bash history",
                subtype="bash_history",
                sourcetype="",
                record_count=_count_records(source),
            )
        )

    if not logs:
        expected_names = ", ".join(sorted(SPLUNK_SOURCE_SPECS_BY_NAME))
        raise SplunkHarnessError(
            f"no Splunk-supported generated files found below {source_root}; "
            f"expected one of: {expected_names}"
        )
    return tuple(logs), tuple(unsupported)


def build_splunk_configs(
    work_dir: Path,
    staged_logs: tuple[StagedSplunkLog, ...],
    *,
    splunk_apps: tuple[Path, ...] = (),
) -> SplunkGeneratedConfig:
    """Write EvidenceForge-owned Splunk app configs for one parser run."""
    config_root = work_dir.resolve() / "runtime-config-src"
    app_dir = config_root / "apps" / SPLUNK_APP_NAME
    local_dir = app_dir / "local"
    local_dir.mkdir(parents=True, exist_ok=True)
    supplied_apps_dir = config_root / "supplied-apps"
    supplied_apps_dir.mkdir(parents=True, exist_ok=True)
    supplied_app_count = stage_splunk_apps(splunk_apps, supplied_apps_dir)

    inputs_conf = local_dir / "inputs.conf"
    props_conf = local_dir / "props.conf"
    transforms_conf = local_dir / "transforms.conf"
    indexes_conf = local_dir / "indexes.conf"
    server_conf = local_dir / "server.conf"
    inputs_conf.write_text(
        _inputs_conf(staged_logs, work_dir.resolve() / "stage" / "data"),
        encoding="utf-8",
    )
    props_conf.write_text(_props_conf(), encoding="utf-8")
    transforms_conf.write_text(_transforms_conf(), encoding="utf-8")
    indexes_conf.write_text(_indexes_conf(), encoding="utf-8")
    server_conf.write_text(_server_conf(), encoding="utf-8")
    (app_dir / "metadata").mkdir(exist_ok=True)
    (app_dir / "metadata" / "default.meta").write_text(
        "[]\naccess = read : [ * ], write : [ admin ]\n",
        encoding="utf-8",
    )
    return SplunkGeneratedConfig(
        root=config_root,
        app_dir=app_dir,
        local_dir=local_dir,
        inputs_conf=inputs_conf,
        props_conf=props_conf,
        transforms_conf=transforms_conf,
        indexes_conf=indexes_conf,
        server_conf=server_conf,
        supplied_apps_dir=supplied_apps_dir,
        supplied_app_count=supplied_app_count,
    )


def stage_splunk_apps(app_paths: tuple[Path, ...], destination_root: Path) -> int:
    """Copy or unpack user-supplied Splunk apps into ephemeral runtime state."""
    count = 0
    for app_path in app_paths:
        source = app_path.expanduser().resolve()
        if not source.exists():
            raise SplunkHarnessError(f"supplied Splunk app path does not exist: {source}")
        if source.is_dir():
            destination = _unique_app_destination(destination_root, source.name)
            shutil.copytree(source, destination, symlinks=False)
            count += 1
            continue
        extracted = _extract_app_archive(source, destination_root)
        count += len(extracted)
    return count


def validate_splunk_output(
    manifest: SplunkStageManifest,
    compose_run: SplunkComposeRun,
) -> tuple[dict[str, int], str]:
    """Validate Splunk ingest counts, metadata, parser warnings, and CIM mode."""
    observed = observed_sourcetype_counts(compose_run)
    failures: list[str] = []
    for sourcetype, expected in manifest.expected_sourcetype_counts.items():
        got = observed.get(sourcetype, 0)
        if got != expected:
            failures.append(f"{sourcetype}: expected {expected} indexed events, got {got}")

    metadata_rows = export_search(
        compose_run,
        _metadata_validation_search(tuple(manifest.expected_sourcetype_counts)),
        output_name="metadata-validation",
    )
    failures.extend(_metadata_failures(metadata_rows))

    field_rows = export_search(
        compose_run,
        _required_field_validation_search(
            manifest.logs,
            use_supplied_app_sourcetypes=manifest.supplied_app_count > 0,
        ),
        output_name="required-field-validation",
    )
    failures.extend(_field_failures(field_rows))

    internal_rows = _search_result_rows(
        export_search(
            compose_run,
            _internal_issue_search(),
            output_name="internal-parser-issues",
        )
    )
    if internal_rows:
        failures.append(f"Splunk _internal reported {len(internal_rows)} parser issue row(s)")

    cim_status = _validate_cim(manifest, compose_run, failures)

    if failures:
        report_path = _write_failure_report(
            manifest,
            compose_run.parsed_dir,
            expected=manifest.expected_sourcetype_counts,
            observed=observed,
            failures=failures,
            cim_status=cim_status,
            internal_rows=internal_rows,
        )
        raise SplunkParserError(
            "Splunk parser validation failed; "
            f"failure report written to {report_path}:\n- " + "\n- ".join(failures[:20])
        )

    _write_success_report(manifest, compose_run.parsed_dir, observed, cim_status)
    return observed, cim_status


def _inputs_conf(staged_logs: tuple[StagedSplunkLog, ...], data_root: Path) -> str:
    lines = []
    for log in staged_logs:
        stanza_path = Path("/evidenceforge-data") / log.staged.relative_to(data_root)
        lines.extend(
            (
                f"[monitor://{stanza_path}]",
                "disabled = 0",
                f"index = {SPLUNK_INDEX}",
                f"sourcetype = {log.sourcetype}",
                f"host = {log.host}",
                f"crcSalt = <SOURCE>{log.sourcetype}",
                "",
            )
        )
    return "\n".join(lines)


def _props_conf() -> str:
    zeek_stanzas = "\n".join(
        f"""[{sourcetype}]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TRUNCATE = 0
KV_MODE = json
TIME_PREFIX = "ts"\\s*:\\s*
TIME_FORMAT = %s.%Q
MAX_TIMESTAMP_LOOKAHEAD = 24
"""
        for sourcetype in sorted(set(ZEEK_SPLUNK_SOURCETYPES.values()))
    )
    return f"""[default]
CHARSET = UTF-8
TRUNCATE = 0
MAX_DAYS_AGO = 3650
MAX_DAYS_HENCE = 3650

{zeek_stanzas}
[evidenceforge:ecar:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TRUNCATE = 0
KV_MODE = json

[XmlWinEventLog:Security]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TRUNCATE = 0
KV_MODE = xml
EXTRACT-evidenceforge-windows-base = <EventID>(?<EventID>\\d+)</EventID>.*<Computer>(?<Computer>[^<]*)</Computer>
TIME_PREFIX = <TimeCreated SystemTime="
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7N%Z
MAX_TIMESTAMP_LOOKAHEAD = 32

[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TRUNCATE = 0
KV_MODE = xml
EXTRACT-evidenceforge-windows-base = <EventID>(?<EventID>\\d+)</EventID>.*<Computer>(?<Computer>[^<]*)</Computer>
TIME_PREFIX = <TimeCreated SystemTime="
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7N%Z
MAX_TIMESTAMP_LOOKAHEAD = 32

[syslog]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
EXTRACT-evidenceforge-rfc5424 = ^<(?<pri>\\d+)>1\\s+\\S+\\s+\\S+\\s+(?<app>\\S+)\\s+(?<pid>\\S+)\\s+\\S+\\s+\\S+\\s+(?<message>.*)$
TIME_PREFIX = ^<\\d+>1\\s+
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z
MAX_TIMESTAMP_LOOKAHEAD = 32

[cisco:asa]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
EXTRACT-evidenceforge-asa = ^<(?<pri>\\d+)>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+\\s+\\S+\\s+%ASA-\\d+-(?<asa_msg_id>\\d+):\\s+(?<message>.*)$
TIME_PREFIX = ^<\\d+>
TIME_FORMAT = %b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 15

[access_combined]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
EXTRACT-evidenceforge-web = ^(?<src_ip>\\S+)\\s+\\S+\\s+(?<user>\\S+)\\s+\\[[^\\]]+\\]\\s+"(?<http_method>\\S+)\\s+(?<uri>\\S+)\\s+(?<http_version>[^"]+)"\\s+(?<status>\\d{{3}})\\s+(?<bytes>\\S+)\\s+"(?<referrer>[^"]*)"\\s+"(?<user_agent>[^"]*)"
TIME_PREFIX = \\[
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
MAX_TIMESTAMP_LOOKAHEAD = 32

[evidenceforge:proxy:w3c]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\\r\\n]+)
TRANSFORMS-evidenceforge-proxy-comments = evidenceforge_proxy_comment_drop
EXTRACT-evidenceforge-proxy = ^(?<date>\\d{{4}}-\\d{{2}}-\\d{{2}})\\s+(?<time>\\d{{2}}:\\d{{2}}:\\d{{2}})\\s+(?<src_ip>\\S+)\\s+(?<user>\\S+)\\s+(?<http_method>\\S+)\\s+(?<uri>\\S+)\\s+(?<http_version>\\S+)\\s+(?<status>\\d{{3}})\\s+(?<bytes_out>\\d+)\\s+(?<bytes_in>\\d+)\\s+(?<duration_ms>\\d+)\\s+(?<dest_host>\\S+)\\s+(?<user_agent>\\S+)\\s+(?<referrer>\\S+)\\s+(?<content_type>\\S+)\\s+(?<cache_result>\\S+)\\s+(?<proxy_action>\\S+)
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 20
"""


def _transforms_conf() -> str:
    return r"""[evidenceforge_proxy_comment_drop]
REGEX = ^#
DEST_KEY = queue
FORMAT = nullQueue
"""


def _indexes_conf() -> str:
    return f"""[{SPLUNK_INDEX}]
homePath = $SPLUNK_DB/{SPLUNK_INDEX}/db
coldPath = $SPLUNK_DB/{SPLUNK_INDEX}/colddb
thawedPath = $SPLUNK_DB/{SPLUNK_INDEX}/thaweddb
"""


def _server_conf() -> str:
    return """[general]
allowRemoteLogin = always
"""


def _metadata_validation_search(sourcetypes: tuple[str, ...]) -> str:
    quoted = ",".join(json.dumps(sourcetype) for sourcetype in sourcetypes)
    return (
        f"search index={SPLUNK_INDEX} sourcetype IN ({quoted}) "
        "| eval empty_raw=if(isnull(_raw) OR len(_raw)=0,1,0) "
        "| eval missing_time=if(isnull(_time),1,0) "
        '| eval missing_host=if(isnull(host) OR host="",1,0) '
        '| eval missing_source=if(isnull(source) OR source="",1,0) '
        "| stats count sum(empty_raw) as empty_raw sum(missing_time) as missing_time "
        "sum(missing_host) as missing_host sum(missing_source) as missing_source by sourcetype"
    )


def _required_field_validation_search(
    logs: tuple[StagedSplunkLog, ...],
    *,
    use_supplied_app_sourcetypes: bool = False,
) -> str:
    sourcetypes = sorted(
        {
            _validation_sourcetype(
                SPLUNK_SOURCE_SPECS_BY_FORMAT[log.format_name],
                use_supplied_app_sourcetypes=use_supplied_app_sourcetypes,
            )
            for log in logs
        }
    )
    quoted = ",".join(json.dumps(sourcetype) for sourcetype in sourcetypes)
    extractions = [
        'rex field=_raw "<EventID>(?<EventID>\\d+)</EventID>.*<Computer>(?<Computer>[^<]*)</Computer>"',
        'rex field=_raw "^<(?<pri>\\d+)>1\\s+\\S+\\s+\\S+\\s+(?<app>\\S+)\\s+(?<pid>\\S+)\\s+\\S+\\s+\\S+\\s+(?<message>.*)$"',
        'rex field=_raw "^<(?<pri>\\d+)>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+\\s+\\S+\\s+%ASA-\\d+-(?<asa_msg_id>\\d+):\\s+(?<message>.*)$"',
        'rex field=_raw "^(?<src_ip>\\S+)\\s+\\S+\\s+(?<user>\\S+)\\s+\\[[^\\]]+\\]\\s+\\"(?<http_method>\\S+)\\s+(?<uri>\\S+)\\s+(?<http_version>[^\\"]+)\\"\\s+(?<status>\\d{3})\\s+(?<bytes>\\S+)\\s+\\"(?<referrer>[^\\"]*)\\"\\s+\\"(?<user_agent>[^\\"]*)\\""',
        'rex field=_raw "^(?<date>\\d{4}-\\d{2}-\\d{2})\\s+(?<time>\\d{2}:\\d{2}:\\d{2})\\s+(?<src_ip>\\S+)\\s+(?<user>\\S+)\\s+(?<http_method>\\S+)\\s+(?<uri>\\S+)\\s+(?<http_version>\\S+)\\s+(?<status>\\d{3})\\s+(?<bytes_out>\\d+)\\s+(?<bytes_in>\\d+)\\s+(?<duration_ms>\\d+)\\s+(?<dest_host>\\S+)\\s+(?<user_agent>\\S+)\\s+(?<referrer>\\S+)\\s+(?<content_type>\\S+)\\s+(?<cache_result>\\S+)\\s+(?<proxy_action>\\S+)"',
    ]
    evals = [
        (
            spec,
            _validation_sourcetype(
                spec,
                use_supplied_app_sourcetypes=use_supplied_app_sourcetypes,
            ),
        )
        for spec in SPLUNK_SOURCE_SPECS
        if spec.required_fields
    ]
    eval_commands = [
        f"eval missing_{_field_token(spec.format_name)}=if("
        f"sourcetype={json.dumps(sourcetype)},if("
        + " OR ".join(
            f'isnull({_spl_field(field)}) OR {_spl_field(field)}=""'
            for field in spec.required_fields
        )
        + ",1,0),0)"
        for spec, sourcetype in evals
        if sourcetype in sourcetypes
    ]
    sums = " ".join(
        f"sum(missing_{_field_token(spec.format_name)}) as missing_{_field_token(spec.format_name)}"
        for spec, sourcetype in evals
        if sourcetype in sourcetypes
    )
    return (
        f"search index={SPLUNK_INDEX} sourcetype IN ({quoted}) "
        + " | ".join(["", *extractions, *eval_commands])
        + f" | stats count {sums} by sourcetype"
    )


def _internal_issue_search() -> str:
    return (
        "search index=_internal sourcetype=splunkd "
        "(component=DateParserVerbose OR component=LineBreakingProcessor OR "
        "component=AggregatorMiningProcessor OR component=TailReader) "
        "(ERROR OR WARN) evidenceforge"
        " | head 50 | table _time component log_level message _raw"
    )


def _cim_dataset_validation_search(
    expectation: SplunkCimExpectation,
    *,
    sourcetype: str,
) -> str:
    field_missing_counts = [
        f"count(eval({_missing_cim_field_expr(expectation.object_name, field)})) "
        f"as missing_{_field_token(field)}"
        for field in expectation.required_fields
    ]
    source_clause = ""
    if expectation.source_filter:
        source_clause = f" source={json.dumps(expectation.source_filter)}"
    return (
        f"| datamodel {expectation.data_model} {expectation.object_name} search "
        f"| search index={SPLUNK_INDEX} sourcetype={json.dumps(sourcetype)}{source_clause} "
        f"| stats count as cim_count {' '.join(field_missing_counts)}"
    )


def _cim_model_search() -> str:
    return (
        "| rest /services/datamodel/model "
        "| search title IN (Authentication,Network_Traffic,Web,Endpoint,Change,Intrusion_Detection) "
        "| table title eai:acl.app"
    )


def _validate_cim(
    manifest: SplunkStageManifest,
    compose_run: SplunkComposeRun,
    failures: list[str],
) -> str:
    if manifest.cim_mode == CimMode.OFF:
        return "off"
    if manifest.supplied_app_count == 0:
        if manifest.cim_mode == CimMode.REQUIRE:
            failures.append("CIM validation required but no supplied Splunk apps were installed")
            return "missing-required-apps"
        return "skipped-no-supplied-apps"

    rows = export_search(compose_run, _cim_model_search(), output_name="cim-data-models")
    model_names = {
        str(row.get("result", {}).get("title") or "")
        for row in rows
        if isinstance(row.get("result"), dict)
    }
    if not model_names:
        failures.append("CIM mode had supplied apps but no CIM data models were visible")
        return "failed-no-data-models"
    dataset_checks = _validate_cim_datasets(manifest, compose_run, failures)
    status_parts = [f"checked-models:{','.join(sorted(model_names))}"]
    if dataset_checks:
        status_parts.append(f"checked-datasets:{','.join(dataset_checks)}")
    return ";".join(status_parts)


def _validate_cim_datasets(
    manifest: SplunkStageManifest,
    compose_run: SplunkComposeRun,
    failures: list[str],
) -> tuple[str, ...]:
    checked: list[str] = []
    expected_counts = manifest.expected_counts
    use_supplied_app_sourcetypes = manifest.supplied_app_count > 0
    for expectation in CIM_EXPECTATIONS:
        expected_count = expected_counts.get(expectation.format_name, 0)
        if expected_count == 0:
            continue
        spec = SPLUNK_SOURCE_SPECS_BY_FORMAT[expectation.format_name]
        sourcetype = _validation_sourcetype(
            spec,
            use_supplied_app_sourcetypes=use_supplied_app_sourcetypes,
        )
        rows = _search_result_rows(
            export_search(
                compose_run,
                _cim_dataset_validation_search(
                    expectation,
                    sourcetype=sourcetype,
                ),
                output_name=f"cim-{_field_token(expectation.format_name)}",
            )
        )
        checked.append(f"{expectation.data_model}.{expectation.object_name}")
        failures.extend(
            _cim_dataset_failures(
                expectation,
                rows,
                expected_count=expected_count,
            )
        )
    return tuple(sorted(set(checked)))


def _metadata_failures(rows: list[JsonObject]) -> list[str]:
    failures: list[str] = []
    for row in rows:
        result = row.get("result", row)
        if not isinstance(result, dict):
            continue
        sourcetype = str(result.get("sourcetype") or "unknown")
        for field in ("empty_raw", "missing_time", "missing_host", "missing_source"):
            if _int_value(result.get(field)) > 0:
                failures.append(f"{sourcetype}: {result[field]} event(s) failed {field}")
    return failures


def _field_failures(rows: list[JsonObject]) -> list[str]:
    failures: list[str] = []
    for row in rows:
        result = row.get("result", row)
        if not isinstance(result, dict):
            continue
        sourcetype = str(result.get("sourcetype") or "unknown")
        for field, value in result.items():
            if field.startswith("missing_") and _int_value(value) > 0:
                failures.append(f"{sourcetype}: {value} event(s) missing fields for {field}")
    return failures


def _cim_dataset_failures(
    expectation: SplunkCimExpectation,
    rows: list[JsonObject],
    *,
    expected_count: int,
) -> list[str]:
    dataset = f"{expectation.data_model}.{expectation.object_name}"
    if not rows:
        return [
            f"{expectation.format_name}: expected {expected_count} event(s) in CIM {dataset}, got 0"
        ]
    result = rows[0].get("result", rows[0])
    if not isinstance(result, dict):
        return [f"{expectation.format_name}: CIM {dataset} returned no result object"]

    failures: list[str] = []
    cim_count = _int_value(result.get("cim_count"))
    if cim_count < expected_count:
        failures.append(
            f"{expectation.format_name}: expected {expected_count} event(s) in CIM "
            f"{dataset}, got {cim_count}"
        )
    for field in expectation.required_fields:
        missing = _int_value(result.get(f"missing_{_field_token(field)}"))
        if missing > 0:
            failures.append(
                f"{expectation.format_name}: {missing} CIM {dataset} event(s) missing {field}"
            )
    return failures


def _search_result_rows(rows: list[JsonObject]) -> list[JsonObject]:
    return [row for row in rows if isinstance(row.get("result"), dict)]


def _validation_sourcetype(
    spec: SplunkSourceSpec,
    *,
    use_supplied_app_sourcetypes: bool,
) -> str:
    if use_supplied_app_sourcetypes and spec.supplied_app_sourcetype:
        return spec.supplied_app_sourcetype
    return spec.sourcetype


def _write_failure_report(
    manifest: SplunkStageManifest,
    parsed_dir: Path,
    *,
    expected: dict[str, int],
    observed: dict[str, int],
    failures: list[str],
    cim_status: str,
    internal_rows: list[JsonObject],
) -> Path:
    parsed_dir.mkdir(parents=True, exist_ok=True)
    report_path = parsed_dir / SPLUNK_FAILURE_REPORT_FILENAME
    report = _base_report(manifest, observed, cim_status)
    report.update(
        {
            "expected_sourcetype_counts": expected,
            "failure_count": len(failures),
            "failures": failures,
            "internal_issue_samples": internal_rows[:10],
        }
    )
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report_path


def _write_success_report(
    manifest: SplunkStageManifest,
    parsed_dir: Path,
    observed: dict[str, int],
    cim_status: str,
) -> None:
    parsed_dir.mkdir(parents=True, exist_ok=True)
    report = _base_report(manifest, observed, cim_status)
    report["failure_count"] = 0
    (parsed_dir / "splunk_validation_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _base_report(
    manifest: SplunkStageManifest,
    observed: dict[str, int],
    cim_status: str,
) -> JsonObject:
    return {
        "validator": SPLUNK_VALIDATOR_NAME,
        "expected_counts": manifest.expected_counts,
        "expected_sourcetype_counts": manifest.expected_sourcetype_counts,
        "observed_sourcetype_counts": observed,
        "cim_mode": manifest.cim_mode.value,
        "cim_status": cim_status,
        "supplied_app_count": manifest.supplied_app_count,
        "staged_logs": [
            {
                "source": str(log.source),
                "staged": str(log.staged),
                "format_name": log.format_name,
                "sourcetype": log.sourcetype,
                "record_count": log.record_count,
            }
            for log in manifest.logs
        ],
        "unsupported_logs": [
            {
                "source": str(log.source),
                "format_name": log.format_name,
                "record_count": log.record_count,
            }
            for log in manifest.unsupported_logs
        ],
    }


def require_splunk_output_target(data_dir: Path) -> OutputTarget:
    """Return the output target and fail unless it is the Splunk target."""
    output_target = read_output_target_marker(data_dir)
    if output_target != OutputTarget.SPLUNK:
        raise SplunkHarnessError(
            "Splunk external parser validation requires data generated with "
            "`uv run eforge generate <scenario.yaml> --target splunk`"
        )
    return output_target


def _extract_app_archive(source: Path, destination_root: Path) -> tuple[Path, ...]:
    temp_dir = destination_root / f".extract-{source.stem}"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)
    try:
        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                _safe_zip_extract(archive, temp_dir)
        elif tarfile.is_tarfile(source):
            with tarfile.open(source) as archive:
                _safe_tar_extract(archive, temp_dir)
        else:
            raise SplunkHarnessError(f"unsupported Splunk app archive type: {source}")
        roots = [path for path in temp_dir.iterdir() if path.is_dir()]
        extracted: list[Path] = []
        for root in roots:
            destination = _unique_app_destination(destination_root, root.name)
            shutil.move(str(root), destination)
            extracted.append(destination)
        return tuple(extracted)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _safe_zip_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if not target.is_relative_to(destination):
            raise SplunkHarnessError(f"unsafe path in Splunk app archive: {member.filename}")
    archive.extractall(destination)


def _safe_tar_extract(archive: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if not target.is_relative_to(destination):
            raise SplunkHarnessError(f"unsafe path in Splunk app archive: {member.name}")
    archive.extractall(destination)


def _unique_app_destination(destination_root: Path, app_name: str) -> Path:
    safe = app_name.replace("/", "_").replace("\\", "_")
    candidate = destination_root / safe
    suffix = 1
    while candidate.exists():
        suffix += 1
        candidate = destination_root / f"{safe}-{suffix}"
    return candidate


def _count_records(path: Path, *, skip_comments: bool = False) -> int:
    with path.open("r", encoding="utf-8") as handle:
        return sum(
            1
            for line in handle
            if line.strip() and not (skip_comments and line.lstrip().startswith("#"))
        )


def _host_for_path(data_dir: Path, path: Path) -> str:
    relative = path.relative_to(data_dir)
    if len(relative.parts) == 1:
        return "default"
    if len(relative.parts) >= 3 and relative.parts[-2] == "bash_history":
        return relative.parts[0]
    if len(relative.parts) >= 3 and relative.parts[-2].isdigit() and len(relative.parts[-2]) == 4:
        return str(Path(*relative.parts[:-2]))
    return str(relative.parent)


def _host_for_log_path(data_dir: Path, path: Path, spec: SplunkSourceSpec) -> str:
    relative = path.relative_to(data_dir)
    if len(relative.parts) == 1:
        return spec.root_host
    return _host_for_path(data_dir, path)


def _staged_relative_path(relative: Path, staged_paths: set[Path]) -> Path:
    """Return a Splunk-mounted path with safe parent directories.

    EvidenceForge output paths are preserved as the source of truth. The Splunk
    harness stages copies under an ephemeral monitored tree, so parent directory
    names can be normalized without changing the generated dataset or Splunk host
    metadata.
    """
    if len(relative.parts) == 1:
        staged_paths.add(relative)
        return relative

    parent_parts = tuple(_safe_stage_part(part) for part in relative.parts[:-1])
    candidate = Path(*parent_parts, relative.name)
    if candidate not in staged_paths:
        staged_paths.add(candidate)
        return candidate

    digest = hashlib.sha256(relative.as_posix().encode("utf-8")).hexdigest()[:8]
    deduped_parent = (*parent_parts[:-1], f"{parent_parts[-1]}_{digest}")
    candidate = Path(*deduped_parent, relative.name)
    suffix = 1
    while candidate in staged_paths:
        suffix += 1
        candidate = Path(*deduped_parent[:-1], f"{deduped_parent[-1]}_{suffix}", relative.name)
    staged_paths.add(candidate)
    return candidate


def _safe_stage_part(value: str) -> str:
    safe = _SAFE_STAGE_PART_PATTERN.sub("_", value).strip("_")
    return safe or "source"


def _field_token(value: str) -> str:
    return value.replace("-", "_").replace(":", "_").replace("/", "_").replace(".", "_")


def _spl_field(value: str) -> str:
    return "'" + value.replace("'", "\\'") + "'"


def _cim_field_expr(object_name: str, field: str) -> str:
    return f"coalesce({_spl_field(f'{object_name}.{field}')},{_spl_field(field)})"


def _missing_cim_field_expr(object_name: str, field: str) -> str:
    value = _cim_field_expr(object_name, field)
    return f'isnull({value}) OR {value}=""'


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
