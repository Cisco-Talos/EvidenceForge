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

"""Docker Compose runtime for the Splunk external parser harness."""

from __future__ import annotations

import base64
import json
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidenceforge.external_parsers.compose_runtime import ComposeCommand, find_compose_runtime
from evidenceforge.external_parsers.errors import SplunkHarnessError, SplunkParserError

SPLUNK_IMAGE = "splunk/splunk:10.2.3"
SPLUNK_PLATFORM = "linux/amd64"
SPLUNK_APP_NAME = "evidenceforge_parser_validation"
SPLUNK_INDEX = "eforge"
SPLUNK_CONTAINER_LABEL = "evidenceforge.external_parser=splunk"
SPLUNK_GENERAL_TERMS_ACCEPTANCE = "--accept-sgt-current-at-splunk-com"
COMPOSE_PROJECT_PREFIX = "eforge-splunk"
SPLUNK_MANAGEMENT_PORT = 8089
SPLUNK_USER = "admin"
SPLUNK_RUNTIME_DIR_NAMES = (
    "stage",
    "parsed",
    "pipeline-logs",
    "runtime-config-src",
    "search-results",
)

ProgressCallback = Callable[[str, dict[str, object]], None]
JsonObject = dict[str, Any]


@dataclass(frozen=True)
class SplunkGeneratedConfig:
    """Host-side generated Splunk app and optional supplied app paths."""

    root: Path
    app_dir: Path
    local_dir: Path
    inputs_conf: Path
    props_conf: Path
    transforms_conf: Path
    eventtypes_conf: Path
    tags_conf: Path
    indexes_conf: Path
    server_conf: Path
    supplied_apps_dir: Path
    supplied_app_count: int
    supplied_app_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class SplunkComposeRun:
    """Generated Compose project metadata for a Splunk parser run."""

    compose: ComposeCommand
    project_name: str
    run_id: str
    work_dir: Path
    compose_file: Path
    generated_config: SplunkGeneratedConfig
    staged_data_dir: Path
    parsed_dir: Path
    pipeline_log_dir: Path
    search_results_dir: Path
    password: str
    management_port: int


def reset_splunk_run_directories(work_dir: Path) -> None:
    """Clear and recreate transient Splunk parser state below a run work directory."""
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    for name in SPLUNK_RUNTIME_DIR_NAMES:
        path = work_dir / name
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)


def create_splunk_compose_run(
    *,
    work_dir: Path,
    generated_config: SplunkGeneratedConfig,
    staged_data_dir: Path,
    parsed_dir: Path,
    pipeline_log_dir: Path,
    search_results_dir: Path,
    runtime: str | None,
    accept_splunk_license: bool,
) -> SplunkComposeRun:
    """Generate Compose metadata and file for a Splunk parser run."""
    if not accept_splunk_license:
        raise SplunkHarnessError(
            "Splunk parser validation requires explicit Splunk license and General Terms "
            "acceptance. Re-run with --accept-splunk-license after reviewing Splunk's terms."
        )
    if runtime not in {None, "docker"}:
        raise SplunkHarnessError("Splunk parser validation currently supports Docker Compose only")

    work_dir = work_dir.resolve()
    compose = find_compose_runtime("docker")
    run_id = uuid.uuid4().hex[:12]
    project_name = f"{COMPOSE_PROJECT_PREFIX}-{run_id}"
    password = f"EforgeSplunk!{run_id}"
    management_port = _free_tcp_port()
    compose_file = work_dir / "compose.yaml"
    compose_file.write_text(
        _compose_yaml(
            generated_config=generated_config,
            staged_data_dir=staged_data_dir,
            password=password,
            management_port=management_port,
            run_id=run_id,
        ),
        encoding="utf-8",
    )
    return SplunkComposeRun(
        compose=compose,
        project_name=project_name,
        run_id=run_id,
        work_dir=work_dir,
        compose_file=compose_file,
        generated_config=generated_config,
        staged_data_dir=staged_data_dir,
        parsed_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        search_results_dir=search_results_dir,
        password=password,
        management_port=management_port,
    )


def run_splunk_compose(
    compose_run: SplunkComposeRun,
    *,
    expected_sourcetype_counts: Mapping[str, int],
    timeout_seconds: int,
    progress_callback: ProgressCallback,
) -> None:
    """Start Splunk through Compose and wait until staged records are indexed."""
    progress_callback("validator_step", {"description": "Starting Splunk"})
    _compose_run(compose_run, ["up", "-d", "splunk"], description="start Splunk")
    progress_callback("validator_step", {"description": "Waiting for Splunk REST API"})
    _wait_for_splunk(compose_run, timeout_seconds)
    progress_callback("validator_step", {"description": "Waiting for staged input ingest"})
    _wait_for_expected_counts(compose_run, expected_sourcetype_counts, timeout_seconds)


def finalize_splunk_compose(compose_run: SplunkComposeRun) -> None:
    """Capture Splunk runtime diagnostics and remove Compose containers/volumes."""
    try:
        _capture_runtime_artifacts(compose_run)
    finally:
        _compose_down(compose_run)


def export_search(
    compose_run: SplunkComposeRun,
    search: str,
    *,
    output_name: str,
    namespace_app: str | None = None,
) -> list[JsonObject]:
    """Run a Splunk REST search/export request and save the JSONL response."""
    rows = _rest_search_export(compose_run, search, namespace_app=namespace_app)
    output_path = compose_run.search_results_dir / f"{output_name}.jsonl"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")
    return rows


def _wait_for_splunk(compose_run: SplunkComposeRun, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            _rest_json(compose_run, "/services/server/info", {"output_mode": "json"})
            return
        except SplunkHarnessError as exc:
            last_error = str(exc)
            time.sleep(3)
    raise SplunkHarnessError(
        f"Splunk REST API did not become ready before timeout. Last error: {last_error}"
    )


def _wait_for_expected_counts(
    compose_run: SplunkComposeRun,
    expected_sourcetype_counts: Mapping[str, int],
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    observed: dict[str, int] = {}
    last_error = ""
    while time.monotonic() < deadline:
        try:
            observed = observed_sourcetype_counts(compose_run)
        except SplunkHarnessError as exc:
            last_error = str(exc)
            time.sleep(3)
            continue
        if all(
            observed.get(sourcetype, 0) >= count
            for sourcetype, count in expected_sourcetype_counts.items()
        ):
            return
        time.sleep(3)
    raise SplunkParserError(
        f"Splunk ingest timed out after {timeout_seconds}s; "
        f"expected {dict(expected_sourcetype_counts)}, observed {observed}. "
        f"Last REST error: {last_error}"
    )


def observed_sourcetype_counts(compose_run: SplunkComposeRun) -> dict[str, int]:
    """Return indexed event counts by sourcetype from Splunk."""
    rows = export_search(
        compose_run,
        f"search index={SPLUNK_INDEX} | stats count by sourcetype",
        output_name="sourcetype-counts",
    )
    counts: dict[str, int] = {}
    for row in rows:
        result = row.get("result", row)
        if not isinstance(result, dict):
            continue
        sourcetype = str(result.get("sourcetype") or "")
        if not sourcetype:
            continue
        counts[sourcetype] = _int_value(result.get("count"))
    return counts


def _rest_search_export(
    compose_run: SplunkComposeRun,
    search: str,
    *,
    namespace_app: str | None = None,
) -> list[JsonObject]:
    body = urllib.parse.urlencode(
        {
            "search": search,
            "output_mode": "json",
            "exec_mode": "oneshot",
            "earliest_time": "0",
            "latest_time": "+10y",
        }
    ).encode("utf-8")
    if namespace_app:
        app = urllib.parse.quote(namespace_app, safe="")
        path = f"/servicesNS/admin/{app}/search/jobs/export"
    else:
        path = "/services/search/jobs/export"
    payload = _rest_bytes(compose_run, path, body)
    rows: list[JsonObject] = []
    for line in payload.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SplunkParserError("Splunk search/export returned invalid JSON") from exc
        if isinstance(parsed, dict):
            rows.append(parsed)
    return rows


def _rest_json(
    compose_run: SplunkComposeRun,
    path: str,
    params: Mapping[str, str],
) -> JsonObject:
    query = urllib.parse.urlencode(params)
    payload = _rest_bytes(compose_run, f"{path}?{query}", None)
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SplunkHarnessError("Splunk REST API returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise SplunkHarnessError("Splunk REST API returned a non-object JSON response")
    return parsed


def _rest_bytes(compose_run: SplunkComposeRun, path: str, body: bytes | None) -> bytes:
    url = f"https://127.0.0.1:{compose_run.management_port}{path}"
    request = urllib.request.Request(url, data=body, method="POST" if body else "GET")
    credentials = f"{SPLUNK_USER}:{compose_run.password}".encode()
    request.add_header("Authorization", f"Basic {base64.b64encode(credentials).decode('ascii')}")
    if body is not None:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    last_error: urllib.error.URLError | TimeoutError | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2)
                continue
    raise SplunkHarnessError(f"failed Splunk REST request {path}: {last_error}") from last_error


def _capture_runtime_artifacts(compose_run: SplunkComposeRun) -> None:
    compose_run.pipeline_log_dir.mkdir(parents=True, exist_ok=True)
    (compose_run.pipeline_log_dir / "splunk-container.log").write_text(
        _compose_logs(compose_run, "splunk"),
        encoding="utf-8",
    )
    for config_name in ("inputs", "props", "transforms", "indexes", "server"):
        output = _compose_exec(
            compose_run,
            ["/opt/splunk/bin/splunk", "btool", config_name, "list", "--debug"],
            check=False,
        )
        (compose_run.pipeline_log_dir / f"btool-{config_name}.txt").write_text(
            output,
            encoding="utf-8",
        )
    splunkd = _compose_exec(
        compose_run,
        ["sh", "-c", "tail -n 2000 /opt/splunk/var/log/splunk/splunkd.log"],
        check=False,
    )
    (compose_run.pipeline_log_dir / "splunkd.log").write_text(splunkd, encoding="utf-8")


def _compose_args(compose_run: SplunkComposeRun, args: list[str]) -> list[str]:
    return [
        *compose_run.compose.command,
        "-f",
        str(compose_run.compose_file),
        "-p",
        compose_run.project_name,
        *args,
    ]


def _compose_run(
    compose_run: SplunkComposeRun,
    args: list[str],
    *,
    description: str,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(_compose_args(compose_run, args), description=description, timeout=timeout)


def _compose_exec(
    compose_run: SplunkComposeRun,
    args: list[str],
    *,
    check: bool,
) -> str:
    completed = subprocess.run(
        _compose_args(compose_run, ["exec", "-T", "--user", "splunk", "splunk", *args]),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = completed.stdout + completed.stderr
    if check and completed.returncode != 0:
        raise SplunkHarnessError(f"failed to run command in Splunk container: {output}")
    return output


def _compose_logs(compose_run: SplunkComposeRun, service: str) -> str:
    completed = subprocess.run(
        _compose_args(compose_run, ["logs", "--no-color", service]),
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout + completed.stderr


def _compose_down(compose_run: SplunkComposeRun) -> None:
    subprocess.run(
        _compose_args(compose_run, ["down", "-v", "--remove-orphans"]),
        check=False,
        capture_output=True,
        text=True,
    )


def _run(
    cmd: list[str],
    *,
    description: str,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        output = _timeout_output(exc)
        detail = f"\nPartial output:\n{output}" if output else ""
        raise SplunkHarnessError(f"{description} timed out after {timeout}s{detail}") from exc
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout.strip()
        stderr = exc.stderr.strip()
        output = "\n".join(part for part in (stdout, stderr) if part)
        if not output:
            output = f"exit code {exc.returncode}"
        raise SplunkHarnessError(f"failed to {description}: {output}") from exc


def _compose_yaml(
    *,
    generated_config: SplunkGeneratedConfig,
    staged_data_dir: Path,
    password: str,
    management_port: int,
    run_id: str,
) -> str:
    labels = _labels_yaml(run_id, indent=6)
    volumes = [
        ("bind", staged_data_dir, "/evidenceforge-data", True),
        ("bind", generated_config.app_dir, f"/opt/splunk/etc/apps/{SPLUNK_APP_NAME}", False),
    ]
    if generated_config.supplied_app_count:
        for app_dir in sorted(generated_config.supplied_apps_dir.iterdir()):
            if app_dir.is_dir():
                volumes.append(("bind", app_dir, f"/opt/splunk/etc/apps/{app_dir.name}", False))
    volumes_yaml = _volumes_yaml(tuple(volumes), indent=6)
    return f"""services:
  splunk:
    image: {_yaml_string(SPLUNK_IMAGE)}
    platform: {_yaml_string(SPLUNK_PLATFORM)}
    hostname: "eforge-splunk"
    environment:
      SPLUNK_START_ARGS: "--accept-license"
      SPLUNK_GENERAL_TERMS: {_yaml_string(SPLUNK_GENERAL_TERMS_ACCEPTANCE)}
      SPLUNK_PASSWORD: {_yaml_string(password)}
      SPLUNK_LICENSE_URI: "Free"
      SPLUNK_HEC_TOKEN: "unused-by-evidenceforge-file-monitor"
    ports:
      - "127.0.0.1:{management_port}:{SPLUNK_MANAGEMENT_PORT}"
    labels:
{labels}
    volumes:
{volumes_yaml}
"""


def _labels_yaml(run_id: str, *, indent: int) -> str:
    spaces = " " * indent
    labels = (
        ("evidenceforge.external_parser", "splunk"),
        ("evidenceforge.external_parser.run_id", run_id),
    )
    return "\n".join(f"{spaces}{_yaml_string(key)}: {_yaml_string(value)}" for key, value in labels)


def _volumes_yaml(
    volumes: tuple[tuple[str, str | Path, str, bool], ...],
    *,
    indent: int,
) -> str:
    spaces = " " * indent
    lines: list[str] = []
    for volume_type, source, target, read_only in volumes:
        lines.extend(
            (
                f"{spaces}- type: {volume_type}",
                f"{spaces}  source: {_yaml_string(str(source))}",
                f"{spaces}  target: {_yaml_string(target)}",
            )
        )
        if read_only:
            lines.append(f"{spaces}  read_only: true")
    return "\n".join(lines)


def _yaml_string(value: str) -> str:
    return json.dumps(value)


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
    parts: list[str] = []
    for value in (exc.stdout, exc.stderr):
        if not value:
            continue
        if isinstance(value, bytes):
            parts.append(value.decode("utf-8", errors="replace").strip())
        else:
            parts.append(value.strip())
    return "\n".join(part for part in parts if part)


def _int_value(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0
