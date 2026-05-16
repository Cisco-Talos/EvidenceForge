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

"""Docker/Podman Compose runtime for external parser harnesses."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from evidenceforge.external_parsers.errors import SofElkHarnessError, SofElkParserError

SOF_ELK_PREP_IMAGE = "alpine/git:2.49.1"
SOF_ELK_CONTAINER_PATH = "/usr/local/sof-elk"
COMPOSE_RUNTIME_CONFIG_PATH = "/runtime-config"
COMPOSE_PROJECT_PREFIX = "eforge-sof-elk"
HARNESS_RUN_ID_LABEL = "evidenceforge.external_parser.run_id"
COMPOSE_REQUIRED_MESSAGE = (
    "Docker Compose or Podman Compose is required for external parser validation"
)

ProgressCallback = Callable[[str, dict[str, object]], None]


@dataclass(frozen=True)
class ComposeCommand:
    """A discovered Compose command."""

    runtime: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class SofElkGeneratedConfig:
    """Host-side EvidenceForge-owned runtime config inputs for the prep service."""

    root: Path
    pipeline_dir: Path
    filebeat_inputs_dir: Path
    filebeat_config: Path
    sof_elk_filter_files: tuple[str, ...]
    sof_elk_filebeat_inputs: tuple[str, ...]


@dataclass(frozen=True)
class SofElkComposeRun:
    """Generated Compose project metadata for a parser run."""

    compose: ComposeCommand
    project_name: str
    run_id: str
    work_dir: Path
    compose_file: Path
    prep_script: Path
    generated_config: SofElkGeneratedConfig


def find_compose_runtime(runtime: str | None = None) -> ComposeCommand:
    """Return the available Compose command, preferring Docker Compose."""
    candidates = (runtime,) if runtime else ("docker", "podman")
    for candidate in candidates:
        if candidate not in {"docker", "podman"}:
            continue
        command = (candidate, "compose")
        if _compose_available(command) and _runtime_available(candidate):
            return ComposeCommand(runtime=candidate, command=command)
    raise SofElkHarnessError(COMPOSE_REQUIRED_MESSAGE)


def build_generated_config(
    work_dir: Path,
    *,
    sof_elk_filter_files: tuple[str, ...],
    sof_elk_filebeat_inputs: tuple[str, ...],
    supplemental_filebeat_inputs: str = "",
    output_path: str = "/parsed-output/%{[labels][type]}.jsonl",
    capture_original: bool = True,
) -> SofElkGeneratedConfig:
    """Write EvidenceForge-owned configs consumed by the SOF-ELK prep service."""
    config_root = work_dir.resolve() / "runtime-config-src"
    pipeline_dir = config_root / "pipeline"
    filebeat_inputs_dir = config_root / "filebeat-inputs"
    pipeline_dir.mkdir(parents=True, exist_ok=True)
    filebeat_inputs_dir.mkdir(parents=True, exist_ok=True)

    (pipeline_dir / "0000-input-beats.conf").write_text(
        """input {
  beats {
    port => 5044
    tags => [ "process_archive", "filebeat" ]
  }
}
""",
        encoding="utf-8",
    )
    if capture_original:
        (pipeline_dir / "0001-capture-original.conf").write_text(
            """filter {
  if [message] {
    mutate {
      copy => { "message" => "[event][original]" }
    }
  }
}
""",
            encoding="utf-8",
        )
    if supplemental_filebeat_inputs:
        (filebeat_inputs_dir / "evidenceforge-zeek.yml").write_text(
            supplemental_filebeat_inputs,
            encoding="utf-8",
        )
    (pipeline_dir / "9999-output-jsonl.conf").write_text(
        f"""output {{
  file {{
    path => "{output_path}"
    codec => json_lines
  }}
}}
""",
        encoding="utf-8",
    )

    filebeat_config = config_root / "filebeat.yml"
    filebeat_config.write_text(
        f"""filebeat.config.inputs:
  enabled: true
  path: {COMPOSE_RUNTIME_CONFIG_PATH}/filebeat-inputs/*.yml
  reload.enabled: false

output.logstash:
  hosts: ["logstash:5044"]

logging.level: info
path.data: /usr/share/filebeat/data
""",
        encoding="utf-8",
    )
    return SofElkGeneratedConfig(
        root=config_root,
        pipeline_dir=pipeline_dir,
        filebeat_inputs_dir=filebeat_inputs_dir,
        filebeat_config=filebeat_config,
        sof_elk_filter_files=tuple(dict.fromkeys(sof_elk_filter_files)),
        sof_elk_filebeat_inputs=tuple(dict.fromkeys(sof_elk_filebeat_inputs)),
    )


def create_compose_run(
    *,
    work_dir: Path,
    generated_config: SofElkGeneratedConfig,
    logstash_root: Path,
    parsed_dir: Path,
    filebeat_data_dir: Path,
    logstash_data_dir: Path,
    repo_url: str,
    commit: str,
    filebeat_image: str,
    logstash_image: str,
    runtime: str | None,
    container_label: str,
) -> SofElkComposeRun:
    """Generate compose.yaml and the SOF-ELK prep script for a parser run."""
    work_dir = work_dir.resolve()
    compose = find_compose_runtime(runtime)
    run_id = uuid.uuid4().hex[:12]
    project_name = f"{COMPOSE_PROJECT_PREFIX}-{run_id}"
    prep_script = work_dir / "prep-sof-elk.sh"
    compose_file = work_dir / "compose.yaml"
    prep_script.write_text(
        _prep_script(
            repo_url=repo_url,
            commit=commit,
            filter_files=generated_config.sof_elk_filter_files,
            filebeat_inputs=generated_config.sof_elk_filebeat_inputs,
        ),
        encoding="utf-8",
    )
    compose_file.write_text(
        _compose_yaml(
            generated_config=generated_config,
            logstash_root=logstash_root,
            parsed_dir=parsed_dir,
            filebeat_data_dir=filebeat_data_dir,
            logstash_data_dir=logstash_data_dir,
            prep_script=prep_script,
            filebeat_image=filebeat_image,
            logstash_image=logstash_image,
            container_label=container_label,
            run_id=run_id,
        ),
        encoding="utf-8",
    )
    return SofElkComposeRun(
        compose=compose,
        project_name=project_name,
        run_id=run_id,
        work_dir=work_dir,
        compose_file=compose_file,
        prep_script=prep_script,
        generated_config=generated_config,
    )


def run_sof_elk_compose(
    compose_run: SofElkComposeRun,
    *,
    expected_output_counts: Mapping[str, int],
    parsed_dir: Path,
    pipeline_log_dir: Path,
    timeout_seconds: int,
    progress_callback: ProgressCallback,
) -> None:
    """Run prep, Logstash config validation, Filebeat, and Logstash through Compose."""
    try:
        progress_callback("validator_step", {"description": "Preparing SOF-ELK assets"})
        _compose_run(compose_run, ["run", "--rm", "prep"], description="prepare SOF-ELK assets")
        progress_callback("validator_step", {"description": "Validating Logstash config"})
        _compose_run(
            compose_run,
            ["run", "--rm", "logstash-test"],
            description="validate Logstash parser config",
            timeout=600,
        )
        progress_callback("validator_step", {"description": "Running Filebeat and Logstash"})
        _compose_run(compose_run, ["up", "-d", "logstash"], description="start Logstash parser")
        _wait_for_logstash(compose_run, timeout_seconds)
        _compose_run(compose_run, ["up", "-d", "filebeat"], description="start Filebeat parser")
        _wait_for_expected_output(expected_output_counts, parsed_dir, timeout_seconds)
    finally:
        pipeline_log_dir.mkdir(parents=True, exist_ok=True)
        (pipeline_log_dir / "filebeat.log").write_text(
            _compose_logs(compose_run, "filebeat"),
            encoding="utf-8",
        )
        (pipeline_log_dir / "logstash.log").write_text(
            _compose_logs(compose_run, "logstash"),
            encoding="utf-8",
        )
        _compose_down(compose_run)


def _compose_args(compose_run: SofElkComposeRun, args: list[str]) -> list[str]:
    return [
        *compose_run.compose.command,
        "-f",
        str(compose_run.compose_file),
        "-p",
        compose_run.project_name,
        *args,
    ]


def _compose_run(
    compose_run: SofElkComposeRun,
    args: list[str],
    *,
    description: str,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(_compose_args(compose_run, args), description=description, timeout=timeout)


def _compose_logs(compose_run: SofElkComposeRun, service: str) -> str:
    completed = subprocess.run(
        _compose_args(compose_run, ["logs", "--no-color", service]),
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout + completed.stderr


def _compose_down(compose_run: SofElkComposeRun) -> None:
    subprocess.run(
        _compose_args(compose_run, ["down", "-v", "--remove-orphans"]),
        check=False,
        capture_output=True,
        text=True,
    )


def _wait_for_logstash(compose_run: SofElkComposeRun, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    ready_markers = (
        "Starting server on port: 5044",
        "Beats inputs: Starting input listener",
        "Pipeline started",
    )
    last_logs = ""
    while time.monotonic() < deadline:
        last_logs = _compose_logs(compose_run, "logstash")
        if any(marker in last_logs for marker in ready_markers):
            return
        time.sleep(1)
    raise SofElkHarnessError(
        "Logstash did not start its Beats listener before timeout. "
        f"Recent logs:\n{last_logs[-4000:]}"
    )


def _wait_for_expected_output(
    expected_output_counts: Mapping[str, int],
    parsed_dir: Path,
    timeout_seconds: int,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if all(
            _count_jsonl_lines(parsed_dir / f"{output_type}.jsonl") >= count
            for output_type, count in expected_output_counts.items()
        ):
            return
        time.sleep(1)

    observed = {
        output_type: _count_jsonl_lines(parsed_dir / f"{output_type}.jsonl")
        for output_type in expected_output_counts
    }
    raise SofElkParserError(
        f"SOF-ELK output timed out after {timeout_seconds}s; "
        f"expected {dict(expected_output_counts)}, observed {observed}"
    )


def _count_jsonl_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _prep_script(
    *,
    repo_url: str,
    commit: str,
    filter_files: tuple[str, ...],
    filebeat_inputs: tuple[str, ...],
) -> str:
    filter_args = " ".join(_shell_quote(filename) for filename in filter_files)
    input_args = " ".join(_shell_quote(filename) for filename in filebeat_inputs)
    return f"""set -eu

SOF_ELK_DIR=/sof-elk-checkout
find "$SOF_ELK_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +
git clone --filter=blob:none --no-checkout {_shell_quote(repo_url)} "$SOF_ELK_DIR"
git -C "$SOF_ELK_DIR" checkout {_shell_quote(commit)}
ACTUAL_COMMIT="$(git -C "$SOF_ELK_DIR" rev-parse HEAD)"
if [ "$ACTUAL_COMMIT" != {_shell_quote(commit)} ]; then
  echo "SOF-ELK checkout is $ACTUAL_COMMIT, expected {commit}" >&2
  exit 1
fi

rm -rf /runtime-config/pipeline /runtime-config/filebeat-inputs
mkdir -p /runtime-config/pipeline /runtime-config/filebeat-inputs
cp /evidenceforge-config/pipeline/*.conf /runtime-config/pipeline/
cp /evidenceforge-config/filebeat.yml /runtime-config/filebeat.yml
if [ -d /evidenceforge-config/filebeat-inputs ]; then
  cp /evidenceforge-config/filebeat-inputs/*.yml /runtime-config/filebeat-inputs/ 2>/dev/null || true
fi

for file in {filter_args}; do
  test -f "$SOF_ELK_DIR/configfiles/$file"
  cp "$SOF_ELK_DIR/configfiles/$file" "/runtime-config/pipeline/$file"
done

for file in {input_args}; do
  test -f "$SOF_ELK_DIR/lib/filebeat_inputs/$file"
  cp "$SOF_ELK_DIR/lib/filebeat_inputs/$file" "/runtime-config/filebeat-inputs/$file"
done
"""


def _compose_yaml(
    *,
    generated_config: SofElkGeneratedConfig,
    logstash_root: Path,
    parsed_dir: Path,
    filebeat_data_dir: Path,
    logstash_data_dir: Path,
    prep_script: Path,
    filebeat_image: str,
    logstash_image: str,
    container_label: str,
    run_id: str,
) -> str:
    labels = _labels_yaml(container_label, run_id, indent=6)
    prep_volumes = _volumes_yaml(
        (
            ("volume", "sof_elk_checkout", "/sof-elk-checkout", False),
            ("volume", "runtime_config", "/runtime-config", False),
            ("bind", generated_config.root, "/evidenceforge-config", True),
            ("bind", prep_script, "/prep-sof-elk.sh", True),
        ),
        indent=6,
    )
    logstash_volumes = _volumes_yaml(
        (
            ("volume", "runtime_config", COMPOSE_RUNTIME_CONFIG_PATH, True),
            ("volume", "sof_elk_checkout", SOF_ELK_CONTAINER_PATH, True),
            ("bind", parsed_dir, "/parsed-output", False),
            ("bind", logstash_data_dir, "/usr/share/logstash/data", False),
        ),
        indent=6,
    )
    filebeat_volumes = _volumes_yaml(
        (
            ("bind", logstash_root, "/logstash", True),
            ("volume", "runtime_config", COMPOSE_RUNTIME_CONFIG_PATH, True),
            ("volume", "sof_elk_checkout", SOF_ELK_CONTAINER_PATH, True),
            ("bind", filebeat_data_dir, "/usr/share/filebeat/data", False),
        ),
        indent=6,
    )
    return f"""services:
  prep:
    image: {_yaml_string(SOF_ELK_PREP_IMAGE)}
    entrypoint: ["/bin/sh"]
    command: ["/prep-sof-elk.sh"]
    labels:
{labels}
    volumes:
{prep_volumes}

  logstash-test:
    image: {_yaml_string(logstash_image)}
    command: ["-f", "{COMPOSE_RUNTIME_CONFIG_PATH}/pipeline", "--config.test_and_exit"]
    environment:
      LS_JAVA_OPTS: "-Xms512m -Xmx512m"
      XPACK_MONITORING_ENABLED: "false"
    labels:
{labels}
    volumes:
{logstash_volumes}

  logstash:
    image: {_yaml_string(logstash_image)}
    command: ["-f", "{COMPOSE_RUNTIME_CONFIG_PATH}/pipeline"]
    environment:
      LS_JAVA_OPTS: "-Xms512m -Xmx512m"
      XPACK_MONITORING_ENABLED: "false"
    labels:
{labels}
    volumes:
{logstash_volumes}

  filebeat:
    image: {_yaml_string(filebeat_image)}
    user: "root"
    command: ["-e", "-c", "{COMPOSE_RUNTIME_CONFIG_PATH}/filebeat.yml", "--strict.perms=false"]
    labels:
{labels}
    volumes:
{filebeat_volumes}

volumes:
  sof_elk_checkout: {{}}
  runtime_config: {{}}
"""


def _labels_yaml(container_label: str, run_id: str, *, indent: int) -> str:
    key, value = container_label.split("=", 1)
    spaces = " " * indent
    labels = (
        (key, value),
        (HARNESS_RUN_ID_LABEL, run_id),
    )
    return "\n".join(
        f"{spaces}{_yaml_string(label_key)}: {_yaml_string(label_value)}"
        for label_key, label_value in labels
    )


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


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _compose_available(command: tuple[str, ...]) -> bool:
    if shutil.which(command[0]) is None:
        return False
    try:
        completed = subprocess.run(
            [*command, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0


def _runtime_available(runtime: str) -> bool:
    try:
        completed = subprocess.run(
            [runtime, "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0


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
        raise SofElkHarnessError(f"{description} timed out after {timeout}s{detail}") from exc
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout.strip()
        stderr = exc.stderr.strip()
        output = "\n".join(part for part in (stdout, stderr) if part)
        if not output:
            output = f"exit code {exc.returncode}"
        raise SofElkHarnessError(f"failed to {description}: {output}") from exc


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
