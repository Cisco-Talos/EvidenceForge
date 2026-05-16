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

"""Tests for the SOF-ELK Compose runtime."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from evidenceforge.external_parsers import compose_runtime
from evidenceforge.external_parsers.compose_runtime import (
    ComposeCommand,
    build_generated_config,
    create_compose_run,
    find_compose_runtime,
)
from evidenceforge.external_parsers.errors import SofElkHarnessError


def test_find_compose_runtime_prefers_docker_compose(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose_runtime.shutil, "which", lambda command: f"/usr/bin/{command}")

    def fake_run(
        cmd: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        assert cmd in (["docker", "compose", "version"], ["docker", "info"])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(compose_runtime.subprocess, "run", fake_run)

    command = find_compose_runtime()

    assert command == ComposeCommand(runtime="docker", command=("docker", "compose"))


def test_find_compose_runtime_supports_podman_compose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compose_runtime.shutil, "which", lambda command: f"/usr/bin/{command}")

    def fake_run(
        cmd: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        returncode = 0 if cmd[0] == "podman" else 1
        return subprocess.CompletedProcess(cmd, returncode, "", "")

    monkeypatch.setattr(compose_runtime.subprocess, "run", fake_run)

    command = find_compose_runtime()

    assert command == ComposeCommand(runtime="podman", command=("podman", "compose"))


def test_find_compose_runtime_errors_when_compose_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compose_runtime.shutil, "which", lambda _command: None)

    with pytest.raises(SofElkHarnessError, match="Docker Compose or Podman Compose"):
        find_compose_runtime()


def test_create_compose_run_writes_prep_and_compose_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        compose_runtime,
        "find_compose_runtime",
        lambda runtime=None: ComposeCommand(runtime or "docker", (runtime or "docker", "compose")),
    )
    generated_config = build_generated_config(
        tmp_path,
        sof_elk_filter_files=("1000-preprocess-all.conf", "6200-zeek_dns.conf"),
        sof_elk_filebeat_inputs=("zeek.yml",),
        supplemental_filebeat_inputs="- type: filestream\n",
    )

    compose_run = create_compose_run(
        work_dir=tmp_path,
        generated_config=generated_config,
        logstash_root=tmp_path / "stage" / "logstash",
        parsed_dir=tmp_path / "parsed",
        filebeat_data_dir=tmp_path / "filebeat-data",
        logstash_data_dir=tmp_path / "logstash-data",
        repo_url="https://github.com/philhagen/sof-elk.git",
        commit="517af9445574cc084cd5f4b80539fc244dab82b0",
        filebeat_image="docker.elastic.co/beats/filebeat:8.19.0",
        logstash_image="docker.elastic.co/logstash/logstash:8.19.0",
        runtime=None,
        container_label="evidenceforge.external_parser=sof-elk",
    )

    compose_yaml = compose_run.compose_file.read_text(encoding="utf-8")
    prep_script = compose_run.prep_script.read_text(encoding="utf-8")
    assert "prep:" in compose_yaml
    assert "logstash-test:" in compose_yaml
    assert "logstash:" in compose_yaml
    assert "filebeat:" in compose_yaml
    assert 'source: "sof_elk_checkout"' in compose_yaml
    assert 'source: "runtime_config"' in compose_yaml
    assert "alpine/git:2.49.1" in compose_yaml
    assert "/usr/local/sof-elk" in compose_yaml
    assert "SOF_ELK_DIR=/sof-elk-checkout" in prep_script
    assert 'find "$SOF_ELK_DIR" -mindepth 1' in prep_script
    assert "git clone --filter=blob:none --no-checkout" in prep_script
    assert "517af9445574cc084cd5f4b80539fc244dab82b0" in prep_script
    assert "1000-preprocess-all.conf" in prep_script
    assert "6200-zeek_dns.conf" in prep_script
    assert "zeek.yml" in prep_script
    input_config = (generated_config.pipeline_dir / "0000-input-beats.conf").read_text(
        encoding="utf-8"
    )
    assert 'tags => [ "process_archive", "filebeat" ]' in input_config
    assert not (generated_config.pipeline_dir / "1000-preprocess-all.conf").exists()
    assert not (generated_config.filebeat_inputs_dir / "zeek.yml").exists()
