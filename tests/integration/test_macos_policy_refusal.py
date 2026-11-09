# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented refusal output through the CLI; no native app or collector runs."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.formats.macos_unified_log import decode_unified_log_record
from tests.support.output_equivalence import deterministic_bundle_files

_IMAGE = "/Applications/ExampleRefused.app/Contents/MacOS/ExampleRefused"


@pytest.mark.slow
def test_policy_refusal_generation_preserves_caller_and_native_filter_equivalence(
    tmp_path: Path,
) -> None:
    data = yaml.safe_load(Path("scenarios/macos-workstation-example/scenario.yaml").read_text())
    data["macos_process_coverage"] = (
        "partial"  # This contract tests refusal, not all launch producers.
    )
    data["time_window"].update(duration="20m", warmup="1h")
    data["baseline_activity"]["suspicious_noise"] = "low"
    data["storyline"] = [
        dict(
            id="caller",
            time="+1m",
            actor="alex",
            system="MAC-01",
            activity="Existing initiator",
            events=[dict(type="process", process_name="/bin/zsh", process_ref="caller")],
        ),
        dict(
            id="refusal",
            time="+2m",
            actor="alex",
            system="MAC-01",
            activity="Explicit app-policy refusal",
            events=[
                dict(
                    type="process",
                    process_name=_IMAGE,
                    command_line=_IMAGE + " https://never-executed.example.test/payload",
                    parent_ref="caller",
                    outcome="policy_refused",
                )
            ],
        ),
    ]
    data["output"]["logs"].extend(
        [{"format": "macos_unified_log"}, {"format": "macos_endpoint_security"}]
    )
    scenario = tmp_path / "refusal.yaml"
    scenario.write_text(yaml.safe_dump(data))
    outputs = []
    for label, hash_seed, formats in [
        ("all", "11", ""),
        ("repeat", "97", ""),
        ("native", "23", "macos_unified_log"),
        ("ecar", "39", "ecar"),
    ]:
        output = tmp_path / label
        args = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "328",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats:
            args.extend(["--formats", formats])
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=180,
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(deterministic_bundle_files(output))
    assert outputs[0] == outputs[1]
    native = {
        name: value
        for name, value in outputs[0].items()
        if name.endswith("macos_unified_log.ndjson")
    }
    assert native == {
        name: value
        for name, value in outputs[2].items()
        if name.endswith("macos_unified_log.ndjson")
    }
    assert {name: value for name, value in outputs[0].items() if name.endswith("ecar.json")} == {
        name: value for name, value in outputs[3].items() if name.endswith("ecar.json")
    }
    records = [
        decode_unified_log_record(line)
        for content in native.values()
        for line in content.splitlines()
    ]
    refusals = [record for record in records if _IMAGE in record.event_message]
    assert len(refusals) == 1
    refusal = refusals[0]
    assert refusal.process_id == refusal.user_id == 0
    assert refusal.process_image_uuid != refusal.sender_image_uuid
    assert refusal.sender_image_path.endswith("/AppleSystemPolicy")
    assert refusal.trace_id & 0xFFFFFFFF == 0x00080004
    for name, content in outputs[0].items():
        if name.startswith("data/") and not name.endswith("macos_unified_log.ndjson"):
            assert _IMAGE.encode() not in content
        if name.startswith("data/"):
            assert b"never-executed.example.test" not in content
    truth = json.loads((tmp_path / "all" / "GROUND_TRUTH.json").read_text())
    event = next(event for event in truth["events"] if event["storyline_id"] == "refusal")
    assert event["emitted"] is True
    assert event["attributes"]["outcome"] == "policy_refused"
    assert (
        event["attributes"]["refusal_cause"]
        == event["attributes"]["execution_stage"]
        == "unclassified"
    )
    assert str(event["attributes"]["refused_target_pid"]) in refusal.event_message
