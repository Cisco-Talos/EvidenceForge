"""Workflow contracts preserve gate ownership, provenance and shard completeness."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_routine_matrix_has_eight_unique_shards_for_each_platform() -> None:
    jobs = workflow("ci.yml")["jobs"]
    rows = jobs["tests"]["strategy"]["matrix"]["include"]
    assert len(rows) == 16
    for platform in ("ubuntu-latest", "windows-latest"):
        assert {row["index"] for row in rows if row["os"] == platform} == set(range(8))
    assert jobs["tests"]["timeout-minutes"] == 120
    assert {
        "tests",
        "coverage",
        "studio",
        "studio-state-recovery",
        "windows-checkpoint-durability",
    } <= set(jobs["ci-required"]["needs"])
    commands = "\n".join(step.get("run", "") for step in jobs["ci-required"]["steps"])
    assert "routine-windows-latest-plain" in commands and "--count 8" in commands


def test_coverage_is_combined_after_all_shards_before_the_unchanged_threshold() -> None:
    jobs = workflow("ci.yml")["jobs"]
    coverage = jobs["coverage"]
    assert coverage["needs"] == ["tests"]
    commands = "\n".join(step.get("run", "") for step in coverage["steps"])
    assert commands.index("ci_evidence validate") < commands.index("coverage combine")
    assert "--coverage" in commands and "--count 8" in commands
    assert "coverage report --show-missing --fail-under=70" in commands
    test_commands = "\n".join(step.get("run", "") for step in jobs["tests"]["steps"])
    assert "--cov-fail-under=0" in test_commands


def test_identical_checks_queue_without_cancelling_other_release_consumers() -> None:
    for name in ("ci.yml", "release-slow.yml", "ci-recovery.yml"):
        document = workflow(name)
        assert document["permissions"] == {"contents": "read", "actions": "read"}
        for job in document["jobs"].values():
            concurrency = job.get("concurrency")
            if concurrency:
                assert concurrency["queue"] == "max"
                assert not concurrency.get("cancel-in-progress", False)
                assert "needs.inputs.outputs.digest" in concurrency["group"]


def test_every_reusable_job_records_only_after_its_execution_and_uploads_proof() -> None:
    for name in ("ci.yml", "release-slow.yml", "ci-recovery.yml"):
        for job in workflow(name)["jobs"].values():
            if "CI_CHECK_ID" not in job.get("env", {}):
                continue
            steps = job["steps"]
            resolve = next(
                index for index, step in enumerate(steps) if step.get("id") == "evidence"
            )
            record = next(
                index
                for index, step in enumerate(steps)
                if step.get("name") == "Record verified execution"
            )
            upload = next(
                index
                for index, step in enumerate(steps)
                if step.get("name") == "Upload CI evidence"
            )
            assert resolve < record < upload
            executed = steps[resolve + 1 : record]
            assert any("steps.evidence.outputs.reused" in step.get("if", "") for step in executed)
            assert steps[upload]["with"]["if-no-files-found"] == "error"


def test_native_recovery_has_one_shared_owner_and_retains_platform_variants() -> None:
    ci = workflow("ci.yml")["jobs"]
    native = ci["studio-state-recovery"]
    assert native["uses"] == "./.github/workflows/ci-recovery.yml"
    assert native["strategy"]["matrix"]["os"] == [
        "macos-latest",
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
    ]
    assert workflow("installers.yml")["jobs"]["native-recovery"]["uses"] == native["uses"]
    commands = "\n".join(step.get("run", "") for step in ci["studio"]["steps"])
    for name in ("runtime", "ownership", "sessions", "state_contracts", "state_durability"):
        assert f"--ignore=tests/unit/test_studio_{name}.py" in commands
    # Ubuntu-latest's slow cases remain: its image differs from native Ubuntu 24.04.
    slow = workflow("release-slow.yml")["jobs"]["slow-comprehensive"]
    command = next(step["run"] for step in slow["steps"] if step.get("name") == "Run slow shard")
    assert "--ignore" not in command
    assert "-m slow --no-cov" in command


def test_embedded_installer_matrix_selector_is_valid_python() -> None:
    steps = workflow("installers.yml")["jobs"]["plan"]["steps"]
    command = next(step["run"] for step in steps if step.get("id") == "matrix")
    script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    ast.parse(script)
    assert "has_linux=" in script


def test_release_overlaps_builds_but_publication_requires_all_selected_gates() -> None:
    jobs = workflow("release.yml")["jobs"]
    assert jobs["build-installers"]["needs"] == ["release-scope", "validate-release-version"]
    assert "release-gates" in jobs["publish-release"]["needs"]
    assert {
        "release-ci",
        "release-slow",
        "build-installers",
        "release-ci-legacy",
        "release-slow-legacy",
        "build-installers-legacy",
    } <= set(jobs["release-gates"]["needs"])
    for name in ("release-ci", "release-slow", "build-installers"):
        old = jobs[name + "-legacy"]
        assert old["uses"].endswith("@4302afd5f38126118ad4346efb7c76b3dac8d06d")
        assert old["with"]["source-ref"] == "${{ needs.validate-release-version.outputs.sha }}"
        assert "ci-modern == 'false'" in old["if"]


@pytest.mark.skipif(sys.platform == "win32", reason="Release gates execute on native Ubuntu bash")
@pytest.mark.parametrize("modern", [True, False])
@pytest.mark.parametrize(
    "damage", [None, "failed", "cancelled", "skipped", "missing-policy", "version"]
)
def test_actual_release_gate_command_rejects_missing_or_unsuccessful_checks(
    modern: bool,
    damage: str | None,
) -> None:
    command = workflow("release.yml")["jobs"]["release-gates"]["steps"][0]["run"]
    environment = {
        **os.environ,
        "VERSION_RESULT": "success",
        "MODERN": str(modern).lower(),
        "CI_RESULT": "success" if modern else "skipped",
        "SLOW_RESULT": "success" if modern else "skipped",
        "INSTALLER_RESULT": "success" if modern else "skipped",
        "LEGACY_CI_RESULT": "skipped" if modern else "success",
        "LEGACY_SLOW_RESULT": "skipped" if modern else "success",
        "LEGACY_INSTALLER_RESULT": "skipped" if modern else "success",
    }
    if damage == "missing-policy":
        environment["MODERN"] = ""
    elif damage == "version":
        environment["VERSION_RESULT"] = "failure"
    elif damage:
        environment["SLOW_RESULT" if modern else "LEGACY_SLOW_RESULT"] = damage
    result = subprocess.run(
        ["bash", "-ec", command],
        env=environment,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert (result.returncode == 0) == (damage is None)
