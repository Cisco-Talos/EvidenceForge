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


def test_native_recovery_has_one_shared_owner_and_retains_platform_variants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import ci_studio

    ci = workflow("ci.yml")["jobs"]
    native = ci["studio-state-recovery"]
    assert native["uses"] == "./.github/workflows/ci-recovery.yml"
    assert native["strategy"]["matrix"]["os"] == [
        "macos-latest",
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "windows-2025",
    ]
    assert workflow("installers.yml")["jobs"]["native-recovery"]["uses"] == native["uses"]
    commands = "\n".join(step.get("run", "") for step in ci["studio"]["steps"])
    assert "scripts.ci_studio" in commands
    selected: list[str] = []

    def record(command: list[str], *, check: bool) -> None:
        assert check
        selected.extend(Path(argument).as_posix() for argument in command)

    monkeypatch.setattr(ci_studio.subprocess, "run", record)
    ci_studio.main()
    assert "tests/unit/test_studio_service.py" in selected
    assert "tests/unit/test_desktop_jobs.py" in selected
    for name in ("runtime", "ownership", "sessions", "state_contracts", "state_durability"):
        assert f"tests/unit/test_studio_{name}.py" not in selected
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


def test_windows_preview_keeps_normal_integration_gates() -> None:
    ci = workflow("ci.yml")
    assert "ready_for_review" in ci[True]["pull_request"]["types"]
    for name in ("inputs", "lint", "studio-state-recovery"):
        assert "if" not in ci["jobs"][name]
    assert ci["jobs"]["ci-required"]["if"] == "always()"
    preview = workflow("windows-preview.yml")
    assert "push" not in preview[True]
    assert {"workflow_dispatch", "workflow_call"} <= preview[True].keys()
    assert preview["jobs"]["preview"]["runs-on"] == "windows-2025"
    assert preview["concurrency"]["cancel-in-progress"] is True
    commands = "\n".join(step.get("run", "") for step in preview["jobs"]["preview"]["steps"])
    assert "verify_studio_windows.py" in commands
    assert "package_studio_windows.py" in commands
    native = preview["jobs"]["native-tests"]
    assert native["runs-on"] == "windows-2025"
    assert "needs" not in native and "needs" not in preview["jobs"]["preview"]
    native_commands = "\n".join(step.get("run", "") for step in native["steps"])
    assert "scripts.ci_native_recovery" in native_commands
    assert "scripts.ci_studio" in native_commands


def test_windows_qualified_artifact_requires_both_native_and_installer_gates() -> None:
    jobs = workflow("windows-preview.yml")["jobs"]
    qualified = jobs["qualify"]
    assert set(qualified["needs"]) == {"preview", "native-tests"}
    assert qualified["if"] == "${{ !inputs.build-only }}"
    for name in ("preview", "native-tests"):
        assert "source-sha" in jobs[name]["outputs"]
        for step in jobs[name]["steps"]:
            assert step.get("with", {}).get("name") != "preview-installer-windows-x86_64"
    script = "\n".join(step.get("run", "") for step in qualified["steps"])
    assert "$env:PACKAGE_SOURCE -ne $env:NATIVE_SOURCE" in script
    assert "$report.source_sha -ne $env:PACKAGE_SOURCE" in script
    assert "Get-FileHash" in script and "$report.sha256 -ne $hash" in script
    assert "$report.authoring.filesystem_permissions -ne 'passed'" in script
    assert "$report.authoring.packaged_cli_guard -ne 'passed'" in script
    assert "$report.maintenance_navigation.$scope -ne 'passed'" in script
    assert "$report.scopes.$scope.packaged_cleanup_inventory -ne 'passed'" in script
    uploads = [
        step for step in qualified["steps"] if "actions/upload-artifact@" in step.get("uses", "")
    ]
    assert uploads[0]["with"]["name"] == "preview-installer-windows-x86_64"
    assert uploads[0]["with"]["if-no-files-found"] == "error"


def test_windows_build_only_mode_skips_acceptance_and_never_uploads_as_qualified() -> None:
    preview = workflow("windows-preview.yml")
    for entry in ("workflow_dispatch", "workflow_call"):
        option = preview[True][entry]["inputs"]["build-only"]
        assert option["type"] == "boolean" and option["default"] is False
    jobs = preview["jobs"]
    full_only = "${{ !inputs.build-only }}"
    assert jobs["native-tests"]["if"] == jobs["qualify"]["if"] == full_only
    steps = jobs["preview"]["steps"]
    for step in steps:
        if step["name"].startswith(("Test ", "Verify ", "Check Python")) or step["name"] in {
            "Install pinned native Codex",
            "Upload installer candidate pending native service checks",
        }:
            assert step["if"] == full_only, step["name"]
    build = next(step for step in steps if step.get("id") == "package-build")
    assert "if" not in build and "package_studio_windows.py" in build["run"]
    fast = next(
        step for step in steps if step["name"] == "Upload unqualified Windows test installer"
    )
    assert fast["if"] == "${{ inputs.build-only }}"
    assert fast["with"]["name"] == "unqualified-windows-installer-x86_64"
    assert ".verification.json" not in fast["with"]["path"]
    metadata = next(step for step in steps if step["name"] == "Record unqualified build metadata")
    assert metadata["if"] == "${{ inputs.build-only }}"
    for required in (
        "qualification = 'not_run'",
        "runtime_id = $runtimeHash",
        "source_sha =",
        "ci_run_id =",
        "sha256 = $hash",
        "Build checksum mismatch",
    ):
        assert required in metadata["run"]


def test_memory_gate_runs_outside_pytest_and_is_required_for_release() -> None:
    memory = workflow("evaluation-memory.yml")
    assert memory["permissions"] == {"contents": "read"}
    job = memory["jobs"]["memory"]
    assert set(job["strategy"]["matrix"]["os"]) == {
        "ubuntu-24.04",
        "ubuntu-24.04-arm",
        "macos-latest",
        "windows-latest",
    }
    command = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Measure fixed evaluation workloads"
    )
    assert "scripts.check_evaluation_memory" in command
    assert "pytest" not in command and "--cov" not in command
    assert "github.event_name == 'workflow_dispatch' && inputs.calibrate" in command
    assert "calibrate" not in memory[True]["workflow_call"].get("inputs", {})
    upload = job["steps"][-1]
    assert upload["if"] == "always()"
    assert "measurements.json" in upload["with"]["path"]
    release = workflow("release-slow.yml")["jobs"]
    assert release["evaluation-memory"]["uses"] == "./.github/workflows/evaluation-memory.yml"
    required = release["release-required"]
    assert "evaluation-memory" in required["needs"]
    assert "needs['evaluation-memory'].result" in required["steps"][0]["run"]


@pytest.mark.skipif(sys.platform == "win32", reason="Release policy uses the Ubuntu shell")
@pytest.mark.parametrize(
    "current,legacy,allowed", [(False, True, True), (True, False, True), (True, True, False)]
)
def test_historical_memory_policy_cannot_skip_current_snapshot_gate(
    tmp_path: Path,
    current: bool,
    legacy: bool,
    allowed: bool,
) -> None:
    jobs = workflow("release-slow.yml")["jobs"]
    step = next(
        s for s in jobs["inputs"]["steps"] if s["name"] == "Verify historical memory policy"
    )
    if current:
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts/check_evaluation_memory.py").write_text("# current harness\n")
    result = subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        cwd=tmp_path,
        env={**os.environ, "LEGACY_MEMORY_POLICY": str(legacy).lower()},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is allowed
    release = workflow("release.yml")["jobs"]["release-slow"]
    assert "ci-memory != 'true'" in release["with"]["legacy-memory-policy"]


@pytest.mark.skipif(sys.platform == "win32", reason="Release policy uses the Ubuntu shell")
@pytest.mark.parametrize(
    "legacy,memory,slow,allowed",
    [
        (False, "success", "success", True),
        (False, "skipped", "success", False),
        (False, "failure", "success", False),
        (True, "skipped", "success", True),
        (True, "failure", "success", False),
        (True, "skipped", "failure", False),
    ],
)
def test_extended_release_requires_each_applicable_resource_and_correctness_gate(
    legacy: bool,
    memory: str,
    slow: str,
    allowed: bool,
) -> None:
    step = workflow("release-slow.yml")["jobs"]["release-required"]["steps"][0]
    command = step["run"]
    for job, result in (
        ("evaluation-memory", memory),
        ("slow-comprehensive", slow),
        ("checkpoint-portability", "success"),
    ):
        command = command.replace("${{ needs['" + job + "'].result }}", result)
    result = subprocess.run(
        ["bash", "-e", "-c", command],
        env={**os.environ, "LEGACY_MEMORY_POLICY": str(legacy).lower()},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is allowed


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


def test_release_publisher_ignores_unused_branch_skips_but_requires_successful_gates() -> None:
    publisher = workflow("release.yml")["jobs"]["publish-release"]
    # The unused modern/legacy branch is skipped even on a successful release.
    # A status function must override GitHub's implicit ancestor success() check.
    terms = {term.strip() for term in publisher["if"].split("&&")}
    assert {
        "always()",
        "!cancelled()",
        "github.event_name != 'pull_request'",
        "needs.release-scope.outputs.cleanup != 'true'",
        "needs.validate-release-version.result == 'success'",
        "needs.release-gates.result == 'success'",
    } <= terms
    assert {"validate-release-version", "release-gates"} <= set(publisher["needs"])


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
