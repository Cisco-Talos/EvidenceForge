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

"""Security invariants for GitHub Actions workflows."""

import re
import shlex
from pathlib import Path
from typing import Any

import yaml

_USES_PATTERN = re.compile(r"^\s*uses:\s*(?P<action>\S+)", re.MULTILINE)
_FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def _release_slow_jobs() -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load(
        (repo_root / ".github/workflows/release-slow.yml").read_text(encoding="utf-8")
    )
    return workflow["jobs"]


def _slow_test_arguments(jobs: dict[str, Any]) -> list[str]:
    commands = [
        step["run"]
        for step in jobs["slow-comprehensive"]["steps"]
        if step.get("name") == "Run slow shard"
    ]
    assert len(commands) == 1
    return shlex.split(commands[0])


def test_external_github_actions_are_pinned_to_full_commit_shas() -> None:
    """External actions must resolve to immutable reviewed source revisions."""
    repo_root = Path(__file__).resolve().parents[2]
    workflows_dir = repo_root / ".github" / "workflows"
    workflow_paths = sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml"))
    failures: list[str] = []

    for workflow_path in workflow_paths:
        workflow = workflow_path.read_text(encoding="utf-8")
        for match in _USES_PATTERN.finditer(workflow):
            action = match.group("action")
            if action.startswith("./"):
                continue
            _target, separator, revision = action.rpartition("@")
            if separator and _FULL_COMMIT_SHA.fullmatch(revision):
                continue
            line_number = workflow.count("\n", 0, match.start()) + 1
            failures.append(f"{workflow_path.relative_to(repo_root)}:{line_number}: {action}")

    assert not failures, "External GitHub Actions must use full commit SHAs:\n" + "\n".join(
        failures
    )


def test_release_slow_workflow_excludes_soak_diagnostics() -> None:
    """The release lane selects the exclusive slow tier through native pytest markers."""

    arguments = _slow_test_arguments(_release_slow_jobs())
    assert arguments[:2] == ["uv", "run"]
    assert "pytest" in arguments
    assert arguments[arguments.index("-m") + 1] == "slow"
    assert arguments[arguments.index("--ci-tier") + 1] == "slow"
    assert "--no-cov" in arguments
    assert not any(argument == "--cov" or argument.startswith("--cov=") for argument in arguments)
    assert "--include-slow" not in arguments
    assert "--include-soak" not in arguments


def test_release_slow_workflow_shards_tests_and_parallelizes_portability() -> None:
    """The release lane preserves all slow tests across four independent shards."""

    jobs = _release_slow_jobs()
    arguments = _slow_test_arguments(jobs)
    assert arguments[arguments.index("--ci-shard-count") + 1] == "4"
    assert arguments[arguments.index("--ci-shard-index") + 1] == "${{ matrix.shard_index }}"
    shards = jobs["slow-comprehensive"]["strategy"]["matrix"]["include"]
    assert len(shards) == 4
    assert {shard["shard_index"] for shard in shards} == set(range(4))
    assert all(shard["shard_number"] == shard["shard_index"] + 1 for shard in shards)
    assert "checkpoint-portability" not in jobs["slow-comprehensive"]["needs"]
    assert "slow-comprehensive" not in jobs["checkpoint-portability"]["needs"]
    assert set(jobs["release-required"]["needs"]) == {
        "slow-comprehensive",
        "checkpoint-portability",
    }
