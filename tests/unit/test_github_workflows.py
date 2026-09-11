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
from pathlib import Path

_USES_PATTERN = re.compile(r"^\s*uses:\s*(?P<action>\S+)", re.MULTILINE)
_FULL_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


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

    repo_root = Path(__file__).resolve().parents[2]
    workflow = (repo_root / ".github" / "workflows" / "release-slow.yml").read_text(
        encoding="utf-8"
    )
    assert "uv run pytest -m slow --no-cov" in workflow
    assert "--include-slow" not in workflow
    assert "--include-soak" not in workflow
