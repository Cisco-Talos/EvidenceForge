# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compile/run a syscall-stubbed C simulation, never the native job guard."""

import shutil
import subprocess
from pathlib import Path

import pytest

from tests.support.platforms import requires_posix_reference


@requires_posix_reference
def test_launchd_guard_cancellation_deadlines_recovery_and_fixed_root_scope(tmp_path: Path) -> None:
    compiler = shutil.which("clang")
    if compiler is None:
        pytest.skip("C unit simulation requires Clang")
    source = Path(__file__).parents[1] / "fixtures/macos_launchd_guard_simulation.c"
    executable = tmp_path / "guard-simulation"
    compilation = subprocess.run(
        [compiler, "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert compilation.returncode == 0, compilation.stdout + compilation.stderr
    result = subprocess.run([str(executable)], check=True, capture_output=True, timeout=5)
    assert result.stdout == b"launchd guard simulations passed\n"
    assert result.stderr == b""
