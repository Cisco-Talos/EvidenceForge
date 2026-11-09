"""The remote collector guard runs only invented executables in these tests."""

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

SOURCE = (
    Path(__file__).resolve().parents[2]
    / "docs/design/macos-workstation-feasibility/remote-reference/collector_guard.c"
)


@pytest.fixture(scope="module")
def guard(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if sys.platform == "win32":
        pytest.skip("POSIX process-group guard")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler is unavailable")
    root = tmp_path_factory.mktemp("invented-remote-guard")
    fake = root / "invented.c"
    fake.write_text(
        "#include <stdio.h>\n#include <unistd.h>\n"
        "int main(int argc, char **argv) {\n"
        'for (int i=1; i<argc; i++) printf("%s\\n", argv[i]);\n'
        "fflush(stdout); for (;;) pause(); }\n"
    )
    collector = root / "invented-collector"
    subprocess.run([compiler, str(fake), "-o", str(collector)], check=True, capture_output=True)
    executable = root / "guard"
    subprocess.run(
        [
            compiler,
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DEFORGE_GUARD_TEST",
            f'-DEFORGE_TEST_COLLECTOR="{collector}"',
            str(SOURCE),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
    )
    return executable


@pytest.mark.parametrize("shutdown", ["deadline", "pipe_close", "signal"])
def test_guard_bounds_collection_and_reaps_fixed_child(guard: Path, shutdown: str) -> None:
    process = subprocess.Popen(
        [str(guard), "filesystem"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        assert process.stdout is not None and process.stdin is not None
        expected = ["fork", "exec", "exit", "create", "close", "rename", "unlink"]
        assert [process.stdout.readline().strip() for _ in expected] == expected
        if shutdown == "pipe_close":
            process.stdin.close()
        elif shutdown == "signal":
            os.kill(process.pid, signal.SIGTERM)
        assert process.wait(timeout=5) == 0
        # A remaining child retaining stdout would prevent EOF.
        assert process.stdout.read() == ""
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


@pytest.mark.parametrize("arguments", [[], ["other"], ["process", "extra"]])
def test_guard_rejects_arbitrary_commands_and_options(guard: Path, arguments: list[str]) -> None:
    result = subprocess.run([str(guard), *arguments], capture_output=True, timeout=5)
    assert result.returncode == 2 and result.stdout == b""
