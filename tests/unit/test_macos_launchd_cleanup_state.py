"""Exact test-control inspection uses invented files and mocked service responses only."""

import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest
from scripts import macos_ulf_launchd_reference as kit

from tests.support.platforms import requires_posix_reference

NONCE = "a" * 32
SECRET = "invented-private-canary-do-not-export"
LEASE = "invented-control-lease"
DIRECTORY = (
    b"DIRECTORY_PRESENT\nDIRECTORY_OWNER_MATCH\nDIRECTORY_MODE_MATCH\nDIRECTORY_KIND_MATCH\n"
)
COMPLETE = DIRECTORY + (
    b"LEASE_PRESENT\nLEASE_OWNER_MATCH\nLEASE_MODE_MATCH\nLEASE_KIND_MATCH\n"
    b"LEASE_LINKS_MATCH\nLEASE_SIZE_MATCH\nLEASE_CONTENT_MATCH\n"
)


@pytest.fixture(autouse=True)
def owned_scratch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect mocked compiler scratch to owned test storage on every POSIX host."""

    def scratch(*, prefix: str, dir: str) -> TemporaryDirectory:
        assert dir == "/private/tmp"
        return TemporaryDirectory(prefix=prefix, dir=tmp_path)

    monkeypatch.setattr(kit, "tempfile", SimpleNamespace(TemporaryDirectory=scratch))


def _missing(nonce: str = NONCE) -> bytes:
    return (
        f'Could not find service "org.evidenceforge.reference.launchd.{nonce}" '
        "in domain for system\n"
    ).encode()


@pytest.mark.parametrize(
    "returncode,stderr,expected",
    [
        (0, b"", "PRESENT"),
        (0, SECRET.encode(), "PRESENT"),
        (113, _missing(), "ABSENT"),
        (113, b"Bad request.\n" + _missing(), "ABSENT"),
        (113, b"", "INCONCLUSIVE"),
        (1, SECRET.encode(), "INCONCLUSIVE"),
        (-9, _missing(), "INCONCLUSIVE"),
        (113, _missing("b" * 32), "INCONCLUSIVE"),
        (113, _missing().replace(b"system", b"user"), "INCONCLUSIVE"),
        (113, _missing() + SECRET.encode(), "INCONCLUSIVE"),
    ],
)
def test_service_absence_requires_explicit_exact_label_diagnostic(
    returncode: int, stderr: bytes, expected: str
) -> None:
    result = kit._exact_service_state(returncode, stderr, NONCE)
    assert result == expected and SECRET not in result


@pytest.mark.parametrize(
    "output",
    [
        b"",
        SECRET.encode(),
        b"DIRECTORY_ABSENT\nDIRECTORY_PRESENT\n",
        b"DIRECTORY_ABSENT\nLEASE_PRESENT\n",
        b"DIRECTORY_PRESENT\n",
        DIRECTORY,
        DIRECTORY + b"LEASE_PRESENT\n",
        COMPLETE.replace(b"LEASE_CONTENT_MATCH\n", b""),
        COMPLETE + b"LEASE_CONTENT_MATCH\n",
    ],
)
def test_partial_unknown_or_contradictory_inspection_cannot_prove_cleanup(output: bytes) -> None:
    report = kit._cleanup_state_labels(output, kit.CleanupState())
    assert report.error == "CONTROL" and report.cleanup_state == "UNVERIFIED"
    assert SECRET not in report.model_dump_json()


@requires_posix_reference
@pytest.mark.parametrize(
    "output,service_code,service_error,expected,error",
    [
        (b"DIRECTORY_ABSENT\n", 113, _missing(), "ABSENCE_VERIFIED", "NONE"),
        (b"DIRECTORY_ABSENT\n", 0, b"", "UNVERIFIED", "NONE"),
        (b"DIRECTORY_ABSENT\n", 1, SECRET.encode(), "UNVERIFIED", "CONTROL"),
        (COMPLETE, 0, b"", "OWNED_LEASE_PRESENT", "NONE"),
        (COMPLETE, 113, _missing(), "OWNED_LEASE_PRESENT", "NONE"),
        (DIRECTORY + b"LEASE_ABSENT\n", 113, _missing(), "UNVERIFIED", "NONE"),
        (SECRET.encode(), 113, _missing(), "UNVERIFIED", "CONTROL"),
    ],
)
def test_grouped_checker_never_collects_reads_records_or_changes_original_kit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output: bytes,
    service_code: int,
    service_error: bytes,
    expected: str,
    error: str,
) -> None:
    private = tmp_path / "records.ndjson"
    private.write_text(SECRET)
    before = private.read_bytes()
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(kit, "_config", lambda root: kit.Config(nonce=NONCE, hashes={}))
    monkeypatch.setattr(kit, "_read", lambda *a: pytest.fail("no record read"))
    results = iter(
        [
            SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=0, stdout=output),
            SimpleNamespace(returncode=service_code, stderr=service_error),
        ]
    )
    calls: list[tuple[list[str], dict]] = []

    def run(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((arguments, kwargs))
        return next(results)

    monkeypatch.setattr(kit.subprocess, "run", run)
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *a, **k: pytest.fail("no collector"))
    report = kit.check_cleanup(tmp_path)
    assert report.cleanup_state == expected and report.error == error
    assert report.controls == report.sudo_credentials == "PASS"
    assert report.native_record_files == "NOT_OPENED"
    assert report.collectors == "NOT_STARTED" and report.jobs_started == "NONE"
    assert SECRET not in report.model_dump_json() and NONCE not in report.model_dump_json()
    assert private.read_bytes() == before and set(tmp_path.iterdir()) == {private}
    assert calls[0][0] == ["/usr/bin/sudo", "-n", "-v"]
    assert calls[1][0][0] == "/usr/bin/cc"
    assert calls[2][0][:2] == ["/usr/bin/sudo", "-n"]
    assert calls[2][0][-2:] == ["inspect", NONCE]
    assert calls[3][0] == [
        "/usr/bin/sudo",
        "-n",
        "/bin/launchctl",
        "print",
        "system/org.evidenceforge.reference.launchd." + NONCE,
    ]
    assert calls[3][1]["stdout"] == subprocess.DEVNULL
    assert all(call[1]["timeout"] <= 30 for call in calls)


@requires_posix_reference
@pytest.mark.parametrize("failed_step,code", [(0, "CONTROL"), (1, "BUILD")])
def test_preflight_failure_prevents_privileged_inspection_and_service_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_step: int, code: str
) -> None:
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(kit, "_config", lambda root: kit.Config(nonce=NONCE, hashes={}))
    calls = []

    def run(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(arguments)
        return SimpleNamespace(returncode=int(len(calls) == failed_step + 1))

    monkeypatch.setattr(kit.subprocess, "run", run)
    report = kit.check_cleanup(tmp_path)
    assert report.error == code and len(calls) == failed_step + 1
    assert report.cleanup_state == "UNVERIFIED"


@pytest.fixture(scope="module")
def synthetic_inspector(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler unavailable; Python privacy checks remain applicable")
    root = tmp_path_factory.mktemp("synthetic-cleanup-guard")
    guard = Path(
        "docs/design/macos-workstation-feasibility/launchd-reference/job_guard.c"
    ).resolve()
    source = root / "harness.c"
    # This harness bypasses the privileged CLI and invokes only its read-only file
    # classifier on invented test paths. fstat supplies a synthetic root owner.
    source.write_text(
        "#define _POSIX_C_SOURCE 200809L\n#define _DARWIN_C_SOURCE 1\n"
        "#include <sys/stat.h>\n#include <string.h>\n"
        "static int synthetic_fstat(int fd, struct stat *s) {\n"
        "    int result = fstat(fd, s); if (!result) s->st_uid = 0; return result;\n}\n"
        "#define fstat synthetic_fstat\n#define main original_guard_main\n"
        f'#include "{guard}"\n'
        "#undef main\nint main(int argc, char **argv) {\n"
        "    if (argc != 3) return 2;\n"
        "    return inspect(argv[1], argv[2], (int)strlen(argv[2]));\n}\n"
    )
    binary = root / "synthetic-inspector"
    subprocess.run(
        [compiler, "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
        capture_output=True,
        check=True,
        timeout=30,
    )
    return binary


@requires_posix_reference
@pytest.mark.parametrize(
    "case,expected,content_checked",
    [
        ("missing_directory", "DIRECTORY_ABSENT", False),
        ("directory_symlink", "DIRECTORY_UNSAFE_PATH", False),
        ("directory_permissions", "DIRECTORY_MODE_MISMATCH", False),
        ("missing_lease", "LEASE_ABSENT", False),
        ("lease_symlink", "LEASE_UNSAFE_PATH", False),
        ("lease_permissions", "LEASE_MODE_MISMATCH", False),
        ("lease_hardlink", "LEASE_LINKS_MISMATCH", False),
        ("lease_wrong_size", "LEASE_SIZE_MISMATCH", False),
        ("lease_wrong_content", "LEASE_CONTENT_MISMATCH", True),
        ("complete", "LEASE_CONTENT_MATCH", True),
    ],
)
def test_c_inspection_rejects_unsafe_controls_without_mutating_them(
    tmp_path: Path, synthetic_inspector: Path, case: str, expected: str, content_checked: bool
) -> None:
    directory = tmp_path / "control"
    if case != "missing_directory":
        directory.mkdir(mode=0o700)
    lease = directory / "job.plist"
    if case not in {"missing_directory", "missing_lease"}:
        lease.write_text(LEASE)
        lease.chmod(0o600)
    if case == "directory_symlink":
        target = directory.rename(tmp_path / "target")
        directory.symlink_to(target)
    elif case == "directory_permissions":
        directory.chmod(0o755)
    elif case == "lease_symlink":
        lease.unlink()
        target = tmp_path / "secret"
        target.write_text(SECRET)
        lease.symlink_to(target)
    elif case == "lease_permissions":
        lease.chmod(0o644)
    elif case == "lease_hardlink":
        os.link(lease, tmp_path / "other-link")
    elif case == "lease_wrong_size":
        lease.write_text(SECRET)
    elif case == "lease_wrong_content":
        lease.write_text("X" * len(LEASE))
    before = {
        str(path.relative_to(tmp_path)): (
            path.lstat().st_mode,
            path.readlink() if path.is_symlink() else path.read_bytes() if path.is_file() else None,
        )
        for path in tmp_path.rglob("*")
    }
    result = subprocess.run(
        [str(synthetic_inspector), str(directory), LEASE],
        capture_output=True,
        check=True,
        timeout=5,
    )
    labels = result.stdout.decode().splitlines()
    assert expected in labels and SECRET not in result.stdout.decode()
    assert any(label.startswith("LEASE_CONTENT_") for label in labels) == content_checked
    parsed = kit._cleanup_state_labels(result.stdout, kit.CleanupState())
    assert parsed.error == "NONE"
    after = {
        str(path.relative_to(tmp_path)): (
            path.lstat().st_mode,
            path.readlink() if path.is_symlink() else path.read_bytes() if path.is_file() else None,
        )
        for path in tmp_path.rglob("*")
    }
    assert before == after
