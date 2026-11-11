"""Verify the actual NSIS installer in both scopes on a disposable Windows CI host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

import psutil

if __package__:
    from .verify_studio_runtime import verify_runtime
else:
    from verify_studio_runtime import verify_runtime


def registry_location(scope: str) -> str | None:
    """Read installation registration without interpreting an uninstall command."""
    import winreg

    hive = winreg.HKEY_LOCAL_MACHINE if scope == "AllUsers" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(
            hive,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\EvidenceForge Studio",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            return str(winreg.QueryValueEx(key, "InstallLocation")[0]).strip('"')
    except FileNotFoundError:
        return None


def installer_command(command: list[str], *, expected: int = 0) -> None:
    """Bound NSIS execution and require the expected installer result."""
    result = subprocess.run(command, timeout=240, check=False)
    if result.returncode != expected:
        raise RuntimeError(f"NSIS exited {result.returncode}, expected {expected}: {command}")


def helper_smoke(app: Path, directory: Path) -> None:
    """Launch the installed shell and authenticate to its retained-runtime helper."""
    environment = {
        **os.environ,
        "EFORGE_STUDIO_HOME": str(directory / "private"),
        "EFORGE_STUDIO_DEFAULT_WORKSPACE": str(directory / "workspace"),
        "PATH": str(Path(os.environ["SystemRoot"]) / "System32"),
    }
    for name in ("EFORGE_STUDIO_PYTHON", "EFORGE_STUDIO_RUNTIME_ROOT", "PYTHONHOME", "PYTHONPATH"):
        environment.pop(name, None)
    process = subprocess.Popen([str(app)], env=environment)
    helper: psutil.Process | None = None
    try:
        discovery = directory / "private/state/service.json"
        deadline = time.monotonic() + 90
        descriptor: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Installed Studio window exited before helper startup")
            try:
                descriptor = json.loads(discovery.read_bytes())
            except (FileNotFoundError, ValueError):
                time.sleep(0.1)
                continue
            break
        if descriptor is None:
            raise RuntimeError("Installed Studio did not publish helper discovery")
        helper = psutil.Process(descriptor["pid"])
        assert abs(helper.create_time() - descriptor["created_at"]) < 0.01
        assert Path(helper.exe()).is_relative_to(directory / "private/data/runtimes")
        assert "evidenceforge.studio.bootstrap" in helper.cmdline()
        request = urllib.request.Request(
            f"http://127.0.0.1:{descriptor['port']}/v1/health",
            headers={"X-EForge-Token": descriptor["token"]},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == 200
    finally:
        # Clean only this harness's unreaped window and verified helper child.
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=15)
        if helper is not None:
            try:
                helper.terminate()
                helper.wait(timeout=15)
            except psutil.NoSuchProcess:
                pass


def verify_installer(installer: Path) -> dict[str, Any]:
    """Exercise actual install/reinstall/scope refusal/uninstall and packaged code."""
    if sys.platform != "win32" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("Installer acceptance requires a disposable native Windows Actions host")
    if any(registry_location(scope) for scope in ("CurrentUser", "AllUsers")):
        raise RuntimeError("Refusing to modify a host with an existing Studio installation")
    checksum = hashlib.sha256(installer.read_bytes()).hexdigest()
    expected = f"{checksum}  {installer.name}"
    if installer.with_suffix(".exe.sha256").read_text(encoding="utf-8").strip() != expected:
        raise RuntimeError("Installer checksum file does not match the artifact")
    report: dict[str, Any] = {
        "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "runner_image": os.environ.get("ImageVersion"),
        "installer": installer.name,
        "sha256": checksum,
        "signed": False,
        "scopes": {},
        "desktop_acceptance": "pending Windows 11 interactive and separate-account testing",
    }
    with tempfile.TemporaryDirectory(prefix="eforge installed ü ") as temporary:
        root = Path(temporary).resolve()
        sentinel = root / "private/user-data.txt"
        sentinel.parent.mkdir()
        sentinel.write_text("preserve authored work and private data", encoding="utf-8")
        for scope in ("CurrentUser", "AllUsers"):
            destination = root / scope
            command = [str(installer), "/S", f"/{scope}", f"/D={destination}"]
            installed = False
            retained_database: Path | None = None
            retained_bytes: bytes | None = None
            try:
                installer_command(command)
                installed = True
                assert Path(registry_location(scope) or "") == destination
                assert (destination / "evidenceforge-studio.exe").is_file()
                assert (destination / "runtime/manifest.json").is_file()
                installer_command(command)  # Same-version reinstall/upgrade path.
                opposite = "AllUsers" if scope == "CurrentUser" else "CurrentUser"
                installer_command(
                    [str(installer), "/S", f"/{opposite}", f"/D={root / opposite}"], expected=2
                )
                assert registry_location(opposite) is None
                runtime = verify_runtime(destination / "runtime", "x86_64")
                helper_smoke(destination / "evidenceforge-studio.exe", root / f"launch-{scope}")
                retained_database = root / f"launch-{scope}/private/data/studio.sqlite"
                retained_bytes = retained_database.read_bytes()
                # Use the installed interpreter for every CLI subprocess in the
                # existing synchronized checkpoint/resume/equivalence contract.
                resources = destination / "runtime"
                selected = json.loads((resources / "manifest.json").read_bytes())["runtimes"][
                    "x86_64"
                ]
                native_python = (
                    root
                    / f"launch-{scope}/private/data/runtimes"
                    / f"{selected['sha256']}-x86_64/python.exe"
                )
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "--no-cov",
                        "-q",
                        "tests/integration/test_checkpoint_smoke.py",
                        "-k",
                        "default and not 2026",
                    ],
                    check=True,
                    timeout=600,
                    env={
                        **os.environ,
                        "EFORGE_CHECKPOINT_TEST_PYTHON": str(native_python),
                        "PYTHONUTF8": "1",
                    },
                )
                report["scopes"][scope] = {
                    "install_reinstall_scope_refusal": "passed",
                    "runtime": runtime,
                    "native_shell_helper": "passed",
                    "packaged_checkpoint_resume_equivalence": "passed",
                }
            finally:
                if installed and (destination / "uninstall.exe").is_file():
                    installer_command(
                        [str(destination / "uninstall.exe"), "/S", f"/{scope}", f"_?={destination}"]
                    )
                assert registry_location(scope) is None
                assert (
                    sentinel.read_text(encoding="utf-8")
                    == "preserve authored work and private data"
                )
                if retained_database is not None:
                    assert retained_database.read_bytes() == retained_bytes
                    assert (retained_database.parent / "runtimes").is_dir()
    return report


def main() -> None:
    """Write exact-artifact verification evidence beside the installer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installer", type=Path)
    arguments = parser.parse_args()
    installer = arguments.installer.resolve()
    report = verify_installer(installer)
    output = installer.with_suffix(".verification.json")
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
