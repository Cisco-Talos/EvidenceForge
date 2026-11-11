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
import urllib.error
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
    arguments: list[str] | str = command
    if command[-1].startswith(("/D=", "_?=")):
        # NSIS consumes the entire unquoted tail for these special options.
        # Standard Windows argv quoting would silently discard the override.
        # This is a direct CreateProcess invocation, never a shell command.
        arguments = subprocess.list2cmdline(command[:-1]) + " " + command[-1]
    result = subprocess.run(arguments, executable=command[0], timeout=240, check=False)
    if result.returncode != expected:
        raise RuntimeError(f"NSIS exited {result.returncode}, expected {expected}: {command}")


def verify_shortcuts(scope: str, app: Path) -> list[Path]:
    """Require Start-menu/Desktop links to target this scope's installed binary."""
    script = """
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$shell = New-Object -ComObject WScript.Shell
$folders = if ($env:EFORGE_VERIFY_SCOPE -eq 'AllUsers') {
    @('CommonPrograms', 'CommonDesktopDirectory')
} else { @('Programs', 'DesktopDirectory') }
$links = foreach ($folder in $folders) {
    $root = [Environment]::GetFolderPath($folder)
    $found = @(Get-ChildItem -LiteralPath $root -Filter 'EvidenceForge Studio.lnk' -Recurse)
    if ($found.Count -ne 1) { throw "Expected one Studio shortcut in $root; found $($found.Count)" }
    $shortcut = $shell.CreateShortcut($found[0].FullName)
    @{ path = $found[0].FullName; target = $shortcut.TargetPath }
}
ConvertTo-Json -InputObject @($links) -Compress
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        env={**os.environ, "EFORGE_VERIFY_SCOPE": scope, "EFORGE_VERIFY_APP": str(app)},
    )
    if result.returncode != 0:
        raise RuntimeError(f"{scope} shortcut verification failed: {result.stderr.strip()}")
    links = json.loads(result.stdout)
    expected = app.resolve()
    for link in links:
        actual = Path(link["target"]).resolve()
        assert actual == expected, f"Shortcut {link['path']!r}: {actual!s} != {expected!s}"
    return [Path(link["path"]) for link in links]


def uninstall_app(destination: Path, scope: str) -> None:
    """Wait for uninstallation and finish NSIS's direct-uninstaller cleanup."""
    uninstaller = destination / "uninstall.exe"
    installer_command([str(uninstaller), "/S", f"/{scope}", f"_?={destination}"])
    assert registry_location(scope) is None
    # _?= prevents NSIS's temporary copy. The waiting caller must remove that
    # now-unmapped executable itself, as documented by NSIS command-line usage.
    uninstaller.unlink(missing_ok=True)
    if destination.exists():
        destination.rmdir()  # A nonempty app directory is an uninstall failure.


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
    working = directory / "launch-directory"
    poison = working / "evidenceforge"
    poison.mkdir(parents=True)
    (poison / "__init__.py").write_text(
        "raise RuntimeError('Studio imported the launch directory instead of its runtime')\n",
        encoding="utf-8",
    )
    environment["PYTHONPATH"] = str(working)
    environment["PYTHONHOME"] = str(working / "unavailable-python")
    environment["PYTHONUTF8"] = "0"
    environment["PYTHONIOENCODING"] = "ascii"
    process = subprocess.Popen([str(app)], env=environment, cwd=working)
    helper: psutil.Process | None = None
    try:
        discovery = directory / "private/state/service.json"
        deadline = time.monotonic() + 180
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
        # Discovery is published before Uvicorn has finished starting. Retain
        # the exact process identity while waiting for its authenticated health.
        while time.monotonic() < deadline:
            if process.poll() is not None or not helper.is_running():
                raise RuntimeError("Installed Studio exited before authenticated readiness")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    assert response.status == 200
                break
            except urllib.error.HTTPError:
                raise  # Authentication failures must never become readiness retries.
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
        else:
            raise RuntimeError("Installed Studio helper did not reach authenticated readiness")
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
        "toolchain": {
            "python": sys.version,
            "rust": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "node": subprocess.check_output(["node", "--version"], text=True).strip(),
            "uv": subprocess.check_output(["uv", "--version"], text=True).strip(),
        },
        "installer": installer.name,
        "sha256": checksum,
        "signed": False,
        "scopes": {},
        "default_directories": {},
        "desktop_acceptance": "pending Windows 11 interactive and separate-account testing",
    }
    private_root = Path(os.environ["LOCALAPPDATA"]) / "EvidenceForge"
    private_state_existed = private_root.exists()
    for scope, parent in (
        ("CurrentUser", Path(os.environ["LOCALAPPDATA"]) / "Programs"),
        ("AllUsers", Path(os.environ.get("ProgramW6432", os.environ["ProgramFiles"]))),
    ):
        destination = parent / "EvidenceForge Studio"
        if destination.exists():
            raise RuntimeError(
                f"Refusing to replace an existing application directory: {destination}"
            )
        installer_command([str(installer), "/S", f"/{scope}"])
        try:
            registered = registry_location(scope)
            assert Path(registered or "") == destination, (
                f"{scope}: default directory {registered!r}, expected {str(destination)!r}"
            )
            shortcuts = verify_shortcuts(scope, destination / "evidenceforge-studio.exe")
            if not private_state_existed:
                assert not private_root.exists(), (
                    "Setup initialized private state before normal launch"
                )
        finally:
            uninstaller = destination / "uninstall.exe"
            if uninstaller.is_file():
                uninstall_app(destination, scope)
        assert registry_location(scope) is None
        assert all(not shortcut.exists() for shortcut in shortcuts)
        report["default_directories"][scope] = str(destination)
    with tempfile.TemporaryDirectory(prefix="eforge installed 汉 ü ") as temporary:
        root = Path(temporary).resolve()
        sentinel = root / "private/user-data.txt"
        sentinel.parent.mkdir()
        sentinel.write_text("preserve authored work and private data", encoding="utf-8")
        for scope in ("CurrentUser", "AllUsers"):
            destination = root / scope
            command = [str(installer), "/S", f"/{scope}", f"/D={destination}"]
            installed = False
            uninstalled = False
            retained_database: Path | None = None
            retained_bytes: bytes | None = None
            shortcuts: list[Path] = []
            authored = root / f"launch-{scope}/workspace/scenarios/preserved.yaml"
            try:
                installer_command(command)
                installed = True
                registered = registry_location(scope)
                assert Path(registered or "") == destination, (
                    f"{scope}: registered {registered!r}, expected {str(destination)!r}"
                )
                assert (destination / "evidenceforge-studio.exe").is_file()
                assert (destination / "runtime/manifest.json").is_file()
                installer_command(command)  # Same-version reinstall/upgrade path.
                shortcuts = verify_shortcuts(scope, destination / "evidenceforge-studio.exe")
                opposite = "AllUsers" if scope == "CurrentUser" else "CurrentUser"
                installer_command(
                    [str(installer), "/S", f"/{opposite}", f"/D={root / opposite}"], expected=2
                )
                assert registry_location(opposite) is None
                runtime = verify_runtime(destination / "runtime", "x86_64")
                helper_smoke(destination / "evidenceforge-studio.exe", root / f"launch-{scope}")
                retained_database = root / f"launch-{scope}/private/data/studio.sqlite"
                retained_bytes = retained_database.read_bytes()
                authored.parent.mkdir(parents=True, exist_ok=True)
                authored.write_bytes(b"name: preserved authored work\n")
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
                    "scope_shortcuts": "passed",
                    "runtime": runtime,
                    "native_shell_helper": "passed",
                    "packaged_checkpoint_resume_equivalence": "passed",
                }
            finally:
                if installed and (destination / "uninstall.exe").is_file():
                    uninstall_app(destination, scope)
                    uninstalled = True
                    assert registry_location(scope) is None
                    assert all(not shortcut.exists() for shortcut in shortcuts)
                assert (
                    sentinel.read_text(encoding="utf-8")
                    == "preserve authored work and private data"
                )
                if retained_database is not None:
                    assert retained_database.read_bytes() == retained_bytes
                    assert (retained_database.parent / "runtimes").is_dir()
                    assert authored.read_bytes() == b"name: preserved authored work\n"
            assert uninstalled, "The installed preview did not provide an uninstaller"
            report["scopes"][scope]["uninstall_preservation"] = "passed"
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
