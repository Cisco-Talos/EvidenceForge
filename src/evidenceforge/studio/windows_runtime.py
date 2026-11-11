"""Install the Windows payload through the existing native private-storage adapter.

The installed app carries a bootstrap interpreter as well as a checksummed payload.
Only installation uses the bootstrap interpreter; helpers and jobs always execute
from the retained per-account copy, independently of app replacement/uninstall.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tarfile
import time
from pathlib import Path, PurePosixPath
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.studio.runtime import RuntimeRelease
from evidenceforge.studio.state_io import (
    StateLock,
    StudioStateBusyError,
    StudioStateError,
    atomic_write,
    open_regular,
    private_directory,
    read_bytes,
    safe_path,
)


class WindowsArchive(BaseModel):
    """One fixed-architecture payload; paths cannot escape the app resources."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    archive: str = Field(pattern=r"^runtime-x86_64\.tar\.gz$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class WindowsManifest(BaseModel):
    """Windows-only private packaging contract, independent of POSIX manifests."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = Field(strict=True, ge=1, le=1)
    evidenceforge_version: str
    python_version: str
    minimum_windows: str = Field(min_length=1)
    runtimes: dict[str, WindowsArchive]


def payload_path(name: str) -> Path:
    """Reject traversal and Windows aliases before materializing an archive member."""
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or "\\" in name:
        raise StudioStateError("Runtime archive contains an invalid path")
    for part in path.parts:
        if (
            part in {".", ".."}
            or part.endswith((".", " "))
            or any(character in part for character in ':<>"|?*')
            or any(ord(character) < 32 for character in part)
            or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part, re.I)
        ):
            raise StudioStateError("Runtime archive contains a Windows path alias")
    return Path(*path.parts)


def install_runtime(resources: Path, data: Path) -> Path:
    """Verify/extract privately and publish a complete content-addressed runtime."""
    if os.name != "nt":
        raise StudioStateError("Windows runtimes must be installed on native Windows x86_64")
    manifest = WindowsManifest.model_validate_json((resources / "manifest.json").read_bytes())
    if set(manifest.runtimes) != {"x86_64"}:
        raise StudioStateError("This preview requires exactly one Windows x86_64 payload")
    selected = manifest.runtimes["x86_64"]
    release = RuntimeRelease(
        runtime_id=selected.sha256,
        evidenceforge_version=manifest.evidenceforge_version,
        python_version=manifest.python_version,
        architecture="x86_64",
    )
    private_directory(data)
    runtimes = data / "runtimes"
    private_directory(runtimes)
    lock = StateLock(runtimes / "install.lock")
    deadline = time.monotonic() + 180
    while True:
        try:
            lock.acquire()
            break
        except StudioStateBusyError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    with lock:
        root = runtimes / f"{selected.sha256}-x86_64"
        private_directory(runtimes / "leases")
        with os.fdopen(
            open_regular(runtimes / "leases" / f"{root.name}.lock", os.O_RDWR | os.O_CREAT), "r+b"
        ):
            pass
        safe_path(root)
        if root.exists():
            actual = RuntimeRelease.model_validate_json(read_bytes(root / "release.json", 16384))
            if actual != release:
                raise StudioStateError("Installed runtime receipt does not match this app")
            for name in ("python.exe", "Scripts/eforge.exe"):
                with os.fdopen(open_regular(root / name, os.O_RDONLY), "rb"):
                    pass
            return root
        archive_path = resources / selected.archive
        # Keep the verified file open during extraction; replacing its name cannot
        # substitute different bytes after the checksum has been checked.
        with archive_path.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != selected.sha256:
                raise StudioStateError("Bundled runtime checksum mismatch; download Studio again")
            source.seek(0)
            temporary = runtimes / f".install-{uuid4().hex}"
            private_directory(temporary)
            seen: set[str] = set()
            with tarfile.open(fileobj=source, mode="r:gz") as archive:
                for member in archive:
                    relative = payload_path(member.name)
                    key = relative.as_posix().casefold()
                    if key in seen or not (member.isdir() or member.isfile()):
                        raise StudioStateError(
                            "Runtime archive contains duplicate entries or links"
                        )
                    seen.add(key)
                    destination = temporary / relative
                    if member.isdir():
                        private_directory(destination)
                        continue
                    private_directory(destination.parent)
                    content = archive.extractfile(member)
                    if content is None:
                        raise StudioStateError("Runtime archive contains an unreadable file")
                    with (
                        content,
                        os.fdopen(
                            open_regular(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "wb"
                        ) as output,
                    ):
                        while chunk := content.read(1024 * 1024):
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
            if not all(
                (temporary / name).is_file() for name in ("python.exe", "Scripts/eforge.exe")
            ):
                raise StudioStateError("The bundled Windows runtime is incomplete")
            atomic_write(temporary / "release.json", release.model_dump_json().encode())
            # Windows pruning is disabled. Do not advertise the POSIX cleanup contract.
            from evidenceforge.utils.windows_filesystem import publish_new_directory

            publish_new_directory(temporary, root)
        return root


def main() -> None:
    """Return the retained root to the native launcher without touching Studio state."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", required=True, type=Path)
    parser.add_argument("--data", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        root = install_runtime(arguments.resources.absolute(), arguments.data.absolute())
    except (OSError, ValueError, tarfile.TarError, StudioStateError) as error:
        parser.exit(1, f"Could not install Studio's private runtime: {error}\n")
    print(json.dumps(str(root)))


if __name__ == "__main__":
    main()
