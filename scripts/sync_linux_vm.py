"""Copy this checkout's source files to a Linux checkout using rsync over SSH."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4


def source_manifest(root: Path) -> tuple[bytes, int]:
    """Include tracked and unignored new files, omitting locally removed files."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--deduplicate", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    included: list[bytes] = []
    removed: int = 0
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        path = root / os.fsdecode(entry)
        if path.is_symlink() or path.is_file():
            included.append(entry)
        elif path.is_dir():
            raise ValueError(f"Cannot sync a directory entry (possibly a submodule): {path}")
        else:
            removed += 1
    if not included:
        raise ValueError("No source files found in this checkout")
    return b"\0".join(sorted(included)) + b"\0", removed


def main() -> int:
    """Synchronize source while preserving remote dependencies and replacement backups."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="SSH destination, for example developer@linux-vm")
    parser.add_argument("destination", help="Absolute path to the existing Linux checkout")
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview without changing remote files"
    )
    arguments = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", arguments.host):
        parser.error("Use an SSH hostname or user@hostname, without shell options")
    destination = PurePosixPath(arguments.destination)
    if not destination.is_absolute() or ".." in destination.parts or len(destination.parts) < 4:
        parser.error("Use an absolute checkout path, such as /home/developer/EvidenceForge")
    for executable in ("git", "rsync", "ssh"):
        if shutil.which(executable) is None:
            parser.error(f"Install {executable} on the source machine first")
    root = Path(__file__).resolve().parents[1]
    try:
        manifest, removed = source_manifest(root)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.error(str(exc))
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    backup = destination.parent / f"{destination.name}.sync-backups" / stamp
    command: list[str] = [
        "rsync",
        "--recursive",
        "--links",
        "--safe-links",
        "--executability",
        "--omit-dir-times",
        "--checksum",
        "--compress",
        "--protect-args",
        "--from0",
        "--files-from=-",
        "--backup",
        f"--backup-dir={backup}",
        "--itemize-changes",
        "--stats",
        "--rsh=ssh -o ConnectTimeout=10",
    ]
    # Also protect these paths if accidentally tracked in a future checkout.
    for pattern in (
        ".git/",
        ".venv/",
        "node_modules/",
        "__pycache__/",
        ".pytest_cache/",
        ".ruff_cache/",
        ".mypy_cache/",
        ".uv/",
        ".codex/",
        ".claude/",
        ".agents/",
        "dist/",
        "build/",
        "/desktop-ui/src-tauri/target/",
        ".DS_Store",
        "._*",
        ".env",
        ".env.*",
    ):
        command.append(f"--exclude={pattern}")
    if arguments.dry_run:
        command.append("--dry-run")
    command.extend(["--", f"{root}/", f"{arguments.host}:{destination}/"])
    print(f"Source: {root}", flush=True)
    print(f"Destination: {arguments.host}:{destination}", flush=True)
    print(f"Replacement backups: {backup}", flush=True)
    if removed:
        print(f"Skipped {removed} locally removed files; review remote deletions separately.")
    print("Remote-only files are retained. Git metadata is not synchronized.", flush=True)
    return subprocess.run(command, input=manifest, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
