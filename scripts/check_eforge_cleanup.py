"""Recognize the one-time project-state removal that must not publish a release.

Only deletion of every tracked .eforge file, removal of its ignore exceptions,
and the supporting release guard/workflow/tests qualify. Product and version
changes use the normal release path. Once .eforge is untracked, ordinary future
maintenance cannot qualify because it has no project-state deletions.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path


def git(root: Path, *arguments: str) -> str:
    """Read committed Git data, failing closed on missing objects or Git errors."""
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def is_eforge_cleanup(root: Path, base: str, head: str = "HEAD") -> bool:
    """Return whether the complete committed diff is the bounded cleanup."""
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", base) or set(base) == {"0"}:
        return False
    fields = git(root, "diff", "--no-renames", "--name-status", "-z", base, head).split("\0")
    changes = dict(zip(fields[1::2], fields[0:-1:2], strict=True))
    supporting = {
        ".gitignore": "M",
        ".github/workflows/release.yml": "M",
        "scripts/check_eforge_cleanup.py": "A",
        "tests/unit/test_eforge_cleanup.py": "A",
        "tests/unit/test_release_pipeline.py": "M",
    }
    removed = False
    for path, status in changes.items():
        if path.startswith(".eforge/"):
            if status != "D":
                return False
            removed = True
        elif supporting.get(path) != status:
            return False
    if not removed or changes.get(".gitignore") != "M":
        return False
    if git(root, "ls-tree", "-r", "--name-only", head, "--", ".eforge"):
        return False
    before = git(root, "show", f"{base}:.gitignore")
    after = git(root, "show", f"{head}:.gitignore")
    expected = "".join(
        line
        for line in before.splitlines(keepends=True)
        if not line.startswith(("!.eforge/", ".eforge/*", ".eforge/packs/"))
    )
    return after == expected and ".eforge/" in after.splitlines()


def main() -> None:
    """Write the release-scope output for the exact PR or main-push diff."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    arguments = parser.parse_args()
    cleanup = is_eforge_cleanup(Path.cwd().resolve(), arguments.base)
    value = "true" if cleanup else "false"
    print(f"Project-state cleanup without publication: {value}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(f"cleanup={value}\n")


if __name__ == "__main__":
    main()
