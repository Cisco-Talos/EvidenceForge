"""Synchronize Studio release metadata from pyproject.toml, or check it without writes."""

from __future__ import annotations

import argparse
import ast
import json
import re
import tomllib
from pathlib import Path


def studio_version(version: str) -> str:
    """Convert the project's canonical PEP 440 release version to SemVer."""
    match = re.fullmatch(
        r"((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})(?:(a|b|rc)(0|[1-9][0-9]*))?",
        version,
    )
    if match is None:
        raise ValueError(
            "EvidenceForge version must be X.Y.Z, X.Y.ZaN, X.Y.ZbN or X.Y.ZrcN "
            f"with canonical numbers, got {version!r}"
        )
    base, phase, number = match.groups()
    if phase is None:
        return base
    label = {"a": "alpha", "b": "beta", "rc": "rc"}[phase]
    return f"{base}-{label}.{number}"


def release_version(root: Path) -> str:
    """Read the authoritative version and verify the Python package and lock agree."""
    version: str = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    studio_version(version)
    tree = ast.parse((root / "src/evidenceforge/__init__.py").read_text())
    declared: str | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                declared = node.value.value
    lock = tomllib.loads((root / "uv.lock").read_text())
    locked = next(
        (package["version"] for package in lock["package"] if package["name"] == "evidence-forge"),
        None,
    )
    for label, actual in (("src/evidenceforge/__init__.py", declared), ("uv.lock", locked)):
        if actual != version:
            raise ValueError(
                f"{label} version {actual!r} does not match pyproject.toml {version!r}"
            )
    return version


def synchronize(root: Path, *, check: bool = False) -> str:
    """Update derived Studio metadata, or reject drift without changing any files."""
    version = release_version(root)
    expected = studio_version(version)
    changes: dict[Path, str] = {}
    for relative in (
        "desktop-ui/package.json",
        "desktop-ui/package-lock.json",
        "desktop-ui/src-tauri/tauri.conf.json",
    ):
        path = root / relative
        original = path.read_text()
        document = json.loads(original)
        mismatch = document["version"] != expected
        if relative.endswith("package-lock.json"):
            mismatch = mismatch or document["packages"][""]["version"] != expected
        if not mismatch:
            continue
        document["version"] = expected
        if relative.endswith("package-lock.json"):
            document["packages"][""]["version"] = expected
        updated = json.dumps(document, indent=2) + "\n"
        if updated != original:
            changes[path] = updated
    for relative, section in (
        ("desktop-ui/src-tauri/Cargo.toml", "[package]"),
        ("desktop-ui/src-tauri/Cargo.lock", 'name = "evidenceforge-studio"'),
    ):
        path = root / relative
        original = path.read_text()
        pattern = rf'({re.escape(section)}\n(?:(?!\[).)*?^version = ")[^"]+("$)'
        updated, count = re.subn(
            pattern, rf"\g<1>{expected}\2", original, count=1, flags=re.M | re.S
        )
        if count != 1:
            raise ValueError(f"Could not find the Studio package version in {relative}")
        if updated != original:
            changes[path] = updated
    if check and changes:
        paths = ", ".join(str(path.relative_to(root)) for path in changes)
        raise ValueError(
            f"Studio version metadata differs from {version}: {paths}. Run npm run version:sync in desktop-ui."
        )
    for path, content in changes.items():
        path.write_text(content)
    return version


def main() -> None:
    """Expose synchronization and a read-only release guard without extra dependencies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    try:
        version = synchronize(Path(__file__).resolve().parents[1], check=arguments.check)
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"{error}\n")
    print(f"EvidenceForge and Studio release version: {version}")


if __name__ == "__main__":
    main()
