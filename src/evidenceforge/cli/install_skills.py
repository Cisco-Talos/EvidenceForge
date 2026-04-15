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

"""Install EvidenceForge Claude Code commands to .claude/commands/ directory."""

import importlib.resources
import os
import shutil
from pathlib import Path

from evidenceforge.utils.files import ensure_directory

# Relative paths within the installed eforge/ directory that we expect to exist.
# Used both to copy files and to identify stale files for cleanup.
SKILL_FILES = [
    "scenario.md",
    "generate.md",
    "validate.md",
    "evaluate.md",
]

REFERENCE_FILES = [
    "references/scenario-reference.md",
    "references/evidence-formats.md",
]


def _get_data_root() -> Path:
    """Resolve the root directory containing bundled data files.

    In an installed package (pip install / uv tool install), files live under
    evidenceforge/_data/ via hatch force-include. In development (editable install),
    they live at the project root in their original locations.

    Returns:
        Path to the data root, or raises FileNotFoundError.
    """
    # Try importlib.resources first (installed package)
    try:
        data_pkg = importlib.resources.files("evidenceforge._data")
        # Check that it actually has content (not just the __init__.py)
        skills_dir = data_pkg / "commands" / "eforge" / "scenario.md"
        # Traversable.is_file() works for both filesystem and zip paths
        if skills_dir.is_file():
            return Path(str(data_pkg))
    except (ModuleNotFoundError, TypeError, FileNotFoundError, AttributeError):
        pass

    # Development fallback: walk up from this file to find project root
    current = Path(__file__).resolve().parent
    for _ in range(5):
        current = current.parent
        if (current / "commands" / "eforge" / "scenario.md").exists():
            return current

    raise FileNotFoundError(
        "Cannot locate EvidenceForge data files. "
        "Ensure you're running from the project directory or have installed the package."
    )


def _collect_source_files(data_root: Path) -> dict[str, Path]:
    """Build a mapping of relative target paths to source file paths.

    Handles both installed layout (_data/commands/eforge/, _data/personas/, _data/references/)
    and development layout (commands/eforge/, personas/, docs/).

    Returns:
        Dict mapping relative path within eforge/ -> absolute source path.
    """
    manifest: dict[str, Path] = {}

    # Detect layout: installed has _data/commands/eforge/, dev has commands/eforge/
    if (data_root / "commands" / "eforge" / "scenario.md").exists():
        skills_dir = data_root / "commands" / "eforge"
    else:
        raise FileNotFoundError(f"Command files not found under {data_root}")

    # Skill markdown files
    for skill_file in SKILL_FILES:
        source = skills_dir / skill_file
        if source.exists():
            manifest[skill_file] = source

    # Reference docs — installed: _data/references/, dev: docs/reference/
    for ref_name, dev_name in [
        ("scenario-reference.md", "scenario-reference.md"),
        ("evidence-formats.md", "EVIDENCE_FORMATS.md"),
    ]:
        installed_ref = data_root / "references" / ref_name
        dev_ref = data_root / "docs" / "reference" / dev_name
        if installed_ref.exists():
            manifest[f"references/{ref_name}"] = installed_ref
        elif dev_ref.exists():
            manifest[f"references/{ref_name}"] = dev_ref

    # Persona files — installed: _data/personas/, dev: config/personas/
    personas_dir = data_root / "personas"
    if not personas_dir.is_dir():
        # Dev-mode: personas live in src/evidenceforge/config/personas/
        from evidenceforge.config import get_personas_directory

        try:
            personas_dir = get_personas_directory()
        except Exception:
            personas_dir = None
    if personas_dir and personas_dir.is_dir():
        for yaml_file in sorted(personas_dir.glob("*.yaml")):
            rel_path = f"personas/{yaml_file.name}"
            manifest[rel_path] = yaml_file

    return manifest


def _remove_stale_files(eforge_dir: Path, manifest: dict[str, Path]) -> list[str]:
    """Remove files in the target eforge/ directory that aren't in the manifest.

    Only removes files, not directories (empty dirs are harmless).

    Returns:
        List of relative paths that were removed.
    """
    removed = []
    if not eforge_dir.exists():
        return removed

    for path in sorted(eforge_dir.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(eforge_dir))
            if rel not in manifest:
                path.unlink()
                removed.append(rel)

    # Clean up empty directories (bottom-up)
    for path in sorted(eforge_dir.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()

    return removed


def _ensure_safe_eforge_directory(target_dir: Path) -> Path:
    """Create or validate a safe install directory for eforge skills.

    Rejects symlinked destination directories to prevent writes/deletes from
    being redirected outside the intended install location.
    """
    eforge_dir = target_dir / "eforge"
    if eforge_dir.exists() and eforge_dir.is_symlink():
        raise PermissionError(f"Refusing to install skills into symlinked directory: {eforge_dir}")

    ensure_directory(target_dir)
    eforge_dir.mkdir(parents=True, exist_ok=True)

    # Check again after creation to avoid races where the path is swapped.
    if eforge_dir.is_symlink():
        raise PermissionError(f"Refusing to install skills into symlinked directory: {eforge_dir}")

    target_real = target_dir.resolve()
    eforge_real = eforge_dir.resolve()
    if os.path.commonpath([str(eforge_real), str(target_real)]) != str(target_real):
        raise PermissionError(f"Refusing to install skills outside target directory: {eforge_dir}")

    return eforge_dir


def install_skills(target_dir: Path) -> tuple[list[str], list[str]]:
    """Install EvidenceForge skills to the target directory.

    Creates {target_dir}/eforge/ with skills, references, and personas.
    Overwrites existing files and removes stale files from previous installs.

    Args:
        target_dir: Parent directory (e.g., .claude/commands/)

    Returns:
        Tuple of (installed_files, removed_files) as relative path lists.
    """
    data_root = _get_data_root()
    manifest = _collect_source_files(data_root)

    if not manifest:
        raise FileNotFoundError("No skill files found to install.")

    eforge_dir = _ensure_safe_eforge_directory(target_dir)

    # Copy all files from manifest
    installed = []
    for rel_path, source in sorted(manifest.items()):
        dest = eforge_dir / rel_path
        ensure_directory(dest.parent)
        shutil.copy2(source, dest)
        installed.append(rel_path)

    # Remove stale files
    removed = _remove_stale_files(eforge_dir, manifest)

    return installed, removed
