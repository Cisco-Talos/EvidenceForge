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

"""Install EvidenceForge agent skills."""

import importlib.resources
import os
import shutil
from pathlib import Path

from evidenceforge.utils.files import ensure_directory

CODEX_SKILL_NAMES = ("scenario", "generate", "validate", "evaluate", "config")

_CODEX_REFERENCES_BY_SKILL = {
    "config": (
        "references/config-apps-processes.md",
        "references/config-dependency-graph.md",
        "references/config-dns-network.md",
        "references/config-evaluation.md",
        "references/config-formats.md",
        "references/config-host-activity.md",
        "references/config-personas.md",
        "references/config-validation.md",
    ),
    "evaluate": (
        "references/evidence-formats.md",
        "references/scenario-reference.md",
    ),
    "generate": (
        "references/evidence-formats.md",
        "references/scenario-reference.md",
    ),
    "scenario": (
        "references/evidence-formats.md",
        "references/scenario-reference.md",
    ),
    "validate": ("references/scenario-reference.md",),
}

_CODEX_REFERENCE_REWRITES = {
    "/eforge:references:scenario-reference": "`references/scenario-reference.md`",
    "/eforge:references:evidence-formats": "`references/evidence-formats.md`",
}

_CODEX_COMMAND_REWRITES = {
    "/eforge scenario": "the `eforge-scenario` skill",
    "/eforge generate": "the `eforge-generate` skill",
    "/eforge validate": "the `eforge-validate` skill",
    "/eforge evaluate": "the `eforge-evaluate` skill",
    "/eforge config": "the `eforge-config` skill",
}


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

    Auto-discovers all files under commands/eforge/ so that adding new skills
    or references doesn't require updating a manifest. Also discovers persona
    YAML files from the config directory.

    Handles both installed layout (_data/commands/eforge/) and development
    layout (commands/eforge/).

    Returns:
        Dict mapping relative path within eforge/ -> absolute source path.
    """
    manifest: dict[str, Path] = {}

    # Detect layout: installed has _data/commands/eforge/, dev has commands/eforge/
    if (data_root / "commands" / "eforge" / "scenario.md").exists():
        skills_dir = data_root / "commands" / "eforge"
    else:
        raise FileNotFoundError(f"Command files not found under {data_root}")

    # Auto-discover all .md files under commands/eforge/ (skills + references).
    # The directory structure mirrors the installed layout, so relative paths
    # map directly to target paths.
    for md_file in sorted(skills_dir.rglob("*.md")):
        rel_path = str(md_file.relative_to(skills_dir))
        manifest[rel_path] = md_file

    # Persona YAML files are NOT installed here. Skills that need persona
    # data should run `eforge info --json` to get the persona list and read
    # files from `paths.personas`. This avoids stale copies and ensures
    # overlay personas are visible.

    return manifest


def _collect_command_files(manifest: dict[str, Path]) -> dict[str, Path]:
    """Return top-level command skill files keyed by command name."""
    command_files: dict[str, Path] = {}
    for name in CODEX_SKILL_NAMES:
        rel_path = f"{name}.md"
        if rel_path not in manifest:
            raise FileNotFoundError(f"Required skill file not found: {rel_path}")
        command_files[name] = manifest[rel_path]
    return command_files


def _collect_reference_files(manifest: dict[str, Path]) -> dict[str, Path]:
    """Return reference files to bundle inside each Codex skill."""
    return {rel: source for rel, source in manifest.items() if rel.startswith("references/")}


def _references_for_codex_skill(
    skill_name: str, reference_files: dict[str, Path]
) -> dict[str, Path]:
    """Return the reference files needed by a single Codex skill."""
    refs: dict[str, Path] = {}
    for rel_path in _CODEX_REFERENCES_BY_SKILL[skill_name]:
        if rel_path not in reference_files:
            raise FileNotFoundError(f"Required reference file not found: {rel_path}")
        refs[rel_path] = reference_files[rel_path]
    return refs


def _validate_relative_install_path(rel_path: str) -> Path:
    """Return a safe relative install path and reject traversal/absolute paths."""
    path = Path(rel_path)
    if path.is_absolute() or ".." in path.parts:
        raise PermissionError(
            f"Refusing to install skill file outside target directory: {rel_path}"
        )
    return path


def _ensure_descendant(root: Path, path: Path) -> None:
    """Raise if path does not resolve inside root."""
    root_real = root.resolve()
    path_real = path.resolve()
    if os.path.commonpath([str(path_real), str(root_real)]) != str(root_real):
        raise PermissionError(f"Refusing to install skills outside target directory: {path}")


def _ensure_safe_install_parent(root: Path, relative_parent: Path) -> Path:
    """Create a destination parent directory without following nested symlinks."""
    from evidenceforge.utils.paths import reject_symlink

    current = root
    _ensure_descendant(root, current)
    for part in relative_parent.parts:
        current = current / part
        reject_symlink(current)
        current.mkdir(exist_ok=True)
        reject_symlink(current)
        if not current.is_dir():
            raise PermissionError(f"Refusing to install through non-directory path: {current}")
        _ensure_descendant(root, current)
    return current


def _safe_install_destination(root: Path, rel_path: str) -> Path:
    """Return a destination path after validating nested parents and existing files."""
    from evidenceforge.utils.paths import reject_symlink

    safe_rel_path = _validate_relative_install_path(rel_path)
    _ensure_safe_install_parent(root, safe_rel_path.parent)
    dest = root / safe_rel_path
    reject_symlink(dest)
    if dest.exists() and not dest.is_file():
        raise PermissionError(f"Refusing to overwrite non-file install path: {dest}")
    _ensure_descendant(root, dest.parent)
    return dest


def _write_text_no_follow(dest: Path, content: str) -> None:
    """Write text to dest without following an existing destination symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(dest, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def _copy_file_no_follow(source: Path, dest: Path) -> None:
    """Copy a file to dest without following an existing destination symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    mode = source.stat().st_mode & 0o777
    fd = os.open(dest, flags, mode)
    with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
        shutil.copyfileobj(src, dst)
    shutil.copystat(source, dest, follow_symlinks=False)


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


def _is_evidenceforge_codex_skill(path: Path) -> bool:
    """Return True if path appears to be an EvidenceForge-owned Codex skill."""
    skill_file = path / "SKILL.md"
    if not skill_file.is_file():
        return False

    try:
        content = skill_file.read_text(encoding="utf-8")
    except OSError:
        return False

    return "EvidenceForge" in content and "name: eforge-" in content


def _split_frontmatter(content: str, source: Path) -> tuple[list[str], str]:
    """Split a Markdown skill file into YAML frontmatter lines and body text."""
    if not content.startswith("---\n"):
        raise ValueError(f"Skill file is missing YAML frontmatter: {source}")

    try:
        frontmatter_text, body = content[4:].split("\n---\n", 1)
    except ValueError as exc:
        raise ValueError(f"Skill file has unterminated YAML frontmatter: {source}") from exc

    return frontmatter_text.splitlines(), body


def _extract_frontmatter_value(lines: list[str], key: str, source: Path) -> str:
    """Extract a top-level scalar frontmatter value from a Claude command file."""
    prefix = f"{key}:"
    for line in lines:
        if line.startswith(prefix):
            value = line.removeprefix(prefix).strip()
            if not value:
                break
            return value
    raise ValueError(f"Skill file is missing required frontmatter field '{key}': {source}")


def _extract_frontmatter_block(lines: list[str], key: str, source: Path) -> list[str]:
    """Extract a block-style frontmatter value from a Claude command file."""
    prefix = f"{key}:"
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue

        marker = line.removeprefix(prefix).strip()
        if marker not in {">", "|", ">-", "|-", ">+", "|+"}:
            value = marker
            if value:
                return [f"  {value}"]
            break

        block_lines: list[str] = []
        for block_line in lines[index + 1 :]:
            if block_line and not block_line.startswith((" ", "\t")) and ":" in block_line:
                break
            block_lines.append(block_line)

        if block_lines:
            return block_lines
        break

    raise ValueError(f"Skill file is missing required frontmatter field '{key}': {source}")


def _codex_frontmatter_text(source: Path, frontmatter_lines: list[str]) -> str:
    """Build Codex-compatible SKILL.md frontmatter from Claude command metadata."""
    name = _extract_frontmatter_value(frontmatter_lines, "name", source)
    description_lines = _extract_frontmatter_block(frontmatter_lines, "description", source)

    return (
        "---\n"
        + "\n".join(
            [
                f"name: {name}",
                "description: >",
                *description_lines,
            ]
        )
        + "\n---\n"
    )


def _rewrite_codex_skill_body(body: str) -> str:
    """Adapt Claude-specific references in a skill body for Codex."""
    content = body
    for old, new in _CODEX_REFERENCE_REWRITES.items():
        content = content.replace(old, new)
    for old, new in _CODEX_COMMAND_REWRITES.items():
        content = content.replace(old, new)
    return content


def _ensure_safe_eforge_directory(target_dir: Path) -> Path:
    """Create or validate a safe install directory for eforge skills.

    Rejects symlinked destination directories to prevent writes/deletes from
    being redirected outside the intended install location.
    """
    from evidenceforge.utils.paths import reject_symlink

    eforge_dir = target_dir / "eforge"
    # Check symlink before and after creation (TOCTOU defense)
    reject_symlink(eforge_dir)

    ensure_directory(target_dir)
    eforge_dir.mkdir(parents=True, exist_ok=True)

    # Check again after creation to avoid races where the path is swapped.
    reject_symlink(eforge_dir)

    # Verify containment
    target_real = target_dir.resolve()
    eforge_real = eforge_dir.resolve()
    if os.path.commonpath([str(eforge_real), str(target_real)]) != str(target_real):
        raise PermissionError(f"Refusing to install skills outside target directory: {eforge_dir}")

    return eforge_dir


def _ensure_safe_codex_skill_directory(target_dir: Path, skill_name: str) -> Path:
    """Create or validate a safe Codex skill directory."""
    from evidenceforge.utils.paths import reject_symlink

    skill_dir = target_dir / skill_name
    reject_symlink(skill_dir)

    ensure_directory(target_dir)
    skill_dir.mkdir(parents=True, exist_ok=True)

    reject_symlink(skill_dir)

    target_real = target_dir.resolve()
    skill_real = skill_dir.resolve()
    if os.path.commonpath([str(skill_real), str(target_real)]) != str(target_real):
        raise PermissionError(f"Refusing to install skills outside target directory: {skill_dir}")

    return skill_dir


def _codex_skill_text(source: Path) -> str:
    """Read a command file and convert it to a valid Codex SKILL.md file."""
    content = source.read_text(encoding="utf-8")
    frontmatter_lines, body = _split_frontmatter(content, source)
    return _codex_frontmatter_text(source, frontmatter_lines) + _rewrite_codex_skill_body(body)


def install_skills(target_dir: Path) -> tuple[list[str], list[str]]:
    """Install EvidenceForge Claude skills to the target directory.

    Creates {target_dir}/eforge/ with skills and references.
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
        dest = _safe_install_destination(eforge_dir, rel_path)
        _copy_file_no_follow(source, dest)
        installed.append(rel_path)

    # Remove stale files
    removed = _remove_stale_files(eforge_dir, manifest)

    return installed, removed


def install_codex_skills(target_dir: Path) -> tuple[list[str], list[str]]:
    """Install EvidenceForge skills to a Codex skills directory.

    Creates one Codex skill directory per EvidenceForge command, each with a
    SKILL.md file and bundled references. Existing EvidenceForge-owned skill
    directories are updated and stale EvidenceForge-owned skill directories are
    removed.

    Args:
        target_dir: Codex skills directory, e.g. ~/.codex/skills/.

    Returns:
        Tuple of (installed_files, removed_files) as relative path lists.
    """
    data_root = _get_data_root()
    manifest = _collect_source_files(data_root)
    command_files = _collect_command_files(manifest)
    reference_files = _collect_reference_files(manifest)

    if not command_files:
        raise FileNotFoundError("No skill files found to install.")

    installed: list[str] = []
    removed: list[str] = []
    for name, source in sorted(command_files.items()):
        skill_name = f"eforge-{name}"
        skill_dir = _ensure_safe_codex_skill_directory(target_dir, skill_name)
        skill_reference_files = _references_for_codex_skill(name, reference_files)

        skill_manifest: dict[str, Path] = {"SKILL.md": source}
        skill_manifest.update(skill_reference_files)

        skill_file = _safe_install_destination(skill_dir, "SKILL.md")
        _write_text_no_follow(skill_file, _codex_skill_text(source))
        installed.append(f"{skill_name}/SKILL.md")

        for rel_path, ref_source in sorted(skill_reference_files.items()):
            dest = _safe_install_destination(skill_dir, rel_path)
            _copy_file_no_follow(ref_source, dest)
            installed.append(f"{skill_name}/{rel_path}")

        for stale in _remove_stale_files(skill_dir, skill_manifest):
            removed.append(f"{skill_name}/{stale}")

    return installed, removed
