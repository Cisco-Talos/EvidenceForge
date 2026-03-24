"""Install EvidenceForge Claude Code commands to .claude/commands/ directory."""

import importlib.resources
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

    # Reference docs — installed: _data/references/, dev: docs/
    for ref_name, dev_name in [
        ("scenario-reference.md", "scenario-reference.md"),
        ("evidence-formats.md", "EVIDENCE_FORMATS.md"),
    ]:
        installed_ref = data_root / "references" / ref_name
        dev_ref = data_root / "docs" / dev_name
        if installed_ref.exists():
            manifest[f"references/{ref_name}"] = installed_ref
        elif dev_ref.exists():
            manifest[f"references/{ref_name}"] = dev_ref

    # Persona files — installed: _data/personas/, dev: personas/
    personas_dir = data_root / "personas"
    if personas_dir.is_dir():
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

    eforge_dir = ensure_directory(target_dir / "eforge")

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
