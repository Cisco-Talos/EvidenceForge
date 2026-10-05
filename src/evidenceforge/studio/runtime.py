"""Private standalone runtime identity and command discovery."""

from __future__ import annotations

import os
import shutil
import sys
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class RuntimeRelease(BaseModel):
    """Identity of the retained payload selected by the native launcher."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    runtime_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidenceforge_version: str
    python_version: str
    architecture: str


def runtime_root() -> Path | None:
    """Return the explicitly selected private runtime, never infer a project root."""
    value = os.environ.get("EFORGE_STUDIO_RUNTIME_ROOT")
    return Path(value).resolve() if value else None


_source_identity: str | None = None


def _source_runtime_id(package: Path) -> str:
    """Fingerprint the source backend and its selected dependency declarations."""
    digest = sha256()
    digest.update(os.fsencode(package.resolve()))
    digest.update(os.fsencode(Path(sys.executable).resolve()))
    sources = sorted(path for path in package.rglob("*.py") if "__pycache__" not in path.parts)
    project = package.parent.parent
    sources.extend(
        path for name in ("pyproject.toml", "uv.lock") if (path := project / name).is_file()
    )
    for path in sources:
        digest.update(os.fsencode(path.relative_to(project)))
        digest.update(b"\0")
        digest.update(sha256(path.read_bytes()).digest())
    return f"source-{digest.hexdigest()}"


def runtime_id() -> str:
    """Return packaged or source content identity for the current helper build."""
    global _source_identity
    root = runtime_root()
    if root is None:
        if _source_identity is None:
            _source_identity = _source_runtime_id(Path(__file__).resolve().parent.parent)
        return _source_identity
    release = RuntimeRelease.model_validate_json((root / "release.json").read_bytes())
    if not Path(sys.executable).resolve().is_relative_to(root):
        raise RuntimeError("Studio's interpreter is outside its selected private runtime")
    return release.runtime_id


def command_environment() -> dict[str, str]:
    """Expose the private CLI only to Studio's subprocesses."""
    environment = dict(os.environ)
    root = runtime_root()
    if root is not None:
        environment["PATH"] = str(root / "bin") + os.pathsep + environment.get("PATH", "")
        environment.pop("PYTHONHOME", None)
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def discover_codex(explicit: Path | None = None) -> str | None:
    """Locate separately installed Codex without requiring a login shell."""
    configured = os.environ.get("EFORGE_DESKTOP_CODEX_BIN")
    if configured:
        return configured
    if explicit is not None:
        return str(explicit.expanduser().resolve())
    found = shutil.which("codex")
    if found or sys.platform != "darwin":
        return found
    # Finder has a minimal PATH. Prefer the standalone CLI there too so a
    # separate Codex.app installation does not hide the CLI's model catalog.
    candidates = [
        Path("/opt/homebrew/bin/codex"),
        Path("/usr/local/bin/codex"),
        Path.home() / ".local/bin/codex",
        Path("/Applications/Codex.app/Contents/Resources/codex"),
        Path.home() / "Applications/Codex.app/Contents/Resources/codex",
    ]
    return next(
        (str(path) for path in candidates if path.is_file() and os.access(path, os.X_OK)), None
    )
