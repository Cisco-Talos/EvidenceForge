"""Platform locations for private Studio data and user-authored workspaces."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from platformdirs import user_documents_path
from pydantic import BaseModel, ConfigDict, Field


class StudioPaths(BaseModel):
    """Resolved private paths for one OS user."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    config: Path
    data: Path
    state: Path
    cache: Path
    logs: Path
    # Explicit overrides cannot inherit the permission-repair policy of application defaults.
    custom_roots: tuple[Path, ...] = Field(default=(), exclude=True, repr=False)

    @property
    def settings_file(self) -> Path:
        """Return the global settings path."""
        return self.config / "settings.json"

    @property
    def database_file(self) -> Path:
        """Return the durable metadata database path."""
        return self.data / "studio.sqlite"

    @property
    def service_file(self) -> Path:
        """Return the private service discovery path."""
        return self.state / "service.json"


def studio_paths() -> StudioPaths:
    """Use platform conventions, with one disposable-root test override."""
    override = os.environ.get("EFORGE_STUDIO_HOME")
    if override:
        root = Path(override).expanduser().absolute()
        return StudioPaths(
            config=root / "config",
            data=root / "data",
            state=root / "state",
            cache=root / "cache",
            logs=root / "logs",
            custom_roots=(root,),
        )
    if sys.platform == "darwin":
        support = Path.home() / "Library" / "Application Support" / "EvidenceForge"
        return StudioPaths(
            config=support,
            data=support,
            state=support / "state",
            cache=Path.home() / "Library" / "Caches" / "EvidenceForge",
            logs=Path.home() / "Library" / "Logs" / "EvidenceForge",
        )
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        root = local / "EvidenceForge"
        return StudioPaths(
            config=root,
            data=root,
            state=root,
            cache=root / "cache",
            logs=root / "logs",
        )
    config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    data = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return StudioPaths(
        config=config / "evidenceforge",
        data=data / "evidenceforge",
        state=state / "evidenceforge",
        cache=cache / "evidenceforge",
        logs=state / "evidenceforge",
        custom_roots=tuple(
            root / "evidenceforge"
            for variable, root, standard in (
                ("XDG_CONFIG_HOME", config, Path.home() / ".config"),
                ("XDG_DATA_HOME", data, Path.home() / ".local/share"),
                ("XDG_STATE_HOME", state, Path.home() / ".local/state"),
                ("XDG_CACHE_HOME", cache, Path.home() / ".cache"),
            )
            if variable in os.environ and root.absolute() != standard.absolute()
        ),
    )


def _linux_documents() -> Path | None:
    """Return a distinct XDG Documents directory when one is configured."""
    config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    try:
        lines = (config / "user-dirs.dirs").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == "XDG_DOCUMENTS_DIR":
            raw = value.strip().strip('"').replace("$HOME", str(Path.home()))
            path = Path(raw).expanduser()
            if path.is_absolute() and path.resolve() != Path.home().resolve():
                return path
    return None


def default_workspace() -> Path:
    """Choose a visible Documents workspace independent of the launch directory."""
    override = os.environ.get("EFORGE_STUDIO_DEFAULT_WORKSPACE")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform.startswith("linux"):
        return (_linux_documents() or Path.home()) / "EvidenceForge"
    return user_documents_path() / "EvidenceForge"


def ensure_workspace(path: Path) -> Path:
    """Create only the default authoring and run directories."""
    workspace = path.expanduser().resolve()
    (workspace / "scenarios").mkdir(parents=True, exist_ok=True)
    (workspace / "runs").mkdir(parents=True, exist_ok=True)
    return workspace
