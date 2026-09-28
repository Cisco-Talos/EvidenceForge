"""Optional desktop entry point with a useful missing-dependency error."""

from __future__ import annotations


def main() -> None:
    """Load Qt only when the optional desktop command is invoked."""
    try:
        from evidenceforge.desktop.main import main as launch
    except ModuleNotFoundError as error:
        if error.name == "PySide6":
            raise SystemExit("Install the desktop extra: uv sync --extra desktop") from error
        raise
    launch()
