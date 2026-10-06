"""Disposable native helper process with an announced startup barrier."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from evidenceforge.studio import bootstrap
from evidenceforge.studio.service import create_app
from evidenceforge.studio.sessions import WindowSessions
from tests.support.studio_state import paths


def main() -> None:
    """Run production server shutdown with shortened, injected test grace periods."""
    root = Path(sys.argv[1])
    os.environ["EFORGE_STUDIO_DEFAULT_WORKSPACE"] = str(root / "workspace")
    os.environ.pop("EFORGE_STUDIO_RUNTIME_ROOT", None)
    os.environ["EFORGE_DESKTOP_CODEX_BIN"] = str(root / "no-codex-in-helper-tests")

    def announced_app(*args: Any, **kwargs: Any) -> FastAPI:
        app = create_app(
            *args, **kwargs, sessions=WindowSessions(lease_seconds=10, idle_seconds=0.1)
        )
        original = app.router.lifespan_context

        @asynccontextmanager
        async def announced_lifespan(app: FastAPI) -> AsyncIterator[None]:
            async with original(app):
                print("ready", flush=True)
                yield

        app.router.lifespan_context = announced_lifespan
        return app

    bootstrap.create_app = announced_app
    bootstrap.serve(paths(root / "private"))


if __name__ == "__main__":
    main()
