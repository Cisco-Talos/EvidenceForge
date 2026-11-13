"""Private, timestamped helper lifecycle phases without connection credentials."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from evidenceforge.studio.paths import StudioPaths
from evidenceforge.studio.state_io import open_regular

_reporter: ContextVar[Callable[[str], None] | None] = ContextVar(
    "studio_startup_reporter", default=None
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.propagate = False


def startup_phase(phase: str) -> None:
    """Record a phase only inside an explicitly configured helper/launcher context."""
    reporter = _reporter.get()
    if reporter is not None:
        reporter(phase)


@contextmanager
def lifecycle_log(paths: StudioPaths, role: str, runtime: str) -> Iterator[None]:
    """Append UTC phases to the owned service log while leaving console/IPC output alone."""
    descriptor = open_regular(paths.logs / "service.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as stream:
        handler = logging.StreamHandler(stream)
        context = object()
        handler.addFilter(
            lambda record: getattr(record, "_studio_startup_context", None) is context
        )
        formatter = logging.Formatter("%(asctime)sZ %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        started = time.monotonic()

        def report(phase: str) -> None:
            logger.info(
                "Studio lifecycle role=%s phase=%s elapsed_s=%.3f pid=%d runtime=%s",
                role,
                phase,
                time.monotonic() - started,
                os.getpid(),
                runtime,
                extra={"_studio_startup_context": context},
            )

        token = _reporter.set(report)
        try:
            report("enter")
            yield
        finally:
            report("exit")
            _reporter.reset(token)
            logger.removeHandler(handler)
            handler.close()
