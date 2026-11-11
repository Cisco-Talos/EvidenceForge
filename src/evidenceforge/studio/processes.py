"""Platform launch options for Studio-owned subprocesses."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def executable_command(command: str | Path) -> list[str]:
    """Run explicit Python scripts on Windows without relying on shell associations."""
    path = str(command)
    if os.name == "nt" and Path(path).suffix.lower() == ".py":
        return [sys.executable, path]
    return [path]


def launch_options(*, detached: bool = False) -> dict[str, Any]:
    """Hide Windows consoles; preserve POSIX sessions and inherited runtime leases."""
    if os.name == "nt":
        # Windows children are independent of their parent by default. A separate
        # process group also prevents console interrupts targeting the launcher.
        flags = subprocess.CREATE_NO_WINDOW
        if detached:
            flags |= subprocess.CREATE_NEW_PROCESS_GROUP
        return {"creationflags": flags}
    from evidenceforge.studio.runtime_cleanup import runtime_worker_fds

    options: dict[str, Any] = {"pass_fds": runtime_worker_fds()}
    if detached:
        options["start_new_session"] = True
    return options
