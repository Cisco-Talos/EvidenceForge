"""Test-only migration subprocess with parent-controlled synchronization barriers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from evidenceforge.studio.state_upgrade import StateCoordinator
from tests.support.studio_state import paths


def main() -> None:
    """Run an operation in disposable storage; expose no production crash switches."""
    root = Path(sys.argv[1])
    boundary = sys.argv[2]
    action = sys.argv[3]
    os.environ["EFORGE_STUDIO_DEFAULT_WORKSPACE"] = str(root / "workspace")

    def observer(name: str) -> None:
        if name == boundary:
            print(json.dumps({"boundary": name}), flush=True)
            sys.stdin.readline()  # Parent deliberately terminates this blocked child.

    workspace = None
    file_migrations = ()
    if action.startswith("workspace-"):
        from tests.integration.test_studio_state_migrations import MOVES

        workspace = root / "workspace"
        file_migrations = MOVES
        action = action.removeprefix("workspace-")
    coordinator = StateCoordinator(
        paths(root / "private"), workspace, observer=observer, file_migrations=file_migrations
    )
    try:
        if action == "fresh":
            coordinator.initialize_if_fresh()
        status = (
            coordinator.status
            if action == "fresh" or action == "recover" and coordinator.status.state == "restored"
            else coordinator.apply(coordinator.status.operation_id, restore=action == "restore")
        )
        print(json.dumps({"result": status.state, "error": status.error}), flush=True)
    finally:
        coordinator.close()


if __name__ == "__main__":
    main()
