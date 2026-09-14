"""Test process running the real CLI, stopped at an observed native I/O boundary."""

import argparse
import os
import sys
from pathlib import Path

from tests.support.checkpoint_power_loss import StorageEvent
from tests.support.windows_checkpoint_trace import trace_checkpoint_io


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--restore", action="store_true")
    arguments, cli = parser.parse_known_args()
    assert cli[0] == "--"
    assert os.name == "nt"
    assert "PYTEST_CURRENT_TEST" in os.environ

    def stop(event: StorageEvent) -> None:
        if not arguments.restore and event.operation == "ack" and event.sequence == 2:
            os._exit(0)
        if arguments.restore and event.operation == "rename" and "/staged/" in event.target:
            with arguments.trace.open("a", encoding="utf-8") as output:
                import json

                output.write(
                    json.dumps(StorageEvent("stage", stage="restore-interrupted").document()) + "\n"
                )
            os._exit(0)

    from evidenceforge.cli.commands import main as cli_main

    sys.argv = ["eforge", *cli[1:]]
    with trace_checkpoint_io(arguments.root, arguments.trace, on_event=stop):
        cli_main()
    raise AssertionError("CLI completed without reaching the requested test interruption")


if __name__ == "__main__":
    main()
