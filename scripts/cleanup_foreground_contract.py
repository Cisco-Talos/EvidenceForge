"""Capture bounded foreground lifecycle evidence through the real eCAR renderer.

This fixture supplies canonical session/shell state directly so an absent release
really is absent: storyline lifetime heuristics cannot invent one for the fixture.
Run each source/seed/case in a fresh process and compare raw output directories.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

CASES = (
    "unknown",
    "collection_end",
    "early_termination",
    "bounded_early_termination",
    "legacy_early_termination",
    "known_completion",
    "session_teardown",
    "explicit_concurrency",
    "separate_shell",
)


def capture(args: argparse.Namespace) -> None:
    """Execute the fixed lifecycle input using the selected implementation."""
    sys.path.insert(0, str(args.source.resolve() / "src"))
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.models.scenario import System, User
    from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng

    args.output.mkdir(parents=True, exist_ok=False)
    with generation_seed_scope(args.seed):
        reset_thread_rng()
        start = datetime(2024, 3, 18, 13, tzinfo=UTC)
        state = StateManager()
        state.set_current_time(start - timedelta(minutes=5))
        emitter = EcarEmitter(load_format("ecar"), args.output, threaded=args.threaded)
        emitters = {"ecar": emitter}
        dispatcher = EventDispatcher(state_manager=state, emitters=emitters)
        generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
        generator._scenario_end_time = start + timedelta(minutes=12)
        user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.test")
        system = System(
            hostname="LNX-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=user.username,
        )
        terminal = "/usr/libexec/gnome-terminal-server"
        root_pid = state.create_process(
            system.hostname, 0, terminal, terminal, user.username, "Medium"
        )
        logon_id = state.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=start - timedelta(minutes=4),
            session_kind="interactive",
        )
        state.set_current_time(start - timedelta(minutes=3))
        shell_pid = state.create_process(
            system.hostname,
            root_pid,
            "/bin/bash",
            "-bash",
            user.username,
            "Medium",
            logon_id=logon_id,
        )
        session = state.get_session(logon_id)
        assert session is not None
        session.session_shell_pid = shell_pid
        image = "/usr/bin/smbclient"
        command = "smbclient //FILE-SRV/Shared"
        if args.case == "bounded_early_termination":
            image, command = "/usr/bin/sleep", "sleep 600"
        group = "pipeline:foreground-fixture" if args.case == "explicit_concurrency" else ""
        pid = generator.generate_process(
            user,
            system,
            start,
            logon_id,
            image,
            command,
            parent_pid=shell_pid,
            suppress_command_file_effect=True,
            concurrency_group_id=group,
        )
        assert pid > 0
        requested = start + timedelta(seconds=30)
        if args.case == "collection_end":
            generator.finalize_foreground_process_lifetimes(generator._scenario_end_time)
        if args.case == "known_completion":
            generator._remember_foreground_process_finalizer(
                system=system,
                user=user,
                pid=pid,
                process_name=image,
                logon_id=logon_id,
                termination_time=start + timedelta(seconds=20),
            )
            generator.finalize_foreground_process_lifetimes(requested)
        if args.case in {
            "early_termination",
            "bounded_early_termination",
            "legacy_early_termination",
        }:
            if args.case == "legacy_early_termination":
                generator._remember_foreground_shell_available(
                    system=system,
                    username=user.username,
                    logon_id=logon_id,
                    parent_pid=shell_pid,
                    termination_time=generator._scenario_end_time,
                    seed_text=command,
                )
            generator.generate_process_termination(
                user, system, start + timedelta(seconds=20), pid, image, logon_id
            )
        if args.case == "session_teardown":
            generator.generate_logoff(user, system, start + timedelta(seconds=20), logon_id)
        if args.case == "separate_shell":
            shell_pid = state.create_process(
                system.hostname,
                root_pid,
                "/bin/bash",
                "-bash",
                user.username,
                "Medium",
                logon_id=logon_id,
            )
        reserved = None
        next_pid = 0
        if args.case != "session_teardown":
            if group:
                reserved = requested
            else:
                reserved = generator.reserve_linux_foreground_process_start(
                    system=system,
                    username=user.username,
                    logon_id=logon_id,
                    parent_pid=shell_pid,
                    requested_time=requested,
                    process_name="/usr/bin/hostname",
                    command_line="hostname",
                )
            if reserved is not None and reserved < generator._scenario_end_time:
                next_pid = generator.generate_process(
                    user,
                    system,
                    reserved,
                    logon_id,
                    "/usr/bin/hostname",
                    "hostname",
                    parent_pid=shell_pid,
                    suppress_command_file_effect=True,
                    concurrency_group_id=group,
                )
        truth = {
            "case": args.case,
            "seed": args.seed,
            "command": command,
            "pid": pid,
            "requested": requested.isoformat(),
            "reserved": reserved.isoformat() if reserved is not None else None,
            "next_pid": next_pid,
            "foreground_remains_active": state.get_process(system.hostname, pid) is not None,
            "session_remains_active": state.get_session(logon_id) is not None,
        }
        emitter.close()
        (args.output / "GROUND_TRUTH.json").write_text(json.dumps(truth, indent=2) + "\n")


def main() -> None:
    """Capture one immutable native-evidence case."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, choices=(42, 137), required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--threaded", action="store_true")
    capture(parser.parse_args())


if __name__ == "__main__":
    main()
