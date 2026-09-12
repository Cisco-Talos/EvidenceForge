"""Capture process normalization, reuse and admission through the canonical eCAR path."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

CASES = (
    "powershell_script",
    "batch_script",
    "psexec_service",
    "defender_path",
    "persistent_reuse",
    "browser_reuse",
    "browser_precedence",
    "exact_parent",
    "visibility_rejection",
)


def capture(args: argparse.Namespace) -> None:
    """Execute a fixed process request with explicit warm-up session and parent state."""
    sys.path.insert(0, str(args.source.resolve() / "src"))
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.models.scenario import System, User
    from evidenceforge.utils.rng import _get_rng, generation_seed_scope, reset_thread_rng

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
            hostname="WIN-01",
            ip="10.10.2.20",
            os="Windows 11",
            type="workstation",
            assigned_user=user.username,
        )
        logon_id = state.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=start - timedelta(minutes=4),
            session_kind="interactive",
        )
        parent_pid = state.create_process(
            system.hostname,
            4,
            r"C:\Windows\explorer.exe",
            r"C:\Windows\explorer.exe",
            user.username,
            "Medium",
            logon_id=logon_id,
        )
        session = state.get_session(logon_id)
        assert session is not None
        session.session_shell_pid = parent_pid
        image = r"C:\Windows\System32\whoami.exe"
        command = "whoami.exe"
        existing: dict[str, int] = {}
        if args.case == "powershell_script":
            image = r"C:\Users\analyst\inventory.ps1"
            command = r"C:\Users\analyst\inventory.ps1 -Verbose"
        elif args.case == "batch_script":
            image = r"C:\Users\analyst\inventory.cmd"
            command = r"C:\Users\analyst\inventory.cmd /verbose"
        elif args.case == "psexec_service":
            image, command = "PSEXESVC.exe", "PSEXESVC.exe -accepteula"
        elif args.case == "defender_path":
            image = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.00000.0\MsMpEng.exe"
            command = image
        elif args.case == "persistent_reuse":
            image = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
            command = image
            existing["outlook"] = state.create_process(
                system.hostname,
                parent_pid,
                image,
                command,
                user.username,
                "Medium",
                logon_id=logon_id,
            )
        elif args.case in {"browser_reuse", "browser_precedence"}:
            image = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            command = "chrome.exe https://intranet.example.test/"
            existing["chrome"] = state.create_process(
                system.hostname,
                parent_pid,
                image,
                image,
                user.username,
                "Medium",
                logon_id=logon_id,
            )
            if args.case == "browser_precedence":
                edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
                state.set_current_time(start - timedelta(minutes=3))
                existing["edge"] = state.create_process(
                    system.hostname,
                    parent_pid,
                    edge,
                    edge,
                    user.username,
                    "Medium",
                    logon_id=logon_id,
                )
                generator._preferred_browser_by_session[(system.hostname, user.username, "")] = (
                    "msedge.exe"
                )
        elif args.case == "exact_parent":
            image = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            command = "chrome.exe --type=renderer"
            state.set_current_time(start - timedelta(minutes=3))
            parent_pid = state.create_process(
                system.hostname,
                parent_pid,
                image,
                "chrome.exe",
                user.username,
                "Medium",
                logon_id=logon_id,
            )
        pid = generator.generate_process(
            user,
            system,
            start,
            logon_id,
            image,
            command,
            parent_pid=parent_pid,
            suppress_command_file_effect=True,
            require_exact_parent=args.case == "exact_parent",
            source_visible_by=start if args.case == "visibility_rejection" else None,
        )
        running = state.get_process(system.hostname, pid) if pid else None
        truth = {
            "case": args.case,
            "seed": args.seed,
            "requested_image": image,
            "requested_command": command,
            "requested_parent": parent_pid,
            "pid": pid,
            "existing": existing,
            "process": None
            if running is None
            else {
                "image": running.image,
                "command": running.command_line,
                "parent_pid": running.parent_pid,
                "username": running.username,
                "logon_id": running.logon_id,
                "start": running.start_time.isoformat(),
                "last_activity": running.last_activity_time.isoformat()
                if running.last_activity_time
                else None,
            },
            "rng_sha256": hashlib.sha256(repr(_get_rng().getstate()).encode()).hexdigest(),
        }
        emitter.close()
        (args.output / "GROUND_TRUTH.json").write_text(json.dumps(truth, indent=2) + "\n")


def main() -> None:
    """Capture one immutable native-evidence process case."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, choices=(42, 137), required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--threaded", action="store_true")
    capture(parser.parse_args())


if __name__ == "__main__":
    main()
