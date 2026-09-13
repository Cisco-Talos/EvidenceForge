"""Capture parent and preflight decisions together with canonical process evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

CASES = (
    "windows_gui",
    "windows_same_exe",
    "windows_network",
    "windows_service",
    "windows_remote_wrapper",
    "windows_wrong_principal",
    "windows_future_parent",
    "windows_missing_parent",
    "linux_shell",
    "linux_missing_anchor",
    "linux_service",
    "linux_second_shell",
    "required_file",
    "registry_effects",
    "module_effects",
    "scanner_plan",
    "preflight_reuse",
    "preflight_deadline",
)


def capture(args: argparse.Namespace) -> None:
    """Freeze admission, parent selection, prepared effects, RNG state and rendered bytes."""
    sys.path.insert(0, str(args.source.resolve() / "src"))
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.actions.process_execution import (
        ProcessExecutionActionBundle,
        ProcessExecutionRequest,
    )
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.models.scenario import System, User
    from evidenceforge.utils.rng import _get_rng, generation_seed_scope, reset_thread_rng

    args.output.mkdir(parents=True, exist_ok=False)
    with generation_seed_scope(args.seed):
        reset_thread_rng()
        start = datetime(2024, 3, 18, 13, tzinfo=UTC)
        linux = args.case.startswith("linux_")
        state = StateManager()
        state.set_current_time(start - timedelta(minutes=5))
        emitter = EcarEmitter(load_format("ecar"), args.output, threaded=args.threaded)
        emitters = {"ecar": emitter}
        generator = ActivityGenerator(
            state, emitters, dispatcher=EventDispatcher(state_manager=state, emitters=emitters)
        )
        generator._scenario_end_time = start + timedelta(minutes=12)
        user = User(username="analyst", full_name="Analyst", email="analyst@example.test")
        system = System(
            hostname="LNX" if linux else "WIN",
            ip="10.10.2.20",
            os="Ubuntu 24.04" if linux else "Windows 11",
            type="workstation",
            architecture="x64",
        )
        logon_type = {"windows_network": 3, "windows_service": 5}.get(args.case, 2)
        logon_id = state.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=logon_type,
            source_ip="-",
            start_time=start - timedelta(minutes=4),
            session_kind={3: "network", 5: "service"}.get(logon_type, "interactive"),
        )
        if linux:
            state.register_process(
                system=system.hostname,
                pid=1,
                parent_pid=0,
                image="/usr/lib/systemd/systemd",
                command_line="systemd",
                username="root",
                integrity_level="System",
                os_category="linux",
                start_time=start - timedelta(minutes=5),
            )
        shell_image = "/bin/bash" if linux else r"C:\Windows\explorer.exe"
        parent_pid = state.create_process(
            system.hostname,
            1 if linux else 4,
            shell_image,
            shell_image,
            user.username,
            "Medium",
            logon_id=logon_id,
        )
        session = state.get_session(logon_id)
        assert session is not None
        session.session_shell_pid = parent_pid
        session.explorer_pid = None if linux else parent_pid
        generator._system_pids = {system.hostname: {"bash" if linux else "explorer": parent_pid}}
        roles = generator._system_pids[system.hostname]
        if not linux:
            for role, exe in (("services", "services.exe"), ("svchost_netsvcs", "svchost.exe")):
                roles[role] = state.create_process(
                    system.hostname,
                    4,
                    rf"C:\Windows\System32\{exe}",
                    exe,
                    "SYSTEM",
                    "System",
                    logon_id="0x3e7",
                )
        image = "/usr/bin/id" if linux else r"C:\Windows\System32\whoami.exe"
        command = "id" if linux else "whoami.exe"
        if args.case == "windows_gui":
            image, command = r"C:\Windows\System32\notepad.exe", "notepad.exe notes.txt"
        elif args.case == "windows_same_exe":
            image = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            parent_pid = state.create_process(
                system.hostname,
                parent_pid,
                image,
                "chrome.exe",
                user.username,
                "Medium",
                logon_id=logon_id,
            )
            command = "chrome.exe --type=renderer"
        elif args.case == "windows_remote_wrapper":
            logon_id = state.create_session(
                username=user.username,
                system=system.hostname,
                logon_type=3,
                source_ip="10.10.2.10",
                start_time=start - timedelta(minutes=4),
                session_kind="network",
            )
            parent_pid = state.create_process(
                system.hostname,
                roles["services"],
                r"C:\Windows\PSEXESVC.exe",
                "PSEXESVC.exe",
                "SYSTEM",
                "System",
                logon_id="0x3e7",
            )
            roles["psexesvc"] = parent_pid
        elif args.case in {"windows_wrong_principal", "windows_future_parent"}:
            if args.case == "windows_future_parent":
                state.set_current_time(start + timedelta(minutes=2))
            parent_pid = state.create_process(
                system.hostname,
                4,
                r"C:\Windows\System32\cmd.exe",
                "cmd.exe",
                "other" if args.case == "windows_wrong_principal" else user.username,
                "Medium",
                logon_id="other-session" if args.case == "windows_wrong_principal" else logon_id,
            )
        elif args.case == "windows_missing_parent":
            parent_pid = 999999
        elif args.case == "linux_missing_anchor":
            del generator._system_pids
            parent_pid = 999999
        elif args.case == "linux_service":
            roles["cron"] = state.create_process(
                system.hostname,
                1,
                "/usr/sbin/cron",
                "cron",
                "root",
                "System",
                logon_id="",
            )
            user = User(username="root", full_name="Root", email="root@example.test")
            logon_id = ""
            parent_pid = roles["cron"]
        elif args.case == "linux_second_shell":
            parent_pid = state.create_process(
                system.hostname,
                parent_pid,
                "/bin/bash",
                "/bin/bash",
                user.username,
                "Medium",
                logon_id=logon_id,
            )
        elif args.case == "required_file":
            image, command = r"C:\Tools\inventory.exe", "inventory.exe"
        elif args.case == "registry_effects":
            image, command = r"C:\Windows\System32\reg.exe", "reg.exe query HKCU\\Software"
        elif args.case == "module_effects":
            image, command = (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe -NoProfile Get-Date",
            )
        elif args.case == "scanner_plan":
            image, command = r"C:\Tools\nmap.exe", "nmap -sT -p 443 10.10.2.30"
        elif args.case == "preflight_reuse":
            image = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
            command = image
            state.create_process(
                system.hostname,
                parent_pid,
                image,
                command,
                user.username,
                "Medium",
                logon_id=logon_id,
            )
        state.set_current_time(start)
        request = ProcessExecutionRequest(
            user=user,
            system=system,
            time=start,
            logon_id=logon_id,
            process_name=image,
            command_line=command,
            parent_pid=parent_pid,
            ensure_file_event=args.case == "required_file",
            suppress_command_file_effect=args.case != "required_file",
            require_exact_parent=args.case in {"windows_same_exe", "linux_second_shell"},
            source_visible_by=start if args.case == "preflight_deadline" else None,
        )
        admitted = generator._preflight_bounded_process_source_deadline(request)
        prepared = None
        pid = 0
        if admitted is not None:
            prepared = ProcessExecutionActionBundle(generator, admitted).preflight()
            if args.case != "scanner_plan":
                pid = ProcessExecutionActionBundle(generator, prepared).execute()
        running = state.get_process(system.hostname, pid) if pid else None
        effects = prepared.prepared_effects if prepared is not None else None
        truth = {
            "case": args.case,
            "seed": args.seed,
            "admitted": admitted is not None,
            "requested_parent": parent_pid,
            "pid": pid,
            "process": None
            if running is None
            else {
                "image": running.image,
                "command": running.command_line,
                "parent_pid": running.parent_pid,
                "username": running.username,
                "logon_id": running.logon_id,
                "start": running.start_time.isoformat(),
                "end": running.end_time.isoformat() if running.end_time else None,
            },
            "actor": None
            if effects is None
            else {
                "image": effects.actor.image,
                "command": effects.actor.command_line,
                "username": effects.actor.username,
                "logon_id": effects.actor.logon_id,
                "start": effects.actor.started_at.isoformat(),
                "lifetime": effects.lifetime_plan.mode.value if effects.lifetime_plan else None,
                "provisional_close": effects.provisional_termination.isoformat()
                if effects.provisional_termination
                else None,
                "endpoints": [effect.event_type for effect in effects.endpoint.effects]
                if effects.endpoint
                else [],
                "runtime_module": None
                if effects.runtime_image_load is None
                else {
                    "timestamp": effects.runtime_image_load.timestamp.isoformat(),
                    "path": effects.runtime_image_load.path,
                    "signed": effects.runtime_image_load.signed,
                    "signature": effects.runtime_image_load.signature,
                    "signature_status": effects.runtime_image_load.signature_status,
                },
            },
            "effect_plan_nodes": len(prepared.effect_plan.nodes)
            if prepared and prepared.effect_plan
            else 0,
            "rng_sha256": hashlib.sha256(repr(_get_rng().getstate()).encode()).hexdigest(),
        }
        emitter.close()
        (args.output / "GROUND_TRUTH.json").write_text(json.dumps(truth, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, choices=(42, 137), required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--threaded", action="store_true")
    capture(parser.parse_args())
