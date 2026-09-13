"""Capture fixed protocol decisions through canonical network publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

CASES = ("icmp_echo", "icmp_missing", "dns", "ntp", "syslog", "kerberos", "tcp_reset", "invalid")


def capture(args: argparse.Namespace) -> None:
    """Record native evidence and exact canonical transport/RNG truth."""
    sys.path.insert(0, str(args.source.resolve() / "src"))
    from evidenceforge.events.contexts import DnsContext
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.actions.network_connection import NetworkConnectionIdentityCapture
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from evidenceforge.generation.emitters.zeek import ZeekEmitter
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.models.scenario import System
    from evidenceforge.utils.rng import _get_rng, generation_seed_scope, reset_thread_rng

    args.output.mkdir(parents=True, exist_ok=False)
    with generation_seed_scope(args.seed):
        reset_thread_rng()
        start = datetime(2024, 3, 18, 13, tzinfo=UTC)
        state = StateManager()
        state.set_current_time(start)
        emitters = {
            "zeek_conn": ZeekEmitter(load_format("zeek_conn"), args.output, threaded=args.threaded),
            "ecar": EcarEmitter(load_format("ecar"), args.output, threaded=args.threaded),
        }
        dispatcher = EventDispatcher(state_manager=state, emitters=emitters)
        generator = ActivityGenerator(
            state,
            emitters,
            dispatcher=dispatcher,
            generation_window_start=start - timedelta(hours=1),
            generation_window_end=start + timedelta(hours=1),
        )
        system = System(hostname="LINUX-01", ip="10.10.2.20", os="Ubuntu 24.04", type="server")
        generator._ip_to_system = {system.ip: system}
        generator._all_system_ips = [system.ip]
        values = {
            "icmp_echo": ("icmp", "", 0, 56, 56, "SF"),
            "icmp_missing": ("icmp", "", 0, 56, 0, "S0"),
            "dns": ("udp", "dns", 53, 12, 96, "SF"),
            "ntp": ("udp", "ntp", 123, 48, 48, "SF"),
            "syslog": ("udp", "syslog", 514, 170, 0, "OTH"),
            "kerberos": ("tcp", "kerberos", 88, 700, 1400, "SF"),
            "tcp_reset": ("tcp", "", 8443, 500, 1000, "RSTR"),
            "invalid": ("tcp", "", 8443, 64, 128, "SF"),
        }
        proto, service, port, orig, resp, conn_state = values[args.case]
        identity = NetworkConnectionIdentityCapture()
        uid = generator.generate_connection(
            src_ip=system.ip,
            dst_ip="127.0.0.1" if args.case == "invalid" else "10.10.2.53",
            time=start,
            dst_port=port,
            proto=proto,
            service=service,
            duration=0.25,
            orig_bytes=orig,
            resp_bytes=resp,
            src_port=50001,
            conn_state=conn_state,
            source_system=system,
            hostname="",
            suppress_source_pid_inference=True,
            suppress_application_side_effects=True,
            preserve_explicit_payload=True,
            preserve_start_time=True,
            identity_capture=identity,
            dns=DnsContext(
                query="inventory.example.test", query_type="A", answers=["10.10.2.80"], rtt=0.012
            )
            if args.case == "dns"
            else None,
        )
        transaction = identity.transaction
        truth = {
            "case": args.case,
            "seed": args.seed,
            "uid": uid,
            "transaction": None,
            "rng_sha256": hashlib.sha256(repr(_get_rng().getstate()).encode()).hexdigest(),
        }
        if transaction is not None:
            truth["transaction"] = {
                "stable_id": transaction.stable_id,
                "conn_id": transaction.conn_id,
                "protocol": transaction.protocol,
                "service": transaction.service,
                "src_port": transaction.src_port,
                "dst_port": transaction.dst_port,
                "dst_ip": transaction.dst_ip,
                "conn_state": transaction.conn_state,
                "history": transaction.history,
                "duration": transaction.duration,
                "started_at": transaction.started_at.isoformat(),
                "closed_at": transaction.closed_at.isoformat(),
                "traffic": asdict(transaction.traffic),
                "outcome": identity.require_outcome().value,
            }
        for emitter in emitters.values():
            emitter.close()
        (args.output / "GROUND_TRUTH.json").write_text(json.dumps(truth, indent=2) + "\n")


def main() -> None:
    """Capture one frozen protocol case."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, choices=(42, 137), required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--threaded", action="store_true")
    capture(parser.parse_args())


if __name__ == "__main__":
    main()
