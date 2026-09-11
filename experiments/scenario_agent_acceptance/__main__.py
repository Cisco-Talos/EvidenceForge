"""Command-line interface for the repository-local experiment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import AgentName
from .reporting import (
    BASELINE_PATH,
    baseline_from_report,
    compare_baseline,
    load_baseline,
    load_verified_report,
    write_baseline,
)
from .runner import DEFAULT_TIMEOUT_SECONDS, run_suite
from .util import sha256_file


def _agents(value: str) -> list[AgentName]:
    try:
        agents = [AgentName(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if not agents or len(agents) != len(set(agents)):
        raise argparse.ArgumentTypeError(
            "agents must be a unique comma-separated subset of codex,claude"
        )
    return agents


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="run a live experimental suite")
    run.add_argument("--suite", choices=("smoke", "full"), required=True)
    run.add_argument("--agents", type=_agents, required=True)
    run.add_argument("--report", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    verify = subparsers.add_parser("verify", help="verify integrity, strict gates, and baseline")
    verify.add_argument("--report", type=Path, required=True)
    baseline = subparsers.add_parser("baseline", help="preview or apply an aggregate baseline")
    baseline.add_argument("--from-report", type=Path, required=True)
    baseline.add_argument("--apply", action="store_true")
    return parser


def _run(args: argparse.Namespace) -> int:
    report = run_suite(
        suite=args.suite,
        agents=args.agents,
        report_path=args.report,
        timeout=args.timeout_seconds,
    )
    print(json.dumps(report.aggregate.model_dump(mode="json"), indent=2, sort_keys=True))
    return 2 if report.aggregate.infrastructure_errors or report.aggregate.failures else 0


def _verify(args: argparse.Namespace) -> int:
    report = load_verified_report(args.report)
    failures: list[str] = []
    for session in report.sessions:
        if session.status.value != "PASS":
            failures.append(f"{session.case_id}/{session.agent.value}: {session.status.value}")
        failures.extend(
            f"{session.case_id}/{session.agent.value}: {violation}"
            for violation in session.metrics.strict_violations
        )
        for label, raw_path, expected in (
            ("transcript", session.transcript_path, session.transcript_digest),
            ("trace", session.trace_path, session.trace_digest),
            ("final scenario", session.final_scenario_path, session.final_scenario_digest),
        ):
            if expected is None:
                continue
            path = Path(raw_path)
            if not path.is_file():
                failures.append(f"{session.case_id}/{session.agent.value}: missing {label}")
            elif sha256_file(path) != expected:
                failures.append(f"{session.case_id}/{session.agent.value}: {label} digest mismatch")
    baseline = load_baseline()
    regressions = compare_baseline(report, baseline) if baseline else []
    payload = {
        "valid": not failures and not regressions,
        "report_digest": report.report_digest,
        "strict_failures": failures,
        "baseline": str(BASELINE_PATH) if baseline else None,
        "regressions": regressions,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["valid"] else 2


def _baseline(args: argparse.Namespace) -> int:
    report = load_verified_report(args.from_report)
    baseline = baseline_from_report(report)
    payload = baseline.model_dump(mode="json")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.apply:
        if report.aggregate.infrastructure_errors or report.aggregate.strict_violations:
            print(
                "refusing to baseline infrastructure errors or strict violations",
                file=sys.stderr,
            )
            return 2
        write_baseline(BASELINE_PATH, baseline)
        print(f"wrote {BASELINE_PATH}", file=sys.stderr)
    return 0


def main() -> int:
    """Parse arguments and execute one experimental command."""

    args = _parser().parse_args()
    if args.command == "run":
        return _run(args)
    if args.command == "verify":
        return _verify(args)
    return _baseline(args)


if __name__ == "__main__":
    raise SystemExit(main())
