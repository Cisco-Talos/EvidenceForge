"""Capture bounded KDC/WFP timing controls against an isolated source checkout.

The stress mode supplies a late permit candidate through the normal planner,
without changing transport truth or suppressing errors. The starting build must
reject it; the corrected build must publish a complete, causally ordered bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from compare_cleanup_output import snapshot


def main() -> None:
    """Generate one immutable capture and verify every admitted KDC interval."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--target", choices=("default", "sof-elk", "splunk"), default="default")
    parser.add_argument("--serial", action="store_true")
    parser.add_argument("--windows-only", action="store_true")
    parser.add_argument("--stress-late-wfp", action="store_true")
    parser.add_argument(
        "--record-existing-violations",
        action="store_true",
        help="Capture historical evidence despite timing violations; never use for acceptance",
    )
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve() / "src"))
    from datetime import timedelta

    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.generation.source_timing import (
        SourceTimingPlanner,
        endpoint_event_render_key,
    )
    from evidenceforge.models.exceptions import StateError
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils.files import load_yaml

    fixture = Path(__file__).parent / "fixtures/cleanup-system-families.yaml"
    expected = json.loads((fixture.parent / "cleanup-inputs.json").read_text())[fixture.name]
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == expected
    scenario = Scenario(**load_yaml(fixture))
    if args.windows_only:
        scenario.output.logs = [{"format": "windows"}]
    original_init = LogEmitter.__init__
    if args.serial:

        def initialize_serial(self: LogEmitter, *values: Any, **kwargs: Any) -> None:
            if len(values) >= 4:
                values = (*values[:3], False, *values[4:])
            else:
                kwargs["threaded"] = False
            original_init(self, *values, **kwargs)

        LogEmitter.__init__ = initialize_serial

    original_wfp = SourceTimingPlanner._windows_wfp_time_inside_transport
    forced = 0
    if args.stress_late_wfp:

        def late_candidate(self: SourceTimingPlanner, event: Any, **kwargs: Any) -> Any:
            nonlocal forced
            network = event.network
            host = event.src_host
            if (
                network is not None
                and network.closed_at is not None
                and host is not None
                and host.ip == network.dst_ip
                and network.service == "kerberos"
                and network.dst_port == 88
                and network.protocol in {"tcp", "udp"}
            ):
                kwargs["preferred"] = self._runtime_endpoint_clock_time(
                    network.closed_at, hostname=host.hostname, os_category=host.os_category
                ) - timedelta(microseconds=2)
                forced += 1
            return original_wfp(self, event, **kwargs)

        SourceTimingPlanner._windows_wfp_time_inside_transport = late_candidate

    original_plan = SourceTimingPlanner.plan_event
    observations: dict[str, dict[str, Any]] = {}
    violations: list[dict[str, str]] = []

    def check_plan(self: SourceTimingPlanner, event: Any, *values: Any, **kwargs: Any) -> Any:
        planned = original_plan(self, event, *values, **kwargs)
        network, lifecycle, host = planned.network, planned.lifecycle, planned.dst_host
        if (
            planned.event_type in {"kerberos_tgt", "kerberos_service", "kerberos_preauth_failed"}
            and network is not None
            and network.closed_at is not None
            and lifecycle is not None
            and host is not None
            and planned.source_timing is not None
        ):
            key = self._transaction_transport_key(
                lifecycle.group_id,
                host.hostname,
                network.src_ip,
                network.src_port,
                network.dst_ip,
                network.dst_port,
                network.protocol,
            )
            anchor = self._admitted_windows_transport_transactions.get(key)
            observed = planned.source_timing.finalized_times.get(
                endpoint_event_render_key("windows_event_security", host.hostname)
            )
            if anchor is not None and observed is not None:
                close = self._runtime_endpoint_clock_time(
                    network.closed_at, hostname=host.hostname, os_category=host.os_category
                )
                if not anchor < observed < close:
                    violations.append(
                        {
                            "transaction": lifecycle.group_id,
                            "type": str(planned.event_type),
                            "permit": anchor.isoformat(),
                            "audit": observed.isoformat(),
                            "close": close.isoformat(),
                        }
                    )
                    assert args.record_existing_violations, violations[-1]
                observations[f"{lifecycle.group_id}:{planned.event_type}"] = {
                    "transaction": lifecycle.group_id,
                    "type": planned.event_type,
                    "host": host.hostname,
                    "tuple": list(key[2:]),
                    "permit": anchor.isoformat(),
                    "audit": observed.isoformat(),
                    "close": close.isoformat(),
                }
        return planned

    SourceTimingPlanner.plan_event = check_plan
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        GenerationEngine(
            scenario,
            args.output,
            generation_seed=args.seed,
            output_target=args.target,
        ).generate()
    except StateError as error:
        args.output.with_suffix(".failure.json").write_text(
            json.dumps({"error": str(error), "forced_candidates": forced}, indent=2) + "\n"
        )
        raise
    assert observations, "Control did not exercise any admitted KDC audit"
    if args.stress_late_wfp:
        assert forced > 0
    report = {
        "fixture_sha256": expected,
        "seed": args.seed,
        "target": args.target,
        "serial": args.serial,
        "windows_only": args.windows_only,
        "forced_candidates": forced,
        "observations": list(observations.values()),
        "violations": violations,
        "files": snapshot(args.output),
    }
    args.output.with_suffix(".timing.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    status = "HISTORICAL CAPTURE" if violations else "PASS"
    print(
        f"{status}: {len(observations)} KDC intervals, {forced} forced permit candidates, "
        f"{len(violations)} violations"
    )


if __name__ == "__main__":
    main()
