"""Capture resolver-correction evidence with a bounded, explicit daemon control.

Only the ambient daemon catalog is narrowed to its existing systemd-resolved
entry. Rendering, scheduling, RNG, DNS connections and all other activities use
the selected build. Traces stay outside the evidence bundle and record the
exact input/RNG boundary at which the original and corrected builds diverge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

from compare_cleanup_output import snapshot


def capture(args: argparse.Namespace) -> None:
    """Capture one build without replacing existing evidence or normalizing bytes."""
    sys.path.insert(0, str(args.source.resolve() / "src"))
    from evidenceforge.generation.activity import extra_syslog
    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.generation.engine import baseline as baseline_module
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils.files import load_yaml

    fixture = Path(__file__).parent / "fixtures/cleanup-resolver-ownership.yaml"
    document = load_yaml(fixture)
    if args.configured:
        document["environment"]["systems"][-1].update(
            type="domain_controller", services=["dns"], roles=["domain_controller"]
        )
    if args.filtered:
        document["output"]["logs"] = [{"format": "zeek"}, {"format": "syslog"}]
    scenario = Scenario(**document)
    args.output.mkdir(parents=True, exist_ok=False)
    resolver = baseline_module.activity_dns_resolver_ips
    render = baseline_module.BaselineMixin._render_systemd_resolved_message
    catalog = extra_syslog.load_extra_syslog_messages
    emitter_init = LogEmitter.__init__
    pools: dict[str, list[str]] = {}
    traces: list[dict[str, Any]] = []
    selections = 0

    def select(activity: Any, ip: str) -> list[str]:
        nonlocal selections
        selections += 1
        selected = resolver(activity, ip)
        pools[ip] = selected
        return selected

    def render_traced(
        owner: Any, entry: dict[str, Any], hostname: str, provided: list[str], rng: Any
    ) -> str:
        host = next(host for host in scenario.environment.systems if host.hostname == hostname)
        before = hashlib.sha256(repr(rng.getstate()).encode()).hexdigest()
        message = render(owner, entry, hostname, provided, rng)
        traces.append(
            {
                "host": hostname,
                "expected_pool": pools[host.ip],
                "provided_pool": provided,
                "rng_before": before,
                "rng_after": hashlib.sha256(repr(rng.getstate()).encode()).hexdigest(),
                "message": message,
                "feature_state": owner._linux_resolved_feature_states[hostname],
            }
        )
        return message

    def resolved_catalog() -> list[dict[str, Any]]:
        return [entry for entry in catalog() if entry["app"] == "systemd-resolved"]

    def initialize_emitter(owner: Any, *positional: Any, **kwargs: Any) -> None:
        if args.serial:
            if len(positional) >= 4:
                positional = (*positional[:3], False, *positional[4:])
            else:
                kwargs["threaded"] = False
        emitter_init(owner, *positional, **kwargs)

    with (
        patch.object(baseline_module, "activity_dns_resolver_ips", select),
        patch.object(
            baseline_module.BaselineMixin, "_render_systemd_resolved_message", render_traced
        ),
        patch.object(extra_syslog, "load_extra_syslog_messages", resolved_catalog),
        patch.object(LogEmitter, "__init__", initialize_emitter),
    ):
        engine = GenerationEngine(
            scenario, args.output, generation_seed=args.seed, output_target=args.target
        )
        engine.generate()
    if not traces or {row["host"] for row in traces} != {"LINUX-01", "LINUX-02"}:
        raise AssertionError("Control did not exercise both Linux resolver renderers")
    result = {
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "resolver_selections": selections,
        "resolver_traces": traces,
        "files": snapshot(args.output),
        "retained_resolver_mapping": any("dns_ips_by_host" in key for key in vars(engine)),
    }
    args.output.with_suffix(".resolver.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    print(f"Captured {len(traces)} resolver messages; {selections} existing selections")


def main() -> None:
    """Select a frozen build, seed, target and output projection."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, choices=(42, 137), required=True)
    parser.add_argument("--target", choices=("default", "sof-elk", "splunk"), required=True)
    parser.add_argument("--serial", action="store_true")
    parser.add_argument("--filtered", action="store_true")
    parser.add_argument("--configured", action="store_true")
    capture(parser.parse_args())


if __name__ == "__main__":
    main()
