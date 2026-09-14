"""Measure fixed mixed-host generation without a slowdown acceptance threshold."""

from __future__ import annotations

import argparse
import gc
import json
import resource
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any
from unittest.mock import patch

from compare_cleanup_output import snapshot


def main() -> None:
    """Run warmups, repeated generation and a separate allocation observation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--configured", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Performance report must be new")
    sys.path.insert(0, str(args.source.resolve() / "src"))
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

    def generate() -> dict[str, str]:
        with tempfile.TemporaryDirectory(prefix="eforge-resolver-measure-") as temporary:
            output = Path(temporary).resolve()
            engine = GenerationEngine(Scenario(**document), output, generation_seed=42)
            engine.generate()
            assert "dns_ips_by_host" not in vars(engine)
            return snapshot(output)

    reference = generate()
    samples: list[float] = []
    for _ in range(3):
        started = time.perf_counter()
        result = generate()
        samples.append(time.perf_counter() - started)
        assert result == reference
    gc.collect()
    tracemalloc.start()
    assert generate() == reference
    gc.collect()
    retained_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Instrument outside timing/allocation measurements; count actual selections
    # and mapping sizes rather than inferring them from the implementation.
    resolver = baseline_module.activity_dns_resolver_ips
    syslog_pass = baseline_module.BaselineMixin._generate_system_linux_syslog
    selection_count = 0
    mapping_sizes: list[int] = []

    def select(*positional: Any, **kwargs: Any) -> list[str]:
        nonlocal selection_count
        selection_count += 1
        return resolver(*positional, **kwargs)

    def observe_pass(owner: Any, **kwargs: Any) -> None:
        mapping_sizes.append(len(kwargs.get("dns_ips_by_host", {})))
        syslog_pass(owner, **kwargs)

    with (
        patch.object(baseline_module, "activity_dns_resolver_ips", select),
        patch.object(baseline_module.BaselineMixin, "_generate_system_linux_syslog", observe_pass),
    ):
        assert generate() == reference
    report = {
        "source": str(args.source.resolve()),
        "configured": args.configured,
        "warmups": 1,
        "samples_seconds": samples,
        "median_seconds": statistics.median(samples),
        "generations_per_second": 1 / statistics.median(samples),
        "peak_traced_bytes": peak_bytes,
        "retained_traced_bytes": retained_bytes,
        "process_max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "resolver_selection_count": selection_count,
        "per_pass_mapping_sizes": mapping_sizes,
        "files": reference,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Measured median {report['median_seconds']:.6f} s")


if __name__ == "__main__":
    main()
