#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure retained evaluator RSS growth with reproducible eCAR corpora."""

from __future__ import annotations

import argparse
import json
import platform
import resource
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

_FIXTURE = Path(__file__).parent.parent / "tests" / "fixtures" / "scenarios" / "minimal.yaml"
_RECORD = {
    "timestamp_ms": 1_710_763_200_000,
    "object": "PROCESS",
    "action": "CREATE",
    "principal": "analyst",
    "hostname": "WS-01",
    "properties": {
        "pid": 4242,
        "ppid": 900,
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoProfile -File C:\\Ops\\inventory.ps1",
    },
}


def _rss_bytes() -> int:
    """Normalize ``ru_maxrss`` to bytes on macOS and Linux."""

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if platform.system() == "Darwin" else value * 1024)


def _run_child(record_count: int) -> dict[str, int]:
    """Generate and retain one corpus in an isolated process."""

    scenario = Scenario(**load_yaml(_FIXTURE))
    encoded = (json.dumps(_RECORD, separators=(",", ":")) + "\n").encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="eforge-eval-capacity-") as temporary:
        output_dir = Path(temporary)
        corpus = output_dir / "ecar.json"
        with corpus.open("wb") as handle:
            for _index in range(record_count):
                handle.write(encoded)
        before = _rss_bytes()
        engine = EvaluationEngine(
            output_dir=output_dir,
            scenario=scenario,
            allow_large_evaluation=True,
        )
        records, _counts = engine._parse_all_logs()
        after = _rss_bytes()
        retained = sum(len(items) for items in records.values())
        return {
            "records": retained,
            "corpus_bytes": corpus.stat().st_size,
            "baseline_rss_bytes": before,
            "peak_rss_bytes": after,
            "rss_growth_bytes": max(0, after - before),
        }


def _invoke_child(record_count: int) -> dict[str, int]:
    command = [sys.executable, str(Path(__file__).resolve()), "--child-records", str(record_count)]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def _summary(rows: list[dict[str, int]]) -> dict[str, Any]:
    per_record = [row["rss_growth_bytes"] / row["records"] for row in rows if row["records"] > 0]
    conservative = max(per_record, default=0.0)
    return {
        "schema_version": 1,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "measurements": rows,
        "max_observed_rss_growth_bytes_per_record": round(conservative, 2),
        "projected_growth_at_500k_records_bytes": round(conservative * 500_000),
        "projected_growth_at_2m_records_bytes": round(conservative * 2_000_000),
        "note": (
            "Projection is deliberately conservative and covers retained parse objects only; "
            "full scorer working sets require additional headroom."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--records",
        nargs="+",
        type=int,
        default=[25_000, 50_000, 100_000],
        help="Isolated corpus sizes to measure.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON result path.")
    parser.add_argument("--child-records", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.child_records is not None:
        print(json.dumps(_run_child(args.child_records), sort_keys=True))
        return 0
    if any(count <= 0 for count in args.records):
        parser.error("--records values must be positive")

    result = _summary([_invoke_child(count) for count in args.records])
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
