# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure five isolated full CLI evaluations per revision on macOS/Linux.

Includes imports, parsing and all scoring pillars. Records wall time and peak child RSS;
20% is an investigation threshold, never a timing-sensitive CI assertion.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def main() -> None:
    """Alternate the two interpreters against exactly the same retained bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-python", type=Path, required=True)
    parser.add_argument("--candidate-python", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not hasattr(os, "wait4"):
        parser.error("Peak child RSS collection requires macOS or Linux wait4")
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    rows: list[dict[str, Any]] = []
    for index in range(5):
        for revision, executable in (
            ("baseline", args.baseline_python),
            ("candidate", args.candidate_python),
        ):
            stem = output / f"{revision}-{index}"
            with (
                stem.with_suffix(".json").open("w") as stdout,
                stem.with_suffix(".err").open("w") as stderr,
            ):
                start = time.monotonic()
                process = subprocess.Popen(
                    [
                        str(executable.absolute()),
                        "-m",
                        "evidenceforge",
                        "eval",
                        str(args.bundle.resolve()),
                        "--format",
                        "json",
                    ],
                    stdout=stdout,
                    stderr=stderr,
                )
                _pid, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                seconds = time.monotonic() - start
            if process.returncode:
                raise RuntimeError(
                    f"{revision} evaluation failed; inspect {stem.with_suffix('.err')}"
                )
            text = stem.with_suffix(".json").read_text()
            # The baseline can emit warnings before its JSON; retain original bytes.
            report = json.JSONDecoder().raw_decode(text[text.index("{") :])[0]
            if len(report["pillars"]) != 4 or any(p["score"] is None for p in report["pillars"]):
                raise RuntimeError(f"{revision} did not complete all scoring pillars")
            rows.append(
                {
                    "revision": revision,
                    "run": index,
                    "seconds": seconds,
                    "peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
                    "records": report["total_records"],
                    "exit": process.returncode,
                }
            )
            (output / "runs.json").write_text(json.dumps(rows, indent=2))
    summary = {
        revision: {
            metric: statistics.median(row[metric] for row in rows if row["revision"] == revision)
            for metric in ("seconds", "peak_rss_bytes")
        }
        for revision in ("baseline", "candidate")
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
