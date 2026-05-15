# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Run external parser harnesses against generated EvidenceForge data."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_REPORT_FILENAME,
    SofElkHarnessError,
    SofElkParserError,
    run_sof_elk_zeek_parser,
)


def main() -> int:
    """Run the external parser CLI."""
    parser = argparse.ArgumentParser(
        description="Run external parser validation against generated EvidenceForge data.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    zeek = subparsers.add_parser(
        "sof-elk-zeek",
        help="Validate generated Zeek logs through the SOF-ELK Filebeat/Logstash path.",
    )
    zeek.add_argument("data_dir", type=Path, help="Generated EvidenceForge data/ directory")
    zeek.add_argument(
        "--work-dir",
        type=Path,
        help="Directory for staged files, parsed JSONL, logs, and reports",
    )
    zeek.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Seconds to wait for parser output before failing",
    )
    zeek.add_argument(
        "--cache-dir",
        type=Path,
        help="External cache directory for downloaded parser assets",
    )
    zeek.add_argument(
        "--runtime",
        choices=("docker", "podman"),
        help="Container runtime to use; default auto-detects Docker then Podman",
    )

    args = parser.parse_args()
    if args.command == "sof-elk-zeek":
        return _run_sof_elk_zeek(args)

    parser.error(f"unsupported command: {args.command}")
    return 1


def _run_sof_elk_zeek(args: argparse.Namespace) -> int:
    data_dir = args.data_dir.resolve()
    if not data_dir.is_dir():
        print(f"error: data directory does not exist: {data_dir}", file=sys.stderr)
        return 1

    work_dir = (
        args.work_dir.resolve()
        if args.work_dir
        else Path(tempfile.mkdtemp(prefix="eforge-sof-elk-zeek-"))
    )
    print(f"Data directory: {data_dir}", flush=True)
    print(f"Work directory: {work_dir}", flush=True)

    try:
        result = run_sof_elk_zeek_parser(
            data_dir,
            work_dir,
            cache_dir=args.cache_dir,
            timeout_seconds=args.timeout,
            runtime=args.runtime,
        )
    except SofElkParserError as exc:
        print(f"\nFAIL: {exc}", file=sys.stderr)
        _print_failure_report(work_dir / "parsed" / FAILURE_REPORT_FILENAME)
        _print_artifact_paths(work_dir)
        return 2
    except SofElkHarnessError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        _print_artifact_paths(work_dir)
        return 1

    print("\nPASS: SOF-ELK parsed all staged Zeek records without validation failures")
    print(f"Expected counts: {result.manifest.expected_counts}")
    print(
        "Observed counts: "
        f"{ {log_type: len(events) for log_type, events in result.events_by_type.items() if events} }"
    )
    _print_artifact_paths(work_dir)
    return 0


def _print_failure_report(report_path: Path) -> None:
    if not report_path.exists():
        print(f"Failure report: missing ({report_path})")
        return

    with report_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    print("\nFailure summary:")
    print(f"  Report: {report_path}")
    print(f"  Expected counts: {report.get('expected_counts', {})}")
    print(f"  Observed counts: {report.get('observed_counts', {})}")
    print(f"  Failure count: {report.get('failure_count', 0)}")
    print(f"  Failure tag counts: {report.get('failure_tag_counts', {})}")
    dns_qtypes = report.get("dns_failure_qtype_counts")
    if dns_qtypes:
        print(f"  DNS failures by qtype: {dns_qtypes}")


def _print_artifact_paths(work_dir: Path) -> None:
    print("\nArtifacts:")
    print(f"  Staged input: {work_dir / 'stage' / 'logstash' / 'zeek'}")
    print(f"  Parsed JSONL: {work_dir / 'parsed'}")
    print(f"  Pipeline logs: {work_dir / 'pipeline-logs'}")
    print(f"  Runtime config: {work_dir / 'runtime-config'}")


if __name__ == "__main__":
    raise SystemExit(main())
