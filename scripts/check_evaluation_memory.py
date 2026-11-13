"""Check fixed evaluator workloads with RSS sampled only after worker readiness.

Run as a separate CI job, without pytest or coverage. Lifetime ru_maxrss is retained
as a diagnostic, never subtracted or used as the evaluator's measured RSS. Inputs
are invented fixtures written incrementally; this script never runs generation.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import platform
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any, Literal

import psutil
import yaml
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "tests/fixtures/eval/memory-workloads.yaml"
MIB = 1024 * 1024
SAMPLE_SECONDS = 0.01
Workload = Literal["processes", "correlated"]


class Limits(BaseModel):
    """Platform envelopes for the fixed corpus sizes and spill budget."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    peak_mib: int = Field(gt=0)
    growth_mib: int = Field(gt=0)


class Profile(BaseModel):
    """Versioned workload contract; changes require explicit recalibration."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1]
    memory_budget_mib: int = Field(gt=0)
    records: list[int] = Field(min_length=3)
    limits: dict[str, Limits]


class WorkerResult(BaseModel):
    """Functional checks and worker-owned memory diagnostics."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    records: int
    source_counts: dict[str, int]
    spec_conformance: float
    resources: dict[str, Any]
    final_rss_bytes: int
    lifetime_peak_bytes: int | None
    scratch_clean: bool


class Measurement(BaseModel):
    """One independent evaluation, including the measurement boundaries."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    workload: Workload
    records: int
    baseline_rss_bytes: int
    peak_rss_bytes: int
    startup_lifetime_peak_bytes: int | None
    samples: int
    evaluation_seconds: float
    input_sha256: str
    result: WorkerResult


def lifetime_peak() -> int | None:
    """Read the process-lifetime high-water mark for diagnosis only."""
    if sys.platform == "win32":
        return None
    import resource

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def process_row(number: int, *, unit: int | None = None) -> dict[str, Any]:
    """Build an invented process identity with increasing key cardinality."""
    owner = number if unit is None else unit
    identity = f"00000000-0000-4000-8000-{owner:012x}"
    return {
        "timestamp_ms": 1705312800000 + owner % 3600 * 1000,
        "id": f"00000000-0000-4000-9000-{number:012x}",
        "hostname": "TEST-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": identity,
        "pid": owner + 10,
        "tid": owner + 10,
        "ppid": 0,
        "principal": "test_user",
        "properties": {
            "command_line": "cmd.exe /c ver",
            "image_path": r"C:\Windows\System32\cmd.exe",
        },
    }


def correlated_rows(unit: int) -> Iterator[tuple[str, dict[str, Any]]]:
    """Exercise process, file, tuple, DNS, TLS, UID and file-ID indexes together."""
    create = process_row(unit * 4, unit=unit)
    at = create["timestamp_ms"]
    uid = f"C{unit:017x}"
    fuid = f"F{unit:017x}"
    domain = f"asset-{unit}.example.test"
    port = 10000 + unit % 50000
    common = {
        "ts": at / 1000 + 0.1,
        "uid": uid,
        "id.orig_h": "10.0.0.1",
        "id.orig_p": port,
        "id.resp_h": "192.0.2.10",
        "id.resp_p": 443,
        "proto": "tcp",
    }
    yield "ecar.json", create
    yield (
        "ecar.json",
        {
            **process_row(unit * 4 + 1, unit=unit),
            "timestamp_ms": at + 100,
            "object": "FLOW",
            "action": "CONNECT",
            "objectID": uid,
            "properties": {
                "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.10",
                "src_port": str(port),
                "dst_port": "443",
                "protocol": "tcp",
            },
        },
    )
    yield (
        "ecar.json",
        {
            **process_row(unit * 4 + 2, unit=unit),
            "timestamp_ms": at + 200,
            "object": "FILE",
            "action": "CREATE",
            "objectID": fuid,
            "properties": {"file_path": rf"C:\Temp\asset-{unit}.txt"},
        },
    )
    yield (
        "ecar.json",
        {
            **process_row(unit * 4 + 3, unit=unit),
            "timestamp_ms": at + 900,
            "action": "TERMINATE",
        },
    )
    yield (
        "zeek_conn.json",
        {
            **common,
            "service": "ssl",
            "duration": 0.5,
            "orig_bytes": 512,
            "resp_bytes": 1024,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 8,
            "resp_pkts": 8,
            "orig_ip_bytes": 1024,
            "resp_ip_bytes": 1536,
        },
    )
    yield (
        "zeek_dns.json",
        {
            **common,
            "ts": at / 1000,
            "uid": f"D{unit:017x}",
            "id.resp_h": "10.0.0.53",
            "id.resp_p": 53,
            "proto": "udp",
            "query": domain,
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": 1,
            "qtype_name": "A",
            "rcode": 0,
            "rcode_name": "NOERROR",
            "answers": ["192.0.2.10"],
            "TTLs": [300.0],
            "rejected": False,
            "opcode": 0,
            "opcode_name": "query",
        },
    )
    yield (
        "zeek_ssl.json",
        {
            **{key: value for key, value in common.items() if key != "proto"},
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "server_name": domain,
            "resumed": False,
            "established": True,
            "cert_chain_fuids": [fuid],
        },
    )
    yield (
        "zeek_files.json",
        {
            "ts": at / 1000 + 0.2,
            "fuid": fuid,
            "conn_uids": [uid],
            "tx_hosts": ["192.0.2.10"],
            "rx_hosts": ["10.0.0.1"],
            "source": "SSL",
            "depth": 0,
            "analyzers": [],
            "mime_type": "text/plain",
            "seen_bytes": 1024,
            "total_bytes": 1024,
            "missing_bytes": 0,
            "overflow_bytes": 0,
            "timedout": False,
            "is_orig": False,
        },
    )


def write_corpus(root: Path, workload: Workload, records: int) -> str:
    """Stream fixed inputs to disk without retaining a generated record list."""
    from contextlib import ExitStack

    root.mkdir(parents=True)
    digest = hashlib.sha256()
    with ExitStack() as stack:
        names = ["ecar.json"]
        if workload == "correlated":
            if records % 8:
                raise ValueError("Correlated corpus record count must be a multiple of eight")
            names += [f"zeek_{kind}.json" for kind in ("conn", "dns", "ssl", "files")]
        files = {name: stack.enter_context((root / name).open("wb")) for name in names}
        for number in range(records if workload == "processes" else records // 8):
            rows = (
                [("ecar.json", process_row(number))]
                if workload == "processes"
                else correlated_rows(number)
            )
            for name, row in rows:
                encoded = (json.dumps(row, separators=(",", ":")) + "\n").encode()
                files[name].write(encoded)
                digest.update(name.encode() + b"\0" + encoded)
    return digest.hexdigest()


def worker(workload: Workload, records: int, budget_mib: int, workspace: Path) -> None:
    """Prepare inputs/imports, wait for the observer, then evaluate exactly once."""
    from evidenceforge.evaluation.engine import EvaluationEngine
    from evidenceforge.models.scenario import Scenario
    from evidenceforge.utils.files import load_yaml

    digest = write_corpus(workspace / "data/TEST-01", workload, records)
    scenario = Scenario(**load_yaml(ROOT / "tests/fixtures/scenarios/minimal.yaml"))
    scenario.output.logs = [{"format": "ecar"}]
    if workload == "correlated":
        scenario.output.logs.append({"format": "zeek"})
    scratch = workspace / "scratch"
    scratch.mkdir()
    engine = EvaluationEngine(
        workspace / "data", scenario, memory_budget_bytes=budget_mib * MIB, scratch_dir=scratch
    )
    gc.collect()
    print(
        json.dumps(
            {
                "baseline_rss_bytes": psutil.Process().memory_info().rss,
                "startup_lifetime_peak_bytes": lifetime_peak(),
                "input_sha256": digest,
            }
        ),
        flush=True,
    )
    if sys.stdin.readline().strip() != "start":
        raise ValueError("Observer did not authorize the measurement boundary")
    report = engine.run()
    score = next(
        score.score
        for pillar in report.pillars
        for score in pillar.sub_scores
        if score.key == "spec_conformance"
    )
    result = WorkerResult(
        records=report.total_records,
        source_counts=report.source_counts,
        spec_conformance=score,
        resources=report.supplementary["evaluation_resources"],
        final_rss_bytes=psutil.Process().memory_info().rss,
        lifetime_peak_bytes=lifetime_peak(),
        scratch_clean=not any(scratch.iterdir()),
    )
    print(result.model_dump_json(), flush=True)


def sample_rss(pid: int, stop: Event, started: Event, baseline: int) -> tuple[int, int]:
    """Sample only the ready worker, independent of the observer's memory history."""
    process = psutil.Process(pid)
    peak = baseline
    samples = 0
    while not stop.is_set():
        try:
            peak = max(peak, process.memory_info().rss)
        except psutil.NoSuchProcess:
            break
        samples += 1
        started.set()
        stop.wait(SAMPLE_SECONDS)
    return peak, samples


def measure(workload: Workload, records: int, budget_mib: int, workspace: Path) -> Measurement:
    """Use a readiness handshake, bounded wait and external RSS sampling per run."""
    workspace = workspace.resolve()
    workspace.mkdir(parents=True)
    command = [
        sys.executable,
        "-m",
        "scripts.check_evaluation_memory",
        "--worker",
        workload,
        "--records",
        str(records),
        "--budget-mib",
        str(budget_mib),
        "--output-dir",
        str(workspace),
    ]
    stop = Event()
    sampling_started = Event()
    with (
        subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=ROOT,
        ) as process,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        try:
            assert process.stdout is not None
            ready = json.loads(executor.submit(process.stdout.readline).result(timeout=60))
            baseline = int(ready["baseline_rss_bytes"])
            sampler = executor.submit(sample_rss, process.pid, stop, sampling_started, baseline)
            if not sampling_started.wait(timeout=10):
                raise RuntimeError("RSS observer did not start before evaluation")
            started = monotonic()
            output, error = process.communicate("start\n", timeout=600)
            (workspace / "worker.stderr").write_text(error)
            elapsed = monotonic() - started
            stop.set()
            peak, samples = sampler.result(timeout=10)
            if process.returncode:
                raise RuntimeError(f"Evaluation worker failed ({process.returncode}): {error}")
            result = WorkerResult.model_validate_json(output)
            return Measurement(
                workload=workload,
                records=records,
                baseline_rss_bytes=baseline,
                peak_rss_bytes=max(peak, result.final_rss_bytes),
                startup_lifetime_peak_bytes=ready["startup_lifetime_peak_bytes"],
                samples=samples,
                evaluation_seconds=elapsed,
                input_sha256=ready["input_sha256"],
                result=result,
            )
        finally:
            stop.set()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def history_probe(workspace: Path, budget_mib: int) -> dict[str, Any]:
    """Compare the same ready worker before and during retained parent pressure."""
    clean = measure("processes", 240, budget_mib, workspace / "clean-parent")
    clean_parent_rss = psutil.Process().memory_info().rss
    pressure = bytearray(256 * MIB)
    for offset in range(0, len(pressure), 4096):
        pressure[offset] = 1
    retained_parent_rss = psutil.Process().memory_info().rss
    dirty = measure("processes", 240, budget_mib, workspace / "retained-parent")
    del pressure
    return {
        "parent_pressure_bytes": 256 * MIB,
        "clean_parent_rss_bytes": clean_parent_rss,
        "retained_parent_rss_bytes": retained_parent_rss,
        "clean": clean.model_dump(mode="json"),
        "retained": dirty.model_dump(mode="json"),
        "sampled_peak_difference_bytes": dirty.peak_rss_bytes - clean.peak_rss_bytes,
        "startup_history_exceeds_sampled_peak": (
            dirty.startup_lifetime_peak_bytes is not None
            and dirty.startup_lifetime_peak_bytes > dirty.peak_rss_bytes + 64 * MIB
        ),
    }


def check_measurements(rows: list[Measurement], profile: Profile, limits: Limits) -> list[str]:
    """Require complete execution, spill, cleanup, absolute RSS and bounded growth."""
    failures: list[str] = []
    for workload in ("processes", "correlated"):
        family = sorted((row for row in rows if row.workload == workload), key=lambda r: r.records)
        if [row.records for row in family] != profile.records:
            failures.append(f"{workload}: incomplete or duplicate scaling matrix")
            continue
        for row in family:
            label = f"{workload}/{row.records}"
            expected_counts = (
                {"ecar": row.records}
                if workload == "processes"
                else {
                    "ecar": row.records // 2,
                    **{
                        f"zeek_{kind}": row.records // 8 for kind in ("conn", "dns", "ssl", "files")
                    },
                }
            )
            if row.result.records != row.records or row.result.source_counts != expected_counts:
                failures.append(f"{label}: incomplete evaluation")
            if row.result.spec_conformance != 100:
                failures.append(f"{label}: fixture has schema failures")
            if not row.result.scratch_clean or row.samples < 2:
                failures.append(f"{label}: scratch cleanup or RSS sampling failed")
            if not row.result.resources["spilled"]:
                failures.append(f"{label}: workload did not exercise spill")
            if row.result.resources["working_memory_bytes"] != profile.memory_budget_mib * MIB:
                failures.append(f"{label}: wrong working-state budget")
            if row.peak_rss_bytes > limits.peak_mib * MIB:
                failures.append(f"{label}: RSS {row.peak_rss_bytes} exceeds {limits.peak_mib} MiB")
        growth = max(row.peak_rss_bytes for row in family) - family[0].peak_rss_bytes
        if growth > limits.growth_mib * MIB:
            failures.append(f"{workload}: RSS growth {growth} exceeds {limits.growth_mib} MiB")
    return failures


def check_history_probe(probe: dict[str, Any]) -> list[str]:
    """Reject inflated worker RSS, allowing lower startup RSS on later runs."""
    if probe["sampled_peak_difference_bytes"] > 32 * MIB:
        return ["RSS sampling increased by over 32 MiB under unrelated parent pressure"]
    return []


def main() -> None:
    """Retain every measurement before enforcing the calibrated envelopes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--measure-only", action="store_true", help="Calibration only; not a gate")
    parser.add_argument("--worker", choices=("processes", "correlated"), help=argparse.SUPPRESS)
    parser.add_argument("--records", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--budget-mib", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.output_dir = args.output_dir.expanduser().resolve()
    args.profile = args.profile.expanduser().resolve()
    if args.worker:
        if not args.records or args.records < 0 or not args.budget_mib or args.budget_mib < 0:
            parser.error("Worker record count and memory budget must be positive")
        worker(args.worker, args.records, args.budget_mib, args.output_dir)
        return
    profile = Profile.model_validate(yaml.safe_load(args.profile.read_text()))
    platform_key = f"{sys.platform}-{platform.machine().lower()}"
    if platform_key not in profile.limits:
        parser.error(f"No calibrated memory envelope for {platform_key}")
    if profile.records != sorted(set(profile.records)) or any(
        n <= 0 or n % 8 for n in profile.records
    ):
        parser.error("Workload sizes must be increasing unique positive multiples of eight")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    rows: list[Measurement] = []
    report: dict[str, Any] = {
        "source_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "platform": platform_key,
        "python": sys.version,
        "profile_sha256": hashlib.sha256(args.profile.read_bytes()).hexdigest(),
        "sample_interval_seconds": SAMPLE_SECONDS,
        "measure_only": args.measure_only,
        "measurements": [],
    }
    report["history_probe"] = history_probe(args.output_dir / "history", profile.memory_budget_mib)
    (args.output_dir / "measurements.json").write_text(json.dumps(report, indent=2) + "\n")
    for workload in ("processes", "correlated"):
        for count in profile.records:
            row = measure(
                workload, count, profile.memory_budget_mib, args.output_dir / f"{workload}-{count}"
            )
            rows.append(row)
            report["measurements"].append(row.model_dump(mode="json"))
            (args.output_dir / "measurements.json").write_text(json.dumps(report, indent=2) + "\n")
            print(row.model_dump_json(), flush=True)
    failures = check_measurements(rows, profile, profile.limits[platform_key])
    failures.extend(check_history_probe(report["history_probe"]))
    report["failures"] = failures
    (args.output_dir / "measurements.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures and not args.measure_only:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
