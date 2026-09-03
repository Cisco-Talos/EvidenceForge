"""Benchmark incremental generation checkpoints in rotated fresh-process pairs.

The harness measures the generator body with and without checkpointing, verifies every pair's
complete deterministic output digest, and times checkpoint commits from outside production code.
It intentionally uses only production dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable
from contextlib import nullcontext
from pathlib import Path
from typing import cast

try:
    import resource
except ImportError:  # pragma: no cover - exercised on Windows
    resource = None

from evidenceforge.composition import compile_scenario, with_runtime_scenario
from evidenceforge.composition.artifacts import (
    build_resolved_document,
    serialize_resolved_document,
)
from evidenceforge.generation.checkpoints import IncrementalCheckpointStore
from evidenceforge.generation.checkpoints.fingerprint import run_fingerprint
from evidenceforge.generation.checkpoints.models import CheckpointCursor, CheckpointManifest
from evidenceforge.generation.checkpoints.participants import IncrementalCheckpointParticipant
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.engine import GenerationEngine

_RESULT_PREFIX = "EFORGE_CHECKPOINT_BENCHMARK_RESULT="
_SCALING_HOURS = frozenset({6, 24, 168, 720, 1_440})


def _directory_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _output_digest(root: Path) -> tuple[str, dict[str, str], int]:
    digest = hashlib.sha256()
    hashes: dict[str, str] = {}
    size = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if ".eforge-generation" in path.parts or path.name in {
            "GENERATION_MANIFEST.json",
            "generation.log",
        }:
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        hashes[relative.decode("utf-8")] = hashlib.sha256(payload).hexdigest()
        size += len(payload)
    return digest.hexdigest(), hashes, size


def _peak_rss_bytes() -> int | None:
    if resource is None:
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _run_child(args: argparse.Namespace) -> int:
    compiled = compile_scenario(args.scenario)
    if args.duration is not None:
        scenario = compiled.scenario.model_copy(deep=True)
        scenario.time_window.duration = args.duration
        compiled = with_runtime_scenario(compiled, scenario)
    scenario = compiled.scenario
    formats = [
        str(log["format"])
        for log in scenario.output.logs
        if isinstance(log, dict) and "format" in log
    ]
    resolved_scenario = serialize_resolved_document(build_resolved_document(compiled))
    if args.child_output_root is None:
        workspace = tempfile.TemporaryDirectory(
            prefix="eforge-checkpoint-benchmark-",
            dir=args.work_directory,
        )
    else:
        args.child_output_root.mkdir(parents=True)
        workspace = nullcontext(str(args.child_output_root))
    with workspace as temporary:
        root = Path(temporary)
        checkpoints: list[dict[str, float | int | str]] = []
        phase_started: dict[str, float] = {}
        phase_seconds: dict[str, float] = {}
        engine: GenerationEngine | None = None
        finalization_instrumented = False

        def measured_call(
            phase_name: str,
            operation: Callable[..., object],
        ) -> Callable[..., object]:
            def measured(*call_args: object, **call_kwargs: object) -> object:
                operation_started = time.perf_counter()
                try:
                    return operation(*call_args, **call_kwargs)
                finally:
                    phase_seconds[phase_name] = phase_seconds.get(phase_name, 0.0) + (
                        time.perf_counter() - operation_started
                    )

            return measured

        def instrument_finalization() -> None:
            nonlocal finalization_instrumented
            if finalization_instrumented or engine is None:
                return
            finalization_instrumented = True
            engine._drain_terminal_stages_before_close = cast(
                Callable[..., None],
                measured_call(
                    "finalize.terminal_stages",
                    engine._drain_terminal_stages_before_close,
                ),
            )
            engine._close_emitters = cast(
                Callable[..., None],
                measured_call("finalize.close_emitters", engine._close_emitters),
            )
            coordinator = engine._source_finalization_coordinator
            if coordinator is not None:
                coordinator.finalize = cast(
                    Callable[[], None],
                    measured_call("finalize.source_publication", coordinator.finalize),
                )
            generator = engine.activity_generator
            if generator is not None:
                generator.write_artifacts_manifest = cast(
                    Callable[[], None],
                    measured_call(
                        "finalize.artifacts_manifest",
                        generator.write_artifacts_manifest,
                    ),
                )
            for format_name, emitter in engine.emitters.items():
                original_close = cast(Callable[[], None], emitter.close)
                phase_name = f"finalize.emitter.{format_name}"

                def measured_close(
                    _original: Callable[[], None] = original_close,
                    _phase: str = phase_name,
                ) -> None:
                    close_started = time.perf_counter()
                    try:
                        _original()
                    finally:
                        phase_seconds[_phase] = phase_seconds.get(_phase, 0.0) + (
                            time.perf_counter() - close_started
                        )

                emitter.close = measured_close

        def record_phase(event_type: str, data: dict[str, object]) -> None:
            phase = data.get("phase")
            if type(phase) is not str:
                return
            if event_type == "phase_start":
                if phase == "finalize":
                    instrument_finalization()
                phase_started[phase] = time.perf_counter()
            elif event_type == "phase_end" and phase in phase_started:
                phase_seconds[phase] = phase_seconds.get(phase, 0.0) + (
                    time.perf_counter() - phase_started.pop(phase)
                )

        started = time.perf_counter()
        controller = None
        store = None
        if args.child_checkpoint_hours > 0:
            store = IncrementalCheckpointStore(root)
            controller = IncrementalCheckpointController(
                store=store,
                fingerprint=run_fingerprint(
                    compiled,
                    output_target="default",
                    formats=formats,
                    oob_hosts=(),
                ),
                checkpoint_hours=args.child_checkpoint_hours,
                resolved_scenario=resolved_scenario,
            )
            original_commit = controller.commit

            def measured_checkpoint_commit(
                *,
                cursor: CheckpointCursor,
                participants: Iterable[IncrementalCheckpointParticipant],
            ) -> CheckpointManifest:
                checkpoint_started = time.perf_counter()
                manifest = original_commit(cursor=cursor, participants=participants)
                checkpoints.append(
                    {
                        "checkpoint_seconds": time.perf_counter() - checkpoint_started,
                        "completed_simulated_hours": cursor.completed_simulated_hours,
                        "phase": cursor.phase,
                        "sequence": manifest.sequence,
                    }
                )
                return manifest

            controller.commit = measured_checkpoint_commit  # type: ignore[method-assign]
        engine = GenerationEngine(
            scenario,
            root / "data",
            ground_truth_dir=root,
            artifact_dir=root / "artifacts",
            scenario_root=args.scenario.parent,
            compiled_scenario=compiled,
            checkpoint_hours=args.child_checkpoint_hours,
            checkpoint_controller=controller,
            allow_large_workload=True,
            progress_callback=record_phase,
        )
        engine.generate()
        wall_seconds = time.perf_counter() - started
        output_digest, output_hashes, output_bytes = _output_digest(root)
        workspace_bytes = (
            0
            if store is None or not store.workspace.exists()
            else _directory_bytes(store.workspace)
        )
        scale_points = [
            item for item in checkpoints if int(item["completed_simulated_hours"]) in _SCALING_HOURS
        ]
        result = {
            "checkpoint_count": len(checkpoints),
            "checkpoint_hours": args.child_checkpoint_hours,
            "checkpoint_seconds": sum(float(item["checkpoint_seconds"]) for item in checkpoints),
            "output_bytes": output_bytes,
            "output_digest": output_digest,
            "output_hashes": output_hashes,
            "peak_rss_bytes": _peak_rss_bytes(),
            "phase_seconds": phase_seconds,
            "scale_points": scale_points,
            "wall_seconds": wall_seconds,
            "workspace_bytes": workspace_bytes,
        }
        print(_RESULT_PREFIX + json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _child_command(args: argparse.Namespace, checkpoint_hours: int) -> list[str]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--scenario",
        str(args.scenario),
        "--trials",
        "1",
        "--child-checkpoint-hours",
        str(checkpoint_hours),
    ]
    if args.duration is not None:
        command.extend(("--duration", args.duration))
    if args.work_directory is not None:
        command.extend(("--work-directory", str(args.work_directory)))
    return command


def _invoke_child(args: argparse.Namespace, checkpoint_hours: int) -> dict[str, object]:
    completed = subprocess.run(
        _child_command(args, checkpoint_hours),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "checkpoint benchmark child failed\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    line = next(
        (
            item
            for item in reversed(completed.stdout.splitlines())
            if item.startswith(_RESULT_PREFIX)
        ),
        None,
    )
    if line is None:
        raise RuntimeError("checkpoint benchmark child returned no structured result")
    value = json.loads(line.removeprefix(_RESULT_PREFIX))
    if type(value) is not dict:
        raise RuntimeError("checkpoint benchmark child returned an invalid result")
    return value


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle]


def _run_parent(args: argparse.Namespace) -> dict[str, object]:
    trials: list[dict[str, object]] = []
    for checkpoint_hours in args.cadences:
        for trial in range(args.trials):
            order = (0, checkpoint_hours) if trial % 2 == 0 else (checkpoint_hours, 0)
            by_cadence = {cadence: _invoke_child(args, cadence) for cadence in order}
            control = by_cadence[0]
            checkpoint = by_cadence[checkpoint_hours]
            if (
                control["output_digest"] != checkpoint["output_digest"]
                or control["output_hashes"] != checkpoint["output_hashes"]
                or control["output_bytes"] != checkpoint["output_bytes"]
            ):
                control_hashes = control["output_hashes"]
                checkpoint_hashes = checkpoint["output_hashes"]
                if type(control_hashes) is not dict or type(checkpoint_hashes) is not dict:
                    raise RuntimeError("checkpoint benchmark child output hashes are invalid")
                differences = sorted(
                    path
                    for path in set(control_hashes) | set(checkpoint_hashes)
                    if control_hashes.get(path) != checkpoint_hashes.get(path)
                )
                raise RuntimeError(
                    f"checkpoint cadence {checkpoint_hours} changed deterministic output bytes: "
                    f"{differences}"
                )
            control_seconds = float(control["wall_seconds"])
            checkpoint_seconds = float(checkpoint["wall_seconds"])
            trials.append(
                {
                    "checkpoint": checkpoint,
                    "checkpoint_hours": checkpoint_hours,
                    "control": control,
                    "overhead_percent": 100.0
                    * (checkpoint_seconds - control_seconds)
                    / control_seconds,
                    "trial": trial + 1,
                }
            )
    summaries: list[dict[str, object]] = []
    for cadence in args.cadences:
        matching = [item for item in trials if item["checkpoint_hours"] == cadence]
        summaries.append(
            {
                "checkpoint_hours": cadence,
                "median_checkpoint_path_seconds": _median(
                    [float(item["checkpoint"]["checkpoint_seconds"]) for item in matching]  # type: ignore[index]
                ),
                "median_overhead_percent": _median(
                    [float(item["overhead_percent"]) for item in matching]
                ),
                "median_wall_seconds": _median(
                    [float(item["checkpoint"]["wall_seconds"]) for item in matching]  # type: ignore[index]
                ),
            }
        )
    return {
        "cadences": args.cadences,
        "duration": args.duration,
        "scenario": str(args.scenario.resolve()),
        "summaries": summaries,
        "trials": trials,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--duration")
    parser.add_argument("--cadences", type=int, nargs="+", default=[6])
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--work-directory", type=Path)
    parser.add_argument("--child-checkpoint-hours", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--child-output-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    if any(value <= 0 for value in args.cadences):
        parser.error("--cadences values must be positive")
    if args.child_checkpoint_hours is not None and args.child_checkpoint_hours < 0:
        parser.error("--child-checkpoint-hours must be non-negative")
    if args.child_output_root is not None:
        args.child_output_root = args.child_output_root.resolve()
        if args.child_output_root.exists():
            parser.error(f"child output root already exists: {args.child_output_root}")
    args.scenario = args.scenario.resolve()
    if not args.scenario.is_file():
        parser.error(f"scenario does not exist: {args.scenario}")
    if args.work_directory is not None:
        args.work_directory = args.work_directory.resolve()
        if not args.work_directory.is_dir():
            parser.error(f"work directory does not exist: {args.work_directory}")
    return args


def main() -> int:
    args = _parse_args()
    if args.child_checkpoint_hours is not None:
        return _run_child(args)
    result = _run_parent(args)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
