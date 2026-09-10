# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Low-overhead, opt-in profiling for deterministic generation runs."""

from __future__ import annotations

import logging
import os
import platform
import signal
import sys
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge import __version__

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on Windows
    resource = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

GENERATION_PROFILE_FILENAME = "GENERATION_PROFILE.json"
GENERATION_PROFILE_SCHEMA_VERSION = "1.0"
DEFAULT_SAMPLE_HZ = 100
DEFAULT_MAX_UNIQUE_STACKS = 50_000
DEFAULT_MAX_STACK_DEPTH = 96


class ProfileMetricProvider(Protocol):
    """Provide bounded, constant-time metrics to the generation profiler."""

    def profiling_metrics(self) -> Mapping[str, int | float | bool]:
        """Return one snapshot without walking retained generation state."""

        ...


class ProfileFunctionSample(BaseModel):
    """Aggregated samples attributed to one Python function."""

    location: str
    exclusive_samples: int = Field(ge=0)
    inclusive_samples: int = Field(ge=0)
    exclusive_percent: float = Field(ge=0.0, le=100.0)
    inclusive_percent: float = Field(ge=0.0, le=100.0)

    model_config = ConfigDict(extra="forbid")


class ProfileStackSample(BaseModel):
    """One folded root-to-leaf Python stack and its sample count."""

    frames: tuple[str, ...]
    samples: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid")


class ProfileEmitterHour(BaseModel):
    """One emitter's work observed during a simulated hour."""

    rendered_rows: int = Field(ge=0)
    barrier_seconds: float = Field(ge=0.0)
    worker_cpu_seconds: float | None = Field(default=None, ge=0.0)
    queue_depth_before_barrier: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class ProfileEmitterSummary(BaseModel):
    """Final rendered-row and barrier totals for one concrete output format."""

    rendered_rows: int = Field(ge=0)
    barrier_seconds: float = Field(ge=0.0)
    worker_cpu_seconds: float | None = Field(default=None, ge=0.0)
    max_queue_depth_before_barrier: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class ProfileHour(BaseModel):
    """Bounded metrics for one completed simulated hour."""

    phase: Literal["warmup", "collection"]
    simulated_time: str
    wall_seconds: float = Field(ge=0.0)
    process_cpu_seconds: float = Field(ge=0.0)
    peak_rss_bytes: int = Field(ge=0)
    stages: dict[str, float]
    emitters: dict[str, ProfileEmitterHour]
    state_metrics: dict[str, int | float | bool]

    model_config = ConfigDict(extra="forbid")


class GenerationProfileDocument(BaseModel):
    """Machine-readable profile for one generation process invocation."""

    kind: Literal["evidenceforge.generation-profile"] = "evidenceforge.generation-profile"
    schema_version: Literal["1.0"] = GENERATION_PROFILE_SCHEMA_VERSION
    evidenceforge_version: str
    scenario: str
    generation_seed: int = Field(ge=0)
    output_target: str
    selected_formats: tuple[str, ...]
    runtime: dict[str, str]
    started_at: str
    completed_at: str
    starting_cursor: dict[str, object] | None = None
    generation_status: Literal["completed", "failed", "suspended"]
    degraded: bool
    warnings: tuple[str, ...]
    sample_hz: int = Field(gt=0)
    sampler: Literal["itimer-prof", "unavailable"]
    total_samples: int = Field(ge=0)
    dropped_samples: int = Field(ge=0)
    elapsed_wall_seconds: float = Field(ge=0.0)
    elapsed_process_cpu_seconds: float = Field(ge=0.0)
    peak_rss_bytes: int = Field(ge=0)
    phases: dict[str, float]
    stages: dict[str, float]
    hours: tuple[ProfileHour, ...]
    emitters: dict[str, ProfileEmitterSummary]
    functions: tuple[ProfileFunctionSample, ...]
    stacks: tuple[ProfileStackSample, ...]

    model_config = ConfigDict(extra="forbid")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _peak_rss_bytes() -> int:
    """Return the process peak RSS using platform-correct getrusage units."""

    if resource is None:
        return 0
    peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if platform.system() == "Darwin":
        return max(0, peak)
    return max(0, peak * 1024)


class GenerationProfiler:
    """Collect bounded statistical and coarse generation measurements."""

    def __init__(
        self,
        *,
        scenario: str,
        generation_seed: int,
        output_target: str,
        selected_formats: tuple[str, ...],
        source_root: Path | None = None,
        sample_hz: int = DEFAULT_SAMPLE_HZ,
        max_unique_stacks: int = DEFAULT_MAX_UNIQUE_STACKS,
        max_stack_depth: int = DEFAULT_MAX_STACK_DEPTH,
    ) -> None:
        if sample_hz <= 0:
            raise ValueError("sample_hz must be positive")
        if max_unique_stacks <= 0:
            raise ValueError("max_unique_stacks must be positive")
        if max_stack_depth <= 0:
            raise ValueError("max_stack_depth must be positive")
        self.scenario = scenario
        self.generation_seed = generation_seed
        self.output_target = output_target
        self.selected_formats = tuple(sorted(selected_formats))
        self.source_root = Path(source_root).resolve() if source_root is not None else None
        self.sample_hz = sample_hz
        self.max_unique_stacks = max_unique_stacks
        self.max_stack_depth = max_stack_depth

        self._started = False
        self._finished = False
        self._started_at = ""
        self._completed_at = ""
        self._start_wall_ns = 0
        self._start_cpu_ns = 0
        self._elapsed_wall_seconds = 0.0
        self._elapsed_cpu_seconds = 0.0
        self._generation_status: Literal["completed", "failed", "suspended"] = "failed"
        self._starting_cursor: dict[str, object] | None = None
        self._warnings: list[str] = []
        self._degraded = False

        self._stack_counts: Counter[tuple[str, ...]] = Counter()
        self._dropped_samples = 0
        self._sampler: Literal["itimer-prof", "unavailable"] = "unavailable"
        self._prior_sigprof_handler: Any = None
        self._prior_sigprof_timer: tuple[float, float] | None = None
        self._sampler_state_captured = False
        self._location_cache: dict[tuple[str, str, int], str] = {}

        self._phase_started_ns: dict[str, int] = {}
        self._phase_seconds: Counter[str] = Counter()
        self._stage_seconds: Counter[str] = Counter()
        self._active_hour: dict[str, object] | None = None
        self._hours: list[ProfileHour] = []
        self._emitter_rows: dict[str, int] = {}
        self._emitter_worker_cpu_ns: dict[str, int] = {}
        self._emitter_summaries: dict[str, ProfileEmitterSummary] = {}

    @property
    def active(self) -> bool:
        """Return whether this profiler is collecting one invocation."""

        return self._started and not self._finished

    @property
    def started(self) -> bool:
        """Return whether this profiler has ever started its single invocation."""

        return self._started

    @property
    def finished(self) -> bool:
        """Return whether this profiler has frozen its invocation measurements."""

        return self._finished

    def start(self, *, starting_cursor: Mapping[str, object] | None = None) -> None:
        """Start one process-local profile and install the CPU sampler when supported."""

        if self._started:
            raise RuntimeError("Generation profiler cannot be started twice")
        self._started = True
        self._started_at = _utc_now()
        self._start_wall_ns = time.perf_counter_ns()
        self._start_cpu_ns = time.process_time_ns()
        self._starting_cursor = dict(starting_cursor) if starting_cursor is not None else None
        self._install_sampler()

    def finish(
        self,
        status: Literal["completed", "failed", "suspended"],
    ) -> None:
        """Stop sampling and freeze elapsed invocation measurements."""

        if not self._started or self._finished:
            return
        try:
            self._restore_sampler()
        except (OSError, RuntimeError, ValueError) as exc:
            self._degrade(f"Unable to restore SIGPROF state: {exc}")
        now_wall_ns = time.perf_counter_ns()
        now_cpu_ns = time.process_time_ns()
        for name, started_ns in tuple(self._phase_started_ns.items()):
            self._phase_seconds[name] += max(0.0, (now_wall_ns - started_ns) / 1e9)
        self._phase_started_ns.clear()
        self._elapsed_wall_seconds = max(0.0, (now_wall_ns - self._start_wall_ns) / 1e9)
        self._elapsed_cpu_seconds = max(0.0, (now_cpu_ns - self._start_cpu_ns) / 1e9)
        self._completed_at = _utc_now()
        self._generation_status = status
        self._finished = True

    def observe_progress(self, event_type: str, data: Mapping[str, object]) -> None:
        """Translate existing phase progress events into coarse phase timers."""

        if not self.active:
            return
        phase = data.get("phase")
        if type(phase) is not str or not phase:
            return
        now_ns = time.perf_counter_ns()
        if event_type == "phase_start":
            self._phase_started_ns.setdefault(phase, now_ns)
        elif event_type == "phase_end":
            started_ns = self._phase_started_ns.pop(phase, None)
            if started_ns is not None:
                self._phase_seconds[phase] += max(0.0, (now_ns - started_ns) / 1e9)

    def begin_phase(self, name: str) -> None:
        """Start an internal profiling phase without changing progress callbacks."""

        if self.active:
            self._phase_started_ns.setdefault(name, time.perf_counter_ns())

    def end_phase(self, name: str) -> None:
        """Complete an internal profiling phase when it is active."""

        if not self.active:
            return
        started_ns = self._phase_started_ns.pop(name, None)
        if started_ns is not None:
            self._phase_seconds[name] += max(
                0.0,
                (time.perf_counter_ns() - started_ns) / 1e9,
            )

    @contextmanager
    def span(self, name: str) -> Iterator[None]:
        """Measure one low-frequency named generation stage."""

        if not self.active:
            yield
            return
        started_ns = time.perf_counter_ns()
        try:
            yield
        finally:
            seconds = max(0.0, (time.perf_counter_ns() - started_ns) / 1e9)
            self._stage_seconds[name] += seconds
            active_hour = self._active_hour
            if active_hour is not None:
                stages = active_hour["stages"]
                assert isinstance(stages, Counter)
                stages[name] += seconds

    def begin_hour(
        self,
        *,
        phase: Literal["warmup", "collection"],
        simulated_time: datetime,
    ) -> None:
        """Open one simulated-hour measurement at its exact generation boundary."""

        if not self.active:
            return
        if self._active_hour is not None:
            self._degrade("A new simulated hour started before the prior hour completed")
            self._active_hour = None
        self._active_hour = {
            "phase": phase,
            "simulated_time": simulated_time.isoformat(),
            "wall_ns": time.perf_counter_ns(),
            "cpu_ns": time.process_time_ns(),
            "stages": Counter(),
            "barriers": Counter(),
            "queue_depths": {},
        }

    def record_emitter_barrier(
        self,
        *,
        format_name: str,
        elapsed_seconds: float,
        queue_depth_before: int,
    ) -> None:
        """Record one emitter's share of a completed barrier."""

        active_hour = self._active_hour
        if not self.active or active_hour is None:
            return
        barriers = active_hour["barriers"]
        queue_depths = active_hour["queue_depths"]
        assert isinstance(barriers, Counter)
        assert isinstance(queue_depths, dict)
        barriers[format_name] += max(0.0, elapsed_seconds)
        queue_depths[format_name] = max(
            int(queue_depths.get(format_name, 0)),
            max(0, queue_depth_before),
        )

    def end_hour(
        self,
        *,
        emitter_snapshots: Mapping[str, Mapping[str, int | None]],
        state_metrics: Mapping[str, int | float | bool],
    ) -> None:
        """Close one hour after lifecycle cleanup and capture bounded deltas."""

        if not self.active:
            return
        active_hour = self._active_hour
        if active_hour is None:
            self._degrade("A simulated hour completed without a matching start")
            return
        barriers = active_hour["barriers"]
        queue_depths = active_hour["queue_depths"]
        stages = active_hour["stages"]
        assert isinstance(barriers, Counter)
        assert isinstance(queue_depths, dict)
        assert isinstance(stages, Counter)
        emitters: dict[str, ProfileEmitterHour] = {}
        for format_name, snapshot in sorted(emitter_snapshots.items()):
            rows = int(snapshot.get("rendered_rows") or 0)
            previous_rows = self._emitter_rows.get(format_name, 0)
            self._emitter_rows[format_name] = rows
            worker_cpu_raw = snapshot.get("worker_cpu_ns")
            worker_cpu_seconds: float | None = None
            if type(worker_cpu_raw) is int:
                previous_cpu = self._emitter_worker_cpu_ns.get(format_name, 0)
                self._emitter_worker_cpu_ns[format_name] = worker_cpu_raw
                worker_cpu_seconds = max(0.0, (worker_cpu_raw - previous_cpu) / 1e9)
            emitters[format_name] = ProfileEmitterHour(
                rendered_rows=max(0, rows - previous_rows),
                barrier_seconds=max(0.0, float(barriers.get(format_name, 0.0))),
                worker_cpu_seconds=worker_cpu_seconds,
                queue_depth_before_barrier=max(0, int(queue_depths.get(format_name, 0))),
            )
        wall_started = int(active_hour["wall_ns"])
        cpu_started = int(active_hour["cpu_ns"])
        self._hours.append(
            ProfileHour(
                phase=str(active_hour["phase"]),
                simulated_time=str(active_hour["simulated_time"]),
                wall_seconds=max(0.0, (time.perf_counter_ns() - wall_started) / 1e9),
                process_cpu_seconds=max(0.0, (time.process_time_ns() - cpu_started) / 1e9),
                peak_rss_bytes=_peak_rss_bytes(),
                stages={name: value for name, value in sorted(stages.items())},
                emitters=emitters,
                state_metrics=dict(sorted(state_metrics.items())),
            )
        )
        self._active_hour = None

    def record_final_emitters(
        self,
        emitter_snapshots: Mapping[str, Mapping[str, int | None]],
    ) -> None:
        """Capture final rendered totals after deferred emitters have closed."""

        if not self.active:
            return
        summaries: dict[str, ProfileEmitterSummary] = {}
        format_names = sorted(set(self.selected_formats) | set(emitter_snapshots))
        for format_name in format_names:
            snapshot = emitter_snapshots.get(format_name, {})
            worker_cpu_ns = snapshot.get("worker_cpu_ns")
            hourly_metrics = [
                hour.emitters[format_name] for hour in self._hours if format_name in hour.emitters
            ]
            summaries[format_name] = ProfileEmitterSummary(
                rendered_rows=max(0, int(snapshot.get("rendered_rows") or 0)),
                barrier_seconds=sum(metric.barrier_seconds for metric in hourly_metrics),
                worker_cpu_seconds=(
                    max(0.0, worker_cpu_ns / 1e9) if type(worker_cpu_ns) is int else None
                ),
                max_queue_depth_before_barrier=max(
                    (metric.queue_depth_before_barrier for metric in hourly_metrics),
                    default=0,
                ),
            )
        self._emitter_summaries = summaries

    def mark_degraded(self, warning: str) -> None:
        """Record a non-fatal profiling failure without affecting generation."""

        self._degrade(warning)

    def document(self) -> GenerationProfileDocument:
        """Build the validated report for a finished invocation."""

        if not self._finished:
            raise RuntimeError("Generation profile must be finished before serialization")
        total_samples = sum(self._stack_counts.values())
        inclusive: Counter[str] = Counter()
        exclusive: Counter[str] = Counter()
        for stack, count in self._stack_counts.items():
            if not stack:
                continue
            exclusive[self._function_location(stack[-1])] += count
            for function in {self._function_location(frame) for frame in stack}:
                inclusive[function] += count
        locations = sorted(
            inclusive,
            key=lambda location: (-exclusive[location], -inclusive[location], location),
        )
        denominator = max(1, total_samples)
        functions = tuple(
            ProfileFunctionSample(
                location=location,
                exclusive_samples=exclusive[location],
                inclusive_samples=inclusive[location],
                exclusive_percent=100.0 * exclusive[location] / denominator,
                inclusive_percent=100.0 * inclusive[location] / denominator,
            )
            for location in locations
        )
        stacks = tuple(
            ProfileStackSample(frames=stack, samples=count)
            for stack, count in sorted(
                self._stack_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
        )
        return GenerationProfileDocument(
            evidenceforge_version=__version__,
            scenario=self.scenario,
            generation_seed=self.generation_seed,
            output_target=self.output_target,
            selected_formats=self.selected_formats,
            runtime={
                "python": platform.python_version(),
                "platform": platform.system().lower(),
                "platform_release": platform.release(),
            },
            started_at=self._started_at,
            completed_at=self._completed_at,
            starting_cursor=self._starting_cursor,
            generation_status=self._generation_status,
            degraded=self._degraded,
            warnings=tuple(self._warnings),
            sample_hz=self.sample_hz,
            sampler=self._sampler,
            total_samples=total_samples,
            dropped_samples=self._dropped_samples,
            elapsed_wall_seconds=self._elapsed_wall_seconds,
            elapsed_process_cpu_seconds=self._elapsed_cpu_seconds,
            peak_rss_bytes=_peak_rss_bytes(),
            phases={name: value for name, value in sorted(self._phase_seconds.items())},
            stages={name: value for name, value in sorted(self._stage_seconds.items())},
            hours=tuple(self._hours),
            emitters=dict(sorted(self._emitter_summaries.items())),
            functions=functions,
            stacks=stacks,
        )

    def write(self, bundle_root: Path) -> Path | None:
        """Atomically write the completed diagnostic sidecar without failing generation."""

        destination = Path(bundle_root) / GENERATION_PROFILE_FILENAME
        temporary: Path | None = None
        try:
            if destination.is_symlink():
                raise PermissionError(
                    f"refusing to write generation profile through symlink: {destination}"
                )
            payload = (self.document().model_dump_json(indent=2) + "\n").encode("utf-8")
            temporary = destination.with_name(f".{destination.name}.pending-{uuid.uuid4().hex}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except (OSError, RuntimeError, ValueError) as exc:
            self._degrade(f"Unable to write generation profile: {exc}")
            logger.warning("Unable to write generation profile: %s", exc)
            return None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return destination

    def _install_sampler(self) -> None:
        if (
            threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "SIGPROF")
            or not hasattr(signal, "ITIMER_PROF")
            or not hasattr(signal, "setitimer")
        ):
            self._degrade("ITIMER_PROF sampling is unavailable; coarse metrics remain enabled")
            return
        try:
            self._prior_sigprof_handler = signal.getsignal(signal.SIGPROF)
            self._prior_sigprof_timer = signal.getitimer(signal.ITIMER_PROF)
            self._sampler_state_captured = True
            signal.signal(signal.SIGPROF, self._sample)
            interval = 1.0 / self.sample_hz
            signal.setitimer(signal.ITIMER_PROF, interval, interval)
            self._sampler = "itimer-prof"
        except (OSError, RuntimeError, ValueError) as exc:
            self._degrade(f"Unable to start ITIMER_PROF sampling: {exc}")
            self._sampler = "unavailable"
            try:
                self._restore_sampler_state()
            except (OSError, RuntimeError, ValueError) as restore_exc:
                self._degrade(f"Unable to roll back partial SIGPROF state: {restore_exc}")

    def _restore_sampler(self) -> None:
        if self._sampler == "itimer-prof":
            signal.setitimer(signal.ITIMER_PROF, 0.0, 0.0)
        self._restore_sampler_state()

    def _restore_sampler_state(self) -> None:
        if not self._sampler_state_captured:
            return
        if self._prior_sigprof_handler is not None:
            signal.signal(signal.SIGPROF, self._prior_sigprof_handler)
        if self._prior_sigprof_timer is not None:
            delay, interval = self._prior_sigprof_timer
            if delay > 0.0 or interval > 0.0:
                signal.setitimer(signal.ITIMER_PROF, delay, interval)
        self._sampler_state_captured = False

    def _sample(self, _signum: int, frame: FrameType | None) -> None:
        if frame is None:
            self._dropped_samples += 1
            return
        frames: list[str] = []
        cursor: FrameType | None = frame
        depth = 0
        while cursor is not None and depth < self.max_stack_depth:
            code = cursor.f_code
            frames.append(self._frame_location(code.co_filename, code.co_name, cursor.f_lineno))
            cursor = cursor.f_back
            depth += 1
        stack = tuple(reversed(frames))
        if stack in self._stack_counts or len(self._stack_counts) < self.max_unique_stacks:
            self._stack_counts[stack] += 1
        else:
            self._dropped_samples += 1

    def _frame_location(self, filename: str, function: str, line: int) -> str:
        key = (filename, function, line)
        cached = self._location_cache.get(key)
        if cached is not None:
            return cached
        path = Path(filename)
        normalized: str
        if self.source_root is not None:
            try:
                normalized = path.resolve().relative_to(self.source_root).as_posix()
            except (OSError, ValueError):
                normalized = self._external_path(path)
        else:
            normalized = self._external_path(path)
        location = f"{normalized}:{line}:{function}"
        if len(self._location_cache) < self.max_unique_stacks * 2:
            self._location_cache[key] = location
        return location

    @staticmethod
    def _function_location(frame_location: str) -> str:
        """Collapse one line-level folded frame to a portable function key."""

        path, _line, function = frame_location.rsplit(":", 2)
        return f"{path}:{function}"

    @staticmethod
    def _external_path(path: Path) -> str:
        parts = path.parts
        if "site-packages" in parts:
            index = parts.index("site-packages")
            return "<site-packages>/" + "/".join(parts[index + 1 :])
        prefix = Path(sys.base_prefix).resolve()
        try:
            return "<stdlib>/" + path.resolve().relative_to(prefix).as_posix()
        except (OSError, ValueError):
            return f"<external>/{path.name}"

    def _degrade(self, warning: str) -> None:
        self._degraded = True
        if warning not in self._warnings:
            self._warnings.append(warning)


__all__ = [
    "GENERATION_PROFILE_FILENAME",
    "GENERATION_PROFILE_SCHEMA_VERSION",
    "GenerationProfileDocument",
    "GenerationProfiler",
    "ProfileMetricProvider",
]
