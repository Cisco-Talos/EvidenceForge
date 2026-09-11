# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Timing realism profile loader and helpers."""

from __future__ import annotations

import logging
import random
from collections.abc import Callable, Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from itertools import islice
from threading import Condition, get_ident
from typing import Any, Literal, NoReturn, Protocol

from evidenceforge.config import get_activity_directory
from evidenceforge.config.compatibility import (
    EvidenceForgeDeprecationWarning,
    warn_legacy_config,
)
from evidenceforge.config.overlay import load_with_overlay
from evidenceforge.config.provider import (
    _CONFIG_EXECUTION_LOCK,
    _CONFIG_SCOPE_LEASE,
    _register_timing_profile_runtime_cache,
    current_prepared_timing_profiles,
)
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.timing import (
    ConstantDistribution,
    DistributionSpec,
    MixtureDistribution,
    TimingRuntime,
    TimingSampler,
    TimingScope,
    TriangularDistribution,
    WeightedDistribution,
)
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)

_CONFIG_PATH = get_activity_directory() / "timing_profiles.yaml"
_MAX_RELATIONSHIP_MS = 86_400_000
_MAX_COLLISION_NEAR_ZERO_UNTIL = 10_000
_MAX_COLLISION_GAP_US = 1_000_000
_MAX_COLLISION_GAP_MS = 60_000
_MAX_SENSOR_TIMING_US = 1_000_000
_MAX_ENDPOINT_CLOCK_OFFSET_MS = 300_000
_MAX_ENDPOINT_CLOCK_DRIFT_PPM = 500
_NETWORK_SENSOR_PROFILE_ALIASES = (
    ("clock_skew_us", "clock_offset_us"),
    ("path_delay_us", "route_delay_us"),
)


class TimingProfileError(ValueError):
    """Raised when timing-profile input cannot be admitted safely."""


@dataclass(frozen=True, slots=True)
class _TimingProfileGraphLimits:
    """Hard limits applied before timing-profile graph copying or freezing.

    Depth and aggregate bytes match the existing scenario-composition limits.
    The remaining limits constrain YAML aliases and individual containers more
    tightly because the packaged timing profile is only about 13 KiB.
    """

    max_depth: int = 32
    max_container_members: int = 4_096
    max_unique_nodes: int = 262_144
    max_references: int = 524_288
    max_scalar_bytes: int = 1 * 1_024 * 1_024
    max_aggregate_bytes: int = 16 * 1_024 * 1_024

    def __post_init__(self) -> None:
        """Reject nonsensical graph budgets."""

        values = (
            self.max_depth,
            self.max_container_members,
            self.max_unique_nodes,
            self.max_references,
            self.max_scalar_bytes,
            self.max_aggregate_bytes,
        )
        if any(value < 1 for value in values):
            raise ValueError("timing-profile graph limits must be positive")


@dataclass(frozen=True, slots=True)
class _TimingProfileGraphStats:
    """Preflight accounting for one admitted timing-profile object graph."""

    unique_nodes: int
    references: int
    scalar_bytes: int
    aggregate_bytes: int
    max_depth: int


_TIMING_PROFILE_GRAPH_LIMITS = _TimingProfileGraphLimits()
# Deliberately exceed ordinary CPython container headers and reference slots so
# the 16 MiB logical budget remains conservative across supported runtimes.
_TIMING_PROFILE_CONTAINER_OVERHEAD_BYTES = 128
_TIMING_PROFILE_REFERENCE_OVERHEAD_BYTES = 32
_TIMING_PROFILE_MERGE_MEMO_ENTRY_BYTES = 96


class _FrozenTimingProfileMapping(tuple, Mapping[str, Any]):
    """An immutable mapping backed only by recursively frozen tuple storage."""

    __slots__ = ()
    __hash__ = None

    def __new__(cls, values: dict[str, Any]) -> _FrozenTimingProfileMapping:
        """Detach exact string/value pairs from a private construction dict."""

        return tuple.__new__(cls, tuple(dict.items(values)))

    def __getitem__(self, key: str) -> Any:
        """Return a frozen value for one exact string key."""

        for candidate, value in tuple.__iter__(self):
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        """Iterate mapping keys in authored order."""

        return (key for key, _value in tuple.__iter__(self))

    def __contains__(self, key: object) -> bool:
        """Return whether one exact key exists instead of using tuple membership."""

        return any(candidate == key for candidate, _value in tuple.__iter__(self))

    def __len__(self) -> int:
        """Return the number of mapping entries."""

        return tuple.__len__(self)

    def __repr__(self) -> str:
        """Render the frozen mapping using ordinary mapping notation."""

        return repr(dict(tuple.__iter__(self)))

    def __eq__(self, other: object) -> bool:
        """Compare mapping content with bounded alias-aware pair memoization."""

        if type(other) not in {dict, _FrozenTimingProfileMapping}:
            return NotImplemented
        return _timing_profile_values_equal(self, other)

    def __copy__(self) -> _FrozenTimingProfileMapping:
        """Return the same immutable value for a shallow copy."""

        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        """Return a detached mutable dict while preserving shared graph aliases."""

        copied: dict[str, Any] = {}
        memo[id(self)] = copied
        for key, value in tuple.__iter__(self):
            copied[deepcopy(key, memo)] = deepcopy(value, memo)
        return copied

    def _reject_mutation(self, *_args: Any, **_kwargs: Any) -> NoReturn:
        """Reject every ordinary mapping mutation surface."""

        raise TypeError("timing profile snapshot is immutable")

    __setitem__ = _reject_mutation
    __delitem__ = _reject_mutation
    __setattr__ = _reject_mutation
    __delattr__ = _reject_mutation
    __ior__ = _reject_mutation
    clear = _reject_mutation
    pop = _reject_mutation
    popitem = _reject_mutation
    setdefault = _reject_mutation
    update = _reject_mutation


class _FrozenTimingProfileList(tuple):
    """Immutable list storage that deep-copies to a detached mutable list."""

    __slots__ = ()

    def __deepcopy__(self, memo: dict[int, Any]) -> list[Any]:
        """Return a detached list while preserving shared descendant aliases."""

        copied: list[Any] = []
        memo[id(self)] = copied
        copied.extend(deepcopy(value, memo) for value in tuple.__iter__(self))
        return copied


class _TimingProfileCachePhase(Enum):
    """Exact public cache initialization phases."""

    EMPTY = "empty"
    INITIALIZING = "initializing"
    PREPARED = "prepared"
    READY = "ready"


@dataclass(frozen=True, slots=True)
class _TimingProfileCacheState:
    """One immutable state-machine revision for the timing-profile cache."""

    phase: _TimingProfileCachePhase
    epoch: int
    owner_thread_id: int | None = None
    snapshot: _FrozenTimingProfileMapping | None = None
    warning_generation: int | None = None
    warning_aliases: frozenset[str] | None = None

    def __post_init__(
        self,
        _empty_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.EMPTY,
        _initializing_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.INITIALIZING,
        _prepared_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.PREPARED,
    ) -> None:
        """Reject impossible cache-state combinations."""

        if self.epoch < 0:
            raise ValueError("timing profile cache epoch must be non-negative")
        if self.phase is _empty_phase:
            valid = (
                self.owner_thread_id is None
                and self.snapshot is None
                and self.warning_generation is None
                and self.warning_aliases is None
            )
        elif self.phase is _initializing_phase:
            valid = (
                self.owner_thread_id is not None
                and self.snapshot is None
                and self.warning_generation is None
                and self.warning_aliases is None
            )
        elif self.phase is _prepared_phase:
            valid = (
                self.owner_thread_id is not None
                and self.snapshot is not None
                and self.warning_generation is not None
                and self.warning_aliases is not None
            )
        else:
            valid = (
                self.owner_thread_id is None
                and self.snapshot is not None
                and self.warning_generation is not None
                and self.warning_aliases is not None
            )
        if not valid:
            raise ValueError("timing profile cache state fields do not match its phase")


class _TimingProfileCacheReentryError(RuntimeError):
    """Raised when the initializing thread reenters cache or provider operations."""


class _TimingProfileCacheCoordinator:
    """Own cache state and the provider save/clear/restore synchronization protocol."""

    __slots__ = ("_condition", "_state")

    def __init__(
        self,
        _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
        _empty_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.EMPTY,
    ) -> None:
        self._condition = Condition()
        self._state = _state_type(
            phase=_empty_phase,
            epoch=0,
        )

    @property
    def state(self) -> _TimingProfileCacheState:
        """Return the current immutable state revision for diagnostics and tests."""

        with self._condition:
            return self._state

    def _wait_until_stable(
        self,
        action: str,
        _initializing_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.INITIALIZING,
        _reentry_error: type[_TimingProfileCacheReentryError] = _TimingProfileCacheReentryError,
    ) -> None:
        """Wait for another initializer or reject same-thread reentry."""

        thread_id = get_ident()
        while self._state.phase is _initializing_phase:
            if self._state.owner_thread_id == thread_id:
                raise _reentry_error(
                    f"timing profile cache {action} reentered on its initializing thread"
                )
            self._condition.wait()

    def clear(
        self,
        *,
        action: str,
        _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
        _empty_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.EMPTY,
    ) -> None:
        """Synchronously clear one stable cache namespace."""

        with self._condition:
            self._wait_until_stable(action)
            self._state = _state_type(
                phase=_empty_phase,
                epoch=self._state.epoch + 1,
            )
            self._condition.notify_all()

    def _evidenceforge_runtime_cache_snapshot(self) -> _TimingProfileCacheState:
        """Save one exact stable state for the provider scope protocol."""

        with self._condition:
            self._wait_until_stable("provider snapshot")
            return self._state

    def _evidenceforge_runtime_cache_clear(self) -> None:
        """Clear state at a provider boundary without replacing this coordinator."""

        self.clear(action="provider clear")

    def _evidenceforge_runtime_cache_restore(
        self,
        snapshot: _TimingProfileCacheState,
        _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
        _initializing_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.INITIALIZING,
    ) -> None:
        """Restore the exact cache state saved before a provider scope."""

        if type(snapshot) is not _state_type:
            raise TypeError("timing profile provider snapshot has invalid type")
        if snapshot.phase is _initializing_phase:
            raise ValueError("cannot restore an initializing timing profile cache state")
        with self._condition:
            self._wait_until_stable("provider restore")
            self._state = snapshot
            self._condition.notify_all()


_TIMING_PROFILE_CACHE_COORDINATOR = _TimingProfileCacheCoordinator()


def _make_timing_profile_cache_protocol(
    coordinator: _TimingProfileCacheCoordinator,
    coordinator_type: type[_TimingProfileCacheCoordinator],
    state_type: type[_TimingProfileCacheState],
    snapshot_type: type[_FrozenTimingProfileMapping],
    empty_phase: _TimingProfileCachePhase,
    initializing_phase: _TimingProfileCachePhase,
    prepared_phase: _TimingProfileCachePhase,
    ready_phase: _TimingProfileCachePhase,
    reentry_error: type[_TimingProfileCacheReentryError],
    thread_identity: Callable[[], int],
) -> tuple[
    Callable[[Any], _TimingProfileCacheState],
    Callable[[Any], None],
    Callable[[Any, Any], None],
    Callable[[str], None],
    Callable[[str], None],
    Callable[[], None],
]:
    """Capture a singleton-specific cache protocol with no post-callback dispatch."""

    object_getattribute = object.__getattribute__
    object_setattr = object.__setattr__
    condition = object_getattribute(coordinator, "_condition")
    condition_acquire = condition.acquire
    condition_release = condition.release
    condition_wait = condition.wait
    condition_notify_all = condition.notify_all
    allowed_phases = (empty_phase, initializing_phase, prepared_phase, ready_phase)

    def require_controller(candidate: Any) -> None:
        if candidate is not coordinator or type(candidate) is not coordinator_type:
            raise TypeError("timing profile cache coordinator has invalid identity")

    def read_state() -> _TimingProfileCacheState:
        state = object_getattribute(coordinator, "_state")
        if type(state) is not state_type:
            raise TypeError("timing profile cache state has invalid type")
        phase = object_getattribute(state, "phase")
        epoch = object_getattribute(state, "epoch")
        owner = object_getattribute(state, "owner_thread_id")
        snapshot = object_getattribute(state, "snapshot")
        warning_generation = object_getattribute(state, "warning_generation")
        warning_aliases = object_getattribute(state, "warning_aliases")
        if not any(phase is allowed for allowed in allowed_phases):
            raise ValueError("timing profile cache state has invalid phase")
        if type(epoch) is not int or epoch < 0:
            raise ValueError("timing profile cache state has invalid epoch")
        if owner is not None and type(owner) is not int:
            raise TypeError("timing profile cache owner has invalid type")
        if snapshot is not None and type(snapshot) is not snapshot_type:
            raise TypeError("timing profile cache snapshot has invalid type")
        if warning_generation is not None and type(warning_generation) is not int:
            raise TypeError("timing profile warning generation has invalid type")
        if warning_aliases is not None and (
            type(warning_aliases) is not frozenset
            or any(type(alias) is not str for alias in warning_aliases)
        ):
            raise TypeError("timing profile warning aliases have invalid type")
        if phase is empty_phase:
            valid = (
                owner is None
                and snapshot is None
                and warning_generation is None
                and warning_aliases is None
            )
        elif phase is initializing_phase:
            valid = (
                owner is not None
                and snapshot is None
                and warning_generation is None
                and warning_aliases is None
            )
        elif phase is prepared_phase:
            valid = (
                owner is not None
                and snapshot is not None
                and warning_generation is not None
                and warning_aliases is not None
            )
        else:
            valid = (
                owner is None
                and snapshot is not None
                and warning_generation is not None
                and warning_aliases is not None
            )
        if not valid:
            raise ValueError("timing profile cache state fields do not match its phase")
        return state

    def wait_locked(action: str) -> _TimingProfileCacheState:
        if type(action) is not str:
            raise TypeError("timing profile cache action must be a builtin string")
        current_thread_id = thread_identity()
        state = read_state()
        while object_getattribute(state, "phase") is initializing_phase:
            if object_getattribute(state, "owner_thread_id") == current_thread_id:
                raise reentry_error(
                    f"timing profile cache {action} reentered on its initializing thread"
                )
            condition_wait()
            state = read_state()
        return state

    def snapshot(candidate: Any) -> _TimingProfileCacheState:
        require_controller(candidate)
        condition_acquire()
        try:
            return wait_locked("provider snapshot")
        finally:
            condition_release()

    def clear_for_action(action: str) -> None:
        condition_acquire()
        try:
            state = wait_locked(action)
            object_setattr(
                coordinator,
                "_state",
                state_type(
                    phase=empty_phase,
                    epoch=object_getattribute(state, "epoch") + 1,
                ),
            )
            condition_notify_all()
        finally:
            condition_release()

    def clear(candidate: Any) -> None:
        require_controller(candidate)
        clear_for_action("provider clear")

    def restore(candidate: Any, saved_state: Any) -> None:
        require_controller(candidate)
        if type(saved_state) is not state_type:
            raise TypeError("timing profile provider snapshot has invalid type")
        condition_acquire()
        try:
            wait_locked("provider restore")
            current = object_getattribute(coordinator, "_state")
            object_setattr(coordinator, "_state", saved_state)
            try:
                restored = read_state()
                if object_getattribute(restored, "phase") is initializing_phase:
                    raise ValueError("cannot restore an initializing timing profile cache state")
            except BaseException:
                object_setattr(coordinator, "_state", current)
                raise
            condition_notify_all()
        finally:
            condition_release()

    def wait_for_action(action: str) -> None:
        condition_acquire()
        try:
            wait_locked(action)
        finally:
            condition_release()

    def invalidate_binding() -> None:
        condition_acquire()
        try:
            state = read_state()
            if object_getattribute(state, "phase") is not empty_phase:
                object_setattr(
                    coordinator,
                    "_state",
                    state_type(
                        phase=empty_phase,
                        epoch=object_getattribute(state, "epoch") + 1,
                    ),
                )
                condition_notify_all()
        finally:
            condition_release()

    return snapshot, clear, restore, clear_for_action, wait_for_action, invalidate_binding


(
    _timing_profile_cache_snapshot_operation,
    _timing_profile_cache_clear_operation,
    _timing_profile_cache_restore_operation,
    _clear_timing_profile_cache_for_action,
    _wait_for_stable_timing_profile_cache,
    _invalidate_timing_profile_cache_binding,
) = _make_timing_profile_cache_protocol(
    _TIMING_PROFILE_CACHE_COORDINATOR,
    _TimingProfileCacheCoordinator,
    _TimingProfileCacheState,
    _FrozenTimingProfileMapping,
    _TimingProfileCachePhase.EMPTY,
    _TimingProfileCachePhase.INITIALIZING,
    _TimingProfileCachePhase.PREPARED,
    _TimingProfileCachePhase.READY,
    _TimingProfileCacheReentryError,
    get_ident,
)
_CACHED_TIMING_PROFILES = _TIMING_PROFILE_CACHE_COORDINATOR
_TIMING_PROFILE_MODULE_NAMESPACE = globals()
_register_timing_profile_runtime_cache(
    __name__,
    _TIMING_PROFILE_MODULE_NAMESPACE,
    _TIMING_PROFILE_CACHE_COORDINATOR,
    _TimingProfileCacheCoordinator,
    _timing_profile_cache_snapshot_operation,
    _timing_profile_cache_clear_operation,
    _timing_profile_cache_restore_operation,
)
_WARNED_TIMING_PROFILE_ALIASES: frozenset[str] = frozenset()
_EMITTED_TIMING_PROFILE_DIAGNOSTICS: frozenset[str] = frozenset()
_TIMING_PROFILE_WARNING_ROLLBACK_GENERATION = 0


def _make_timing_profile_cache_binding_guard(
    namespace: dict[str, Any],
    coordinator: _TimingProfileCacheCoordinator,
    invalidate_binding: Callable[[], None],
) -> Callable[[], None]:
    """Pin the public cache slot to its one registered coordinator identity."""

    def require_current_binding() -> None:
        if dict.get(namespace, "_CACHED_TIMING_PROFILES") is coordinator:
            return
        invalidate_binding()
        raise RuntimeError("timing profile cache coordinator binding was replaced")

    return require_current_binding


_require_timing_profile_cache_binding = _make_timing_profile_cache_binding_guard(
    _TIMING_PROFILE_MODULE_NAMESPACE,
    _TIMING_PROFILE_CACHE_COORDINATOR,
    _invalidate_timing_profile_cache_binding,
)


def _make_timing_profile_callback_ledger(
    namespace: dict[str, Any],
    coordinator: _TimingProfileCacheCoordinator,
    aliases: tuple[tuple[str, str], ...],
) -> tuple[
    Callable[
        [frozenset[str], tuple[str, ...]],
        tuple[tuple[tuple[str, str], ...], tuple[str, ...], int],
    ],
    Callable[[tuple[tuple[str, str], ...], tuple[str, ...]], int],
    Callable[[int, frozenset[str]], bool],
    Callable[[], None],
    Callable[[frozenset[str]], None],
    Callable[[], None],
]:
    """Own callback reservations in closure state immune to peer-global rebinding."""

    warned_aliases: frozenset[str] = frozenset()
    emitted_diagnostics: frozenset[str] = frozenset()
    rollback_generation = 0

    def publish_mirrors() -> tuple[Any, Any, Any]:
        pinned = (
            dict.get(namespace, "_WARNED_TIMING_PROFILE_ALIASES"),
            dict.get(namespace, "_EMITTED_TIMING_PROFILE_DIAGNOSTICS"),
            dict.get(namespace, "_TIMING_PROFILE_WARNING_ROLLBACK_GENERATION"),
        )
        dict.__setitem__(namespace, "_WARNED_TIMING_PROFILE_ALIASES", warned_aliases)
        dict.__setitem__(namespace, "_EMITTED_TIMING_PROFILE_DIAGNOSTICS", emitted_diagnostics)
        dict.__setitem__(
            namespace,
            "_TIMING_PROFILE_WARNING_ROLLBACK_GENERATION",
            rollback_generation,
        )
        return pinned

    def reserve(
        encountered_aliases: frozenset[str],
        diagnostics: tuple[str, ...],
    ) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...], int]:
        nonlocal emitted_diagnostics
        nonlocal warned_aliases
        if type(encountered_aliases) is not frozenset or type(diagnostics) is not tuple:
            raise TypeError("timing profile callback reservation has invalid type")
        with coordinator._condition:
            aliases_to_warn = tuple(
                (legacy_name, canonical_name)
                for legacy_name, canonical_name in aliases
                if legacy_name in encountered_aliases and legacy_name not in warned_aliases
            )
            warned_aliases = frozenset.union(
                warned_aliases,
                frozenset(legacy for legacy, _canonical in aliases_to_warn),
            )
            diagnostics_to_emit = tuple(
                dict.fromkeys(
                    diagnostic
                    for diagnostic in diagnostics
                    if diagnostic not in emitted_diagnostics
                )
            )
            emitted_diagnostics = frozenset.union(
                emitted_diagnostics,
                frozenset(diagnostics_to_emit),
            )
            generation = rollback_generation
            pinned = publish_mirrors()
        del pinned
        return aliases_to_warn, diagnostics_to_emit, generation

    def rollback(
        aliases_to_warn: tuple[tuple[str, str], ...],
        diagnostics: tuple[str, ...],
    ) -> int:
        nonlocal emitted_diagnostics
        nonlocal rollback_generation
        nonlocal warned_aliases
        reserved_aliases = frozenset(
            legacy_name for legacy_name, _canonical_name in aliases_to_warn
        )
        reserved_diagnostics = frozenset(diagnostics)
        with coordinator._condition:
            warned_aliases = frozenset.difference(warned_aliases, reserved_aliases)
            emitted_diagnostics = frozenset.difference(
                emitted_diagnostics,
                reserved_diagnostics,
            )
            rollback_generation += 1
            generation = rollback_generation
            pinned = publish_mirrors()
            coordinator._condition.notify_all()
        del pinned
        return generation

    def is_current(generation: int, required_aliases: frozenset[str]) -> bool:
        if type(generation) is not int or type(required_aliases) is not frozenset:
            return False
        if any(type(alias) is not str for alias in required_aliases):
            return False
        with coordinator._condition:
            return generation == rollback_generation and frozenset.issubset(
                required_aliases,
                warned_aliases,
            )

    def reset() -> None:
        nonlocal emitted_diagnostics
        nonlocal rollback_generation
        nonlocal warned_aliases
        with coordinator._condition:
            warned_aliases = frozenset()
            emitted_diagnostics = frozenset()
            rollback_generation += 1
            pinned = publish_mirrors()
            coordinator._condition.notify_all()
        del pinned

    def set_warned_for_tests(value: frozenset[str]) -> None:
        nonlocal warned_aliases
        if type(value) is not frozenset or any(type(alias) is not str for alias in value):
            raise TypeError("timing profile warning test ledger has invalid type")
        with coordinator._condition:
            warned_aliases = value
            pinned = publish_mirrors()
        del pinned

    def require_mirrors() -> None:
        mismatch = False
        with coordinator._condition:
            current = (
                dict.get(namespace, "_WARNED_TIMING_PROFILE_ALIASES"),
                dict.get(namespace, "_EMITTED_TIMING_PROFILE_DIAGNOSTICS"),
                dict.get(namespace, "_TIMING_PROFILE_WARNING_ROLLBACK_GENERATION"),
            )
            expected = (warned_aliases, emitted_diagnostics, rollback_generation)
            mismatch = any(
                actual is not wanted for actual, wanted in zip(current, expected, strict=True)
            )
            if mismatch:
                pinned = publish_mirrors()
        if mismatch:
            del pinned
            raise RuntimeError("timing profile callback ledger binding was replaced")

    pinned = publish_mirrors()
    del pinned
    return reserve, rollback, is_current, reset, set_warned_for_tests, require_mirrors


(
    _reserve_timing_profile_callback_ledger,
    _rollback_timing_profile_callback_ledger,
    _timing_profile_callback_ledger_is_current,
    _reset_timing_profile_callback_ledger,
    _set_timing_profile_warned_aliases_for_tests,
    _require_timing_profile_callback_ledger_bindings,
) = _make_timing_profile_callback_ledger(
    _TIMING_PROFILE_MODULE_NAMESPACE,
    _TIMING_PROFILE_CACHE_COORDINATOR,
    _NETWORK_SENSOR_PROFILE_ALIASES,
)


def _make_timing_profile_runtime_binding_guard(
    cache_guard: Callable[[], None],
    ledger_guard: Callable[[], None],
) -> Callable[[], None]:
    """Check and repair every callback-visible peer binding outside provider locks."""

    def require_runtime_bindings() -> None:
        retained_failure: BaseException | None = None
        for guard in (cache_guard, ledger_guard):
            try:
                guard()
            except BaseException as binding_failure:
                if retained_failure is None:
                    retained_failure = binding_failure
        if retained_failure is not None:
            raise retained_failure

    return require_runtime_bindings


_require_timing_profile_runtime_bindings = _make_timing_profile_runtime_binding_guard(
    _require_timing_profile_cache_binding,
    _require_timing_profile_callback_ledger_bindings,
)


@dataclass(frozen=True, slots=True)
class _PreparedTimingProfiles:
    """A canonical immutable snapshot whose aliases were prewarned lock-free."""

    snapshot: _FrozenTimingProfileMapping
    warning_generation: int
    warning_aliases: frozenset[str]


@dataclass(frozen=True, slots=True)
class TimingWindow:
    """A sampled timing window for a named causal relationship."""

    min_ms: int
    max_ms: int
    position: Literal["before", "after"]
    relationship_class: str = ""


@dataclass(frozen=True, slots=True)
class StartupModuleObservationTiming:
    """Source-visible Windows process initialization timing parameters."""

    initial_delay_min_us: int
    initial_delay_max_us: int
    inter_load_gap_median_us: int
    inter_load_gap_sigma: float
    inter_load_gap_min_us: int
    inter_load_gap_max_us: int


@dataclass(frozen=True, slots=True)
class NetworkSensorObservationTiming:
    """Per-sensor clock, route, jitter, and capture-loss bounds."""

    profile_name: str
    clock_offset_min_us: int
    clock_offset_max_us: int
    clock_drift_min_ppm: int
    clock_drift_max_ppm: int
    route_delay_min_us: int
    route_delay_max_us: int
    event_jitter_min_us: int
    event_jitter_max_us: int
    capture_loss_probability: float
    capture_loss_min_fraction: float
    capture_loss_max_fraction: float
    capture_loss_max_missed_bytes: int

    @property
    def clock_skew_min_us(self) -> int:
        """Compatibility alias for the former clock-skew field."""

        return self.clock_offset_min_us

    @property
    def clock_skew_max_us(self) -> int:
        """Compatibility alias for the former clock-skew field."""

        return self.clock_offset_max_us

    @property
    def path_delay_min_us(self) -> int:
        """Compatibility alias for the former path-delay field."""

        return self.route_delay_min_us

    @property
    def path_delay_max_us(self) -> int:
        """Compatibility alias for the former path-delay field."""

        return self.route_delay_max_us


@dataclass(frozen=True, slots=True)
class EndpointClockTiming:
    """Per-host endpoint clock offset and drift bounds."""

    host_offset_min_ms: int
    host_offset_max_ms: int
    host_drift_min_ppm: int
    host_drift_max_ppm: int


@dataclass(frozen=True, slots=True)
class FirewallObservationTiming:
    """Source-native connection-table timers for one firewall sensor."""

    policy_name: str
    tcp_embryonic_timeout_seconds: int
    tcp_idle_timeout_seconds: int


@dataclass(frozen=True, slots=True)
class SysmonEnvelopeTiming:
    """Provider-envelope latency parameters for one Sysmon event family."""

    median_us: int
    sigma: float
    min_us: int
    max_us: int
    tail_probability: float
    tail_min_us: int
    tail_max_us: int


@dataclass(frozen=True, slots=True)
class SshAuthenticationTiming:
    """Contextual SSH authentication-phase timing parameters."""

    fast_probability: float
    fast_min_ms: int
    fast_max_ms: int
    typical_min_ms: int
    typical_max_ms: int
    tail_probability: float
    tail_min_ms: int
    tail_max_ms: int
    cache_miss_probability: float
    cache_miss_min_ms: int
    cache_miss_max_ms: int


@dataclass(frozen=True, slots=True)
class SshAcceptedAuthenticationTiming:
    """Audited component gaps composing one SSH authentication acceptance."""

    phase_ms: float
    cache_delay_ms: float
    route_delay_ms: float
    receiver_delay_ms: float
    key_penalty_ms: float

    @property
    def total_ms(self) -> float:
        """Return the complete accepted-authentication gap."""

        return (
            self.phase_ms
            + self.cache_delay_ms
            + self.route_delay_ms
            + self.receiver_delay_ms
            + self.key_penalty_ms
        )


@dataclass(frozen=True, slots=True)
class InclusiveMillisecondTimingSupport:
    """One normalized union of inclusive millisecond timing intervals."""

    intervals: tuple[tuple[float, float], ...]

    def __post_init__(self) -> None:
        """Validate, sort, and merge overlapping or adjacent intervals."""

        if not self.intervals:
            raise ValueError("millisecond timing support must contain at least one interval")
        merged: list[tuple[float, float]] = []
        for minimum, maximum in sorted(self.intervals):
            if maximum < minimum:
                raise ValueError("millisecond timing support maximum must not precede minimum")
            if merged and minimum <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], maximum))
            else:
                merged.append((minimum, maximum))
        object.__setattr__(self, "intervals", tuple(merged))

    @property
    def bounds(self) -> tuple[float, float]:
        """Return the minimum and maximum across the exact interval union."""

        return self.intervals[0][0], self.intervals[-1][1]

    def __contains__(self, value: object) -> bool:
        """Return whether a millisecond value belongs to any exact support interval."""

        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and any(minimum <= value <= maximum for minimum, maximum in self.intervals)
        )

    def __add__(
        self,
        other: InclusiveMillisecondTimingSupport,
    ) -> InclusiveMillisecondTimingSupport:
        """Return the exact Minkowski sum of two millisecond interval unions."""

        return InclusiveMillisecondTimingSupport(
            tuple(
                (left_min + right_min, left_max + right_max)
                for left_min, left_max in self.intervals
                for right_min, right_max in other.intervals
            )
        )


def _millisecond_support(
    *intervals: tuple[float, float],
) -> InclusiveMillisecondTimingSupport:
    """Construct one normalized exact millisecond timing support."""

    return InclusiveMillisecondTimingSupport(intervals)


@dataclass(frozen=True, slots=True)
class SshAcceptedAuthenticationTimingSupport:
    """Exact millisecond supports for accepted-authentication components."""

    phase_ms: InclusiveMillisecondTimingSupport
    cache_delay_ms: InclusiveMillisecondTimingSupport
    route_delay_ms: InclusiveMillisecondTimingSupport
    receiver_delay_ms: InclusiveMillisecondTimingSupport
    key_penalty_ms: InclusiveMillisecondTimingSupport

    @property
    def total_ms(self) -> InclusiveMillisecondTimingSupport:
        """Return the exact support of the component sum."""

        supports = (
            self.phase_ms,
            self.cache_delay_ms,
            self.route_delay_ms,
            self.receiver_delay_ms,
            self.key_penalty_ms,
        )
        total = _millisecond_support((0, 0))
        for support in supports:
            total += support
        return total


@dataclass(frozen=True, slots=True)
class SshAuthenticationTimingPlan:
    """One complete ordered SSH authentication lifecycle timing plan."""

    connection_gap_ms: float
    accepted: SshAcceptedAuthenticationTiming
    pam_gap_ms: float
    logind_gap_ms: float

    @property
    def accepted_gap_ms(self) -> float:
        """Return the composed gap between connection and accepted evidence."""

        return self.accepted.total_ms

    @property
    def lifecycle_gap_ms(self) -> float:
        """Return the complete transport-to-logind phase-gap sum."""

        return self.connection_gap_ms + self.accepted_gap_ms + self.pam_gap_ms + self.logind_gap_ms


@dataclass(frozen=True, slots=True)
class SshAuthenticationTimingSupport:
    """Exact millisecond supports for one full SSH authentication plan."""

    connection_gap_ms: InclusiveMillisecondTimingSupport
    accepted: SshAcceptedAuthenticationTimingSupport
    pam_gap_ms: InclusiveMillisecondTimingSupport
    logind_gap_ms: InclusiveMillisecondTimingSupport

    @property
    def accepted_gap_ms(self) -> InclusiveMillisecondTimingSupport:
        """Return the exact support of the accepted-authentication sum."""

        return self.accepted.total_ms

    @property
    def lifecycle_gap_ms(self) -> InclusiveMillisecondTimingSupport:
        """Return the exact support of every ordered phase gap."""

        supports = (
            self.connection_gap_ms,
            self.accepted_gap_ms,
            self.pam_gap_ms,
            self.logind_gap_ms,
        )
        total = _millisecond_support((0, 0))
        for support in supports:
            total += support
        return total


class _SshTimingRuntime(Protocol):
    """Sampling surface shared by canonical and prepared timing runtimes."""

    @property
    def sampler(self) -> TimingSampler:
        """Return the runtime-owned stateless audited sampler."""


_SSH_CONNECTION_GAP_MS = (35, 160)
_SSH_PAM_GAP_MS = (45, 180)
_SSH_LOGIND_GAP_MS = (420, 760)


def _timing_profile_container_kind(
    value: Any,
) -> Literal["dict", "list", "tuple", "set", "frozenset"] | None:
    """Return the exact supported container kind without trusting subclasses."""

    value_type = type(value)
    if value_type is dict or value_type is _FrozenTimingProfileMapping:
        return "dict"
    if value_type is list or value_type is _FrozenTimingProfileList:
        return "list"
    if value_type is tuple:
        return "tuple"
    if value_type is set:
        return "set"
    if value_type is frozenset:
        return "frozenset"
    return None


def _timing_profile_mapping_items(value: Any) -> tuple[tuple[str, Any], ...]:
    """Return exact mapping pairs without invoking user-defined callbacks."""

    if type(value) is _FrozenTimingProfileMapping:
        return tuple(tuple.__iter__(value))
    return tuple(dict.items(value))


def _timing_profile_container_values(value: Any, kind: str) -> tuple[Any, ...]:
    """Return bounded child values for one already-admitted container."""

    if kind == "dict":
        return tuple(item for _key, item in _timing_profile_mapping_items(value))
    return tuple(value)


def _capture_timing_profile_container_items(
    value: Any,
    kind: Literal["dict", "list", "tuple", "set", "frozenset"],
    *,
    member_limit: int,
) -> tuple[Any, ...]:
    """Capture one exact container once, bounded to one over the member limit.

    The exact builtin entry points avoid subclass callbacks. Returning at most
    ``member_limit + 1`` entries bounds the temporary capture even if another
    thread grows a mutable container between admission and iteration.
    """

    capture_limit = member_limit + 1
    try:
        if kind == "dict":
            if type(value) is _FrozenTimingProfileMapping:
                return tuple(islice(tuple.__iter__(value), capture_limit))
            return tuple(islice(dict.items(value), capture_limit))
        if kind == "list":
            if type(value) is _FrozenTimingProfileList:
                return tuple(islice(tuple.__iter__(value), capture_limit))
            return tuple(list.__getitem__(value, slice(0, capture_limit)))
        if kind == "tuple":
            return tuple(islice(tuple.__iter__(value), capture_limit))
        if kind == "set":
            return tuple(islice(set.__iter__(value), capture_limit))
        return tuple(islice(frozenset.__iter__(value), capture_limit))
    except RuntimeError as exc:
        raise TimingProfileError(
            "timing profile container changed while its snapshot was captured"
        ) from exc


def _timing_profile_scalar_size(value: Any, limits: _TimingProfileGraphLimits) -> int:
    """Return a conservative encoded size for one exact supported scalar."""

    value_type = type(value)
    if value is None:
        size = 1
    elif value_type is bool:
        size = 1
    elif value_type is int:
        size = max(1, (abs(value).bit_length() + 7) // 8)
    elif value_type is float:
        size = 8
    elif value_type is str:
        if len(value) > limits.max_scalar_bytes:
            raise TimingProfileError(
                "timing profile scalar exceeds limit "
                f"{limits.max_scalar_bytes} bytes before UTF-8 encoding"
            )
        size = len(value.encode("utf-8"))
    elif value_type is bytes:
        size = len(value)
    else:
        raise TimingProfileError("timing profile graph contains an unsupported scalar type")
    if size > limits.max_scalar_bytes:
        raise TimingProfileError(
            f"timing profile scalar is {size} bytes; limit is {limits.max_scalar_bytes}"
        )
    return size


def _preflight_timing_profile_graph(
    value: Any,
    *,
    limits: _TimingProfileGraphLimits | None = None,
) -> _TimingProfileGraphStats:
    """Validate and budget an alias-aware graph before copying or freezing it.

    Identity-distinct containers are expanded exactly once. Every outgoing edge
    is still charged as a reference, scalar leaves are charged where referenced,
    and a back-edge to an active container is rejected as a YAML alias cycle.
    """

    effective_limits = limits or _TIMING_PROFILE_GRAPH_LIMITS
    active: set[int] = set()
    heights: dict[int, int] = {}
    unique_nodes = 0
    references = 0
    scalar_bytes = 0
    aggregate_bytes = 0
    max_depth_seen = 0

    def consume_unique_node() -> None:
        nonlocal unique_nodes
        unique_nodes += 1
        if unique_nodes > effective_limits.max_unique_nodes:
            raise TimingProfileError(
                "timing profile unique node count exceeds limit "
                f"{effective_limits.max_unique_nodes}"
            )

    def consume_aggregate(size: int) -> None:
        nonlocal aggregate_bytes
        aggregate_bytes += size
        if aggregate_bytes > effective_limits.max_aggregate_bytes:
            raise TimingProfileError(
                "timing profile aggregate bytes exceed limit "
                f"{effective_limits.max_aggregate_bytes}"
            )

    def consume_scalar(item: Any, *, depth: int) -> None:
        nonlocal scalar_bytes, max_depth_seen
        if depth > effective_limits.max_depth:
            raise TimingProfileError(
                f"timing profile graph depth exceeds limit {effective_limits.max_depth}"
            )
        max_depth_seen = max(max_depth_seen, depth)
        consume_unique_node()
        size = _timing_profile_scalar_size(item, effective_limits)
        scalar_bytes += size
        consume_aggregate(size)

    stack: list[tuple[bool, Any, int]] = [(False, value, 0)]
    while stack:
        leaving, node, depth = stack.pop()
        kind = _timing_profile_container_kind(node)

        if leaving:
            if kind is None:  # pragma: no cover - frames are internal
                raise RuntimeError("timing profile preflight exit frame is not a container")
            node_height = 0
            if kind == "dict" and len(node):
                node_height = 1
            for child in _timing_profile_container_values(node, kind):
                child_kind = _timing_profile_container_kind(child)
                child_height = 0 if child_kind is None else heights[id(child)]
                node_height = max(node_height, child_height + 1)
            active.remove(id(node))
            heights[id(node)] = node_height
            continue

        if depth > effective_limits.max_depth:
            raise TimingProfileError(
                f"timing profile graph depth exceeds limit {effective_limits.max_depth}"
            )
        max_depth_seen = max(max_depth_seen, depth)
        if kind is None:
            consume_scalar(node, depth=depth)
            continue

        node_id = id(node)
        if node_id in active:
            raise TimingProfileError(
                "recursive YAML alias graph is not supported in timing profiles"
            )
        if node_id in heights:
            reachable_depth = depth + heights[node_id]
            if reachable_depth > effective_limits.max_depth:
                raise TimingProfileError(
                    f"timing profile graph depth exceeds limit {effective_limits.max_depth}"
                )
            max_depth_seen = max(max_depth_seen, reachable_depth)
            continue

        member_count = len(node)
        if member_count > effective_limits.max_container_members:
            raise TimingProfileError(
                f"timing profile container has {member_count} members; limit is "
                f"{effective_limits.max_container_members}"
            )
        consume_unique_node()
        consume_aggregate(_TIMING_PROFILE_CONTAINER_OVERHEAD_BYTES)

        outgoing_references = member_count * 2 if kind == "dict" else member_count
        references += outgoing_references
        if references > effective_limits.max_references:
            raise TimingProfileError(
                f"timing profile reference count exceeds limit {effective_limits.max_references}"
            )
        consume_aggregate(outgoing_references * _TIMING_PROFILE_REFERENCE_OVERHEAD_BYTES)

        if kind == "dict":
            for key, _item in _timing_profile_mapping_items(node):
                if type(key) is not str:
                    raise TimingProfileError("timing profile mapping keys must be strings")
                consume_scalar(key, depth=depth + 1)

        active.add(node_id)
        stack.append((True, node, depth))
        children = _timing_profile_container_values(node, kind)
        stack.extend((False, child, depth + 1) for child in reversed(children))

    return _TimingProfileGraphStats(
        unique_nodes=unique_nodes,
        references=references,
        scalar_bytes=scalar_bytes,
        aggregate_bytes=aggregate_bytes,
        max_depth=max_depth_seen,
    )


def _capture_timing_profile_snapshot(
    value: Any,
    *,
    limits: _TimingProfileGraphLimits | None = None,
) -> Any:
    """Fuse bounded admission and immutable capture of one timing graph.

    Each exact container is read through a callback-free builtin entry point at
    most once. All validation, cycle detection, depth accounting, and output
    construction then use that captured view, never the caller-owned graph.
    """

    effective_limits = limits or _TIMING_PROFILE_GRAPH_LIMITS
    captured: dict[
        int,
        tuple[
            Literal["dict", "list", "tuple", "set", "frozenset"],
            tuple[Any, ...],
        ],
    ] = {}
    frozen: dict[int, Any] = {}
    heights: dict[int, int] = {}
    active: set[int] = set()
    unique_nodes = 0
    references = 0
    aggregate_bytes = 0

    def consume_unique_node() -> None:
        nonlocal unique_nodes
        unique_nodes += 1
        if unique_nodes > effective_limits.max_unique_nodes:
            raise TimingProfileError(
                "timing profile unique node count exceeds limit "
                f"{effective_limits.max_unique_nodes}"
            )

    def consume_aggregate(size: int) -> None:
        nonlocal aggregate_bytes
        aggregate_bytes += size
        if aggregate_bytes > effective_limits.max_aggregate_bytes:
            raise TimingProfileError(
                "timing profile aggregate bytes exceed limit "
                f"{effective_limits.max_aggregate_bytes}"
            )

    def consume_scalar(item: Any, *, depth: int) -> None:
        if depth > effective_limits.max_depth:
            raise TimingProfileError(
                f"timing profile graph depth exceeds limit {effective_limits.max_depth}"
            )
        consume_unique_node()
        consume_aggregate(_timing_profile_scalar_size(item, effective_limits))

    root_kind = _timing_profile_container_kind(value)
    if root_kind is None:
        consume_scalar(value, depth=0)
        return value

    stack: list[tuple[bool, Any, int]] = [(False, value, 0)]
    while stack:
        leaving, node, depth = stack.pop()
        kind = _timing_profile_container_kind(node)
        if kind is None:
            consume_scalar(node, depth=depth)
            continue
        node_id = id(node)

        if leaving:
            captured_kind, items = captured[node_id]

            def transformed(child: Any) -> Any:
                child_kind = _timing_profile_container_kind(child)
                return child if child_kind is None else frozen[id(child)]

            if captured_kind == "dict":
                private: dict[str, Any] = {}
                node_height = 1 if items else 0
                for key, child in items:
                    dict.__setitem__(private, key, transformed(child))
                    child_kind = _timing_profile_container_kind(child)
                    child_height = 0 if child_kind is None else heights[id(child)]
                    node_height = max(node_height, child_height + 1)
                frozen[node_id] = _FrozenTimingProfileMapping(private)
            else:
                transformed_items = tuple(transformed(child) for child in items)
                node_height = 0
                for child in items:
                    child_kind = _timing_profile_container_kind(child)
                    child_height = 0 if child_kind is None else heights[id(child)]
                    node_height = max(node_height, child_height + 1)
                if captured_kind == "list":
                    frozen[node_id] = _FrozenTimingProfileList(transformed_items)
                elif captured_kind == "tuple":
                    frozen[node_id] = transformed_items
                else:
                    frozen[node_id] = frozenset(transformed_items)
            active.remove(node_id)
            heights[node_id] = node_height
            continue

        if depth > effective_limits.max_depth:
            raise TimingProfileError(
                f"timing profile graph depth exceeds limit {effective_limits.max_depth}"
            )
        if node_id in active:
            raise TimingProfileError(
                "recursive YAML alias graph is not supported in timing profiles"
            )
        if node_id in frozen:
            if depth + heights[node_id] > effective_limits.max_depth:
                raise TimingProfileError(
                    f"timing profile graph depth exceeds limit {effective_limits.max_depth}"
                )
            continue

        items = _capture_timing_profile_container_items(
            node,
            kind,
            member_limit=effective_limits.max_container_members,
        )
        member_count = len(items)
        if member_count > effective_limits.max_container_members:
            raise TimingProfileError(
                f"timing profile container has {member_count} members; limit is "
                f"{effective_limits.max_container_members}"
            )
        consume_unique_node()
        consume_aggregate(_TIMING_PROFILE_CONTAINER_OVERHEAD_BYTES)

        outgoing_references = member_count * 2 if kind == "dict" else member_count
        references += outgoing_references
        if references > effective_limits.max_references:
            raise TimingProfileError(
                f"timing profile reference count exceeds limit {effective_limits.max_references}"
            )
        consume_aggregate(outgoing_references * _TIMING_PROFILE_REFERENCE_OVERHEAD_BYTES)

        if kind == "dict":
            for pair in items:
                if type(pair) is not tuple or len(pair) != 2:  # pragma: no cover
                    raise RuntimeError("timing profile mapping capture is malformed")
                key, _child = pair
                if type(key) is not str:
                    raise TimingProfileError("timing profile mapping keys must be strings")
                consume_scalar(key, depth=depth + 1)
            children = tuple(child for _key, child in items)
        else:
            children = items

        captured[node_id] = (kind, items)
        active.add(node_id)
        stack.append((True, node, depth))
        stack.extend((False, child, depth + 1) for child in reversed(children))

    return frozen[id(value)]


def _detached_timing_profile_copy(
    value: Any,
    *,
    limits: _TimingProfileGraphLimits | None = None,
) -> Any:
    """Return a mutable copy of one fused, callback-free immutable capture."""

    return deepcopy(_capture_timing_profile_snapshot(value, limits=limits))


def _freeze_timing_profile_value(
    value: Any,
    *,
    limits: _TimingProfileGraphLimits | None = None,
) -> Any:
    """Return a detached immutable snapshot through fused graph admission."""

    return _capture_timing_profile_snapshot(value, limits=limits)


class _TimingProfileComparison:
    """Memoize and bound structural hashes and exact node-pair comparisons."""

    __slots__ = (
        "_digest_aggregate_bytes",
        "_digest_references",
        "_digest_unique_nodes",
        "_digests",
        "_limits",
        "_pair_aggregate_bytes",
        "_pair_references",
        "_pair_visits",
    )

    def __init__(self, limits: _TimingProfileGraphLimits) -> None:
        self._limits = limits
        self._digests: dict[int, int] = {}
        self._digest_unique_nodes = 0
        self._digest_references = 0
        self._digest_aggregate_bytes = 0
        self._pair_visits = 0
        self._pair_references = 0
        self._pair_aggregate_bytes = 0

    def _charge_digest_scalar(self, value: Any) -> None:
        self._digest_unique_nodes += 1
        if self._digest_unique_nodes > self._limits.max_unique_nodes:
            raise TimingProfileError(
                "timing profile comparison node count exceeds limit "
                f"{self._limits.max_unique_nodes}"
            )
        self._digest_aggregate_bytes += _timing_profile_scalar_size(value, self._limits)
        if self._digest_aggregate_bytes > self._limits.max_aggregate_bytes:
            raise TimingProfileError(
                f"timing profile comparison bytes exceed limit {self._limits.max_aggregate_bytes}"
            )

    def _charge_digest_container(self, *, kind: str, members: int) -> None:
        if members > self._limits.max_container_members:
            raise TimingProfileError(
                f"timing profile comparison container has {members} members; limit is "
                f"{self._limits.max_container_members}"
            )
        self._digest_unique_nodes += 1
        if self._digest_unique_nodes > self._limits.max_unique_nodes:
            raise TimingProfileError(
                "timing profile comparison node count exceeds limit "
                f"{self._limits.max_unique_nodes}"
            )
        outgoing = members * 2 if kind == "dict" else members
        self._digest_references += outgoing
        if self._digest_references > self._limits.max_references:
            raise TimingProfileError(
                "timing profile comparison reference count exceeds limit "
                f"{self._limits.max_references}"
            )
        self._digest_aggregate_bytes += (
            _TIMING_PROFILE_CONTAINER_OVERHEAD_BYTES
            + _TIMING_PROFILE_MERGE_MEMO_ENTRY_BYTES
            + outgoing * _TIMING_PROFILE_REFERENCE_OVERHEAD_BYTES
        )
        if self._digest_aggregate_bytes > self._limits.max_aggregate_bytes:
            raise TimingProfileError(
                f"timing profile comparison bytes exceed limit {self._limits.max_aggregate_bytes}"
            )

    def _charge_pair(self, *, kind: str, members: int) -> None:
        self._pair_visits += 1
        if self._pair_visits > self._limits.max_unique_nodes:
            raise TimingProfileError(
                "timing profile comparison pair count exceeds limit "
                f"{self._limits.max_unique_nodes}"
            )
        outgoing = members * 2 if kind == "dict" else members
        self._pair_references += outgoing
        if self._pair_references > self._limits.max_references:
            raise TimingProfileError(
                "timing profile comparison pair references exceed limit "
                f"{self._limits.max_references}"
            )
        self._pair_aggregate_bytes += (
            _TIMING_PROFILE_MERGE_MEMO_ENTRY_BYTES
            + outgoing * _TIMING_PROFILE_REFERENCE_OVERHEAD_BYTES
        )
        if self._pair_aggregate_bytes > self._limits.max_aggregate_bytes:
            raise TimingProfileError(
                "timing profile comparison pair bytes exceed limit "
                f"{self._limits.max_aggregate_bytes}"
            )

    @staticmethod
    def _scalar_digest(value: Any) -> int:
        """Hash exact supported scalars with Python-compatible numeric equality."""

        if type(value) in {bool, int, float}:
            return hash(("number", value))
        if value is None:
            return hash(("none",))
        if type(value) is str:
            return hash(("string", value))
        if type(value) is bytes:
            return hash(("bytes", value))
        raise TimingProfileError("timing profile graph contains an unsupported scalar type")

    def digest(self, value: Any) -> int:
        """Return an alias-aware structural digest with one visit per container."""

        root_kind = _timing_profile_container_kind(value)
        if root_kind is None:
            self._charge_digest_scalar(value)
            return self._scalar_digest(value)

        active: set[int] = set()
        captured: dict[int, tuple[str, tuple[Any, ...]]] = {}
        stack: list[tuple[bool, Any]] = [(False, value)]
        while stack:
            leaving, node = stack.pop()
            kind = _timing_profile_container_kind(node)
            if kind is None:
                continue
            node_id = id(node)
            if leaving:
                captured_kind, items = captured[node_id]
                if captured_kind == "dict":
                    digest = hash(
                        (
                            "dict",
                            frozenset((key, self.digest(child)) for key, child in items),
                        )
                    )
                else:
                    child_digests = tuple(self.digest(child) for child in items)
                    if captured_kind == "list":
                        digest = hash(("list", child_digests))
                    elif captured_kind == "tuple":
                        digest = hash(("tuple", child_digests))
                    else:
                        digest = hash(("set", frozenset(child_digests)))
                self._digests[node_id] = digest
                active.remove(node_id)
                continue
            if node_id in self._digests:
                continue
            if node_id in active:
                raise TimingProfileError(
                    "recursive YAML alias graph is not supported in timing profiles"
                )
            member_count = len(node)
            self._charge_digest_container(kind=kind, members=member_count)
            if kind == "dict":
                items = _timing_profile_mapping_items(node)
                for key, _child in items:
                    if type(key) is not str:
                        raise TimingProfileError("timing profile mapping keys must be strings")
                    self._charge_digest_scalar(key)
                children = tuple(child for _key, child in items)
            else:
                items = _timing_profile_container_values(node, kind)
                children = items
            captured[node_id] = (kind, items)
            active.add(node_id)
            stack.append((True, node))
            stack.extend(
                (False, child)
                for child in reversed(children)
                if _timing_profile_container_kind(child) is not None
                and id(child) not in self._digests
            )
        return self._digests[id(value)]

    @staticmethod
    def _compatible_kinds(left_kind: str, right_kind: str) -> bool:
        """Return whether two container spellings share equality semantics."""

        if left_kind == right_kind:
            return True
        return {left_kind, right_kind} == {"set", "frozenset"}

    def equal(self, left: Any, right: Any) -> bool:
        """Compare two graphs in bounded O(identity-distinct node pairs + edges)."""

        if left is right:
            return True
        if self.digest(left) != self.digest(right):
            return False

        seen_pairs: set[tuple[str, int, int]] = set()
        stack: list[tuple[Any, Any]] = [(left, right)]
        while stack:
            lower, higher = stack.pop()
            if lower is higher:
                continue
            lower_kind = _timing_profile_container_kind(lower)
            higher_kind = _timing_profile_container_kind(higher)
            if lower_kind is None or higher_kind is None:
                if lower_kind is not None or higher_kind is not None or lower != higher:
                    return False
                continue
            if not self._compatible_kinds(lower_kind, higher_kind):
                return False
            pair_kind = "set" if lower_kind in {"set", "frozenset"} else lower_kind
            pair_key = (pair_kind, id(lower), id(higher))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            lower_member_count = len(lower)
            higher_member_count = len(higher)
            if lower_member_count != higher_member_count:
                return False
            self._charge_pair(kind=pair_kind, members=lower_member_count)
            if pair_kind == "dict":
                higher_pairs = _timing_profile_mapping_items(higher)
                higher_by_key = {key: child for key, child in higher_pairs}
                if len(higher_by_key) != len(higher_pairs):  # pragma: no cover
                    raise RuntimeError("timing profile mapping contains duplicate keys")
                for key, child in _timing_profile_mapping_items(lower):
                    if key not in higher_by_key:
                        return False
                    stack.append((child, higher_by_key[key]))
                continue
            lower_items = _timing_profile_container_values(lower, lower_kind)
            higher_items = _timing_profile_container_values(higher, higher_kind)
            if pair_kind in {"list", "tuple"}:
                stack.extend(zip(lower_items, higher_items, strict=True))
                continue

            higher_buckets: dict[int, list[Any]] = {}
            for item in higher_items:
                higher_buckets.setdefault(self.digest(item), []).append(item)
            for item in lower_items:
                bucket = higher_buckets.get(self.digest(item), [])
                match_index = next(
                    (
                        index
                        for index, candidate in enumerate(bucket)
                        if self.equal(item, candidate)
                    ),
                    None,
                )
                if match_index is None:
                    return False
                bucket.pop(match_index)
        return True


def _timing_profile_values_equal(
    left: Any,
    right: Any,
    *,
    limits: _TimingProfileGraphLimits | None = None,
    comparison: _TimingProfileComparison | None = None,
) -> bool:
    """Return bounded structural equality with optional shared memo state."""

    effective_limits = limits or _TIMING_PROFILE_GRAPH_LIMITS
    active_comparison = comparison or _TimingProfileComparison(effective_limits)
    return active_comparison.equal(left, right)


@dataclass(slots=True)
class _TimingProfileMergeBudget:
    """Bound live normalized inputs plus every merge-owned container before allocation."""

    limits: _TimingProfileGraphLimits
    unique_nodes: int
    references: int
    aggregate_bytes: int

    @classmethod
    def from_inputs(
        cls,
        default_stats: _TimingProfileGraphStats,
        overlay_stats: _TimingProfileGraphStats,
        *,
        limits: _TimingProfileGraphLimits,
    ) -> _TimingProfileMergeBudget:
        """Charge both admitted input graphs before constructing merge output."""

        unique_nodes = default_stats.unique_nodes + overlay_stats.unique_nodes
        references = default_stats.references + overlay_stats.references
        aggregate_bytes = default_stats.aggregate_bytes + overlay_stats.aggregate_bytes
        if unique_nodes > limits.max_unique_nodes:
            raise TimingProfileError(
                f"timing profile merge input node count exceeds limit {limits.max_unique_nodes}"
            )
        if references > limits.max_references:
            raise TimingProfileError(
                f"timing profile merge input reference count exceeds limit {limits.max_references}"
            )
        if aggregate_bytes > limits.max_aggregate_bytes:
            raise TimingProfileError(
                f"timing profile merge input bytes exceed limit {limits.max_aggregate_bytes}"
            )
        return cls(
            limits=limits,
            unique_nodes=unique_nodes,
            references=references,
            aggregate_bytes=aggregate_bytes,
        )

    def charge_container(self, *, kind: Literal["dict", "list"], members: int) -> None:
        """Charge one memoized output container before allocating it."""

        if members > self.limits.max_container_members:
            raise TimingProfileError(
                f"timing profile merged container has {members} members; limit is "
                f"{self.limits.max_container_members}"
            )
        outgoing_references = members * 2 if kind == "dict" else members
        unique_nodes = self.unique_nodes + 1
        references = self.references + outgoing_references
        aggregate_bytes = (
            self.aggregate_bytes
            + _TIMING_PROFILE_CONTAINER_OVERHEAD_BYTES
            + _TIMING_PROFILE_MERGE_MEMO_ENTRY_BYTES
            + outgoing_references * _TIMING_PROFILE_REFERENCE_OVERHEAD_BYTES
        )
        if unique_nodes > self.limits.max_unique_nodes:
            raise TimingProfileError(
                "timing profile merge output node count exceeds limit "
                f"{self.limits.max_unique_nodes}"
            )
        if references > self.limits.max_references:
            raise TimingProfileError(
                "timing profile merge output reference count exceeds limit "
                f"{self.limits.max_references}"
            )
        if aggregate_bytes > self.limits.max_aggregate_bytes:
            raise TimingProfileError(
                f"timing profile merge output bytes exceed limit {self.limits.max_aggregate_bytes}"
            )
        self.unique_nodes = unique_nodes
        self.references = references
        self.aggregate_bytes = aggregate_bytes


def _merged_timing_profile_member_count(default: dict[str, Any], overlay: dict[str, Any]) -> int:
    """Return mapping-union cardinality without constructing the union."""

    return len(default) + sum(
        1 for key in dict.keys(overlay) if not dict.__contains__(default, key)
    )


def _merge_timing_profile_dicts(
    default: dict[str, Any],
    overlay: dict[str, Any],
    *,
    limits: _TimingProfileGraphLimits | None = None,
    diagnostics: list[str] | None = None,
) -> dict[str, Any]:
    """Iteratively deep-merge exact builtins with pair memoization and precharging."""

    if type(default) is not dict or type(overlay) is not dict:
        raise TimingProfileError("timing profile merge inputs must be mappings")
    effective_limits = limits or _TIMING_PROFILE_GRAPH_LIMITS
    default_stats = _preflight_timing_profile_graph(default, limits=effective_limits)
    overlay_stats = _preflight_timing_profile_graph(overlay, limits=effective_limits)
    budget = _TimingProfileMergeBudget.from_inputs(
        default_stats,
        overlay_stats,
        limits=effective_limits,
    )
    comparison = _TimingProfileComparison(effective_limits)
    pair_memo: dict[tuple[Literal["dict", "list"], int, int], Any] = {}

    def allocate_dict_pair(
        lower: dict[str, Any],
        higher: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        pair_key = ("dict", id(lower), id(higher))
        if pair_key in pair_memo:
            return pair_memo[pair_key], False
        members = _merged_timing_profile_member_count(lower, higher)
        budget.charge_container(kind="dict", members=members)
        merged = dict(lower)
        pair_memo[pair_key] = merged
        return merged, True

    def allocate_list_pair(lower: list[Any], higher: list[Any]) -> list[Any]:
        pair_key = ("list", id(lower), id(higher))
        if pair_key in pair_memo:
            return pair_memo[pair_key]
        budget.charge_container(kind="list", members=len(lower) + len(higher))
        merged = list(lower)
        merged.extend(higher)
        pair_memo[pair_key] = merged
        return merged

    root, _created = allocate_dict_pair(default, overlay)
    stack: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = [(default, overlay, root)]
    while stack:
        lower, higher, merged = stack.pop()
        for key, higher_value in _timing_profile_mapping_items(higher):
            if not dict.__contains__(lower, key):
                dict.__setitem__(merged, key, higher_value)
                continue
            lower_value = dict.__getitem__(lower, key)
            lower_type = type(lower_value)
            higher_type = type(higher_value)
            if lower_type is dict and higher_type is dict:
                child, created = allocate_dict_pair(lower_value, higher_value)
                dict.__setitem__(merged, key, child)
                if created:
                    stack.append((lower_value, higher_value, child))
                continue
            if lower_type is list and higher_type is list:
                dict.__setitem__(merged, key, allocate_list_pair(lower_value, higher_value))
                continue
            if lower_type is dict:
                if diagnostics is not None:
                    diagnostics.append(
                        "Config overlay: timing profile type mismatch; expected mapping — skipping"
                    )
                continue
            if lower_type is list:
                if diagnostics is not None:
                    diagnostics.append(
                        "Config overlay: timing profile type mismatch; expected list — skipping"
                    )
                continue
            if not _timing_profile_values_equal(
                lower_value,
                higher_value,
                limits=effective_limits,
                comparison=comparison,
            ):
                if diagnostics is not None:
                    diagnostics.append("Config overlay: replacing timing profile value")
            dict.__setitem__(merged, key, higher_value)

    _preflight_timing_profile_graph(root, limits=effective_limits)
    return root


def _normalize_timing_profile_compatibility(
    data: dict[str, Any],
) -> tuple[dict[str, Any], frozenset[str]]:
    """Copy and normalize supported sensor aliases without publishing side effects."""

    normalized = _detached_timing_profile_copy(data)
    if type(normalized) is not dict:
        raise TimingProfileError("timing profile root must be a mapping")
    observation = normalized.get("network_sensor_observation")
    if type(observation) is not dict:
        return normalized, frozenset()
    profiles = observation.get("profiles")
    if type(profiles) is not dict:
        return normalized, frozenset()

    comparison = _TimingProfileComparison(_TIMING_PROFILE_GRAPH_LIMITS)

    conflicts = [
        (
            "timing_profiles.network_sensor_observation.profiles"
            f"[{profile_name!r}] defines conflicting {legacy_name} and {canonical_name} values"
        )
        for profile_name, profile in profiles.items()
        if type(profile) is dict
        for legacy_name, canonical_name in _NETWORK_SENSOR_PROFILE_ALIASES
        if (
            legacy_name in profile
            and canonical_name in profile
            and not _timing_profile_values_equal(
                profile[legacy_name],
                profile[canonical_name],
                comparison=comparison,
            )
        )
    ]
    if conflicts:
        raise TimingProfileError("; ".join(conflicts))

    encountered_aliases: set[str] = set()
    for profile in profiles.values():
        if type(profile) is not dict:
            continue
        for legacy_name, canonical_name in _NETWORK_SENSOR_PROFILE_ALIASES:
            if legacy_name not in profile:
                continue
            legacy_value = profile.pop(legacy_name)
            if canonical_name not in profile:
                profile[canonical_name] = legacy_value
            encountered_aliases.add(legacy_name)
    return normalized, frozenset(encountered_aliases)


def _load_normalized_timing_profiles(
    _require_binding: Callable[[], None] = _require_timing_profile_runtime_bindings,
) -> tuple[
    dict[str, Any],
    frozenset[str],
    tuple[str, ...],
]:
    """Load all overlay layers while normalizing each before canonical merge."""

    encountered_aliases: set[str] = set()
    diagnostics: list[str] = []

    def merge_overlay(
        default: dict[str, Any],
        overlay: dict[str, Any],
    ) -> dict[str, Any]:
        normalized_default, default_aliases = _normalize_timing_profile_compatibility(default)
        normalized_overlay, overlay_aliases = _normalize_timing_profile_compatibility(overlay)
        encountered_aliases.update(default_aliases)
        encountered_aliases.update(overlay_aliases)
        merged = _merge_timing_profile_dicts(
            normalized_default,
            normalized_overlay,
            diagnostics=diagnostics,
        )
        normalized_merged, merged_aliases = _normalize_timing_profile_compatibility(merged)
        encountered_aliases.update(merged_aliases)
        return normalized_merged

    _require_binding()
    try:
        merged = load_with_overlay(
            _CONFIG_PATH,
            "activity/timing_profiles.yaml",
            merge_overlay,
        )
    except BaseException:
        _require_binding()
        raise
    _require_binding()
    normalized, merged_aliases = _normalize_timing_profile_compatibility(merged)
    encountered_aliases.update(merged_aliases)
    return normalized, frozenset(encountered_aliases), tuple(diagnostics)


def _reserve_timing_profile_callbacks(
    encountered_aliases: frozenset[str],
    diagnostics: tuple[str, ...],
    _reserve: Callable[
        [frozenset[str], tuple[str, ...]],
        tuple[tuple[tuple[str, str], ...], tuple[str, ...], int],
    ] = _reserve_timing_profile_callback_ledger,
    _require_binding: Callable[[], None] = _require_timing_profile_runtime_bindings,
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...], int]:
    """Reserve process-wide warning/log callbacks and their rollback generation."""

    _require_binding()
    aliases_to_warn, diagnostics_to_emit, generation = _reserve(
        encountered_aliases,
        diagnostics,
    )
    _require_binding()
    return aliases_to_warn, diagnostics_to_emit, generation


def _emit_timing_profile_alias_warnings(
    aliases_to_warn: tuple[tuple[str, str], ...],
    _require_binding: Callable[[], None] = _require_timing_profile_runtime_bindings,
) -> None:
    """Emit every reservation and re-raise the first promoted warning."""

    first_warning_error: EvidenceForgeDeprecationWarning | None = None
    for legacy_name, canonical_name in aliases_to_warn:
        legacy_path = "timing_profiles.network_sensor_observation.profiles.*." + legacy_name
        canonical_path = "timing_profiles.network_sensor_observation.profiles.*." + canonical_name
        _require_binding()
        try:
            warn_legacy_config(legacy_path, canonical_path, stacklevel=5)
        except EvidenceForgeDeprecationWarning as exc:
            _require_binding()
            if first_warning_error is None:
                first_warning_error = exc
        except BaseException:
            _require_binding()
            raise
        else:
            _require_binding()
    if first_warning_error is not None:
        raise first_warning_error


def _emit_timing_profile_callbacks(
    diagnostics: tuple[str, ...],
    aliases_to_warn: tuple[tuple[str, str], ...],
    _require_binding: Callable[[], None] = _require_timing_profile_runtime_bindings,
) -> None:
    """Emit every reserved logging and deprecation callback without provider locks."""

    for diagnostic in diagnostics:
        _require_binding()
        try:
            logger.warning("%s", diagnostic)
        except BaseException:
            _require_binding()
            raise
        _require_binding()
    _emit_timing_profile_alias_warnings(
        aliases_to_warn,
        _require_binding=_require_binding,
    )


def _rollback_timing_profile_alias_reservations(
    aliases_to_warn: tuple[tuple[str, str], ...],
    diagnostics: tuple[str, ...] = (),
    _rollback: Callable[[tuple[tuple[str, str], ...], tuple[str, ...]], int] = (
        _rollback_timing_profile_callback_ledger
    ),
) -> int:
    """Release only callbacks newly reserved by one unpublished attempt."""

    return _rollback(aliases_to_warn, diagnostics)


def _prepared_timing_profiles_are_current(
    prepared: Any,
    _require_binding: Callable[[], None] = _require_timing_profile_cache_binding,
    _prepared_type: type[_PreparedTimingProfiles] = _PreparedTimingProfiles,
    _ledger_is_current: Callable[[int, frozenset[str]], bool] = (
        _timing_profile_callback_ledger_is_current
    ),
) -> bool:
    """Validate one exact scope preparation against warning rollback state."""

    if type(prepared) is not _prepared_type:
        return False
    _require_binding()
    is_current = _ledger_is_current(
        prepared.warning_generation,
        prepared.warning_aliases,
    )
    _require_binding()
    return is_current


def _invalidate_stale_timing_profile_cache(
    _coordinator: _TimingProfileCacheCoordinator = _TIMING_PROFILE_CACHE_COORDINATOR,
    _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
    _empty_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.EMPTY,
    _prepared_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.PREPARED,
    _ready_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.READY,
    _scope_lease: Any = _CONFIG_SCOPE_LEASE,
    _execution_lock: Any = _CONFIG_EXECUTION_LOCK,
    _ledger_is_current: Callable[[int, frozenset[str]], bool] = (
        _timing_profile_callback_ledger_is_current
    ),
) -> None:
    """Clear any publication that depended on a rolled-back warning."""

    with _scope_lease.hold(), _execution_lock, _coordinator._condition:
        state = _coordinator._state
        if (
            state.phase in {_prepared_phase, _ready_phase}
            and state.warning_aliases is not None
            and state.warning_generation is not None
            and not _ledger_is_current(state.warning_generation, state.warning_aliases)
        ):
            _coordinator._state = _state_type(
                phase=_empty_phase,
                epoch=state.epoch + 1,
            )
            _coordinator._condition.notify_all()


def _build_prepared_timing_profiles(
    _load_normalized: Callable[
        [], tuple[dict[str, Any], frozenset[str], tuple[str, ...]]
    ] = _load_normalized_timing_profiles,
    _reserve_callbacks: Callable[..., tuple[tuple[tuple[str, str], ...], tuple[str, ...], int]] = (
        _reserve_timing_profile_callbacks
    ),
    _require_binding: Callable[[], None] = _require_timing_profile_runtime_bindings,
) -> tuple[
    _PreparedTimingProfiles,
    tuple[tuple[str, str], ...],
    tuple[str, ...],
]:
    """Build, freeze, and reserve every callback without invoking it."""

    _require_binding()
    normalized, encountered_aliases, diagnostics = _load_normalized()
    _require_binding()
    snapshot = _freeze_timing_profile_value(normalized)
    if not isinstance(snapshot, _FrozenTimingProfileMapping):  # pragma: no cover
        raise TimingProfileError("timing profile root must be a mapping")
    aliases_to_warn, diagnostics_to_emit, warning_generation = _reserve_callbacks(
        encountered_aliases,
        diagnostics,
    )
    _require_binding()
    return (
        _PreparedTimingProfiles(
            snapshot=snapshot,
            warning_generation=warning_generation,
            warning_aliases=encountered_aliases,
        ),
        aliases_to_warn,
        diagnostics_to_emit,
    )


def _prepare_timing_profile_candidate(
    _build: Callable[
        [], tuple[_PreparedTimingProfiles, tuple[tuple[str, str], ...], tuple[str, ...]]
    ] = _build_prepared_timing_profiles,
    _emit_callbacks: Callable[[tuple[str, ...], tuple[tuple[str, str], ...]], None] = (
        _emit_timing_profile_callbacks
    ),
    _rollback_callbacks: Callable[[tuple[tuple[str, str], ...], tuple[str, ...]], int] = (
        _rollback_timing_profile_alias_reservations
    ),
    _invalidate_stale: Callable[[], None] = _invalidate_stale_timing_profile_cache,
    _require_binding: Callable[[], None] = _require_timing_profile_runtime_bindings,
) -> _PreparedTimingProfiles:
    """Build and deliver one optimistic candidate without holding provider locks."""

    _require_binding()
    prepared, aliases_to_warn, diagnostics = _build()
    callbacks_succeeded = False
    try:
        _emit_callbacks(diagnostics, aliases_to_warn)
        _require_binding()
        callbacks_succeeded = True
        return prepared
    finally:
        if not callbacks_succeeded:
            _rollback_callbacks(aliases_to_warn, diagnostics)
            _invalidate_stale()


@dataclass(frozen=True, slots=True)
class _TimingProfileCacheMiss:
    """One exact empty-state generation observed before optimistic preparation."""

    state: _TimingProfileCacheState


def _ready_timing_profile_snapshot_locked(
    coordinator: _TimingProfileCacheCoordinator,
    _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
    _empty_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.EMPTY,
    _prepared_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.PREPARED,
    _ready_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.READY,
    _ledger_is_current: Callable[[int, frozenset[str]], bool] = (
        _timing_profile_callback_ledger_is_current
    ),
) -> _FrozenTimingProfileMapping | None:
    """Return one valid publication, normalizing stale provisional state."""

    current_state = coordinator._state
    if current_state.phase not in {_prepared_phase, _ready_phase}:
        return None
    if (
        current_state.snapshot is not None
        and current_state.warning_aliases is not None
        and current_state.warning_generation is not None
        and _ledger_is_current(
            current_state.warning_generation,
            current_state.warning_aliases,
        )
    ):
        if current_state.phase is _prepared_phase:
            current_state = _state_type(
                phase=_ready_phase,
                epoch=current_state.epoch,
                snapshot=current_state.snapshot,
                warning_generation=current_state.warning_generation,
                warning_aliases=current_state.warning_aliases,
            )
            coordinator._state = current_state
            coordinator._condition.notify_all()
        return current_state.snapshot
    coordinator._state = _state_type(
        phase=_empty_phase,
        epoch=current_state.epoch + 1,
    )
    coordinator._condition.notify_all()
    return None


def _load_timing_profiles_locked(
    _coordinator: _TimingProfileCacheCoordinator = _TIMING_PROFILE_CACHE_COORDINATOR,
    _prepared_is_current: Callable[[Any], bool] = _prepared_timing_profiles_are_current,
    _current_prepared: Callable[[], Any | None] = current_prepared_timing_profiles,
    _require_binding: Callable[[], None] = _require_timing_profile_cache_binding,
    _ready_snapshot: Callable[
        [_TimingProfileCacheCoordinator], _FrozenTimingProfileMapping | None
    ] = _ready_timing_profile_snapshot_locked,
    _prepared_type: type[_PreparedTimingProfiles] = _PreparedTimingProfiles,
    _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
    _miss_type: type[_TimingProfileCacheMiss] = _TimingProfileCacheMiss,
    _initializing_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.INITIALIZING,
    _ready_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.READY,
) -> _FrozenTimingProfileMapping | _TimingProfileCacheMiss:
    """Read or publish provider-prepared data without invoking external callbacks."""

    _require_binding()
    with _coordinator._condition:
        _require_binding()
        snapshot = _ready_snapshot(_coordinator)
        if snapshot is not None:
            _require_binding()
            return snapshot
        current_state = _coordinator._state
        if current_state.phase is _initializing_phase:
            raise RuntimeError("timing profile cache contains an unsupported initializer claim")

        provider_prepared = _current_prepared()
        if provider_prepared is not None:
            if type(provider_prepared) is not _prepared_type:
                raise TypeError("provider timing preparation has invalid type")
            if not _prepared_is_current(provider_prepared):
                raise TimingProfileError(
                    "provider timing preparation was invalidated by a warning rollback"
                )
            ready_state = _state_type(
                phase=_ready_phase,
                epoch=current_state.epoch + 1,
                snapshot=provider_prepared.snapshot,
                warning_generation=provider_prepared.warning_generation,
                warning_aliases=provider_prepared.warning_aliases,
            )
            _coordinator._state = ready_state
            _require_binding()
            _coordinator._condition.notify_all()
            return provider_prepared.snapshot
        _require_binding()
        return _miss_type(state=current_state)


def _publish_timing_profile_candidate_locked(
    miss: _TimingProfileCacheMiss,
    prepared: _PreparedTimingProfiles,
    _coordinator: _TimingProfileCacheCoordinator = _TIMING_PROFILE_CACHE_COORDINATOR,
    _require_binding: Callable[[], None] = _require_timing_profile_cache_binding,
    _ready_snapshot: Callable[
        [_TimingProfileCacheCoordinator], _FrozenTimingProfileMapping | None
    ] = _ready_timing_profile_snapshot_locked,
    _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
    _ready_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.READY,
    _ledger_is_current: Callable[[int, frozenset[str]], bool] = (
        _timing_profile_callback_ledger_is_current
    ),
) -> _FrozenTimingProfileMapping | None:
    """Reconcile one optimistic result with the exact observed cache generation."""

    _require_binding()
    with _coordinator._condition:
        _require_binding()
        snapshot = _ready_snapshot(_coordinator)
        if snapshot is not None:
            _require_binding()
            return snapshot
        current_state = _coordinator._state
        if current_state is not miss.state:
            return None
        if not _ledger_is_current(
            prepared.warning_generation,
            prepared.warning_aliases,
        ):
            return None
        ready_state = _state_type(
            phase=_ready_phase,
            epoch=current_state.epoch + 1,
            snapshot=prepared.snapshot,
            warning_generation=prepared.warning_generation,
            warning_aliases=prepared.warning_aliases,
        )
        _coordinator._state = ready_state
        _require_binding()
        _coordinator._condition.notify_all()
        return prepared.snapshot


def _discard_publication_after_failed_preparation(
    baseline: _TimingProfileCacheState,
    _coordinator: _TimingProfileCacheCoordinator = _TIMING_PROFILE_CACHE_COORDINATOR,
    _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
    _empty_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.EMPTY,
    _prepared_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.PREPARED,
    _ready_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.READY,
    _scope_lease: Any = _CONFIG_SCOPE_LEASE,
    _execution_lock: Any = _CONFIG_EXECUTION_LOCK,
) -> None:
    """Invalidate a nested publication produced by one failed callback attempt."""

    with _scope_lease.hold(), _execution_lock, _coordinator._condition:
        current_state = _coordinator._state
        if current_state is not baseline and current_state.phase in {
            _prepared_phase,
            _ready_phase,
        }:
            _coordinator._state = _state_type(
                phase=_empty_phase,
                epoch=current_state.epoch + 1,
            )
            _coordinator._condition.notify_all()


def _reconcile_provider_preparation_publication(
    baseline: _TimingProfileCacheState,
    prepared: _PreparedTimingProfiles,
    _coordinator: _TimingProfileCacheCoordinator = _TIMING_PROFILE_CACHE_COORDINATOR,
    _state_type: type[_TimingProfileCacheState] = _TimingProfileCacheState,
    _prepared_type: type[_PreparedTimingProfiles] = _PreparedTimingProfiles,
    _prepared_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.PREPARED,
    _ready_phase: _TimingProfileCachePhase = _TimingProfileCachePhase.READY,
    _scope_lease: Any = _CONFIG_SCOPE_LEASE,
    _execution_lock: Any = _CONFIG_EXECUTION_LOCK,
    _values_equal: Callable[[Any, Any], bool] = _timing_profile_values_equal,
    _snapshot_operation: Callable[[Any], _TimingProfileCacheState] = (
        _timing_profile_cache_snapshot_operation
    ),
) -> None:
    """Restore an entry baseline if a preparation callback published its scope data."""

    if type(baseline) is not _state_type or type(prepared) is not _prepared_type:
        raise TypeError("provider timing preparation reconciliation has invalid type")
    with _scope_lease.hold(), _execution_lock, _coordinator._condition:
        current = _snapshot_operation(_coordinator)
        if current is baseline:
            return
        if (
            current.phase in {_prepared_phase, _ready_phase}
            and current.snapshot is not None
            and current.warning_generation == prepared.warning_generation
            and current.warning_aliases is not None
            and frozenset.__eq__(current.warning_aliases, prepared.warning_aliases)
            and _values_equal(current.snapshot, prepared.snapshot)
        ):
            _coordinator._state = baseline
            _coordinator._condition.notify_all()


def _prepare_timing_profiles_for_active_provider(
    _coordinator: _TimingProfileCacheCoordinator = _TIMING_PROFILE_CACHE_COORDINATOR,
    _prepare_candidate: Callable[[], _PreparedTimingProfiles] = _prepare_timing_profile_candidate,
    _discard_failed: Callable[[_TimingProfileCacheState], None] = (
        _discard_publication_after_failed_preparation
    ),
    _reconcile_publication: Callable[
        [_TimingProfileCacheState, _PreparedTimingProfiles], None
    ] = _reconcile_provider_preparation_publication,
    _require_binding: Callable[[], None] = _require_timing_profile_cache_binding,
    _snapshot_operation: Callable[[Any], _TimingProfileCacheState] = (
        _timing_profile_cache_snapshot_operation
    ),
) -> _PreparedTimingProfiles:
    """Prepare a provider snapshot without holding a lease or publisher claim."""

    _require_binding()
    baseline = _snapshot_operation(_coordinator)
    try:
        prepared = _prepare_candidate()
        _reconcile_publication(baseline, prepared)
        return prepared
    except BaseException:
        _discard_failed(baseline)
        raise


def _make_public_timing_profile_loader(
    load_locked: Callable[[], _FrozenTimingProfileMapping | _TimingProfileCacheMiss],
    prepare_candidate: Callable[[], _PreparedTimingProfiles],
    publish_locked: Callable[
        [_TimingProfileCacheMiss, _PreparedTimingProfiles],
        _FrozenTimingProfileMapping | None,
    ],
    discard_failed: Callable[[_TimingProfileCacheState], None],
    require_binding: Callable[[], None],
    scope_lease: Any,
    execution_lock: Any,
    snapshot_type: type[_FrozenTimingProfileMapping],
) -> Callable[[], Mapping[str, Any]]:
    """Close the public loader over every trusted state-machine dependency."""

    def load_timing_profiles() -> Mapping[str, Any]:
        """Return one coalesced immutable timing-profile snapshot for the active scope."""

        while True:
            with scope_lease.hold(), execution_lock:
                require_binding()
                result = load_locked()
                require_binding()
            if type(result) is snapshot_type:
                return result

            try:
                with scope_lease.suspend_current():
                    prepared = prepare_candidate()
            except BaseException:
                discard_failed(result.state)
                raise

            with scope_lease.hold(), execution_lock:
                require_binding()
                published = publish_locked(result, prepared)
                require_binding()
            if published is not None:
                return published

    return load_timing_profiles


load_timing_profiles = _make_public_timing_profile_loader(
    _load_timing_profiles_locked,
    _prepare_timing_profile_candidate,
    _publish_timing_profile_candidate_locked,
    _discard_publication_after_failed_preparation,
    _require_timing_profile_cache_binding,
    _CONFIG_SCOPE_LEASE,
    _CONFIG_EXECUTION_LOCK,
    _FrozenTimingProfileMapping,
)


def _make_public_timing_profile_cache_reset(
    clear_for_action: Callable[[str], None],
    require_binding: Callable[[], None],
    scope_lease: Any,
    execution_lock: Any,
) -> Callable[[], None]:
    """Close the public reset operation over its original coordinator and locks."""

    def reset_timing_profiles_cache() -> None:
        """Synchronously clear the timing-profile snapshot in the active provider scope."""

        with scope_lease.hold(), execution_lock:
            require_binding()
            clear_for_action("reset")
            require_binding()

    return reset_timing_profiles_cache


reset_timing_profiles_cache = _make_public_timing_profile_cache_reset(
    _clear_timing_profile_cache_for_action,
    _require_timing_profile_cache_binding,
    _CONFIG_SCOPE_LEASE,
    _CONFIG_EXECUTION_LOCK,
)


def _reset_timing_profile_warning_ledger_for_tests(
    _require_binding: Callable[[], None] = _require_timing_profile_cache_binding,
    _reset_ledger: Callable[[], None] = _reset_timing_profile_callback_ledger,
    _wait_for_stable: Callable[[str], None] = _wait_for_stable_timing_profile_cache,
) -> None:
    """Clear warning reservations after synchronizing with cache initialization."""

    with _CONFIG_SCOPE_LEASE.hold(), _CONFIG_EXECUTION_LOCK:
        _require_binding()
        _wait_for_stable("warning reset")
        _reset_ledger()
        _require_binding()


def _safe_int(value: Any, fallback: int, *, minimum: int, maximum: int) -> int:
    """Convert input to int and clamp to a safe range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def _safe_int_range(
    value: Any,
    *,
    fallback_min: int,
    fallback_max: int,
    minimum: int,
    maximum: int,
) -> tuple[int, int]:
    """Read a ``{min, max}`` mapping and fall back when the range is invalid."""
    if not isinstance(value, Mapping):
        return fallback_min, fallback_max
    min_value = _safe_int(value.get("min"), fallback_min, minimum=minimum, maximum=maximum)
    max_value = _safe_int(value.get("max"), fallback_max, minimum=minimum, maximum=maximum)
    if max_value < min_value:
        return fallback_min, fallback_max
    return min_value, max_value


def _safe_float(
    value: Any,
    fallback: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    """Convert input to float and clamp it to a safe range."""

    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def get_timing_window(
    key: str,
    *,
    default_min_ms: int,
    default_max_ms: int,
    default_position: Literal["before", "after"],
    default_class: str = "",
) -> TimingWindow:
    """Return a named timing relationship with safe code defaults."""
    entry = load_timing_profiles().get("relationships", {}).get(key, {})
    if not isinstance(entry, Mapping):
        entry = {}
    min_ms = _safe_int(
        entry.get("min_ms", default_min_ms),
        default_min_ms,
        minimum=0,
        maximum=_MAX_RELATIONSHIP_MS,
    )
    max_ms = _safe_int(
        entry.get("max_ms", default_max_ms),
        default_max_ms,
        minimum=0,
        maximum=_MAX_RELATIONSHIP_MS,
    )
    if max_ms < min_ms:
        min_ms, max_ms = default_min_ms, default_max_ms
    position = entry.get("position", default_position)
    if position not in {"before", "after"}:
        position = default_position
    return TimingWindow(
        min_ms=min_ms,
        max_ms=max_ms,
        position=position,
        relationship_class=str(entry.get("class", default_class)),
    )


def sample_timing_delta(key: str, *, seed_parts: tuple[Any, ...] = ()) -> timedelta:
    """Sample a deterministic timedelta for a named timing relationship."""
    window = get_timing_window(
        key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    if window.max_ms <= window.min_ms:
        return timedelta(milliseconds=window.min_ms)
    seed = "timing_delta:" + key + ":" + ":".join(str(part) for part in seed_parts)
    rng = random.Random(_stable_seed(seed))
    return timedelta(milliseconds=rng.randint(window.min_ms, window.max_ms))


def sample_packet_timing_delta(key: str, *, seed_parts: tuple[Any, ...] = ()) -> timedelta:
    """Sample a direct-helper-compatible typed packet-observation delta.

    Production generators inject their engine timing runtime directly. This
    stateless adapter remains only for direct helper tests and external callers
    that have not constructed an engine.
    """

    window = get_timing_window(
        key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    stable_id = (
        "packet-timing-compatibility:" + key + ":" + ":".join(str(part) for part in seed_parts)
    )
    return BaselineTimingPlanner(
        TimingRuntime.compatibility_default(),
        source="network",
    ).packet_observation_delta(
        relationship_key=key,
        stable_id=stable_id,
        minimum_ms=window.min_ms,
        maximum_ms=window.max_ms,
    )


def ssh_authentication_timing(auth_method: str) -> SshAuthenticationTiming:
    """Return bounded data-driven timing for one SSH authentication method."""

    normalized_method = auth_method.strip().lower()
    fallback = {
        "publickey": {
            "fast_probability": 0.22,
            "fast_ms": (25, 180),
            "typical_ms": (180, 1250),
            "tail_probability": 0.12,
            "tail_ms": (1250, 4800),
            "cache_miss_probability": 0.18,
            "cache_miss_ms": (120, 1500),
        },
        "password": {
            "fast_probability": 0.08,
            "fast_ms": (180, 550),
            "typical_ms": (550, 3600),
            "tail_probability": 0.18,
            "tail_ms": (3600, 9000),
            "cache_miss_probability": 0.32,
            "cache_miss_ms": (250, 2800),
        },
    }
    fallback_profile = fallback.get(normalized_method, fallback["password"])
    data = load_timing_profiles().get("ssh_authentication", {})
    if not isinstance(data, Mapping):
        data = {}
    profiles = data.get("profiles", {})
    if not isinstance(profiles, Mapping):
        profiles = {}
    profile = profiles.get(normalized_method, {})
    if not isinstance(profile, Mapping):
        profile = {}

    fast_min, fast_max = _safe_int_range(
        profile.get("fast_ms"),
        fallback_min=fallback_profile["fast_ms"][0],
        fallback_max=fallback_profile["fast_ms"][1],
        minimum=1,
        maximum=60_000,
    )
    typical_min, typical_max = _safe_int_range(
        profile.get("typical_ms"),
        fallback_min=fallback_profile["typical_ms"][0],
        fallback_max=fallback_profile["typical_ms"][1],
        minimum=1,
        maximum=60_000,
    )
    tail_min, tail_max = _safe_int_range(
        profile.get("tail_ms"),
        fallback_min=fallback_profile["tail_ms"][0],
        fallback_max=fallback_profile["tail_ms"][1],
        minimum=1,
        maximum=60_000,
    )
    cache_min, cache_max = _safe_int_range(
        profile.get("cache_miss_ms"),
        fallback_min=fallback_profile["cache_miss_ms"][0],
        fallback_max=fallback_profile["cache_miss_ms"][1],
        minimum=0,
        maximum=60_000,
    )
    return SshAuthenticationTiming(
        fast_probability=_safe_float(
            profile.get("fast_probability"),
            fallback_profile["fast_probability"],
            minimum=0.0,
            maximum=0.75,
        ),
        fast_min_ms=fast_min,
        fast_max_ms=fast_max,
        typical_min_ms=typical_min,
        typical_max_ms=typical_max,
        tail_probability=_safe_float(
            profile.get("tail_probability"),
            fallback_profile["tail_probability"],
            minimum=0.0,
            maximum=0.5,
        ),
        tail_min_ms=tail_min,
        tail_max_ms=tail_max,
        cache_miss_probability=_safe_float(
            profile.get("cache_miss_probability"),
            fallback_profile["cache_miss_probability"],
            minimum=0.0,
            maximum=1.0,
        ),
        cache_miss_min_ms=cache_min,
        cache_miss_max_ms=cache_max,
    )


def _inclusive_uniform_millisecond_distribution(
    minimum: float,
    maximum: float,
) -> DistributionSpec:
    """Return an edge-triangular mixture with the exact former millisecond support."""

    if minimum == maximum:
        return ConstantDistribution(float(minimum * 1_000))
    lower = float(minimum * 1_000) - 0.5
    upper = float(maximum * 1_000) + 0.5
    return MixtureDistribution(
        (
            WeightedDistribution(
                1.0,
                TriangularDistribution(minimum=lower, mode=lower, maximum=upper),
            ),
            WeightedDistribution(
                1.0,
                TriangularDistribution(minimum=lower, mode=upper, maximum=upper),
            ),
        )
    )


def _inclusive_triangular_millisecond_distribution(
    minimum: float,
    mode: float,
    maximum: float,
) -> DistributionSpec:
    """Return a triangular distribution with the exact former millisecond support."""

    if minimum == maximum:
        return ConstantDistribution(float(minimum * 1_000))
    lower = float(minimum * 1_000) - 0.5
    upper = float(maximum * 1_000) + 0.5
    return TriangularDistribution(
        minimum=lower,
        mode=min(upper, max(lower, mode * 1_000)),
        maximum=upper,
    )


def _sample_ssh_milliseconds(
    planner: BaselineTimingPlanner,
    distribution: DistributionSpec,
    *,
    relationship_key: str,
    scope: TimingScope,
    sample_key: str,
) -> float:
    """Sample one audited microsecond-quantized component in milliseconds."""

    microseconds = planner.runtime.sampler.sample_microseconds(
        distribution,
        relationship_key=relationship_key,
        scope=scope,
        sample_key=sample_key,
    )
    return microseconds / 1_000


def _ssh_authentication_context_support(
    auth_method: str,
    *,
    public_key_type: str,
    route_class: str,
) -> tuple[SshAuthenticationTiming, SshAcceptedAuthenticationTimingSupport]:
    """Resolve one profile and its exact accepted-authentication component supports."""

    profile = ssh_authentication_timing(auth_method)
    tail_weight = min(1.0, profile.tail_probability)
    fast_weight = min(max(0.0, 1.0 - tail_weight), profile.fast_probability)
    typical_weight = max(0.0, 1.0 - tail_weight - fast_weight)
    phase_supports = tuple(
        support
        for weight, support in (
            (tail_weight, (profile.tail_min_ms, profile.tail_max_ms)),
            (fast_weight, (profile.fast_min_ms, profile.fast_max_ms)),
            (typical_weight, (profile.typical_min_ms, profile.typical_max_ms)),
        )
        if weight > 0
    )

    data = load_timing_profiles().get("ssh_authentication", {})
    if not isinstance(data, Mapping):
        data = {}
    route_profiles = data.get("route_rtt_ms", {})
    if not isinstance(route_profiles, Mapping):
        route_profiles = {}
    route_support = _safe_int_range(
        route_profiles.get(route_class),
        fallback_min=2 if route_class == "private" else 25,
        fallback_max=55 if route_class == "private" else 320,
        minimum=0,
        maximum=10_000,
    )
    receiver_support = _safe_int_range(
        data.get("receiver_load_ms"),
        fallback_min=0,
        fallback_max=650,
        minimum=0,
        maximum=10_000,
    )
    penalties = data.get("public_key_penalty_ms", {})
    if not isinstance(penalties, Mapping):
        penalties = {}
    key_type = public_key_type.strip().upper()
    key_support = (
        _safe_int_range(
            penalties.get(key_type),
            fallback_min=0,
            fallback_max=0,
            minimum=0,
            maximum=10_000,
        )
        if key_type
        else (0, 0)
    )
    cache_intervals: list[tuple[int, int]] = []
    if profile.cache_miss_probability < 1.0:
        cache_intervals.append((0, 0))
    if profile.cache_miss_probability > 0.0:
        cache_intervals.append((profile.cache_miss_min_ms, profile.cache_miss_max_ms))
    return profile, SshAcceptedAuthenticationTimingSupport(
        phase_ms=_millisecond_support(*phase_supports),
        cache_delay_ms=_millisecond_support(*cache_intervals),
        route_delay_ms=_millisecond_support(route_support),
        receiver_delay_ms=_millisecond_support(receiver_support),
        key_penalty_ms=_millisecond_support(key_support),
    )


def ssh_authentication_timing_support(
    auth_method: str,
    *,
    public_key_type: str = "",
    route_class: str = "private",
) -> SshAuthenticationTimingSupport:
    """Return exact inclusive component and total supports for one SSH auth plan."""

    _profile, accepted_support = _ssh_authentication_context_support(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
    )
    return SshAuthenticationTimingSupport(
        connection_gap_ms=_millisecond_support(_SSH_CONNECTION_GAP_MS),
        accepted=accepted_support,
        pam_gap_ms=_millisecond_support(_SSH_PAM_GAP_MS),
        logind_gap_ms=_millisecond_support(_SSH_LOGIND_GAP_MS),
    )


def _plan_ssh_accepted_authentication_timing(
    auth_method: str,
    *,
    public_key_type: str,
    route_class: str,
    planner: BaselineTimingPlanner,
    scope: TimingScope,
) -> SshAcceptedAuthenticationTiming:
    """Plan every independently stable component of SSH authentication acceptance."""

    profile, support = _ssh_authentication_context_support(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
    )
    tail_weight = min(1.0, profile.tail_probability)
    fast_weight = min(max(0.0, 1.0 - tail_weight), profile.fast_probability)
    typical_weight = max(0.0, 1.0 - tail_weight - fast_weight)
    phase_components: list[WeightedDistribution] = []
    for weight, distribution in (
        (
            tail_weight,
            _inclusive_uniform_millisecond_distribution(
                profile.tail_min_ms,
                profile.tail_max_ms,
            ),
        ),
        (
            fast_weight,
            _inclusive_uniform_millisecond_distribution(
                profile.fast_min_ms,
                profile.fast_max_ms,
            ),
        ),
        (
            typical_weight,
            _inclusive_triangular_millisecond_distribution(
                profile.typical_min_ms,
                profile.typical_min_ms + (profile.typical_max_ms - profile.typical_min_ms) * 0.35,
                profile.typical_max_ms,
            ),
        ),
    ):
        if weight > 0:
            phase_components.append(WeightedDistribution(weight, distribution))
    phase_ms = _sample_ssh_milliseconds(
        planner,
        MixtureDistribution(tuple(phase_components)),
        relationship_key="ssh.authentication.phase",
        scope=scope,
        sample_key="phase",
    )

    cache_components: list[WeightedDistribution] = []
    if profile.cache_miss_probability < 1.0:
        cache_components.append(
            WeightedDistribution(
                1.0 - profile.cache_miss_probability,
                ConstantDistribution(0.0),
            )
        )
    if profile.cache_miss_probability > 0.0:
        cache_components.append(
            WeightedDistribution(
                profile.cache_miss_probability,
                _inclusive_uniform_millisecond_distribution(
                    profile.cache_miss_min_ms,
                    profile.cache_miss_max_ms,
                ),
            )
        )
    cache_delay_ms = _sample_ssh_milliseconds(
        planner,
        MixtureDistribution(tuple(cache_components)),
        relationship_key="ssh.authentication.cache_delay",
        scope=scope,
        sample_key="cache",
    )
    route_delay_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*support.route_delay_ms.bounds),
        relationship_key="ssh.authentication.route_delay",
        scope=scope,
        sample_key="route",
    )
    receiver_delay_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_triangular_millisecond_distribution(
            support.receiver_delay_ms.bounds[0],
            float(support.receiver_delay_ms.bounds[0]),
            support.receiver_delay_ms.bounds[1],
        ),
        relationship_key="ssh.authentication.receiver_delay",
        scope=scope,
        sample_key="receiver",
    )
    key_type = public_key_type.strip().upper()
    key_penalty_ms = 0.0
    if key_type:
        key_penalty_ms = _sample_ssh_milliseconds(
            planner,
            _inclusive_uniform_millisecond_distribution(*support.key_penalty_ms.bounds),
            relationship_key="ssh.authentication.key_penalty",
            scope=scope,
            sample_key=f"key:{key_type}",
        )
    return SshAcceptedAuthenticationTiming(
        phase_ms=phase_ms,
        cache_delay_ms=cache_delay_ms,
        route_delay_ms=route_delay_ms,
        receiver_delay_ms=receiver_delay_ms,
        key_penalty_ms=key_penalty_ms,
    )


def plan_ssh_authentication_timing(
    auth_method: str,
    *,
    public_key_type: str,
    route_class: str,
    timing_runtime: _SshTimingRuntime,
    scope: TimingScope,
) -> SshAuthenticationTimingPlan:
    """Plan all ordered SSH authentication gaps through one exact injected runtime."""

    planner = BaselineTimingPlanner(timing_runtime, source=scope.source)
    connection_gap_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*_SSH_CONNECTION_GAP_MS),
        relationship_key="ssh.authentication.connection_after_transport",
        scope=scope,
        sample_key="connection_gap",
    )
    accepted = _plan_ssh_accepted_authentication_timing(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
        planner=planner,
        scope=scope,
    )
    pam_gap_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*_SSH_PAM_GAP_MS),
        relationship_key="ssh.authentication.pam_after_accepted",
        scope=scope,
        sample_key="pam_gap",
    )
    logind_gap_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*_SSH_LOGIND_GAP_MS),
        relationship_key="ssh.authentication.logind_after_pam",
        scope=scope,
        sample_key="logind_gap",
    )
    return SshAuthenticationTimingPlan(
        connection_gap_ms=connection_gap_ms,
        accepted=accepted,
        pam_gap_ms=pam_gap_ms,
        logind_gap_ms=logind_gap_ms,
    )


def sample_ssh_authentication_phase_ms_compatibility(
    auth_method: str,
    *,
    public_key_type: str = "",
    route_class: str = "private",
    seed_parts: tuple[Any, ...] = (),
) -> float:
    """Sample accepted-auth timing for direct legacy helper callers only."""

    seed_text = ":".join(str(part) for part in seed_parts)
    stable_id = f"{auth_method}:{seed_text}"
    runtime = TimingRuntime.compatibility_default()
    planner = BaselineTimingPlanner(runtime, source="ssh-auth-compatibility")
    return _plan_ssh_accepted_authentication_timing(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
        planner=planner,
        scope=TimingScope(
            stable_id=stable_id,
            source=planner.source,
            lifecycle_id=stable_id,
        ),
    ).total_ms


def sysmon_envelope_timing(event_id: int) -> SysmonEnvelopeTiming:
    """Return data-driven Sysmon provider-envelope timing for an event ID."""

    data = load_timing_profiles().get("sysmon_event_envelope", {})
    if not isinstance(data, Mapping):
        data = {}
    default = data.get("default", {})
    if not isinstance(default, Mapping):
        default = {}
    event_profiles = data.get("event_ids", {})
    if not isinstance(event_profiles, Mapping):
        event_profiles = {}
    override = event_profiles.get(str(event_id), {})
    if not isinstance(override, Mapping):
        override = {}
    profile = {**default, **override}
    minimum_us = _safe_int(profile.get("min_us"), 80, minimum=1, maximum=1_000_000)
    maximum_us = _safe_int(profile.get("max_us"), 18_000, minimum=minimum_us, maximum=1_000_000)
    tail_min_us = _safe_int(
        profile.get("tail_min_us"), 12_000, minimum=minimum_us, maximum=1_000_000
    )
    tail_max_us = _safe_int(
        profile.get("tail_max_us"), 85_000, minimum=tail_min_us, maximum=1_000_000
    )
    return SysmonEnvelopeTiming(
        median_us=_safe_int(profile.get("median_us"), 850, minimum=minimum_us, maximum=maximum_us),
        sigma=_safe_float(profile.get("sigma"), 0.8, minimum=0.05, maximum=3.0),
        min_us=minimum_us,
        max_us=maximum_us,
        tail_probability=_safe_float(
            profile.get("tail_probability"), 0.012, minimum=0.0, maximum=0.25
        ),
        tail_min_us=tail_min_us,
        tail_max_us=tail_max_us,
    )


def startup_module_observation_timing() -> StartupModuleObservationTiming:
    """Return safe data-driven timing for source-visible startup module bursts."""
    data = load_timing_profiles().get("windows_startup_modules", {})
    if not isinstance(data, Mapping):
        data = {}
    initial_min, initial_max = _safe_int_range(
        data.get("initial_delay_us"),
        fallback_min=250,
        fallback_max=6_500,
        minimum=1,
        maximum=1_000_000,
    )
    gap_data = data.get("inter_load_gap_us", {})
    if not isinstance(gap_data, Mapping):
        gap_data = {}
    gap_min = _safe_int(
        gap_data.get("min"),
        120,
        minimum=1,
        maximum=1_000_000,
    )
    gap_max = _safe_int(
        gap_data.get("max"),
        65_000,
        minimum=1,
        maximum=1_000_000,
    )
    if gap_max < gap_min:
        gap_min, gap_max = 120, 65_000
    gap_median = _safe_int(
        gap_data.get("median"),
        1_900,
        minimum=gap_min,
        maximum=gap_max,
    )
    gap_sigma = _safe_float(
        gap_data.get("sigma"),
        0.95,
        minimum=0.05,
        maximum=3.0,
    )
    return StartupModuleObservationTiming(
        initial_delay_min_us=initial_min,
        initial_delay_max_us=initial_max,
        inter_load_gap_median_us=gap_median,
        inter_load_gap_sigma=gap_sigma,
        inter_load_gap_min_us=gap_min,
        inter_load_gap_max_us=gap_max,
    )


def network_sensor_observation_timing(
    profile_name: str | None = None,
) -> NetworkSensorObservationTiming:
    """Return safe timing and capture bounds for one network sensor profile."""
    data = load_timing_profiles().get("network_sensor_observation", {})
    if not isinstance(data, Mapping):
        data = {}
    profiles = data.get("profiles", {})
    if not isinstance(profiles, Mapping):
        profiles = {}
    default_profile = str(data.get("default_profile", "well_synced") or "well_synced")
    selected_profile = str(profile_name or default_profile)
    profile = profiles.get(selected_profile, {})
    if not isinstance(profile, Mapping):
        selected_profile = default_profile
        profile = profiles.get(default_profile, {})
    if not isinstance(profile, Mapping):
        profile = {}

    skew_min, skew_max = _safe_int_range(
        profile.get("clock_offset_us"),
        fallback_min=-18_000,
        fallback_max=22_000,
        minimum=-_MAX_SENSOR_TIMING_US,
        maximum=_MAX_SENSOR_TIMING_US,
    )
    drift_min, drift_max = _safe_int_range(
        profile.get("clock_drift_ppm"),
        fallback_min=0,
        fallback_max=0,
        minimum=-500,
        maximum=500,
    )
    delay_min, delay_max = _safe_int_range(
        profile.get("route_delay_us"),
        fallback_min=1_200,
        fallback_max=58_000,
        minimum=0,
        maximum=_MAX_SENSOR_TIMING_US,
    )
    jitter_min, jitter_max = _safe_int_range(
        profile.get("event_jitter_us"),
        fallback_min=-997,
        fallback_max=997,
        minimum=-_MAX_SENSOR_TIMING_US,
        maximum=_MAX_SENSOR_TIMING_US,
    )
    capture_loss = profile.get("capture_loss", {})
    if not isinstance(capture_loss, Mapping):
        capture_loss = {}
    loss_probability = _safe_float(
        capture_loss.get("probability", 0.0),
        0.0,
        minimum=0.0,
        maximum=1.0,
    )
    loss_min_fraction = _safe_float(
        capture_loss.get("min_fraction", 0.0),
        0.0,
        minimum=0.0,
        maximum=1.0,
    )
    loss_max_fraction = _safe_float(
        capture_loss.get("max_fraction", 0.0),
        0.0,
        minimum=0.0,
        maximum=1.0,
    )
    if loss_max_fraction < loss_min_fraction:
        loss_min_fraction = 0.0
        loss_max_fraction = 0.0
    loss_max_missed_bytes = _safe_int(
        capture_loss.get("max_missed_bytes", 0),
        0,
        minimum=0,
        maximum=1_000_000_000,
    )
    return NetworkSensorObservationTiming(
        profile_name=selected_profile,
        clock_offset_min_us=skew_min,
        clock_offset_max_us=skew_max,
        clock_drift_min_ppm=drift_min,
        clock_drift_max_ppm=drift_max,
        route_delay_min_us=delay_min,
        route_delay_max_us=delay_max,
        event_jitter_min_us=jitter_min,
        event_jitter_max_us=jitter_max,
        capture_loss_probability=loss_probability,
        capture_loss_min_fraction=loss_min_fraction,
        capture_loss_max_fraction=loss_max_fraction,
        capture_loss_max_missed_bytes=loss_max_missed_bytes,
    )


def endpoint_clock_timing(profile_name: str, os_category: str) -> EndpointClockTiming:
    """Return safe endpoint host-clock bounds for an observation profile and OS."""
    data = load_timing_profiles().get("endpoint_clock", {})
    if not isinstance(data, Mapping):
        data = {}
    profiles = data.get("profiles", {})
    if not isinstance(profiles, Mapping):
        profiles = {}
    profile = profiles.get(profile_name)
    if not isinstance(profile, Mapping):
        profile = profiles.get("complete", {})
    if not isinstance(profile, Mapping):
        profile = {}

    os_key = "windows" if os_category == "windows" else "linux"
    os_profile = profile.get(os_key, {})
    if not isinstance(os_profile, Mapping):
        os_profile = {}
    offset_min, offset_max = _safe_int_range(
        os_profile.get("host_offset_ms"),
        fallback_min=0,
        fallback_max=0,
        minimum=-_MAX_ENDPOINT_CLOCK_OFFSET_MS,
        maximum=_MAX_ENDPOINT_CLOCK_OFFSET_MS,
    )
    drift_min, drift_max = _safe_int_range(
        os_profile.get("host_drift_ppm"),
        fallback_min=0,
        fallback_max=0,
        minimum=-_MAX_ENDPOINT_CLOCK_DRIFT_PPM,
        maximum=_MAX_ENDPOINT_CLOCK_DRIFT_PPM,
    )
    return EndpointClockTiming(
        host_offset_min_ms=offset_min,
        host_offset_max_ms=offset_max,
        host_drift_min_ppm=drift_min,
        host_drift_max_ppm=drift_max,
    )


def firewall_observation_timing(sensor_identity: str = "") -> FirewallObservationTiming:
    """Return the configured firewall timer policy for one sensor."""

    data = load_timing_profiles().get("firewall_observation", {})
    if not isinstance(data, Mapping):
        data = {}
    policies = data.get("policies", {})
    if not isinstance(policies, Mapping):
        policies = {}
    sensor_policies = data.get("sensor_policies", {})
    if not isinstance(sensor_policies, Mapping):
        sensor_policies = {}
    default_policy = str(data.get("default_policy", "asa_default") or "asa_default")
    policy_name = str(sensor_policies.get(sensor_identity, default_policy) or default_policy)
    policy = policies.get(policy_name, {})
    if not isinstance(policy, Mapping):
        policy_name = default_policy
        policy = policies.get(default_policy, {})
    if not isinstance(policy, Mapping):
        policy = {}
    return FirewallObservationTiming(
        policy_name=policy_name,
        tcp_embryonic_timeout_seconds=_safe_int(
            policy.get("tcp_embryonic_timeout_seconds", 30),
            30,
            minimum=1,
            maximum=3600,
        ),
        tcp_idle_timeout_seconds=_safe_int(
            policy.get("tcp_idle_timeout_seconds", 3600),
            3600,
            minimum=1,
            maximum=604_800,
        ),
    )


def windows_collision_spacing_config() -> dict[str, int]:
    """Return Windows/Sysmon same-timestamp collision spacing settings."""
    spacing = load_timing_profiles().get("windows_event_time", {}).get("collision_spacing", {})
    if not isinstance(spacing, Mapping):
        spacing = {}
    config = {
        "near_zero_until": _safe_int(
            spacing.get("near_zero_until", 25),
            25,
            minimum=0,
            maximum=_MAX_COLLISION_NEAR_ZERO_UNTIL,
        ),
        "near_gap_min_us": _safe_int(
            spacing.get("near_gap_min_us", 50),
            50,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_US,
        ),
        "near_gap_max_us": _safe_int(
            spacing.get("near_gap_max_us", 500),
            500,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_US,
        ),
        "large_gap_min_ms": _safe_int(
            spacing.get("large_gap_min_ms", 1000),
            1000,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_MS,
        ),
        "large_gap_max_ms": _safe_int(
            spacing.get("large_gap_max_ms", 4000),
            4000,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_MS,
        ),
    }
    if config["near_gap_max_us"] < config["near_gap_min_us"]:
        config["near_gap_min_us"], config["near_gap_max_us"] = 50, 500
    if config["large_gap_max_ms"] < config["large_gap_min_ms"]:
        config["large_gap_min_ms"], config["large_gap_max_ms"] = 1000, 4000
    return config
