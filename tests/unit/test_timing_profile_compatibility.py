# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded compatibility and exact-publication tests for timing profiles."""

from __future__ import annotations

import importlib
import logging
import subprocess
import sys
import warnings
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Barrier, Event, Lock, Thread
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import yaml

from evidenceforge.composition.models import EffectiveConfig
from evidenceforge.config import provider as config_provider
from evidenceforge.config.compatibility import EvidenceForgeDeprecationWarning
from evidenceforge.config.provider import (
    current_effective_config,
    effective_config_scope,
)
from evidenceforge.generation.activity import timing_profiles as timing_profiles_module
from evidenceforge.generation.activity.timing_profiles import (
    TimingProfileError,
    _freeze_timing_profile_value,
    _FrozenTimingProfileMapping,
    _preflight_timing_profile_graph,
    _reset_timing_profile_warning_ledger_for_tests,
    _timing_profile_values_equal,
    _TimingProfileCachePhase,
    _TimingProfileComparison,
    _TimingProfileGraphLimits,
    load_timing_profiles,
    network_sensor_observation_timing,
    reset_timing_profiles_cache,
)

pytestmark = pytest.mark.slow

_TIMING_PROFILE_OVERLAY_PATH = "activity/timing_profiles.yaml"
_NO_TIMING_DOCUMENT = object()


@pytest.fixture(autouse=True)
def _reset_public_cache_and_warning_ledger() -> Iterator[None]:
    """Give every test a fresh public cache epoch and warning ledger."""

    reset_timing_profiles_cache()
    _reset_timing_profile_warning_ledger_for_tests()
    yield
    reset_timing_profiles_cache()
    _reset_timing_profile_warning_ledger_for_tests()


def _cache_phase() -> _TimingProfileCachePhase:
    """Return the exact coordinated cache phase."""

    return timing_profiles_module._CACHED_TIMING_PROFILES.state.phase


def _limits(**overrides: int) -> _TimingProfileGraphLimits:
    """Return a compact test budget with selected exact overrides."""

    values = {
        "max_depth": 16,
        "max_container_members": 64,
        "max_unique_nodes": 512,
        "max_references": 1_024,
        "max_scalar_bytes": 1_024,
        "max_aggregate_bytes": 64 * 1_024,
    }
    values.update(overrides)
    return _TimingProfileGraphLimits(**values)


def _nested_mapping(depth: int) -> dict[str, Any]:
    """Build a mapping with a scalar leaf at the requested graph depth."""

    value: Any = 1
    for _index in range(depth):
        value = {"next": value}
    return value


def _compact_binary_dag(depth: int, leaf: dict[str, Any]) -> dict[str, Any]:
    """Build a binary path product backed by only one node per level."""

    node = leaf
    for _index in range(depth):
        node = {"left": node, "right": node}
    return node


def _legacy_authored(*, shared_profiles: bool = False) -> dict[str, Any]:
    """Return timing data containing both supported legacy aliases."""

    profile = {
        "clock_skew_us": {"min": -25, "max": 25},
        "path_delay_us": {"min": 50, "max": 500},
    }
    profiles = {"branch": profile}
    if shared_profiles:
        profiles["branch_secondary"] = profile
    return {
        "network_sensor_observation": {
            "default_profile": "branch",
            "profiles": profiles,
        }
    }


def _return_value_loader(
    value: dict[str, Any],
    calls: list[int] | None = None,
) -> Callable[
    [Path, str, Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]], dict[str, Any]
]:
    """Return a loader fake that exposes the exact caller-owned graph."""

    def load(
        _package_path: Path,
        _overlay_subpath: str,
        _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        if calls is not None:
            calls.append(1)
        return value

    return load


def _layered_loader(
    default: dict[str, Any],
    overlay: dict[str, Any],
) -> Callable[
    [Path, str, Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]], dict[str, Any]
]:
    """Exercise the real timing merge callback with two detached layers."""

    def load(
        _package_path: Path,
        _overlay_subpath: str,
        merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        return merge_fn(deepcopy(default), deepcopy(overlay))

    return load


def _marker_loader(
    _package_path: Path,
    _overlay_subpath: str,
    _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Return timing data marked by the active provider scope."""

    effective = current_effective_config()
    marker = 0 if effective is None else int(effective.marker)
    return {
        "scope_marker": marker,
        "network_sensor_observation": {"profiles": {}},
    }


class _FaultingRuntimeCacheCoordinator:
    """Deterministic provider-protocol fake for transactional failure gates."""

    def __init__(self, name: str, log: list[tuple[str, str]] | None = None) -> None:
        self.name = name
        self.state = f"saved-{name}"
        self.clear_calls = 0
        self.restore_calls = 0
        self.clear_failures: dict[int, BaseException] = {}
        self.restore_failures: dict[int, BaseException] = {}
        self.block_clear_call: int | None = None
        self.clear_started = Event()
        self.clear_release = Event()
        self.log = [] if log is None else log
        self.cleared_states: list[str] = []
        self.restored_snapshots: list[str] = []

    def _evidenceforge_runtime_cache_snapshot(self) -> str:
        """Return the exact current fake state."""

        self.log.append(("snapshot", self.name))
        return self.state

    def _evidenceforge_runtime_cache_clear(self) -> None:
        """Mutate first, optionally block, then raise the configured BaseException."""

        self.clear_calls += 1
        self.log.append(("clear", self.name))
        self.state = f"cleared-{self.name}-{self.clear_calls}"
        self.cleared_states.append(self.state)
        if self.block_clear_call == self.clear_calls:
            self.clear_started.set()
            if not self.clear_release.wait(timeout=10):
                raise TimeoutError("transactional cache clear was not released")
        failure = self.clear_failures.get(self.clear_calls)
        if failure is not None:
            raise failure

    def _evidenceforge_runtime_cache_restore(self, snapshot: str) -> None:
        """Restore exact state before optionally raising a configured failure."""

        self.restore_calls += 1
        self.log.append(("restore", self.name))
        self.restored_snapshots.append(snapshot)
        self.state = snapshot
        failure = self.restore_failures.get(self.restore_calls)
        if failure is not None:
            raise failure


class _FaultingCachedCallable:
    """Derived-cache fake that can fail after recording an exact clear attempt."""

    def __init__(self) -> None:
        self.clear_calls = 0
        self.clear_failures: dict[int, BaseException] = {}

    def __call__(self) -> None:
        """Make this object discoverably callable."""

    def cache_clear(self) -> None:
        """Record the attempt before raising a configured failure."""

        self.clear_calls += 1
        failure = self.clear_failures.get(self.clear_calls)
        if failure is not None:
            raise failure


def _install_faulting_runtime_caches(
    monkeypatch: pytest.MonkeyPatch,
    coordinators: tuple[_FaultingRuntimeCacheCoordinator, ...],
) -> None:
    """Add ordered fakes without hiding real raw or derived cache targets."""

    original_snapshots = config_provider._cache_globals
    original_clear_values = config_provider._cache_globals_for_clear
    namespaces = tuple({} for _coordinator in coordinators)
    for index, (namespace, coordinator) in enumerate(zip(namespaces, coordinators, strict=True)):
        dict.__setitem__(namespace, f"_CACHED_TEST_{index}", coordinator)

    def snapshots() -> list[tuple[dict[str, Any], str, Any]]:
        fake_snapshots = [
            (
                namespace,
                f"_CACHED_TEST_{index}",
                config_provider._CoordinatedRuntimeCacheValue(
                    controller=coordinator,
                    snapshot=coordinator._evidenceforge_runtime_cache_snapshot(),
                    clear_operation=(type(coordinator)._evidenceforge_runtime_cache_clear),
                    restore_operation=(type(coordinator)._evidenceforge_runtime_cache_restore),
                ),
            )
            for index, (namespace, coordinator) in enumerate(
                zip(namespaces, coordinators, strict=True)
            )
        ]
        return [*fake_snapshots, *original_snapshots()]

    def clear_values() -> tuple[list[tuple[dict[str, Any], str, Any]], BaseException | None]:
        fake_values = [
            (
                namespace,
                f"_CACHED_TEST_{index}",
                config_provider._CoordinatedRuntimeCacheValue(
                    controller=coordinator,
                    snapshot=None,
                    clear_operation=(type(coordinator)._evidenceforge_runtime_cache_clear),
                    restore_operation=(type(coordinator)._evidenceforge_runtime_cache_restore),
                ),
            )
            for index, (namespace, coordinator) in enumerate(
                zip(namespaces, coordinators, strict=True)
            )
        ]
        real_values, discovery_failure = original_clear_values()
        return [*fake_values, *real_values], discovery_failure

    monkeypatch.setattr(config_provider, "_cache_globals", snapshots)
    monkeypatch.setattr(config_provider, "_cache_globals_for_clear", clear_values)


def _effective_timing_config(
    document: Any = _NO_TIMING_DOCUMENT,
    *,
    packaged_document: Any = _NO_TIMING_DOCUMENT,
) -> EffectiveConfig:
    """Build a real provider snapshot without recursively validating a hostile graph."""

    packaged_defaults = (
        {}
        if packaged_document is _NO_TIMING_DOCUMENT
        else {_TIMING_PROFILE_OVERLAY_PATH: packaged_document}
    )
    project_overlays = (
        {} if document is _NO_TIMING_DOCUMENT else {_TIMING_PROFILE_OVERLAY_PATH: document}
    )
    return EffectiveConfig.model_construct(
        project_root=".",
        packaged_defaults=packaged_defaults,
        catalogs={},
        project_overlays=project_overlays,
        families={},
        embedded_yaml_assets={},
        ambient_overlay_compat=False,
    )


def _legacy_warnings(
    records: list[warnings.WarningMessage],
) -> list[warnings.WarningMessage]:
    """Return public EvidenceForge compatibility warnings only."""

    return [
        record for record in records if issubclass(record.category, EvidenceForgeDeprecationWarning)
    ]


def _write_legacy_overlay(root: Path) -> None:
    """Write two profiles containing both supported aliases."""

    overlay = root / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True, exist_ok=True)
    (overlay / "timing_profiles.yaml").write_text(
        """
network_sensor_observation:
  profiles:
    branch:
      clock_skew_us: {min: -25, max: 25}
      path_delay_us: {min: 50, max: 500}
    branch_secondary:
      clock_skew_us: {min: -75, max: 75}
      path_delay_us: {min: 100, max: 750}
""".lstrip(),
        encoding="utf-8",
    )


def test_real_safe_loader_self_cycle_rejects_before_warning_or_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real SafeLoader alias cycle fails closed without recursion or side effects."""

    authored = yaml.load(
        """
network_sensor_observation:
  profiles:
    branch: &branch
      clock_skew_us: *branch
""".lstrip(),
        Loader=yaml.SafeLoader,
    )
    warning_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    monkeypatch.setattr(
        timing_profiles_module,
        "warn_legacy_config",
        lambda legacy, replacement, **_kwargs: warning_calls.append((legacy, replacement)),
    )

    with pytest.raises(TimingProfileError, match="recursive YAML alias graph"):
        load_timing_profiles()

    assert warning_calls == []
    assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()
    assert _cache_phase() is _TimingProfileCachePhase.EMPTY


def test_compact_alias_dag_is_traversed_once_and_frozen_with_shared_identity() -> None:
    """A wide alias fan-out charges graph edges without re-expanding shared descendants."""

    shared: dict[str, Any] = {"leaf": 1}
    for _index in range(7):
        shared = {"next": shared}
    graph = {f"branch_{index}": shared for index in range(48)}
    limits = _limits(max_depth=9, max_container_members=64)

    stats = _preflight_timing_profile_graph(graph, limits=limits)
    frozen = _freeze_timing_profile_value(graph, limits=limits)

    assert stats.max_depth == 9
    assert stats.unique_nodes < 80
    assert stats.references < 120
    first = frozen["branch_0"]
    assert all(frozen[f"branch_{index}"] is first for index in range(48))


def test_shared_dag_longer_path_still_enforces_descendant_depth() -> None:
    """A memoized subtree cannot bypass the depth bound through a deeper alias edge."""

    shared = {"child": {"leaf": 1}}
    graph = {"short": shared, "long": {"step": {"alias": shared}}}

    with pytest.raises(TimingProfileError, match="depth exceeds limit 4"):
        _freeze_timing_profile_value(graph, limits=_limits(max_depth=4))


def test_fused_provider_capture_uses_pre_growth_mapping_view_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 4096-member capture cannot reread a caller mapping after it grows to 5001."""

    racy = {f"key_{index}": index for index in range(4_096)}
    document = {"racy": racy}
    captured = Event()
    mutated = Event()
    capture_calls = 0
    original_capture = timing_profiles_module._capture_timing_profile_container_items

    def capture_once(value: Any, kind: Any, *, member_limit: int) -> tuple[Any, ...]:
        nonlocal capture_calls
        items = original_capture(value, kind, member_limit=member_limit)
        if value is racy:
            capture_calls += 1
            captured.set()
            if not mutated.wait(timeout=10):
                raise TimeoutError("mapping race did not mutate the caller graph")
        return items

    def grow_mapping() -> None:
        if not captured.wait(timeout=10):
            raise TimeoutError("mapping race did not reach fused capture")
        racy.update({f"key_{index}": index for index in range(4_096, 5_001)})
        mutated.set()

    monkeypatch.setattr(
        timing_profiles_module,
        "_capture_timing_profile_container_items",
        capture_once,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        mutation = executor.submit(grow_mapping)
        with effective_config_scope(
            _effective_timing_config(document),
            refresh_legacy_globals=False,
        ):
            snapshot = load_timing_profiles()
            assert len(snapshot["racy"]) == 4_096
        mutation.result(timeout=10)

    assert len(racy) == 5_001
    assert capture_calls == 1


def test_fused_provider_capture_ignores_cycle_added_after_child_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cycle checks and copying consume the same immutable child capture."""

    racy: dict[str, Any] = {"leaf": 1}
    document = {"racy": racy}
    captured = Event()
    mutated = Event()
    capture_calls = 0
    original_capture = timing_profiles_module._capture_timing_profile_container_items

    def capture_once(value: Any, kind: Any, *, member_limit: int) -> tuple[Any, ...]:
        nonlocal capture_calls
        items = original_capture(value, kind, member_limit=member_limit)
        if value is racy:
            capture_calls += 1
            captured.set()
            if not mutated.wait(timeout=10):
                raise TimeoutError("cycle race did not mutate the caller graph")
        return items

    def add_cycle() -> None:
        if not captured.wait(timeout=10):
            raise TimeoutError("cycle race did not reach fused capture")
        racy["cycle"] = racy
        mutated.set()

    monkeypatch.setattr(
        timing_profiles_module,
        "_capture_timing_profile_container_items",
        capture_once,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        mutation = executor.submit(add_cycle)
        with effective_config_scope(
            _effective_timing_config(document),
            refresh_legacy_globals=False,
        ):
            snapshot = load_timing_profiles()
            assert snapshot["racy"] == {"leaf": 1}
        mutation.result(timeout=10)

    assert racy["cycle"] is racy
    assert capture_calls == 1


def test_equal_and_unequal_compact_dags_use_one_exact_node_pair_per_level() -> None:
    """Structural hashing and equality stay linear in compact DAG nodes, not paths."""

    limits = _limits(max_unique_nodes=256, max_references=512)
    left = _compact_binary_dag(16, {"leaf": "same"})
    equal_right = _compact_binary_dag(16, {"leaf": "same"})
    unequal_right = _compact_binary_dag(16, {"leaf": "different"})

    equal_comparison = _TimingProfileComparison(limits)
    assert _timing_profile_values_equal(
        left,
        equal_right,
        limits=limits,
        comparison=equal_comparison,
    )
    assert equal_comparison._pair_visits == 17

    unequal_comparison = _TimingProfileComparison(limits)
    assert not _timing_profile_values_equal(
        left,
        unequal_right,
        limits=limits,
        comparison=unequal_comparison,
    )
    assert unequal_comparison._pair_visits == 0


@pytest.mark.parametrize(
    ("boundary", "over", "limits", "message"),
    [
        (
            _nested_mapping(4),
            _nested_mapping(5),
            _limits(max_depth=4),
            "depth exceeds limit 4",
        ),
        (
            [0, 1, 2, 3],
            [0, 1, 2, 3, 4],
            _limits(max_container_members=4),
            "container has 5 members",
        ),
        (
            [0, 1],
            [0, 1, 2],
            _limits(max_unique_nodes=3),
            "unique node count exceeds limit 3",
        ),
        (
            [0, 1, 2, 3],
            [0, 1, 2, 3, 4],
            _limits(max_references=4),
            "reference count exceeds limit 4",
        ),
        (
            "1234",
            "12345",
            _limits(max_scalar_bytes=4),
            "scalar exceeds limit 4 bytes",
        ),
        (
            [None],
            [None],
            _limits(max_aggregate_bytes=161),
            "aggregate bytes exceed limit 160",
        ),
    ],
)
def test_graph_budget_accepts_boundary_and_rejects_one_over(
    boundary: Any,
    over: Any,
    limits: _TimingProfileGraphLimits,
    message: str,
) -> None:
    """Every admission budget has an exact accepted boundary and controlled overflow."""

    _freeze_timing_profile_value(boundary, limits=limits)
    rejected_limits = limits
    if message == "aggregate bytes exceed limit 160":
        rejected_limits = _limits(max_aggregate_bytes=160)
    with pytest.raises(TimingProfileError, match=message):
        _freeze_timing_profile_value(over, limits=rejected_limits)


def test_graph_limit_rejection_precedes_alias_warning_and_cache_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An over-budget legacy document cannot reserve warnings or publish a snapshot."""

    authored = _legacy_authored()
    authored["oversized"] = "12345"
    warning_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        timing_profiles_module,
        "_TIMING_PROFILE_GRAPH_LIMITS",
        _limits(max_scalar_bytes=4),
    )
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    monkeypatch.setattr(
        timing_profiles_module,
        "warn_legacy_config",
        lambda legacy, replacement, **_kwargs: warning_calls.append((legacy, replacement)),
    )

    with pytest.raises(TimingProfileError, match="scalar exceeds limit 4 bytes"):
        load_timing_profiles()

    assert warning_calls == []
    assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()
    assert _cache_phase() is _TimingProfileCachePhase.EMPTY


def test_effective_config_depth_cycle_and_hostile_dict_reject_before_copy_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider admission controls hostile timing graphs before generic deepcopy."""

    callback_called = False
    generic_copy_called = False
    type_metadata_called = False

    class HostileType(type):
        def __getattribute__(cls, name: str) -> Any:
            nonlocal type_metadata_called
            if name == "__name__":
                type_metadata_called = True
                raise AssertionError("hostile type metadata executed")
            return type.__getattribute__(cls, name)

    class HostileDict(dict, metaclass=HostileType):
        def __deepcopy__(self, _memo: dict[int, Any]) -> dict[str, Any]:
            nonlocal callback_called
            callback_called = True
            raise AssertionError("hostile deepcopy callback executed")

    documents: tuple[tuple[Any, str], ...] = (
        (_nested_mapping(600), "depth exceeds limit"),
        (HostileDict({"value": 1}), "unsupported scalar type"),
    )
    cycle: dict[str, Any] = {}
    cycle["self"] = cycle
    documents += ((cycle, "recursive YAML alias graph"),)
    project_configs = tuple(
        (_effective_timing_config(document), message) for document, message in documents
    )
    packaged_configs = tuple(
        (_effective_timing_config(packaged_document=document), message)
        for document, message in documents
    )

    def reject_generic_copy(_value: Any) -> Any:
        nonlocal generic_copy_called
        generic_copy_called = True
        raise AssertionError("generic deepcopy executed before timing admission")

    monkeypatch.setattr(config_provider.copy, "deepcopy", reject_generic_copy)

    for effective_config, message in (*project_configs, *packaged_configs):
        with pytest.raises(TimingProfileError, match=message):
            with effective_config_scope(
                effective_config,
                refresh_legacy_globals=False,
            ):
                load_timing_profiles()
        assert _cache_phase() is _TimingProfileCachePhase.EMPTY
        assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()

    assert not callback_called
    assert not generic_copy_called
    assert not type_metadata_called


def test_effective_config_depth_and_member_boundaries_accept_then_reject_one_over() -> None:
    """Real provider scopes enforce exact depth and container-member boundaries."""

    accepted = {
        "depth_boundary": _nested_mapping(31),
        "member_boundary": {f"key_{index}": index for index in range(4_096)},
    }
    accepted_configs = (
        _effective_timing_config(accepted),
        _effective_timing_config(packaged_document=accepted),
    )
    for effective_config in accepted_configs:
        with effective_config_scope(
            effective_config,
            refresh_legacy_globals=False,
        ):
            snapshot = load_timing_profiles()
            assert len(snapshot["member_boundary"]) == 4_096
            node = snapshot["depth_boundary"]
            for _index in range(31):
                node = node["next"]
            assert node == 1

    rejected_documents = (
        ({"depth_over": _nested_mapping(32)}, "depth exceeds limit 32"),
        (
            {"member_over": {f"key_{index}": index for index in range(4_097)}},
            "container has 4097 members",
        ),
    )
    for document, message in rejected_documents:
        rejected_configs = (
            _effective_timing_config(document),
            _effective_timing_config(packaged_document=document),
        )
        for effective_config in rejected_configs:
            with pytest.raises(TimingProfileError, match=message):
                with effective_config_scope(
                    effective_config,
                    refresh_legacy_globals=False,
                ):
                    load_timing_profiles()
            assert _cache_phase() is _TimingProfileCachePhase.EMPTY


def test_effective_config_giant_unique_node_graph_rejects_before_copy() -> None:
    """A shallow exact-builtins graph cannot exceed the unique-node budget."""

    branches = [list(range(index * 4_096, (index + 1) * 4_096)) for index in range(65)]
    document = {"node_over": branches}

    with pytest.raises(TimingProfileError, match="unique node count exceeds limit 262144"):
        with effective_config_scope(
            _effective_timing_config(document),
            refresh_legacy_globals=False,
        ):
            load_timing_profiles()
    assert _cache_phase() is _TimingProfileCachePhase.EMPTY
    assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()


def test_effective_config_alias_dag_is_detached_and_preserved_across_provider_copy() -> None:
    """Provider admission copies a shared DAG once without retaining caller ownership."""

    shared = {"nested": {"value": 1}}
    document = {"provider_dag": {"left": shared, "right": shared}}
    original = deepcopy(document)

    with effective_config_scope(
        _effective_timing_config(document),
        refresh_legacy_globals=False,
    ):
        snapshot = load_timing_profiles()
        graph = snapshot["provider_dag"]
        assert graph["left"] is graph["right"]
        assert document == original
        shared["nested"]["value"] = 99
        assert graph["left"]["nested"]["value"] == 1


def test_effective_config_packaged_project_merge_memoizes_compact_binary_dag() -> None:
    """Pair memoization prevents a compact two-layer DAG from expanding by path count."""

    packaged_leaf = {"winner": "packaged", "kept": "yes"}
    project_leaf = {"winner": "project"}
    packaged = {"merge_product": _compact_binary_dag(16, packaged_leaf)}
    project = {"merge_product": _compact_binary_dag(16, project_leaf)}
    packaged_original = deepcopy(packaged)
    project_original = deepcopy(project)

    with effective_config_scope(
        _effective_timing_config(project, packaged_document=packaged),
        refresh_legacy_globals=False,
    ):
        snapshot = load_timing_profiles()
        graph = snapshot["merge_product"]
        for _index in range(16):
            assert graph["left"] is graph["right"]
            graph = graph["left"]
        assert graph == {"winner": "project", "kept": "yes"}
        stats = _preflight_timing_profile_graph(snapshot)
        assert stats.unique_nodes < 100
        assert stats.references < 100

        assert packaged == packaged_original
        assert project == project_original
        packaged_leaf["kept"] = "changed"
        project_leaf["winner"] = "changed"
        assert graph == {"winner": "project", "kept": "yes"}


def test_repeated_aliases_detach_input_preserve_snapshot_sharing_and_deepcopy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalization never mutates input and snapshot/deepcopy retain DAG sharing."""

    authored = _legacy_authored(shared_profiles=True)
    original = deepcopy(authored)
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        snapshot = load_timing_profiles()

    profiles = snapshot["network_sensor_observation"]["profiles"]
    assert authored == original
    assert profiles["branch"] is profiles["branch_secondary"]
    assert profiles["branch"]["clock_offset_us"] == {"min": -25, "max": 25}
    assert "clock_skew_us" not in profiles["branch"]
    assert len(_legacy_warnings(caught)) == 2

    authored_profile = authored["network_sensor_observation"]["profiles"]["branch"]
    authored_profile["clock_skew_us"]["min"] = -999
    assert profiles["branch"]["clock_offset_us"]["min"] == -25

    mutable = deepcopy(snapshot)
    mutable_profiles = mutable["network_sensor_observation"]["profiles"]
    assert mutable_profiles["branch"] is mutable_profiles["branch_secondary"]
    mutable_profiles["branch"]["clock_offset_us"]["min"] = -100
    assert profiles["branch"]["clock_offset_us"]["min"] == -25


def test_cached_snapshot_is_non_dict_mapping_immune_to_every_base_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No public, dict-base, tuple-storage, attribute, or nested path mutates the cache."""

    authored = {
        "root": {
            "nested": {"value": 1},
            "items": [{"value": 2}],
            "tags": {"one", "two"},
        }
    }
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    snapshot = load_timing_profiles()
    root = snapshot["root"]
    nested = root["nested"]

    assert isinstance(snapshot, Mapping)
    assert isinstance(snapshot, _FrozenTimingProfileMapping)
    assert not isinstance(snapshot, dict)
    assert load_timing_profiles() is snapshot
    assert isinstance(root["items"], tuple)
    assert isinstance(root["tags"], frozenset)

    mutations = (
        lambda: snapshot.__setitem__("poison", 1),
        lambda: snapshot.__delitem__("root"),
        lambda: snapshot.update({"poison": 1}),
        lambda: snapshot.clear(),
        lambda: snapshot.pop("root"),
        lambda: snapshot.popitem(),
        lambda: snapshot.setdefault("poison", 1),
        lambda: snapshot.__ior__({"poison": 1}),
        lambda: dict.__setitem__(snapshot, "poison", 1),
        lambda: dict.update(snapshot, {"poison": 1}),
        lambda: dict.__delitem__(snapshot, "root"),
        lambda: dict.__init__(snapshot, {"poison": 1}),
        lambda: dict.__ior__(snapshot, {"poison": 1}),
        lambda: dict.clear(snapshot),
        lambda: dict.pop(snapshot, "root"),
        lambda: dict.popitem(snapshot),
        lambda: dict.setdefault(snapshot, "poison", 1),
        lambda: dict.__setitem__(nested, "value", 9),
        lambda: dict.__delitem__(nested, "value"),
        lambda: nested.__setitem__("value", 9),
        lambda: root["items"].__setitem__(0, None),
        lambda: root["tags"].add("poison"),
        lambda: object.__setattr__(snapshot, "_storage", ()),
        lambda: object.__delattr__(snapshot, "_storage"),
    )
    for mutate in mutations:
        with pytest.raises((AttributeError, TypeError)):
            mutate()
        assert load_timing_profiles() is snapshot
        assert snapshot["root"]["nested"]["value"] == 1
        assert "poison" not in snapshot

    mutable = deepcopy(snapshot)
    mutable["root"]["nested"]["value"] = 9
    mutable["root"]["items"][0]["value"] = 10
    assert snapshot["root"]["nested"]["value"] == 1
    assert snapshot["root"]["items"][0]["value"] == 2


def test_public_load_normalizes_aliases_once_per_process_across_cache_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Canonical immutable snapshots reload while warning reservations remain process-wide."""

    _write_legacy_overlay(tmp_path)
    monkeypatch.chdir(tmp_path)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        first = load_timing_profiles()
        assert load_timing_profiles() is first
        reset_timing_profiles_cache()
        second = load_timing_profiles()

    profile = second["network_sensor_observation"]["profiles"]["branch"]
    assert first is not second
    assert first == second
    assert profile["clock_offset_us"] == {"min": -25, "max": 25}
    assert profile["route_delay_us"] == {"min": 50, "max": 500}
    assert "clock_skew_us" not in profile
    assert "path_delay_us" not in profile
    assert len(_legacy_warnings(caught)) == 2


def test_canonical_and_legacy_conflict_fails_before_warning_and_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mixed-value alias conflict leaves an exact empty cache and no reservation."""

    authored = _legacy_authored()
    profile = authored["network_sensor_observation"]["profiles"]["branch"]
    profile["clock_offset_us"] = {"min": -50, "max": 50}
    warning_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    monkeypatch.setattr(
        timing_profiles_module,
        "warn_legacy_config",
        lambda legacy, replacement, **_kwargs: warning_calls.append((legacy, replacement)),
    )

    with pytest.raises(TimingProfileError, match="conflicting.*clock_skew_us.*clock_offset_us"):
        load_timing_profiles()
    assert warning_calls == []
    assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()
    assert _cache_phase() is _TimingProfileCachePhase.EMPTY

    profile["clock_offset_us"] = profile["clock_skew_us"]
    timing = network_sensor_observation_timing("branch")
    assert timing.clock_offset_min_us == -25
    assert timing.route_delay_max_us == 500


def test_equal_canonical_and_legacy_values_collapse_to_canonical_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Equal duplicate spellings publish only under the canonical name."""

    authored = _legacy_authored()
    profile = authored["network_sensor_observation"]["profiles"]["branch"]
    profile["clock_offset_us"] = deepcopy(profile["clock_skew_us"])
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        snapshot = load_timing_profiles()

    normalized = snapshot["network_sensor_observation"]["profiles"]["branch"]
    assert normalized["clock_offset_us"] == {"min": -25, "max": 25}
    assert "clock_skew_us" not in normalized
    assert len(_legacy_warnings(caught)) == 2


def test_warning_as_error_rolls_back_publication_and_exact_retry_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Promoted warnings fail one attempt without poisoning an exact retry."""

    authored = _legacy_authored()
    load_calls: list[int] = []
    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored, load_calls),
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error", EvidenceForgeDeprecationWarning)
        with pytest.raises(EvidenceForgeDeprecationWarning):
            load_timing_profiles()
        assert _cache_phase() is _TimingProfileCachePhase.EMPTY
        assert timing_profiles_module._CACHED_TIMING_PROFILES.state.snapshot is None
        assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        recovered = load_timing_profiles()

    assert len(load_calls) == 2
    assert len(_legacy_warnings(caught)) == 2
    assert load_timing_profiles() is recovered
    assert timing_profiles_module._CACHED_TIMING_PROFILES.state.snapshot is recovered


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeError("warning callback failed"),
        ValueError("warning callback failed"),
        KeyboardInterrupt("warning callback failed"),
    ],
    ids=("runtime-error", "value-error", "base-exception"),
)
def test_warning_callback_failure_rolls_back_reservations_and_reemits_on_retry(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    """Every callback failure leaves no cache or ledger state for the retry."""

    authored = _legacy_authored()
    load_calls: list[int] = []
    delivered: list[str] = []

    def fail_warning_callback(
        message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        delivered.append(str(message))
        raise failure

    def record_warning_callback(
        message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        delivered.append(str(message))

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored, load_calls),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", fail_warning_callback)
        with pytest.raises(type(failure), match="warning callback failed"):
            load_timing_profiles()
        assert _cache_phase() is _TimingProfileCachePhase.EMPTY
        assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()

        monkeypatch.setattr(warnings, "showwarning", record_warning_callback)
        recovered = load_timing_profiles()

    assert len(load_calls) == 2
    assert load_timing_profiles() is recovered
    assert len(delivered) == 3
    assert sum("clock_skew_us" in message for message in delivered) == 2
    assert sum("path_delay_us" in message for message in delivered) == 1


def test_warning_failure_rolls_back_only_aliases_reserved_by_current_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed attempt cannot erase an alias successfully warned by an earlier load."""

    authored = _legacy_authored()
    delivered: list[str] = []
    timing_profiles_module._set_timing_profile_warned_aliases_for_tests(
        frozenset({"clock_skew_us"})
    )

    def fail_warning_callback(
        message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        delivered.append(str(message))
        raise ValueError("warning callback failed")

    def record_warning_callback(
        message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        delivered.append(str(message))

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", fail_warning_callback)
        with pytest.raises(ValueError, match="warning callback failed"):
            load_timing_profiles()
        assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset({"clock_skew_us"})
        assert _cache_phase() is _TimingProfileCachePhase.EMPTY

        monkeypatch.setattr(warnings, "showwarning", record_warning_callback)
        recovered = load_timing_profiles()

    assert load_timing_profiles() is recovered
    assert len(delivered) == 2
    assert all("path_delay_us" in message for message in delivered)


def test_same_thread_warning_hook_reentry_reconciles_loader_and_provider_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-thread hooks reuse prepared state without recursive warning delivery."""

    authored = _legacy_authored()
    load_calls: list[int] = []
    nested_snapshots: list[Mapping[str, Any]] = []

    def reenter_from_showwarning(
        _message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        nested_snapshots.append(load_timing_profiles())
        with effective_config_scope(
            _effective_timing_config({"scope_marker": 2}),
            refresh_legacy_globals=False,
        ):
            nested_snapshots.append(load_timing_profiles())

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored, load_calls),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", reenter_from_showwarning)
        snapshot = load_timing_profiles()

    assert len(nested_snapshots) == 4
    assert nested_snapshots[0] is snapshot
    assert nested_snapshots[2] is snapshot
    assert len(load_calls) == 4
    assert load_timing_profiles() is snapshot


def test_provider_preparation_reentry_cannot_be_restored_as_ambient_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-thread warning load cannot leak its provider snapshot after scope exit."""

    nested_snapshots: list[Mapping[str, Any]] = []

    def legacy_marker_loader(
        package_path: Path,
        overlay_subpath: str,
        merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        marker = _marker_loader(package_path, overlay_subpath, merge_fn)["scope_marker"]
        return {**_legacy_authored(), "scope_marker": marker}

    def reenter_from_showwarning(
        _message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        nested_snapshots.append(load_timing_profiles())

    provider = SimpleNamespace(
        marker=2,
        ambient_overlay_compat=False,
        packaged_defaults={},
        project_overlays={},
    )
    monkeypatch.setattr(timing_profiles_module, "load_with_overlay", legacy_marker_loader)
    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", reenter_from_showwarning)
        with effective_config_scope(provider, refresh_legacy_globals=False):
            scoped = load_timing_profiles()

    ambient = load_timing_profiles()
    assert [snapshot["scope_marker"] for snapshot in nested_snapshots] == [2, 2]
    assert scoped["scope_marker"] == 2
    assert ambient["scope_marker"] == 0
    assert all(snapshot is not ambient for snapshot in nested_snapshots)


def test_warning_hook_joins_public_loader_and_provider_threads_outside_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Warning callbacks can synchronously join both public entry paths."""

    authored = _legacy_authored()
    hook_calls = 0
    nested_snapshots: list[Mapping[str, Any]] = []

    def scoped_load() -> Mapping[str, Any]:
        with effective_config_scope(
            _effective_timing_config({"scope_marker": 2}),
            refresh_legacy_globals=False,
        ):
            return load_timing_profiles()

    def join_threads_from_showwarning(
        _message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        nonlocal hook_calls
        hook_calls += 1
        assert not config_provider._CONFIG_EXECUTION_LOCK._is_owned()
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
        with ThreadPoolExecutor(max_workers=2) as executor:
            loader_future = executor.submit(load_timing_profiles)
            provider_future = executor.submit(scoped_load)
            nested_snapshots.append(loader_future.result(timeout=10))
            nested_snapshots.append(provider_future.result(timeout=10))

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", join_threads_from_showwarning)
        snapshot = load_timing_profiles()

    assert hook_calls == 2
    assert len(nested_snapshots) == 4
    assert nested_snapshots[0] is snapshot
    assert nested_snapshots[2] is snapshot
    assert load_timing_profiles() is snapshot


def test_warning_hook_failure_invalidates_snapshot_published_by_joined_loader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A joined provisional publication cannot survive its warning callback failure."""

    authored = _legacy_authored()
    nested_snapshots: list[Mapping[str, Any]] = []
    delivered: list[str] = []

    def publish_then_fail(
        message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        delivered.append(str(message))
        with ThreadPoolExecutor(max_workers=1) as executor:
            nested_snapshots.append(executor.submit(load_timing_profiles).result(timeout=10))
        raise ValueError("joined warning callback failed")

    def record_warning(
        message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        delivered.append(str(message))

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(authored),
    )
    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        monkeypatch.setattr(warnings, "showwarning", publish_then_fail)
        with pytest.raises(ValueError, match="joined warning callback failed"):
            load_timing_profiles()
        assert len(nested_snapshots) == 1
        assert _cache_phase() is _TimingProfileCachePhase.EMPTY
        assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()

        monkeypatch.setattr(warnings, "showwarning", record_warning)
        recovered = load_timing_profiles()

    assert load_timing_profiles() is recovered
    assert len(delivered) == 3


def test_32_concurrent_callers_optimistically_reconcile_five_epochs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent optimistic preparations reconcile to one snapshot per epoch."""

    authored = _legacy_authored(shared_profiles=True)
    state_lock = Lock()
    load_count = 0
    warning_calls: list[tuple[str, str]] = []
    preparation_barrier: Barrier | None = None

    def synchronized_loader(
        _package_path: Path,
        _overlay_subpath: str,
        _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        nonlocal load_count
        with state_lock:
            load_count += 1
        barrier = preparation_barrier
        if barrier is None:  # pragma: no cover - guarded by each test round
            raise RuntimeError("timing-profile preparation barrier is not installed")
        barrier.wait(timeout=10)
        return authored

    def record_warning(legacy: str, replacement: str, *, stacklevel: int = 3) -> None:
        del stacklevel
        with state_lock:
            warning_calls.append((legacy, replacement))

    def load_after_barrier(barrier: Barrier) -> tuple[Mapping[str, Any], ...]:
        barrier.wait(timeout=10)
        return tuple(load_timing_profiles() for _index in range(5))

    monkeypatch.setattr(timing_profiles_module, "load_with_overlay", synchronized_loader)
    monkeypatch.setattr(timing_profiles_module, "warn_legacy_config", record_warning)
    epoch_snapshots: list[Mapping[str, Any]] = []
    with ThreadPoolExecutor(max_workers=32) as executor:
        for _round_index in range(5):
            reset_timing_profiles_cache()
            preparation_barrier = Barrier(32)
            barrier = Barrier(32)
            futures = [executor.submit(load_after_barrier, barrier) for _index in range(32)]
            results = [future.result(timeout=10) for future in futures]
            first = results[0][0]
            assert all(snapshot is first for result in results for snapshot in result)
            epoch_snapshots.append(first)

    assert load_count == 160
    assert len({id(snapshot) for snapshot in epoch_snapshots}) == 5
    assert len(warning_calls) == 2


def test_optimistic_work_and_callbacks_are_bounded_across_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prepublication work is per caller while reserved callbacks remain process-once."""

    from evidenceforge.config import overlay as overlay_module

    default = {**_legacy_authored(shared_profiles=True), "replace_me": 1}
    overlay = {"replace_me": 2}
    state_lock = Lock()
    preparation_barrier: Barrier | None = None
    build_count = 0
    ambient_info_states: list[tuple[bool, bool]] = []
    diagnostic_calls: list[str] = []
    warning_calls: list[tuple[str, str]] = []

    class AmbientInfoHandler(logging.Handler):
        def emit(self, _record: logging.LogRecord) -> None:
            ambient_info_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )

    def synchronized_layered_loader(
        _package_path: Path,
        _overlay_subpath: str,
        merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        nonlocal build_count
        with state_lock:
            build_count += 1
        overlay_module.logger.info("Merging trusted timing overlay")
        barrier = preparation_barrier
        if barrier is None:  # pragma: no cover - guarded by each test epoch
            raise RuntimeError("optimistic preparation barrier is not installed")
        barrier.wait(timeout=10)
        return merge_fn(deepcopy(default), deepcopy(overlay))

    def record_diagnostic(message: str, *args: Any, **_kwargs: Any) -> None:
        rendered = message % args if args else message
        with state_lock:
            diagnostic_calls.append(rendered)

    def record_warning(legacy: str, replacement: str, *, stacklevel: int = 3) -> None:
        del stacklevel
        with state_lock:
            warning_calls.append((legacy, replacement))

    def load_after_start(start: Barrier) -> Mapping[str, Any]:
        start.wait(timeout=10)
        return load_timing_profiles()

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        synchronized_layered_loader,
    )
    monkeypatch.setattr(timing_profiles_module.logger, "warning", record_diagnostic)
    monkeypatch.setattr(timing_profiles_module, "warn_legacy_config", record_warning)
    handler = AmbientInfoHandler()
    original_level = overlay_module.logger.level
    overlay_module.logger.setLevel(logging.INFO)
    overlay_module.logger.addHandler(handler)
    epoch_snapshots: list[Mapping[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=32) as executor:
            for _epoch in range(2):
                reset_timing_profiles_cache()
                preparation_barrier = Barrier(32)
                start = Barrier(32)
                futures = [executor.submit(load_after_start, start) for _index in range(32)]
                snapshots = [future.result(timeout=10) for future in futures]
                assert all(snapshot is snapshots[0] for snapshot in snapshots)
                epoch_snapshots.append(snapshots[0])
    finally:
        overlay_module.logger.removeHandler(handler)
        overlay_module.logger.setLevel(original_level)

    assert build_count == 64
    assert ambient_info_states == [(False, False)] * 64
    assert len(diagnostic_calls) == 1
    assert len(warning_calls) == 2
    assert epoch_snapshots[0] is not epoch_snapshots[1]


def test_reset_invalidates_inflight_optimistic_preparation_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reset generation forces an older optimistic candidate to rebuild."""

    authored = {"relationships": {"test": {"min_ms": 1, "max_ms": 2}}}
    initializer_started = Event()
    initializer_release = Event()
    reset_started = Event()
    reset_finished = Event()
    load_count = 0

    def blocking_loader(
        _package_path: Path,
        _overlay_subpath: str,
        _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        nonlocal load_count
        load_count += 1
        if load_count == 1:
            initializer_started.set()
            if not initializer_release.wait(timeout=10):
                raise TimeoutError("timing-profile reset test did not release initializer")
        return authored

    def reset_cache() -> None:
        reset_started.set()
        reset_timing_profiles_cache()
        reset_finished.set()

    monkeypatch.setattr(timing_profiles_module, "load_with_overlay", blocking_loader)
    with ThreadPoolExecutor(max_workers=2) as executor:
        load_future = executor.submit(load_timing_profiles)
        assert initializer_started.wait(timeout=10)
        reset_future = executor.submit(reset_cache)
        assert reset_started.wait(timeout=10)
        assert reset_finished.wait(timeout=10)
        initializer_release.set()
        reset_future.result(timeout=10)
        published = load_future.result(timeout=10)

    assert reset_finished.is_set()
    assert _cache_phase() is _TimingProfileCachePhase.READY
    assert load_timing_profiles() is published
    assert load_count == 2


def test_provider_scopes_load_marker_one_then_two_and_restore_base_identity() -> None:
    """Sequential provider scopes receive isolated snapshots and restore the exact base."""

    base = load_timing_profiles()
    assert base.get("scope_marker", 0) == 0

    with effective_config_scope(
        _effective_timing_config({"scope_marker": 1}),
        refresh_legacy_globals=False,
    ):
        first = load_timing_profiles()
        assert first["scope_marker"] == 1
        assert load_timing_profiles() is first
    assert load_timing_profiles() is base

    with effective_config_scope(
        _effective_timing_config({"scope_marker": 2}),
        refresh_legacy_globals=False,
    ):
        second = load_timing_profiles()
        assert second["scope_marker"] == 2
        assert second is not first
    assert load_timing_profiles() is base


def test_nested_provider_scope_restores_outer_then_base_snapshot_identity() -> None:
    """Nested provider save/clear/restore is exact at both unwind boundaries."""

    base = load_timing_profiles()
    with effective_config_scope(
        _effective_timing_config({"scope_marker": 1}),
        refresh_legacy_globals=False,
    ):
        outer = load_timing_profiles()
        with effective_config_scope(
            _effective_timing_config({"scope_marker": 2}),
            refresh_legacy_globals=False,
        ):
            inner = load_timing_profiles()
            assert inner["scope_marker"] == 2
            assert inner is not outer
        assert load_timing_profiles() is outer
        assert outer["scope_marker"] == 1
    assert load_timing_profiles() is base


def test_concurrent_provider_scopes_serialize_without_marker_or_cache_leakage() -> None:
    """Overlapping scope attempts serialize and each observes only its own marker."""

    base = load_timing_profiles()
    first_entered = Event()
    first_release = Event()
    second_attempted = Event()
    second_entered = Event()

    def first_scope() -> tuple[int, int]:
        with effective_config_scope(
            _effective_timing_config({"scope_marker": 1}),
            refresh_legacy_globals=False,
        ):
            snapshot = load_timing_profiles()
            first_entered.set()
            if not first_release.wait(timeout=10):
                raise TimeoutError("provider scope test did not release first scope")
            return int(snapshot["scope_marker"]), id(snapshot)

    def second_scope() -> tuple[int, int]:
        assert first_entered.wait(timeout=10)
        second_attempted.set()
        with effective_config_scope(
            _effective_timing_config({"scope_marker": 2}),
            refresh_legacy_globals=False,
        ):
            second_entered.set()
            snapshot = load_timing_profiles()
            return int(snapshot["scope_marker"]), id(snapshot)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(first_scope)
        second_future = executor.submit(second_scope)
        assert second_attempted.wait(timeout=10)
        assert not second_entered.wait(timeout=0.05)
        first_release.set()
        first_result = first_future.result(timeout=10)
        second_result = second_future.result(timeout=10)

    assert first_result[0] == 1
    assert second_result[0] == 2
    assert first_result[1] != second_result[1]
    assert load_timing_profiles() is base


def test_provider_scope_isolates_concurrent_optimistic_load_and_restores_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scope can run during preparation without leaking its publication or generation."""

    initializer_started = Event()
    initializer_release = Event()
    scope_attempted = Event()
    scope_entered = Event()
    load_count = 0

    def blocking_marker_loader(
        package_path: Path,
        overlay_subpath: str,
        merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        nonlocal load_count
        load_count += 1
        if load_count == 1:
            initializer_started.set()
            if not initializer_release.wait(timeout=10):
                raise TimeoutError("provider inflight test did not release initializer")
        return _marker_loader(package_path, overlay_subpath, merge_fn)

    def scoped_load() -> Mapping[str, Any]:
        scope_attempted.set()
        with effective_config_scope(SimpleNamespace(marker=2), refresh_legacy_globals=False):
            scope_entered.set()
            return load_timing_profiles()

    monkeypatch.setattr(timing_profiles_module, "load_with_overlay", blocking_marker_loader)
    with ThreadPoolExecutor(max_workers=2) as executor:
        base_future = executor.submit(load_timing_profiles)
        assert initializer_started.wait(timeout=10)
        scope_future = executor.submit(scoped_load)
        assert scope_attempted.wait(timeout=10)
        assert scope_entered.wait(timeout=10)
        scoped = scope_future.result(timeout=10)
        initializer_release.set()
        base = base_future.result(timeout=10)

    assert base["scope_marker"] == 0
    assert scoped["scope_marker"] == 2
    assert load_timing_profiles() is base
    assert load_count == 2


@pytest.mark.parametrize("failure_index", range(3), ids=("first", "middle", "last"))
@pytest.mark.parametrize(
    "failure_type",
    [KeyboardInterrupt, SystemExit, RuntimeError],
    ids=("keyboard-interrupt", "system-exit", "runtime-error"),
)
def test_partial_cache_clear_restores_every_ordered_snapshot_and_exact_retry(
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
    failure_type: type[BaseException],
) -> None:
    """A fail-first/middle/last clear is one rollback-safe transaction."""

    log: list[tuple[str, str]] = []
    coordinators = tuple(
        _FaultingRuntimeCacheCoordinator(name, log) for name in ("zero", "one", "two")
    )
    _install_faulting_runtime_caches(monkeypatch, coordinators)
    initial_states = tuple(coordinator.state for coordinator in coordinators)
    failure = failure_type(f"clear failed at {failure_index}")
    coordinators[failure_index].clear_failures[1] = failure
    effective = _effective_timing_config()

    with pytest.raises(failure_type) as caught:
        with effective_config_scope(effective):
            pytest.fail("scope body ran after a failed cache clear")

    assert caught.value is failure
    assert log == [
        *(("snapshot", coordinator.name) for coordinator in coordinators),
        *(("clear", coordinator.name) for coordinator in coordinators),
        *(("restore", coordinator.name) for coordinator in coordinators),
    ]
    assert tuple(coordinator.clear_calls for coordinator in coordinators) == (1, 1, 1)
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (1, 1, 1)
    assert tuple(coordinator.state for coordinator in coordinators) == initial_states
    assert coordinators[failure_index].cleared_states == [
        f"cleared-{coordinators[failure_index].name}-1"
    ]
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    coordinators[failure_index].clear_failures.clear()
    with effective_config_scope(effective):
        assert current_effective_config() is effective
    assert tuple(coordinator.state for coordinator in coordinators) == initial_states
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (2, 2, 2)
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize(
    "failure_type",
    [KeyboardInterrupt, SystemExit],
    ids=("keyboard-interrupt", "system-exit"),
)
def test_direct_runtime_cache_clear_rolls_back_baseexception_and_releases_lease(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    """The standalone clearing helper cannot strand a mutated coordinator."""

    coordinator = _FaultingRuntimeCacheCoordinator("direct")
    _install_faulting_runtime_caches(monkeypatch, (coordinator,))
    failure = failure_type("direct clear failed")
    coordinator.clear_failures[1] = failure

    with pytest.raises(failure_type) as caught:
        config_provider._clear_runtime_caches()

    assert caught.value is failure
    assert coordinator.cleared_states == ["cleared-direct-1"]
    assert coordinator.restored_snapshots == ["saved-direct"]
    assert coordinator.state == "saved-direct"
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize(
    "failure_type",
    [KeyboardInterrupt, SystemExit],
    ids=("keyboard-interrupt", "system-exit"),
)
def test_clear_primary_wins_over_restore_failure_and_all_snapshots_are_attempted(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    """Rollback failures are diagnostic and never replace the setup primary."""

    log: list[tuple[str, str]] = []
    coordinators = tuple(
        _FaultingRuntimeCacheCoordinator(name, log) for name in ("zero", "one", "two")
    )
    _install_faulting_runtime_caches(monkeypatch, coordinators)
    primary = failure_type("setup clear primary")
    restore_failure = ValueError("restore also failed")
    coordinators[1].clear_failures[1] = primary
    coordinators[0].restore_failures[1] = restore_failure

    with pytest.raises(failure_type) as caught:
        with effective_config_scope(_effective_timing_config()):
            pytest.fail("scope body ran after a failed cache clear")

    assert caught.value is primary
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (1, 1, 1)
    assert tuple(coordinator.state for coordinator in coordinators) == (
        "saved-zero",
        "saved-one",
        "saved-two",
    )
    assert any("runtime-cache restoration" in note for note in primary.__notes__)
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize("failure_index", range(3), ids=("first", "middle", "last"))
def test_normal_scope_restore_attempts_all_and_propagates_exact_ordered_failure(
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
) -> None:
    """A normal exit restores every coordinator before raising its first failure."""

    log: list[tuple[str, str]] = []
    coordinators = tuple(
        _FaultingRuntimeCacheCoordinator(name, log) for name in ("zero", "one", "two")
    )
    _install_faulting_runtime_caches(monkeypatch, coordinators)
    failure = RuntimeError(f"restore failed at {failure_index}")
    coordinators[failure_index].restore_failures[1] = failure

    with pytest.raises(RuntimeError) as caught:
        with effective_config_scope(_effective_timing_config()):
            assert current_effective_config() is not None

    assert caught.value is failure
    assert log == [
        *(("snapshot", coordinator.name) for coordinator in coordinators),
        *(("clear", coordinator.name) for coordinator in coordinators),
        *(("clear", coordinator.name) for coordinator in coordinators),
        *(("restore", coordinator.name) for coordinator in coordinators),
    ]
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (1, 1, 1)
    assert tuple(coordinator.state for coordinator in coordinators) == (
        "saved-zero",
        "saved-one",
        "saved-two",
    )
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    coordinators[failure_index].restore_failures.clear()
    retry_config = _effective_timing_config()
    with effective_config_scope(retry_config):
        assert current_effective_config() is retry_config
    assert tuple(coordinator.state for coordinator in coordinators) == (
        "saved-zero",
        "saved-one",
        "saved-two",
    )


def test_multiple_restore_failures_preserve_first_and_attempt_every_coordinator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first restore failure wins while later restore failures become notes."""

    coordinators = tuple(_FaultingRuntimeCacheCoordinator(name) for name in ("zero", "one", "two"))
    _install_faulting_runtime_caches(monkeypatch, coordinators)
    failures = tuple(RuntimeError(f"restore-{index}") for index in range(3))
    for coordinator, failure in zip(coordinators, failures, strict=True):
        coordinator.restore_failures[1] = failure

    with pytest.raises(RuntimeError) as caught:
        with effective_config_scope(_effective_timing_config()):
            pass

    assert caught.value is failures[0]
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (1, 1, 1)
    assert len(failures[0].__notes__) == 2
    assert tuple(coordinator.state for coordinator in coordinators) == (
        "saved-zero",
        "saved-one",
        "saved-two",
    )
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize(
    "failure_type",
    [KeyboardInterrupt, SystemExit],
    ids=("keyboard-interrupt", "system-exit"),
)
def test_body_primary_wins_over_clear_and_restore_cleanup_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    """Cleanup is exhaustive but cannot mask a BaseException from the body."""

    coordinators = tuple(_FaultingRuntimeCacheCoordinator(name) for name in ("zero", "one", "two"))
    _install_faulting_runtime_caches(monkeypatch, coordinators)
    cleanup_clear_failure = ValueError("cleanup clear failed")
    restore_failure = RuntimeError("cleanup restore failed")
    coordinators[0].clear_failures[2] = cleanup_clear_failure
    coordinators[1].restore_failures[1] = restore_failure
    primary = failure_type("scope body primary")

    with pytest.raises(failure_type) as caught:
        with effective_config_scope(_effective_timing_config()):
            raise primary

    assert caught.value is primary
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (1, 1, 1)
    assert tuple(coordinator.state for coordinator in coordinators) == (
        "saved-zero",
        "saved-one",
        "saved-two",
    )
    assert len(primary.__notes__) == 2
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


def test_nested_clear_failure_restores_outer_state_then_allows_exact_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An inner failed setup restores its outer cache namespace and context."""

    coordinator = _FaultingRuntimeCacheCoordinator("nested")
    _install_faulting_runtime_caches(monkeypatch, (coordinator,))
    outer = _effective_timing_config()
    inner = _effective_timing_config()

    with effective_config_scope(outer):
        outer_state = coordinator.state
        assert outer_state == "cleared-nested-1"
        failure = SystemExit("inner clear failed")
        coordinator.clear_failures[2] = failure
        with pytest.raises(SystemExit) as caught:
            with effective_config_scope(inner):
                pytest.fail("inner scope body ran after its failed cache clear")
        assert caught.value is failure
        assert current_effective_config() is outer
        assert coordinator.state == outer_state

        coordinator.clear_failures.clear()
        with effective_config_scope(inner):
            assert current_effective_config() is inner
        assert current_effective_config() is outer
        assert coordinator.state == outer_state

    assert coordinator.state == "saved-nested"
    assert coordinator.restore_calls == 3
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


def test_concurrent_scope_retries_after_blocked_partial_clear_baseexception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A waiting scope enters only after failed setup restores and releases its lease."""

    coordinator = _FaultingRuntimeCacheCoordinator("concurrent")
    _install_faulting_runtime_caches(monkeypatch, (coordinator,))
    failure = KeyboardInterrupt("first concurrent clear failed")
    coordinator.block_clear_call = 1
    coordinator.clear_failures[1] = failure
    second_attempted = Event()
    second_entered = Event()
    failed_thread_state: list[tuple[BaseException, Any | None, bool]] = []
    first = _effective_timing_config()
    second = _effective_timing_config()

    def failing_scope() -> None:
        try:
            with effective_config_scope(first):
                pytest.fail("failed concurrent scope unexpectedly entered")
        except BaseException as caught:
            failed_thread_state.append(
                (
                    caught,
                    current_effective_config(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            raise

    def waiting_scope() -> Any:
        second_attempted.set()
        with effective_config_scope(second):
            second_entered.set()
            return current_effective_config()

    with ThreadPoolExecutor(max_workers=2) as executor:
        failed_future = executor.submit(failing_scope)
        assert coordinator.clear_started.wait(timeout=10)
        waiting_future = executor.submit(waiting_scope)
        assert second_attempted.wait(timeout=10)
        assert not second_entered.wait(timeout=0.05)
        coordinator.clear_release.set()
        with pytest.raises(KeyboardInterrupt) as caught:
            failed_future.result(timeout=10)
        observed_second = waiting_future.result(timeout=10)

    assert caught.value is failure
    assert failed_thread_state == [(failure, None, False)]
    assert observed_second is second
    assert second_entered.is_set()
    assert coordinator.restore_calls == 2
    assert coordinator.state == "saved-concurrent"
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


def test_scope_cleanup_rescans_and_clears_real_lazily_imported_beacon_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module first imported inside a scope cannot retain its provider data."""

    module_name = "evidenceforge.config.beacon_profiles"
    config_package = importlib.import_module("evidenceforge.config")
    missing_package_attribute = object()
    prior_package_attribute = vars(config_package).get(
        "beacon_profiles",
        missing_package_attribute,
    )
    prior_module = sys.modules.pop(module_name, None)
    imported_module: Any | None = None
    effective = _effective_timing_config()

    try:
        with effective_config_scope(effective):
            imported_module = importlib.import_module(module_name)

            def marker_loader(
                _package_path: Path,
                _overlay_subpath: str,
                _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
            ) -> dict[str, Any]:
                marker = "scoped" if current_effective_config() is effective else "base"
                return {"profiles": {"marker": {"value": marker}}}

            monkeypatch.setattr(imported_module, "load_with_overlay", marker_loader)
            inside = imported_module.load_beacon_profiles()
            assert inside["profiles"]["marker"]["value"] == "scoped"

        assert imported_module._CACHED_DATA is None
        outside = imported_module.load_beacon_profiles()
        assert outside["profiles"]["marker"]["value"] == "base"
        assert outside is not inside
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    finally:
        if imported_module is not None:
            imported_module.reset_beacon_profiles_cache()
        if prior_module is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior_module
        if prior_package_attribute is missing_package_attribute:
            vars(config_package).pop("beacon_profiles", None)
        else:
            vars(config_package)["beacon_profiles"] = prior_package_attribute


def test_cleanup_coordinator_keyboardinterrupt_still_clears_real_storage_lru(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A coordinator failure cannot skip a later production derived-cache clear."""

    from evidenceforge.generation import storage_world

    storage_world._load_catalog_config.cache_clear()
    coordinator = _FaultingRuntimeCacheCoordinator("storage")
    _install_faulting_runtime_caches(monkeypatch, (coordinator,))
    effective = _effective_timing_config()
    failure = KeyboardInterrupt("coordinator cleanup failed")
    coordinator.clear_failures[2] = failure

    def marker_loader(
        _package_path: Path,
        _overlay_subpath: str,
        _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        marker = "scoped" if current_effective_config() is effective else "base"
        return {"marker": marker}

    monkeypatch.setattr(storage_world, "load_with_overlay", marker_loader)
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            with effective_config_scope(effective):
                inside = storage_world._load_catalog_config()
                assert inside["marker"] == "scoped"

        assert caught.value is failure
        assert storage_world._load_catalog_config.cache_info().currsize == 0
        outside = storage_world._load_catalog_config()
        assert outside["marker"] == "base"
        assert outside is not inside
        assert coordinator.state == "saved-storage"
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

        coordinator.clear_failures.clear()
        with effective_config_scope(effective):
            retried = storage_world._load_catalog_config()
            assert retried["marker"] == "scoped"
        assert storage_world._load_catalog_config()["marker"] == "base"
    finally:
        storage_world._load_catalog_config.cache_clear()


@pytest.mark.parametrize(
    "failure_position",
    [0, 2, 5],
    ids=("before-first", "after-middle", "after-last"),
)
def test_legacy_dns_refresh_systemexit_restores_all_five_exact_globals_and_retry(
    monkeypatch: pytest.MonkeyPatch,
    failure_position: int,
) -> None:
    """Fail-before/middle/after refresh restores every binding, identity, and value."""

    from evidenceforge.generation.activity import network

    objects = (
        network.REVERSE_DNS,
        network.FORWARD_DNS,
        network.EXTERNAL_IPS,
        network._CDN_RANGES,
        network._IPV6_MAP,
    )
    contents = (
        dict.copy(network.REVERSE_DNS),
        dict.copy(network.FORWARD_DNS),
        {key: list(value) for key, value in network.EXTERNAL_IPS.items()},
        list.copy(network._CDN_RANGES),
        dict.copy(network._IPV6_MAP),
    )
    external_value_ids = {key: id(value) for key, value in network.EXTERNAL_IPS.items()}
    failure = SystemExit(f"legacy refresh failed at {failure_position}")
    should_fail = True

    def replace_dict(target: dict[Any, Any], value: dict[Any, Any]) -> None:
        dict.clear(target)
        dict.update(target, value)

    def replace_list(target: list[Any], value: list[Any]) -> None:
        list.clear(target)
        list.extend(target, value)

    def faulting_refresh(_owner: Any, _prepared: Any) -> None:
        actions: tuple[Callable[[], None], ...] = (
            lambda: replace_dict(network.REVERSE_DNS, {"10.0.0.1": "inner.example"}),
            lambda: replace_dict(network.FORWARD_DNS, {"inner.example": "10.0.0.1"}),
            lambda: replace_dict(network.EXTERNAL_IPS, {"connection_web": ["10.0.0.1"]}),
            lambda: replace_list(network._CDN_RANGES, [("10.0.0.0", "10.0.0.255")]),
            lambda: replace_dict(network._IPV6_MAP, {"10.0.0.1": "2001:db8::1"}),
        )
        for index, action in enumerate(actions):
            if should_fail and failure_position == index:
                raise failure
            action()
        if should_fail and failure_position == len(actions):
            raise failure

    def assert_outer_state() -> None:
        assert network.REVERSE_DNS is objects[0]
        assert network.FORWARD_DNS is objects[1]
        assert network.EXTERNAL_IPS is objects[2]
        assert network._CDN_RANGES is objects[3]
        assert network._IPV6_MAP is objects[4]
        assert network.REVERSE_DNS == contents[0]
        assert network.FORWARD_DNS == contents[1]
        assert network.EXTERNAL_IPS == contents[2]
        assert network._CDN_RANGES == contents[3]
        assert network._IPV6_MAP == contents[4]
        assert {key: id(value) for key, value in network.EXTERNAL_IPS.items()} == (
            external_value_ids
        )

    monkeypatch.setattr(config_provider, "_refresh_legacy_registry_globals", faulting_refresh)
    effective = _effective_timing_config()
    with pytest.raises(SystemExit) as caught:
        with effective_config_scope(effective):
            pytest.fail("scope body ran after a failed legacy refresh")

    assert caught.value is failure
    assert_outer_state()
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    should_fail = False
    with effective_config_scope(effective):
        assert network.REVERSE_DNS == {"10.0.0.1": "inner.example"}
        assert network._IPV6_MAP == {"10.0.0.1": "2001:db8::1"}
    assert_outer_state()


def test_legacy_registry_restore_pins_bindings_and_contents_until_both_locks_release() -> None:
    """DNS restore cannot run displaced-value finalizers inside provider serialization."""

    from evidenceforge.generation.activity import network

    callback_states: list[tuple[str, bool, bool]] = []

    class JoiningFinalizer:
        def __init__(self, label: str) -> None:
            self.label = label

        def __del__(self) -> None:
            callback_states.append(
                (
                    self.label,
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)

    namespace = vars(network)
    reverse_dns = network.REVERSE_DNS
    reverse_dns_items = dict.copy(reverse_dns)
    cdn_ranges = network._CDN_RANGES
    cdn_range_items = list.copy(cdn_ranges)
    try:
        with effective_config_scope(_effective_timing_config()):
            dict.__setitem__(reverse_dns, "finalizer", JoiningFinalizer("dict contents"))
            dict.__setitem__(namespace, "REVERSE_DNS", JoiningFinalizer("dict binding"))
            list.append(cdn_ranges, JoiningFinalizer("list contents"))
            dict.__setitem__(namespace, "_CDN_RANGES", JoiningFinalizer("list binding"))

        import gc

        gc.collect()
        assert network.REVERSE_DNS is reverse_dns
        assert network.REVERSE_DNS == reverse_dns_items
        assert network._CDN_RANGES is cdn_ranges
        assert network._CDN_RANGES == cdn_range_items
        assert sorted(callback_states) == [
            ("dict binding", False, False),
            ("dict contents", False, False),
            ("list binding", False, False),
            ("list contents", False, False),
        ]
    finally:
        dict.__setitem__(namespace, "REVERSE_DNS", reverse_dns)
        dict.clear(reverse_dns)
        dict.update(reverse_dns, reverse_dns_items)
        dict.__setitem__(namespace, "_CDN_RANGES", cdn_ranges)
        list.clear(cdn_ranges)
        list.extend(cdn_ranges, cdn_range_items)

    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize(
    "setup_failure",
    [False, True],
    ids=("normal-cleanup", "setup-rollback"),
)
def test_nested_legacy_registry_pins_survive_until_outermost_lease_release(
    monkeypatch: pytest.MonkeyPatch,
    setup_failure: bool,
) -> None:
    """Inner DNS pins remain alive while a reentrant outer scope owns the lease."""

    from evidenceforge.generation.activity import network

    callback_states: list[tuple[str, bool, bool]] = []

    class JoiningFinalizer:
        def __init__(self, label: str) -> None:
            self.label = label

        def __del__(self) -> None:
            callback_states.append(
                (
                    self.label,
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)

    namespace = vars(network)
    reverse_dns = network.REVERSE_DNS
    reverse_dns_items = dict.copy(reverse_dns)
    cdn_ranges = network._CDN_RANGES
    cdn_range_items = list.copy(cdn_ranges)
    armed = False
    installed = False

    def install_finalizers() -> None:
        nonlocal installed
        installed = True
        dict.__setitem__(reverse_dns, "finalizer", JoiningFinalizer("dict contents"))
        dict.__setitem__(namespace, "REVERSE_DNS", JoiningFinalizer("dict binding"))
        list.append(cdn_ranges, JoiningFinalizer("list contents"))
        dict.__setitem__(namespace, "_CDN_RANGES", JoiningFinalizer("list binding"))

    class MutatingDerivedCache:
        def cache_clear(self) -> None:
            if armed and not installed:
                install_finalizers()

    class FailingDerivedCache:
        def cache_clear(self) -> None:
            if armed:
                raise SystemExit("nested setup clear failed")

    if setup_failure:
        original_cached_callables = config_provider._cached_callables
        mutator = MutatingDerivedCache()
        failing = FailingDerivedCache()
        monkeypatch.setattr(
            config_provider,
            "_cached_callables",
            lambda: [*original_cached_callables(), mutator, failing],
        )

    try:
        outer = _effective_timing_config()
        with effective_config_scope(outer):
            outer_reverse_dns_items = dict.copy(reverse_dns)
            outer_cdn_range_items = list.copy(cdn_ranges)
            if setup_failure:
                armed = True
                try:
                    try:
                        with effective_config_scope(_effective_timing_config()):
                            pytest.fail("scope body ran after setup clear failure")
                    except SystemExit as caught:
                        assert caught.args == ("nested setup clear failed",)
                        caught.__traceback__ = None
                finally:
                    armed = False
            else:
                with effective_config_scope(_effective_timing_config()):
                    install_finalizers()

            assert installed
            assert callback_states == []
            assert config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
            assert network.REVERSE_DNS is reverse_dns
            assert network.REVERSE_DNS == outer_reverse_dns_items
            assert network._CDN_RANGES is cdn_ranges
            assert network._CDN_RANGES == outer_cdn_range_items

        import gc

        gc.collect()
        assert sorted(callback_states) == [
            ("dict binding", False, False),
            ("dict contents", False, False),
            ("list binding", False, False),
            ("list contents", False, False),
        ]
        assert config_provider._CONFIG_SCOPE_LEASE._cleanup_pin_groups == []
    finally:
        dict.__setitem__(namespace, "REVERSE_DNS", reverse_dns)
        dict.clear(reverse_dns)
        dict.update(reverse_dns, reverse_dns_items)
        dict.__setitem__(namespace, "_CDN_RANGES", cdn_ranges)
        list.clear(cdn_ranges)
        list.extend(cdn_ranges, cdn_range_items)

    with effective_config_scope(_effective_timing_config()):
        assert current_effective_config() is not None
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize(
    "body_failure_type",
    [None, SystemExit],
    ids=("first-cleanup-wins", "body-primary-wins"),
)
def test_multiple_cleanup_failures_are_exhaustive_and_preserve_exception_priority(
    monkeypatch: pytest.MonkeyPatch,
    body_failure_type: type[BaseException] | None,
) -> None:
    """Coordinator, derived-cache, and restore failures never stop later cleanup."""

    coordinator = _FaultingRuntimeCacheCoordinator("multiple")
    _install_faulting_runtime_caches(monkeypatch, (coordinator,))
    derived = _FaultingCachedCallable()
    original_cached_callables = config_provider._cached_callables
    original_clear_callables = config_provider._cached_callables_for_clear
    monkeypatch.setattr(
        config_provider,
        "_cached_callables",
        lambda: [*original_cached_callables(), derived],
    )

    def clear_callables() -> tuple[list[Any], BaseException | None]:
        current, discovery_failure = original_clear_callables()
        return [*current, derived], discovery_failure

    monkeypatch.setattr(
        config_provider,
        "_cached_callables_for_clear",
        clear_callables,
    )
    coordinator_failure = KeyboardInterrupt("coordinator cleanup failed")
    derived_failure = ValueError("derived cleanup failed")
    restore_failure = RuntimeError("coordinator restore failed")
    coordinator.clear_failures[2] = coordinator_failure
    coordinator.restore_failures[1] = restore_failure
    derived.clear_failures[2] = derived_failure
    body_failure = None if body_failure_type is None else body_failure_type("scope body failed")
    expected = coordinator_failure if body_failure is None else body_failure

    with pytest.raises(type(expected)) as caught:
        with effective_config_scope(_effective_timing_config()):
            if body_failure is not None:
                raise body_failure

    assert caught.value is expected
    assert coordinator.clear_calls == 2
    assert derived.clear_calls == 2
    assert coordinator.restore_calls == 1
    assert coordinator.state == "saved-multiple"
    assert len(expected.__notes__) == (2 if body_failure is None else 3)
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    coordinator.clear_failures.clear()
    coordinator.restore_failures.clear()
    derived.clear_failures.clear()
    retry = _effective_timing_config()
    with effective_config_scope(retry):
        assert current_effective_config() is retry
    assert coordinator.state == "saved-multiple"


def test_untrusted_coordinator_is_rejected_before_joining_callbacks_under_lease() -> None:
    """Discovery fail-closes before an untrusted protocol can join a waiting scope."""

    callback_attempts: list[str] = []
    joined_config = _effective_timing_config()

    def joining_callback(action: str) -> None:
        callback_attempts.append(action)

        def joined_scope() -> None:
            with effective_config_scope(joined_config):
                pass

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            executor.submit(joined_scope).result(timeout=0.2)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    class JoiningCoordinator:
        def __getattribute__(self, name: str) -> Any:
            if name.startswith("_evidenceforge_runtime_cache_"):
                callback_attempts.append("protocol metadata")
            return object.__getattribute__(self, name)

        def _evidenceforge_runtime_cache_snapshot(self) -> str:
            joining_callback("snapshot")
            return "snapshot"

        def _evidenceforge_runtime_cache_clear(self) -> None:
            joining_callback("clear")

        def _evidenceforge_runtime_cache_restore(self, _snapshot: str) -> None:
            joining_callback("restore")

    trusted = timing_profiles_module._CACHED_TIMING_PROFILES
    timing_profiles_module._CACHED_TIMING_PROFILES = JoiningCoordinator()
    try:
        with pytest.raises(
            RuntimeError,
            match="timing profile runtime cache coordinator was replaced",
        ):
            with effective_config_scope(SimpleNamespace(marker=1)):
                pytest.fail("untrusted coordinator scope unexpectedly entered")
    finally:
        timing_profiles_module._CACHED_TIMING_PROFILES = trusted

    assert callback_attempts == []
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    with effective_config_scope(joined_config):
        assert current_effective_config() is joined_config


def test_untrusted_exact_lru_is_rejected_before_joining_finalizer_callback() -> None:
    """Foreign exact wrappers fail closed without decref callbacks under provider locks."""

    from functools import lru_cache

    callback_states: list[tuple[bool, bool]] = []

    class JoiningFinalizer:
        def __del__(self) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)

    @lru_cache(maxsize=1)
    def foreign_cache() -> JoiningFinalizer:
        return JoiningFinalizer()

    module_name = "evidenceforge.foreign_lru_callback_probe"
    foreign_cache.__module__ = module_name
    foreign_cache()
    foreign_module = ModuleType(module_name)
    foreign_module.foreign_cache = foreign_cache
    sys.modules[module_name] = foreign_module
    try:
        with pytest.raises(RuntimeError, match="untrusted derived cache wrapper discovered"):
            with effective_config_scope(_effective_timing_config()):
                pytest.fail("scope with an untrusted exact LRU unexpectedly entered")
        assert callback_states == []
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    finally:
        sys.modules.pop(module_name, None)

    foreign_cache.cache_clear()
    assert callback_states == [(False, False)]
    retry = _effective_timing_config()
    with effective_config_scope(retry):
        assert current_effective_config() is retry


def test_trusted_derived_cache_value_graphs_have_no_finalizer_callback_carriers() -> None:
    """The three allowlisted cache graphs contain no finalizer or weakref callbacks."""

    import weakref
    from dataclasses import fields, is_dataclass

    from pydantic import BaseModel

    from evidenceforge.evaluation.thresholds import load_thresholds
    from evidenceforge.generation.resource_forecast import load_resource_forecast_calibration
    from evidenceforge.generation.storage_world import _load_catalog_config

    wrappers = (
        load_resource_forecast_calibration,
        _load_catalog_config,
        load_thresholds,
    )
    for wrapper in wrappers:
        wrapper.cache_clear()
    try:
        stack = [wrapper() for wrapper in wrappers]
        seen: set[int] = set()
        while stack:
            value = stack.pop()
            if id(value) in seen:
                continue
            seen.add(id(value))
            assert "__del__" not in vars(type(value))
            assert not isinstance(
                value,
                (
                    weakref.ReferenceType,
                    weakref.WeakKeyDictionary,
                    weakref.WeakSet,
                    weakref.WeakValueDictionary,
                    weakref.finalize,
                ),
            )
            if type(value) is dict:
                stack.extend(value.keys())
                stack.extend(value.values())
            elif type(value) in {list, tuple, set, frozenset}:
                stack.extend(value)
            elif isinstance(value, BaseModel):
                stack.extend(vars(value).values())
            elif is_dataclass(value) and not isinstance(value, type):
                stack.extend(getattr(value, field.name) for field in fields(value))
    finally:
        for wrapper in wrappers:
            wrapper.cache_clear()


@pytest.mark.parametrize("entry_kind", ["proxy", "module-subclass"])
def test_runtime_module_registry_rejects_callback_capable_entries_before_access(
    entry_kind: str,
) -> None:
    """A name prefix cannot grant callback-capable objects cache provenance."""

    callback_attempts: list[str] = []

    class HostileProxy:
        def __getattribute__(self, name: str) -> Any:
            callback_attempts.append(f"get:{name}")
            return object.__getattribute__(self, name)

        def __setattr__(self, name: str, value: Any) -> None:
            callback_attempts.append(f"set:{name}")
            object.__setattr__(self, name, value)

    class HostileModule(ModuleType):
        def __getattribute__(self, name: str) -> Any:
            callback_attempts.append(f"get:{name}")
            return ModuleType.__getattribute__(self, name)

        def __setattr__(self, name: str, value: Any) -> None:
            callback_attempts.append(f"set:{name}")
            ModuleType.__setattr__(self, name, value)

    entry: Any
    if entry_kind == "proxy":
        entry = object.__new__(HostileProxy)
    else:
        entry = HostileModule("evidenceforge.callback_module")
        callback_attempts.clear()
    module_name = f"evidenceforge.callback_probe_{entry_kind}"
    dict.__setitem__(sys.modules, module_name, entry)
    try:
        with pytest.raises(RuntimeError, match="exact module objects"):
            with effective_config_scope(SimpleNamespace(marker=1), refresh_legacy_globals=False):
                pytest.fail("callback-capable registry entry unexpectedly entered a scope")
    finally:
        dict.__delitem__(sys.modules, module_name)

    assert callback_attempts == []
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    with effective_config_scope(SimpleNamespace(marker=2), refresh_legacy_globals=False):
        assert current_effective_config().marker == 2


@pytest.mark.parametrize("location", ["registry", "namespace"])
def test_string_subclass_cache_names_are_rejected_without_virtual_startswith(
    location: str,
) -> None:
    """Only builtin strings are classified as module or cache names."""

    callback_attempts: list[str] = []

    class HostileName(str):
        def startswith(self, *_args: Any, **_kwargs: Any) -> bool:
            callback_attempts.append("startswith")
            raise AssertionError("virtual startswith executed")

    module_name = "evidenceforge.string_name_probe"
    module = ModuleType(module_name)
    if location == "registry":
        key: str = HostileName(module_name)
    else:
        key = module_name
        dict.__setitem__(vars(module), HostileName("_CACHED_TRAP"), object())
    dict.__setitem__(sys.modules, key, module)
    try:
        expected = "registry keys" if location == "registry" else "namespace keys"
        with pytest.raises(RuntimeError, match=expected):
            with effective_config_scope(SimpleNamespace(marker=1), refresh_legacy_globals=False):
                pytest.fail("string-subclass cache name unexpectedly entered a scope")
    finally:
        dict.__delitem__(sys.modules, key)

    assert callback_attempts == []
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


def test_custom_sys_modules_mapping_is_rejected_without_mapping_callbacks() -> None:
    """The runtime module registry itself must remain an exact builtin dict."""

    callback_attempts: list[str] = []

    class HostileModules(dict[str, Any]):
        def items(self) -> Any:
            callback_attempts.append("items")
            raise AssertionError("custom registry items executed")

        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            callback_attempts.append("get")
            raise AssertionError("custom registry get executed")

    original_modules = sys.modules
    replacement = HostileModules(original_modules)
    ModuleType.__setattr__(sys, "modules", replacement)
    try:
        with pytest.raises(RuntimeError, match="builtin mapping"):
            with effective_config_scope(SimpleNamespace(marker=1), refresh_legacy_globals=False):
                pytest.fail("custom sys.modules unexpectedly entered a scope")
    finally:
        ModuleType.__setattr__(sys, "modules", original_modules)

    assert callback_attempts == []
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


def test_lru_module_string_subclass_is_rejected_without_virtual_startswith() -> None:
    """Mutable wrapper metadata cannot execute string-subclass callbacks under locks."""

    from functools import lru_cache

    callback_attempts: list[str] = []

    class HostileName(str):
        def startswith(self, *_args: Any, **_kwargs: Any) -> bool:
            callback_attempts.append("startswith")
            raise AssertionError("virtual wrapper metadata startswith executed")

    @lru_cache(maxsize=1)
    def unknown_cache() -> object:
        return object()

    module_name = "evidenceforge.wrapper_metadata_probe"
    unknown_cache.__module__ = HostileName(module_name)
    module = ModuleType(module_name)
    module.unknown_cache = unknown_cache
    dict.__setitem__(sys.modules, module_name, module)
    try:
        with pytest.raises(RuntimeError, match="wrapper metadata is invalid"):
            with effective_config_scope(SimpleNamespace(marker=1), refresh_legacy_globals=False):
                pytest.fail("hostile wrapper metadata unexpectedly entered a scope")
    finally:
        dict.__delitem__(sys.modules, module_name)

    assert callback_attempts == []
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize("alias_kind", ["canonical-duplicate", "external", "bad-spec"])
def test_module_alias_and_spec_provenance_fail_without_cache_mutation(alias_kind: str) -> None:
    """Only one canonical exact module entry can contribute runtime cache slots."""

    from importlib.machinery import ModuleSpec

    module_name = f"evidenceforge.module_alias_probe_{alias_kind}"
    if alias_kind == "canonical-duplicate":
        module = timing_profiles_module
        expected = "alias has invalid provenance"
    else:
        module = ModuleType(
            "external.module" if alias_kind == "external" else module_name,
        )
        module._CACHED_TRAP = object()
        expected = "alias has invalid provenance" if alias_kind == "external" else "spec is invalid"
        if alias_kind == "bad-spec":
            module.__spec__ = ModuleSpec("evidenceforge.different_name", loader=None)
    original_coordinator = timing_profiles_module._CACHED_TIMING_PROFILES
    original_trap = getattr(module, "_CACHED_TRAP", None)
    dict.__setitem__(sys.modules, module_name, module)
    try:
        with pytest.raises(RuntimeError, match=expected):
            with effective_config_scope(SimpleNamespace(marker=1), refresh_legacy_globals=False):
                pytest.fail("noncanonical module entry unexpectedly entered a scope")
    finally:
        dict.__delitem__(sys.modules, module_name)

    assert timing_profiles_module._CACHED_TIMING_PROFILES is original_coordinator
    if alias_kind != "canonical-duplicate":
        assert module._CACHED_TRAP is original_trap
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    with effective_config_scope(SimpleNamespace(marker=2), refresh_legacy_globals=False):
        assert current_effective_config().marker == 2


def test_aligned_timing_coordinator_rebinding_cannot_move_provider_trust_anchor() -> None:
    """Replacing both peer bindings cannot authorize coordinator callbacks."""

    callback_attempts: list[str] = []

    class AlignedCoordinator:
        def _evidenceforge_runtime_cache_snapshot(self) -> str:
            callback_attempts.append("snapshot")
            return "malicious"

        def _evidenceforge_runtime_cache_clear(self) -> None:
            callback_attempts.append("clear")

        def _evidenceforge_runtime_cache_restore(self, _snapshot: str) -> None:
            callback_attempts.append("restore")

    original_type = timing_profiles_module._TimingProfileCacheCoordinator
    original_controller = timing_profiles_module._CACHED_TIMING_PROFILES
    timing_profiles_module._TimingProfileCacheCoordinator = AlignedCoordinator
    timing_profiles_module._CACHED_TIMING_PROFILES = AlignedCoordinator()
    try:
        with pytest.raises(RuntimeError, match="coordinator was replaced"):
            with effective_config_scope(SimpleNamespace(marker=1), refresh_legacy_globals=False):
                pytest.fail("aligned coordinator replacement unexpectedly entered a scope")
    finally:
        timing_profiles_module._TimingProfileCacheCoordinator = original_type
        timing_profiles_module._CACHED_TIMING_PROFILES = original_controller

    assert callback_attempts == []
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    with effective_config_scope(_effective_timing_config()):
        assert isinstance(load_timing_profiles(), Mapping)


def test_aligned_trusted_lru_rebinding_cannot_clear_joining_finalizer() -> None:
    """Canonical owner location and exact wrapper type cannot replace anchored identity."""

    from functools import lru_cache

    from evidenceforge.generation import storage_world

    callback_states: list[tuple[bool, bool]] = []

    class JoiningFinalizer:
        def __del__(self) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)

    @lru_cache(maxsize=1)
    def replacement() -> JoiningFinalizer:
        return JoiningFinalizer()

    replacement.__module__ = storage_world.__name__
    replacement()
    original = storage_world._load_catalog_config
    storage_world._load_catalog_config = replacement
    try:
        with pytest.raises(RuntimeError, match="trusted derived cache owner was replaced"):
            with effective_config_scope(_effective_timing_config()):
                pytest.fail("aligned LRU replacement unexpectedly entered a scope")
        assert callback_states == []
    finally:
        storage_world._load_catalog_config = original

    replacement.cache_clear()
    assert callback_states == [(False, False)]
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    with effective_config_scope(_effective_timing_config()):
        assert current_effective_config() is not None


@pytest.mark.parametrize(
    "invalid_name",
    [
        "evidenceforge.000_partial_failure",
        "evidenceforge.partial_nnn_failure",
        "evidenceforge.zzzz_partial_failure",
    ],
    ids=("first", "middle", "last"),
)
def test_cleanup_module_discovery_failure_still_clears_every_safe_late_cache(
    invalid_name: str,
) -> None:
    """Incremental cleanup retains safe modules on failures at every scan position."""

    callback_attempts: list[str] = []

    class HostileProxy:
        def __getattribute__(self, name: str) -> Any:
            callback_attempts.append(name)
            return object.__getattribute__(self, name)

    safe_names = (
        "evidenceforge.aaa_partial_safe",
        "evidenceforge.partial_mmm_safe",
        "evidenceforge.zzz_partial_safe",
    )
    safe_modules = [ModuleType(name) for name in safe_names]
    proxy = object.__new__(HostileProxy)
    try:
        with pytest.raises(RuntimeError, match="exact module objects"):
            with effective_config_scope(_effective_timing_config()):
                for module_name, module in zip(safe_names, safe_modules, strict=True):
                    module._CACHED_DATA = {"marker": "scoped"}
                    dict.__setitem__(sys.modules, module_name, module)
                dict.__setitem__(sys.modules, invalid_name, proxy)
    finally:
        for module_name in (*safe_names, invalid_name):
            dict.pop(sys.modules, module_name, None)

    assert callback_attempts == []
    assert all(module._CACHED_DATA is None for module in safe_modules)
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    with effective_config_scope(_effective_timing_config()):
        assert current_effective_config() is not None


@pytest.mark.parametrize(
    "module_name",
    [
        "evidenceforge.000_unknown_lru",
        "evidenceforge.generation.unknown_lru",
        "evidenceforge.zzzz_unknown_lru",
    ],
    ids=("first", "middle", "last"),
)
def test_cleanup_lru_discovery_failure_still_clears_every_anchored_cache(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
) -> None:
    """An unknown late wrapper cannot discard already anchored cleanup targets."""

    from functools import lru_cache

    from evidenceforge.generation import storage_world

    effective = _effective_timing_config()

    def marker_loader(
        _package_path: Path,
        _overlay_subpath: str,
        _merge_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        return {"marker": "scoped" if current_effective_config() is effective else "base"}

    @lru_cache(maxsize=1)
    def unknown_cache() -> object:
        return object()

    unknown_cache.__module__ = module_name
    unknown_module = ModuleType(module_name)
    unknown_module.unknown_cache = unknown_cache
    storage_world._load_catalog_config.cache_clear()
    monkeypatch.setattr(storage_world, "load_with_overlay", marker_loader)
    try:
        with pytest.raises(RuntimeError, match="untrusted derived cache wrapper discovered"):
            with effective_config_scope(effective):
                assert storage_world._load_catalog_config()["marker"] == "scoped"
                unknown_cache()
                dict.__setitem__(sys.modules, module_name, unknown_module)
        assert storage_world._load_catalog_config.cache_info().currsize == 0
        assert unknown_cache.cache_info().currsize == 1
        assert storage_world._load_catalog_config()["marker"] == "base"
    finally:
        dict.pop(sys.modules, module_name, None)
        unknown_cache.cache_clear()
        storage_world._load_catalog_config.cache_clear()

    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


def test_plain_late_cache_finalizer_runs_only_after_cleanup_releases_both_locks() -> None:
    """The cleanup census pins raw cache values through callback-free rebinding."""

    callback_states: list[tuple[bool, bool]] = []

    class JoiningFinalizer:
        def __del__(self) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)

    module_name = "evidenceforge.raw_cache_finalizer_probe"
    module = ModuleType(module_name)
    dict.__setitem__(sys.modules, module_name, module)
    try:
        with effective_config_scope(_effective_timing_config()):
            dict.__setitem__(vars(module), "_CACHED_TRAP", JoiningFinalizer())
        assert dict.get(vars(module), "_CACHED_TRAP") is None
        assert callback_states == [(False, False)]
    finally:
        dict.__delitem__(sys.modules, module_name)

    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize("entry_path", ["direct", "provider"])
def test_merge_logging_handler_joins_public_threads_outside_every_provider_lock(
    monkeypatch: pytest.MonkeyPatch,
    entry_path: str,
) -> None:
    """Inert merge diagnostics invoke logging only in the callback-safe phase."""

    default = {
        "replace_me": 1,
        "network_sensor_observation": {"profiles": {}},
    }
    overlay = {"replace_me": 2}
    callback_states: list[tuple[bool, bool]] = []
    nested_snapshots: list[Mapping[str, Any]] = []

    def scoped_load() -> Mapping[str, Any]:
        with effective_config_scope(_effective_timing_config(), refresh_legacy_globals=False):
            return load_timing_profiles()

    class JoiningHandler(logging.Handler):
        def emit(self, _record: logging.LogRecord) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=2) as executor:
                direct = executor.submit(load_timing_profiles)
                scoped = executor.submit(scoped_load)
                nested_snapshots.append(direct.result(timeout=10))
                nested_snapshots.append(scoped.result(timeout=10))

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _layered_loader(default, overlay),
    )
    handler = JoiningHandler()
    original_level = timing_profiles_module.logger.level
    timing_profiles_module.logger.setLevel(logging.WARNING)
    timing_profiles_module.logger.addHandler(handler)
    try:
        if entry_path == "direct":
            snapshot = load_timing_profiles()
        else:
            with effective_config_scope(
                _effective_timing_config(),
                refresh_legacy_globals=False,
            ):
                snapshot = load_timing_profiles()
    finally:
        timing_profiles_module.logger.removeHandler(handler)
        timing_profiles_module.logger.setLevel(original_level)

    assert callback_states == [(False, False)]
    assert len(nested_snapshots) == 2
    assert all(item["replace_me"] == 2 for item in nested_snapshots)
    assert snapshot["replace_me"] == 2
    if entry_path == "direct":
        assert load_timing_profiles() is snapshot
    else:
        assert load_timing_profiles()["replace_me"] == 2


def test_merge_logging_handler_baseexception_rolls_back_and_retries_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A logging callback failure cannot leave a provisional cache or reservation."""

    default = {
        "replace_me": 1,
        "network_sensor_observation": {"profiles": {}},
    }
    overlay = {"replace_me": 2}
    callback_states: list[tuple[bool, bool]] = []
    delivered: list[str] = []

    class FailingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            delivered.append(record.getMessage())
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)
            raise ValueError("timing merge logging callback failed")

    class RecordingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            delivered.append(record.getMessage())

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _layered_loader(default, overlay),
    )
    failing = FailingHandler()
    recording = RecordingHandler()
    original_level = timing_profiles_module.logger.level
    timing_profiles_module.logger.setLevel(logging.WARNING)
    timing_profiles_module.logger.addHandler(failing)
    try:
        with pytest.raises(ValueError, match="logging callback failed"):
            load_timing_profiles()
        assert _cache_phase() is _TimingProfileCachePhase.EMPTY
        assert timing_profiles_module._EMITTED_TIMING_PROFILE_DIAGNOSTICS == frozenset()

        timing_profiles_module.logger.removeHandler(failing)
        timing_profiles_module.logger.addHandler(recording)
        recovered = load_timing_profiles()
    finally:
        timing_profiles_module.logger.removeHandler(failing)
        timing_profiles_module.logger.removeHandler(recording)
        timing_profiles_module.logger.setLevel(original_level)

    assert callback_states == [(False, False), (False, False)]
    assert len(delivered) == 2
    assert load_timing_profiles() is recovered
    assert recovered["replace_me"] == 2


def test_first_network_import_hook_runs_outside_locks_and_failure_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An absent canonical network entry is prepared before any provider serialization."""

    owner = config_provider._get_legacy_network_module_anchor()
    assert owner is not None
    namespace = owner.namespace
    bindings = (
        dict.get(namespace, "REVERSE_DNS"),
        dict.get(namespace, "FORWARD_DNS"),
        dict.get(namespace, "EXTERNAL_IPS"),
        dict.get(namespace, "_CDN_RANGES"),
        dict.get(namespace, "_IPV6_MAP"),
    )
    contents = (
        dict.copy(bindings[0]),
        dict.copy(bindings[1]),
        dict.copy(bindings[2]),
        list.copy(bindings[3]),
        dict.copy(bindings[4]),
    )
    callback_states: list[tuple[bool, bool]] = []
    failure = SystemExit("network import hook failed")
    should_fail = True

    def callback_safe_import(module_name: str) -> ModuleType:
        nonlocal should_fail
        assert module_name == "evidenceforge.generation.activity.network"
        callback_states.append(
            (
                config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
            )
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            direct = executor.submit(load_timing_profiles)

            def scoped() -> None:
                with effective_config_scope(
                    SimpleNamespace(marker=2),
                    refresh_legacy_globals=False,
                ):
                    assert current_effective_config().marker == 2

            provider = executor.submit(scoped)
            direct.result(timeout=10)
            provider.result(timeout=10)
        if should_fail:
            should_fail = False
            raise failure
        dict.__setitem__(sys.modules, owner.name, owner.module)
        return owner.module

    monkeypatch.setattr(config_provider.importlib, "import_module", callback_safe_import)
    dict.__delitem__(sys.modules, owner.name)
    try:
        with pytest.raises(SystemExit) as caught:
            with effective_config_scope(_effective_timing_config()):
                pytest.fail("scope body ran after network import failure")
        assert caught.value is failure
        assert dict.get(sys.modules, owner.name) is None
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
        assert bindings == (
            dict.get(namespace, "REVERSE_DNS"),
            dict.get(namespace, "FORWARD_DNS"),
            dict.get(namespace, "EXTERNAL_IPS"),
            dict.get(namespace, "_CDN_RANGES"),
            dict.get(namespace, "_IPV6_MAP"),
        )
        assert contents == (
            dict.copy(bindings[0]),
            dict.copy(bindings[1]),
            dict.copy(bindings[2]),
            list.copy(bindings[3]),
            dict.copy(bindings[4]),
        )

        retry = _effective_timing_config()
        with effective_config_scope(retry):
            assert current_effective_config() is retry
    finally:
        dict.__setitem__(sys.modules, owner.name, owner.module)

    assert callback_states == [(False, False), (False, False)]
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()


@pytest.mark.parametrize(
    "failure_types",
    [
        (KeyboardInterrupt,),
        (SystemExit,),
        (KeyboardInterrupt, SystemExit, KeyboardInterrupt),
    ],
    ids=("keyboard-interrupt", "system-exit", "repeated-mixed"),
)
def test_nested_lease_reacquisition_restores_exact_depth_before_reraising_interrupt(
    monkeypatch: pytest.MonkeyPatch,
    failure_types: tuple[type[BaseException], ...],
) -> None:
    """Interrupted waits cannot expose an active outer scope without its lease."""

    from threading import get_ident

    lease = config_provider._CONFIG_SCOPE_LEASE
    main_thread_id = get_ident()
    preparation_started = Event()
    competitor_entered = Event()
    competitor_release = Event()
    failing_config = SimpleNamespace(marker=3)
    competitor_config = SimpleNamespace(marker=4)
    original_prepare = config_provider._prepare_effective_timing_profiles
    original_wait = lease._condition.wait
    failures = [
        failure_type(f"lease wait failure {index}")
        for index, failure_type in enumerate(failure_types)
    ]

    def controlled_prepare(effective: Any) -> Any:
        if effective is failing_config and get_ident() == main_thread_id:
            preparation_started.set()
            if not competitor_entered.wait(timeout=10):
                raise TimeoutError("competitor did not acquire the suspended lease")
        return original_prepare(effective)

    def interruptible_wait(timeout: float | None = None) -> bool:
        if get_ident() == main_thread_id:
            if failures:
                raise failures.pop(0)
            competitor_release.set()
        return original_wait(timeout)

    def competitor() -> None:
        if not preparation_started.wait(timeout=10):
            raise TimeoutError("nested preparation did not suspend the lease")
        with effective_config_scope(competitor_config, refresh_legacy_globals=False):
            competitor_entered.set()
            if not competitor_release.wait(timeout=10):
                raise TimeoutError("competitor scope was not released")

    monkeypatch.setattr(config_provider, "_prepare_effective_timing_profiles", controlled_prepare)
    monkeypatch.setattr(lease._condition, "wait", interruptible_wait)
    outer = SimpleNamespace(marker=1)
    middle = SimpleNamespace(marker=2)
    with ThreadPoolExecutor(max_workers=1) as executor:
        with effective_config_scope(outer, refresh_legacy_globals=False):
            with effective_config_scope(middle, refresh_legacy_globals=False):
                future = executor.submit(competitor)
                with pytest.raises(failure_types[0]) as caught:
                    with effective_config_scope(failing_config, refresh_legacy_globals=False):
                        pytest.fail("interrupted nested scope unexpectedly entered its body")
                assert lease.owned_by_current_thread()
                with lease._condition:
                    assert lease._depth == 2
                assert current_effective_config() is middle
                future.result(timeout=10)
                assert caught.value.args[0] == "lease wait failure 0"
                assert len(getattr(caught.value, "__notes__", ())) == len(failure_types) - 1
            assert current_effective_config() is outer
        assert current_effective_config() is None

    retry = SimpleNamespace(marker=5)
    with effective_config_scope(retry, refresh_legacy_globals=False):
        assert current_effective_config() is retry
    assert not lease.owned_by_current_thread()


def test_setup_failure_rescan_pins_replaced_raw_value_until_locks_are_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rollback restoration cannot decref a newly installed raw cache under locks."""

    callback_states: list[tuple[bool, bool]] = []

    class JoiningFinalizer:
        def __del__(self) -> None:
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                executor.submit(load_timing_profiles).result(timeout=10)

    module_name = "evidenceforge.setup_rollback_pin_probe"
    module = ModuleType(module_name)
    outer_value = {"marker": "outer"}
    module._CACHED_TRAP = outer_value
    dict.__setitem__(sys.modules, module_name, module)
    mutator_calls = 0
    failure_enabled = True

    class MutatingDerivedCache:
        def cache_clear(self) -> None:
            nonlocal mutator_calls
            mutator_calls += 1
            if mutator_calls == 1:
                dict.__setitem__(vars(module), "_CACHED_TRAP", JoiningFinalizer())

    class FailingDerivedCache:
        def cache_clear(self) -> None:
            if failure_enabled:
                raise SystemExit("derived setup clear failed")

    mutator = MutatingDerivedCache()
    failing = FailingDerivedCache()
    original_cached_callables = config_provider._cached_callables
    monkeypatch.setattr(
        config_provider,
        "_cached_callables",
        lambda: [*original_cached_callables(), mutator, failing],
    )
    try:
        with pytest.raises(SystemExit, match="derived setup clear failed"):
            with effective_config_scope(_effective_timing_config()):
                pytest.fail("scope body ran after setup clear failure")
        import gc

        gc.collect()
        assert module._CACHED_TRAP is outer_value
        assert callback_states == [(False, False)]
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

        failure_enabled = False
        with effective_config_scope(_effective_timing_config()):
            assert current_effective_config() is not None
        assert module._CACHED_TRAP is outer_value
    finally:
        dict.__delitem__(sys.modules, module_name)


def test_missing_canonical_timing_module_fails_before_cache_clear_and_retries() -> None:
    """A registered timing coordinator requires its exact canonical module slot."""

    anchor = config_provider._get_timing_profile_runtime_cache_anchor()
    assert anchor is not None
    published = load_timing_profiles()
    saved_state = anchor.controller.state

    dict.__delitem__(sys.modules, anchor.owner.name)
    try:
        with pytest.raises(
            RuntimeError,
            match="anchored timing profile runtime module is missing or replaced",
        ):
            with effective_config_scope(
                SimpleNamespace(marker=1),
                refresh_legacy_globals=False,
            ):
                pytest.fail("scope entered without its canonical timing module")
        assert anchor.controller.state is saved_state
        assert load_timing_profiles() is published
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    finally:
        dict.__setitem__(sys.modules, anchor.owner.name, anchor.owner.module)

    retry = SimpleNamespace(marker=2)
    with effective_config_scope(retry, refresh_legacy_globals=False):
        assert current_effective_config() is retry


def test_missing_canonical_trusted_lru_owner_fails_before_clear_and_retries() -> None:
    """A registered trusted LRU requires its exact canonical module slot."""

    from evidenceforge.generation import storage_world

    wrapper = storage_world._load_catalog_config
    wrapper.cache_clear()
    published = wrapper()
    cache_info = wrapper.cache_info()

    dict.__delitem__(sys.modules, storage_world.__name__)
    try:
        with pytest.raises(
            RuntimeError,
            match="trusted derived cache canonical owner is missing",
        ):
            with effective_config_scope(
                _effective_timing_config(),
                refresh_legacy_globals=False,
            ):
                pytest.fail("scope entered without its canonical trusted LRU owner")
        assert wrapper.cache_info() == cache_info
        assert wrapper() is published
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
    finally:
        dict.__setitem__(sys.modules, storage_world.__name__, storage_world)

    retry = _effective_timing_config()
    with effective_config_scope(retry, refresh_legacy_globals=False):
        assert current_effective_config() is retry
    wrapper.cache_clear()


def test_network_preload_requires_canonical_slot_before_scope_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returning the anchor without restoring its registry slot cannot enter a scope."""

    owner = config_provider._get_legacy_network_module_anchor()
    assert owner is not None
    namespace = owner.namespace
    bindings = (
        dict.get(namespace, "REVERSE_DNS"),
        dict.get(namespace, "FORWARD_DNS"),
        dict.get(namespace, "EXTERNAL_IPS"),
        dict.get(namespace, "_CDN_RANGES"),
        dict.get(namespace, "_IPV6_MAP"),
    )
    contents = (
        dict.copy(bindings[0]),
        dict.copy(bindings[1]),
        dict.copy(bindings[2]),
        list.copy(bindings[3]),
        dict.copy(bindings[4]),
    )
    callback_states: list[tuple[bool, bool]] = []

    def return_unregistered_anchor(module_name: str) -> ModuleType:
        assert module_name == owner.name
        callback_states.append(
            (
                config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
            )
        )
        return owner.module

    monkeypatch.setattr(
        config_provider.importlib,
        "import_module",
        return_unregistered_anchor,
    )
    dict.__delitem__(sys.modules, owner.name)
    try:
        with pytest.raises(RuntimeError, match="anchored runtime module was replaced"):
            with effective_config_scope(_effective_timing_config()):
                pytest.fail("scope entered without its canonical network module")
        assert current_effective_config() is None
        assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
        assert bindings == (
            dict.get(namespace, "REVERSE_DNS"),
            dict.get(namespace, "FORWARD_DNS"),
            dict.get(namespace, "EXTERNAL_IPS"),
            dict.get(namespace, "_CDN_RANGES"),
            dict.get(namespace, "_IPV6_MAP"),
        )
        assert contents == (
            dict.copy(bindings[0]),
            dict.copy(bindings[1]),
            dict.copy(bindings[2]),
            list.copy(bindings[3]),
            dict.copy(bindings[4]),
        )
    finally:
        dict.__setitem__(sys.modules, owner.name, owner.module)

    retry = _effective_timing_config()
    with effective_config_scope(retry):
        assert current_effective_config() is retry
    assert callback_states == [(False, False), (False, False)]


def test_cleanup_notes_bypass_joining_exception_attribute_callbacks_under_locks() -> None:
    """Diagnostic notes cannot dispatch hostile exception attribute methods."""

    callback_states: list[tuple[str, bool, bool]] = []
    callback_threads: list[Thread] = []

    def attempt_join(action: str) -> None:
        callback_states.append(
            (
                action,
                config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
            )
        )
        thread = Thread(target=load_timing_profiles)
        callback_threads.append(thread)
        thread.start()
        thread.join(timeout=0.05)

    class JoiningPrimary(BaseException):
        def __getattribute__(self, name: str) -> Any:
            if name == "__notes__":
                attempt_join("get")
            return BaseException.__getattribute__(self, name)

        def __setattr__(self, name: str, value: Any) -> None:
            if name == "__notes__":
                attempt_join("set")
            BaseException.__setattr__(self, name, value)

    primary = JoiningPrimary("primary")
    with config_provider._CONFIG_SCOPE_LEASE.hold(), config_provider._CONFIG_EXECUTION_LOCK:
        retained = config_provider._retain_provider_failure(
            primary,
            RuntimeError("secondary"),
            description="callback-safe annotation",
        )

    for thread in callback_threads:
        thread.join(timeout=10)
    exception_namespace = BaseException.__dict__["__dict__"].__get__(
        primary,
        BaseException,
    )
    assert retained is primary
    assert callback_states == []
    assert type(exception_namespace["__notes__"]) is list
    assert exception_namespace["__notes__"] == [
        "additional callback-safe annotation failure was suppressed during provider cleanup"
    ]


def test_cleanup_notes_ignore_list_subclass_without_callbacks_under_locks() -> None:
    """A hostile preexisting note container is never iterated or mutated."""

    callback_states: list[tuple[str, bool, bool]] = []

    class HostileNotes(list[str]):
        def __iter__(self) -> Iterator[str]:
            callback_states.append(
                (
                    "iterate",
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            return super().__iter__()

        def append(self, value: str) -> None:
            callback_states.append(
                (
                    "append",
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            super().append(value)

    primary = SystemExit("primary")
    hostile_notes = HostileNotes(["existing"])
    exception_namespace = BaseException.__dict__["__dict__"].__get__(
        primary,
        BaseException,
    )
    dict.__setitem__(exception_namespace, "__notes__", hostile_notes)
    with config_provider._CONFIG_SCOPE_LEASE.hold(), config_provider._CONFIG_EXECUTION_LOCK:
        retained = config_provider._retain_provider_failure(
            primary,
            RuntimeError("secondary"),
            description="hostile note container",
        )

    assert retained is primary
    assert callback_states == []
    assert dict.get(exception_namespace, "__notes__") is hostile_notes
    assert list.__eq__(hostile_notes, ["existing"])


def test_hostile_primary_preserves_multi_failure_precedence_and_exact_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple locked failures annotate storage directly and retain the exact primary."""

    callback_states: list[tuple[str, bool, bool]] = []

    class JoiningPrimary(BaseException):
        def __getattribute__(self, name: str) -> Any:
            if name == "__notes__":
                callback_states.append(
                    (
                        "get",
                        config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                        config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                    )
                )
            return BaseException.__getattribute__(self, name)

        def __setattr__(self, name: str, value: Any) -> None:
            if name == "__notes__":
                callback_states.append(
                    (
                        "set",
                        config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                        config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                    )
                )
            BaseException.__setattr__(self, name, value)

    coordinators = tuple(
        _FaultingRuntimeCacheCoordinator(name) for name in ("primary", "secondary", "restore")
    )
    _install_faulting_runtime_caches(monkeypatch, coordinators)
    primary = JoiningPrimary("setup primary")
    coordinators[0].clear_failures[1] = primary
    coordinators[1].clear_failures[1] = SystemExit("secondary clear")
    coordinators[2].restore_failures[1] = RuntimeError("secondary restore")

    with pytest.raises(BaseException) as caught:
        with effective_config_scope(
            _effective_timing_config(),
            refresh_legacy_globals=False,
        ):
            pytest.fail("scope entered after hostile primary cache failure")

    exception_namespace = BaseException.__dict__["__dict__"].__get__(
        primary,
        BaseException,
    )
    assert caught.value is primary
    assert callback_states == []
    assert type(exception_namespace["__notes__"]) is list
    assert len(exception_namespace["__notes__"]) == 2
    assert tuple(coordinator.restore_calls for coordinator in coordinators) == (1, 1, 1)
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    for coordinator in coordinators:
        coordinator.clear_failures.clear()
        coordinator.restore_failures.clear()
    retry = _effective_timing_config()
    with effective_config_scope(retry, refresh_legacy_globals=False):
        assert current_effective_config() is retry


def test_real_ambient_overlay_logger_joins_loader_outside_all_provider_locks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Production overlay logging can join an independently prepared publication."""

    from evidenceforge.config import overlay as overlay_module

    overlay_directory = tmp_path / ".eforge" / "config" / "activity"
    overlay_directory.mkdir(parents=True)
    (overlay_directory / "timing_profiles.yaml").write_text(
        "relationships: {}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    callback_states: list[tuple[bool, bool]] = []
    nested_snapshots: list[Mapping[str, Any]] = []
    callback_lock = Lock()
    should_join = True

    class JoiningOverlayHandler(logging.Handler):
        def filter(self, _record: logging.LogRecord) -> bool:
            with callback_lock:
                return should_join

        def emit(self, _record: logging.LogRecord) -> None:
            nonlocal should_join
            callback_states.append(
                (
                    config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                    config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
                )
            )
            with callback_lock:
                should_join = False
            with ThreadPoolExecutor(max_workers=1) as executor:
                nested_snapshots.append(executor.submit(load_timing_profiles).result(timeout=10))

    handler = JoiningOverlayHandler()
    original_level = overlay_module.logger.level
    overlay_module.logger.setLevel(logging.INFO)
    overlay_module.logger.addHandler(handler)
    try:
        published = load_timing_profiles()
    finally:
        overlay_module.logger.removeHandler(handler)
        overlay_module.logger.setLevel(original_level)

    assert callback_states == [(False, False)]
    assert nested_snapshots == [published]
    assert load_timing_profiles() is published


@pytest.mark.parametrize("callback_kind", ["warning", "logger"])
@pytest.mark.parametrize("entry_path", ["direct", "provider"])
def test_callback_coordinator_rebinding_uses_only_anchor_and_retries(
    monkeypatch: pytest.MonkeyPatch,
    callback_kind: str,
    entry_path: str,
) -> None:
    """Warning and logger callbacks cannot move publication to a hostile peer binding."""

    callback_attempts: list[str] = []

    class HostileCoordinator:
        def __getattribute__(self, name: str) -> Any:
            callback_attempts.append(name)
            raise AssertionError("hostile replacement coordinator was invoked")

    replacement = HostileCoordinator()
    original_coordinator = timing_profiles_module._CACHED_TIMING_PROFILES
    if callback_kind == "warning":
        monkeypatch.setattr(
            timing_profiles_module,
            "load_with_overlay",
            _return_value_loader(_legacy_authored()),
        )
    else:
        monkeypatch.setattr(
            timing_profiles_module,
            "load_with_overlay",
            _layered_loader(
                {
                    "replace_me": 1,
                    "network_sensor_observation": {"profiles": {}},
                },
                {"replace_me": 2},
            ),
        )

    def rebind_coordinator() -> None:
        dict.__setitem__(
            timing_profiles_module.__dict__,
            "_CACHED_TIMING_PROFILES",
            replacement,
        )

    def invoke() -> Mapping[str, Any]:
        if entry_path == "direct":
            return load_timing_profiles()
        effective = _effective_timing_config()
        with effective_config_scope(effective, refresh_legacy_globals=False):
            assert current_effective_config() is effective
            return load_timing_profiles()

    original_showwarning = warnings.showwarning

    class RebindingHandler(logging.Handler):
        def emit(self, _record: logging.LogRecord) -> None:
            rebind_coordinator()

    handler = RebindingHandler()
    original_level = timing_profiles_module.logger.level
    try:
        if callback_kind == "warning":

            def rebind_from_warning(
                _message: Warning | str,
                _category: type[Warning],
                _filename: str,
                _lineno: int,
                _file: Any = None,
                _line: str | None = None,
            ) -> None:
                rebind_coordinator()

            warnings.showwarning = rebind_from_warning
        else:
            timing_profiles_module.logger.setLevel(logging.WARNING)
            timing_profiles_module.logger.addHandler(handler)
        with warnings.catch_warnings():
            warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
            with pytest.raises(
                RuntimeError,
                match="timing profile cache coordinator binding was replaced",
            ):
                invoke()
    finally:
        warnings.showwarning = original_showwarning
        timing_profiles_module.logger.removeHandler(handler)
        timing_profiles_module.logger.setLevel(original_level)
        dict.__setitem__(
            timing_profiles_module.__dict__,
            "_CACHED_TIMING_PROFILES",
            original_coordinator,
        )

    assert callback_attempts == []
    assert original_coordinator.state.phase is _TimingProfileCachePhase.EMPTY
    assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()
    assert timing_profiles_module._EMITTED_TIMING_PROFILE_DIAGNOSTICS == frozenset()
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        recovered = invoke()
    assert isinstance(recovered, Mapping)


@pytest.mark.parametrize("callback_kind", ["warning", "logger"])
@pytest.mark.parametrize("entry_path", ["direct", "provider"])
def test_callback_ledger_rebinding_is_callback_free_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
    callback_kind: str,
    entry_path: str,
) -> None:
    """Callback-visible ledger mirrors cannot dispatch hostile work under cache locks."""

    callback_attempts: list[str] = []

    class HostileLedger:
        def __getattribute__(self, name: str) -> Any:
            callback_attempts.append(name)
            raise AssertionError("hostile timing callback ledger was invoked")

        def __iter__(self) -> Iterator[Any]:
            callback_attempts.append("__iter__")
            raise AssertionError("hostile timing callback ledger was iterated")

    replacement = HostileLedger()
    if callback_kind == "warning":
        monkeypatch.setattr(
            timing_profiles_module,
            "load_with_overlay",
            _return_value_loader(_legacy_authored()),
        )
        ledger_name = "_WARNED_TIMING_PROFILE_ALIASES"
    else:
        monkeypatch.setattr(
            timing_profiles_module,
            "load_with_overlay",
            _layered_loader(
                {
                    "replace_me": 1,
                    "network_sensor_observation": {"profiles": {}},
                },
                {"replace_me": 2},
            ),
        )
        ledger_name = "_EMITTED_TIMING_PROFILE_DIAGNOSTICS"

    def rebind_ledger() -> None:
        dict.__setitem__(timing_profiles_module.__dict__, ledger_name, replacement)

    def invoke() -> Mapping[str, Any]:
        if entry_path == "direct":
            return load_timing_profiles()
        effective = _effective_timing_config()
        with effective_config_scope(effective, refresh_legacy_globals=False):
            return load_timing_profiles()

    original_showwarning = warnings.showwarning

    class RebindingHandler(logging.Handler):
        def emit(self, _record: logging.LogRecord) -> None:
            rebind_ledger()

    handler = RebindingHandler()
    original_level = timing_profiles_module.logger.level
    try:
        if callback_kind == "warning":

            def rebind_from_warning(
                _message: Warning | str,
                _category: type[Warning],
                _filename: str,
                _lineno: int,
                _file: Any = None,
                _line: str | None = None,
            ) -> None:
                rebind_ledger()

            warnings.showwarning = rebind_from_warning
        else:
            timing_profiles_module.logger.setLevel(logging.WARNING)
            timing_profiles_module.logger.addHandler(handler)
        with warnings.catch_warnings():
            warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
            with pytest.raises(
                RuntimeError,
                match="timing profile callback ledger binding was replaced",
            ):
                invoke()
    finally:
        warnings.showwarning = original_showwarning
        timing_profiles_module.logger.removeHandler(handler)
        timing_profiles_module.logger.setLevel(original_level)

    assert callback_attempts == []
    assert timing_profiles_module._WARNED_TIMING_PROFILE_ALIASES == frozenset()
    assert timing_profiles_module._EMITTED_TIMING_PROFILE_DIAGNOSTICS == frozenset()
    assert _cache_phase() is _TimingProfileCachePhase.EMPTY
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        recovered = invoke()
    assert isinstance(recovered, Mapping)


def test_provider_preparation_validates_exact_timing_module_before_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A callback-time module replacement is rejected before validator dispatch or lease."""

    module_name = "evidenceforge.generation.activity.timing_profiles"
    original_module = dict.get(sys.modules, module_name)
    replacement = ModuleType(module_name)
    callback_states: list[tuple[bool, bool]] = []
    hostile_validator_states: list[tuple[bool, bool]] = []

    def hostile_validator(_prepared: Any) -> bool:
        hostile_validator_states.append(
            (
                config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
            )
        )
        raise AssertionError("hostile timing preparation validator was invoked")

    dict.__setitem__(
        replacement.__dict__,
        "_prepared_timing_profiles_are_current",
        hostile_validator,
    )

    def replace_module_from_warning(
        _message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        callback_states.append(
            (
                config_provider._CONFIG_EXECUTION_LOCK._is_owned(),
                config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread(),
            )
        )
        dict.__setitem__(sys.modules, module_name, replacement)

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(_legacy_authored()),
    )
    original_showwarning = warnings.showwarning
    provider = _effective_timing_config()
    try:
        warnings.showwarning = replace_module_from_warning
        with warnings.catch_warnings():
            warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
            with pytest.raises(RuntimeError, match="anchored runtime module was replaced"):
                with effective_config_scope(provider, refresh_legacy_globals=False):
                    pytest.fail("scope entered after timing module replacement")
    finally:
        warnings.showwarning = original_showwarning
        if original_module is not None:
            dict.__setitem__(sys.modules, module_name, original_module)

    assert callback_states == [(False, False), (False, False)]
    assert hostile_validator_states == []
    assert _cache_phase() is _TimingProfileCachePhase.EMPTY
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    with effective_config_scope(provider, refresh_legacy_globals=False):
        assert load_timing_profiles()


def test_coordinator_protocol_ignores_callback_rebound_class_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider snapshot/clear/restore and public reset use captured protocol closures."""

    coordinator = timing_profiles_module._TIMING_PROFILE_CACHE_COORDINATOR
    coordinator_type = type(coordinator)
    original_clear = coordinator_type.clear
    original_wait = coordinator_type._wait_until_stable
    original_get_ident = timing_profiles_module.get_ident
    callback_attempts: list[str] = []

    def hostile_clear(*_args: Any, **_kwargs: Any) -> None:
        callback_attempts.append("clear")
        raise AssertionError("rebound coordinator clear was invoked")

    def hostile_wait(*_args: Any, **_kwargs: Any) -> None:
        callback_attempts.append("wait")
        raise AssertionError("rebound coordinator wait was invoked")

    def hostile_get_ident() -> int:
        callback_attempts.append("get_ident")
        raise AssertionError("rebound thread identity helper was invoked")

    def rebind_protocol_from_warning(
        _message: Warning | str,
        _category: type[Warning],
        _filename: str,
        _lineno: int,
        _file: Any = None,
        _line: str | None = None,
    ) -> None:
        type.__setattr__(coordinator_type, "clear", hostile_clear)
        type.__setattr__(coordinator_type, "_wait_until_stable", hostile_wait)
        dict.__setitem__(timing_profiles_module.__dict__, "get_ident", hostile_get_ident)

    monkeypatch.setattr(
        timing_profiles_module,
        "load_with_overlay",
        _return_value_loader(_legacy_authored()),
    )
    original_showwarning = warnings.showwarning
    try:
        warnings.showwarning = rebind_protocol_from_warning
        with warnings.catch_warnings():
            warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
            with effective_config_scope(
                _effective_timing_config(),
                refresh_legacy_globals=False,
            ):
                assert load_timing_profiles()
        reset_timing_profiles_cache()
        _reset_timing_profile_warning_ledger_for_tests()
    finally:
        warnings.showwarning = original_showwarning
        type.__setattr__(coordinator_type, "clear", original_clear)
        type.__setattr__(coordinator_type, "_wait_until_stable", original_wait)
        dict.__setitem__(timing_profiles_module.__dict__, "get_ident", original_get_ident)

    assert callback_attempts == []
    assert coordinator.state.phase is _TimingProfileCachePhase.EMPTY
    assert current_effective_config() is None
    assert not config_provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()

    with warnings.catch_warnings():
        warnings.simplefilter("always", EvidenceForgeDeprecationWarning)
        with effective_config_scope(
            _effective_timing_config(),
            refresh_legacy_globals=False,
        ):
            assert load_timing_profiles()


@pytest.mark.parametrize("removed_target", ["module", "slot"])
def test_late_timing_import_removed_before_cleanup_clears_anchor_and_retries(
    removed_target: str,
) -> None:
    """Cleanup explicitly clears a late coordinator whose canonical owner disappears."""

    script = """
import importlib
import sys
from types import SimpleNamespace

from evidenceforge.config import provider

name = "evidenceforge.generation.activity.timing_profiles"
removed_target = "__REMOVED_TARGET__"
assert name not in sys.modules
assert provider._get_timing_profile_runtime_cache_anchor() is None
primary = SystemExit("body primary")
anchor = None
try:
    with provider.effective_config_scope(
        SimpleNamespace(marker=1, ambient_overlay_compat=True, packaged_defaults={}),
        refresh_legacy_globals=False,
    ):
        timing = importlib.import_module(name)
        anchor = provider._get_timing_profile_runtime_cache_anchor()
        assert anchor is not None
        timing.load_timing_profiles()
        assert anchor.controller.state.phase.name == "READY"
        if removed_target == "module":
            dict.__delitem__(sys.modules, name)
        else:
            dict.__delitem__(timing.__dict__, "_CACHED_TIMING_PROFILES")
        raise primary
except SystemExit as caught:
    assert caught is primary
assert anchor is not None
assert anchor.controller.state.phase.name == "EMPTY"
assert provider.current_effective_config() is None
assert not provider._CONFIG_SCOPE_LEASE.owned_by_current_thread()
if removed_target == "module":
    dict.__setitem__(sys.modules, name, anchor.owner.module)
else:
    dict.__setitem__(timing.__dict__, "_CACHED_TIMING_PROFILES", anchor.controller)
with provider.effective_config_scope(
    SimpleNamespace(marker=2, ambient_overlay_compat=True, packaged_defaults={}),
    refresh_legacy_globals=False,
):
    assert timing.load_timing_profiles()
assert anchor.controller.state.phase.name == "EMPTY"
""".replace("__REMOVED_TARGET__", removed_target)
    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
