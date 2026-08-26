# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production-boundary coverage for persistent Windows SMB activities."""

from __future__ import annotations

import gc
import json
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import copy
from datetime import timedelta
from pathlib import Path
from typing import Literal

import pytest

from evidenceforge.events.dispatcher import PersistentSmbSourcePublicationResult
from evidenceforge.generation.actions.smb_activity import SmbActivityActionBundle
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbTerminalContinuation,
    PersistentSmbTerminalContinuationAuthority,
)
from evidenceforge.generation.resource_forecast import (
    ForecastRange,
    ResourceForecast,
    ResourceSnapshot,
)
from evidenceforge.generation.source_timing import SourceTimingPreparation
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng

_SOURCE_FILENAMES = frozenset(
    {
        "conn.json",
        "ecar.json",
        "files.json",
        "smb_files.json",
        "smb_mapping.json",
        "windows_event_security.xml",
    }
)


class _InjectedPublicError(RuntimeError):
    """One test-only failure injected at a public instance method."""


class _OneShotPublicFault:
    """Fail one public call either before mutation or after its return is lost."""

    def __init__(
        self,
        original: Callable[..., object],
        mode: Literal["fail_before", "lost_return"],
        *,
        observe: Callable[[], object] | None = None,
    ) -> None:
        self.original = original
        self.mode = mode
        self.observe = observe
        self.calls = 0
        self.results: list[object] = []
        self.observations: list[object] = []

    def __call__(self, *args: object, **kwargs: object) -> object:
        self.calls += 1
        if self.calls == 1:
            if self.mode == "lost_return":
                result = self.original(*args, **kwargs)
                self.results.append(result)
            if self.observe is not None:
                self.observations.append(self.observe())
            raise _InjectedPublicError(f"injected {self.mode}")
        result = self.original(*args, **kwargs)
        self.results.append(result)
        return result


class _PersistentPublicFault:
    """Keep one public acknowledgement unavailable until the test restores it."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: object, **kwargs: object) -> object:
        self.calls += 1
        raise _InjectedPublicError("injected persistent fail-before")


class _ReservationCapture:
    """Capture the exact continuation returned by one real pre-root reservation."""

    def __init__(self, original: Callable[..., PersistentSmbTerminalContinuation]) -> None:
        self.original = original
        self.continuation: PersistentSmbTerminalContinuation | None = None
        self.arguments: dict[str, object] = {}

    def __call__(self, **kwargs: object) -> PersistentSmbTerminalContinuation:
        continuation = self.original(**kwargs)
        self.continuation = continuation
        self.arguments = dict(kwargs)
        return continuation


def _assert_event_contract_error_without_traceback(call: Callable[[], object]) -> None:
    """Assert one guard failure without retaining owner-bearing traceback frames."""

    try:
        call()
    except EventContractError as error:
        error.__traceback__ = None
        return
    raise AssertionError("Expected EventContractError")


def _assert_terminal_continuation_capacity_is_neutral(arguments: dict[str, object]) -> None:
    """Exercise capacity failure in a disposable frame that releases retained receipts."""

    authority = PersistentSmbTerminalContinuationAuthority(capacity=1)
    capacity_arguments = dict(arguments)
    retained = authority.reserve_claimed(**capacity_arguments)
    before = authority.census()
    capacity_arguments["action_id"] = f"{capacity_arguments['action_id']}:capacity"
    capacity_arguments["action_binding_digest"] = "d" * 64
    _assert_event_contract_error_without_traceback(
        lambda: authority.reserve_claimed(**capacity_arguments)
    )
    assert authority.census() == before
    assert before.retained_continuations == 1
    assert authority.root_facts(retained).phase == "reserved"
    assert authority.cancel_uncommitted(retained)
    assert authority.census().retained_continuations == 0


def _forecast(output: Path) -> ResourceForecast:
    available = 64 * 1024**3
    return ResourceForecast(
        calibration_version=1,
        calibration_label="test",
        memory=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        final_output=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        disk=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        snapshot=ResourceSnapshot(
            total_memory_bytes=available,
            available_memory_bytes=available,
            free_swap_bytes=available,
            free_disk_bytes=available,
            disk_path=str(output),
        ),
    )


def _windows_read_scenario(
    scenarios_dir: Path,
    *,
    output_formats: tuple[str, ...] = ("windows", "zeek", "ecar"),
    file_count: int = 1,
    outcome: Literal["success", "access_denied"] = "success",
) -> Scenario:
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["generation_seed"] = 99
    data["time_window"] = {"start": "2024-01-15T10:00:00Z", "duration": "20m"}
    data["baseline_activity"]["intensity"] = "low"
    data["baseline_activity"]["traffic_rates"] = {"smb_interval": 50_000}
    client_hostname = "SMBCLIENT-09"
    data["environment"]["users"][0]["primary_system"] = client_hostname
    data["environment"]["systems"][0]["hostname"] = client_hostname
    data["environment"]["network"]["segments"][0]["systems"] = [client_hostname]
    data["environment"]["systems"].append(
        {
            "hostname": "FS-01",
            "ip": "10.0.0.20",
            "os": "Windows Server 2022",
            "type": "server",
            "roles": [],
        }
    )
    data["environment"]["network"]["segments"][0]["systems"].append("FS-01")
    data["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "D:\\"}],
                "shares": [
                    {
                        "id": "finance",
                        "name": "Finance",
                        "volume": "data",
                        "root": "Departments\\Finance",
                        "preset": "department",
                        "access": {
                            "read": ["test_user"],
                            "modify": ["test_user"],
                            "deny": ["test_user"] if outcome == "access_denied" else [],
                        },
                        "seed_files": [
                            {
                                "ref": "forecast" if file_count == 1 else f"forecast-{index:02d}",
                                "path": "Reports\\FY26\\forecast.xlsx"
                                if file_count == 1
                                else f"Reports\\FY26\\forecast-{index:02d}.xlsx",
                                "size_bytes": 1_843_200 if file_count == 1 else 4_096 + index,
                                "tags": ["finance"],
                            }
                            for index in range(file_count)
                        ],
                    }
                ],
            }
        ],
    }
    data["storyline"] = [
        {
            "id": "read-forecast",
            "time": "+10m",
            "actor": "test_user",
            "system": client_hostname,
            "activity": "Read a forecast from Finance",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {
                        "type": "share",
                        "share": "FS-01.finance",
                        **({"file_ref": "forecast"} if file_count == 1 else {}),
                    },
                    **(
                        {"batch": {"count": file_count, "duration": "8m"}} if file_count > 1 else {}
                    ),
                    "outcome": outcome,
                }
            ],
        }
    ]
    data["output"]["logs"] = [{"format": format_name} for format_name in output_formats]
    return Scenario(**data)


def _windows_client_file_set_scenario(
    scenarios_dir: Path,
    *,
    operation: Literal["copy", "move"] = "copy",
) -> Scenario:
    """Return one bounded two-file upload through the production SMB owner."""

    data = _windows_read_scenario(scenarios_dir, file_count=2).model_dump(mode="python")
    data["environment"]["storage"]["file_sets"] = [
        {
            "id": "client-staging",
            "system": "SMBCLIENT-09",
            "root": r"C:\Users\test_user",
            "preset": "homes",
            "population": "small",
            "seed_files": [
                {
                    "ref": "client-doc",
                    "path": r"Documents\Client Plan.docx",
                    "size_bytes": 8192,
                    "tags": ["staging"],
                },
                {
                    "ref": "client-image",
                    "path": r"Pictures\Client Diagram.png",
                    "size_bytes": 16384,
                    "tags": ["staging"],
                },
            ],
        }
    ]
    data["storyline"][0]["activity"] = "Upload a bounded local staging set"
    data["storyline"][0]["events"] = [
        {
            "type": "smb_activity",
            "operation": operation,
            "source": {
                "type": "client",
                "file_set": "client-staging",
                "selector": {"tags_any": ["staging"]},
            },
            "destination": {
                "type": "share",
                "share": "FS-01.finance",
                "directory": "Incoming",
            },
            "batch": {"count": 2, "duration": "20s"},
            "outcome": "success",
        }
    ]
    return Scenario.model_validate(data)


def _json_records(output: Path, filename: str) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for path in output.rglob(filename)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _source_bytes(output: Path) -> tuple[tuple[str, bytes], ...]:
    return tuple(
        sorted(
            (str(path.relative_to(output)), path.read_bytes())
            for path in output.rglob("*")
            if path.is_file() and path.name in _SOURCE_FILENAMES
        )
    )


def _invoke_windows_read(engine: GenerationEngine, scenario: Scenario) -> object:
    storyline = scenario.storyline[0]
    with generation_seed_scope(scenario.generation_seed):
        reset_thread_rng()
        return engine.activity_generator.generate_smb_activity(
            spec=storyline.events[0],
            actor=scenario.environment.users[0],
            parent_system=scenario.environment.systems[0],
            time=engine.start_time + timedelta(minutes=10),
            activity_source="storyline",
        )


def _assert_exact_source_order(output: Path) -> None:
    source_paths = tuple(path for path, _payload in _source_bytes(output))
    assert source_paths == (
        "FS-01.example.com/ecar.json",
        "FS-01.example.com/windows_event_security.xml",
        "SMBCLIENT-09.example.com/ecar.json",
        "core-zeek/conn.json",
        "core-zeek/files.json",
        "core-zeek/smb_files.json",
        "core-zeek/smb_mapping.json",
    )
    assert [row["action"] for row in _json_records(output, "FS-01.example.com/ecar.json")] == [
        "CONNECT",
        "LOGIN",
        "READ",
        "LOGOUT",
    ]
    assert [
        row["action"] for row in _json_records(output, "SMBCLIENT-09.example.com/ecar.json")
    ] == ["CONNECT"]
    assert [row["action"] for row in _json_records(output, "smb_files.json")] == [
        "SMB::FILE_OPEN",
        "SMB::FILE_READ",
    ]
    windows_xml = next(output.rglob("windows_event_security.xml")).read_text(encoding="utf-8")
    assert re.findall(r"<EventID[^>]*>(\d+)</EventID>", windows_xml) == [
        "4624",
        "5140",
        "4634",
    ]


def _assert_transient_authorities_drained(engine: GenerationEngine) -> None:
    generator = engine.activity_generator
    state = generator.state_manager.get_state_summary()
    assert {
        key: value
        for key, value in state.items()
        if key.startswith("smb_file_mutation_") or key.startswith("smb_connection_")
    } == {
        "smb_file_mutation_journals": 0,
        "smb_file_mutation_capabilities": 0,
        "smb_file_mutation_operation_indexes": 0,
        "smb_file_mutation_file_owners": 0,
        "smb_file_mutation_path_owners": 0,
        "smb_file_mutation_journal_entries": 0,
        "smb_file_mutation_commit_results": 0,
        "smb_file_mutation_commit_receipts": 0,
        "smb_file_mutation_acknowledging": 0,
        "smb_file_mutation_cancelling": 0,
        "smb_file_mutation_journal_locators": 0,
        "smb_file_mutation_result_locators": 0,
        "smb_file_mutation_retained_bytes": 0,
        "smb_connection_pins_active": 0,
        "smb_connection_pins_terminal": 0,
        "smb_connection_pin_install_receipts": 0,
        "smb_connection_finalization_results": 0,
        "smb_connection_finalization_receipts": 0,
        "smb_connection_pin_acknowledging": 0,
        "smb_connection_pin_session_owners": 0,
        "smb_connection_pin_protected_sessions": 0,
        "smb_connection_pin_reserved_bytes": 0,
        "smb_connection_pin_retained_bytes": 0,
    }
    application = generator._smb_channel_manager.census()
    assert (application.open_sessions, application.open_trees, application.open_handles) == (
        0,
        0,
        0,
    )
    assert (
        application.application.prepared_admissions,
        application.application.claimed_admissions,
        application.application.reserved_channel_ids,
        application.application.reserved_transport_ids,
        application.application.reserved_operation_ids,
        application.application.prepared_admission_tokens,
        application.application.prepared_admission_capabilities,
        application.application.prepared_close_tokens,
        application.application.prepared_close_capabilities,
        application.application.prepared_close_projections,
        application.application.prepared_commit_journals,
        application.application.prepared_close_commit_journals,
        application.application.releasing_admissions,
        application.application.acknowledging_admission_results,
        application.application.acknowledging_close_results,
        application.application.recoverable_admission_receipts,
        application.application.recoverable_close_results,
        application.application.recoverable_close_receipts,
    ) == (0,) * 18
    group = generator.dispatcher.persistent_smb_projection_group_census()
    assert (
        group.retained_groups,
        group.inactive_members,
        group.certified_members,
        group.committed_unacknowledged_members,
        group.retained_commit_receipts,
        group.retained_bytes,
        group.reserved_member_capacity,
        group.reserved_receipt_capacity,
        group.reserved_byte_capacity,
        group.retained_target_generations,
    ) == (0,) * 10
    source = generator.dispatcher.persistent_smb_source_publication_census()
    assert (
        source.active_publications,
        source.prepared_publications,
        source.published_unacknowledged,
        source.acknowledged_terminal_proofs,
        source.retained_rows,
        source.retained_bytes,
    ) == (0,) * 6
    exact = generator.dispatcher.exact_projection_recovery_census()
    assert (
        exact.unresolved_recoveries,
        exact.reserved_recoveries,
        exact.active_recoveries,
        exact.state_neutral_receipts,
        exact.authority.active_batches,
        exact.authority.prepared_batches,
        exact.authority.retained_rows,
        exact.authority.retained_bytes,
    ) == (0,) * 8
    network = generator._network_transaction_runtime.census()
    assert (
        network.open_preparations,
        network.prepared_transactions,
        network.claimed_transactions,
        network.reserved_points,
        network.preparation_fences,
        network.reserved_deadlines,
    ) == (0,) * 6
    lifecycle = generator._lifecycle_authority.census()
    assert (
        lifecycle.materialization_batch_transactions_pending,
        lifecycle.materialization_batch_transactions_unacknowledged,
    ) == (0, 0)
    timing = generator._source_timing_planner.preparation_authority_census()
    assert (
        timing.retained_preparations,
        timing.active_claims,
        timing.terminal_preparations,
        timing.retained_receipts,
        timing.retained_plan_operations,
    ) == (0,) * 5
    assert generator._source_timing_planner.detached_binding_census().retained_bindings == 0
    terminal = generator.persistent_smb_terminal_continuation_census()
    assert (
        terminal.retained_continuations,
        terminal.active_claims,
        terminal.retained_bytes,
    ) == (0, 0, 0)


def _retained_smb_terminal_state(engine: GenerationEngine) -> tuple[int, int, int, int]:
    state = engine.activity_generator.state_manager.get_state_summary()
    return (
        state["smb_file_mutation_journals"],
        state["smb_file_mutation_commit_results"],
        state["smb_connection_pins_active"],
        state["smb_connection_pins_terminal"],
    )


@pytest.fixture(scope="module")
def windows_read_control(tmp_path_factory: pytest.TempPathFactory) -> tuple[tuple[str, bytes], ...]:
    output = tmp_path_factory.mktemp("persistent-smb-control")
    scenario = _windows_read_scenario(Path(__file__).parents[1] / "fixtures" / "scenarios")
    engine = GenerationEngine(scenario, output, resource_forecast=_forecast(output))
    try:
        engine._initialize()
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    connection_uids = {
        str(row["uid"]) for row in _json_records(output, "conn.json") if row.get("service") == "smb"
    }
    assert result.transport_uids[0] in connection_uids
    _assert_exact_source_order(output)
    return _source_bytes(output)


@pytest.fixture(scope="module")
def windows_two_file_control(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, tuple[dict[str, object], ...], tuple[tuple[str, bytes], ...]]:
    """Generate one exact two-file persistent-SMB control."""

    output = tmp_path_factory.mktemp("persistent-smb-two-file-control")
    scenario = _windows_read_scenario(
        Path(__file__).parents[1] / "fixtures" / "scenarios",
        file_count=2,
    )
    engine = GenerationEngine(scenario, output, resource_forecast=_forecast(output))
    try:
        engine._initialize()
        result = _invoke_windows_read(engine, scenario)
        assert len(result.operations) == 2
        assert len(result.transport_uids) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    return output, result.operations, _source_bytes(output)


@pytest.mark.slow
def test_generate_smb_activity_uses_one_persistent_windows_root(
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """The real caller completes one TCP/445 session/tree/file/close vertical."""

    assert tuple(path for path, _payload in windows_read_control) == (
        "FS-01.example.com/ecar.json",
        "FS-01.example.com/windows_event_security.xml",
        "SMBCLIENT-09.example.com/ecar.json",
        "core-zeek/conn.json",
        "core-zeek/files.json",
        "core-zeek/smb_files.json",
        "core-zeek/smb_mapping.json",
    )


@pytest.mark.slow
def test_client_file_set_move_commits_destinations_before_retiring_sources(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    """A bounded client move leaves two live destinations and no live source objects."""

    scenario = _windows_client_file_set_scenario(scenarios_dir, operation="move")
    source_files = scenario.environment.storage.file_sets[0]
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        world = engine.activity_generator._storage_world
        selected = world.select_file_set(
            source_files.id, selector=scenario.storyline[0].events[0].source.selector
        )
        result = _invoke_windows_read(engine, scenario)

        assert len(result.operations) == 2
        assert all(
            not engine.activity_generator.state_manager.smb_file_is_available(file)
            for file in selected
        )
        destinations = [
            state
            for state in engine.activity_generator.state_manager._smb_file_overlay.values()
            if state.share.casefold() == "fs-01.finance"
            and state.path.casefold().startswith("incoming\\")
            and not state.deleted
        ]
        assert len(destinations) == 2
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()


@pytest.mark.slow
def test_multi_file_client_upload_lost_commit_return_does_not_duplicate_evidence(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One lost mutation acknowledgement recovers a two-file upload exactly once."""

    scenario = _windows_client_file_set_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        state = engine.activity_generator.state_manager
        fault = _OneShotPublicFault(state.acknowledge_smb_file_mutation_commit, "lost_return")
        monkeypatch.setattr(state, "acknowledge_smb_file_mutation_commit", fault)

        result = _invoke_windows_read(engine, scenario)

        assert len(result.operations) == 2
        assert fault.calls == 1
        assert len(fault.results) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()

    writes = [
        row
        for row in _json_records(tmp_path, "smb_files.json")
        if row.get("action") == "SMB::FILE_WRITE"
        and str(row.get("name", "")).startswith("Incoming\\")
    ]
    assert len(writes) == 2
    assert len({row["uid"] for row in writes}) == 1


@pytest.mark.slow
def test_persistent_smb_result_uses_exact_published_transport_identifier() -> None:
    """Terminal activity truth selects the authenticated transport projection exactly."""

    def source_result(
        identifiers: tuple[tuple[str, str], ...],
    ) -> PersistentSmbSourcePublicationResult:
        return PersistentSmbSourcePublicationResult(
            group_id=1,
            generation_id="generation",
            publication_key="publication",
            publication_binding_digest="a" * 64,
            target_formats=("zeek_conn",),
            member_operation_ids=("activity:0:transport",),
            row_facts=(),
            projection_identifiers=(identifiers,),
            publication_digest="b" * 64,
        )

    observed_uid = "C-observed"
    canonical_uid = "C-canonical"
    assert SmbActivityActionBundle._persistent_source_transport_uids(
        source_result((("zeek_conn", observed_uid),)),
        canonical_uid=canonical_uid,
    ) == (observed_uid,)
    assert SmbActivityActionBundle._persistent_source_transport_uids(
        source_result(()),
        canonical_uid=canonical_uid,
    ) == (canonical_uid,)
    assert SmbActivityActionBundle._persistent_source_transport_uids(
        source_result((("snort_alert", ""), ("zeek_conn", ""))),
        canonical_uid=canonical_uid,
    ) == (canonical_uid,)
    with pytest.raises(EventContractError, match="ambiguous"):
        SmbActivityActionBundle._persistent_source_transport_uids(
            source_result(
                (
                    ("zeek_conn", observed_uid),
                    ("zeek_conn", "C-second-observation"),
                )
            ),
            canonical_uid=canonical_uid,
        )
    with pytest.raises(EventContractError, match="ambiguous"):
        SmbActivityActionBundle._persistent_source_transport_uids(
            source_result((("zeek_conn", ""), ("zeek_conn", observed_uid))),
            canonical_uid=canonical_uid,
        )
    with pytest.raises(EventContractError, match="malformed"):
        SmbActivityActionBundle._persistent_source_transport_uids(
            source_result((("", ""),)),
            canonical_uid=canonical_uid,
        )


@pytest.mark.slow
def test_persistent_smb_two_file_order_counters_and_transport_bytes(
    windows_two_file_control: tuple[
        Path,
        tuple[dict[str, object], ...],
        tuple[tuple[str, bytes], ...],
    ],
) -> None:
    """Two files retain source order and exact aggregate read transport bytes."""

    output, operations, _source = windows_two_file_control
    operation_paths = [str(operation["path"]) for operation in operations]
    server_rows = [
        row for row in _json_records(output, "ecar.json") if row.get("hostname") == "FS-01"
    ]
    assert [row["action"] for row in server_rows] == [
        "CONNECT",
        "LOGIN",
        "READ",
        "READ",
        "LOGOUT",
    ]
    assert [
        row.get("properties", {}).get("file_path") for row in server_rows if row["action"] == "READ"
    ] == [f"D:\\Departments\\Finance\\{path}" for path in operation_paths]

    smb_rows = _json_records(output, "smb_files.json")
    assert [row["action"] for row in smb_rows] == [
        "SMB::FILE_OPEN",
        "SMB::FILE_READ",
        "SMB::FILE_OPEN",
        "SMB::FILE_READ",
    ]
    assert [row["name"] for row in smb_rows] == [
        operation_paths[0],
        operation_paths[0],
        operation_paths[1],
        operation_paths[1],
    ]
    connection = _json_records(output, "conn.json")
    assert len(connection) == 1
    assert connection[0]["orig_bytes"] == 3_427
    assert (
        connection[0]["resp_bytes"]
        == sum(int(operation["size_bytes"]) for operation in operations) + 4_412
    )


@pytest.mark.slow
def test_persistent_smb_second_file_failure_is_neutral_and_replayable(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_two_file_control: tuple[
        Path,
        tuple[dict[str, object], ...],
        tuple[tuple[str, bytes], ...],
    ],
) -> None:
    """A second-file preparation failure cancels every pre-root owner before replay."""

    scenario = _windows_read_scenario(scenarios_dir, file_count=2)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        state = engine.activity_generator.state_manager
        state_before = state.get_state_summary()
        original = state.touch_smb_file
        calls = 0

        def fail_second_touch(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise _InjectedPublicError("injected second-file preparation failure")
            return original(*args, **kwargs)

        monkeypatch.setattr(state, "touch_smb_file", fail_second_touch)
        with pytest.raises(_InjectedPublicError, match="second-file"):
            _invoke_windows_read(engine, scenario)
        assert calls == 2
        assert state.get_state_summary() == state_before
        assert _source_bytes(tmp_path) == ()
        _assert_transient_authorities_drained(engine)

        monkeypatch.setattr(state, "touch_smb_file", original)
        result = _invoke_windows_read(engine, scenario)
        assert len(result.operations) == 2
        assert len(result.transport_uids) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_two_file_control[2]


@pytest.mark.soak
def test_persistent_smb_50_file_batch_uses_one_bounded_carrier(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    """The supported 50-file scenario retains every operation on one carrier."""

    scenario = _windows_read_scenario(scenarios_dir, output_formats=("zeek",), file_count=50)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        result = _invoke_windows_read(engine, scenario)
        assert len(result.operations) == 50
        assert len(result.transport_uids) == 1
        assert len({str(operation["path"]) for operation in result.operations}) == 50
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert len(_json_records(tmp_path, "conn.json")) == 1
    smb_rows = _json_records(tmp_path, "smb_files.json")
    assert len(smb_rows) == 100
    assert [row["action"] for row in smb_rows[::2]] == ["SMB::FILE_OPEN"] * 50
    assert [row["action"] for row in smb_rows[1::2]] == ["SMB::FILE_READ"] * 50


@pytest.mark.slow
def test_persistent_smb_denied_batch_is_short_framing_only_and_file_neutral(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    """A denied batch emits one failure member per file without payload or mutation."""

    scenario = _windows_read_scenario(scenarios_dir, file_count=2, outcome="access_denied")
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        state_before = engine.activity_generator.state_manager.get_state_summary()
        result = _invoke_windows_read(engine, scenario)
        assert len(result.operations) == 2
        assert {str(operation["outcome"]) for operation in result.operations} == {"access_denied"}
        assert all(operation["fuid"] is None for operation in result.operations)
        state_after = engine.activity_generator.state_manager.get_state_summary()
        assert state_after["smb_mutations"] == state_before["smb_mutations"]
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()

    connection = _json_records(tmp_path, "conn.json")
    assert len(connection) == 1
    assert connection[0]["duration"] < 5.0
    assert (connection[0]["orig_bytes"], connection[0]["resp_bytes"]) == (3_427, 4_412)
    assert _json_records(tmp_path, "files.json") == []
    assert _json_records(tmp_path, "smb_files.json") == []
    windows_xml = next(tmp_path.rglob("windows_event_security.xml")).read_text(encoding="utf-8")
    assert re.findall(r"<EventID[^>]*>(\d+)</EventID>", windows_xml) == [
        "4624",
        "5140",
        "5145",
        "5145",
        "4634",
    ]


@pytest.mark.slow
def test_persistent_smb_target_preflight_capacity_and_empty_cancel_are_neutral(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    """Unsupported, absent, over-capacity, and empty work cannot mutate owners."""

    scenario = _windows_read_scenario(scenarios_dir, output_formats=("windows",))
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        dispatcher = engine.activity_generator.dispatcher
        state_before = engine.activity_generator.state_manager.get_state_summary()
        group_before = dispatcher.persistent_smb_projection_group_census()
        for target_formats in (("syslog",), ("zeek_conn",)):
            with pytest.raises(EventContractError):
                dispatcher.reserve_persistent_smb_projection_group(
                    route_generation_digest="a" * 64,
                    member_budget=1,
                    byte_budget=1_024,
                    required_target_formats=target_formats,
                )
        with pytest.raises(EventContractError):
            dispatcher.reserve_persistent_smb_projection_group(
                route_generation_digest="b" * 64,
                member_budget=65_537,
                byte_budget=1_024,
                required_target_formats=("windows_event_security",),
            )
        group = dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest="c" * 64,
            member_budget=1,
            byte_budget=1_024,
            required_target_formats=("windows_event_security",),
        )
        dispatcher.cancel_empty_persistent_smb_projection_group(group)
        assert engine.activity_generator.state_manager.get_state_summary() == state_before
        group_after = dispatcher.persistent_smb_projection_group_census()
        assert (
            group_after.retained_groups,
            group_after.inactive_members,
            group_after.certified_members,
            group_after.committed_unacknowledged_members,
            group_after.retained_commit_receipts,
            group_after.retained_bytes,
            group_after.reserved_member_capacity,
            group_after.reserved_receipt_capacity,
            group_after.reserved_byte_capacity,
            group_after.retained_target_generations,
        ) == (
            group_before.retained_groups,
            group_before.inactive_members,
            group_before.certified_members,
            group_before.committed_unacknowledged_members,
            group_before.retained_commit_receipts,
            group_before.retained_bytes,
            group_before.reserved_member_capacity,
            group_before.reserved_receipt_capacity,
            group_before.reserved_byte_capacity,
            group_before.retained_target_generations,
        )
    finally:
        engine._close_emitters()


@pytest.mark.slow
def test_persistent_smb_fail_before_transport_cancels_empty_group_and_replays(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """A pre-transport failure leaves no group or owner mutation and can replay."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        generator = engine.activity_generator
        state_before = generator.state_manager.get_state_summary()
        original = generator.generate_connection
        fault = _OneShotPublicFault(original, "fail_before")
        monkeypatch.setattr(generator, "generate_connection", fault)
        with pytest.raises(_InjectedPublicError):
            _invoke_windows_read(engine, scenario)
        assert fault.calls == 1
        assert generator.state_manager.get_state_summary() == state_before
        _assert_transient_authorities_drained(engine)
        monkeypatch.setattr(generator, "generate_connection", original)
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control


@pytest.mark.soak
def test_persistent_smb_new_client_process_is_root_atomic_and_retry_neutral(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new direct client actor appears only with its successful physical root."""

    scenario = _windows_read_scenario(scenarios_dir)
    client = scenario.environment.systems[0]
    client.os = "Ubuntu 24.04"
    client.services = ["smbclient"]
    actor = scenario.environment.users[0]
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        generator = engine.activity_generator
        generator.generate_logon(
            actor,
            client,
            engine.start_time + timedelta(minutes=1),
            logon_type=2,
        )
        state = generator.state_manager
        before = tuple(
            (process.ecar_object_id, process.pid, process.image, process.command_line)
            for process in state.get_processes_on_system(client.hostname)
        )
        state_before = state.get_state_summary()

        original = generator.generate_connection
        fault = _OneShotPublicFault(original, "fail_before")
        monkeypatch.setattr(generator, "generate_connection", fault)
        with pytest.raises(_InjectedPublicError):
            _invoke_windows_read(engine, scenario)
        assert fault.calls == 1
        assert state.get_state_summary() == state_before
        assert (
            tuple(
                (process.ecar_object_id, process.pid, process.image, process.command_line)
                for process in state.get_processes_on_system(client.hostname)
            )
            == before
        )
        _assert_transient_authorities_drained(engine)

        monkeypatch.setattr(generator, "generate_connection", original)
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        before_ids = {identity[0] for identity in before}
        materialized = [
            process
            for process in state.get_processes_on_system(client.hostname)
            if process.ecar_object_id not in before_ids
        ]
        assert len(materialized) == 1
        assert materialized[0].image == "/usr/bin/smbclient"
        assert "smbclient" in materialized[0].command_line
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()


@pytest.mark.parametrize(
    "mode",
    (
        pytest.param("fail_before", marks=pytest.mark.soak),
        pytest.param("lost_return", marks=pytest.mark.slow),
    ),
)
def test_persistent_smb_application_terminal_faults_converge_exactly_once(
    mode: Literal["fail_before", "lost_return"],
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """The retained common application result converges across either fault mode."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        registry = engine.activity_generator._smb_channel_manager.application_registry
        fault = _OneShotPublicFault(
            registry.acknowledge_committed_admission,
            mode,
            observe=lambda: _retained_smb_terminal_state(engine),
        )
        monkeypatch.setattr(registry, "acknowledge_committed_admission", fault)
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        assert fault.calls == (2 if mode == "fail_before" else 1)
        assert len([value for value in fault.results if value]) == 1
        assert len(fault.observations) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control


@pytest.mark.parametrize("mode", ("fail_before", "lost_return"))
@pytest.mark.soak
def test_persistent_smb_state_terminal_faults_recover_without_second_commit(
    mode: Literal["fail_before", "lost_return"],
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """State file and connection terminal lost returns recover exact receipts."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        state = engine.activity_generator.state_manager
        file_fault = _OneShotPublicFault(
            state.acknowledge_smb_file_mutation_commit,
            mode,
            observe=lambda: _retained_smb_terminal_state(engine),
        )
        finalization_fault = _OneShotPublicFault(
            state.materialize_action_cohort,
            mode,
            observe=lambda: _retained_smb_terminal_state(engine),
        )
        monkeypatch.setattr(state, "acknowledge_smb_file_mutation_commit", file_fault)
        monkeypatch.setattr(state, "materialize_action_cohort", finalization_fault)
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        expected_calls = 2 if mode == "fail_before" else 1
        assert file_fault.calls == expected_calls
        assert finalization_fault.calls == expected_calls
        assert len(file_fault.results) == 1
        assert len(finalization_fault.results) == 1
        assert len(file_fault.observations) == 1
        assert len(finalization_fault.observations) == 1
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control


@pytest.mark.parametrize(
    "mode",
    (
        pytest.param("fail_before", marks=pytest.mark.soak),
        pytest.param("lost_return", marks=pytest.mark.slow),
    ),
)
def test_persistent_smb_projection_and_publication_faults_recover_exact_bytes(
    mode: Literal["fail_before", "lost_return"],
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """Member commit and exact source publication recover without duplicate bytes."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        dispatcher = engine.activity_generator.dispatcher
        timing_commit_calls = 0
        timing_fence_errors: list[BaseException] = []
        timing_receipts: list[object] = []
        original_timing_commit = SourceTimingPreparation.commit_no_fail

        def lose_timing_commit_return(
            preparation: SourceTimingPreparation,
        ) -> object:
            nonlocal timing_commit_calls
            if object.__getattribute__(preparation, "_action_capacity") is None:
                return original_timing_commit(preparation)
            timing_commit_calls += 1
            if timing_commit_calls == 1:
                planner = preparation.owner
                retained_bindings = tuple(planner._detached_bindings.values())
                assert retained_bindings
                binding = retained_bindings[0].binding_ref()
                assert binding is not None
                try:
                    planner.discard_detached_preparation_binding(binding)
                except BaseException as error:
                    timing_fence_errors.append(error)
                else:
                    raise AssertionError(
                        "Certified SMB timing allowed concurrent detached cancellation"
                    )
                receipt = original_timing_commit(preparation)
                timing_receipts.append(receipt)
                raise _InjectedPublicError("injected timing commit lost_return")
            return original_timing_commit(preparation)

        if mode == "lost_return":
            monkeypatch.setattr(
                SourceTimingPreparation,
                "commit_no_fail",
                lose_timing_commit_return,
            )
        member_fault = _OneShotPublicFault(
            dispatcher.commit_persistent_smb_projection_member,
            mode,
            observe=lambda: _retained_smb_terminal_state(engine),
        )
        publication_fault = _OneShotPublicFault(
            dispatcher.publish_persistent_smb_source_publication,
            mode,
            observe=lambda: _retained_smb_terminal_state(engine),
        )
        monkeypatch.setattr(
            dispatcher,
            "commit_persistent_smb_projection_member",
            member_fault,
        )
        monkeypatch.setattr(
            dispatcher,
            "publish_persistent_smb_source_publication",
            publication_fault,
        )
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        assert member_fault.calls == (9 if mode == "fail_before" else 8)
        assert len(member_fault.results) == 8
        assert publication_fault.calls == 2
        assert len(publication_fault.results) == (1 if mode == "fail_before" else 2)
        if mode == "lost_return":
            assert timing_commit_calls == 1
            assert len(timing_receipts) == 1
            assert len(timing_fence_errors) == 1
            assert isinstance(timing_fence_errors[0], StateError)
            assert "active action commit" in str(timing_fence_errors[0])
            assert publication_fault.results[0] is publication_fault.results[1]
            timing_receipts.clear()
            timing_fence_errors[0].__traceback__ = None
            timing_fence_errors.clear()
            gc.collect()
        assert member_fault.observations == [(1, 1, 0, 1)]
        assert publication_fault.observations == [(1, 1, 0, 1)]
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control


@pytest.mark.parametrize(
    ("owner_name", "method_name", "mode"),
    (
        pytest.param(
            "dispatcher",
            "acknowledge_persistent_smb_source_publication",
            "fail_before",
            marks=pytest.mark.slow,
            id="fail_before-dispatcher-acknowledge_persistent_smb_source_publication",
        ),
        pytest.param(
            "dispatcher",
            "acknowledge_persistent_smb_source_publication",
            "lost_return",
            marks=pytest.mark.soak,
            id="lost_return-dispatcher-acknowledge_persistent_smb_source_publication",
        ),
        pytest.param(
            "state",
            "acknowledge_smb_file_mutation_commit",
            "fail_before",
            marks=pytest.mark.soak,
            id="fail_before-state-acknowledge_smb_file_mutation_commit",
        ),
        pytest.param(
            "state",
            "acknowledge_smb_file_mutation_commit",
            "lost_return",
            marks=pytest.mark.soak,
            id="lost_return-state-acknowledge_smb_file_mutation_commit",
        ),
        pytest.param(
            "state",
            "acknowledge_smb_connection_finalization",
            "fail_before",
            marks=pytest.mark.soak,
            id="fail_before-state-acknowledge_smb_connection_finalization",
        ),
        pytest.param(
            "state",
            "acknowledge_smb_connection_finalization",
            "lost_return",
            marks=pytest.mark.soak,
            id="lost_return-state-acknowledge_smb_connection_finalization",
        ),
    ),
)
def test_persistent_smb_terminal_acknowledgements_resume_exactly_once(
    owner_name: Literal["dispatcher", "state"],
    method_name: str,
    mode: Literal["fail_before", "lost_return"],
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """Every post-publication acknowledgement resumes from its exact cursor."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    completed = False
    try:
        engine._initialize()
        generator = engine.activity_generator
        owner = generator.dispatcher if owner_name == "dispatcher" else generator.state_manager
        fault = _OneShotPublicFault(
            getattr(owner, method_name),
            mode,
            observe=lambda: _retained_smb_terminal_state(engine),
        )
        monkeypatch.setattr(owner, method_name, fault)
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        assert fault.calls == (2 if mode == "fail_before" else 1)
        assert len(fault.results) == 1
        assert generator.persistent_smb_terminal_continuation_census().retained_continuations == 0
        _assert_transient_authorities_drained(engine)
        completed = True
    finally:
        if completed:
            engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control


@pytest.mark.slow
def test_persistent_smb_ordinary_retry_resumes_terminal_cursor_without_new_root(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """An escaped terminal failure is recoverable by the ordinary public caller."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    completed = False
    try:
        engine._initialize()
        generator = engine.activity_generator
        dispatcher = generator.dispatcher
        original = dispatcher.acknowledge_persistent_smb_source_publication
        fault = _PersistentPublicFault()
        monkeypatch.setattr(
            dispatcher,
            "acknowledge_persistent_smb_source_publication",
            fault,
        )
        with pytest.raises(_InjectedPublicError):
            _invoke_windows_read(engine, scenario)
        assert fault.calls >= 2
        assert generator.persistent_smb_terminal_continuation_census().retained_continuations == 1
        monkeypatch.setattr(
            dispatcher,
            "acknowledge_persistent_smb_source_publication",
            original,
        )
        result = _invoke_windows_read(engine, scenario)
        assert len(result.transport_uids) == 1
        _assert_transient_authorities_drained(engine)
        completed = True
    finally:
        if completed:
            engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control


def _exercise_terminal_continuation_guards(
    engine: GenerationEngine,
    scenario: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise retained-owner guards in a disposable frame."""

    generator = engine.activity_generator
    authority = generator._persistent_smb_terminal_continuations
    capture = _ReservationCapture(authority.reserve_claimed)
    monkeypatch.setattr(authority, "reserve_claimed", capture)
    dispatcher = generator.dispatcher
    original_advance = authority.advance
    captured_source: list[tuple[object, object]] = []

    def observe_terminal_proof() -> bool:
        continuation = capture.continuation
        assert continuation is not None
        facts = authority.facts(continuation)
        assert facts.cursor == 1
        _assert_event_contract_error_without_traceback(lambda: authority.facts(copy(continuation)))
        _assert_event_contract_error_without_traceback(
            lambda: PersistentSmbTerminalContinuationAuthority().facts(continuation)
        )
        _assert_event_contract_error_without_traceback(
            lambda: original_advance(continuation, expected_cursor=0)
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(authority.facts, continuation)
            _assert_event_contract_error_without_traceback(
                lambda completed=future: completed.result(timeout=2)
            )
            del future
        source_carrier = facts.source_carrier
        source_result = facts.source_result
        captured_source.append((source_carrier, source_result))
        assert dispatcher.authenticates_published_persistent_smb_source_publication(
            source_carrier,
            source_result,
        )
        try:
            copied_source = copy(source_carrier)
        except TypeError:
            copied_source = object()
        assert not dispatcher.authenticates_published_persistent_smb_source_publication(
            copied_source,
            source_result,
        )
        return True

    advance_fault = _OneShotPublicFault(
        original_advance,
        "lost_return",
        observe=observe_terminal_proof,
    )
    monkeypatch.setattr(authority, "advance", advance_fault)
    with pytest.raises(_InjectedPublicError, match="lost_return"):
        _invoke_windows_read(engine, scenario)
    assert advance_fault.observations == [True]
    assert authority.census().retained_continuations == 1
    monkeypatch.setattr(authority, "advance", original_advance)
    result = _invoke_windows_read(engine, scenario)
    assert len(result.transport_uids) == 1
    continuation = capture.continuation
    assert continuation is not None
    _assert_event_contract_error_without_traceback(lambda: authority.facts(continuation))
    assert len(captured_source) == 1
    source_carrier, source_result = captured_source[0]
    assert not dispatcher.authenticates_published_persistent_smb_source_publication(
        source_carrier,
        source_result,
    )
    _assert_terminal_continuation_capacity_is_neutral(capture.arguments)
    capture.arguments.clear()
    monkeypatch.undo()


@pytest.mark.slow
def test_persistent_smb_terminal_continuation_guards_and_proof_release(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows_read_control: tuple[tuple[str, bytes], ...],
) -> None:
    """Continuation copies, foreign owners, threads, CAS drift, and stale use fail closed."""

    scenario = _windows_read_scenario(scenarios_dir)
    engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
    try:
        engine._initialize()
        _exercise_terminal_continuation_guards(engine, scenario, monkeypatch)
        gc.collect()
        _assert_transient_authorities_drained(engine)
    finally:
        engine._close_emitters()
    assert _source_bytes(tmp_path) == windows_read_control
