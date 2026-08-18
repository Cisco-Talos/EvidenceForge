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

"""Tests for system process stability — seeded PIDs must survive the full scenario."""

import copy
import gc
import threading
import weakref
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from unittest.mock import Mock, patch

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
    LifecycleMaterializationBatchPlanningAttempt,
    LifecycleMaterializationBatchPlanningCapability,
    LifecycleMaterializationBatchTerminalResult,
    LifecycleMaterializationBatchTransaction,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    PreparedLifecycleStartBatch,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import (
    MaterializationBatchBuilder,
    PreparedMaterializationBatch,
    StateManager,
)
from evidenceforge.models import System, User
from evidenceforge.models.exceptions import StateError


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 8, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")


class TestSystemProcessProtection:
    """Verify seeded system processes are never terminated."""

    def _seed_and_get_pids(self, state_manager, mock_emitters, system):
        """Helper: seed system process tree and return (engine, pids dict)."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        # Create a minimal engine-like object with the mixins we need
        engine = type(
            "FakeEngine",
            (EmitterSetupMixin, BaselineMixin),
            {},
        ).__new__(type("FakeEngine", (EmitterSetupMixin, BaselineMixin), {}))
        engine.state_manager = state_manager
        engine.activity_generator = ag
        engine.scenario = Mock()
        engine.scenario.environment.systems = [system]
        engine.scenario.environment.users = []
        engine._system_pids = {}
        engine._infra_ips = {"dns": ["10.0.0.1"]}
        engine._system_service_defaults = {}
        engine._find_actor = lambda username: User(
            username=username, full_name=username, email=f"{username}@test.com", enabled=True
        )
        ag._system_pids = {}

        from evidenceforge.generation.activity import _get_os_category

        os_cat = _get_os_category(system.os)
        pids = {}
        if os_cat == "windows":
            engine._seed_windows_process_tree(system, pids)
        else:
            engine._seed_linux_process_tree(system, pids)
        engine._system_pids[system.hostname] = pids
        ag._system_pids = engine._system_pids

        return engine, pids

    @staticmethod
    def _seed_with_lifecycle_authority(
        state_manager: StateManager,
        system: System,
    ) -> tuple[dict[str, int], GeneratorLifecycleAuthority, LifecycleRegistry]:
        """Seed one fixture boot tree through the direct strict wrapper."""

        registry = LifecycleRegistry(shard_count=8)
        shadow = LifecycleShadow(state_manager, registry)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            shadow,
            shard_count=8,
        )
        engine_type = type("StrictBootEngine", (EmitterSetupMixin,), {})
        engine = engine_type.__new__(engine_type)
        engine.state_manager = state_manager
        engine.lifecycle_authority = authority
        engine.scenario = Mock()
        engine.scenario.environment.service_accounts = []
        engine._system_service_defaults = {}
        pids: dict[str, int] = {}

        with patch.object(
            shadow,
            "ensure_process",
            side_effect=AssertionError("boot seeding must not use compatibility backfill"),
        ):
            if "windows" in system.os.casefold():
                engine._seed_windows_process_tree(system, pids)
            else:
                engine._seed_linux_process_tree(system, pids)
        return pids, authority, registry

    @staticmethod
    def _strict_fleet_engine(
        state_manager: StateManager,
    ) -> tuple[
        object,
        GeneratorLifecycleAuthority,
        LifecycleRegistry,
        LifecycleShadow,
        tuple[System, System],
    ]:
        """Build a production-shaped two-host boot fleet around exact owners."""

        systems = (
            System(
                hostname="FLEET-WIN-01",
                ip="10.0.10.51",
                os="Windows Server 2022",
                type="server",
            ),
            System(
                hostname="FLEET-LNX-01",
                ip="10.0.10.52",
                os="Linux Ubuntu 22.04",
                type="server",
            ),
        )
        registry = LifecycleRegistry(shard_count=8)
        shadow = LifecycleShadow(state_manager, registry)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            shadow,
            shard_count=8,
        )
        engine_type = type("StrictFleetBootEngine", (EmitterSetupMixin,), {})
        engine = engine_type.__new__(engine_type)
        engine.state_manager = state_manager
        engine.lifecycle_authority = authority
        engine.activity_generator = Mock()
        engine.scenario = Mock()
        engine.scenario.environment.systems = list(systems)
        engine.scenario.environment.service_accounts = []
        engine.start_time = state_manager.state.current_time
        engine._kernel_boot_uptimes = {
            systems[0].hostname: 300.0,
            systems[1].hostname: 900.0,
        }
        engine._system_pids = {"preexisting": {"sentinel": 999}}
        engine._machine_ids = {"preexisting": "sentinel-machine-id"}
        engine._system_service_defaults = {}
        engine._org_cidr_networks = []
        engine._infra_ips = {
            "db_servers": [],
            "dns": [],
            "exchange": None,
            "dc_hostnames": [],
            "dc": [],
        }
        return engine, authority, registry, shadow, systems

    @staticmethod
    def _assert_boot_identity_parity(
        state_manager: StateManager,
        registry: LifecycleRegistry,
        hostname: str,
        pids: dict[str, int],
    ) -> None:
        """Assert every unique State boot identity has one exact lifecycle row."""

        unique_pids = set(pids.values())
        assert len(
            [
                process
                for process in state_manager.list_running_processes()
                if process.system == hostname
            ]
        ) == len(unique_pids)
        for pid in unique_pids:
            process = state_manager.get_process(hostname, pid)
            assert process is not None
            snapshot = registry.get_process(process.ecar_object_id)
            assert snapshot is not None
            assert snapshot.identity.hostname == process.system
            assert snapshot.identity.object_id == process.ecar_object_id
            assert snapshot.identity.pid == process.pid
            assert snapshot.identity.started_at == process.start_time
            assert snapshot.identity.image == process.image
            assert snapshot.token.principal == process.username
            assert snapshot.token.logon_id == process.logon_id
            if process.parent_pid == 0:
                assert snapshot.identity.parent_object_id == ""
            else:
                parent = state_manager.get_process(hostname, process.parent_pid)
                assert parent is not None
                assert snapshot.identity.parent_object_id == parent.ecar_object_id

    @staticmethod
    def _authority_lifecycle_census(
        authority: GeneratorLifecycleAuthority,
    ) -> tuple[object, ...]:
        """Return canonical lifecycle queue truth, excluding retry bookkeeping."""

        census = authority.census()
        return (
            census.process_close_intents,
            census.deferred_session_closes,
            census.strict_markers,
            census.deadline_entries,
            census.deadline_backing_entries,
            census.allocated_shards,
            census.maximum_shard_entries,
            census.high_water_entries,
            census.bootstrapped_sessions,
            census.bootstrapped_processes,
            census.watermark,
        )

    @pytest.mark.parametrize(
        ("system", "root_name", "root_pid"),
        (
            (
                System(
                    hostname="BOOT-WIN-01",
                    ip="10.0.10.31",
                    os="Windows Server 2022",
                    type="server",
                ),
                "system",
                4,
            ),
            (
                System(
                    hostname="BOOT-LNX-01",
                    ip="10.0.10.32",
                    os="Linux Ubuntu 22.04",
                    type="server",
                ),
                "systemd",
                1,
            ),
        ),
    )
    def test_boot_tree_materializes_exact_lifecycle_identity_without_bootstrap(
        self,
        system: System,
        root_name: str,
        root_pid: int,
    ) -> None:
        """Strict boot seeding should publish State and lifecycle identity together."""

        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 3, 15, 8, 0, tzinfo=UTC))

        pids, authority, registry = self._seed_with_lifecycle_authority(
            state_manager,
            system,
        )

        assert pids[root_name] == root_pid
        assert authority._bootstrap_complete is False
        assert registry.stats().live_processes == len(set(pids.values()))
        self._assert_boot_identity_parity(state_manager, registry, system.hostname, pids)

    @pytest.mark.parametrize("failure_position", ("first", "middle", "last"))
    def test_fleet_boot_batch_failure_is_exactly_neutral_and_retryable(
        self,
        failure_position: str,
    ) -> None:
        """Any member-staging failure leaves the whole fleet exactly retryable."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        clean_state = StateManager()
        clean_state.set_current_time(start)
        clean_engine, clean_authority, clean_registry, clean_shadow, systems = (
            self._strict_fleet_engine(clean_state)
        )
        with (
            patch.object(
                clean_shadow,
                "ensure_process",
                side_effect=AssertionError("boot seeding must not use compatibility backfill"),
            ),
            patch.object(
                clean_authority,
                "materialize_batch",
                wraps=clean_authority.materialize_batch,
            ) as clean_materialize,
        ):
            clean_engine._seed_system_process_trees()
        clean_materialize.assert_called_once()
        total_processes = clean_registry.stats().live_processes
        failure_ordinal = {
            "first": 1,
            "middle": (total_processes + 1) // 2,
            "last": total_processes,
        }[failure_position]

        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, shadow, _systems = self._strict_fleet_engine(state_manager)
        before_state = state_manager.materialization_digest()
        before_pid = state_manager.pid_allocator_census()
        before_lifecycle = self._authority_lifecycle_census(authority)
        before_registry = registry.census()
        before_time = state_manager.state.current_time
        before_pids = {
            hostname: dict(host_pids) for hostname, host_pids in engine._system_pids.items()
        }
        before_machine_ids = dict(engine._machine_ids)
        project_calls = 0
        project_process_start = shadow.project_process_start

        def reject_member(identity, **kwargs):
            nonlocal project_calls
            project_calls += 1
            if project_calls == failure_ordinal:
                raise StateError(f"injected {failure_position} boot member failure")
            return project_process_start(identity, **kwargs)

        with (
            patch.object(shadow, "project_process_start", side_effect=reject_member),
            pytest.raises(
                StateError,
                match=rf"injected {failure_position} boot member failure",
            ),
        ):
            engine._seed_system_process_trees()

        assert project_calls == failure_ordinal
        assert state_manager.materialization_digest() == before_state
        assert state_manager.pid_allocator_census() == before_pid
        assert self._authority_lifecycle_census(authority) == before_lifecycle
        assert registry.census() == before_registry
        assert state_manager.state.current_time == before_time
        assert engine._system_pids == before_pids
        assert engine._machine_ids == before_machine_ids
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)

        with patch.object(
            shadow,
            "ensure_process",
            side_effect=AssertionError("boot retry must not use compatibility backfill"),
        ):
            engine._seed_system_process_trees()

        assert authority._bootstrap_complete is False
        assert engine._system_pids == clean_engine._system_pids
        assert engine._machine_ids == clean_engine._machine_ids
        assert engine._external_scanner_ips == clean_engine._external_scanner_ips
        assert engine._external_scanner_weights == clean_engine._external_scanner_weights
        assert state_manager.state.current_time == clean_state.state.current_time == start
        assert state_manager.pid_allocator_census() == clean_state.pid_allocator_census()
        assert state_manager.materialization_digest() == clean_state.materialization_digest()
        assert registry.census() == clean_registry.census()
        assert engine._system_pids[systems[0].hostname]["system"] == 4
        assert engine._system_pids[systems[1].hostname]["systemd"] == 1
        assert registry.stats().live_processes == sum(
            len(set(engine._system_pids[system.hostname].values())) for system in systems
        )
        for system in systems:
            assert state_manager.get_boot_time(system.hostname) == clean_state.get_boot_time(
                system.hostname
            )
            self._assert_boot_identity_parity(
                state_manager,
                registry,
                system.hostname,
                engine._system_pids[system.hostname],
            )

    @pytest.mark.parametrize("failure_ordinal", (1, 2))
    def test_fleet_boot_time_staging_failure_precedes_all_owner_publication(
        self,
        failure_ordinal: int,
    ) -> None:
        """First/middle host boot-time failure cannot expose a partial fleet."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, shadow, systems = self._strict_fleet_engine(state_manager)
        before_state = state_manager.materialization_digest()
        before_registry = registry.census()
        before_authority = self._authority_lifecycle_census(authority)
        before_pid = state_manager.pid_allocator_census()
        before_system_pids = {
            hostname: dict(host_pids) for hostname, host_pids in engine._system_pids.items()
        }
        before_machine_ids = dict(engine._machine_ids)
        original_plan_boot_time = MaterializationBatchBuilder.plan_boot_time
        boot_time_calls = 0

        def reject_boot_time(
            builder: MaterializationBatchBuilder,
            hostname: str,
            boot_time: datetime,
        ) -> datetime:
            nonlocal boot_time_calls
            boot_time_calls += 1
            if boot_time_calls == failure_ordinal:
                raise StateError(f"injected boot-time member {failure_ordinal} failure")
            return original_plan_boot_time(builder, hostname, boot_time)

        with (
            patch.object(
                MaterializationBatchBuilder,
                "plan_boot_time",
                new=reject_boot_time,
            ),
            pytest.raises(
                StateError,
                match=rf"injected boot-time member {failure_ordinal} failure",
            ),
        ):
            engine._seed_system_process_trees()

        assert boot_time_calls == failure_ordinal
        assert state_manager.materialization_digest() == before_state
        assert state_manager.pid_allocator_census() == before_pid
        assert registry.census() == before_registry
        assert self._authority_lifecycle_census(authority) == before_authority
        assert engine._system_pids == before_system_pids
        assert engine._machine_ids == before_machine_ids
        assert state_manager.state.current_time == start
        assert state_manager.list_running_processes() == []
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)

        with patch.object(
            shadow,
            "ensure_process",
            side_effect=AssertionError("boot-time retry must not use compatibility backfill"),
        ):
            engine._seed_system_process_trees()
        assert registry.stats().live_processes > 0
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)

    def test_boot_authority_rejects_malformed_or_foreign_owner_before_planning(self) -> None:
        """A non-owner or foreign-State authority cannot enter the batch planner."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        system = System(
            hostname="OWNER-WIN-01",
            ip="10.0.10.61",
            os="Windows Server 2022",
            type="server",
        )
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine_type = type("MalformedBootOwnerEngine", (EmitterSetupMixin,), {})
        engine = engine_type.__new__(engine_type)
        engine.state_manager = state_manager
        engine.scenario = Mock()
        engine.scenario.environment.service_accounts = []
        engine._system_service_defaults = {}
        pids: dict[str, int] = {}
        before_state = state_manager.materialization_digest()

        engine.lifecycle_authority = object()
        with (
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("malformed owner entered planning"),
            ),
            pytest.raises(TypeError, match="exact typed engine owner"),
        ):
            engine._seed_windows_process_tree(system, pids)

        foreign_state = StateManager()
        foreign_state.set_current_time(start)
        foreign_registry = LifecycleRegistry(shard_count=8)
        foreign_shadow = LifecycleShadow(foreign_state, foreign_registry)
        engine.lifecycle_authority = GeneratorLifecycleAuthority(
            foreign_state,
            foreign_shadow,
            shard_count=8,
        )
        with (
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("foreign owner entered planning"),
            ),
            pytest.raises(StateError, match="share the engine StateManager"),
        ):
            engine._seed_windows_process_tree(system, pids)

        assert pids == {}
        assert state_manager.materialization_digest() == before_state

    def test_mid_fleet_boot_time_overlap_fences_process_publication(self) -> None:
        """A concurrent State owner change stales the fleet before any process appears."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        original_plan_boot_time = MaterializationBatchBuilder.plan_boot_time
        boot_time_calls = 0
        external_hostname = "EXTERNAL-BOOT-OWNER"
        external_boot_time = start - timedelta(hours=1)

        def overlap_boot_time(
            builder: MaterializationBatchBuilder,
            hostname: str,
            boot_time: datetime,
        ) -> datetime:
            nonlocal boot_time_calls
            boot_time_calls += 1
            result = original_plan_boot_time(builder, hostname, boot_time)
            if boot_time_calls == 2:
                state_manager.register_boot_time(external_hostname, external_boot_time)
            return result

        with (
            patch.object(
                MaterializationBatchBuilder,
                "plan_boot_time",
                new=overlap_boot_time,
            ),
            pytest.raises(StateError, match="became stale during process planning"),
        ):
            engine._seed_system_process_trees()

        assert boot_time_calls == 2
        assert state_manager.get_boot_time(external_hostname) == external_boot_time
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)
        assert state_manager.list_running_processes() == []
        assert registry.stats().live_processes == 0
        assert authority._bootstrap_complete is False
        assert engine._system_pids == {"preexisting": {"sentinel": 999}}
        assert engine._machine_ids == {"preexisting": "sentinel-machine-id"}

    def test_precommit_reentrant_state_mutation_stales_before_fleet_publication(self) -> None:
        """A fallible precommit hook runs before the claim and forces full revalidation."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        external_host = "EXTERNAL-PRECOMMIT"
        authority._materialization_precommit_hook = lambda: state_manager.register_boot_time(
            external_host,
            start - timedelta(hours=1),
        )

        with pytest.raises(StateError, match="became stale before commit"):
            engine._seed_system_process_trees()

        assert state_manager.get_boot_time(external_host) == start - timedelta(hours=1)
        assert state_manager.list_running_processes() == []
        assert registry.stats().live_processes == 0
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)
        assert engine._system_pids == {"preexisting": {"sentinel": 999}}
        assert engine._machine_ids == {"preexisting": "sentinel-machine-id"}
        census = authority.census()
        assert census.materialization_batch_transactions_pending == 1
        assert census.materialization_batch_transactions_unacknowledged == 0

        authority._materialization_precommit_hook = None
        engine._seed_system_process_trees()

        assert state_manager.materialization_version == 2
        assert registry.stats().live_processes == len(state_manager.list_running_processes())
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)
        assert authority.census().materialization_batch_transactions_acknowledged == 1

    def test_transaction_external_callback_is_rejected_before_publication(self) -> None:
        """Retry-stable transactions reject arbitrary callbacks before canonical writes."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        original_materialize = authority.materialize_batch
        reentrant_host = "EXTERNAL-FINALIZER"

        def materialize_with_reentrant_finalizer(plan, **kwargs):
            def reentrant_finalizer() -> None:
                state_manager.register_boot_time(
                    reentrant_host,
                    start - timedelta(hours=1),
                )

            kwargs["finalize_external_no_fail"] = reentrant_finalizer
            return original_materialize(plan, **kwargs)

        with (
            patch.object(
                authority,
                "materialize_batch",
                side_effect=materialize_with_reentrant_finalizer,
            ),
            pytest.raises(StateError, match="cannot run external callbacks"),
        ):
            engine._seed_system_process_trees()

        assert state_manager.materialization_version == 0
        assert state_manager.get_boot_time(reentrant_host) is None
        assert registry.stats().live_processes == 0
        assert state_manager.list_running_processes() == []
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)
        assert authority.census().materialization_batch_transactions_pending == 1

        engine._seed_system_process_trees()

        assert state_manager.materialization_version == 1
        assert registry.stats().live_processes == len(state_manager.list_running_processes())
        assert authority.census().materialization_batch_transactions_acknowledged == 1

    def test_public_commit_then_raise_retry_restores_maps_without_replanning(self) -> None:
        """A lost public return reconciles the exact terminal before fixed-PID planning."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        original_materialize = authority.materialize_batch

        def commit_then_raise(plan, **kwargs):
            original_materialize(plan, **kwargs)
            raise StateError("injected public return-path failure")

        with (
            patch.object(authority, "materialize_batch", side_effect=commit_then_raise),
            pytest.raises(StateError, match="public return-path failure"),
        ):
            engine._seed_system_process_trees()

        assert engine._system_pids == {"preexisting": {"sentinel": 999}}
        assert engine._machine_ids == {"preexisting": "sentinel-machine-id"}
        retained = authority.reconcile_materialization_batch_transaction(
            engine._boot_materialization_transaction
        )
        assert retained is not None
        expected_machine_ids, expected_pids = engine._decode_boot_materialization_external_result(
            retained.external_result
        )
        committed_registry = registry.census()
        assert state_manager.materialization_version == 1
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)
        assert authority.census().materialization_batch_transactions_unacknowledged == 1

        state_manager.set_current_time(start + timedelta(hours=1))
        committed_state = state_manager.materialization_digest()

        engine._system_pids = {"corrupt": {"pid": 999}}
        engine._machine_ids = {"corrupt": "machine-id"}
        with patch.object(
            state_manager,
            "begin_materialization_batch",
            side_effect=AssertionError("lost-return retry entered fixed-PID planning"),
        ):
            engine._seed_system_process_trees()

        assert engine._system_pids == expected_pids
        assert engine._machine_ids == expected_machine_ids
        assert state_manager.materialization_digest() == committed_state
        assert registry.census() == committed_registry
        assert state_manager.materialization_version == 1
        census = authority.census()
        assert census.materialization_batch_transactions_unacknowledged == 0
        assert census.materialization_batch_transactions_acknowledged == 1

    def test_planning_claim_then_raise_reconciles_before_fixed_pid_planning(self) -> None:
        """A lost planning-capability return completes once and retries from its terminal."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        original_claim = authority.claim_materialization_batch_transaction_for_planning

        def claim_then_raise(transaction, **kwargs):
            original_claim(transaction, **kwargs)
            raise StateError("injected planning capability return loss")

        with (
            patch.object(
                authority,
                "claim_materialization_batch_transaction_for_planning",
                side_effect=claim_then_raise,
            ),
            pytest.raises(StateError, match="planning capability return loss"),
        ):
            engine._seed_system_process_trees()

        assert engine._system_pids == {"preexisting": {"sentinel": 999}}
        assert engine._machine_ids == {"preexisting": "sentinel-machine-id"}
        assert state_manager.materialization_version == 1
        assert registry.stats().live_processes == len(state_manager.list_running_processes())
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)
        retained = authority.reconcile_materialization_batch_transaction(
            engine._boot_materialization_transaction
        )
        assert retained is not None

        with patch.object(
            state_manager,
            "begin_materialization_batch",
            side_effect=AssertionError("planning lost-return retry entered fixed-PID planning"),
        ):
            engine._seed_system_process_trees()

        expected_machine_ids, expected_pids = engine._decode_boot_materialization_external_result(
            retained.external_result
        )
        assert engine._machine_ids == expected_machine_ids
        assert engine._system_pids == expected_pids
        assert authority.census().materialization_batch_transactions_acknowledged == 1

    def test_pending_state_time_rejection_releases_exact_planning_claim(self) -> None:
        """A pending fleet cannot cross State time or leave its planning claim pinned."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        fleet_spec = engine._build_boot_fleet_spec(start)
        transaction_id, request_digest, request_payload = engine._boot_materialization_request(
            fleet_spec
        )
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id=transaction_id,
            request_digest=request_digest,
            request_payload=request_payload,
        )
        engine._boot_materialization_transaction = transaction
        engine._boot_materialization_transaction_identity = transaction
        engine._boot_materialization_state_time = start
        engine._boot_materialization_existing_system_pids = (("preexisting", (("sentinel", 999),)),)
        state_manager.set_current_time(start + timedelta(hours=1))

        with pytest.raises(
            StateError,
            match="Pending boot materialization cannot cross a State-time change",
        ):
            engine._seed_system_process_trees()

        assert state_manager.materialization_version == 0
        assert state_manager.list_running_processes() == []
        assert registry.stats().live_processes == 0
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)
        authority.cancel_materialization_batch_transaction(transaction)
        assert authority.census().materialization_batch_transactions == 0

    def test_planning_capability_is_exact_thread_owned_and_copy_safe(self) -> None:
        """Nested, copied, and wrong-Thread planning capabilities cannot consume the claim."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        registry = LifecycleRegistry(shard_count=8)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            LifecycleShadow(state_manager, registry),
            shard_count=8,
        )
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id="planning-capability",
            request_digest="planning-request",
        )
        attempt = authority.prepare_materialization_batch_transaction_planning_attempt(transaction)
        assert type(attempt) is LifecycleMaterializationBatchPlanningAttempt
        capability = authority.claim_materialization_batch_transaction_for_planning(
            transaction,
            attempt=attempt,
        )
        assert type(capability) is LifecycleMaterializationBatchPlanningCapability
        assert (
            authority.reconcile_materialization_batch_transaction_planning_claim(
                transaction,
                attempt=attempt,
            )
            is capability
        )
        copied_attempt = copy.copy(attempt)
        assert (
            authority.reconcile_materialization_batch_transaction_planning_claim(
                transaction,
                attempt=copied_attempt,
            )
            is None
        )
        with pytest.raises(StateError, match="reentrantly claimed"):
            nested_attempt = authority.prepare_materialization_batch_transaction_planning_attempt(
                transaction
            )
            authority.claim_materialization_batch_transaction_for_planning(
                transaction,
                attempt=nested_attempt,
            )

        copied_capability = copy.copy(capability)
        with pytest.raises(StateError, match="not owned here"):
            authority.release_materialization_batch_transaction_planning_claim(
                transaction,
                copied_capability,
            )

        wrong_thread_errors: list[str] = []

        def wrong_thread_release() -> None:
            try:
                authority.reconcile_materialization_batch_transaction_planning_claim(
                    transaction,
                    attempt=attempt,
                )
            except StateError as error:
                wrong_thread_errors.append(str(error))
            try:
                authority.release_materialization_batch_transaction_planning_claim(
                    transaction,
                    capability,
                )
            except StateError as error:
                wrong_thread_errors.append(str(error))

        thread = threading.Thread(target=wrong_thread_release)
        thread.start()
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert wrong_thread_errors == [
            "Materialization-batch planning claim is owned by another Thread",
            "Materialization-batch planning claim is not owned here",
        ]

        builder = state_manager.begin_materialization_batch()
        builder.plan_boot_time("HOST-A", start - timedelta(hours=1))
        plan = builder.seal()
        with pytest.raises(StateError, match="not owned here"):
            authority.materialize_batch(
                plan,
                transaction=transaction,
                planning_capability=copied_capability,
            )
        authority.materialize_batch(
            plan,
            transaction=transaction,
            planning_capability=capability,
        )
        assert authority.reconcile_materialization_batch_transaction(transaction) is not None

    def test_nested_engine_planning_claim_is_neutral_and_cannot_reconcile_outer_claim(
        self,
    ) -> None:
        """A nested engine invocation cannot mistake an outer claim for its lost return."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        fleet_spec = engine._build_boot_fleet_spec(start)
        transaction_id, request_digest, request_payload = engine._boot_materialization_request(
            fleet_spec
        )
        existing_system_pids = (("preexisting", (("sentinel", 999),)),)
        anticipated_terminal_payload, _anticipated_terminal_bytes = (
            engine._boot_materialization_terminal_reservation(
                fleet_spec,
                transaction_id,
                request_digest,
                existing_system_pids,
            )
        )
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id=transaction_id,
            request_digest=request_digest,
            request_payload=request_payload,
            anticipated_terminal_payload=anticipated_terminal_payload,
        )
        engine._boot_materialization_transaction = transaction
        engine._boot_materialization_transaction_identity = transaction
        engine._boot_materialization_state_time = start
        engine._boot_materialization_existing_system_pids = existing_system_pids
        outer_attempt = authority.prepare_materialization_batch_transaction_planning_attempt(
            transaction
        )
        outer_capability = authority.claim_materialization_batch_transaction_for_planning(
            transaction,
            attempt=outer_attempt,
        )

        with pytest.raises(StateError, match="planning is reentrantly claimed"):
            engine._seed_system_process_trees()

        assert state_manager.materialization_version == 0
        assert state_manager.list_running_processes() == []
        assert registry.stats().live_processes == 0
        assert all(state_manager.get_boot_time(system.hostname) is None for system in systems)
        assert (
            authority.reconcile_materialization_batch_transaction_planning_claim(
                transaction,
                attempt=outer_attempt,
            )
            is outer_capability
        )
        authority.release_materialization_batch_transaction_planning_claim(
            transaction,
            outer_capability,
        )
        authority.cancel_materialization_batch_transaction(transaction)

    def test_materialization_batch_transaction_copy_foreign_aba_and_retention(self) -> None:
        """Terminal records are bounded, pinned, exact-identity, and generation safe."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        registry = LifecycleRegistry(shard_count=8)
        shadow = LifecycleShadow(state_manager, registry)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            shadow,
            shard_count=8,
            materialization_batch_transaction_capacity=1,
        )
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id="boot-transaction",
            request_digest="request-a",
        )
        copied_transaction = copy.copy(transaction)
        with pytest.raises(StateError, match="not retained"):
            authority.reconcile_materialization_batch_transaction(copied_transaction)

        builder = state_manager.begin_materialization_batch()
        builder.plan_boot_time("HOST-A", start - timedelta(hours=1))
        plan = builder.seal()
        authority.materialize_batch(
            plan,
            transaction=transaction,
            external_result=("external", 1),
        )
        result = authority.reconcile_materialization_batch_transaction(transaction)
        assert type(result) is LifecycleMaterializationBatchTerminalResult
        copied_result = copy.copy(result)
        assert not authority.authenticates_materialization_batch_terminal_result(
            transaction,
            copied_result,
        )
        with pytest.raises(StateError, match="not canonical"):
            authority.acknowledge_materialization_batch_transaction(
                transaction,
                copied_result,
            )

        foreign_state = StateManager()
        foreign_state.set_current_time(start)
        foreign_registry = LifecycleRegistry(shard_count=8)
        foreign_authority = GeneratorLifecycleAuthority(
            foreign_state,
            LifecycleShadow(foreign_state, foreign_registry),
            shard_count=8,
        )
        with pytest.raises(StateError, match="authentication"):
            foreign_authority.reconcile_materialization_batch_transaction(transaction)
        with pytest.raises(StateError, match="another request"):
            authority.reserve_materialization_batch_transaction(
                transaction_id="boot-transaction",
                request_digest="request-b",
            )
        with pytest.raises(StateError, match="capacity is exhausted"):
            authority.reserve_materialization_batch_transaction(
                transaction_id="other-transaction",
                request_digest="request-b",
            )

        authority.advance_watermark(start)
        assert authority.census().materialization_batch_transactions_unacknowledged == 1
        authority.acknowledge_materialization_batch_transaction(transaction, result)
        authority.advance_watermark(start + timedelta(seconds=1))
        assert authority.census().materialization_batch_transactions == 0

        replacement = authority.reserve_materialization_batch_transaction(
            transaction_id="boot-transaction",
            request_digest="request-a",
        )
        assert replacement is not transaction
        with pytest.raises(StateError, match="not retained"):
            authority.reconcile_materialization_batch_transaction(transaction)
        assert not authority.validates_archived_materialization_batch_terminal_result(
            replacement,
            result,
        )

    def test_terminal_reconciliation_rejects_partial_state_lifecycle_presence(self) -> None:
        """A terminal cannot mask one-sided canonical process disappearance."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        boot_time = start - timedelta(hours=1)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        registry = LifecycleRegistry(shard_count=8)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            LifecycleShadow(state_manager, registry),
            shard_count=8,
        )
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id="partial-terminal",
            request_digest="partial-request",
        )
        builder = state_manager.begin_materialization_batch()
        builder.plan_boot_time("HOST-A", boot_time)
        builder.plan_process(
            system="HOST-A",
            fixed_pid=1,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --system",
            username="root",
            integrity_level="System",
            os_category="linux",
            start_time=boot_time,
        )
        authority.materialize_batch(
            builder.seal(),
            transaction=transaction,
            external_result=("partial",),
        )
        assert authority.reconcile_materialization_batch_transaction(transaction) is not None

        assert state_manager.end_process("HOST-A", 1)
        assert registry.stats().live_processes == 1
        with pytest.raises(StateError, match="absent from State"):
            authority.reconcile_materialization_batch_transaction(transaction)

    def test_pinned_boot_terminal_rejects_request_aba_before_planning(self) -> None:
        """A changed fleet request cannot reuse an earlier stable transaction result."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, _authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        engine._seed_system_process_trees()
        committed_state = state_manager.materialization_digest()
        committed_registry = registry.census()
        systems[0].roles.append("database")

        with (
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("request ABA entered fixed-PID planning"),
            ),
            pytest.raises(StateError, match="Pinned boot materialization (transaction|terminal)"),
        ):
            engine._seed_system_process_trees()

        assert state_manager.materialization_digest() == committed_state
        assert registry.census() == committed_registry

    def test_boot_fleet_spec_absorbs_service_account_taskeng_membership(self) -> None:
        """Service-account-driven taskeng membership is part of the planned request itself."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, _registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        before_state = state_manager.materialization_digest()
        before_pid = state_manager.pid_allocator_census()

        with patch(
            "evidenceforge.generation.activity.system_processes.get_scheduled_task_entries",
            return_value=[],
        ):
            without_accounts = engine._build_boot_fleet_spec(start)
            engine.scenario.environment.service_accounts = [object()]
            with_accounts = engine._build_boot_fleet_spec(start)

        without_windows = next(
            host for host in without_accounts.hosts if host.hostname == systems[0].hostname
        )
        with_windows = next(
            host for host in with_accounts.hosts if host.hostname == systems[0].hostname
        )
        assert "taskeng" not in {member.alias for member in without_windows.processes}
        assert "taskeng" in {member.alias for member in with_windows.processes}
        without_request = engine._boot_materialization_request(without_accounts)
        with_request = engine._boot_materialization_request(with_accounts)
        assert without_request[0] == with_request[0]
        assert without_request[1] != with_request[1]
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id=without_request[0],
            request_digest=without_request[1],
            request_payload=without_request[2],
        )
        with pytest.raises(StateError, match="already bound to another request"):
            authority.reserve_materialization_batch_transaction(
                transaction_id=with_request[0],
                request_digest=with_request[1],
                request_payload=with_request[2],
            )
        authority.cancel_materialization_batch_transaction(transaction)
        assert state_manager.materialization_digest() == before_state
        assert state_manager.pid_allocator_census() == before_pid

    def test_every_symbolic_boot_forest_field_is_request_authenticated(self) -> None:
        """Every field consumed by planning changes the exact stable request digest."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, _authority, _registry, _shadow, _systems = self._strict_fleet_engine(state_manager)
        fleet = engine._build_boot_fleet_spec(start)
        base_digest = engine._boot_materialization_request(fleet)[1]
        host = fleet.hosts[0]
        member = host.processes[0]

        member_variants = (
            replace(member, alias=f"{member.alias}-changed"),
            replace(member, parent_alias="changed-parent"),
            replace(member, fixed_pid=(member.fixed_pid or 0) + 4),
            replace(member, image=f"{member.image}-changed"),
            replace(member, command_line=f"{member.command_line}-changed"),
            replace(member, username=f"{member.username}-changed"),
            replace(member, integrity_level=f"{member.integrity_level}-changed"),
            replace(member, os_category=f"{member.os_category}-changed"),
            replace(member, logon_id="0xfeed"),
            replace(member, start_time=member.start_time + timedelta(microseconds=1)),
        )
        fleet_variants = [
            replace(fleet, state_time=fleet.state_time + timedelta(microseconds=1)),
            replace(
                fleet,
                hosts=(
                    replace(host, hostname=f"{host.hostname}-changed"),
                    *fleet.hosts[1:],
                ),
            ),
            replace(
                fleet,
                hosts=(
                    replace(host, os_category=f"{host.os_category}-changed"),
                    *fleet.hosts[1:],
                ),
            ),
            replace(
                fleet,
                hosts=(
                    replace(host, boot_time=host.boot_time + timedelta(microseconds=1)),
                    *fleet.hosts[1:],
                ),
            ),
            replace(
                fleet,
                hosts=(
                    replace(host, machine_id="changed-machine-id"),
                    *fleet.hosts[1:],
                ),
            ),
            replace(
                fleet,
                hosts=(
                    replace(host, aliases=(*host.aliases, ("changed", member.alias))),
                    *fleet.hosts[1:],
                ),
            ),
        ]
        fleet_variants.extend(
            replace(
                fleet,
                hosts=(
                    replace(host, processes=(variant, *host.processes[1:])),
                    *fleet.hosts[1:],
                ),
            )
            for variant in member_variants
        )

        assert all(
            engine._boot_materialization_request(variant)[1] != base_digest
            for variant in fleet_variants
        )

    def test_boot_planning_consumes_only_the_prebuilt_symbolic_forest(self) -> None:
        """No scenario/config helper is consulted after the immutable forest is resolved."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, _authority, _registry, _shadow, _systems = self._strict_fleet_engine(state_manager)
        fleet = engine._build_boot_fleet_spec(start)
        builder = state_manager.begin_materialization_batch()

        with (
            patch(
                "evidenceforge.generation.engine.emitter_setup.normalize_defender_platform_path",
                side_effect=AssertionError("planning reread Defender configuration"),
            ),
            patch(
                "evidenceforge.generation.engine.emitter_setup.database_services_for_host",
                side_effect=AssertionError("planning reread database configuration"),
            ),
            patch(
                "evidenceforge.generation.activity.system_processes.get_scheduled_task_entries",
                side_effect=AssertionError("planning reread scheduled tasks"),
            ),
        ):
            planned = {
                host.hostname: engine._plan_boot_host_spec(builder, host) for host in fleet.hosts
            }

        plan = builder.seal()
        assert len(plan.processes) == sum(len(host.processes) for host in fleet.hosts)
        assert set(planned) == {host.hostname for host in fleet.hosts}
        assert planned[fleet.hosts[0].hostname]["system"] == 4
        assert planned[fleet.hosts[1].hostname]["systemd"] == 1

    @pytest.mark.parametrize(
        "system",
        (
            System(
                hostname="PARITY-WIN-DC",
                ip="10.0.20.10",
                os="Windows Server 2022",
                type="domain_controller",
                assigned_user="alice",
                roles=["database"],
                services=["mssql"],
            ),
            System(
                hostname="PARITY-RHEL-WEB",
                ip="10.0.20.11",
                os="Red Hat Enterprise Linux 9",
                type="server",
                roles=["database", "forward_proxy", "web_server"],
                services=["mysql", "postgresql", "squid", "httpd"],
            ),
        ),
    )
    def test_symbolic_boot_forest_matches_legacy_recipe_planning_exactly(
        self,
        system: System,
    ) -> None:
        """The strict fleet spec preserves every legacy member, timing, and PID decision."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        boot_time = start - timedelta(minutes=15)

        def build_engine(state_manager: StateManager):
            registry = LifecycleRegistry(shard_count=8)
            authority = GeneratorLifecycleAuthority(
                state_manager,
                LifecycleShadow(state_manager, registry),
                shard_count=8,
            )
            engine_type = type("BootRecipeParityEngine", (EmitterSetupMixin,), {})
            engine = engine_type.__new__(engine_type)
            engine.state_manager = state_manager
            engine.lifecycle_authority = authority
            engine.scenario = Mock()
            engine.scenario.environment.systems = [system]
            engine.scenario.environment.service_accounts = [object()]
            engine._system_service_defaults = {system.hostname: tuple(system.services)}
            return engine

        legacy_state = StateManager()
        legacy_state.set_current_time(start)
        legacy_engine = build_engine(legacy_state)
        legacy_builder = legacy_state.begin_materialization_batch()
        legacy_pids: dict[str, int] = {}
        if "windows" in system.os.casefold():
            legacy_engine._seed_windows_process_tree(
                system,
                legacy_pids,
                _batch_builder=legacy_builder,
                _boot_base=boot_time,
            )
            host_spec = legacy_engine._build_windows_boot_host_spec(system, boot_time)
        else:
            legacy_engine._seed_linux_process_tree(
                system,
                legacy_pids,
                _batch_builder=legacy_builder,
                _boot_base=boot_time,
            )
            host_spec = legacy_engine._build_linux_boot_host_spec(system, boot_time)
        legacy_plan = legacy_builder.seal()

        symbolic_state = StateManager()
        symbolic_state.set_current_time(start)
        symbolic_engine = build_engine(symbolic_state)
        symbolic_builder = symbolic_state.begin_materialization_batch()
        symbolic_pids = symbolic_engine._plan_boot_host_spec(symbolic_builder, host_spec)
        symbolic_plan = symbolic_builder.seal()

        assert symbolic_pids == legacy_pids
        assert symbolic_plan.boot_times == legacy_plan.boot_times
        assert symbolic_plan.final_state_time == legacy_plan.final_state_time
        assert tuple(member.identity for member in symbolic_plan.processes) == tuple(
            member.identity for member in legacy_plan.processes
        )

    def test_prepared_batch_claim_blocks_public_state_lanes_and_copy_replay(self) -> None:
        """The exact Thread-owned claim fences public mutation and capability minting."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        stale_builder = state_manager.begin_materialization_batch()
        builder = state_manager.begin_materialization_batch()
        builder.plan_boot_time("HOST-A", start - timedelta(hours=1))
        plan = builder.seal()

        with state_manager.prepared_materialization_batch(plan) as prepared:
            with pytest.raises(StateError, match="active .*prepared-State claim"):
                state_manager.register_boot_time("HOST-B", start)
            with pytest.raises(StateError, match="active .*prepared-State claim"):
                state_manager.set_current_time(start + timedelta(seconds=1))
            with pytest.raises(StateError, match="active .*prepared-State claim"):
                state_manager.begin_materialization_batch()
            with pytest.raises(StateError, match="no longer active"):
                copy.copy(prepared).commit_no_fail()
            prepared.commit_no_fail()

        assert state_manager.get_boot_time("HOST-A") == start - timedelta(hours=1)
        with pytest.raises(StateError, match="no longer active"):
            prepared.commit_no_fail()
        with pytest.raises(StateError, match="crossed an active prepared-State claim"):
            stale_builder.plan_boot_time("HOST-C", start)

    @pytest.mark.parametrize(
        ("seam", "failure_mode"),
        (
            ("state", "before"),
            ("state", "after"),
            ("lifecycle", "before"),
            ("lifecycle", "after"),
            ("terminal", "before"),
            ("terminal", "after"),
        ),
    )
    def test_two_owner_commit_faults_are_neutral_or_exactly_reconciled(
        self,
        seam: str,
        failure_mode: str,
    ) -> None:
        """Every public commit boundary converges without partial visible owners."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        before_state = state_manager.materialization_digest()
        before_registry = registry.census()

        if seam == "state":
            original = PreparedMaterializationBatch.apply_provisional

            def fail_state(prepared):
                if failure_mode == "after":
                    original(prepared)
                raise StateError(f"injected {failure_mode} State provisional failure")

            fault = patch.object(
                PreparedMaterializationBatch,
                "apply_provisional",
                new=fail_state,
            )
        elif seam == "lifecycle":
            original = PreparedLifecycleStartBatch.commit

            def fail_lifecycle(ticket):
                if failure_mode == "after":
                    original(ticket)
                raise StateError(f"injected {failure_mode} lifecycle commit failure")

            fault = patch.object(
                PreparedLifecycleStartBatch,
                "commit",
                new=fail_lifecycle,
            )
        else:
            original_terminalize = authority._terminalize_materialization_batch_transaction_no_fail

            def fail_terminal(record, result):
                if failure_mode == "after":
                    original_terminalize(record, result)
                raise StateError(f"injected {failure_mode} terminal install failure")

            fault = patch.object(
                authority,
                "_terminalize_materialization_batch_transaction_no_fail",
                side_effect=fail_terminal,
            )

        with fault, pytest.raises(StateError, match=rf"injected {failure_mode}"):
            engine._seed_system_process_trees()

        assert engine._system_pids == {"preexisting": {"sentinel": 999}}
        assert engine._machine_ids == {"preexisting": "sentinel-machine-id"}
        committed_lost_return = failure_mode == "after" or seam == "terminal"
        if committed_lost_return:
            assert state_manager.materialization_version == 1
            assert registry.stats().live_processes == len(state_manager.list_running_processes())
            assert authority.census().materialization_batch_transactions_unacknowledged == 1
        else:
            assert state_manager.materialization_digest() == before_state
            assert registry.census() == before_registry
            assert authority.census().materialization_batch_transactions_pending == 1

        retry_context = (
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("committed retry entered fixed-PID planning"),
            )
            if committed_lost_return
            else patch.object(
                state_manager,
                "begin_materialization_batch",
                wraps=state_manager.begin_materialization_batch,
            )
        )
        with retry_context:
            engine._seed_system_process_trees()

        assert state_manager.materialization_version == 1
        assert registry.stats().live_processes == len(state_manager.list_running_processes())
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)
        assert set(engine._system_pids) == {"preexisting", *[item.hostname for item in systems]}
        assert authority.census().materialization_batch_transactions_acknowledged == 1

    def test_legacy_batch_callback_cannot_reenter_public_state(self) -> None:
        """The nontransaction compatibility callback remains fenced by the State claim."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        registry = LifecycleRegistry(shard_count=8)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            LifecycleShadow(state_manager, registry),
            shard_count=8,
        )
        builder = state_manager.begin_materialization_batch()
        builder.plan_boot_time("HOST-A", start - timedelta(hours=1))

        with pytest.raises(StateError, match="active .*prepared-State claim"):
            authority.materialize_batch(
                builder.seal(),
                finalize_external_no_fail=lambda: state_manager.register_boot_time(
                    "REENTRANT",
                    start,
                ),
            )

        assert state_manager.materialization_version == 1
        assert state_manager.get_boot_time("HOST-A") == start - timedelta(hours=1)
        assert state_manager.get_boot_time("REENTRANT") is None

    def test_acknowledgement_lost_return_is_idempotent(self) -> None:
        """Call-original-then-raise acknowledgement remains exact on engine retry."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, _systems = self._strict_fleet_engine(state_manager)
        original_ack = authority.acknowledge_materialization_batch_transaction_if_retained

        def ack_then_raise(transaction, result):
            original_ack(transaction, result)
            raise StateError("injected acknowledgement return loss")

        with (
            patch.object(
                authority,
                "acknowledge_materialization_batch_transaction_if_retained",
                side_effect=ack_then_raise,
            ),
            pytest.raises(StateError, match="acknowledgement return loss"),
        ):
            engine._seed_system_process_trees()

        committed_state = state_manager.materialization_digest()
        committed_registry = registry.census()
        assert authority.census().materialization_batch_transactions_acknowledged == 1
        with patch.object(
            state_manager,
            "begin_materialization_batch",
            side_effect=AssertionError("ack retry entered fixed-PID planning"),
        ):
            engine._seed_system_process_trees()
        assert state_manager.materialization_digest() == committed_state
        assert registry.census() == committed_registry
        assert authority.census().materialization_batch_transactions_acknowledged == 1

    def test_pruned_acknowledged_terminal_retries_from_engine_archive_without_planning(
        self,
    ) -> None:
        """A pruned retained record leaves an authentic engine archive for exact retry."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        original_ack = authority.acknowledge_materialization_batch_transaction_if_retained

        def acknowledge_then_raise(transaction, result):
            original_ack(transaction, result)
            raise StateError("injected archived acknowledgement return loss")

        with (
            patch.object(
                authority,
                "acknowledge_materialization_batch_transaction_if_retained",
                side_effect=acknowledge_then_raise,
            ),
            pytest.raises(StateError, match="archived acknowledgement return loss"),
        ):
            engine._seed_system_process_trees()
        expected_system_pids = {host: dict(pids) for host, pids in engine._system_pids.items()}
        expected_machine_ids = dict(engine._machine_ids)
        committed_state = state_manager.materialization_digest()
        committed_registry = registry.census()
        archived_transaction = engine._boot_materialization_transaction
        archived_terminal = engine._boot_materialization_terminal_result
        record_ref = weakref.ref(
            authority._materialization_batch_transactions[archived_transaction.transaction_id]
        )

        authority.advance_watermark(start)
        authority.advance_watermark(start + timedelta(seconds=1))
        gc.collect()
        pruned_census = authority.census()
        assert pruned_census.materialization_batch_transactions == 0
        assert pruned_census.materialization_batch_transaction_retained_bytes == 0
        assert record_ref() is None
        assert engine._boot_materialization_transaction_identity is archived_transaction
        assert engine._boot_materialization_terminal_identity is archived_terminal
        assert not authority.authenticates_materialization_batch_terminal_result(
            archived_transaction,
            archived_terminal,
        )

        engine._boot_materialization_transaction = copy.copy(archived_transaction)
        with pytest.raises(StateError, match="Pinned boot materialization transaction"):
            engine._seed_system_process_trees()
        engine._boot_materialization_transaction = archived_transaction
        engine._boot_materialization_terminal_result = copy.copy(archived_terminal)
        with pytest.raises(StateError, match="Pinned boot materialization terminal"):
            engine._seed_system_process_trees()
        engine._boot_materialization_terminal_result = archived_terminal
        systems[0].roles.append("database")
        with pytest.raises(StateError, match="Pinned boot materialization transaction"):
            engine._seed_system_process_trees()
        systems[0].roles.pop()

        engine._system_pids = {"corrupt": {"pid": 999}}
        engine._machine_ids = {"corrupt": "machine-id"}
        barrier = threading.Barrier(3)
        outcomes: list[str] = []

        def retry_archive() -> None:
            barrier.wait()
            try:
                engine._seed_system_process_trees()
            except StateError as error:
                outcomes.append(f"error:{error}")
            else:
                outcomes.append("success")

        with patch.object(
            state_manager,
            "begin_materialization_batch",
            side_effect=AssertionError("archived retry entered fixed-PID planning"),
        ):
            threads = [threading.Thread(target=retry_archive) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=10)

        assert not any(thread.is_alive() for thread in threads)
        assert sorted(outcomes) == ["success", "success"]

        assert engine._system_pids == expected_system_pids
        assert engine._machine_ids == expected_machine_ids
        assert state_manager.materialization_digest() == committed_state
        assert registry.census() == committed_registry
        assert authority.census().materialization_batch_transactions == 0

    def test_atomic_acknowledgement_converges_across_concurrent_prune(self) -> None:
        """Two retries crossing retained-auth/prune treat the exact archive as delivered."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, _systems = self._strict_fleet_engine(state_manager)
        engine._seed_system_process_trees()
        transaction = engine._boot_materialization_transaction
        terminal = engine._boot_materialization_terminal_result
        committed_state = state_manager.materialization_digest()
        committed_registry = registry.census()
        expected_system_pids = {host: dict(pids) for host, pids in engine._system_pids.items()}
        expected_machine_ids = dict(engine._machine_ids)
        engine._system_pids = {"corrupt": {"pid": 999}}
        engine._machine_ids = {"corrupt": "machine-id"}
        authenticated_barrier = threading.Barrier(3)
        release_ack = threading.Event()
        outcomes: list[str] = []
        original_ack = authority.acknowledge_materialization_batch_transaction_if_retained

        def authenticate_then_pause(
            candidate_transaction: LifecycleMaterializationBatchTransaction,
            candidate_terminal: LifecycleMaterializationBatchTerminalResult,
        ) -> bool:
            assert authority.authenticates_materialization_batch_terminal_result(
                candidate_transaction,
                candidate_terminal,
            )
            authenticated_barrier.wait(timeout=10)
            if not release_ack.wait(timeout=10):
                raise AssertionError("prune-crossing acknowledgement was not released")
            return original_ack(candidate_transaction, candidate_terminal)

        def retry() -> None:
            try:
                engine._seed_system_process_trees()
            except BaseException as error:
                outcomes.append(f"error:{error}")
            else:
                outcomes.append("success")

        with (
            patch.object(
                authority,
                "acknowledge_materialization_batch_transaction_if_retained",
                side_effect=authenticate_then_pause,
            ),
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("prune-crossing retry entered fixed-PID planning"),
            ),
        ):
            threads = [threading.Thread(target=retry) for _ in range(2)]
            for thread in threads:
                thread.start()
            authenticated_barrier.wait(timeout=10)
            authority.advance_watermark(start)
            authority.advance_watermark(start + timedelta(seconds=1))
            assert authority.census().materialization_batch_transactions == 0
            release_ack.set()
            for thread in threads:
                thread.join(timeout=10)

        assert all(not thread.is_alive() for thread in threads)
        assert sorted(outcomes) == ["success", "success"]
        assert engine._system_pids == expected_system_pids
        assert engine._machine_ids == expected_machine_ids
        assert state_manager.materialization_digest() == committed_state
        assert registry.census() == committed_registry
        assert state_manager.materialization_version == 1
        assert authority.census().materialization_batch_transactions == 0
        assert not original_ack(transaction, terminal)
        assert not original_ack(copy.copy(transaction), terminal)
        assert not original_ack(transaction, copy.copy(terminal))
        with pytest.raises(StateError, match="not retained"):
            authority.acknowledge_materialization_batch_transaction(transaction, terminal)

        foreign_state = StateManager()
        foreign_state.set_current_time(start)
        foreign_registry = LifecycleRegistry(shard_count=8)
        foreign_authority = GeneratorLifecycleAuthority(
            foreign_state,
            LifecycleShadow(foreign_state, foreign_registry),
            shard_count=8,
        )
        with pytest.raises(StateError, match="not canonical"):
            foreign_authority.acknowledge_materialization_batch_transaction_if_retained(
                transaction,
                terminal,
            )

    @pytest.mark.parametrize("oversized", ("scalar", "members"))
    def test_boot_request_bounds_reject_before_state_planning(self, oversized: str) -> None:
        """Fleet request width and scalar size are bounded before builder creation."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, _systems = self._strict_fleet_engine(state_manager)
        fleet = engine._build_boot_fleet_spec(start)
        host = fleet.hosts[0]
        member = host.processes[0]
        oversized_host = (
            replace(
                host,
                processes=(
                    replace(member, command_line="x" * (64 * 1024 + 1)),
                    *host.processes[1:],
                ),
            )
            if oversized == "scalar"
            else replace(
                host,
                aliases=tuple((f"alias-{index}", member.alias) for index in range(65_537)),
            )
        )
        oversized_fleet = replace(fleet, hosts=(oversized_host, *fleet.hosts[1:]))
        before_state = state_manager.materialization_digest()
        before_registry = registry.census()

        with (
            patch.object(
                engine,
                "_build_boot_fleet_spec",
                return_value=oversized_fleet,
            ),
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("oversized request entered State planning"),
            ),
            pytest.raises(
                StateError,
                match="too large|too many retained members|retained-byte limit",
            ),
        ):
            engine._seed_system_process_trees()

        assert state_manager.materialization_digest() == before_state
        assert registry.census() == before_registry
        assert authority.census().materialization_batch_transactions == 0

    def test_transaction_byte_capacity_is_reserved_before_boot_planning(self) -> None:
        """Aggregate retained-byte exhaustion rejects before boot capability minting."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, _authority, registry, shadow, _systems = self._strict_fleet_engine(state_manager)
        fleet_spec = engine._build_boot_fleet_spec(start)
        transaction_id, request_digest, request_payload = engine._boot_materialization_request(
            fleet_spec
        )
        existing_system_pids = (("preexisting", (("sentinel", 999),)),)
        _anticipated_terminal_payload, terminal_reservation = (
            engine._boot_materialization_terminal_reservation(
                fleet_spec,
                transaction_id,
                request_digest,
                existing_system_pids,
            )
        )
        assert terminal_reservation > 9_000
        request_only_authority = GeneratorLifecycleAuthority(
            state_manager,
            shadow,
            shard_count=8,
            materialization_batch_transaction_byte_capacity=9_000,
        )
        request_only_transaction = request_only_authority.reserve_materialization_batch_transaction(
            transaction_id=transaction_id,
            request_digest=request_digest,
            request_payload=request_payload,
        )
        request_only_authority.cancel_materialization_batch_transaction(request_only_transaction)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            shadow,
            shard_count=8,
            materialization_batch_transaction_byte_capacity=9_000,
        )
        engine.lifecycle_authority = authority

        with (
            patch.object(
                state_manager,
                "begin_materialization_batch",
                side_effect=AssertionError("byte exhaustion entered State planning"),
            ),
            pytest.raises(StateError, match="byte capacity is exhausted"),
        ):
            engine._seed_system_process_trees()

        census = authority.census()
        assert census.materialization_batch_transactions == 0
        assert census.materialization_batch_transaction_retained_bytes == 0
        assert registry.stats().live_processes == 0

        exact_capacity_authority = GeneratorLifecycleAuthority(
            state_manager,
            shadow,
            shard_count=8,
            materialization_batch_transaction_byte_capacity=terminal_reservation,
        )
        engine.lifecycle_authority = exact_capacity_authority
        engine._seed_system_process_trees()
        exact_census = exact_capacity_authority.census()
        assert exact_census.materialization_batch_transaction_retained_bytes == (
            terminal_reservation
        )
        assert state_manager.materialization_version == 1
        assert registry.stats().live_processes == len(state_manager.list_running_processes())

    def test_anticipated_terminal_node_boundary_and_one_over_are_preflighted(self) -> None:
        """The exact terminal node ceiling is accepted at boundary and rejects one over."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        registry = LifecycleRegistry(shard_count=8)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            LifecycleShadow(state_manager, registry),
            shard_count=8,
        )
        boundary_payload = (None,) * 65_535
        boundary = authority.reserve_materialization_batch_transaction(
            transaction_id="terminal-node-boundary",
            request_digest="terminal-node-boundary-request",
            anticipated_terminal_payload=boundary_payload,
        )
        authority.cancel_materialization_batch_transaction(boundary)

        with pytest.raises(StateError, match="too many retained members"):
            authority.reserve_materialization_batch_transaction(
                transaction_id="terminal-node-one-over",
                request_digest="terminal-node-one-over-request",
                anticipated_terminal_payload=(None,) * 65_536,
            )

        assert authority.census().materialization_batch_transactions == 0
        assert state_manager.materialization_version == 0
        assert registry.stats().live_processes == 0

    def test_supported_wide_fleet_terminal_nodes_reject_before_state_planning(self) -> None:
        """A 180-host supported fleet fails its terminal ceiling before PID/RNG planning."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, _systems = self._strict_fleet_engine(state_manager)
        systems = [
            System(
                hostname=f"WIDE-LNX-{index:03d}",
                ip=f"10.20.0.{index + 1}",
                os="Linux Ubuntu 22.04",
                type="server",
            )
            for index in range(180)
        ]
        engine.scenario.environment.systems = systems
        engine._kernel_boot_uptimes = {
            system.hostname: 300.0 + index for index, system in enumerate(systems)
        }
        before_state = state_manager.materialization_digest()
        before_pid_allocator = state_manager.pid_allocator_census()
        before_system_pids = {host: dict(pids) for host, pids in engine._system_pids.items()}
        before_machine_ids = dict(engine._machine_ids)

        with patch.object(
            state_manager,
            "begin_materialization_batch",
            side_effect=AssertionError("wide terminal entered State planning"),
        ) as begin_batch:
            for _attempt in range(2):
                with pytest.raises(StateError, match="too many retained members"):
                    engine._seed_system_process_trees()

        assert begin_batch.call_count == 0
        assert state_manager.materialization_digest() == before_state
        assert state_manager.pid_allocator_census() == before_pid_allocator
        assert registry.stats().live_processes == 0
        assert engine._system_pids == before_system_pids
        assert engine._machine_ids == before_machine_ids
        assert authority.census().materialization_batch_transactions == 0
        assert not hasattr(engine, "_boot_materialization_transaction")

    def test_transaction_payload_rejects_custom_timezone_and_active_objects_without_repr(
        self,
    ) -> None:
        """Only inert exact built-ins and exact UTC can enter retained transaction payloads."""

        class PoisonTimezone(tzinfo):
            repr_calls = 0

            def utcoffset(self, _value):
                return timedelta(0)

            def dst(self, _value):
                return timedelta(0)

            def tzname(self, _value):
                return "UTC"

            def __repr__(self):
                type(self).repr_calls += 1
                raise AssertionError("custom timezone repr executed")

        class PoisonObject:
            repr_calls = 0

            def __repr__(self):
                type(self).repr_calls += 1
                raise AssertionError("payload repr executed")

        class StringSubclass(str):
            def __repr__(self):
                raise AssertionError("string subclass repr executed")

        class TupleSubclass(tuple):
            def __repr__(self):
                raise AssertionError("tuple subclass repr executed")

        class PayloadMeta(type):
            pass

        class PayloadClass(metaclass=PayloadMeta):
            pass

        state_manager = StateManager()
        state_manager.set_current_time(datetime(2024, 3, 15, 8, 0, tzinfo=UTC))
        registry = LifecycleRegistry(shard_count=8)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            LifecycleShadow(state_manager, registry),
            shard_count=8,
        )
        custom_time = datetime(2024, 3, 15, 8, 0, tzinfo=PoisonTimezone())
        hostile_payloads = (
            (custom_time,),
            (PoisonObject(),),
            (StringSubclass("subclass"),),
            (TupleSubclass(("subclass",)),),
            (lambda: None,),
            (PayloadClass,),
        )
        for index, payload in enumerate(hostile_payloads):
            with pytest.raises(StateError, match="exact built-in UTC|immutable canonical tuples"):
                authority.reserve_materialization_batch_transaction(
                    transaction_id=f"hostile-{index}",
                    request_digest="hostile-request",
                    request_payload=payload,
                )

        with pytest.raises(StateError, match="non-empty string"):
            authority.reserve_materialization_batch_transaction(
                transaction_id=StringSubclass("subclass-id"),
                request_digest="hostile-request",
            )
        exact_utc = authority.reserve_materialization_batch_transaction(
            transaction_id="exact-utc",
            request_digest="exact-utc-request",
            request_payload=(datetime(2024, 3, 15, 8, 0, tzinfo=UTC),),
        )
        authority.cancel_materialization_batch_transaction(exact_utc)
        assert PoisonTimezone.repr_calls == 0
        assert PoisonObject.repr_calls == 0
        assert authority.census().materialization_batch_transactions == 0
        assert state_manager.materialization_version == 0
        assert registry.stats().live_processes == 0

    def test_terminal_authentication_rejects_custom_timezone_without_repr_or_lock_entry(
        self,
    ) -> None:
        """Terminal structure is authenticated before retained-record lock lookup."""

        class PoisonTimezone(tzinfo):
            repr_calls = 0

            def utcoffset(self, _value):
                return timedelta(0)

            def dst(self, _value):
                return timedelta(0)

            def tzname(self, _value):
                return "UTC"

            def __repr__(self):
                type(self).repr_calls += 1
                raise AssertionError("terminal timezone repr executed")

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        registry = LifecycleRegistry(shard_count=8)
        authority = GeneratorLifecycleAuthority(
            state_manager,
            LifecycleShadow(state_manager, registry),
            shard_count=8,
        )
        transaction = authority.reserve_materialization_batch_transaction(
            transaction_id="terminal-structure",
            request_digest="terminal-request",
        )
        builder = state_manager.begin_materialization_batch()
        builder.plan_boot_time("HOST-A", start - timedelta(hours=1))
        authority.materialize_batch(builder.seal(), transaction=transaction)
        result = authority.reconcile_materialization_batch_transaction(transaction)
        assert result is not None
        custom_time = datetime(2024, 3, 15, 8, 0, tzinfo=PoisonTimezone())
        malformed_terminal = replace(result, _terminal_at=custom_time)

        assert not authority.validates_archived_materialization_batch_terminal_result(
            transaction,
            malformed_terminal,
        )
        assert PoisonTimezone.repr_calls == 0

        lock_observations: list[bool] = []
        original_validate = LifecycleMaterializationBatchTransaction._has_valid_integrity

        def observe_lock(candidate, authority_secret):
            lock_observations.append(authority._materialization_batch_transaction_lock._is_owned())
            return original_validate(candidate, authority_secret)

        with patch.object(
            LifecycleMaterializationBatchTransaction,
            "_has_valid_integrity",
            new=observe_lock,
        ):
            assert authority.reconcile_materialization_batch_transaction(transaction) is result
        assert lock_observations
        assert not any(lock_observations)

    @pytest.mark.parametrize(
        "pause_attribute",
        (
            "_boot_materialization_transaction_identity",
            "_boot_materialization_terminal_identity",
        ),
    )
    def test_archive_identity_publishes_before_two_observers_enter(
        self,
        pause_attribute: str,
    ) -> None:
        """Identity-first archive publication has no transient invalid-carrier window."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        pause_entered = threading.Event()
        release_pause = threading.Event()
        first_pause_lock = threading.Lock()
        first_pause = True
        outcomes: list[str] = []
        engine_type = type(engine)

        def pausing_setattr(instance: object, name: str, value: object) -> None:
            nonlocal first_pause
            object.__setattr__(instance, name, value)
            should_pause = False
            if instance is engine and name == pause_attribute:
                with first_pause_lock:
                    if first_pause:
                        first_pause = False
                        should_pause = True
            if should_pause:
                pause_entered.set()
                if not release_pause.wait(timeout=10):
                    raise AssertionError("archive publication pause was not released")

        def seed(label: str) -> None:
            try:
                engine._seed_system_process_trees()
            except BaseException as error:
                outcomes.append(f"{label}:error:{error}")
            else:
                outcomes.append(f"{label}:success")

        threads: list[threading.Thread] = []
        with patch.object(engine_type, "__setattr__", new=pausing_setattr):
            winner = threading.Thread(target=seed, args=("winner",))
            threads.append(winner)
            winner.start()
            assert pause_entered.wait(timeout=10)
            observers = [
                threading.Thread(target=seed, args=(f"observer-{index}",)) for index in range(2)
            ]
            threads.extend(observers)
            for observer in observers:
                observer.start()
            for observer in observers:
                observer.join(timeout=10)
            observers_completed_inside_window = all(
                not observer.is_alive() for observer in observers
            )
            release_pause.set()
            winner.join(timeout=10)

        assert observers_completed_inside_window
        assert all(not thread.is_alive() for thread in threads)
        assert sorted(outcomes) == [
            "observer-0:success",
            "observer-1:success",
            "winner:success",
        ]
        assert state_manager.materialization_version == 1
        assert registry.stats().live_processes == len(state_manager.list_running_processes())
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)
        assert authority.census().materialization_batch_transactions_acknowledged == 1

    def test_two_thread_fleet_retry_converges_on_one_terminal(self) -> None:
        """Concurrent identical callers share one canonical commit and both return."""

        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        state_manager = StateManager()
        state_manager.set_current_time(start)
        engine, authority, registry, _shadow, systems = self._strict_fleet_engine(state_manager)
        barrier = threading.Barrier(3)
        outcomes: list[str] = []

        def seed() -> None:
            barrier.wait()
            try:
                engine._seed_system_process_trees()
            except StateError as exc:
                outcomes.append(f"error:{exc}")
            else:
                outcomes.append("success")

        threads = [threading.Thread(target=seed) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)

        assert all(not thread.is_alive() for thread in threads)
        assert sorted(outcomes) == ["success", "success"]
        assert state_manager.materialization_version == 1
        assert registry.stats().live_processes == len(state_manager.list_running_processes())
        assert all(state_manager.get_boot_time(system.hostname) is not None for system in systems)
        census = authority.census()
        assert census.materialization_batch_transactions == 1
        assert census.materialization_batch_transactions_acknowledged == 1

    @pytest.mark.parametrize(
        "system",
        (
            System(
                hostname="FALLBACK-WIN-01",
                ip="10.0.10.41",
                os="Windows 10",
                type="workstation",
            ),
            System(
                hostname="FALLBACK-LNX-01",
                ip="10.0.10.42",
                os="Linux Ubuntu 22.04",
                type="server",
            ),
        ),
    )
    def test_boot_tree_without_authority_retains_fixture_state_behavior(
        self,
        system: System,
    ) -> None:
        """Fixtures omitting the engine owner should retain the raw State path."""

        fallback_state = StateManager()
        strict_state = StateManager()
        start = datetime(2024, 3, 15, 8, 0, tzinfo=UTC)
        fallback_state.set_current_time(start)
        strict_state.set_current_time(start)
        engine_type = type("FallbackBootEngine", (EmitterSetupMixin,), {})
        engine = engine_type.__new__(engine_type)
        engine.state_manager = fallback_state
        engine.scenario = Mock()
        engine.scenario.environment.service_accounts = []
        engine._system_service_defaults = {}
        fallback_pids: dict[str, int] = {}

        with (
            patch.object(
                fallback_state,
                "register_process",
                wraps=fallback_state.register_process,
            ) as register_process,
            patch.object(
                fallback_state,
                "create_process",
                wraps=fallback_state.create_process,
            ) as create_process,
        ):
            if "windows" in system.os.casefold():
                engine._seed_windows_process_tree(system, fallback_pids)
            else:
                engine._seed_linux_process_tree(system, fallback_pids)

        strict_pids, _authority, _registry = self._seed_with_lifecycle_authority(
            strict_state,
            system,
        )
        assert register_process.call_count == 1
        assert create_process.call_count > 0
        assert fallback_pids == strict_pids
        for pid in set(fallback_pids.values()):
            assert fallback_state.get_process(system.hostname, pid) == strict_state.get_process(
                system.hostname,
                pid,
            )
            assert fallback_state.get_process_identity(
                system.hostname, pid
            ) == strict_state.get_process_identity(system.hostname, pid)
            assert fallback_state.get_primary_thread(
                system.hostname, pid
            ) == strict_state.get_primary_thread(system.hostname, pid)
        assert fallback_state.pid_allocator_census() == strict_state.pid_allocator_census()
        assert fallback_state.state.current_time == strict_state.state.current_time == start

    def test_all_seeded_windows_pids_survive_termination(
        self, state_manager, mock_emitters, win_system
    ):
        """After multiple hours, all seeded Windows PIDs must still exist."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, win_system)

        # Also seed some user processes that SHOULD be terminable
        test_user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)
        engine.scenario.environment.users = [test_user]
        state_manager.create_session(
            username="alice", system="WKS-01", logon_type=2, source_ip="10.0.10.1"
        )
        for i in range(10):
            state_manager.create_process(
                "WKS-01",
                pids["explorer"],
                f"C:\\Users\\alice\\app{i}.exe",
                f"app{i}.exe",
                "alice",
                "Medium",
            )

        # Advance 8 hours, running termination each hour
        for hour in range(8):
            current = datetime(2024, 3, 15, 9 + hour, 0, 0, tzinfo=UTC)
            state_manager.set_current_time(current)
            engine._terminate_stale_processes(current)

        # ALL seeded system PIDs must still be in running_processes
        for role, pid in pids.items():
            key = (win_system.hostname, pid)
            assert key in state_manager.state.running_processes, (
                f"Seeded system process '{role}' (PID {pid}) was terminated"
            )

    def test_seeded_defender_processes_use_host_platform_version(
        self, state_manager, mock_emitters, win_system
    ):
        """Seeded Defender process paths should not mix versioned and unversioned roots."""
        _, pids = self._seed_and_get_pids(state_manager, mock_emitters, win_system)

        msmpeng = state_manager.get_process(win_system.hostname, pids["msmpeng"])
        mpcmdrun = state_manager.get_process(win_system.hostname, pids["mpcmdrun"])

        assert msmpeng is not None
        assert mpcmdrun is not None
        assert r"\Windows Defender\Platform\4.18." in msmpeng.image
        assert mpcmdrun.image.rsplit("\\", 1)[0] == msmpeng.image.rsplit("\\", 1)[0]

    def test_engine_seeded_boot_processes_use_host_boot_times(self, state_manager, mock_emitters):
        """Fleet-seeded system processes should not all share the scenario-window epoch."""
        systems = [
            System(hostname="WKS-A", ip="10.0.10.11", os="Windows 10", type="workstation"),
            System(hostname="WKS-B", ip="10.0.10.12", os="Windows 10", type="workstation"),
        ]
        ag = ActivityGenerator(state_manager, mock_emitters)
        engine = type("FakeEngine", (EmitterSetupMixin, BaselineMixin), {}).__new__(
            type("FakeEngine", (EmitterSetupMixin, BaselineMixin), {})
        )
        engine.state_manager = state_manager
        engine.activity_generator = ag
        engine.scenario = Mock()
        engine.scenario.environment.systems = systems
        engine.scenario.environment.users = []
        engine.start_time = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        engine._kernel_boot_uptimes = {
            "WKS-A": 5 * 86400.0,
            "WKS-B": 17 * 86400.0,
        }
        engine._system_pids = {}
        engine._infra_ips = {"dns": ["10.0.0.1"]}
        engine._system_service_defaults = {}
        engine._find_actor = lambda username: User(
            username=username, full_name=username, email=f"{username}@test.com", enabled=True
        )

        original_time = state_manager.state.current_time
        engine._seed_system_process_trees()

        proc_a = state_manager.get_process("WKS-A", engine._system_pids["WKS-A"]["services"])
        proc_b = state_manager.get_process("WKS-B", engine._system_pids["WKS-B"]["services"])
        assert proc_a is not None
        assert proc_b is not None
        assert proc_a.start_time < engine.start_time - timedelta(days=4)
        assert proc_b.start_time < engine.start_time - timedelta(days=16)
        assert proc_a.start_time != proc_b.start_time
        assert state_manager.state.current_time == original_time

    def test_all_seeded_linux_pids_survive_termination(
        self, state_manager, mock_emitters, linux_system
    ):
        """After multiple hours, all seeded Linux PIDs must still exist."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, linux_system)

        test_user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)
        engine.scenario.environment.users = [test_user]

        for hour in range(8):
            current = datetime(2024, 3, 15, 9 + hour, 0, 0, tzinfo=UTC)
            state_manager.set_current_time(current)
            engine._terminate_stale_processes(current)

        for role, pid in pids.items():
            key = (linux_system.hostname, pid)
            assert key in state_manager.state.running_processes, (
                f"Seeded system process '{role}' (PID {pid}) was terminated"
            )

    def test_linux_seeded_systemd_uses_pid_one(self, state_manager, mock_emitters, linux_system):
        """Linux systemd should anchor source-native process trees at PID 1."""
        _engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, linux_system)

        systemd = state_manager.get_process(linux_system.hostname, pids["systemd"])
        journald = state_manager.get_process(linux_system.hostname, pids["journald"])

        assert pids["systemd"] == 1
        assert systemd is not None
        assert systemd.parent_pid == 0
        assert state_manager.get_process_object_id(linux_system.hostname, 1)
        assert journald is not None
        assert journald.parent_pid == 1

    def test_forward_proxy_seeds_squid_without_role_implied_apache(
        self, state_manager, mock_emitters
    ):
        """Forward proxy hosts should have a source-native proxy listener process."""
        proxy = System(
            hostname="PROXY-01",
            ip="10.0.10.20",
            os="Linux Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
            services=["squid", "ssh"],
        )
        _engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, proxy)

        squid = state_manager.get_process(proxy.hostname, pids["squid"])

        assert squid is not None
        assert squid.image == "/usr/sbin/squid"
        assert squid.command_line == "/usr/sbin/squid --foreground -YC"
        assert squid.username == "proxy"
        assert "apache2" not in pids

    def test_linux_database_services_seed_listener_processes(self, state_manager, mock_emitters):
        """Linux database service inventory should seed matching listener processes."""
        system = System(
            hostname="DB-LNX-01",
            ip="10.0.20.10",
            os="CentOS 8",
            type="server",
            services=["mysql", "postgresql"],
            roles=["database"],
        )
        _engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, system)

        assert "mysqld" in pids
        assert "postgres" in pids
        mysqld = state_manager.get_process(system.hostname, pids["mysqld"])
        postgres = state_manager.get_process(system.hostname, pids["postgres"])
        assert mysqld is not None
        assert postgres is not None
        assert mysqld.username == "mysql"
        assert postgres.username == "postgres"

    def test_windows_mssql_service_seeds_listener_process(self, state_manager, mock_emitters):
        """Windows MSSQL service inventory should seed sqlservr.exe."""
        system = System(
            hostname="DB-WIN-01",
            ip="10.0.20.11",
            os="Windows Server 2022",
            type="server",
            services=["mssql"],
            roles=["database"],
        )
        _engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, system)

        assert "sqlservr" in pids
        process = state_manager.get_process(system.hostname, pids["sqlservr"])
        assert process is not None
        assert process.username == r"NT SERVICE\MSSQLSERVER"

    def test_user_processes_still_terminate(self, state_manager, mock_emitters, win_system):
        """Non-system user processes should still be terminated normally."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, win_system)

        test_user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)
        engine.scenario.environment.users = [test_user]
        state_manager.create_session(
            username="alice", system="WKS-01", logon_type=2, source_ip="10.0.10.1"
        )

        # Create a user process at hour 8
        state_manager.create_process(
            "WKS-01",
            pids["explorer"],
            "C:\\Users\\alice\\malware.exe",
            "malware.exe",
            "alice",
            "Medium",
        )

        # Run termination 4 hours later (well past max_hours for "other" category)
        later = datetime(2024, 3, 15, 12, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(later)

        # Run multiple times to overcome the 50% random chance
        for _ in range(20):
            engine._terminate_stale_processes(later)

        # System processes must STILL be alive regardless of user process fate
        for role, pid in pids.items():
            sys_key = (win_system.hostname, pid)
            assert sys_key in state_manager.state.running_processes, (
                f"System process '{role}' was incorrectly terminated"
            )

    def test_stale_cleanup_honors_registered_foreground_deadline(
        self, state_manager, mock_emitters, linux_system
    ):
        """Hourly cleanup must consume a bounded lifecycle instead of resampling it."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, linux_system)
        activity_generator = engine.activity_generator
        start_time = datetime(2024, 3, 15, 8, 10, tzinfo=UTC)
        deadline = start_time + timedelta(seconds=45)
        state_manager.set_current_time(start_time)
        pid = state_manager.create_process(
            linux_system.hostname,
            pids["systemd"],
            "/usr/bin/apt-get",
            "apt-get update",
            "root",
            "System",
            logon_id="0x3e7",
        )
        activity_generator._remember_foreground_process_finalizer(
            system=linux_system,
            user=User(username="root", full_name="root", email="root@example.test"),
            pid=pid,
            process_name="/usr/bin/apt-get",
            logon_id="0x3e7",
            termination_time=deadline,
        )
        activity_generator.generate_process_termination = Mock()

        engine._terminate_stale_processes(start_time + timedelta(hours=1))

        activity_generator.generate_process_termination.assert_called_once()
        assert activity_generator.generate_process_termination.call_args.kwargs["time"] == deadline


class TestProtectionListCompleteness:
    """Verify the protection list covers all seeded process names."""

    def test_windows_seeded_processes_match_protection_patterns(self):
        """Long-lived Windows seed images should match a protection pattern.

        Seeded taskhostw is protected by its exact PID instead: dynamically
        materialized task hosts are finite and must remain lifecycle-eligible.
        """
        # Images seeded in _seed_windows_process_tree
        seeded_images = [
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\csrss.exe",
            r"C:\Windows\System32\wininit.exe",
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\svchost.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            r"C:\Windows\System32\SearchIndexer.exe",
            r"C:\Windows\System32\winlogon.exe",
            r"C:\Windows\System32\userinit.exe",
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\dwm.exe",
            r"C:\Windows\System32\RuntimeBroker.exe",
            r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
        ]

        # Import the actual patterns from baseline code
        # We replicate the pattern matching logic here
        system_patterns = (
            "svchost",
            "lsass",
            "csrss",
            "services.exe",
            "explorer.exe",
            "smss",
            "wininit",
            "winlogon",
            "fontdrvhost",
            "dwm.exe",
            "userinit.exe",
            "runtimebroker",
            "searchindexer",
            "msmpeng",
            "sqlservr",
            "systemd",
            "cron",
            "crond",
            "sshd",
            "rsyslogd",
            "journald",
            "udevd",
            "logind",
            "snapd",
            "timesyncd",
            "networkmanager",
            "dbus-daemon",
            "bash",
            "agetty",
        )

        for image in seeded_images:
            image_lower = image.lower()
            matched = any(p in image_lower for p in system_patterns)
            assert matched, (
                f"Seeded image '{image}' is NOT covered by system_patterns — "
                f"it will be terminated after 0.5-2 hours"
            )

    def test_linux_seeded_processes_match_protection_patterns(self):
        """Every Linux seeded process image must match a system_patterns entry."""
        seeded_images = [
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd-journald",
            "/lib/systemd/systemd-udevd",
            "/usr/sbin/rsyslogd",
            "/usr/sbin/NetworkManager",
            "/usr/bin/dbus-daemon",
            "/usr/lib/systemd/systemd-logind",
            "/usr/sbin/sshd",
            "/usr/sbin/cron",
            "/usr/sbin/crond",
            "/sbin/agetty",
            "/usr/lib/snapd/snapd",
            "/usr/lib/systemd/systemd-timesyncd",
            "/bin/bash",
            "/usr/sbin/mysqld",
            "/usr/bin/postgres",
        ]

        system_patterns = (
            "svchost",
            "lsass",
            "csrss",
            "services.exe",
            "explorer.exe",
            "smss",
            "wininit",
            "winlogon",
            "fontdrvhost",
            "dwm.exe",
            "userinit.exe",
            "runtimebroker",
            "taskhostw",
            "searchindexer",
            "msmpeng",
            "sqlservr",
            "systemd",
            "cron",
            "crond",
            "sshd",
            "rsyslogd",
            "journald",
            "udevd",
            "logind",
            "snapd",
            "timesyncd",
            "networkmanager",
            "dbus-daemon",
            "bash",
            "agetty",
            "mysqld",
            "postgres",
        )

        for image in seeded_images:
            image_lower = image.lower()
            matched = any(p in image_lower for p in system_patterns)
            assert matched, (
                f"Seeded image '{image}' is NOT covered by system_patterns — "
                f"it will be terminated after 0.5-2 hours"
            )
