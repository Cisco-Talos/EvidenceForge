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

"""Unit tests for StateManager."""

import random
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.identity import EventIdentityPlan
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation import state_manager as state_manager_module
from evidenceforge.generation.indexes import TemporalAllocationIndex
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.storage_world import CompiledStorageFile
from evidenceforge.models.exceptions import StateError

_SMB_TRANSIENT_SUMMARY_FIELDS = (
    "smb_file_mutation_journals",
    "smb_file_mutation_capabilities",
    "smb_file_mutation_operation_indexes",
    "smb_file_mutation_file_owners",
    "smb_file_mutation_path_owners",
    "smb_file_mutation_journal_entries",
    "smb_file_mutation_commit_results",
    "smb_file_mutation_commit_receipts",
    "smb_file_mutation_acknowledging",
    "smb_file_mutation_cancelling",
    "smb_file_mutation_journal_locators",
    "smb_file_mutation_result_locators",
    "smb_file_mutation_retained_bytes",
)


def _assert_no_smb_file_mutation_authority(manager: StateManager) -> None:
    summary = manager.get_state_summary()
    assert {name: summary[name] for name in _SMB_TRANSIENT_SUMMARY_FIELDS} == {
        name: 0 for name in _SMB_TRANSIENT_SUMMARY_FIELDS
    }


class TestStateManagerInit:
    """Tests for StateManager initialization."""

    def test_init_creates_empty_state(self):
        """Test that new StateManager has empty state."""
        sm = StateManager()
        assert len(sm.state.active_sessions) == 0
        assert len(sm.state.running_processes) == 0
        assert len(sm.state.open_connections) == 0
        assert len(sm.state.dns_cache) == 0
        assert sm.state.current_time is None


@pytest.mark.parametrize("drift", ("host", "object", "start", "interval"))
def test_process_materialization_rejects_parent_drift_before_child_publication(
    drift: str,
) -> None:
    """ABA identity drift and a closed parent interval fail before allocator mutation."""

    start = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    parent_plan = manager.plan_process_materialization(
        system="WS-01",
        parent_pid=0,
        image=r"C:\Windows\System32\System",
        command_line="System",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=start,
        fixed_pid=4,
    )
    parent = manager.materialize_process(parent_plan)
    child_plan = manager.plan_process_materialization(
        system="WS-01",
        parent_pid=parent.pid,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        start_time=start + timedelta(seconds=1),
    )
    if drift == "host":
        parent.system = "WS-02"
    elif drift == "object":
        parent.ecar_object_id = "reused-pid-parent"
    elif drift == "start":
        shifted_start = start + timedelta(seconds=2)
        parent.start_time = shifted_start
        primary_thread = manager.state.running_threads[
            ("WS-01", parent.ecar_object_id, parent.primary_tid)
        ]
        primary_thread.start_time = shifted_start
    else:
        parent.end_time = start + timedelta(milliseconds=500)
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()

    with pytest.raises(StateError, match="parent identity (?:drifted|is not active)"):
        manager.materialize_process(child_plan)

    assert manager.materialization_digest() == digest
    assert manager.pid_allocator_census() == allocator_census
    assert manager.get_process("WS-01", child_plan.identity.pid) is None


@pytest.mark.parametrize(
    ("child_host", "child_parent_pid"),
    (("WS-02", 4), ("WS-01", 8)),
    ids=("host", "pid"),
)
def test_batch_process_plan_captures_parent_and_rejects_mismatched_owner(
    child_host: str,
    child_parent_pid: int,
) -> None:
    """A batch child captures its exact earlier parent and cannot change host or PID."""

    start = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    builder = manager.begin_materialization_batch()
    parent = builder.plan_process(
        system="WS-01",
        parent_pid=0,
        image=r"C:\Windows\System32\System",
        command_line="System",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=start,
        fixed_pid=4,
    )
    child = builder.plan_process(
        system="WS-01",
        parent_pid=parent.identity.pid,
        image=r"C:\Windows\System32\winlogon.exe",
        command_line="winlogon.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=start + timedelta(milliseconds=100),
        parent_plan=parent,
    )
    assert child.parent_identity == parent.identity

    with pytest.raises(StateError, match="parent identity is not active"):
        builder.plan_process(
            system=child_host,
            parent_pid=child_parent_pid,
            image=r"C:\Windows\System32\winlogon.exe",
            command_line="winlogon.exe",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
            start_time=start + timedelta(milliseconds=200),
            parent_plan=parent,
        )

    plan = builder.seal()
    manager.validate_materialization_batch(plan)


def test_batch_virtual_pid4_parent_rejects_a_later_modeled_parent_before_mutation() -> None:
    """Compatibility PID 4 cannot conceal a same-batch parent ordered after its child."""

    start = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    builder = manager.begin_materialization_batch()
    builder.plan_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\winlogon.exe",
        command_line="winlogon.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=start + timedelta(milliseconds=100),
    )
    builder.plan_process(
        system="WS-01",
        parent_pid=0,
        image=r"C:\Windows\System32\System",
        command_line="System",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        start_time=start,
        fixed_pid=4,
    )
    plan = builder.seal()
    digest = manager.materialization_digest()
    allocator_census = manager.pid_allocator_census()

    with pytest.raises(StateError, match="parent is not ordered first"):
        manager.validate_materialization_batch(plan)

    assert manager.materialization_digest() == digest
    assert manager.pid_allocator_census() == allocator_census


def test_materialization_plans_reject_public_same_field_checksum_forgery() -> None:
    """Only the issuing StateManager can authenticate an otherwise exact plan."""

    start = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    session_plan = manager.plan_session_materialization(
        username="analyst",
        system="WS-01",
        logon_type=2,
        source_ip="10.0.0.5",
    )
    forged_session = replace(
        session_plan,
        _integrity_token=state_manager_module.hashlib.sha256(
            repr(
                (
                    "session",
                    session_plan._expected_version,
                    session_plan._identity,
                    session_plan._payload,
                    session_plan._allocator_patch,
                )
            ).encode()
        ).hexdigest(),
    )
    process_plan = manager.plan_process_materialization(
        system="WS-01",
        parent_pid=0,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
    )
    forged_process = replace(
        process_plan,
        _integrity_token=state_manager_module.hashlib.sha256(
            repr(
                (
                    "process",
                    process_plan._expected_version,
                    process_plan._identity,
                    process_plan._payload,
                    process_plan._allocator_patch,
                )
            ).encode()
        ).hexdigest(),
    )
    digest = manager.materialization_digest()

    with pytest.raises(StateError, match="integrity validation failed"):
        manager.materialize_session(forged_session)
    with pytest.raises(StateError, match="integrity validation failed"):
        manager.materialize_process(forged_process)

    assert manager.materialization_digest() == digest


def test_standalone_luid_and_transient_pid_allocations_fence_prepared_plans() -> None:
    start = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    session_plan = manager.plan_session_materialization(
        username="analyst",
        system="LNX-01",
        logon_type=2,
        source_ip="-",
        start_time=start,
    )

    manager.allocate_logon_id("LNX-01", start)

    with pytest.raises(StateError, match="plan is stale"):
        with manager.materialization_guard(session_plan):
            manager.materialize_session(session_plan)

    process_plan = manager.plan_process_materialization(
        system="LNX-01",
        parent_pid=0,
        image="/bin/bash",
        command_line="/bin/bash -l",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        start_time=start,
    )
    manager.allocate_transient_linux_pid("LNX-01", start + timedelta(seconds=1))

    with pytest.raises(StateError, match="plan is stale"):
        with manager.materialization_guard(process_plan):
            manager.materialize_process(process_plan)


def test_boot_epoch_and_explicit_thread_allocation_fence_prepared_process_plan() -> None:
    start = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    boot_sensitive = manager.plan_process_materialization(
        system="LNX-01",
        parent_pid=0,
        image="/sbin/init",
        command_line="/sbin/init",
        username="root",
        integrity_level="System",
        os_category="linux",
        start_time=start,
    )

    manager.register_boot_time("LNX-01", start - timedelta(hours=1))

    with pytest.raises(StateError, match="plan is stale"):
        with manager.materialization_guard(boot_sensitive):
            manager.materialize_process(boot_sensitive)

    owner_plan = manager.plan_process_materialization(
        system="LNX-01",
        parent_pid=0,
        image="/bin/bash",
        command_line="/bin/bash -l",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        start_time=start,
    )
    owner = manager.materialize_process(owner_plan)
    stale = manager.plan_process_materialization(
        system="LNX-01",
        parent_pid=owner.pid,
        image="/usr/bin/id",
        command_line="id",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        start_time=start + timedelta(seconds=1),
    )
    manager.create_thread(
        "LNX-01",
        owner.ecar_object_id,
        kind="worker",
        start_time=start + timedelta(milliseconds=500),
    )

    with pytest.raises(StateError, match="plan is stale"):
        with manager.materialization_guard(stale):
            manager.materialize_process(stale)

    def test_init_sets_counters(self):
        """Test that counters are initialized correctly."""
        sm = StateManager()
        assert sm._connection_id_counter == 0
        assert len(sm._pid_counters) == 0
        assert len(sm._used_logon_ids) == 0

    def test_channel_state_is_not_duplicated_in_legacy_manager(self):
        """Protocol channel state belongs only to the shared application registry."""

        sm = StateManager()

        for attribute in (
            "_smb_sessions",
            "_smb_session_affinity",
            "_smb_trees",
            "_smb_tree_by_session_share",
            "_smb_handles",
            "open_smb_session",
            "get_or_open_smb_tree",
            "open_smb_handle",
            "sweep_smb_state",
        ):
            assert not hasattr(sm, attribute)
        assert "smb_sessions" not in sm.get_state_summary()
        assert "smb_trees" not in sm.get_state_summary()
        assert "smb_handles" not in sm.get_state_summary()

    def test_linux_logind_session_ids_follow_event_time(self):
        """Logind session IDs should sort with event time, not generation order."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(7)

        later_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=10),
        )
        earlier_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=1),
        )

        assert earlier_id < later_id
        assert later_id - earlier_id < 600

    def test_linux_logind_session_ids_do_not_encode_elapsed_seconds(self):
        """Logind session IDs should look like allocator counters, not uptime seconds."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(13)

        first = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=4, seconds=58),
        )
        second = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=21, seconds=23),
        )

        assert second > first
        assert second - first != 985
        assert second - first < 200

    def test_linux_logind_session_ids_order_same_minute_out_of_generation_order(self):
        """Same-minute IDs should still sort by rendered syslog time."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(17)

        later_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=14, seconds=41),
        )
        earlier_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=14, seconds=31),
        )

        assert earlier_id < later_id

    def test_linux_logind_session_ids_follow_prior_collision_bumps(self):
        """Later sessions should not dip below earlier IDs inflated by collision repair."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(19)
        earlier_time = start + timedelta(minutes=10)
        later_time = start + timedelta(minutes=20)
        sm._linux_logind_session_initials["linux01"] = 100
        sm._linux_logind_session_used_ids["linux01"] = {180}
        allocations = TemporalAllocationIndex()
        allocations.add(earlier_time, 180)
        sm._linux_logind_session_allocations["linux01"] = allocations

        later_id = sm.next_linux_logind_session_id("linux01", rng, later_time)

        assert later_id > 180

    def test_sessions_for_user_at_stops_at_transport_close(self):
        """Transport-backed sessions should not own activity after their close time."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        close = start + timedelta(minutes=8)
        logon_id = sm.create_session(
            username="alice",
            system="linux01",
            logon_type=10,
            source_ip="10.0.1.50",
            start_time=start,
            session_kind="ssh",
        )
        sm.update_session_metadata(logon_id, network_close_time=close)

        assert [
            s.logon_id for s in sm.get_sessions_for_user_at("alice", close - timedelta(seconds=1))
        ] == [logon_id]
        assert sm.get_sessions_for_user_at("alice", close) == []
        assert sm.get_sessions_for_user_at("alice", close + timedelta(minutes=1)) == []

    def test_active_and_historical_session_queries_have_explicit_boundaries(self):
        """Active-only lookup must exclude ended state that historical lookup can render."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        event_time = start + timedelta(minutes=30)
        end = start + timedelta(hours=1)
        logon_id = sm.create_session(
            username="alice",
            system="WS-01",
            logon_type=2,
            source_ip="-",
            start_time=start,
        )
        assert sm.end_session(logon_id, end)

        assert sm.get_active_sessions_for_user_at("alice", event_time) == []
        assert sm.get_active_sessions_on_system_at("WS-01", event_time) == []
        assert [s.logon_id for s in sm.get_sessions_for_user_at("alice", event_time)] == [logon_id]
        assert [s.logon_id for s in sm.get_sessions_on_system_at("WS-01", event_time)] == [logon_id]
        assert sm.get_session_at(logon_id, event_time) is not None
        assert sm.get_session_at(logon_id, end) is None

    def test_authoritative_end_keeps_durable_ssh_session_live_past_early_disconnect(self):
        """An early SSH transport close must not create a shadow durable session."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        transport_close = start + timedelta(minutes=8)
        deadline = start + timedelta(hours=1)
        logon_id = sm.create_session(
            username="alice",
            system="linux01",
            logon_type=10,
            source_ip="10.0.1.50",
            start_time=start,
            session_kind="ssh",
        )
        sm.update_session_metadata(logon_id, network_close_time=transport_close)
        plan = SessionEndPlan(deadline, "explicit_storyline", "story-logoff")

        assert sm.plan_session_end(logon_id, plan)
        assert [
            session.logon_id
            for session in sm.get_sessions_for_user_at(
                "alice",
                transport_close + timedelta(minutes=10),
            )
        ] == [logon_id]
        assert sm.get_sessions_for_user_at("alice", deadline) == []

    def test_sessions_on_system_at_excludes_authoritatively_ended_session(self):
        """Host-local activity selection must honor a preplanned session deadline."""

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        deadline = start + timedelta(hours=1)
        logon_id = sm.create_session(
            username="alice",
            system="WS-01",
            logon_type=2,
            source_ip="-",
            start_time=start,
        )
        assert sm.plan_session_end(
            logon_id,
            SessionEndPlan(deadline, "explicit_storyline", "story-logoff"),
        )

        assert [
            session.logon_id
            for session in sm.get_sessions_on_system_at(
                "WS-01",
                deadline - timedelta(milliseconds=1),
            )
        ] == [logon_id]
        assert sm.get_sessions_on_system_at("WS-01", deadline) == []

    def test_authoritative_end_blocks_implicit_rebootstrap_until_new_session(self):
        """Baseline planners must not silently recreate an explicitly ended session."""

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        deadline = start + timedelta(hours=1)
        logon_id = sm.create_session(
            username="alice",
            system="WS-01",
            logon_type=2,
            source_ip="-",
            start_time=start,
        )
        assert sm.plan_session_end(
            logon_id,
            SessionEndPlan(deadline, "explicit_storyline", "story-logoff"),
        )

        assert not sm.authoritative_session_end_blocks_rebootstrap(
            "alice",
            "WS-01",
            deadline - timedelta(milliseconds=1),
        )
        assert sm.authoritative_session_end_blocks_rebootstrap(
            "alice",
            "WS-01",
            deadline,
        )

        sm.create_session(
            username="alice",
            system="WS-01",
            logon_type=2,
            source_ip="-",
            start_time=deadline + timedelta(minutes=5),
        )
        assert not sm.authoritative_session_end_blocks_rebootstrap(
            "alice",
            "WS-01",
            deadline + timedelta(minutes=6),
        )

    def test_authoritative_end_plan_cannot_be_replaced(self):
        """The first explicit storyline close remains the immutable session authority."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = sm.create_session(
            username="alice",
            system="linux01",
            logon_type=10,
            source_ip="10.0.1.50",
            start_time=start,
            session_kind="ssh",
        )
        first = SessionEndPlan(start + timedelta(hours=1), "explicit_storyline", "first")
        replacement = SessionEndPlan(
            start + timedelta(hours=2),
            "explicit_storyline",
            "replacement",
        )

        assert sm.plan_session_end(logon_id, first)
        assert sm.plan_session_end(logon_id, first)
        with pytest.raises(StateError, match="Cannot replace authoritative"):
            sm.plan_session_end(logon_id, replacement)
        assert sm.get_session_end_plan(logon_id) == first

    def test_action_bundle_end_plan_is_an_immutable_latest_deadline(self):
        """An action-owned fence is immutable without becoming an exact authored end."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = sm.create_session(
            username="alice",
            system="WS-01",
            logon_type=10,
            source_ip="10.0.1.50",
            start_time=start,
            session_kind="rdp",
        )
        deadline = SessionEndPlan(start + timedelta(hours=8), "action_bundle")

        assert deadline.is_hard_deadline
        assert not deadline.is_authoritative
        assert sm.plan_session_end(logon_id, deadline)
        assert sm.plan_session_end(logon_id, deadline)
        with pytest.raises(StateError, match="action-bundle session end plan"):
            sm.plan_session_end(
                logon_id,
                SessionEndPlan(start + timedelta(hours=9), "action_bundle"),
            )
        assert sm.get_session_end_plan(logon_id) == deadline

    def test_linux_logind_session_collision_ids_avoid_elapsed_second_deltas(self):
        """Collision bumps should not recreate an exact session-time delta."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(23)
        event_times = [
            start + timedelta(minutes=37, seconds=offset)
            for offset in (0, 2, 5, 7, 12, 18, 24, 31, 43, 56)
        ]

        ids = [
            sm.next_linux_logind_session_id("linux01", rng, event_time)
            for event_time in event_times
        ]

        assert len(set(ids)) == len(ids)
        allocations = list(zip(event_times, ids, strict=True))
        for (prev_time, prev_id), (next_time, next_id) in pairwise(allocations):
            elapsed_seconds = int((next_time - prev_time).total_seconds())
            assert abs(next_id - prev_id) != elapsed_seconds

    def test_linux_logind_session_ids_use_syslog_visible_seconds(self):
        """Subsecond allocation timestamps should not leak whole-second deltas."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(29)

        first_time = start + timedelta(minutes=37, seconds=39, milliseconds=950)
        second_time = start + timedelta(minutes=37, seconds=51, milliseconds=50)
        first = sm.next_linux_logind_session_id("linux01", rng, first_time)
        second = sm.next_linux_logind_session_id("linux01", rng, second_time)

        visible_elapsed = int(
            (second_time.replace(microsecond=0) - first_time.replace(microsecond=0)).total_seconds()
        )
        assert abs(second - first) != visible_elapsed

    def test_linux_logind_session_ids_preboot_events_remain_monotonic(self):
        """Pre-boot events should still allocate monotonic IDs without collisions."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(17)

        ids = [
            sm.next_linux_logind_session_id("linux01", rng, start - timedelta(hours=2))
            for _ in range(10)
        ]

        assert ids == sorted(ids)
        assert len(set(ids)) == len(ids)

    def test_linux_logind_session_far_future_time_does_not_materialize_blocks(self):
        """Far-future logind IDs should not cache every elapsed four-hour block."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(31)

        session_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(days=1_000_000),
        )

        assert session_id > 0
        assert sm._linux_logind_session_block_offsets == {}

    def test_linux_pid_far_future_block_offset_does_not_materialize_blocks(self):
        """Far-future Linux PID offsets should be direct arithmetic, not catch-up caches."""
        sm = StateManager()

        offset = sm._linux_pid_block_offset("linux01", 1_000_000_000)

        assert offset > 0
        assert not hasattr(sm, "_linux_pid_block_offsets")

    def test_linux_hidden_pid_churn_has_bursty_hourly_regimes(self):
        """Hidden forks should not expose one nearly constant PID-per-second slope."""
        sm = StateManager()
        hourly = [
            sm._linux_pid_hidden_churn_offset("linux01", hour * 3600)
            - sm._linux_pid_hidden_churn_offset("linux01", (hour - 1) * 3600)
            for hour in range(1, 25)
        ]

        assert max(hourly) > min(hourly) * 2
        assert len(set(hourly)) >= 12

    def test_linux_visible_pids_stay_below_pid_max_after_days(self):
        """Ordinary multi-day uptime should retain plausible pre-wrap PID values."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)
        sm.set_current_time(boot_time + timedelta(days=3, hours=2))

        pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/mysql",
            command_line="mysql -u root",
            username="root",
            integrity_level="Medium",
        )

        assert 8_000 <= pid < 700_000

    def test_linux_pids_increase_across_time_bucket_boundary(self):
        """Linux PIDs should not sawtooth downward at five-minute boundaries."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)

        sm.set_current_time(boot_time + timedelta(minutes=4, seconds=59))
        first_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 first.py",
            username="alice",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(minutes=5, seconds=1))
        second_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 second.py",
            username="alice",
            integrity_level="Medium",
        )

        assert second_pid > first_pid

    def test_linux_pids_keep_chronological_shape_when_allocated_out_of_order(self):
        """Out-of-order generation should not make earlier Linux PIDs look newer."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)

        sm.set_current_time(boot_time + timedelta(minutes=5, seconds=1))
        later_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 later.py",
            username="alice",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(minutes=4, seconds=59))
        earlier_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 earlier.py",
            username="alice",
            integrity_level="Medium",
        )

        assert earlier_pid < later_pid

    def test_linux_pid_out_of_order_insertions_preserve_interval_capacity(self):
        """Repeated temporal insertions should not consume an interval edge prematurely."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)
        offsets = (
            timedelta(minutes=32),
            timedelta(minutes=12),
            timedelta(minutes=30),
            timedelta(minutes=31),
            timedelta(minutes=26),
        )

        allocations: dict[timedelta, int] = {}
        for offset in offsets:
            allocations[offset] = sm.allocate_transient_linux_pid(
                "linux01",
                boot_time + offset,
            )

        chronological_pids = [allocations[offset] for offset in sorted(offsets)]
        assert chronological_pids == sorted(chronological_pids)
        assert len(set(chronological_pids)) == len(chronological_pids)

    def test_linux_pid_future_reservation_absorbs_dense_deferred_baseline(self):
        """A preplanned future process leaves room for dense earlier process churn."""

        sm = StateManager()
        boot_time = datetime(2024, 1, 1, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)
        window_start = boot_time + timedelta(days=29)
        future_time = window_start + timedelta(seconds=190)
        allocations = [(future_time, sm.allocate_transient_linux_pid("linux01", future_time))]

        for ordinal in range(250):
            event_time = window_start + timedelta(seconds=(ordinal * 185) / 249)
            allocations.append((event_time, sm.allocate_transient_linux_pid("linux01", event_time)))

        chronological_pids = [pid for _event_time, pid in sorted(allocations)]
        assert chronological_pids == sorted(chronological_pids)
        assert len(set(chronological_pids)) == len(chronological_pids)

    def test_linux_pid_lane_keeps_headroom_for_dense_late_ssh_bootstrap(self):
        """The measured 36-position burst fits even at second 29 of its lane."""

        import random

        sm = StateManager()
        boot_time = datetime(2024, 1, 1, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)
        lane_start = datetime(2024, 2, 1, 23, 14, tzinfo=UTC)
        future_time = lane_start + timedelta(seconds=45)
        future_pid = sm.allocate_transient_linux_pid("linux01", future_time)
        burst_times = [
            lane_start + timedelta(seconds=(29.361347 * ordinal) / 35) for ordinal in range(36)
        ]
        random.Random(31).shuffle(burst_times)

        burst_pids = [
            sm.allocate_transient_linux_pid("linux01", event_time) for event_time in burst_times
        ]

        assert max(burst_pids) < future_pid
        assert len(set(burst_pids)) == len(burst_pids)

    def test_linux_pid_reorder_lane_fails_when_bounded_capacity_is_exhausted(self, monkeypatch):
        """A known later lane must not be crossed to hide excessive earlier churn."""

        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)
        sm.allocate_transient_linux_pid("linux01", boot_time + timedelta(minutes=1))

        monkeypatch.setattr(
            sm,
            "_linux_pid_reorder_lane",
            lambda _system, _epoch, _elapsed: (
                boot_time,
                boot_time + timedelta(seconds=30),
                0,
                1,
            ),
        )
        sm.allocate_transient_linux_pid("linux01", boot_time)

        with pytest.raises(StateError, match="30-second reorder lane capacity exhausted"):
            sm.allocate_transient_linux_pid("linux01", boot_time + timedelta(seconds=1))

    def test_linux_pids_keep_parent_child_shape_before_future_process(self):
        """Earlier parent/child allocations should fit below known future PIDs."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)

        sm.set_current_time(boot_time + timedelta(minutes=5, seconds=1))
        later_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/journalctl",
            command_line="journalctl -p warning",
            username="alice",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(seconds=35))
        parent_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/bin/sh",
            command_line="/bin/sh -c debian-sa1",
            username="sysstat",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(seconds=38))
        child_pid = sm.create_process(
            system="linux01",
            parent_pid=parent_pid,
            image="/usr/lib/sysstat/debian-sa1",
            command_line="debian-sa1 1 1",
            username="sysstat",
            integrity_level="Medium",
        )

        assert parent_pid < child_pid < later_pid

    def test_linux_transient_syslog_pids_share_process_namespace(self):
        """Syslog-only transient PIDs should not come from a separate low random pool."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        event_time = boot_time + timedelta(days=9, hours=4)
        sm.register_boot_time("linux01", boot_time)

        sudo_pid = sm.allocate_transient_linux_pid("linux01", event_time)
        sm.set_current_time(event_time + timedelta(seconds=2))
        ecar_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/journalctl",
            command_line="journalctl -u sshd --since today",
            username="root",
            integrity_level="Medium",
        )
        sshd_pid = sm.allocate_transient_linux_pid(
            "linux01",
            event_time + timedelta(seconds=5),
        )

        assert sudo_pid > 180_000
        assert ecar_pid > 180_000
        assert sshd_pid > 180_000
        assert len({sudo_pid, ecar_pid, sshd_pid}) == 3
        assert max(sudo_pid, ecar_pid, sshd_pid) - min(sudo_pid, ecar_pid, sshd_pid) < 15_000

    def test_linux_pid_collision_work_is_bounded(self, monkeypatch):
        """A growing allocation history must not cause a growing hash retry chain."""
        real_stable_seed = state_manager_module._stable_seed
        stable_seed_calls = 0

        def counted_stable_seed(value: str) -> int:
            nonlocal stable_seed_calls
            stable_seed_calls += 1
            return real_stable_seed(value)

        monkeypatch.setattr(state_manager_module, "_stable_seed", counted_stable_seed)
        sm = StateManager()
        event_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        allocation_count = 5_000

        for _ in range(allocation_count):
            sm.allocate_transient_linux_pid("linux01", event_time)

        assert stable_seed_calls < allocation_count * 3

    def test_linux_pid_allocation_is_repeatable_after_bounded_collision_repair(self):
        """Equivalent runs should allocate identical PIDs, including out-of-order events."""
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        offsets = (
            timedelta(seconds=0),
            timedelta(minutes=20),
            timedelta(minutes=5),
            timedelta(minutes=5, seconds=3),
            timedelta(hours=8),
        )

        def allocate_sequence() -> list[int]:
            sm = StateManager()
            sm.register_boot_time("linux01", boot_time)
            return [
                sm.allocate_transient_linux_pid("linux01", boot_time + offset) for offset in offsets
            ]

        assert allocate_sequence() == allocate_sequence()

    def test_linux_pid_wrap_uses_exclusive_pid_max_boundary(self):
        """Logical Linux progression wraps from pid_max - 1 to the low ring."""
        sm = StateManager()
        event_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", event_time)
        sm._initialize_pid_allocator("linux01", "linux")
        sm._pid_counters["linux01"] = 4_194_300

        pids = [
            sm.allocate_transient_linux_pid(
                "linux01",
                event_time + timedelta(milliseconds=ordinal),
            )
            for ordinal in range(12)
        ]

        assert any(pid > 4_194_250 for pid in pids)
        assert any(500 <= pid < 600 for pid in pids)
        assert 4_194_304 not in pids

    def test_linux_pid_reuses_only_after_exit_and_natural_wrap(self):
        """A wrapped PID is reusable after exit but never while still active."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        sm._pid_counters["linux01"] = 500
        sm.set_current_time(start)
        first_pid = sm.create_process("linux01", 0, "/bin/first", "/bin/first", "root", "System")
        assert first_pid == 500

        second_time = start + timedelta(seconds=1)
        sm._pid_counters["linux01"] = 4_194_304 - sm._linux_pid_hidden_churn_offset("linux01", 1)
        sm.set_current_time(second_time)
        live_collision_pid = sm.create_process(
            "linux01", 0, "/bin/second", "/bin/second", "root", "System"
        )
        assert live_collision_pid != first_pid
        assert live_collision_pid < 1_000

        assert sm.end_process("linux01", first_pid, start + timedelta(seconds=2))
        sm._pid_counters["linux01"] = 8_388_108 - sm._linux_pid_hidden_churn_offset("linux01", 3)
        sm.set_current_time(start + timedelta(seconds=3))
        reused_pid = sm.create_process("linux01", 0, "/bin/third", "/bin/third", "root", "System")
        assert reused_pid == first_pid

    def test_linux_parent_child_can_cross_rendered_pid_wrap(self):
        """Logical parentage remains chronological across a high-to-low render wrap."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        sm._pid_counters["linux01"] = 4_194_303
        sm.set_current_time(start)
        parent_pid = sm.create_process("linux01", 0, "/bin/sh", "/bin/sh", "root", "System")
        sm.set_current_time(start + timedelta(milliseconds=1))
        child_pid = sm.create_process(
            "linux01", parent_pid, "/bin/child", "/bin/child", "root", "System"
        )

        parent = sm.get_process("linux01", parent_pid)
        child = sm.get_process("linux01", child_pid)
        assert parent is not None and child is not None
        assert parent_pid == 4_194_303
        assert child_pid < 1_000
        assert child.pid_logical_position > parent.pid_logical_position

    def test_transient_pid_reservation_expires_before_natural_reuse(self):
        """A transient companion protects its PID only through its final row."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        sm._initialize_pid_allocator("linux01", "linux")
        sm._pid_counters["linux01"] = 500
        first_pid = sm.allocate_transient_linux_pid(
            "linux01", start, release_time=start + timedelta(seconds=1)
        )
        sm._pid_counters["linux01"] = 4_194_304 - sm._linux_pid_hidden_churn_offset("linux01", 2)
        reused_pid = sm.allocate_transient_linux_pid(
            "linux01",
            start + timedelta(seconds=2),
            release_time=start + timedelta(seconds=3),
        )
        assert first_pid == reused_pid == 500

    def test_linux_pid_cannot_reuse_ended_identity_at_overlapping_earlier_time(self):
        """Out-of-order planning must not reuse a PID inside a retained ended lifetime."""
        manager = StateManager()
        later_start = datetime(2024, 3, 18, 14, 19, 16, tzinfo=UTC)
        manager.set_current_time(later_start)
        first_pid = manager.create_process(
            "linux-01",
            0,
            "/usr/lib/apt/methods/https",
            "/usr/lib/apt/methods/https",
            "root",
            "root",
        )
        manager.end_process("linux-01", first_pid, later_start + timedelta(seconds=45))

        manager._pid_counters["linux-01"] = first_pid - 1
        manager.set_current_time(later_start + timedelta(milliseconds=75))
        second_pid = manager.create_process(
            "linux-01",
            0,
            "/usr/lib/apt/methods/http",
            "/usr/lib/apt/methods/http",
            "root",
            "root",
        )

        assert second_pid != first_pid

    def test_pid_watermark_rejects_late_allocation_and_bounds_history(self):
        """Sealed allocation detail cannot grow with simulated duration."""
        sm = StateManager()
        start = datetime(2024, 1, 1, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        retained_sizes: list[tuple[int, int, int]] = []

        for hour in range(24 * 30):
            event_time = start + timedelta(hours=hour, minutes=5)
            for ordinal in range(8):
                sm.allocate_transient_linux_pid(
                    "linux01",
                    event_time + timedelta(seconds=ordinal),
                )
            sm.advance_pid_allocation_watermark(start + timedelta(hours=hour + 1))
            if hour + 1 in {24, 24 * 7, 24 * 30}:
                census = sm.pid_allocator_census()
                retained_sizes.append(
                    (
                        census["open_allocations"],
                        census["open_ordinals"],
                        census["transient_reservations"],
                    )
                )

        assert retained_sizes == [(0, 0, 0), (0, 0, 0), (0, 0, 0)]
        with pytest.raises(StateError, match="sealed allocation watermark"):
            sm.allocate_transient_linux_pid("linux01", start + timedelta(days=10))

    def test_windows_allocator_never_overwrites_live_pid_after_wrap(self):
        """Every Windows candidate checks the live reservation map, not just reset."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        first_pid = sm.create_process("win01", 0, r"C:\first.exe", "first.exe", "SYSTEM", "System")
        sm._pid_counters["win01"] = first_pid
        second_pid = sm.create_process(
            "win01", 0, r"C:\second.exe", "second.exe", "SYSTEM", "System"
        )

        assert second_pid != first_pid
        assert sm.get_process("win01", first_pid).image == r"C:\first.exe"
        assert sm.get_process("win01", second_pid).image == r"C:\second.exe"

    def test_linux_pid_order_survives_dense_out_of_order_transient_allocation(self):
        """Host PID chronology must not depend on generator traversal order."""
        import random

        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        chronological_times = [boot_time + timedelta(seconds=offset * 3) for offset in range(400)]
        allocation_times = list(chronological_times)
        random.Random(17).shuffle(allocation_times)
        sm = StateManager()
        sm.register_boot_time("linux01", boot_time)

        allocations = sorted(
            (
                event_time,
                sm.allocate_transient_linux_pid("linux01", event_time),
            )
            for event_time in allocation_times
        )

        chronological_pids = [pid for _event_time, pid in allocations]
        assert chronological_pids == sorted(chronological_pids)
        assert len(set(chronological_pids)) == len(chronological_pids)

    def test_linux_transient_pid_rejects_non_linux_hosts_before_allocator_init(self):
        """Transient Linux PIDs should not initialize a Windows host namespace."""
        sm = StateManager()
        event_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)

        with pytest.raises(StateError, match="non-Linux host"):
            sm.allocate_transient_linux_pid("win01", event_time, os_category="windows")

        assert "win01" not in sm._pid_os

    def test_linux_transient_pid_rejects_existing_windows_namespace(self):
        """Transient Linux PID calls should not poison an established Windows allocator."""
        sm = StateManager()
        event_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.set_current_time(event_time)
        win_pid = sm.create_process(
            system="win01",
            parent_pid=0,
            image=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe",
            username="SYSTEM",
            integrity_level="System",
        )

        with pytest.raises(StateError, match="non-Linux host"):
            sm.allocate_transient_linux_pid("win01", event_time, os_category="windows")

        with pytest.raises(StateError, match="PID namespace"):
            sm.allocate_transient_linux_pid("win01", event_time)

        next_pid = sm.create_process(
            system="win01",
            parent_pid=0,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe",
            username="SYSTEM",
            integrity_level="System",
        )

        assert win_pid % 4 == 0
        assert next_pid % 4 == 0
        assert sm._pid_os["win01"] == "windows"


class TestSmbState:
    """Canonical SMB runtime identity and bounded-lifecycle behavior."""

    def test_file_identity_version_move_delete_and_recreate(self):
        sm = StateManager()
        now = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        compiled = CompiledStorageFile(
            file_id="file-seed",
            share="FS-01.finance",
            path="Reports\\forecast.xlsx",
            size_bytes=100,
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        touched = sm.touch_smb_file(compiled)
        updated = sm.update_smb_file(touched.file_id, size_bytes=125)
        moved = sm.move_smb_file(
            updated.file_id,
            share="FS-01.finance",
            path="Archive\\forecast.xlsx",
        )
        deleted = sm.delete_smb_file(moved.file_id)
        recreated = sm.create_smb_file(
            share="FS-01.finance",
            path="Reports\\forecast.xlsx",
            size_bytes=90,
            mime_type=compiled.mime_type,
            timestamp=now,
        )

        assert updated.version == 2
        assert moved.file_id == compiled.file_id
        assert moved.prior_paths == ("Reports\\forecast.xlsx",)
        assert deleted.deleted is True
        assert recreated.file_id != compiled.file_id
        assert recreated.version == 1
        assert sm.smb_file_is_available(compiled) is False

    def test_file_mutation_journal_cancel_restores_exact_identity_paths_and_digest(self):
        sm = StateManager()
        now = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        compiled = CompiledStorageFile(
            file_id="file-seed",
            share="FS-01.finance",
            path="Reports\\forecast.xlsx",
            size_bytes=100,
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        original = sm.touch_smb_file(compiled)
        canonical = sm._smb_file_overlay[original.file_id]
        digest_before = sm.materialization_digest()
        version_before = sm.materialization_version

        journal = sm.begin_smb_file_mutation_journal("operation-rollback")
        sm.update_smb_file(original.file_id, size_bytes=125, journal=journal)
        sm.move_smb_file(
            original.file_id,
            share=compiled.share,
            path="Archive\\forecast.xlsx",
            journal=journal,
        )
        sm.move_smb_file(
            original.file_id,
            share=compiled.share,
            path="Archive\\2026\\forecast.xlsx",
            journal=journal,
        )
        created = sm.create_smb_file(
            share=compiled.share,
            path="Scratch\\notes.txt",
            size_bytes=18,
            mime_type="text/plain",
            timestamp=now,
            journal=journal,
        )
        sm.delete_smb_file(created.file_id, journal=journal)

        sm.cancel_smb_file_mutation_journal(journal)

        assert sm._smb_file_overlay[original.file_id] is canonical
        assert canonical.path == compiled.path
        assert canonical.version == 1
        assert canonical.size_bytes == compiled.size_bytes
        assert canonical.deleted is False
        assert canonical.prior_paths == ()
        assert sm._smb_file_by_share_path[
            (compiled.share.casefold(), compiled.path.casefold())
        ] == (original.file_id)
        assert (
            compiled.share.casefold(),
            "archive\\forecast.xlsx".casefold(),
        ) not in sm._smb_file_by_share_path
        assert created.file_id not in sm._smb_file_overlay
        assert sm.materialization_version == version_before
        assert sm.materialization_digest() == digest_before

    def test_file_mutation_journal_recovery_and_exact_capability_validation(self):
        sm = StateManager()
        foreign = StateManager()
        compiled = CompiledStorageFile(
            file_id="file-seed",
            share="FS-01.finance",
            path="Reports\\forecast.xlsx",
            size_bytes=100,
            mime_type="application/octet-stream",
        )
        state = sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal("operation-recover")

        assert sm.begin_smb_file_mutation_journal("operation-recover") is journal
        assert sm.authenticates_smb_file_mutation_journal(journal)
        assert not sm.authenticates_smb_file_mutation_journal(replace(journal))
        assert not foreign.authenticates_smb_file_mutation_journal(journal)

        copied = replace(journal)
        with pytest.raises(StateError, match="stale, copied, or foreign"):
            sm.update_smb_file(state.file_id, size_bytes=200, journal=copied)
        assert state.size_bytes == 100

        tampered = replace(journal)
        object.__setattr__(tampered, "_operation_id", "operation-tampered")
        with pytest.raises(StateError, match="stale, copied, or foreign"):
            sm.update_smb_file(state.file_id, size_bytes=200, journal=tampered)
        assert state.size_bytes == 100

        sm.update_smb_file(state.file_id, size_bytes=200, journal=journal)
        with pytest.raises(StateError, match="mutation in progress"):
            sm.begin_smb_file_mutation_journal("operation-recover")
        with pytest.raises(StateError, match="owned by an active mutation journal"):
            sm.update_smb_file(state.file_id, size_bytes=300)

        result = sm.commit_smb_file_mutation_journal(journal)
        assert sm._smb_file_overlay[state.file_id].size_bytes == 200
        assert not sm.authenticates_smb_file_mutation_journal(journal)
        assert sm.acknowledge_smb_file_mutation_commit(result)
        with pytest.raises(StateError, match="stale, copied, or foreign"):
            sm.cancel_smb_file_mutation_journal(journal)

    def test_file_mutation_journal_bounds_retained_entries(self, monkeypatch):
        monkeypatch.setattr(state_manager_module, "_MAX_SMB_FILE_MUTATION_JOURNAL_ENTRIES", 2)
        sm = StateManager()
        journal = sm.begin_smb_file_mutation_journal("operation-bounded")

        first = sm.create_smb_file(
            share="FS-01.finance",
            path="Scratch\\first.txt",
            size_bytes=1,
            mime_type="text/plain",
            timestamp=datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
            journal=journal,
        )
        with pytest.raises(StateError, match="exceeds 2 retained entries"):
            sm.move_smb_file(
                first.file_id,
                share="FS-01.finance",
                path="Scratch\\second.txt",
                journal=journal,
            )

        sm.cancel_smb_file_mutation_journal(journal)
        assert not sm._smb_file_overlay
        assert not sm._smb_file_by_share_path

    def test_file_mutation_journal_recovery_remains_available_at_capacity(self, monkeypatch):
        monkeypatch.setattr(state_manager_module, "_MAX_ACTIVE_SMB_FILE_MUTATION_JOURNALS", 1)
        sm = StateManager()
        journal = sm.begin_smb_file_mutation_journal("operation-at-capacity")

        assert sm.begin_smb_file_mutation_journal("operation-at-capacity") is journal
        with pytest.raises(StateError, match="active SMB file mutation journals exceed 1"):
            sm.begin_smb_file_mutation_journal("different-operation")

        sm.cancel_smb_file_mutation_journal(journal)

    def test_file_mutation_journal_long_run_releases_all_transient_authority(self):
        sm = StateManager()
        digest_before = sm.materialization_digest()

        for index in range(2_000):
            journal = sm.begin_smb_file_mutation_journal(f"operation-{index}")
            sm.cancel_smb_file_mutation_journal(journal)

        assert sm.materialization_digest() == digest_before
        _assert_no_smb_file_mutation_authority(sm)

    def test_file_mutation_journal_commit_is_exact_recoverable_and_reader_isolated(self):
        """Readers see prestate until one exact retained terminal result linearizes."""

        sm = StateManager()
        foreign = StateManager()
        compiled = CompiledStorageFile(
            file_id="file-reader-isolation",
            share="FS-01.finance",
            path="Reports\\forecast.xlsx",
            size_bytes=100,
            mime_type="application/octet-stream",
        )
        state = sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal("operation-reader-isolation")
        sm.update_smb_file(state.file_id, size_bytes=225, journal=journal)
        sm.move_smb_file(
            state.file_id,
            share=compiled.share,
            path="Archive\\forecast.xlsx",
            journal=journal,
        )

        assert sm.smb_file_is_available(compiled)
        assert sm.smb_file_size(compiled) == 100

        result = sm.commit_smb_file_mutation_journal(journal)

        assert result.operation_id == journal.operation_id
        assert result.file_ids == (compiled.file_id,)
        assert result.path_keys == (
            (compiled.share.casefold(), compiled.path.casefold()),
            (compiled.share.casefold(), "archive\\forecast.xlsx"),
        )
        assert result.postimage_digest
        assert sm.recover_smb_file_mutation_commit(journal) is result
        assert sm.recover_smb_file_mutation_commit(replace(journal)) is None
        assert foreign.recover_smb_file_mutation_commit(journal) is None
        tampered = replace(journal)
        object.__setattr__(tampered, "_operation_id", "operation-retargeted")
        assert sm.recover_smb_file_mutation_commit(tampered) is None
        assert sm.authenticates_smb_file_mutation_commit_receipt(result.receipt)
        assert not sm.authenticates_smb_file_mutation_commit_receipt(replace(result.receipt))
        assert not foreign.authenticates_smb_file_mutation_commit_receipt(result.receipt)
        tampered_receipt = replace(result.receipt)
        object.__setattr__(tampered_receipt, "postimage_digest", "0" * 64)
        assert not sm.authenticates_smb_file_mutation_commit_receipt(tampered_receipt)
        tampered_result = replace(result)
        object.__setattr__(tampered_result, "operation_id", "operation-retargeted")
        assert not sm.acknowledge_smb_file_mutation_commit(tampered_result)
        assert not sm.smb_file_is_available(compiled)
        assert sm.smb_file_size(compiled) == 225
        with pytest.raises(StateError, match="already committed"):
            sm.begin_smb_file_mutation_journal(journal.operation_id)

        assert sm.acknowledge_smb_file_mutation_commit(result)
        assert sm.recover_smb_file_mutation_commit(journal) is None
        assert not sm.authenticates_smb_file_mutation_commit_receipt(result.receipt)
        assert not sm.acknowledge_smb_file_mutation_commit(result)
        assert not sm.acknowledge_smb_file_mutation_commit(replace(result))

    @pytest.mark.parametrize("fault_stage", ("terminal", "ownership"))
    def test_file_mutation_journal_commit_fault_retains_exact_terminal_result(
        self,
        monkeypatch,
        fault_stage,
    ):
        """A lost commit return is operation-recoverable at every release seam."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id=f"file-commit-{fault_stage}",
            share="FS-01.finance",
            path=f"Scratch\\{fault_stage}.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        state = sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal(f"operation-commit-{fault_stage}")
        sm.update_smb_file(state.file_id, size_bytes=20, journal=journal)
        faulted = False

        def fail_once(stage):
            nonlocal faulted
            if stage == fault_stage and not faulted:
                faulted = True
                raise RuntimeError(f"injected {stage}")

        monkeypatch.setattr(sm, "_smb_file_mutation_commit_fault", fail_once)
        with pytest.raises(RuntimeError, match="injected"):
            sm.commit_smb_file_mutation_journal(journal)

        recovered = sm.recover_smb_file_mutation_commit(journal)
        assert recovered is not None
        assert sm.smb_file_size(compiled) == 20
        assert sm.commit_smb_file_mutation_journal(journal) is recovered
        assert sm.acknowledge_smb_file_mutation_commit(recovered)
        _assert_no_smb_file_mutation_authority(sm)

    @pytest.mark.parametrize(
        "fault_stage",
        (
            "ack-record",
            "ack-ownership",
            "ack-capability",
            "ack-acknowledging",
            "ack-result-locator",
            "ack-operation-index",
            "ack-journal-locator",
        ),
    )
    def test_file_mutation_journal_ack_is_restartable(
        self,
        monkeypatch,
        fault_stage,
    ):
        """Interrupted acknowledgement preserves exact result authority until retry."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id=f"file-ack-{fault_stage}",
            share="FS-01.finance",
            path=f"Scratch\\{fault_stage}.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        state = sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal(f"operation-ack-{fault_stage}")
        sm.update_smb_file(state.file_id, size_bytes=20, journal=journal)
        result = sm.commit_smb_file_mutation_journal(journal)
        faulted = False

        def fail_once(stage):
            nonlocal faulted
            if stage == fault_stage and not faulted:
                faulted = True
                raise RuntimeError(f"injected {stage}")

        monkeypatch.setattr(sm, "_smb_file_mutation_commit_fault", fail_once)
        with pytest.raises(RuntimeError, match="injected"):
            sm.acknowledge_smb_file_mutation_commit(result)

        assert sm.recover_smb_file_mutation_commit(journal) is result
        assert sm.authenticates_smb_file_mutation_commit_receipt(result.receipt)
        with pytest.raises(StateError, match="incomplete|already committed"):
            sm.begin_smb_file_mutation_journal(journal.operation_id)
        with pytest.raises(StateError, match="incomplete journal release"):
            sm.update_smb_file(state.file_id, size_bytes=30)
        assert sm.acknowledge_smb_file_mutation_commit(result)
        assert sm.recover_smb_file_mutation_commit(journal) is None
        _assert_no_smb_file_mutation_authority(sm)

    def test_file_mutation_journal_terminal_result_owns_bounded_capacity(self, monkeypatch):
        """An unacknowledged terminal result remains bounded and operation-recoverable."""

        monkeypatch.setattr(state_manager_module, "_MAX_ACTIVE_SMB_FILE_MUTATION_JOURNALS", 1)
        sm = StateManager()
        first = sm.begin_smb_file_mutation_journal("operation-terminal-capacity")
        result = sm.commit_smb_file_mutation_journal(first)

        assert sm.recover_smb_file_mutation_commit(first) is result
        with pytest.raises(StateError, match="already committed"):
            sm.begin_smb_file_mutation_journal(first.operation_id)
        with pytest.raises(StateError, match="journals exceed 1"):
            sm.begin_smb_file_mutation_journal("operation-terminal-blocked")

        assert sm.acknowledge_smb_file_mutation_commit(result)
        replacement = sm.begin_smb_file_mutation_journal("operation-terminal-blocked")
        sm.cancel_smb_file_mutation_journal(replacement)

    def test_file_mutation_terminal_preparation_is_stale_checked_and_single_swap(self):
        """Composite enrollment prebuilds allocations and publishes one terminal pointer."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id="file-terminal-preparation",
            share="FS-01.finance",
            path="Scratch\\terminal-preparation.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        state = sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal("operation-terminal-preparation")
        sm.update_smb_file(state.file_id, size_bytes=20, journal=journal)
        with sm._lock:
            stale = sm._prepare_smb_file_mutation_terminal_locked(journal)

        assert sm.smb_file_size(compiled) == 10
        sm.update_smb_file(state.file_id, size_bytes=30, journal=journal)
        with sm._lock:
            with pytest.raises(StateError, match="postimage changed"):
                sm._validate_smb_file_mutation_terminal_preparation_locked(stale)
            prepared = sm._prepare_smb_file_mutation_terminal_locked(journal)
            sm._validate_smb_file_mutation_terminal_preparation_locked(prepared)
            terminal = sm._install_smb_file_mutation_terminal_no_fail_locked(prepared)

        assert terminal.result.postimage_digest != stale.expected_postimage_digest
        assert sm.smb_file_size(compiled) == 30
        assert sm.commit_smb_file_mutation_journal(journal) is terminal.result
        assert sm.acknowledge_smb_file_mutation_commit(terminal.result)

    @pytest.mark.parametrize(
        "fault_stage",
        (
            "cancel-record",
            "cancel-capability",
            "cancel-ownership",
            "cancel-cancelling",
            "cancel-operation-index",
            "cancel-journal-locator",
        ),
    )
    def test_file_mutation_journal_cancel_release_is_restartable(
        self,
        monkeypatch,
        fault_stage,
    ):
        """Cancellation restores preimages and removes its authority idempotently."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id=f"file-cancel-{fault_stage}",
            share="FS-01.finance",
            path=f"Scratch\\{fault_stage}.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        original = sm.touch_smb_file(compiled)
        canonical = sm._smb_file_overlay[compiled.file_id]
        journal = sm.begin_smb_file_mutation_journal(f"operation-cancel-{fault_stage}")
        sm.update_smb_file(original.file_id, size_bytes=20, journal=journal)
        faulted = False

        def fail_once(stage):
            nonlocal faulted
            if stage == fault_stage and not faulted:
                faulted = True
                raise RuntimeError(f"injected {stage}")

        monkeypatch.setattr(sm, "_smb_file_mutation_commit_fault", fail_once)
        with pytest.raises(RuntimeError, match="injected"):
            sm.cancel_smb_file_mutation_journal(journal)

        with pytest.raises(StateError, match="incomplete|active mutation|identity collision"):
            sm.begin_smb_file_mutation_journal(journal.operation_id)
        with pytest.raises(StateError, match="incomplete journal release"):
            sm.update_smb_file(original.file_id, size_bytes=30)
        sm.cancel_smb_file_mutation_journal(journal)
        assert sm._smb_file_overlay[compiled.file_id] is canonical
        assert canonical.size_bytes == compiled.size_bytes
        _assert_no_smb_file_mutation_authority(sm)

    def test_file_mutation_journal_commit_ack_long_run_releases_terminal_authority(self):
        """Commit/ack churn leaves no retained result, receipt, owner, or operation index."""

        sm = StateManager()
        for index in range(2_000):
            journal = sm.begin_smb_file_mutation_journal(f"operation-commit-ack-{index}")
            result = sm.commit_smb_file_mutation_journal(journal)
            assert sm.acknowledge_smb_file_mutation_commit(result)

        _assert_no_smb_file_mutation_authority(sm)

    def test_file_mutation_views_are_detached_and_cancel_restores_every_field(self):
        """Escaped views cannot mutate canonical state and cancel restores exact preimages."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id="file-detached",
            share="FS-01.finance",
            path="Reports\\detached.txt",
            size_bytes=100,
            mime_type="text/plain",
            tags=("finance",),
        )
        view = sm.touch_smb_file(compiled)
        canonical = sm._smb_file_overlay[compiled.file_id]
        digest_before = sm.materialization_digest()

        view.file_id = "escaped-file-id"
        view.size_bytes = 999
        view.tags = ["escaped"]  # type: ignore[assignment]
        view.prior_paths = ["escaped"]  # type: ignore[assignment]

        assert canonical.file_id == compiled.file_id
        assert canonical.size_bytes == compiled.size_bytes
        assert canonical.tags == compiled.tags
        assert sm.materialization_digest() == digest_before

        journal = sm.begin_smb_file_mutation_journal("operation-detached-restore")
        updated = sm.update_smb_file(compiled.file_id, size_bytes=225, journal=journal)
        assert updated is not canonical
        canonical.file_id = "tampered-canonical-id"
        canonical.tags = ["tampered"]  # type: ignore[assignment]
        canonical.prior_paths = ["tampered"]  # type: ignore[assignment]

        sm.cancel_smb_file_mutation_journal(journal)

        assert sm._smb_file_overlay[compiled.file_id] is canonical
        assert canonical.file_id == compiled.file_id
        assert canonical.size_bytes == compiled.size_bytes
        assert canonical.tags == compiled.tags
        assert canonical.prior_paths == ()
        assert sm.materialization_digest() == digest_before
        _assert_no_smb_file_mutation_authority(sm)

    def test_created_file_identity_collision_rejects_without_overwrite(self):
        """A retained deterministic identity cannot be replaced after path deletion."""

        sm = StateManager()
        timestamp = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
        created = sm.create_smb_file(
            share="FS-01.finance",
            path="Scratch\\collision.txt",
            size_bytes=10,
            mime_type="text/plain",
            timestamp=timestamp,
        )
        canonical = sm._smb_file_overlay[created.file_id]
        sm.delete_smb_file(created.file_id)
        digest = sm.materialization_digest()

        with pytest.raises(StateError, match="identity collision"):
            sm.create_smb_file(
                share="FS-01.finance",
                path="Scratch\\collision.txt",
                size_bytes=20,
                mime_type="text/plain",
                timestamp=timestamp,
            )

        assert sm._smb_file_overlay[created.file_id] is canonical
        assert canonical.deleted
        assert sm.materialization_digest() == digest

    @pytest.mark.parametrize("fault_stage", ("terminal", "ownership"))
    def test_lost_commit_recovers_after_exact_journal_tamper(
        self,
        monkeypatch,
        fault_stage,
    ):
        """Trusted exact-object recovery survives a lost return and public token tamper."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id=f"file-lost-tamper-{fault_stage}",
            share="FS-01.finance",
            path=f"Scratch\\lost-tamper-{fault_stage}.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal(f"operation-lost-tamper-{fault_stage}")
        sm.update_smb_file(compiled.file_id, size_bytes=20, journal=journal)
        faulted = False

        def fail_once(stage):
            nonlocal faulted
            if stage == fault_stage and not faulted:
                faulted = True
                raise RuntimeError(f"injected {stage}")

        monkeypatch.setattr(sm, "_smb_file_mutation_commit_fault", fail_once)
        with pytest.raises(RuntimeError, match="injected"):
            sm.commit_smb_file_mutation_journal(journal)
        object.__setattr__(journal, "_journal_id", "0" * 64)

        assert not sm.authenticates_smb_file_mutation_journal(journal)
        recovered = sm.recover_smb_file_mutation_commit(journal)
        assert recovered is not None
        assert sm.acknowledge_smb_file_mutation_commit(recovered)
        _assert_no_smb_file_mutation_authority(sm)

    def test_exact_terminal_result_tamper_can_still_be_acknowledged(self):
        """Public result/receipt corruption fails authentication but cannot leak authority."""

        sm = StateManager()
        journal = sm.begin_smb_file_mutation_journal("operation-result-tamper")
        result = sm.commit_smb_file_mutation_journal(journal)
        object.__setattr__(result, "operation_id", "operation-retargeted")
        object.__setattr__(result.receipt, "postimage_digest", "0" * 64)

        assert sm.recover_smb_file_mutation_commit(journal) is None
        assert not sm.authenticates_smb_file_mutation_commit_receipt(result.receipt)
        assert sm.acknowledge_smb_file_mutation_commit(result)
        _assert_no_smb_file_mutation_authority(sm)

    @pytest.mark.parametrize(
        "fault_stage",
        (
            "ack-acknowledging",
            "ack-result-locator",
            "ack-operation-index",
            "ack-journal-locator",
        ),
    )
    def test_mid_ack_exact_result_tamper_does_not_break_retry(
        self,
        monkeypatch,
        fault_stage,
    ):
        """Every late acknowledgement seam retains trusted cleanup authority."""

        sm = StateManager()
        operation_id = f"operation-mid-ack-tamper-{fault_stage}"
        journal = sm.begin_smb_file_mutation_journal(operation_id)
        result = sm.commit_smb_file_mutation_journal(journal)
        faulted = False

        def fail_once(stage):
            nonlocal faulted
            if stage == fault_stage and not faulted:
                faulted = True
                raise RuntimeError(f"injected {stage}")

        monkeypatch.setattr(sm, "_smb_file_mutation_commit_fault", fail_once)
        with pytest.raises(RuntimeError, match="injected"):
            sm.acknowledge_smb_file_mutation_commit(result)
        with pytest.raises(StateError, match="incomplete"):
            sm.begin_smb_file_mutation_journal(operation_id)
        object.__setattr__(result, "operation_id", "operation-tampered")
        object.__setattr__(result.receipt, "postimage_digest", "f" * 64)

        assert sm.acknowledge_smb_file_mutation_commit(result)
        _assert_no_smb_file_mutation_authority(sm)
        replacement = sm.begin_smb_file_mutation_journal(operation_id)
        sm.cancel_smb_file_mutation_journal(replacement)

    @pytest.mark.parametrize(
        "fault_stage",
        ("cancel-cancelling", "cancel-operation-index", "cancel-journal-locator"),
    )
    def test_mid_cancel_exact_journal_tamper_does_not_break_retry(
        self,
        monkeypatch,
        fault_stage,
    ):
        """Every late cancellation seam keeps the old operation generation fenced."""

        sm = StateManager()
        operation_id = f"operation-mid-cancel-tamper-{fault_stage}"
        journal = sm.begin_smb_file_mutation_journal(operation_id)
        faulted = False

        def fail_once(stage):
            nonlocal faulted
            if stage == fault_stage and not faulted:
                faulted = True
                raise RuntimeError(f"injected {stage}")

        monkeypatch.setattr(sm, "_smb_file_mutation_commit_fault", fail_once)
        with pytest.raises(RuntimeError, match="injected"):
            sm.cancel_smb_file_mutation_journal(journal)
        with pytest.raises(StateError, match="incomplete"):
            sm.begin_smb_file_mutation_journal(operation_id)
        object.__setattr__(journal, "_operation_id", "operation-tampered")

        sm.cancel_smb_file_mutation_journal(journal)
        _assert_no_smb_file_mutation_authority(sm)
        replacement = sm.begin_smb_file_mutation_journal(operation_id)
        sm.cancel_smb_file_mutation_journal(replacement)

    def test_reserved_terminal_capacity_survives_full_byte_cap(self, monkeypatch):
        """An admitted journal terminalizes at its exact cap while new work fails cleanly."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id="file-terminal-byte-reservation",
            share="FS-01.finance",
            path="Scratch\\terminal-byte-reservation.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal("operation-terminal-byte-reservation")
        sm.update_smb_file(compiled.file_id, size_bytes=20, journal=journal)
        exact_retained_bytes = sm.get_state_summary()["smb_file_mutation_retained_bytes"]
        monkeypatch.setattr(
            state_manager_module,
            "_MAX_RETAINED_SMB_FILE_MUTATION_BYTES",
            exact_retained_bytes,
        )

        with pytest.raises(StateError, match="retained SMB file mutation authority exceeds"):
            sm.begin_smb_file_mutation_journal("operation-byte-cap-blocked")
        result = sm.commit_smb_file_mutation_journal(journal)
        assert sm.recover_smb_file_mutation_commit(journal) is result
        assert sm.get_state_summary()["smb_file_mutation_retained_bytes"] == exact_retained_bytes
        assert sm.acknowledge_smb_file_mutation_commit(result)
        _assert_no_smb_file_mutation_authority(sm)

    def test_smb_file_numeric_bounds_reject_huge_values_without_journal_drift(self):
        """Arbitrary-precision file values cannot poison an admitted journal terminal."""

        sm = StateManager()
        compiled = CompiledStorageFile(
            file_id="file-numeric-bound",
            share="FS-01.finance",
            path="Scratch\\numeric-bound.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        original = sm.touch_smb_file(compiled)
        journal = sm.begin_smb_file_mutation_journal("operation-numeric-bound")
        summary_before = sm.get_state_summary()

        with pytest.raises(StateError, match="size exceeds the 63-bit SMB file bound"):
            sm.update_smb_file(
                original.file_id,
                size_bytes=1 << 100_000,
                journal=journal,
            )

        assert sm._smb_file_overlay[original.file_id].size_bytes == 10
        assert sm.get_state_summary() == summary_before
        assert sm.authenticates_smb_file_mutation_journal(journal)
        result = sm.commit_smb_file_mutation_journal(journal)
        assert sm.acknowledge_smb_file_mutation_commit(result)
        _assert_no_smb_file_mutation_authority(sm)

    def test_smb_file_numeric_bounds_cover_touch_create_update_and_version_overflow(self):
        """Every file ingress enforces fixed-width integers before canonical mutation."""

        sm = StateManager()
        huge = 1 << 100_000
        now = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

        huge_size = CompiledStorageFile(
            file_id="file-huge-size",
            share="FS-01.finance",
            path="Scratch\\huge-size.txt",
            size_bytes=huge,
            mime_type="text/plain",
        )
        with pytest.raises(StateError, match="size exceeds the 63-bit SMB file bound"):
            sm.touch_smb_file(huge_size)

        huge_version = CompiledStorageFile(
            file_id="file-huge-version",
            share="FS-01.finance",
            path="Scratch\\huge-version.txt",
            version=huge,
            size_bytes=1,
            mime_type="text/plain",
        )
        with pytest.raises(StateError, match="version exceeds the 63-bit SMB file bound"):
            sm.touch_smb_file(huge_version)

        with pytest.raises(StateError, match="size exceeds the 63-bit SMB file bound"):
            sm.create_smb_file(
                share="FS-01.finance",
                path="Scratch\\huge-create.txt",
                size_bytes=huge,
                mime_type="text/plain",
                timestamp=now,
            )

        maximum = state_manager_module._MAX_SMB_FILE_SIZE_BYTES
        assert maximum == state_manager_module._MAX_SMB_FILE_VERSION
        boundary = CompiledStorageFile(
            file_id="file-version-boundary",
            share="FS-01.finance",
            path="Scratch\\version-boundary.txt",
            version=maximum - 1,
            size_bytes=maximum,
            mime_type="text/plain",
        )
        touched = sm.touch_smb_file(boundary)
        with pytest.raises(StateError, match="size exceeds the 63-bit SMB file bound"):
            sm.update_smb_file(touched.file_id, size_bytes=huge)
        assert sm._smb_file_overlay[touched.file_id].version == maximum - 1
        assert sm._smb_file_overlay[touched.file_id].size_bytes == maximum

        journal = sm.begin_smb_file_mutation_journal("operation-numeric-boundary")
        updated = sm.update_smb_file(touched.file_id, size_bytes=maximum, journal=journal)
        assert updated.version == maximum
        assert updated.size_bytes == maximum
        result = sm.commit_smb_file_mutation_journal(journal)
        assert sm.recover_smb_file_mutation_commit(journal) is result
        assert sm.acknowledge_smb_file_mutation_commit(result)
        with pytest.raises(StateError, match="version cannot advance beyond"):
            sm.update_smb_file(touched.file_id, size_bytes=1)

        assert sm._smb_file_overlay[touched.file_id].version == maximum
        assert sm._smb_file_overlay[touched.file_id].size_bytes == maximum
        assert set(sm._smb_file_overlay) == {touched.file_id}
        _assert_no_smb_file_mutation_authority(sm)

    def test_compiled_file_callbacks_run_before_the_state_lock(self):
        """Caller-controlled container iteration cannot re-enter while State is locked."""

        sm = StateManager()
        callback_lock_states: list[bool] = []
        callback_time = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

        class HostileTags:
            def __iter__(self):
                callback_lock_states.append(sm._lock._is_owned())
                sm.set_current_time(callback_time)
                yield "detached-before-lock"

        compiled = CompiledStorageFile(
            file_id="file-callback-boundary",
            share="FS-01.finance",
            path="Scratch\\callback-boundary.txt",
            size_bytes=10,
            mime_type="text/plain",
        )
        compiled.__dict__["tags"] = HostileTags()

        state = sm.touch_smb_file(compiled)

        assert callback_lock_states == [False]
        assert sm.state.current_time == callback_time
        assert state.tags == ("detached-before-lock",)

        class HostileFile:
            @property
            def file_id(self):
                raise AssertionError("unsupported file getters must not run")

        with pytest.raises(StateError, match="exact compiled storage file"):
            sm.smb_file_is_available(HostileFile())  # type: ignore[arg-type]

    def test_compiled_file_tag_detachment_stops_at_the_exact_tuple_bound(self):
        """Tampered catalog iterables are consumed only through the bounded prefix."""

        sm = StateManager()
        yielded = 0
        callback_lock_states: list[bool] = []

        class OversizedTags:
            def __iter__(self):
                nonlocal yielded
                for _index in range(10_000):
                    yielded += 1
                    callback_lock_states.append(sm._lock._is_owned())
                    yield "tag"

        compiled = CompiledStorageFile(
            file_id="file-tag-bound",
            share="FS-01.finance",
            path="Scratch\\tag-bound.txt",
            size_bytes=1,
            mime_type="text/plain",
        )
        compiled.__dict__["tags"] = OversizedTags()

        with pytest.raises(StateError, match="tags exceed the retained tuple bound"):
            sm.touch_smb_file(compiled)

        assert yielded == state_manager_module._MAX_SMB_FILE_TAGS + 1
        assert callback_lock_states == [False] * yielded
        assert not sm._smb_file_overlay
        _assert_no_smb_file_mutation_authority(sm)

    def test_oversized_smb_text_is_rejected_before_state_admission(
        self,
        monkeypatch,
    ):
        """Huge exact strings fail by character count before entering the State lane."""

        sm = StateManager()
        admission_called = False

        def unexpected_admission(_operation, *, admitted_at=None):
            nonlocal admission_called
            admission_called = True
            return 0

        monkeypatch.setattr(
            sm,
            "_reject_mutation_during_action_cohort_claim",
            unexpected_admission,
        )
        with pytest.raises(StateError, match="exceeds 1024 retained UTF-8 bytes"):
            sm.create_smb_file(
                share="x" * 1_025,
                path="Scratch\\oversized.txt",
                size_bytes=1,
                mime_type="text/plain",
                timestamp=datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
            )
        with pytest.raises(StateError, match="nonempty bounded string"):
            sm.begin_smb_file_mutation_journal(" " * 100_000)

        assert not admission_called


class TestSessionManagement:
    """Tests for session lifecycle."""

    def test_historical_session_queries_do_not_scan_global_state(self):
        """User/system history lookups must use secondary indexes."""

        class NoIterationDict(dict):
            def values(self):
                raise AssertionError("global values() scan is forbidden")

            def items(self):
                raise AssertionError("global items() scan is forbidden")

            def __iter__(self):
                raise AssertionError("global key iteration is forbidden")

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        target_logon_id = ""
        for index in range(2_000):
            username = "target" if index == 1_337 else f"user-{index % 41}"
            system = "target-host" if index == 1_337 else f"host-{index % 29}"
            logon_id = sm.create_session(
                username=username,
                system=system,
                logon_type=3,
                source_ip="10.0.0.1",
                start_time=start + timedelta(seconds=index),
            )
            assert sm.end_session(logon_id, start + timedelta(hours=2))
            if index == 1_337:
                target_logon_id = logon_id

        sm._active_sessions._items = NoIterationDict(sm._active_sessions._items)
        sm._ended_sessions._items = NoIterationDict(sm._ended_sessions._items)
        cutoff = start + timedelta(minutes=30)

        assert [session.logon_id for session in sm.get_sessions_for_user_at("target", cutoff)] == [
            target_logon_id
        ]
        assert [
            session.logon_id for session in sm.get_sessions_on_system_at("target-host", cutoff)
        ] == [target_logon_id]

    def test_create_session(self):
        """Test creating a new session."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        logon_id = sm.create_session(
            username="jdoe",
            system="WS-01",
            logon_type=2,
            source_ip="192.168.1.50",
        )

        assert logon_id.startswith("0x")
        assert 0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF
        session = sm.get_session(logon_id)
        assert session is not None
        assert session.username == "jdoe"
        assert session.system == "WS-01"
        assert session.logon_type == 2
        assert session.source_ip == "192.168.1.50"
        assert session.session_id > 0
        assert sm.get_session_id(logon_id) == session.session_id

    def test_windows_session_ids_are_canonical_and_collision_safe(self):
        """Overlapping Windows interactive sessions should not hash-collide by LogonID."""
        sm = StateManager()
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(base)

        console = sm.create_session(
            "aisha.johnson",
            "WS-AJOHNSON-01",
            2,
            "-",
            session_kind="interactive",
        )
        rdp = sm.create_session(
            "aisha.johnson",
            "WS-AJOHNSON-01",
            10,
            "10.10.1.10",
            session_kind="rdp",
            start_time=base + timedelta(minutes=5),
        )
        network = sm.create_session(
            "aisha.johnson",
            "WS-AJOHNSON-01",
            3,
            "10.10.1.20",
            session_kind="network",
            start_time=base + timedelta(minutes=6),
        )

        console_session_id = sm.get_session_id(console)
        rdp_session_id = sm.get_session_id(rdp)

        assert console_session_id > 0
        assert rdp_session_id > 0
        assert console_session_id != rdp_session_id
        assert sm.get_session_id(network) == 0

    @pytest.mark.parametrize("logon_type", [3, 4, 5, 7, 8, 9])
    def test_non_desktop_windows_logons_do_not_allocate_terminal_session_ids(self, logon_type):
        """Only desktop-capable logons own Windows terminal session IDs."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, tzinfo=UTC))

        logon_id = sm.create_session(
            "jdoe",
            "WS-01",
            logon_type,
            "-" if logon_type in {4, 5, 7, 9} else "192.0.2.10",
            session_kind="new_credentials" if logon_type == 9 else "logon",
        )

        assert sm.get_session_id(logon_id) == 0

    @pytest.mark.parametrize("logon_type", [2, 10, 11])
    def test_desktop_windows_logons_allocate_terminal_session_ids(self, logon_type):
        """Interactive, RDP, and cached-interactive logons retain desktop IDs."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, tzinfo=UTC))

        logon_id = sm.create_session("jdoe", "WS-01", logon_type, "-")

        assert sm.get_session_id(logon_id) > 0

    def test_ssh_sessions_do_not_get_windows_session_ids(self):
        """Linux SSH-style sessions should not consume Windows terminal IDs."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ssh = sm.create_session(
            "marcus.chen",
            "DB-PROD-01",
            10,
            "10.10.1.10",
            session_kind="ssh",
        )

        assert sm.get_session_id(ssh) == 0

    def test_create_session_uses_host_local_monotonic_luids(self):
        """New LogonIDs on one host should follow source-native LUID ordering."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)

        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        id1 = sm.create_session("user1", "WS-01", 2, "192.168.1.1")
        sm.set_current_time(datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC))
        id2 = sm.create_session("user2", "WS-01", 3, "192.168.1.2")
        sm.set_current_time(datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC))
        id3 = sm.create_session("user3", "WS-01", 3, "192.168.1.3")

        assert int(id1, 16) < int(id2, 16) < int(id3, 16)

    def test_create_session_luids_do_not_encode_elapsed_seconds(self):
        """LUID gaps should not expose a fixed wall-clock stride."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)

        first = sm.create_session(
            "user1",
            "WS-01",
            2,
            "192.168.1.1",
            start_time=datetime(2024, 1, 15, 12, 3, 37, 27_000, tzinfo=UTC),
        )
        second = sm.create_session(
            "user2",
            "WS-01",
            3,
            "192.168.1.2",
            start_time=datetime(2024, 1, 15, 12, 9, 6, 698_000, tzinfo=UTC),
        )

        diff = int(second, 16) - int(first, 16)
        assert diff > 0
        assert diff != 329 * 4096
        assert diff < 329 * 512

    def test_create_session_varies_low_luid_nibble(self):
        """Generated LogonIDs should not all expose a fixed trailing hex digit."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [sm.create_session(f"user{i}", "WS-01", 3, f"192.168.1.{i}") for i in range(12)]

        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in ids)
        assert len({int(logon_id, 16) & 0xF for logon_id in ids}) > 1
        assert ids == [f"0x{value:x}" for value in sorted(int(logon_id, 16) for logon_id in ids)]

    def test_session_logon_guid_is_stable_per_logon_id(self):
        """Session LogonGuid should be canonical state, not per-emitter derivation."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        logon_id = sm.create_session("jdoe", "WS-01", 3, "192.168.1.50")

        guid_a = sm.get_or_create_session_logon_guid(logon_id, "WS-01")
        guid_b = sm.get_or_create_session_logon_guid(logon_id, "WS-01")
        session = sm.get_session(logon_id)

        assert guid_a == guid_b
        assert session is not None
        assert session.logon_guid == guid_a
        assert guid_a != "{00000000-0000-0000-0000-000000000000}"

    def test_session_logon_guid_nullability_is_immutable(self):
        """Later consumers cannot upgrade a published null LogonGuid for one LogonID."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        logon_id = sm.create_session("jdoe", "WS-01", 3, "192.168.1.50")

        null_guid = sm.get_or_create_session_logon_guid(
            logon_id,
            "WS-01",
            require_nonzero=False,
        )
        later = sm.get_or_create_session_logon_guid(
            logon_id,
            "WS-01",
            require_nonzero=True,
        )

        assert null_guid == "{00000000-0000-0000-0000-000000000000}"
        assert later == null_guid
        with pytest.raises(StateError, match="Cannot replace published session LogonGuid"):
            sm.update_session_metadata(
                logon_id,
                logon_guid="{11111111-2222-4333-8444-555555555555}",
            )

    def test_create_session_can_finalize_logon_guid_policy_before_publication(self):
        """Session creation can seal nullability before any dependent process exists."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        null_id = sm.create_session(
            "service",
            "WS-01",
            5,
            "-",
            logon_guid_required=False,
        )
        nonnull_id = sm.create_session(
            "jdoe",
            "WS-01",
            2,
            "-",
            logon_guid_required=True,
        )

        assert sm.get_session(null_id).logon_guid == "{00000000-0000-0000-0000-000000000000}"
        assert sm.get_session(nonnull_id).logon_guid != "{00000000-0000-0000-0000-000000000000}"

    def test_generated_logon_guids_use_uuid4_morphology(self):
        """Deterministic LogonGuid values should use normal RFC variant/version nibbles."""
        sm = StateManager()

        guids = [
            sm.get_or_create_session_logon_guid(f"0x{value:x}", "WS-01") for value in range(32)
        ]
        version_nibbles = {guid[15] for guid in guids}
        variant_nibbles = {guid[20] for guid in guids}

        assert all(guid.startswith("{") and guid.endswith("}") for guid in guids)
        assert version_nibbles == {"4"}
        assert variant_nibbles <= {"8", "9", "a", "b"}
        assert len(variant_nibbles) > 1

    def test_create_session_uses_explicit_start_time_for_luid(self):
        """Explicit session start time should drive LogonID order despite stale state time."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC))

        later = sm.create_session(
            "svc-late",
            "WS-01",
            5,
            "-",
            start_time=datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC),
        )
        earlier = sm.create_session(
            "svc-early",
            "WS-01",
            5,
            "-",
            start_time=datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC),
        )

        assert int(earlier, 16) < int(later, 16)
        assert sm.get_session(earlier).start_time == datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC)
        assert sm.get_session(later).start_time == datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)

    def test_allocate_logon_id_uses_event_time_without_session(self):
        """Standalone 4624 records should use the same boot-relative LUID model."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC))

        later = sm.allocate_logon_id("DC-01", datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC))
        earlier = sm.allocate_logon_id("DC-01", datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC))

        assert int(earlier, 16) < int(later, 16)
        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in (earlier, later))
        assert sm.get_session(earlier) is None
        assert sm.get_session(later) is None

    def test_allocate_logon_id_preserves_subsecond_event_time_order(self):
        """Out-of-order same-second allocation should still sort by event timestamp."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)

        later = sm.allocate_logon_id("DC-01", datetime(2024, 1, 15, 10, 1, 0, 700000, UTC))
        earlier = sm.allocate_logon_id(
            "DC-01",
            datetime(2024, 1, 15, 10, 1, 0, 100000, UTC),
        )

        assert int(earlier, 16) < int(later, 16)

    def test_allocate_logon_id_far_future_time_does_not_materialize_blocks(self):
        """Far-future Windows LogonIDs should not cache every elapsed minute block."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)

        logon_id = sm.allocate_logon_id("DC-01", boot + timedelta(days=1_000_000))

        assert 0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF
        assert sm._logon_id_block_offsets == {}

    def test_reassign_session_logon_id_rekeys_session_to_event_time(self):
        """Planned sessions can be re-keyed once final source-native logon time is known."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 15, 39, 4, tzinfo=UTC))
        original = sm.create_session("aisha.johnson", "DC-01", 10, "10.10.1.35")

        intervening = sm.allocate_logon_id(
            "DC-01",
            datetime(2024, 1, 15, 15, 39, 5, 397056, UTC),
        )
        reassigned = sm.reassign_session_logon_id(
            original,
            datetime(2024, 1, 15, 15, 39, 9, 751464, UTC),
        )

        assert reassigned is not None
        assert sm.state.active_sessions.get(original) is None
        session = sm.get_session(reassigned)
        assert session is not None
        assert sm.get_session(original) is session
        assert session.start_time == datetime(2024, 1, 15, 15, 39, 9, 751464, UTC)
        assert int(reassigned, 16) > int(intervening, 16)
        assert sm.get_session_id(original) == session.session_id
        assert sm.get_session_id(reassigned) == session.session_id

    def test_create_session_keeps_host_ranges_unique(self):
        """Host-local LUID sequences should not collide in global state."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [sm.create_session(f"user{i}", f"WS-{i:02d}", 3, f"192.168.1.{i}") for i in range(20)]

        assert len(set(ids)) == len(ids)

    def test_semantic_peer_ordinals_are_scoped_by_stable_action_key(self):
        """Unrelated peer allocation must not renumber attempts in another action."""

        sm = StateManager()

        assert sm.next_semantic_peer_ordinal("failed_logon", "action-a") == 0
        assert sm.next_semantic_peer_ordinal("failed_logon", "action-b") == 0
        assert sm.next_semantic_peer_ordinal("failed_logon", "action-a") == 1
        assert StateManager().next_semantic_peer_ordinal("failed_logon", "action-a") == 0

    def test_create_session_supports_more_than_legacy_host_bucket_count(self):
        """Large scenarios should not exhaust Windows LogonID host ranges."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [
            sm.create_session(f"user{i}", f"WS-{i:03d}", 3, f"192.168.{i // 255}.{i % 255}")
            for i in range(300)
        ]

        assert len(ids) == 300
        assert len(set(ids)) == len(ids)
        assert len(sm._logon_id_host_bases) == 300
        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in ids)

    def test_create_session_probes_unbounded_host_bucket_collision_layers(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Host bucket collisions should probe alternate offsets without failing."""
        monkeypatch.setattr(state_manager_module, "_stable_seed", lambda _key: 7)
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [sm.create_session(f"user{i}", f"WS-{i:03d}", 3, f"192.168.1.{i}") for i in range(3)]

        assert len(set(ids)) == 3
        assert len(set(sm._logon_id_host_bases.values())) == 3
        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in ids)

    def test_register_session_marks_external_logon_id_used(self):
        """Externally registered sessions should reserve their LogonID value."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        sm.register_session(
            logon_id="0x123456",
            username="external",
            system="WS-01",
            logon_type=3,
            source_ip="192.168.1.10",
            start_time=start,
        )

        assert int("0x123456", 16) in sm._used_logon_ids

    def test_register_session_rejects_reuse_of_ended_logon_id(self):
        """One canonical LogonID cannot identify two complete session lifecycles."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_session(
            logon_id="0x123456",
            username="alice",
            system="LNX-01",
            logon_type=2,
            source_ip="-",
            start_time=start,
            session_kind="interactive",
            session_id=41,
        )
        assert sm.end_session("0x123456", start + timedelta(minutes=5))

        with pytest.raises(StateError, match="ended LogonID"):
            sm.register_session(
                logon_id="0x123456",
                username="alice",
                system="LNX-01",
                logon_type=2,
                source_ip="-",
                start_time=start + timedelta(minutes=10),
                session_kind="interactive",
                session_id=42,
            )

    def test_session_id_can_be_assigned_once_but_not_replaced(self):
        """Bundle-owned assignment may fill zero but published identity is immutable."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        session = sm.register_session(
            logon_id="0x123456",
            username="alice",
            system="LNX-01",
            logon_type=10,
            source_ip="192.0.2.10",
            start_time=start,
            session_kind="ssh",
            session_id=0,
        )

        assert sm.update_session_metadata(session.logon_id, session_id=41)
        assert sm.update_session_metadata(session.logon_id, session_id=41)
        with pytest.raises(StateError, match="Cannot replace published session ID"):
            sm.update_session_metadata(session.logon_id, session_id=42)

    def test_create_session_requires_current_time(self):
        """Test that creating session fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")

    def test_get_sessions_for_user(self):
        """Test getting all sessions for a user."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_session("jdoe", "WS-02", 3, "192.168.1.1")
        sm.create_session("asmith", "WS-03", 2, "192.168.1.2")

        jdoe_sessions = sm.get_sessions_for_user("jdoe")
        assert len(jdoe_sessions) == 2
        assert all(s.username == "jdoe" for s in jdoe_sessions)

    def test_get_sessions_on_system(self):
        """Test getting all sessions on a system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_session("asmith", "WS-01", 3, "192.168.1.2")
        sm.create_session("bsmith", "WS-02", 2, "192.168.1.3")

        ws01_sessions = sm.get_sessions_on_system("WS-01")
        assert len(ws01_sessions) == 2
        assert all(s.system == "WS-01" for s in ws01_sessions)

    def test_end_session(self):
        """Test ending a session."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        logon_id = sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        assert sm.get_session(logon_id) is not None
        object_id = sm.get_session_object_id(logon_id)

        result = sm.end_session(logon_id)
        assert result is True
        assert sm.get_session(logon_id) is None
        assert sm.get_session_object_id(logon_id) == object_id

    def test_end_nonexistent_session(self):
        """Test ending a non-existent session returns False."""
        sm = StateManager()
        result = sm.end_session("0xnonexistent")
        assert result is False

    def test_list_active_sessions(self):
        """Test listing all active sessions."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_session("user1", "WS-01", 2, "192.168.1.1")
        sm.create_session("user2", "WS-02", 3, "192.168.1.2")

        sessions = sm.list_active_sessions()
        assert len(sessions) == 2


class TestCanonicalIdentityState:
    """Tests for host-scoped process, session, and thread identity."""

    @staticmethod
    def _create_windows_process(sm: StateManager, system: str, pid: int = 4000) -> int:
        sm._pid_counters[system] = pid
        sm._pid_os[system] = "windows"
        return sm.create_process(
            system,
            0,
            rf"C:\\Windows\\System32\\{system}.exe",
            f"{system}.exe",
            "SYSTEM",
            "System",
        )

    def test_identical_pid_and_tid_on_different_hosts_do_not_collide(self) -> None:
        """Host and process object scope identical host-local numeric identifiers."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        pid_a = self._create_windows_process(sm, "WS-01")
        pid_b = self._create_windows_process(sm, "WS-02")
        process_a = sm.get_process_identity("WS-01", pid_a)
        process_b = sm.get_process_identity("WS-02", pid_b)
        assert process_a is not None
        assert process_b is not None
        assert pid_a == pid_b
        assert process_a.object_id != process_b.object_id

        thread_a = sm.create_thread("WS-01", process_a.object_id, tid=9124)
        thread_b = sm.create_thread("WS-02", process_b.object_id, tid=9124)
        assert thread_a.tid == thread_b.tid
        assert thread_a.canonical_key != thread_b.canonical_key
        assert thread_a.object_id != thread_b.object_id

    def test_same_host_pid_reuse_gets_new_process_and_thread_identity(self) -> None:
        """A reused PID starts a new object scope even when a TID also repeats."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        first_pid = self._create_windows_process(sm, "WS-01")
        first = sm.get_process_identity("WS-01", first_pid)
        assert first is not None
        first_thread = sm.create_thread("WS-01", first.object_id, tid=9912)
        assert sm.end_process("WS-01", first_pid, start + timedelta(seconds=2))

        sm.set_current_time(start + timedelta(minutes=1))
        sm._pid_counters["WS-01"] = first_pid
        second_pid = sm.create_process(
            "WS-01",
            0,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe /c whoami",
            "analyst",
            "Medium",
        )
        second = sm.get_process_identity("WS-01", second_pid)
        assert second is not None
        second_thread = sm.create_thread("WS-01", second.object_id, tid=9912)

        assert second_pid == first_pid
        assert second.object_id != first.object_id
        assert second_thread.canonical_key != first_thread.canonical_key
        assert sm.get_thread("WS-01", first.object_id, 9912) is None
        assert sm.get_thread("WS-01", second.object_id, 9912) == second_thread

    def test_primary_thread_is_deterministic_and_immutable(self) -> None:
        """Primary-thread allocation is stable and snapshots cannot mutate runtime state."""
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        snapshots = []
        for _ in range(2):
            sm = StateManager()
            sm.set_current_time(start)
            pid = self._create_windows_process(sm, "WS-01")
            process = sm.get_process_identity("WS-01", pid)
            assert process is not None
            assert process.primary_thread is not None
            snapshots.append(process)

        assert snapshots[0] == snapshots[1]
        with pytest.raises(FrozenInstanceError):
            snapshots[0].primary_thread.tid = 1234

    def test_linux_primary_thread_is_process_leader(self) -> None:
        """Linux process leaders use the kernel's TID-equals-PID convention."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        pid = sm.create_process("LINUX-01", 0, "/usr/bin/bash", "bash", "analyst", "Medium")
        process = sm.get_process_identity("LINUX-01", pid)
        assert process is not None
        assert process.primary_thread is not None
        assert process.primary_thread.tid == pid

    @pytest.mark.parametrize(
        ("system", "pid", "image", "os_category"),
        [
            ("WS-01", 4, "System", "windows"),
            ("LINUX-01", 1, "/usr/lib/systemd/systemd", "linux"),
        ],
    )
    def test_fixed_boot_process_registration_uses_canonical_identity_boundary(
        self,
        system: str,
        pid: int,
        image: str,
        os_category: str,
    ) -> None:
        """Kernel-native fixed PIDs receive object, lifecycle, and primary-thread state."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        process = sm.register_process(
            system,
            pid,
            0,
            image,
            image,
            "SYSTEM" if os_category == "windows" else "root",
            "System",
            os_category=os_category,
        )
        identity = sm.get_process_identity(system, pid)

        assert identity is not None
        assert identity.object_id == process.ecar_object_id
        assert identity.lifecycle_group_id == process.lifecycle_group_id
        assert identity.primary_thread is not None
        if os_category == "linux":
            assert identity.primary_thread.tid == pid

    def test_explicit_thread_requires_live_owning_process(self) -> None:
        """Worker and remote threads cannot outlive or bypass their owning process."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        pid = self._create_windows_process(sm, "WS-01")
        process = sm.get_process_identity("WS-01", pid)
        assert process is not None
        assert sm.end_process("WS-01", pid, start + timedelta(seconds=1))

        with pytest.raises(StateError, match="owning process object is not live"):
            sm.create_thread("WS-01", process.object_id, tid=7000, kind="remote")

    def test_ended_identity_indexes_plateau_across_45_days(self) -> None:
        """Late-reference indexes retain 48 hours, not all elapsed process history."""

        sm = StateManager()
        start = datetime(2024, 1, 1, tzinfo=UTC)
        first_object_id = ""
        latest_object_id = ""

        for hour in range(45 * 24):
            event_time = start + timedelta(hours=hour)
            sm.set_current_time(event_time)
            pid = sm.create_process(
                system="WS-01",
                parent_pid=0,
                image=r"C:\Windows\System32\cmd.exe",
                command_line=f"cmd.exe /c echo {hour}",
                username="analyst",
                integrity_level="Medium",
            )
            identity = sm.get_process_identity("WS-01", pid)
            assert identity is not None
            first_object_id = first_object_id or identity.object_id
            latest_object_id = identity.object_id
            sm.end_process("WS-01", pid, event_time + timedelta(seconds=1))

        assert len(sm._ended_processes_by_object_id) <= 49
        assert len(sm._ended_processes_by_key) <= 49
        assert len(sm._ended_threads) <= 49
        assert sm.get_process_identity_by_object_id(first_object_id) is None
        assert sm.get_process_identity_by_object_id(latest_object_id) is not None


class TestProcessManagement:
    """Tests for process lifecycle."""

    def test_create_process(self):
        """Test creating a new process."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        pid = sm.create_process(
            system="WS-01",
            parent_pid=0,
            image="C:\\Windows\\System32\\explorer.exe",
            command_line="explorer.exe",
            username="jdoe",
            integrity_level="Medium",
        )

        # Phase 6.0: PIDs are now OS-aware (multiples of 4 for Windows, starting in realistic range)
        assert pid >= 2000  # Windows PIDs start in realistic range
        assert pid % 4 == 0  # Windows PIDs are multiples of 4
        process = sm.get_process("WS-01", pid)
        assert process is not None
        assert process.system == "WS-01"
        assert process.image == "C:\\Windows\\System32\\explorer.exe"
        assert process.username == "jdoe"

    def test_create_process_increments_per_system(self):
        """Test that PIDs increment per system with OS-aware allocation."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        # Windows path → multiples of 4
        pid1 = sm.create_process(
            "WS-01", 0, r"C:\Windows\explorer.exe", "explorer.exe", "jdoe", "Medium"
        )
        pid2 = sm.create_process("WS-01", 0, r"C:\Windows\cmd.exe", "cmd.exe", "jdoe", "Medium")
        # Linux path → sequential
        pid3 = sm.create_process("WS-02", 0, "/usr/bin/bash", "bash", "asmith", "Medium")

        assert pid1 % 4 == 0  # Windows: multiple of 4
        assert pid2 % 4 == 0  # Windows: multiple of 4
        assert pid2 > pid1  # Incrementing
        assert pid3 >= 500  # Linux: starts in realistic range

    def test_create_process_requires_current_time(self):
        """Test that creating process fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

    def test_create_process_validates_parent_exists(self):
        """Test that creating process fails if parent doesn't exist."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        with pytest.raises(StateError, match="parent PID .* does not exist"):
            sm.create_process("WS-01", 999, "cmd.exe", "cmd.exe", "jdoe", "Medium")

    def test_create_process_allows_parent_zero(self):
        """Test that parent_pid=0 is allowed (system processes)."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        pid = sm.create_process("WS-01", 0, "System", "System", "SYSTEM", "System")
        assert pid > 0  # PID allocated successfully

    def test_create_process_with_valid_parent(self):
        """Test creating child process with valid parent."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        parent_pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        child_pid = sm.create_process("WS-01", parent_pid, "cmd.exe", "cmd.exe", "jdoe", "Medium")

        assert child_pid > parent_pid
        child = sm.get_process("WS-01", child_pid)
        assert child.parent_pid == parent_pid

    def test_get_processes_for_user(self):
        """Test getting all processes for a user."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "notepad.exe", "notepad.exe", "asmith", "Medium")

        jdoe_procs = sm.get_processes_for_user("jdoe")
        assert len(jdoe_procs) == 2
        assert all(p.username == "jdoe" for p in jdoe_procs)

    def test_get_processes_on_system(self):
        """Test getting all processes on a system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "asmith", "Medium")
        sm.create_process("WS-02", 0, "bash", "bash", "jdoe", "Medium")

        ws01_procs = sm.get_processes_on_system("WS-01")
        assert len(ws01_procs) == 2
        assert all(p.system == "WS-01" for p in ws01_procs)

    def test_get_processes_for_session_uses_logon_index(self, monkeypatch):
        """Session process lookup must not enumerate the global process table."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        wanted_pid = sm.create_process(
            "WS-01",
            0,
            "explorer.exe",
            "explorer.exe",
            "jdoe",
            "Medium",
            "0x111",
        )
        sm.create_process(
            "WS-02",
            0,
            "bash",
            "bash",
            "asmith",
            "Medium",
            "0x222",
        )
        monkeypatch.setattr(
            sm,
            "list_running_processes",
            lambda: pytest.fail("global process enumeration is not allowed"),
        )

        processes = sm.get_processes_for_session("0x111", "WS-01")

        assert [process.pid for process in processes] == [wanted_pid]
        assert sm.end_process("WS-01", wanted_pid)
        assert sm.get_processes_for_session("0x111", "WS-01") == []

    def test_end_process(self):
        """Test ending a process."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        assert sm.get_process("WS-01", pid) is not None

        result = sm.end_process("WS-01", pid)
        assert result is True
        assert sm.get_process("WS-01", pid) is None

    def test_end_nonexistent_process(self):
        """Test ending non-existent process returns False."""
        sm = StateManager()
        result = sm.end_process("WS-01", 999)
        assert result is False

    def test_end_process_clears_active_session_process_references(self):
        """Ended processes should not remain as live session parent pointers."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        logon_id = sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        session = sm.get_session(logon_id)
        assert session is not None

        winlogon_pid = sm.create_process(
            "WS-01",
            4,
            r"C:\Windows\System32\winlogon.exe",
            "winlogon.exe",
            "SYSTEM",
            "System",
            logon_id,
        )
        explorer_pid = sm.create_process(
            "WS-01",
            winlogon_pid,
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            "jdoe",
            "Medium",
            logon_id,
        )
        shell_pid = sm.create_process(
            "WS-01",
            explorer_pid,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe",
            "jdoe",
            "Medium",
            logon_id,
        )
        transport_pid = sm.create_process(
            "WS-01",
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k netsvcs",
            "SYSTEM",
            "System",
            logon_id,
        )
        explorer_object_id = sm.get_process_object_id("WS-01", explorer_pid)

        session.session_winlogon_pid = winlogon_pid
        session.process_tree_root = winlogon_pid
        session.explorer_pid = explorer_pid
        session.session_shell_pid = shell_pid
        session.transport_pid = transport_pid

        assert sm.end_process("WS-01", explorer_pid) is True
        assert session.explorer_pid is None
        assert sm.get_process_object_id("WS-01", explorer_pid) == explorer_object_id

        assert sm.end_process("WS-01", winlogon_pid) is True
        assert session.session_winlogon_pid is None
        assert session.process_tree_root is None

        assert sm.end_process("WS-01", shell_pid) is True
        assert session.session_shell_pid is None

        assert sm.end_process("WS-01", transport_pid) is True
        assert session.transport_pid is None

    def test_update_process_activity_time_keeps_latest(self):
        """Process activity marker should track the latest dependent event."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

        assert sm.update_process_activity_time("WS-01", pid, start + timedelta(minutes=5))
        assert sm.update_process_activity_time("WS-01", pid, start + timedelta(minutes=2))
        proc = sm.get_process("WS-01", pid)

        assert proc is not None
        assert proc.last_activity_time == start + timedelta(minutes=5)

    def test_assign_process_to_session_refreshes_session_index(self):
        """Late-bound responder ownership should be visible to session closure."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        logon_id = sm.create_session(
            username="deploy",
            system="linux01",
            logon_type=10,
            source_ip="10.0.10.50",
        )
        pid = sm.create_process(
            "linux01",
            0,
            "/usr/sbin/sshd",
            "sshd: deploy [priv]",
            "root",
            "root",
        )

        assert sm.assign_process_to_session("linux01", pid, logon_id)
        assigned = sm.get_processes_for_session(logon_id)
        assert [proc.pid for proc in assigned] == [pid]
        assert assigned[0].logon_id == logon_id
        assert assigned[0].token_logon_id == ""

    def test_published_process_auth_identity_is_immutable_across_session_membership(self):
        """Session teardown membership cannot replace a process token identity."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        logon_id = sm.create_session("deploy", "linux01", 10, "10.0.10.50")
        pid = sm.create_process(
            "linux01",
            0,
            "/usr/sbin/sshd",
            "sshd: deploy [priv]",
            "root",
            "System",
            "0x3e7",
        )

        assert sm.publish_process_auth_identity(
            "linux01", pid, logon_id="0x3e7", session_id=0, logon_type=0
        )
        assert sm.assign_process_to_session("linux01", pid, logon_id)
        process = sm.get_process("linux01", pid)
        assert process is not None
        assert process.logon_id == logon_id
        assert process.token_logon_id == "0x3e7"
        assert process.auth_session_id == 0

        with pytest.raises(StateError, match="Cannot replace published process"):
            sm.publish_process_auth_identity(
                "linux01", pid, logon_id=logon_id, session_id=77, logon_type=10
            )

    def test_update_session_activity_time_keeps_latest(self):
        """Session activity marker should track the latest dependent event."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        logon_id = sm.create_session(
            username="jdoe",
            system="WS-01",
            logon_type=2,
            source_ip="-",
        )

        assert sm.update_session_activity_time(logon_id, start + timedelta(minutes=5))
        assert sm.update_session_activity_time(logon_id, start + timedelta(minutes=2))
        session = sm.get_session(logon_id)

        assert session is not None
        assert session.last_activity_time == start + timedelta(minutes=5)

    def test_apply_tracks_process_dependent_activity_time(self):
        """Any process-owned event should extend the process lifecycle marker."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_time = start + timedelta(minutes=3)
        sm.set_current_time(start)
        pid = sm.create_process("WS-01", 0, "proc.exe", "proc.exe", "jdoe", "Medium")

        sm.apply(
            OccurrenceBuilder(
                timestamp=activity_time,
                event_type="process_access",
                src_host=HostContext(
                    hostname="WS-01",
                    ip="10.0.0.10",
                    os="Windows 11",
                    os_category="windows",
                    system_type="workstation",
                ),
                process=ProcessContext(
                    pid=pid,
                    parent_pid=0,
                    image="proc.exe",
                    command_line="proc.exe",
                    username="jdoe",
                ),
            )
        )

        proc = sm.get_process("WS-01", pid)
        assert proc is not None
        assert proc.last_activity_time == activity_time

    def test_apply_tracks_canonical_actor_activity_without_process_context(self):
        """Canonical network actors extend lifetime without a compatibility process context."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_time = start + timedelta(minutes=3)
        sm.set_current_time(start)
        pid = sm.create_process("WS-01", 0, "browser.exe", "browser.exe", "jdoe", "Medium")
        actor = sm.get_process_identity("WS-01", pid)
        assert actor is not None

        sm.apply(
            OccurrenceBuilder(
                timestamp=activity_time,
                event_type="connection",
                identity_plan=EventIdentityPlan(actor=actor),
            )
        )

        proc = sm.get_process("WS-01", pid)
        assert proc is not None
        assert proc.last_activity_time == activity_time

    def test_list_running_processes(self):
        """Test listing all running processes."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-02", 0, "bash", "bash", "asmith", "Medium")

        procs = sm.list_running_processes()
        assert len(procs) == 2


def _final_connection_transaction(
    *,
    conn_id: str,
    zeek_uid: str,
) -> NetworkTransactionPlan:
    started_at = datetime(2026, 8, 16, 13, 0, tzinfo=UTC)
    closed_at = started_at + timedelta(seconds=1.25)
    return NetworkTransactionPlan(
        stable_id="network-transaction-atomic",
        hostname="WS-01",
        outcome="success",
        phase_times=(("transport_start", started_at), ("transport_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=50_001,
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol="tcp",
        service="https",
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=1.25,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=120, packets=2, ip_bytes=200),
            resp=DirectionalTrafficLedger(payload_bytes=480, packets=3, ip_bytes=600),
        ),
    )


def test_connection_materialization_plan_cancel_commit_and_retry_are_atomic() -> None:
    """Final connection truth and both allocator streams publish exactly once."""

    manager = StateManager()
    rng = random.Random(42)
    digest_before = manager.materialization_digest()
    rng_before = rng.getstate()
    identity = manager.plan_connection_identity(rng)
    continuation = identity.continuation_rng()
    continuation.random()  # representative protocol texture after UID allocation
    transaction = _final_connection_transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
    )
    plan = manager.finalize_connection_materialization(
        identity,
        transaction,
        continuation_rng=continuation,
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="example.test",
        initiating_pid=4242,
    )

    assert manager.materialization_digest() == digest_before
    assert rng.getstate() == rng_before
    with manager.prepared_connection_materialization(plan, rng):
        pass
    assert manager.materialization_digest() == digest_before
    assert rng.getstate() == rng_before

    with manager.prepared_connection_materialization(plan, rng) as prepared:
        connection = prepared.commit()
    assert connection is not None
    assert connection.conn_id == identity.conn_id
    assert connection.zeek_uid == identity.zeek_uid
    assert connection.transaction_id == transaction.stable_id
    assert connection.start_time == transaction.started_at
    assert connection.close_time == transaction.closed_at
    assert connection.traffic_ledger == transaction.traffic
    assert connection.bytes_sent == transaction.orig_bytes
    assert connection.bytes_received == transaction.resp_bytes
    assert rng.getstate() == continuation.getstate()

    committed_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="stale before commit"):
        manager.materialize_connection(plan, rng)
    assert manager.materialization_digest() == committed_digest


class TestConnectionManagement:
    """Tests for connection lifecycle."""

    def test_open_connection(self):
        """Test opening a new connection."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        conn_id = sm.open_connection(
            src_ip="192.168.1.100",
            src_port=50000,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
        )

        assert conn_id == "conn-0"
        conn = sm.get_connection(conn_id)
        assert conn is not None
        assert conn.src_ip == "192.168.1.100"
        assert conn.dst_ip == "8.8.8.8"
        assert conn.protocol == "udp"
        assert conn.state == "established"

    def test_open_connection_increments_counter(self):
        """Test that connection IDs increment."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        id1 = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        id2 = sm.open_connection("192.168.1.1", 50001, "8.8.4.4", 53, "udp")

        assert id1 == "conn-0"
        assert id2 == "conn-1"

    def test_open_connection_requires_current_time(self):
        """Test that opening connection fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")

    def test_update_connection_bytes(self):
        """Test updating connection byte counts."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        conn_id = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        result = sm.update_connection_bytes(conn_id, 1024, 2048)

        assert result is True
        conn = sm.get_connection(conn_id)
        assert conn.bytes_sent == 1024
        assert conn.bytes_received == 2048

    def test_update_nonexistent_connection(self):
        """Test updating non-existent connection returns False."""
        sm = StateManager()
        result = sm.update_connection_bytes("conn-999", 1024, 2048)
        assert result is False

    def test_close_connection(self):
        """Test closing a connection."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        conn_id = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        assert sm.get_connection(conn_id) is not None

        result = sm.close_connection(conn_id)
        assert result is True
        assert sm.get_connection(conn_id) is None

    def test_close_nonexistent_connection(self):
        """Test closing non-existent connection returns False."""
        sm = StateManager()
        result = sm.close_connection("conn-999")
        assert result is False

    def test_connection_tuple_lookup_uses_exact_tuple_index(self):
        """Tuple lookup must not scan every retained connection."""

        class NoValuesDict(dict):
            def values(self):
                raise AssertionError("connection tuple lookup performed a full-table scan")

        sm = StateManager()
        now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(now)
        sm.open_connection("10.0.0.10", 50000, "10.0.0.1", 53, "udp")
        sm.open_connection("::ffff:10.0.0.20", 50001, "10.0.0.2", 443, "tcp")
        sm._open_connections._items = NoValuesDict(sm._open_connections._items)

        assert sm.connection_tuple_recently_used(
            "10.0.0.20",
            50001,
            "::ffff:10.0.0.2",
            443,
            "tcp",
            now,
            reuse_window=86_400,
        )
        assert not sm.connection_tuple_recently_used(
            "10.0.0.99",
            59999,
            "10.0.0.2",
            443,
            "tcp",
            now,
            reuse_window=86_400,
        )

    def test_close_connection_removes_tuple_index_entry(self):
        """Closing a connection should remove its tuple lookup entry."""
        sm = StateManager()
        now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(now)
        conn_id = sm.open_connection("10.0.0.10", 50000, "10.0.0.1", 53, "udp")

        assert sm.close_connection(conn_id)
        assert not sm.connection_tuple_recently_used(
            "10.0.0.10",
            50000,
            "10.0.0.1",
            53,
            "udp",
            now,
            reuse_window=86_400,
        )
        assert (
            sm._open_connections.find_keys(
                "exact_tuple",
                ("10.0.0.10", 50000, "10.0.0.1", 53, "udp"),
            )
            == ()
        )

    def test_sweep_removes_connections_closed_by_cutoff(self):
        """Past close times should be evicted even when state remains established."""
        sm = StateManager()
        now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(now)
        past_id = sm.open_connection(
            "10.0.0.10",
            50000,
            "10.0.0.1",
            53,
            "udp",
            close_time=now + timedelta(minutes=5),
        )
        future_id = sm.open_connection(
            "10.0.0.10",
            50001,
            "10.0.0.2",
            443,
            "tcp",
            close_time=now + timedelta(hours=2),
        )

        removed = sm.sweep_closed_connections(now + timedelta(hours=1))

        assert removed == 1
        assert sm.get_connection(past_id) is None
        assert sm.get_connection(future_id) is not None
        assert past_id not in sm._open_connections

    def test_list_open_connections(self):
        """Test listing all open connections."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        sm.open_connection("192.168.1.2", 50001, "8.8.4.4", 53, "udp")

        conns = sm.list_open_connections()
        assert len(conns) == 2


class TestDNSManagement:
    """Tests for DNS cache."""

    def test_register_hostname(self):
        """Test registering a hostname."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")

        ip = sm.resolve_hostname("google.com")
        assert ip == "8.8.8.8"

    def test_register_duplicate_hostname_same_ip(self):
        """Test registering same hostname with same IP is allowed."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")
        sm.register_hostname("google.com", "8.8.8.8")  # Should not raise

        ip = sm.resolve_hostname("google.com")
        assert ip == "8.8.8.8"

    def test_register_duplicate_hostname_different_ip(self):
        """Test registering same hostname with different IP raises error."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")

        with pytest.raises(StateError, match="already mapped to"):
            sm.register_hostname("google.com", "8.8.4.4")

    def test_resolve_nonexistent_hostname(self):
        """Test resolving non-existent hostname returns None."""
        sm = StateManager()
        ip = sm.resolve_hostname("nonexistent.com")
        assert ip is None

    def test_list_dns_cache(self):
        """Test listing all DNS cache entries."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")
        sm.register_hostname("cloudflare.com", "1.1.1.1")

        cache = sm.list_dns_cache()
        assert len(cache) == 2
        assert cache["google.com"] == "8.8.8.8"
        assert cache["cloudflare.com"] == "1.1.1.1"


class TestTimeManagement:
    """Tests for time tracking."""

    def test_set_current_time(self):
        """Test setting current time."""
        sm = StateManager()
        dt = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        sm.set_current_time(dt)
        assert sm.get_current_time() == dt

    def test_advance_time(self):
        """Test advancing time by delta."""
        sm = StateManager()
        dt = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(dt)

        sm.advance_time(timedelta(hours=1))
        assert sm.get_current_time() == datetime(2024, 1, 15, 11, 0, 0, tzinfo=UTC)

    def test_advance_time_requires_current_time(self):
        """Test that advancing time fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.advance_time(timedelta(hours=1))


class TestStateQueries:
    """Tests for state query methods."""

    def test_get_state(self):
        """Test getting complete state."""
        sm = StateManager()
        state = sm.get_state()
        assert state is sm.state

    def test_get_state_summary(self):
        """Test getting state summary."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

        summary = sm.get_state_summary()
        assert summary["active_sessions"] == 1
        assert summary["running_processes"] == 1
        assert summary["open_connections"] == 0
        assert summary["dns_cache_entries"] == 0
        assert "2024-01-15" in summary["current_time"]
