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

"""Tests for RDP background noise in baseline generation."""

import ast
import inspect
import random
import tempfile
import textwrap
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from evidenceforge.generation.actions.rdp_session import (
    RDP_EXPLICIT_END_CLOSE_GAP_MAX_MILLISECONDS,
    RDP_TRANSPORT_DURATION_MAX_SECONDS,
)
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.engine.baseline import (
    BaselineMixin,
    _baseline_success_port_for_target,
    _baseline_success_target_for_guarded_port,
    _BaselineRdpIntent,
)
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel, WorldPlanner
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import (
    BaselineActivity,
    CredentialSprayEventSpec,
    Environment,
    LogonEventSpec,
    OutputSpec,
    RdpSessionEventSpec,
    Scenario,
    StorageConfig,
    StorageServerConfig,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)


def _make_scenario(systems: list[System], *, duration: str = "2h") -> Scenario:
    """Create a minimal test scenario with given systems."""
    return Scenario(
        name="rdp-test",
        description="Test RDP baseline noise",
        environment=Environment(
            description="Test environment",
            users=[
                User(
                    username="admin.user",
                    full_name="Admin User",
                    email="admin@corp.com",
                    persona="sysadmin",
                ),
            ],
            systems=systems,
        ),
        time_window=TimeWindow(
            start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            duration=duration,
        ),
        baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
        output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
    )


class TestRDPBaselineNoise:
    """Verify that baseline generates RDP admin connections to Windows servers."""

    def test_only_explicit_session_paths_can_create_baseline_or_storyline_rdp(self):
        """Generic baseline and non-session authored paths must name a non-RDP kind."""

        for owner in (BaselineMixin, StorylineMixin):
            tree = ast.parse(textwrap.dedent(inspect.getsource(owner)))
            ensure_calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "ensure_user_session"
            ]
            assert ensure_calls
            assert all(
                any(keyword.arg == "session_kind" for keyword in node.keywords)
                for node in ensure_calls
            )

        baseline_tree = ast.parse(textwrap.dedent(inspect.getsource(BaselineMixin)))
        baseline_calls = [node for node in ast.walk(baseline_tree) if isinstance(node, ast.Call)]
        assert not any(
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"generate_rdp_session", "_execute_rdp_session_bundle"}
            for node in baseline_calls
        )
        assert not any(
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "generate_logon"
            and any(
                keyword.arg == "logon_type"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == 10
                for keyword in node.keywords
            )
            for node in baseline_calls
        )
        assert (
            sum(
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "_prepare_rdp_session_bootstrap"
                for node in baseline_calls
            )
            == 1
        )
        assert (
            sum(
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "_bootstrap_prepared_rdp_session"
                for node in baseline_calls
            )
            == 1
        )

        for executor in (
            StorylineMixin._execute_storyline,
            StorylineMixin._execute_single_storyline_event,
            StorylineMixin._execute_single_red_herring_event,
        ):
            executor_tree = ast.parse(textwrap.dedent(inspect.getsource(executor)))
            assert (
                sum(
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_shift_authored_rdp_child_after_frontier"
                    for node in ast.walk(executor_tree)
                )
                == 1
            )
            typed_calls = [
                node
                for node in ast.walk(executor_tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_execute_typed_event"
            ]
            assert typed_calls
            if executor is StorylineMixin._execute_storyline:
                assert "authored_time_shift" in inspect.getsource(executor)
            else:
                assert all(
                    any(keyword.arg == "authored_time_shift" for keyword in node.keywords)
                    for node in typed_calls
                )

        storyline_plan_tree = ast.parse(
            textwrap.dedent(inspect.getsource(StorylineMixin._storyline_non_session_kind))
        )
        assert (
            sum(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "plan_session"
                for node in ast.walk(storyline_plan_tree)
            )
            == 1
        )

        activity_tree = ast.parse(
            textwrap.dedent(inspect.getsource(ActivityGenerator.execute_baseline_activity))
        )
        choice_populations = [
            node.args[0]
            for node in ast.walk(activity_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "choices"
            and node.args
            and isinstance(node.args[0], ast.List)
        ]
        assert choice_populations
        assert all(
            not any(
                isinstance(element, ast.Constant) and element.value == 10
                for element in population.elts
            )
            for population in choice_populations
        )

        windows_server = System(
            hostname="WIN-SRV",
            ip="10.10.20.10",
            os="Windows Server 2022",
            type="server",
        )
        linux_server = System(
            hostname="LINUX-SRV",
            ip="10.10.20.20",
            os="Ubuntu 24.04",
            type="server",
        )
        assert BaselineMixin._baseline_generic_session_kind(windows_server) == "interactive"
        assert BaselineMixin._baseline_generic_session_kind(linux_server) == "ssh"

        class _PlanningWorld:
            def plan_session(self, *, rng, **_kwargs):
                rng.random()
                return SimpleNamespace(session_kind="rdp")

        candidate_rng = random.Random(91)
        control_rng = random.Random(91)
        control_rng.random()
        storyline_harness = SimpleNamespace(world_model=_PlanningWorld())

        assert (
            StorylineMixin._storyline_non_session_kind(
                storyline_harness,
                User(username="admin", full_name="Admin", email="admin@corp.com"),
                windows_server,
                candidate_rng,
            )
            == "interactive"
        )
        assert candidate_rng.random() == control_rng.random()

    def test_cross_target_rdp_sort_uses_real_bootstrap_anchor(self):
        """Close outer requests must execute by the planner's actual RDP anchor."""

        source = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        first_target = System(
            hostname="APP-01",
            ip="10.10.20.10",
            os="Windows Server 2022",
            type="server",
        )
        second_target = System(
            hostname="DB-01",
            ip="10.10.20.20",
            os="Windows Server 2022",
            type="server",
        )
        user = User(
            username="admin.user",
            full_name="Admin User",
            email="admin@corp.com",
            persona="sysadmin",
        )
        scenario = _make_scenario([source, first_target, second_target])
        state_manager = StateManager()
        activity_generator = Mock()
        actual_requests: list[dict[str, object]] = []

        def execute_rdp_session_bundle(**kwargs):
            actual_requests.append(kwargs)
            logon_id = state_manager.create_session(
                username=kwargs["user"].username,
                system=kwargs["target_system"].hostname,
                logon_type=10,
                source_ip=kwargs["source_ip"],
                session_kind="rdp",
                start_time=kwargs["time"],
            )
            return f"uid-{len(actual_requests)}", logon_id

        activity_generator._execute_rdp_session_bundle.side_effect = execute_rdp_session_bundle
        planner = WorldPlanner(
            WorldModel(scenario, "corp.local"), state_manager, activity_generator
        )
        activity_time = datetime(2024, 1, 15, 10, 15, tzinfo=UTC)
        future_source_session_time = activity_time + timedelta(seconds=5)
        state_manager.set_current_time(future_source_session_time)
        state_manager.create_session(
            username=user.username,
            system=source.hostname,
            logon_type=2,
            source_ip=source.ip,
            session_kind="interactive",
            start_time=future_source_session_time,
        )
        planning_rng = random.Random(0)
        first_plan = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=first_target,
            time=activity_time,
            rng=planning_rng,
            source_system=source,
        )
        second_plan = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=second_target,
            time=activity_time + timedelta(seconds=1),
            rng=planning_rng,
            source_system=source,
        )
        assert first_plan.transport_time > second_plan.transport_time
        requests = (
            _BaselineRdpIntent(activity_time, first_target, user, source, first_plan),
            _BaselineRdpIntent(
                activity_time + timedelta(seconds=1),
                second_target,
                user,
                source,
                second_plan,
            ),
        )
        harness = SimpleNamespace(
            state_manager=state_manager,
            world_planner=planner,
            _baseline_rdp_cooldown_allows=Mock(return_value=True),
            _remember_baseline_rdp_session=Mock(),
        )

        observed_state_times: list[datetime] = []
        original_set_current_time = state_manager.set_current_time

        def track_state_time(value: datetime) -> None:
            observed_state_times.append(value)
            original_set_current_time(value)

        with patch.object(state_manager, "set_current_time", side_effect=track_state_time):
            BaselineMixin._execute_baseline_rdp_requests(harness, requests, random.Random(999))

        expected_plans = sorted((first_plan, second_plan), key=lambda plan: plan.transport_time)
        assert [request["target_system"].hostname for request in actual_requests] == [
            plan.session_plan.target_system.hostname for plan in expected_plans
        ]
        assert [request["time"] for request in actual_requests] == [
            plan.transport_time for plan in expected_plans
        ]
        assert [request["source_process_time"] for request in actual_requests] == [
            plan.source_process_time for plan in expected_plans
        ]
        assert observed_state_times == sorted(observed_state_times)
        cooldown_times = [
            entry.kwargs["planned_time"]
            for entry in harness._baseline_rdp_cooldown_allows.call_args_list
        ]
        assert cooldown_times == [plan.transport_time for plan in expected_plans]

    def test_application_retention_does_not_reverse_rdp_lifecycle_frontier(self):
        """Lagging shared retention must preserve the strict RDP action frontier."""

        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 11", type="workstation"),
            System(
                hostname="SRV-01",
                ip="10.10.20.10",
                os="Windows Server 2022",
                type="server",
            ),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()
            action_frontier = datetime(2024, 1, 15, 10, 20, tzinfo=UTC)
            engine.activity_generator.advance_rdp_session_lifecycle_watermark(action_frontier)

            with (
                patch.object(
                    engine.activity_generator.rdp_session_manager,
                    "watermark",
                    wraps=engine.activity_generator.rdp_session_manager.watermark,
                ) as rdp_manager_watermark,
                patch.object(
                    engine.activity_generator._application_channel_registry,
                    "watermark",
                    wraps=engine.activity_generator._application_channel_registry.watermark,
                ) as application_registry_watermark,
            ):
                engine.activity_generator.advance_application_channel_watermark(
                    action_frontier - timedelta(hours=24)
                )

            assert engine.activity_generator._rdp_lifecycle_watermark == action_frontier
            manager_cutoffs = [entry.args[0] for entry in rdp_manager_watermark.call_args_list]
            registry_cutoffs = [
                entry.args[0] for entry in application_registry_watermark.call_args_list
            ]
            assert manager_cutoffs
            assert manager_cutoffs == registry_cutoffs

    def test_two_real_hours_keep_baseline_and_close_authored_rdp_monotonic(self):
        """Hourly composition consumes frozen baseline RDP before close authored groups."""

        source = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        baseline_target = System(
            hostname="BASE-01",
            ip="10.10.20.10",
            os="Windows Server 2022",
            type="server",
        )
        first_authored_target = System(
            hostname="APP-01",
            ip="10.10.20.20",
            os="Windows Server 2022",
            type="server",
        )
        second_authored_target = System(
            hostname="DB-01",
            ip="10.10.20.30",
            os="Windows Server 2022",
            type="server",
        )
        scenario = _make_scenario(
            [source, baseline_target, first_authored_target, second_authored_target],
            duration="3h",
        )
        actor = scenario.environment.users[0]
        actor.primary_system = source.hostname
        scenario.storyline = [
            StorylineEvent(
                id="source-session-mutation",
                time="2024-01-15T10:40:00Z",
                actor=actor.username,
                system=source.hostname,
                activity="Run an administrative command on the source workstation",
                events=[
                    {
                        "type": "process",
                        "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "command_line": "powershell.exe -NoProfile Get-Process",
                    }
                ],
            ),
            StorylineEvent(
                id="first-close-rdp",
                time="2024-01-15T11:00:00Z",
                actor=actor.username,
                system=first_authored_target.hostname,
                activity="Open the first authored remote desktop session",
                events=[{"type": "rdp_session", "source_ip": source.ip}],
            ),
            StorylineEvent(
                id="second-close-rdp",
                time="2024-01-15T11:00:01Z",
                actor=actor.username,
                system=second_authored_target.hostname,
                activity="Open the second authored remote desktop session",
                events=[{"type": "rdp_session", "source_ip": source.ip}],
            ),
        ]

        class _AuthoredJitterRng(random.Random):
            def __init__(self) -> None:
                super().__init__(311)
                self._jitter = iter((0.0, 20.0, -20.0))

            def uniform(self, a: float, b: float) -> float:
                if a == -30 and b == 30:
                    return next(self._jitter)
                return super().uniform(a, b)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()
            first_hour = datetime(2024, 1, 15, 10, tzinfo=UTC)
            second_hour = first_hour + timedelta(hours=1)
            admission: dict[tuple[datetime, str], bool] = {}
            bundle_calls: list[tuple[str, datetime]] = []
            strict_cutoffs: list[datetime] = []
            execution_sequence: list[tuple[str, str]] = []
            rdp_bootstrap_prepared: list[bool] = []
            ensure_kinds: list[str | None] = []

            def deterministic_rdp_family(current_hour, *, planned_logoffs=None):
                del planned_logoffs
                request_offsets = (
                    (("valid", timedelta(minutes=30)), ("tail", timedelta(minutes=59, seconds=59)))
                    if current_hour == first_hour
                    else (("current", timedelta(minutes=30)),)
                )
                requests = []
                committed_frontier = engine.activity_generator._rdp_session_lifecycle_frontier()
                authored_lower_bound = engine._authored_rdp_transport_lower_bound(current_hour)
                for ordinal, (label, offset) in enumerate(request_offsets):
                    request_time = current_hour + offset
                    prepared = engine.world_planner._prepare_rdp_session_bootstrap(
                        user=actor,
                        target_system=baseline_target,
                        time=request_time,
                        rng=random.Random(7100 + current_hour.hour * 10 + ordinal),
                        source_system=source,
                    )
                    allowed = engine._baseline_rdp_anchor_is_admissible(
                        prepared,
                        current_hour=current_hour,
                        committed_frontier=committed_frontier,
                        authored_lower_bound=authored_lower_bound,
                    )
                    admission[(current_hour, label)] = allowed
                    if allowed:
                        requests.append(
                            _BaselineRdpIntent(
                                time=request_time,
                                target_system=baseline_target,
                                user=actor,
                                source_system=source,
                                prepared_bootstrap=prepared,
                            )
                        )
                engine._execute_baseline_rdp_requests(
                    tuple(requests),
                    random.Random(8100 + current_hour.hour),
                )

            original_bundle = engine.activity_generator._execute_rdp_session_bundle
            original_strict_watermark = (
                engine.activity_generator.advance_rdp_session_lifecycle_watermark
            )
            original_generate_process = engine.activity_generator.generate_process
            original_bootstrap = engine.world_planner.bootstrap_user_session
            original_ensure = engine.world_planner.ensure_user_session

            def track_bundle(*args, **kwargs):
                bundle_calls.append((kwargs["target_system"].hostname, kwargs["time"]))
                execution_sequence.append(("rdp", kwargs["target_system"].hostname))
                return original_bundle(*args, **kwargs)

            def track_strict_watermark(cutoff):
                strict_cutoffs.append(cutoff)
                return original_strict_watermark(cutoff)

            def track_process(*args, **kwargs):
                process_name = kwargs.get("process_name", "")
                if process_name.endswith("powershell.exe"):
                    execution_sequence.append(("process", kwargs["system"].hostname))
                return original_generate_process(*args, **kwargs)

            def track_bootstrap(*args, **kwargs):
                if kwargs.get("session_kind") == "rdp":
                    rdp_bootstrap_prepared.append(kwargs.get("_prepared_rdp_bootstrap") is not None)
                return original_bootstrap(*args, **kwargs)

            def track_ensure(*args, **kwargs):
                ensure_kinds.append(kwargs.get("session_kind"))
                return original_ensure(*args, **kwargs)

            unrelated_hourly_methods = (
                "_generate_baseline_smb_activity",
                "_generate_baseline_email",
                "_generate_traffic_affinities",
                "_generate_stale_account_noise",
                "_generate_baseline_failed_logons",
                "_generate_lateral_movement_noise",
                "_generate_suspicious_noise",
                "_generate_firewall_deny_baseline",
                "_terminate_stale_processes",
                "_generate_logoffs_for_hour",
            )
            with ExitStack() as stack:
                for emitter in engine.emitters.values():
                    stack.callback(emitter.close)
                stack.enter_context(patch.object(engine, "_plan_logoffs_for_hour", return_value={}))
                stack.enter_context(patch.object(engine, "_publish_planned_session_end_plans"))
                for method_name in unrelated_hourly_methods:
                    stack.enter_context(patch.object(engine, method_name))
                stack.enter_context(
                    patch.object(
                        engine,
                        "_generate_system_traffic",
                        side_effect=deterministic_rdp_family,
                    )
                )
                stack.enter_context(
                    patch.object(engine.activity_generator, "finalize_ssh_session_lifecycles")
                )
                stack.enter_context(
                    patch(
                        "evidenceforge.generation.engine.storyline._get_rng",
                        return_value=_AuthoredJitterRng(),
                    )
                )
                stack.enter_context(
                    patch.object(
                        engine.activity_generator,
                        "_execute_rdp_session_bundle",
                        side_effect=track_bundle,
                    )
                )
                stack.enter_context(
                    patch.object(
                        engine.activity_generator,
                        "advance_rdp_session_lifecycle_watermark",
                        side_effect=track_strict_watermark,
                    )
                )
                stack.enter_context(
                    patch.object(
                        engine.activity_generator,
                        "generate_process",
                        side_effect=track_process,
                    )
                )
                stack.enter_context(
                    patch.object(
                        engine.world_planner,
                        "bootstrap_user_session",
                        side_effect=track_bootstrap,
                    )
                )
                stack.enter_context(
                    patch.object(
                        engine.world_planner,
                        "ensure_user_session",
                        side_effect=track_ensure,
                    )
                )
                direct_generate_rdp = stack.enter_context(
                    patch.object(
                        engine.activity_generator,
                        "generate_rdp_session",
                        wraps=engine.activity_generator.generate_rdp_session,
                    )
                )

                engine._generate_hour(first_hour, [], flush_emitters=False)
                engine._generate_hour(second_hour, [], flush_emitters=False)

            assert admission[(first_hour, "valid")]
            assert not admission[(first_hour, "tail")]
            assert not admission[(second_hour, "current")]
            assert [hostname for hostname, _time in bundle_calls] == [
                baseline_target.hostname,
                first_authored_target.hostname,
                second_authored_target.hostname,
            ]
            assert [time for _hostname, time in bundle_calls] == sorted(
                time for _hostname, time in bundle_calls
            )
            assert strict_cutoffs == sorted(strict_cutoffs)
            assert len(strict_cutoffs) == 3
            assert rdp_bootstrap_prepared == [True, False, False]
            assert set(ensure_kinds) == {"interactive"}
            assert direct_generate_rdp.call_count == 0
            assert execution_sequence.index(("rdp", baseline_target.hostname)) < (
                execution_sequence.index(("process", source.hostname))
            )

    def test_authored_rdp_preflight_respects_half_open_terminal_bounds(self):
        """Terminal admission must leave room for the full RDP transport lifecycle."""

        epsilon = timedelta(microseconds=1)
        actor = User(username="admin", full_name="Admin", email="admin@corp.com")
        scenario_end = datetime(2024, 1, 15, 12, tzinfo=UTC)
        scenario_limit = (
            scenario_end - timedelta(seconds=RDP_TRANSPORT_DURATION_MAX_SECONDS) - epsilon
        )
        child_time = scenario_limit - timedelta(seconds=30)
        frontier = {"value": scenario_limit - 2 * epsilon}
        harness = object.__new__(StorylineMixin)
        harness.end_time = scenario_end
        harness._session_end_plan_for_current_start = lambda: None
        harness.activity_generator = SimpleNamespace(
            _rdp_session_lifecycle_frontier=lambda: frontier["value"]
        )
        spec = LogonEventSpec(logon_type=10, source_ip="198.51.100.10")
        system = System(
            hostname="APP-01",
            ip="10.10.20.20",
            os="Windows Server 2022",
            type="server",
        )

        shifted, cumulative = harness._shift_authored_rdp_child_after_frontier(
            actor=actor,
            spec=spec,
            system=system,
            child_time=child_time,
            cumulative_shift=timedelta(0),
        )

        assert shifted == scenario_limit - epsilon
        assert cumulative == shifted - child_time

        rejected_frontier = scenario_limit - epsilon
        frontier["value"] = rejected_frontier
        with pytest.raises(StateError, match="cannot be serialized before the scenario end"):
            harness._shift_authored_rdp_child_after_frontier(
                actor=actor,
                spec=spec,
                system=system,
                child_time=child_time,
                cumulative_shift=timedelta(0),
            )
        assert frontier["value"] == rejected_frontier

        explicit_end = datetime(2024, 1, 15, 12, tzinfo=UTC)
        explicit_limit = explicit_end - timedelta(
            milliseconds=RDP_EXPLICIT_END_CLOSE_GAP_MAX_MILLISECONDS
        )
        harness.end_time = explicit_end + timedelta(hours=2)
        harness._session_end_plan_for_current_start = lambda: SimpleNamespace(
            canonical_end=explicit_end
        )
        explicit_child_time = explicit_limit - timedelta(seconds=30)
        frontier["value"] = explicit_limit - 2 * epsilon
        shifted, _cumulative = harness._shift_authored_rdp_child_after_frontier(
            actor=actor,
            spec=spec,
            system=system,
            child_time=explicit_child_time,
            cumulative_shift=timedelta(0),
        )
        assert shifted == explicit_limit - epsilon

        rejected_frontier = explicit_limit - epsilon
        frontier["value"] = rejected_frontier
        with pytest.raises(
            StateError, match="cannot be serialized before its explicit session end"
        ):
            harness._shift_authored_rdp_child_after_frontier(
                actor=actor,
                spec=spec,
                system=system,
                child_time=explicit_child_time,
                cumulative_shift=timedelta(0),
            )
        assert frontier["value"] == rejected_frontier

    def test_authored_rdp_preflight_bounds_periodic_and_source_aligned_anchors(self):
        """Later periodic success and source alignment must be included before admission."""

        source = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        target = System(
            hostname="APP-01",
            ip="10.10.20.20",
            os="Windows Server 2022",
            type="server",
        )
        scenario = _make_scenario([source, target])
        actor = scenario.environment.users[0]
        state_manager = StateManager()
        scenario_end = datetime(2024, 1, 15, 12, tzinfo=UTC)
        frontier = {"value": datetime(2024, 1, 15, 10, tzinfo=UTC)}
        harness = object.__new__(StorylineMixin)
        harness.start_time = scenario.time_window.start
        harness.end_time = scenario_end
        harness.scenario = scenario
        harness.world_model = WorldModel(scenario, "corp.local")
        harness.state_manager = state_manager
        harness._session_end_plan_for_current_start = lambda: None
        harness.activity_generator = SimpleNamespace(
            _rdp_session_lifecycle_frontier=lambda: frontier["value"]
        )

        credential_spec = CredentialSprayEventSpec(
            start_time="2024-01-15T10:58:00Z",
            interval="1m",
            count=3,
            jitter=0.5,
            source_ip=source.ip,
            target_accounts=[actor.username],
            logon_type=10,
            success={"account": actor.username, "after": 2},
        )
        credential_child_time = datetime(2024, 1, 15, 10, 20, tzinfo=UTC)
        credential_minimum = datetime(2024, 1, 15, 10, 59, 30, tzinfo=UTC)
        frontier["value"] = credential_minimum - timedelta(microseconds=1)
        with pytest.raises(StateError, match="cannot be serialized before the scenario end"):
            harness._shift_authored_rdp_child_after_frontier(
                actor=actor,
                spec=credential_spec,
                system=target,
                child_time=credential_child_time,
                cumulative_shift=timedelta(0),
            )
        assert frontier["value"] == credential_minimum - timedelta(microseconds=1)

        rdp_spec = RdpSessionEventSpec(source_ip=source.ip)
        rdp_child_time = datetime(2024, 1, 15, 10, 0, 5, tzinfo=UTC)
        rdp_minimum = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
        frontier["value"] = rdp_minimum
        shifted, _cumulative = harness._shift_authored_rdp_child_after_frontier(
            actor=actor,
            spec=rdp_spec,
            system=target,
            child_time=rdp_child_time,
            cumulative_shift=timedelta(0),
        )
        assert shifted == rdp_child_time + timedelta(microseconds=1)

        future_source_session = datetime(2024, 1, 15, 10, 30, tzinfo=UTC)
        state_manager.set_current_time(future_source_session)
        state_manager.create_session(
            username=actor.username,
            system=source.hostname,
            logon_type=2,
            source_ip=source.ip,
            session_kind="interactive",
            start_time=future_source_session,
        )
        frontier["value"] = rdp_minimum
        with pytest.raises(StateError, match="cannot be serialized before the scenario end"):
            harness._shift_authored_rdp_child_after_frontier(
                actor=actor,
                spec=rdp_spec,
                system=target,
                child_time=rdp_child_time,
                cumulative_shift=timedelta(0),
            )
        assert frontier["value"] == rdp_minimum

    def test_prepared_rdp_anchors_obey_consecutive_hour_windows(self):
        """Adjacent hourly batches must retain disjoint final RDP anchor windows."""

        source = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        first_target = System(
            hostname="APP-01",
            ip="10.10.20.10",
            os="Windows Server 2022",
            type="server",
        )
        second_target = System(
            hostname="DB-01",
            ip="10.10.20.20",
            os="Windows Server 2022",
            type="server",
        )
        user = User(
            username="admin.user",
            full_name="Admin User",
            email="admin@corp.com",
            persona="sysadmin",
        )
        scenario = _make_scenario([source, first_target, second_target])
        state_manager = StateManager()
        planner = WorldPlanner(WorldModel(scenario, "corp.local"), state_manager, Mock())
        first_hour = datetime(2024, 1, 15, 10, tzinfo=UTC)
        second_hour = first_hour + timedelta(hours=1)

        crosses_start = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=first_target,
            time=first_hour + timedelta(milliseconds=100),
            rng=random.Random(0),
            source_system=source,
        )
        valid_first = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=first_target,
            time=first_hour + timedelta(minutes=30),
            rng=random.Random(1),
            source_system=source,
        )

        future_source_session = first_hour + timedelta(minutes=59, seconds=50)
        state_manager.set_current_time(future_source_session)
        state_manager.create_session(
            username=user.username,
            system=source.hostname,
            logon_type=2,
            source_ip=source.ip,
            session_kind="interactive",
            start_time=future_source_session,
        )
        near_end = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=second_target,
            time=first_hour + timedelta(minutes=59, seconds=45),
            rng=random.Random(0),
            source_system=source,
        )
        crosses_next_start = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=second_target,
            time=second_hour + timedelta(milliseconds=100),
            rng=random.Random(0),
            source_system=source,
        )
        valid_second = planner._prepare_rdp_session_bootstrap(
            user=user,
            target_system=second_target,
            time=second_hour + timedelta(minutes=30),
            rng=random.Random(1),
            source_system=source,
        )

        assert not BaselineMixin._baseline_rdp_anchor_is_in_hour(crosses_start, first_hour)
        assert BaselineMixin._baseline_rdp_anchor_is_in_hour(valid_first, first_hour)
        assert BaselineMixin._baseline_rdp_anchor_is_in_hour(near_end, first_hour)
        assert near_end.transport_time < future_source_session
        assert not BaselineMixin._baseline_rdp_anchor_is_in_hour(
            crosses_next_start,
            second_hour,
        )
        assert BaselineMixin._baseline_rdp_anchor_is_in_hour(valid_second, second_hour)
        assert valid_first.transport_time < valid_second.transport_time

    def test_cross_target_rdp_requests_execute_on_one_global_timeline(self):
        """One shared lifecycle frontier should receive globally ordered RDP requests."""

        source = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        dc = System(
            hostname="DC-01",
            ip="10.10.100.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        file_server = System(
            hostname="FILE-SRV-01",
            ip="10.10.20.10",
            os="Windows Server 2022",
            type="server",
        )
        mail_server = System(
            hostname="MAIL-SRV-01",
            ip="10.10.20.20",
            os="Windows Server 2022",
            type="server",
        )
        user = User(
            username="admin.user",
            full_name="Admin User",
            email="admin@corp.com",
            persona="sysadmin",
        )
        hour = datetime(2024, 1, 15, 10, tzinfo=UTC)
        same_later_time = hour + timedelta(minutes=25)
        requests = (
            _BaselineRdpIntent(
                same_later_time,
                file_server,
                user,
                source,
                SimpleNamespace(
                    transport_time=same_later_time,
                    session_plan=SimpleNamespace(target_system=file_server),
                ),
            ),
            _BaselineRdpIntent(
                same_later_time,
                dc,
                user,
                source,
                SimpleNamespace(
                    transport_time=same_later_time,
                    session_plan=SimpleNamespace(target_system=dc),
                ),
            ),
            _BaselineRdpIntent(
                hour + timedelta(minutes=8),
                mail_server,
                user,
                source,
                SimpleNamespace(
                    transport_time=hour + timedelta(minutes=8),
                    session_plan=SimpleNamespace(target_system=mail_server),
                ),
            ),
        )
        state_manager = Mock()
        world_planner = Mock()
        world_planner._bootstrap_prepared_rdp_session.return_value = SimpleNamespace(session=None)
        harness = SimpleNamespace(
            state_manager=state_manager,
            world_planner=world_planner,
            _baseline_rdp_cooldown_allows=Mock(return_value=True),
            _remember_baseline_rdp_session=Mock(),
        )

        BaselineMixin._execute_baseline_rdp_requests(
            harness,
            requests,
            random.Random(11),
        )

        ordered_calls = world_planner._bootstrap_prepared_rdp_session.call_args_list
        assert [
            entry.kwargs["prepared"].session_plan.target_system.hostname for entry in ordered_calls
        ] == [
            "MAIL-SRV-01",
            "DC-01",
            "FILE-SRV-01",
        ]
        assert state_manager.set_current_time.call_args_list == [
            call(hour + timedelta(minutes=8)),
            call(same_later_time),
            call(same_later_time),
        ]

    def test_generic_successful_rdp_remaps_from_linux_without_xrdp(self):
        """Generic baseline noise should not imply successful RDP to Linux-only services."""
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn", "systemd-resolved"],
            roles=["app_server"],
        )

        effective = _baseline_success_port_for_target(
            app_server,
            3389,
            None,
            random.Random(7),
        )

        assert effective is not None
        assert effective[0] != 3389
        assert effective[1] in {"ssh", "http", "ssl"}

    def test_generic_successful_rdp_allows_explicit_xrdp_service(self):
        """Linux RDP is plausible only when visible receiver service inventory says so."""
        xrdp_server = System(
            hostname="JUMP-01",
            ip="10.10.20.31",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "xrdp"],
            roles=["jump_host"],
        )

        assert _baseline_success_port_for_target(
            xrdp_server,
            3389,
            "rdp",
            random.Random(7),
        ) == (3389, "rdp")

    def test_generic_successful_smb_requires_windows_or_samba(self):
        """Generic baseline noise should not imply SMB to Linux hosts without Samba."""
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )
        samba_server = System(
            hostname="FS-LNX-01",
            ip="10.10.20.32",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "samba"],
            roles=["file_server"],
        )
        windows_server = System(
            hostname="FILE-01",
            ip="10.10.20.20",
            os="Windows Server 2019",
            type="server",
            services=["smb", "dns-client"],
            roles=["file_server"],
        )

        remapped = _baseline_success_port_for_target(app_server, 445, "smb", random.Random(9))

        assert remapped is not None
        assert remapped[0] != 445
        assert _baseline_success_port_for_target(
            samba_server,
            445,
            "smb",
            random.Random(9),
        ) == (445, "smb")
        assert _baseline_success_port_for_target(
            windows_server,
            445,
            "smb",
            random.Random(9),
        ) == (445, "smb")

    def test_guarded_profile_smb_retargets_from_linux_app_to_file_server(self):
        """Profile SMB traffic should keep SMB semantics but choose an SMB-capable receiver."""
        workstation = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )
        file_server = System(
            hostname="FILE-01",
            ip="10.10.20.20",
            os="Windows Server 2019",
            type="server",
            services=["smb"],
            roles=["file_server"],
        )

        effective_target = _baseline_success_target_for_guarded_port(
            [workstation, app_server, file_server],
            workstation,
            app_server,
            445,
            random.Random(9),
        )

        assert effective_target == file_server

    def test_guarded_smb_accepts_explicit_linux_storage_capability(self) -> None:
        """Storage topology should authorize SMB success without a redundant service label."""
        client = System(
            hostname="LINUX-CLIENT",
            ip="10.10.10.50",
            os="Ubuntu 24.04",
            type="workstation",
            services=["smbclient"],
        )
        storage = System(
            hostname="STORAGE-01",
            ip="10.10.20.20",
            os="Ubuntu 24.04",
            type="server",
        )
        scenario = _make_scenario([client, storage])
        scenario.environment.storage = StorageConfig(
            servers=[StorageServerConfig(system=storage.hostname, presets=["collaboration"])]
        )
        world_model = WorldModel(scenario, "corp.com")

        assert _baseline_success_port_for_target(
            storage,
            445,
            "smb",
            random.Random(9),
            world_model,
        ) == (445, "smb")

    def test_guarded_smb_never_selects_the_source_as_its_own_server(self) -> None:
        """A sole Samba server must not create successful self-directed SMB traffic."""
        samba = System(
            hostname="SAMBA-01",
            ip="10.10.20.20",
            os="Ubuntu 24.04",
            type="server",
            services=["smbd"],
        )

        assert (
            _baseline_success_target_for_guarded_port(
                [samba],
                samba,
                samba,
                445,
                random.Random(9),
            )
            is None
        )

    def test_guarded_profile_smb_skips_without_compatible_receiver(self):
        """Profile SMB should not invent a success target when no receiver exposes SMB."""
        workstation = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )

        assert (
            _baseline_success_target_for_guarded_port(
                [workstation, app_server],
                workstation,
                app_server,
                445,
                random.Random(9),
            )
            is None
        )

    def test_rdp_connections_generated_for_windows_servers(self):
        """Windows servers should receive baseline RDP admin connections."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
            System(hostname="SRV-01", ip="10.10.20.10", os="Windows Server 2019", type="server"),
            System(
                hostname="DC-01",
                ip="10.10.100.10",
                os="Windows Server 2019",
                type="domain_controller",
            ),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()

            rdp_connections = []
            original = engine.dispatcher.dispatch

            def tracking(event):
                if (
                    event.event_type == "connection"
                    and event.network is not None
                    and event.network.dst_port == 3389
                ):
                    rdp_connections.append(event)
                return original(event)

            with patch.object(engine.dispatcher, "dispatch", side_effect=tracking):
                # Generate multiple hours for determinism
                for h in range(4):
                    hour = datetime(2024, 1, 15, 10 + h, 0, 0, tzinfo=UTC)
                    engine._generate_system_traffic(hour)

            assert len(rdp_connections) > 0, "No RDP baseline connections in 4 hours of generation"
            for conn in rdp_connections:
                assert conn.network is not None
                assert conn.network.dst_port == 3389
                assert conn.network.protocol == "tcp"
                assert conn.network.service == "rdp"

    def test_no_rdp_noise_for_workstations_only(self):
        """Environment with only workstations should not get RDP admin connections."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
            System(hostname="WKS-02", ip="10.10.10.51", os="Windows 10", type="workstation"),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()

            rdp_connections = []
            original = engine.dispatcher.dispatch

            def tracking(event):
                if (
                    event.event_type == "connection"
                    and event.network is not None
                    and event.network.dst_port == 3389
                ):
                    rdp_connections.append(event)
                return original(event)

            with patch.object(engine.dispatcher, "dispatch", side_effect=tracking):
                hour = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
                engine._generate_system_traffic(hour)

            assert len(rdp_connections) == 0, (
                f"Got RDP connections to workstations: {rdp_connections}"
            )

    def test_domain_controller_rdp_noise_is_capped_per_hour(self):
        """DC baseline RDP should not request several new sessions in one hour."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
            System(
                hostname="DC-01",
                ip="10.10.100.10",
                os="Windows Server 2019",
                type="domain_controller",
            ),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()

            with patch.object(engine, "_scaled_randint", return_value=3):
                assert engine._baseline_rdp_hourly_count(random.Random(11), systems[1]) == 1

    def test_rdp_cooldown_rejects_dense_same_tuple_sessions(self):
        """The same source/user/target should not open clustered baseline RDP sessions."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
            System(
                hostname="DC-01",
                ip="10.10.100.10",
                os="Windows Server 2019",
                type="domain_controller",
            ),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()
            first = datetime(2024, 1, 15, 14, 23, tzinfo=UTC)

            assert engine._baseline_rdp_cooldown_allows(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                planned_time=first,
            )
            engine._remember_baseline_rdp_session(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                session_time=first,
            )

            assert not engine._baseline_rdp_cooldown_allows(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                planned_time=first + timedelta(minutes=1),
            )
            assert engine._baseline_rdp_cooldown_allows(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                planned_time=first + timedelta(minutes=46),
            )
