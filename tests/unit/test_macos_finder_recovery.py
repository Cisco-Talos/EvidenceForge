# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Interrupted Finder phases retain the same canonical and source identities."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import (
    ActionCohortPublicationResult,
    PreparedActionCohortCapability,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import ExecutionEffectPlan
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.generation.checkpoints.activity_head import _assert_transient_empty
from evidenceforge.generation.checkpoints.errors import CheckpointError
from tests.unit.test_macos_finder_generation import _APP, _finder_engine


@pytest.mark.slow
@pytest.mark.parametrize("phase", [0, 1, 2], ids=["fork-launcher", "credentials", "app"])
@pytest.mark.parametrize("fault", ["before-commit", "lost-return", "source-release"])
def test_each_finder_phase_resumes_without_duplicate_births_or_execs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: int,
    fault: str,
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True)
    try:
        engine._initialize()
        generator = engine.activity_generator
        system, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        logon = generator.generate_logon(
            user,
            system,
            engine.start_time - timedelta(minutes=5),
            allow_local_session_reuse=False,
        )
        request = ProcessExecutionRequest(
            user,
            system,
            engine.start_time + timedelta(minutes=2),
            logon,
            _APP,
            _APP,
            parent_pid=1,
            require_exact_parent=True,
            arguments=(_APP,),
            macos_launch_kind="finder",
            from_storyline=True,
            effect_plan=ExecutionEffectPlan(
                ActionAnchor("process_execution", "invented-finder-recovery", source="test"),
                (),
            ),
        )
        original = PreparedActionCohortCapability.commit_no_fail
        attempts = 0

        def interrupted(
            capability: PreparedActionCohortCapability,
        ) -> ActionCohortPublicationResult:
            nonlocal attempts
            current = attempts
            attempts += 1
            if current == phase and fault == "before-commit":
                raise OSError("invented Finder interruption")
            result = original(capability)
            if current == phase and fault == "lost-return":
                raise OSError("invented Finder interruption")
            return result

        from evidenceforge.generation.emitters.base import ExactPublicationBatch

        release = ExactPublicationBatch.release_no_fail
        releases = 0

        def interrupted_release(batch: ExactPublicationBatch) -> None:
            nonlocal releases
            current = releases
            releases += 1
            if current == phase:
                raise OSError("invented Finder interruption")
            release(batch)

        with monkeypatch.context() as fault_scope:
            if fault == "source-release":
                fault_scope.setattr(ExactPublicationBatch, "release_no_fail", interrupted_release)
            else:
                fault_scope.setattr(PreparedActionCohortCapability, "commit_no_fail", interrupted)
            with pytest.raises(OSError, match="invented Finder interruption"):
                generator._process_execution_service().create(request)
        assert len(generator._macos_finder_startups) == 1
        with pytest.raises(CheckpointError, match="_macos_finder_startups"):
            _assert_transient_empty(generator)
        before = dict(engine.state_manager.macos_process_census_snapshot())[system.hostname]
        engine.dispatcher.drain_exact_projection_recoveries()
        assert dict(engine.state_manager.macos_process_census_snapshot())[system.hostname] == before
        # A newly bound service must use activity's retained startup owner.
        pid = generator._process_execution_service().create(request)
        assert not generator._macos_finder_startups
        after = dict(engine.state_manager.macos_process_census_snapshot())[system.hostname]
        assert after.forks.count == 1 and after.execs.count == 2 and after.aggregate_births == 0
        current = engine.state_manager.get_process_identity(system.hostname, pid)
        assert current.image == _APP and current.execution_ordinal == 2
        engine.dispatcher.assert_exact_projection_recoveries_drained()
        engine._finalize_macos_process_coverage()
        assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.complete
    finally:
        engine._close_emitters()
