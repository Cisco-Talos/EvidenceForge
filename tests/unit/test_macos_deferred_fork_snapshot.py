# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A deferred SSH batch freezes the same native fork facts before any canonical commit."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import PreparedDispatchStateIntent
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.generation.actions.posix_process import process_fork_occurrence
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_installed_es_process_snapshot,
)
from evidenceforge.generation.macos_es_publication import prepared_macos_es_process_publication
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_installed_provisioning import _scenario


def test_deferred_fork_native_snapshot_is_frozen_without_state_or_source_mutation(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    scenario.macos_process_coverage = "partial"
    scenario.output.logs = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=369)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        state, dispatcher = engine.state_manager, engine.dispatcher
        provider = engine.activity_generator.macos_execution_metadata
        parent = state.get_process_identity("MAC-01", 1)
        at = engine.start_time + timedelta(seconds=10)
        builder = state.begin_materialization_batch()
        session = builder.plan_session(
            username="alex",
            system="MAC-01",
            logon_type=10,
            source_ip="192.0.2.80",
            source_port=51000,
            session_kind="ssh",
            auth_protocol="ssh",
            effective_uid=501,
            effective_gid=20,
            start_time=at,
            source_ready_time=at + timedelta(seconds=2),
            network_close_time=at + timedelta(minutes=2),
            closure_owned_by_bundle=True,
        )
        session = builder.enrich_macos_audit_session(
            session, audit_uid=501, authenticated_at=at + timedelta(seconds=1)
        )
        fork = builder.plan_macos_ssh_receiver_fork(
            parent,
            session=session,
            forked_at=at,
            execution_directory=provider.directory("MAC-01", "/", at),
            lifecycle_group_id="invented-deferred-native-fork",
        )
        builder.bind_session_processes(session, transport_plan=fork, process_tree_root_plan=fork)
        batch = builder.seal()
        event = process_fork_occurrence(
            host=HostContext("MAC-01", "192.0.2.81", "macOS 27", "macos", "workstation"),
            parent=parent,
            child=fork.identity,
            integrity_level="System",
            session=session.identity,
        )
        digest = state.materialization_digest()
        with dispatcher.source_timing_planner.prepared_planning() as timing:
            prepared = dispatcher.prepare_builder(
                event,
                state_intent=PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT,
                lifecycle_ticket=fork,
                source_timing_preparation=timing,
            )
            with prepared_macos_es_process_publication(
                dispatcher, batch, (prepared._occurrence,)
            ) as native:
                assert native is not None and native.ingress is not None
                ingress = native.ingress
                assert len(ingress.rows) == 1
                assert ingress.rows[0].reason == "supported"
                wire = json.loads(ingress.rows[0].native_body)
                assert wire["event_type"] == 11 and wire["version"] == 11
                assert wire["process"]["executable"]["path"] == "/sbin/launchd"
                child = wire["event"]["fork"]["child"]
                assert child["executable"] == wire["process"]["executable"]
                assert child["audit_token"]["pid"] == fork.identity.pid
                assert child["audit_token"]["auid"] == parent.credentials.audit_uid
                assert child["group_id"] == wire["process"]["group_id"]
                assert child["session_id"] == wire["process"]["session_id"]
                ingress.owner.validate(ingress, batch.publication_token)
                with pytest.raises(StateError):
                    ingress.owner.validate(ingress, "another-canonical-plan")
                for damaged in (
                    replace(batch, _processes=()),
                    replace(batch, _session=None),
                ):
                    with pytest.raises(StateError):
                        state.validate_macos_process_observation_plan(damaged)
        assert state.materialization_digest() == digest
        with pytest.raises(StateError, match="initial fork only"):
            prepare_planned_installed_es_process_snapshot(
                state,
                dispatcher.deployment_registry,
                cohort=batch,
                collection=MacosProcessCollectionObservation(fork.identity, at, False, "absent"),
                phase="exec",
                version=11,
                filesystem=dispatcher.macos_installed_filesystem,
            )
        assert state.get_process("MAC-01", fork.identity.pid) is None
        assert state.get_session(session.identity.logon_id) is None
    finally:
        engine._close_emitters()
    assert all(not path.read_bytes() for path in tmp_path.rglob("macos_endpoint_security.ndjson"))
