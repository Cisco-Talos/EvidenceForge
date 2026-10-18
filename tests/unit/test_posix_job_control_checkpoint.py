# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""State v6 recovery with retained immutable allocator segments and v7 writes."""

from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.models import CheckpointCursor
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.participants import ParticipantSeal
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_posix_job_control import _root


class _LegacyStateParticipant(StateManagerParticipant):
    checkpoint_schema_version = "6"

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        seal = super().prepare_checkpoint(sequence)
        head = loads(seal.head.payload)
        head["schema_version"] = "6"
        for name in ("_posix_job_control_reservations", "_posix_job_control_reservation_counts"):
            del head["simple"][name]
        segments = []
        for segment in seal.segments:
            document = loads(segment.payload)
            document["schema_version"] = "6"
            segments.append(replace(segment, schema_version="6", payload=dumps(document)))
        return replace(seal, head=replace(seal.head, payload=dumps(head)), segments=tuple(segments))


@pytest.mark.parametrize("accept_legacy_segments", [False, True])
def test_controller_restores_only_explicitly_compatible_segments(
    tmp_path: Path, accept_legacy_segments: bool
) -> None:
    state, identity = _root()
    state.next_semantic_peer_ordinal("process", "invented-peer")
    store = IncrementalCheckpointStore(tmp_path / "output")
    controller = IncrementalCheckpointController(
        store=store,
        fingerprint="1" * 64,
        checkpoint_hours=6,
        resolved_scenario=b"schema_version: '2.0'\n",
    )
    cursor = CheckpointCursor(
        phase="collection", completed_simulated_hours=6, next_hour="2026-10-15T18:00:00+00:00"
    )
    controller.commit(cursor=cursor, participants=(_LegacyStateParticipant(state),))
    recovery = store.recover()
    assert recovery.segments and all(row.schema_version == "6" for row in recovery.segments)
    restored = StateManager()
    participant = StateManagerParticipant(restored)
    if not accept_legacy_segments:
        participant.checkpoint_compatible_segment_versions = ()
        with pytest.raises(CheckpointError, match="segment schemas"):
            controller.restore_participants(recovery=recovery, participants=(participant,))
        assert restored.get_process_identity(identity.hostname, identity.pid) is None
        return
    controller.restore_participants(recovery=recovery, participants=(participant,))
    assert restored.get_process_identity(identity.hostname, identity.pid) == identity
    assert restored.next_semantic_peer_ordinal("process", "invented-peer") == 1
    next_cursor = CheckpointCursor(
        phase="collection", completed_simulated_hours=12, next_hour="2026-10-16T00:00:00+00:00"
    )
    manifest = controller.commit(cursor=next_cursor, participants=(participant,))
    assert manifest.participant_heads[0].schema_version == "7"
    again = StateManager()
    controller.restore_participants(
        recovery=store.recover(), participants=(StateManagerParticipant(again),)
    )
    assert again.get_process_identity(identity.hostname, identity.pid) == identity
    assert again.next_semantic_peer_ordinal("process", "invented-peer") == 2
