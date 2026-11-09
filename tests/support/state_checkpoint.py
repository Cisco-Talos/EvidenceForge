# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Full StateManager snapshots for fixtures exercising durable allocation history."""

from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
from evidenceforge.generation.state_manager import StateManager

type StateSnapshot = tuple[bytes, tuple[bytes, ...]]


def capture_complete_state(manager: StateManager) -> StateSnapshot:
    """Capture public head and allocator segments without replacing a fixture recorder."""
    recorder = manager._checkpoint_incremental_recorder
    manager._checkpoint_incremental_recorder = None
    try:
        owner = StateManagerParticipant(manager)
        seal = owner.prepare_checkpoint(1)
        owner.checkpoint_committed(1)
        return seal.head.payload, tuple(segment.payload for segment in seal.segments)
    finally:
        manager._checkpoint_incremental_recorder = recorder


def restore_complete_state(manager: StateManager, snapshot: StateSnapshot) -> None:
    """Hydrate all durable facts while retaining a fixture's recorder binding."""
    recorder = manager._checkpoint_incremental_recorder
    manager._checkpoint_incremental_recorder = None
    try:
        StateManagerParticipant(manager).restore_checkpoint(*snapshot)
    finally:
        manager._checkpoint_incremental_recorder = recorder
