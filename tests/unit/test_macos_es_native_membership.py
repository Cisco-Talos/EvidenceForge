# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_es_collector import _profile
from tests.unit.test_macos_es_group_dispatch import _bind, _setup
from tests.unit.test_macos_exact_exit_group import _prepare


def test_native_bytes_cannot_outlive_changed_client_membership_before_canonical_commit(
    tmp_path: Path,
) -> None:
    group, dispatcher, emitter, batch, frozen = _setup(tmp_path)
    assert '"is_es_client":false' in frozen[0]
    # Keep the independent native reservation while replanning the canonical batch.
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    subject = group.records[0].process.process
    group.owner.open(
        _profile(
            source_instance="new-subject-client",
            hostname=subject.hostname,
            opened_at=subject.started_at,
            last_delivery_at=subject.started_at,
        ),
        subject,
    )
    events = []
    for item in group.cohort.process_terminations:
        event = process_exit_occurrence(
            host=HostContext(
                hostname=item.identity.hostname,
                ip="192.0.2.41",
                os="macOS 26",
                os_category="macos",
                system_type="workstation",
            ),
            process=item.identity,
            timestamp=item.end_time,
            integrity_level="Medium",
        )
        event.process.exit_outcome = item.exit_outcome
        events.append(event)
    batch = _prepare(dispatcher, group.cohort, tuple(events))
    before = group.owner.state.materialization_digest()
    try:
        with pytest.raises((StateError, EventContractError)):
            _bind(group, dispatcher, batch)
        assert group.owner.state.materialization_digest() == before
    finally:
        dispatcher.cancel_prepared_action_cohort_batch(batch)
        if group.owner.collectors.owns_pending_batch(group.delivery):
            group.owner.collectors.cancel_batch(group.delivery)
        emitter.close()
