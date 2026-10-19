# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.formats.macos_endpoint_security import (
    ESAuditToken,
    decode_endpoint_security_record,
)
from evidenceforge.formats.macos_process_snapshot import es_process_from_observations
from tests.unit.test_es_collector_ownership import _setup as _collector
from tests.unit.test_macos_endpoint_security_contracts import _record
from tests.unit.test_macos_launch_file import _manager
from tests.unit.test_macos_process_relationship_projection import _family
from tests.unit.test_macos_runtime_file_metadata import _executable


def _inputs() -> tuple[
    ProcessRelationshipObservation,
    MacosProcessCollectionObservation,
    ProcessContext,
    LocalArtifactVersionRecord,
]:
    state, _, _, subject = _family()
    descriptor = replace(_executable(), hostname=subject.hostname)
    record = _manager().build_record(descriptor)
    builder = state.begin_action_cohort_materialization()
    subject = builder.execute_process(
        subject,
        image=record.artifact.native_path,
        command_line="invented-worker",
        executed_at=subject.started_at + timedelta(seconds=1),
        image_security=MacosImageSecurity(7, False, 3),
    )
    state.materialize_action_cohort(builder.seal())
    at = subject.execution_started_at
    relationships = state.observe_process_relationships(subject, observed_at=at)
    collection = MacosProcessCollectionObservation(subject, at, False, "absent")
    context = ProcessContext(
        pid=subject.pid,
        parent_pid=subject.parent_pid,
        image=subject.image,
        command_line=subject.command_line,
        username=subject.principal,
        start_time=subject.started_at,
        binary_identity=record.binary,
    )
    return relationships, collection, context, record


@pytest.mark.parametrize("version", [6, 9, 10])
def test_complete_explicit_snapshot_preserves_versioned_facts(version: int) -> None:
    relationships, collection, context, record = _inputs()
    result = es_process_from_observations(
        relationships, collection, context, record, version=version
    )
    assert result.executable.stat.st_ino == record.macos_file.inode
    assert result.executable.path == context.image
    assert result.is_es_client is False and result.tty is None
    assert result.codesigning_flags == 7
    assert result.cdhash == record.binary.code_signature.cdhash.lower()
    assert result.cs_validation_category == (3 if version == 10 else None)
    assert isinstance(result.audit_token, tuple if version == 10 else ESAuditToken)
    before = result.model_dump_json()
    context.image = "/usr/local/libexec/replaced-image"
    assert result.model_dump_json() == before


@pytest.mark.parametrize(
    "damage",
    [
        "time",
        "subject",
        "file_host",
        "file_path",
        "version",
        "stat",
        "binary",
        "signing",
        "runtime",
    ],
)
def test_snapshot_rejects_missing_or_mixed_fact_owners(damage: str) -> None:
    relationships, collection, context, record = _inputs()
    if damage == "time":
        collection = replace(collection, observed_at=collection.observed_at + timedelta(seconds=1))
    elif damage == "subject":
        collection = replace(collection, process=relationships.parent.parent)
    elif damage == "file_host":
        record = _manager().build_record(replace(_executable(), hostname="another-host"))
    elif damage == "file_path":
        record = replace(record, artifact=replace(record.artifact, native_path="/usr/bin/other"))
    elif damage == "version":
        changed = replace(record.binary, artifact_name="different-binary")
        context.binary_identity = changed
    elif damage == "stat":
        record = replace(record, macos_file=None)
    elif damage == "binary":
        record = replace(record, binary=None)
    elif damage == "signing":
        record = replace(record, binary=replace(record.binary, code_signature=None))
        context.binary_identity = record.binary
    elif damage == "runtime":
        changed = replace(collection.process, image_security=None)
        collection = replace(collection, process=changed)
        relationships = replace(
            relationships,
            parent=replace(relationships.parent, process=changed),
            responsibility=replace(relationships.responsibility, process=changed),
        )
    with pytest.raises(ValueError):
        es_process_from_observations(relationships, collection, context, record, version=10)


@pytest.mark.parametrize(
    "client,terminal",
    [(None, "absent"), (0, "absent"), (False, None), (False, "unknown"), (False, "present")],
)
def test_unknown_client_or_terminal_never_becomes_a_padding_default(
    client: object, terminal: object
) -> None:
    relationships, _, _, _ = _inputs()
    with pytest.raises(ValueError, match="exact timed"):
        MacosProcessCollectionObservation(
            relationships.parent.process, relationships.parent.observed_at, client, terminal
        )


def test_positive_client_fact_requires_the_exact_attached_interval() -> None:
    _, process, owner, connection = _collector()
    fact = MacosProcessCollectionObservation.from_attached_collector(
        process,
        connection,
        observed_at=connection.opened_at,
        terminal="absent",
    )
    assert fact.is_es_client
    owner.collectors.close(connection, connection.opened_at + timedelta(seconds=1))
    closed = owner.collectors.connection(connection.source_instance)
    with pytest.raises(ValueError, match="attached execution and interval"):
        MacosProcessCollectionObservation.from_attached_collector(
            process,
            closed,
            observed_at=closed.closed_at,
            terminal="absent",
        )
    with pytest.raises(ValueError, match="attached execution and interval"):
        MacosProcessCollectionObservation.from_attached_collector(
            process,
            connection.model_copy(update={"process": None}),
            observed_at=connection.opened_at,
            terminal="absent",
        )


@pytest.mark.parametrize("version,family", [(6, "fork"), (9, "exit"), (10, "fork")])
def test_snapshot_preserves_optional_presence_in_native_envelope(version: int, family: str) -> None:
    snapshot = es_process_from_observations(*_inputs(), version=version)
    wire = _record(version, family)
    wire["process"] = snapshot.model_dump(mode="json", exclude_unset=True)
    record = decode_endpoint_security_record(json.dumps(wire))
    serialized = json.loads(record.to_ndjson())["process"]
    assert ("cs_validation_category" in serialized) is (version == 10)
    assert serialized["tty"] is None
    assert serialized["is_es_client"] is False
    assert serialized["executable"]["stat"]["st_blocks"] == 0
    assert decode_endpoint_security_record(record.to_ndjson()) == record
