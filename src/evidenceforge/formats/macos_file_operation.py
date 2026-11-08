# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-native payloads from one explicit canonical filesystem occurrence."""

from evidenceforge.events.macos_file_operation import MacosFileOperationObservation
from evidenceforge.formats.macos_endpoint_security import (
    ESClose,
    ESCloseEvent,
    ESCreate,
    ESCreateEvent,
    ESExistingDestination,
    ESNewDestination,
    ESNewPath,
    ESRenameEvent,
    ESRenameExisting,
    ESRenameNew,
    ESUnlink,
    ESUnlinkEvent,
)
from evidenceforge.formats.macos_file_metadata import (
    es_file_from_directory_observation,
    es_file_from_runtime_record,
)


def es_file_operation_payload(
    observation: MacosFileOperationObservation,
) -> ESCreateEvent | ESCloseEvent | ESRenameEvent | ESUnlinkEvent:
    """Render measured v11 payload variants without allocating or mutating state."""
    if type(observation) is not MacosFileOperationObservation:
        raise ValueError("Native file payload requires one exact canonical observation")
    observation.__post_init__()
    source = es_file_from_runtime_record(observation.source)
    if observation.operation == "create":
        return ESCreateEvent(
            create=ESCreate(
                destination_type=0,
                destination=ESExistingDestination(existing_file=source),
                acl=None,
            )
        )
    if observation.operation == "close":
        return ESCloseEvent(
            close=ESClose(target=source, modified=observation.modified, was_mapped_writable=False)
        )
    parent = observation.parent
    assert parent is not None
    directory = es_file_from_directory_observation(parent)
    if observation.operation == "unlink":
        return ESUnlinkEvent(unlink=ESUnlink(target=source, parent_dir=directory))
    assert observation.target is not None
    if observation.replacement is not None:
        destination = ESExistingDestination(
            existing_file=es_file_from_runtime_record(observation.replacement)
        )
        return ESRenameEvent(
            rename=ESRenameExisting(source=source, destination_type=0, destination=destination)
        )
    target = observation.target.artifact.native_path
    return ESRenameEvent(
        rename=ESRenameNew(
            source=source,
            destination_type=1,
            destination=ESNewDestination(
                new_path=ESNewPath(dir=directory, filename=target.rsplit("/", 1)[-1])
            ),
        )
    )
