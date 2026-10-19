# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native file projection from an exact canonical runtime version."""

from evidenceforge.events.artifact_placement import MacosRuntimeFilePlacementObservation
from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_exec_script import MacosExecScript, validate_macos_exec_script
from evidenceforge.events.macos_execution_directory import validate_macos_execution_directory
from evidenceforge.events.macos_file import (
    MacosDirectoryMetadata,
    MacosFileMetadata,
    MacosTerminalMetadata,
)
from evidenceforge.events.macos_installed_file import MacosInstalledFileObservation
from evidenceforge.events.macos_terminal import MacosTerminalObservation
from evidenceforge.formats.macos_endpoint_security import ESFile, ESFileStat


def es_file_from_runtime_record(record: LocalArtifactVersionRecord) -> ESFile:
    """Render a complete known regular file without inventing stat or truncation facts.

    The canonical placement is a complete path, so this bounded projection is
    untruncated. An exporter requiring a truncated view must model that view
    separately. Calling this helper does not admit a native event family.
    """
    if type(record) is not LocalArtifactVersionRecord or record.macos_file is None:
        raise ValueError("ES file projection requires complete canonical Mac file metadata")
    record.__post_init__()
    metadata = MacosFileMetadata.model_validate_json(record.macos_file.canonical_json())
    return _es_file(record.artifact.native_path, metadata)


def es_directory_at_execution(process: ProcessIdentity) -> ESFile:
    """Project explicit execution-time cwd; never use a launch path as a later cwd."""
    if type(process) is not ProcessIdentity or process.execution_directory is None:
        raise ValueError("Native exec cwd requires an explicit canonical directory observation")
    process.__post_init__()
    directory = process.execution_directory
    validate_macos_execution_directory(
        directory, hostname=process.hostname, observed_at=process.execution_started_at
    )
    metadata = MacosDirectoryMetadata.model_validate_json(directory.metadata.canonical_json())
    return _es_file(directory.native_path, metadata)


def es_file_from_installed_observation(observation: MacosInstalledFileObservation) -> ESFile:
    """Render explicitly observed installed-file facts through the shared stat projection."""
    if type(observation) is not MacosInstalledFileObservation:
        raise ValueError("Installed ES file requires an exact canonical observation")
    observation.__post_init__()
    return _es_file(observation.native_path, observation.metadata)


def es_file_from_terminal_observation(observation: MacosTerminalObservation) -> ESFile:
    """Project an explicitly associated character device; never infer a TTY from argv."""
    if type(observation) is not MacosTerminalObservation:
        raise ValueError("ES terminal requires its exact canonical observation")
    observation.__post_init__()
    return _es_file(observation.native_path, observation.metadata)


def _es_file(
    path: str, metadata: MacosFileMetadata | MacosDirectoryMetadata | MacosTerminalMetadata
) -> ESFile:
    return ESFile(
        path=path,
        path_truncated=False,
        stat=ESFileStat(
            st_dev=metadata.device,
            st_mode=metadata.mode,
            st_nlink=metadata.link_count,
            st_ino=metadata.inode,
            st_uid=metadata.uid,
            st_gid=metadata.gid,
            st_rdev=metadata.special_device,
            st_atimespec=metadata.accessed.native_timestamp(),
            st_mtimespec=metadata.modified.native_timestamp(),
            st_ctimespec=metadata.changed.native_timestamp(),
            st_birthtimespec=metadata.born.native_timestamp(),
            st_size=metadata.size_bytes,
            st_blocks=metadata.allocated_blocks,
            st_blksize=metadata.preferred_block_size,
            st_flags=metadata.flags,
            st_gen=metadata.generation,
        ),
    )


def es_script_at_execution(
    process: ProcessIdentity,
    record: LocalArtifactVersionRecord | MacosRuntimeFilePlacementObservation | None = None,
) -> ESFile | None:
    """Project known shebang-script truth; arguments never establish script presence.

    The loaded interpreter's image/version stays separate from this script file.
    Missing metadata or a replacement at the same path cannot satisfy the reference.
    """
    if type(process) is not ProcessIdentity or process.exec_script is None:
        raise ValueError("ES exec script requires explicitly known execution facts")
    process.__post_init__()
    script = process.exec_script
    validate_macos_exec_script(script, platform="macos", hostname=process.hostname)
    if script.artifact_version_id is None:
        if record is not None:
            raise ValueError("Known script absence cannot carry a script file")
        return None
    placement = record if type(record) is MacosRuntimeFilePlacementObservation else None
    if placement is not None:
        placement.__post_init__()
        if placement.observed_at != process.execution_started_at:
            raise ValueError("ES script placement must describe the exact execution time")
        record = placement.reference
    if (
        type(record) is not LocalArtifactVersionRecord
        or MacosExecScript.from_runtime_record(record) != script
        or process.executable_version is None
        or process.executable_version.platform != "macos"
    ):
        raise ValueError("ES exec script requires its exact file and a distinct loaded interpreter")
    return es_file_from_runtime_record(record if placement is None else placement.placed)
