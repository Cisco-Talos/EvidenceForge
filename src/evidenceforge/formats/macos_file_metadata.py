# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native file projection from an exact canonical runtime version."""

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_execution_directory import validate_macos_execution_directory
from evidenceforge.events.macos_file import MacosDirectoryMetadata, MacosFileMetadata
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


def _es_file(path: str, metadata: MacosFileMetadata | MacosDirectoryMetadata) -> ESFile:
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
