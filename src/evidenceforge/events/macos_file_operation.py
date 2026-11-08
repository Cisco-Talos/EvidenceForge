# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical before/after file-operation observations, separate from native exports."""

import posixpath
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Literal

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.macos_execution_directory import (
    MacosExecutionDirectory,
    validate_macos_execution_directory,
)


@dataclass(frozen=True, slots=True)
class MacosFileOperationObservation:
    """One canonical filesystem occurrence with explicit source-native stat phase.

    Create is the empty file before writing; close observes the current file;
    rename and unlink observe their pre-operation source. Replacement preserves
    the old destination object. This value grants no registry or source authority.
    """

    operation: Literal["create", "close", "rename", "unlink"]
    source: LocalArtifactVersionRecord
    observed_at: datetime
    parent: MacosExecutionDirectory | None = None
    target: LocalArtifactVersionRecord | None = None
    replacement: LocalArtifactVersionRecord | None = None
    previous: LocalArtifactVersionRecord | None = None
    modified: bool | None = None
    was_mapped_writable: bool | None = None

    def __post_init__(self) -> None:
        if self.operation not in {"create", "close", "rename", "unlink"} or (
            type(self.observed_at) is not datetime or self.observed_at.utcoffset() is None
        ):
            raise ValueError("Mac file operation requires its bounded kind and an aware time")
        if type(self.source) is not LocalArtifactVersionRecord:
            raise ValueError("Mac file operation requires its exact canonical file version")
        self.source.__post_init__()
        record = self.source
        metadata = record.macos_file
        if (
            record.artifact.platform != "macos"
            or metadata is None
            or metadata.link_count != 1
            or record.artifact.native_path != record.artifact.normalized_native_path
        ):
            raise ValueError("Mac file operation requires a known single-link regular file")
        if self.operation == "close":
            if type(self.modified) is not bool or self.was_mapped_writable is not False:
                raise ValueError("Bounded Mac close requires explicit modified and unmapped facts")
            if self.previous is not None:
                old = self.previous
                if type(old) is not LocalArtifactVersionRecord:
                    raise ValueError(
                        "Modified close requires its exact prior canonical file version"
                    )
                old.__post_init__()
                if (
                    self.modified is not True
                    or old.artifact.object_key != record.artifact.object_key
                    or old.artifact.native_path != record.artifact.native_path
                    or old.artifact.version >= record.artifact.version
                    or old.macos_file is None
                    or old.macos_file.file_object_id != metadata.file_object_id
                    or old.macos_file.inode != metadata.inode
                    or old.macos_file.device != metadata.device
                    or old.macos_file.volume_id != metadata.volume_id
                    or metadata.model_copy(
                        update={
                            "accessed": old.macos_file.accessed,
                            "modified": old.macos_file.modified,
                            "changed": old.macos_file.changed,
                            "size_bytes": old.macos_file.size_bytes,
                            "allocated_blocks": old.macos_file.allocated_blocks,
                        }
                    )
                    != old.macos_file
                ):
                    raise ValueError("Modified close must preserve the exact prior file object")
        elif self.modified is not None or self.was_mapped_writable is not None:
            raise ValueError("Only close carries modification/mapping observations")
        if self.operation != "close" and self.previous is not None:
            raise ValueError("Only modified close carries its prior content version")
        if self.operation == "create" and (
            record.content.size_bytes != 0 or metadata.size_bytes != 0
        ):
            raise ValueError("Bounded Mac create describes the empty pre-write file")
        if self.operation == "rename":
            if self.target is None:
                raise ValueError("Mac rename requires its exact resulting placement")
            validate_macos_file_rename_records(record, self.target, replacement=self.replacement)
        elif self.target is not None or self.replacement is not None:
            raise ValueError("Only rename carries a target or replaced destination")
        if self.operation in {"rename", "unlink"}:
            if self.parent is None:
                raise ValueError("Mac rename/unlink requires explicit parent-directory facts")
            validate_macos_execution_directory(
                self.parent, hostname=self.parent.hostname, observed_at=self.observed_at
            )
            if (
                self.parent.hostname.casefold() != record.artifact.hostname.casefold()
                or self.parent.native_path != posixpath.dirname(record.artifact.native_path)
                or self.parent.metadata.volume_id != metadata.volume_id
                or self.parent.metadata.device != metadata.device
            ):
                raise ValueError(
                    "Mac file parent must be the exact same-volume containing directory"
                )
        elif self.parent is not None:
            raise ValueError("This bounded create/close observation does not include a directory")


@dataclass(frozen=True, slots=True)
class MacosFileRenameObservation:
    """Detached facts of one prepared rename, not permission to publish or commit.

    Source and replacement describe their pre-operation file versions; target
    describes the planned resulting source placement. These are not assertions
    about which stat instant a particular native collector reports. Directory
    metadata, later path observations and native destination tags remain separate.
    """

    source: LocalArtifactVersionRecord
    target: LocalArtifactVersionRecord
    replacement: LocalArtifactVersionRecord | None
    observed_at: datetime
    canonical_token: str

    def __post_init__(self) -> None:
        if (
            type(self.source) is not LocalArtifactVersionRecord
            or type(self.target) is not LocalArtifactVersionRecord
            or (
                self.replacement is not None
                and type(self.replacement) is not LocalArtifactVersionRecord
            )
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or type(self.canonical_token) is not str
            or len(self.canonical_token) != 64
            or any(character not in "0123456789abcdef" for character in self.canonical_token)
        ):
            raise ValueError(
                "Mac rename observation requires exact records, time and canonical token"
            )
        validate_macos_file_rename_records(self.source, self.target, replacement=self.replacement)


def validate_macos_file_rename_records(
    source: LocalArtifactVersionRecord,
    target: LocalArtifactVersionRecord,
    *,
    replacement: LocalArtifactVersionRecord | None = None,
) -> None:
    """Validate bounded canonical rename facts independently of publication authority."""
    records = (source, target) if replacement is None else (source, target, replacement)
    for record in records:
        if type(record) is not LocalArtifactVersionRecord:
            raise ValueError("Mac rename requires exact canonical file records")
        record.__post_init__()
    before, after = source.artifact, target.artifact
    old_stat, new_stat = source.macos_file, target.macos_file
    if (
        before.platform != "macos"
        or after.platform != "macos"
        or before.object_key != after.object_key
        or after.version <= before.version
        or source.content != target.content
        or source.launchd_job != target.launchd_job
        or old_stat is None
        or new_stat is None
        or old_stat.link_count != 1
        or new_stat.model_copy(update={"changed": old_stat.changed}) != old_stat
        or (new_stat.changed.seconds, new_stat.changed.nanoseconds)
        < (old_stat.changed.seconds, old_stat.changed.nanoseconds)
        or before.normalized_native_path == after.normalized_native_path
        or before.native_path != before.normalized_native_path
        or after.native_path != after.normalized_native_path
        or posixpath.dirname(before.normalized_native_path)
        != posixpath.dirname(after.normalized_native_path)
    ):
        raise ValueError("Mac rename requires one unchanged single-link file in one directory")
    expected_binary = (
        None
        if source.binary is None
        else replace(
            source.binary,
            artifact_version_id=after.artifact_version_id,
            artifact_name=posixpath.basename(after.native_path),
        )
    )
    if target.binary != expected_binary:
        raise ValueError("Mac rename must preserve executable content and signing facts")
    if replacement is not None:
        replaced = replacement.artifact
        replaced_stat = replacement.macos_file
        if (
            replaced.hostname != after.hostname
            or replaced.principal != after.principal
            or replaced.platform != "macos"
            or replaced.native_path != after.native_path
            or replaced.object_key == before.object_key
            or replaced_stat is None
            or replaced_stat.link_count != 1
            or replaced_stat.volume_id != old_stat.volume_id
            or replaced_stat.device != old_stat.device
            or replaced_stat.file_object_id == old_stat.file_object_id
            or replaced_stat.inode == old_stat.inode
        ):
            raise ValueError(
                "Mac rename replacement requires a distinct same-volume single-link destination"
            )
