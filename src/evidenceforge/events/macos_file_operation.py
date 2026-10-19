# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical before/after file-operation observations, separate from native exports."""

import posixpath
from dataclasses import dataclass, replace
from datetime import datetime

from evidenceforge.events.content_identity import LocalArtifactVersionRecord


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
