# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Retained publication/removal times for one immutable runtime placement version."""

import posixpath
from dataclasses import dataclass, replace
from datetime import datetime

from evidenceforge.events.content_identity import LocalArtifactIdentity, LocalArtifactVersionRecord


@dataclass(frozen=True, slots=True)
class LocalArtifactPlacementObservation:
    """Canonical placement bounds, independent of loaded content retention.

    Older checkpoints may lack either bound. Out-of-order legacy publications
    may have contradictory bounds; they cannot establish historical presence.
    This describes one retained version, not a complete file-object path history.
    """

    artifact: LocalArtifactIdentity
    introduced_at: datetime | None
    withdrawn: bool
    withdrawn_at: datetime | None

    def __post_init__(self) -> None:
        if (
            type(self.artifact) is not LocalArtifactIdentity
            or type(self.withdrawn) is not bool
            or (not self.withdrawn and self.withdrawn_at is not None)
            or any(
                type(at) is not datetime or at.utcoffset() is None
                for at in (self.introduced_at, self.withdrawn_at)
                if at is not None
            )
        ):
            raise ValueError("Artifact placement requires an exact identity and known aware bounds")

    def present_at(self, timestamp: datetime) -> bool | None:
        """Return bounded presence, or unknown when retained facts do not establish it."""
        if type(timestamp) is not datetime or timestamp.utcoffset() is None:
            raise ValueError("Artifact placement observation requires an aware timestamp")
        if self.introduced_at is None or (self.withdrawn and self.withdrawn_at is None):
            return None
        if self.withdrawn_at is not None and self.withdrawn_at < self.introduced_at:
            return None
        return timestamp >= self.introduced_at and (
            self.withdrawn_at is None or timestamp < self.withdrawn_at
        )


@dataclass(frozen=True, slots=True)
class MacosRuntimeFilePlacementObservation:
    """One retained file object's known placement at a modeled event time.

    The reference preserves originally loaded bytes and identity. The placed
    record supplies the event-time name and explicit metadata. This detached
    value grants no publication authority and makes no native stat-time claim.
    Only unchanged single-link content is supported; missing history is unknown.
    """

    reference: LocalArtifactVersionRecord
    placed: LocalArtifactVersionRecord
    placement: LocalArtifactPlacementObservation
    observed_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.reference) is not LocalArtifactVersionRecord
            or type(self.placed) is not LocalArtifactVersionRecord
            or type(self.placement) is not LocalArtifactPlacementObservation
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
        ):
            raise ValueError("Mac file placement requires exact records and an aware time")
        before, after = self.reference, self.placed
        before.__post_init__()
        after.__post_init__()
        old_stat, new_stat = before.macos_file, after.macos_file
        expected_binary = (
            None
            if before.binary is None
            else replace(
                before.binary,
                artifact_version_id=after.artifact.artifact_version_id,
                artifact_name=posixpath.basename(after.artifact.native_path),
            )
        )
        if (
            before.artifact.platform != "macos"
            or after.artifact.platform != "macos"
            or before.artifact.object_key != after.artifact.object_key
            or after.artifact.version < before.artifact.version
            or before.content != after.content
            or before.launchd_job != after.launchd_job
            or after.binary != expected_binary
            or old_stat is None
            or new_stat is None
            or old_stat.link_count != 1
            or new_stat.model_copy(update={"changed": old_stat.changed}) != old_stat
            or (new_stat.changed.seconds, new_stat.changed.nanoseconds)
            < (old_stat.changed.seconds, old_stat.changed.nanoseconds)
            or before.artifact.native_path != before.artifact.normalized_native_path
            or after.artifact.native_path != after.artifact.normalized_native_path
            or posixpath.dirname(before.artifact.native_path)
            != posixpath.dirname(after.artifact.native_path)
            or self.placement.artifact != after.artifact
            or self.placement.present_at(self.observed_at) is not True
        ):
            raise ValueError("Mac file placement requires one unchanged retained single-link file")
