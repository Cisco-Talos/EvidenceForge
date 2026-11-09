# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Execution-owned references to existing canonical executable content versions."""

from dataclasses import dataclass
from typing import Literal

from evidenceforge.events.content_identity import BinaryReleaseIdentity, LocalArtifactBinaryIdentity


@dataclass(frozen=True, slots=True)
class ProcessExecutableVersion:
    """Retain the loaded image version independently of later path replacement.

    This reference owns no hashes or file placement. Existing deployment and
    runtime-content registries retain those facts. Absence means the execution's
    backing version was not established, not permission to resolve a newer path.
    """

    platform: Literal["windows", "linux", "macos"]
    identity_kind: Literal["installed_release", "local_artifact"]
    content_id: str
    artifact_version_id: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.platform) is not str
            or self.platform not in {"windows", "linux", "macos"}
            or type(self.identity_kind) is not str
            or self.identity_kind not in {"installed_release", "local_artifact"}
            or type(self.content_id) is not str
            or not self.content_id.strip()
            or len(self.content_id) > 256
            or "\0" in self.content_id
            or (self.identity_kind == "local_artifact") != (self.artifact_version_id is not None)
        ):
            raise ValueError("Process executable version requires an exact canonical reference")
        if self.artifact_version_id is not None and (
            type(self.artifact_version_id) is not str
            or not self.artifact_version_id.strip()
            or len(self.artifact_version_id) > 256
            or "\0" in self.artifact_version_id
        ):
            raise ValueError("Process executable version requires an exact artifact version")

    @classmethod
    def from_binary(
        cls, binary: BinaryReleaseIdentity | LocalArtifactBinaryIdentity
    ) -> "ProcessExecutableVersion":
        """Reference an already resolved image without deriving a content identity."""
        if type(binary) is BinaryReleaseIdentity:
            return cls(binary.key.platform, "installed_release", binary.content_id)
        if type(binary) is LocalArtifactBinaryIdentity:
            return cls(
                binary.platform, "local_artifact", binary.content_id, binary.artifact_version_id
            )
        raise ValueError("Process executable version requires an exact resolved binary")


def validate_process_executable_version(
    version: ProcessExecutableVersion | None, platform: str
) -> None:
    """Reject mismatched platform facts before process allocation or restoration."""
    if version is None:
        return
    if type(version) is not ProcessExecutableVersion:
        raise ValueError("Process executable version requires its exact immutable type")
    version.__post_init__()
    if version.platform != platform:
        raise ValueError("Process executable version belongs to another platform")
