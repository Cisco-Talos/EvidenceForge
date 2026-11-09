# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Occurrence-scoped installed executable placement and explicit filesystem facts."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    SoftwareInstallationIdentity,
    canonical_native_path,
)
from evidenceforge.events.macos_file import MacosFileMetadata, detach_file_metadata


@dataclass(frozen=True, slots=True)
class MacosInstalledFileObservation:
    """Join an installed release to explicit observed stat without deriving stat from hashes.

    Installation is a deployment fact; inode, allocation, times and permissions
    belong to the modeled filesystem producer. Neither a release nor its path
    supplies those missing facts. This observation owns no on-disk artifact.
    """

    installation: SoftwareInstallationIdentity
    binary: BinaryReleaseIdentity
    native_path: str
    observed_at: datetime
    metadata: MacosFileMetadata

    def __post_init__(self) -> None:
        if (
            type(self.installation) is not SoftwareInstallationIdentity
            or type(self.binary) is not BinaryReleaseIdentity
            or type(self.native_path) is not str
            or not self.native_path.startswith("/")
            or "\0" in self.native_path
            or ".." in PurePosixPath(self.native_path).parts
            or type(self.observed_at) is not datetime
            or self.observed_at.utcoffset() is None
            or self.installation.platform != "macos"
            or self.binary.key.platform != "macos"
            or self.binary.release_id != self.installation.release_id
            or canonical_native_path(self.native_path, "macos")
            not in self.installation.normalized_image_paths
            or PurePosixPath(self.native_path).name != self.binary.key.artifact_name
        ):
            raise ValueError("Installed Mac file requires exact release, placement and observation")
        object.__setattr__(self, "metadata", detach_file_metadata(self.metadata))
