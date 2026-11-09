# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable loaded launchd definition, independent of later plist mutations."""

from uuid import UUID

from pydantic import field_serializer, model_validator

from evidenceforge.events.content_identity import (
    LocalArtifactIdentity,
    RuntimeServiceDeploymentIdentity,
)
from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec as LaunchdSystemJobSpec
from evidenceforge.events.macos_launchd_spec import validate_launchd_label as validate_launchd_label


class LaunchdSystemJobDefinition(LaunchdSystemJobSpec):
    """One loaded spec bound to exact installation and canonical file content."""

    installation: RuntimeServiceDeploymentIdentity
    plist: LocalArtifactIdentity

    @field_serializer("installation")
    def installation_fields(self, value: RuntimeServiceDeploymentIdentity) -> dict[str, str]:
        """Serialize constructor facts; the identity discriminator is derived."""
        return {
            "hostname": value.hostname,
            "canonical_name": value.canonical_name,
            "action_id": value.action_id,
        }

    @property
    def logical_service_id(self) -> str:
        """Return the exact native namespace identity independent of installation."""
        return self.installation.canonical_name.removeprefix("macos-launchd-system:")

    @model_validator(mode="after")
    def matching_placement(self) -> "LaunchdSystemJobDefinition":
        if self.plist.platform != "macos" or self.plist.hostname != self.installation.hostname:
            raise ValueError("Loaded launchd definition requires a same-host Mac plist")
        if not self.plist.content_id or not self.plist.native_path.startswith("/"):
            raise ValueError(
                "Loaded launchd definition requires exact content and an absolute path"
            )
        if (
            not self.installation.canonical_name.startswith("macos-launchd-system:")
            or not self.logical_service_id
        ):
            raise ValueError("Loaded launchd installation requires a system-job logical identity")
        if str(UUID(self.logical_service_id)) != self.logical_service_id:
            raise ValueError("Loaded launchd logical identity must be a canonical UUID")
        return self
