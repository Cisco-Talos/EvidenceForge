# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable loaded launchd definition, independent of later plist mutations."""

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from evidenceforge.events.content_identity import (
    LocalArtifactIdentity,
    RuntimeServiceDeploymentIdentity,
)
from evidenceforge.utils.rng import stable_uuid


def validate_launchd_label(label: str) -> str:
    """Require an exact label that cannot be confused with a domain target."""
    if not label or label != label.strip() or any(ord(char) < 32 for char in label):
        raise ValueError("Launchd label must be a nonempty exact label without control characters")
    if "/" in label or "\x7f" in label:
        raise ValueError("Launchd label cannot contain a domain separator or control character")
    return label


class LaunchdSystemJobSpec(BaseModel):
    """Bounded system-domain facts loaded from one authenticated file version.

    This is canonical runtime state, not an authored plist or a native artifact.
    Trigger scheduling and policy approval remain separate owners. The initial
    subset admits explicit activation and RunAtLoad only, without KeepAlive,
    sockets, timers, GUI domains or implicit shell interpretation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    label: str = Field(description="Exact native label in the system domain")
    program: str = Field(description="Absolute executable path, without shell expansion")
    arguments: tuple[str, ...] = Field(min_length=1, description="Exact argv, including argv[0]")
    principal: str = Field(description="Resolved execution principal, distinct from plist owner")
    run_at_load: bool = False

    @field_validator("label")
    @classmethod
    def exact_label(cls, value: str) -> str:
        return validate_launchd_label(value)

    @field_validator("program")
    @classmethod
    def absolute_program(cls, value: str) -> str:
        if not value.startswith("/") or "\x00" in value or value == "/":
            raise ValueError("Launchd program requires an absolute executable path")
        return value

    @field_validator("arguments")
    @classmethod
    def native_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value[0] or any("\x00" in argument for argument in value):
            raise ValueError("Launchd argv requires argv[0] and cannot contain NUL")
        return value

    @field_validator("principal")
    @classmethod
    def exact_principal(cls, value: str) -> str:
        if not value or value != value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Launchd execution requires an exact principal")
        return value


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
        return stable_uuid("macos-launchd-system-job", self.plist.hostname, self.label)

    @model_validator(mode="after")
    def matching_placement(self) -> "LaunchdSystemJobDefinition":
        if self.plist.platform != "macos" or self.plist.hostname != self.installation.hostname:
            raise ValueError("Loaded launchd definition requires a same-host Mac plist")
        if not self.plist.content_id or not self.plist.native_path.startswith("/"):
            raise ValueError(
                "Loaded launchd definition requires exact content and an absolute path"
            )
        if self.installation.canonical_name != f"macos-launchd-system:{self.logical_service_id}":
            raise ValueError("Loaded launchd installation must match its exact label")
        return self
