# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded launchd file semantics independent of loaded runtime ownership."""

from hashlib import sha256
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)


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
    launch_profile: Literal["root_xpcproxy_v11"] | None = None
    launch_environment: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def native_preset_inputs(self) -> "LaunchdSystemJobSpec":
        """Keep this reference scoped to explicit root activation."""
        if self.launch_profile is not None and (self.principal != "root" or self.run_at_load):
            raise ValueError(
                "Native system-job preset requires root and explicit activation without RunAtLoad"
            )
        if self.launch_environment is not None and self.launch_profile is None:
            raise ValueError("Native launch environment requires an explicit launch profile")
        return self

    @model_serializer(mode="wrap")
    def preserve_legacy_definition(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, object]:
        """Keep the exact old file/content identity when no native preset is selected."""
        result = handler(self)
        if self.launch_profile is None:
            result.pop("launch_profile", None)
        if self.launch_environment is None:
            result.pop("launch_environment", None)
        return result

    @field_validator("launch_environment")
    @classmethod
    def literal_environment(cls, values: tuple[str, ...] | None) -> tuple[str, ...] | None:
        """Keep loaded file assignments exact, distinct and NUL-free."""
        if values is None:
            return None
        keys = [value.split("=", 1)[0] for value in values]
        if (
            not values
            or len(set(keys)) != len(keys)
            or any(
                "=" not in value
                or not key
                or "\0" in value
                or "{" in value
                or "}" in value
                or key in {"XPC_FLAGS", "XPC_SERVICE_NAME", "OSLogRateLimit"}
                for key, value in zip(keys, values, strict=True)
            )
        ):
            raise ValueError(
                "Native launchd environment requires distinct literal nonreserved assignments"
            )
        return values

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

    @property
    def content_seed(self) -> str:
        """Bind modeled file content to bounded semantics, excluding loaded placement."""
        spec = LaunchdSystemJobSpec(
            **{name: getattr(self, name) for name in LaunchdSystemJobSpec.model_fields}
        )
        return "launchd-spec:" + sha256(spec.model_dump_json().encode("utf-8")).hexdigest()
