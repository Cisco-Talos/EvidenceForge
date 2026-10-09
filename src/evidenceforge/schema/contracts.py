"""Identify document families before interpreting their version fields."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.models.exceptions import SchemaValidationError
from evidenceforge.naming import validate_display_name

ReleaseVersion = str
VERSION_PATTERN = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"
PUBLISHER_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
LIFECYCLE_FIELDS = frozenset(
    {"status", "draft_id", "publisher", "parents", "release_notes", "configuration_context"}
)


class ParentReference(BaseModel):
    """Exact ancestry; resolving an ancestor is never required to use a release."""

    kind: Literal["scenario", "industry", "organization"]
    publisher: str | None = Field(default=None, pattern=PUBLISHER_PATTERN)
    name: str = Field(min_length=1)
    version: str | None = Field(default=None, pattern=VERSION_PATTERN)
    draft_id: UUID | None = None
    source_schema_version: Literal["1.0", "2.0"] | None = None
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def exact_identity(self) -> ParentReference:
        if (
            self.draft_id is None
            and self.source_schema_version is None
            and (self.publisher is None or self.version is None)
        ):
            raise ValueError("a release parent requires publisher and exact X.Y.Z version")
        return self


class LifecycleMetadata(BaseModel):
    """Schema 3 lifecycle envelope, separate from generation-relevant fields."""

    status: Literal["draft", "published"]
    draft_id: UUID | None = None
    publisher: str | None = Field(default=None, pattern=PUBLISHER_PATTERN)
    version: str | None = Field(default=None, pattern=VERSION_PATTERN)
    parents: list[ParentReference] = Field(default_factory=list)
    release_notes: str | None = Field(default=None, max_length=65536)
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_state(self) -> LifecycleMetadata:
        if self.status == "draft" and self.draft_id is None:
            raise ValueError("drafts require a unique draft_id")
        if self.status == "published":
            if self.publisher is None or self.version is None:
                raise ValueError("published artifacts require publisher and exact X.Y.Z version")
            if self.draft_id is not None:
                raise ValueError("published artifacts cannot retain a draft_id")
        return self


class DocumentContract(BaseModel):
    """Family and envelope inspection; intentionally independent of semantic validity."""

    family: Literal["scenario", "pack", "resolved", "generated", "configuration", "fragment"]
    schema_version: str | None = None
    marker: str | None = None
    lifecycle: LifecycleMetadata | None = None
    upgrade_available: bool = False
    model_config = ConfigDict(extra="forbid", frozen=True)


def _lifecycle(data: dict[str, Any], version_field: str) -> LifecycleMetadata:
    from pydantic import ValidationError

    try:
        if data.get("display_name") is not None:
            if not isinstance(data["display_name"], str):
                raise ValueError("display_name must be text")
            validate_display_name(data["display_name"])
        return LifecycleMetadata.model_validate(
            {
                **{
                    key: data[key]
                    for key in LIFECYCLE_FIELDS
                    if key in data and key != "configuration_context"
                },
                "version": data.get(version_field),
            }
        )
    except (ValidationError, ValueError) as exc:
        raise SchemaValidationError(f"invalid lifecycle metadata: {exc}") from exc


def identify_document(data: dict[str, Any]) -> DocumentContract:
    """Inspect by family, then presence precedence; invalid markers never fall through."""

    kind = data.get("kind")
    if kind == "evidenceforge.resolved-scenario":
        return DocumentContract(family="resolved", schema_version=data.get("schema_version"))
    if data.get("generated") is True or (
        isinstance(kind, str) and kind.startswith("evidenceforge.")
    ):
        return DocumentContract(family="generated")
    if "pack_schema_version" in data:
        version = data["pack_schema_version"]
        if version not in ("2.0", "3.0"):
            raise SchemaValidationError(
                f"unsupported pack_schema_version {version!r}; use 2.0 or 3.0"
            )
        return DocumentContract(
            family="pack",
            schema_version=version,
            marker="pack_schema_version",
            lifecycle=_lifecycle(data, "version") if version == "3.0" else None,
            upgrade_available=version == "2.0",
        )
    if any(
        key in data
        for key in (
            "context_version",
            "context_schema_version",
            "publisher_schema_version",
            "lock_schema_version",
        )
    ):
        return DocumentContract(family="configuration")
    # An environment fragment or a generic versioned configuration is not a scenario root.
    if "name" not in data or not (
        any(key in data for key in ("environment", "composition", "includes"))
        or "schema_version" in data
        and "status" in data
    ):
        return DocumentContract(family="fragment")
    marker = next(
        (key for key in ("schema_version", "scenario_version", "version") if key in data), None
    )
    version = data[marker] if marker else "1.0"
    if not isinstance(version, str) or version not in ("1.0", "2.0", "3.0"):
        raise SchemaValidationError(
            f"unsupported {marker or 'schema version'} {version!r}; use 1.0, 2.0 or 3.0"
        )
    if version == "3.0" and marker != "schema_version":
        raise SchemaValidationError("Scenario 3.0 requires schema_version: '3.0'")
    if version == "3.0" and "version" in data:
        raise SchemaValidationError(
            "Scenario 3.0 uses scenario_version for the release; remove version"
        )
    if version == "2.0" and "version" in data:
        raise SchemaValidationError("Scenario 2.0 cannot define the legacy version field")
    for lower in ("scenario_version", "version"):
        if version != "3.0" and lower in data and data[lower] != version:
            raise SchemaValidationError(
                f"conflicting scenario schema markers: {marker} and {lower}"
            )
    return DocumentContract(
        family="scenario",
        schema_version=version,
        marker=marker,
        lifecycle=_lifecycle(data, "scenario_version") if version == "3.0" else None,
        upgrade_available=version in ("1.0", "2.0"),
    )


def scenario_payload(data: dict[str, Any], contract: DocumentContract) -> dict[str, Any]:
    """Strip envelope fields before existing composition and runtime field validation."""

    removed = {"schema_version", "scenario_version", "version"}
    if contract.schema_version == "3.0":
        removed |= LIFECYCLE_FIELDS | {"display_name"}
    return {key: value for key, value in data.items() if key not in removed}
