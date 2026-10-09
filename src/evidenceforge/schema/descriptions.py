"""Public authoring envelopes; all interfaces share these typed descriptions."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.naming import PACK_NAME_PATTERN, SCENARIO_NAME_PATTERN, DisplayName

from .contracts import VERSION_PATTERN, LifecycleMetadata, ParentReference


class ScenarioEnvelope(BaseModel):
    """Schema 3 root metadata, independent of existing scenario field models."""

    schema_version: Literal["3.0"] = "3.0"
    name: str = Field(min_length=1, pattern=SCENARIO_NAME_PATTERN)
    display_name: DisplayName | None = None
    description: str
    status: Literal["draft", "published"]
    draft_id: UUID | None = None
    publisher: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]*$")
    scenario_version: str | None = Field(default=None, pattern=VERSION_PATTERN)
    parents: list[ParentReference] = Field(default_factory=list)
    release_notes: str | None = Field(default=None, max_length=65536)
    configuration_context: str | None = None
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def lifecycle_contract(self) -> ScenarioEnvelope:
        LifecycleMetadata(
            status=self.status,
            draft_id=self.draft_id,
            publisher=self.publisher,
            version=self.scenario_version,
            parents=self.parents,
            release_notes=self.release_notes,
        )
        return self


class PackEnvelope(BaseModel):
    """Schema 3 authored manifest without internal draft namespace adapters."""

    pack_schema_version: Literal["3.0"] = "3.0"
    type: Literal["industry", "organization"]
    name: str = Field(pattern=PACK_NAME_PATTERN)
    display_name: DisplayName | None = None
    description: str
    requires_evidenceforge: str = ">=2.0.0,<3.0.0"
    status: Literal["draft", "published"]
    draft_id: UUID | None = None
    publisher: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]*$")
    publisher_display_name: str | None = None
    version: str | None = Field(default=None, pattern=VERSION_PATTERN)
    parents: list[ParentReference] = Field(default_factory=list)
    release_notes: str | None = Field(default=None, max_length=65536)
    configuration_context: str | None = None
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def lifecycle_contract(self) -> PackEnvelope:
        LifecycleMetadata(
            status=self.status,
            draft_id=self.draft_id,
            publisher=self.publisher,
            version=self.version,
            parents=self.parents,
            release_notes=self.release_notes,
        )
        return self
