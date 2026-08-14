# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public models for authored scenario composition and resolved inputs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.models.scenario import Persona, Scenario

PackSource = Literal["package", "project", "path"]
PackType = Literal["industry", "organization"]

PACK_SCHEMA_VERSION = "1.0"
RESOLVED_SCENARIO_KIND = "evidenceforge.resolved-scenario"
RESOLVED_SCENARIO_SCHEMA_VERSION = "1.0"


class PackReference(BaseModel):
    """An exact, persisted reference to one whole pack."""

    source: PackSource
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    path: str | None = None

    @model_validator(mode="after")
    def validate_source_path(self) -> PackReference:
        """Require a path only for explicit path references."""

        if self.source == "path" and not self.path:
            raise ValueError("path pack reference requires 'path'")
        if self.source != "path" and self.path is not None:
            raise ValueError("only source: path may define 'path'")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class IndustryDependency(PackReference):
    """An organization pack's exact industry dependency."""

    type: Literal["industry"] = "industry"


class CompositionSpec(BaseModel):
    """Optional Scenario 2.0 pack composition declaration."""

    industries: list[PackReference] = Field(default_factory=list)
    organization: PackReference | None = None

    @model_validator(mode="after")
    def choose_one_composition_mode(self) -> CompositionSpec:
        """Disallow mixing direct industries with an organization."""

        if self.industries and self.organization is not None:
            raise ValueError("composition may define industries or organization, not both")
        identities = [(ref.source, ref.name, ref.version, ref.path) for ref in self.industries]
        if len(identities) != len(set(identities)):
            raise ValueError("composition.industries contains a duplicate exact reference")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class PackManifest(BaseModel):
    """Stable manifest shared by industry and organization packs."""

    pack_schema_version: Literal["1.0"] = PACK_SCHEMA_VERSION
    type: PackType
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    requires_evidenceforge: str = Field(default=">=2.0.0,<3.0.0")
    description: str
    industry_dependencies: list[IndustryDependency] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_dependency_ownership(self) -> PackManifest:
        """Only organization packs can select industry dependencies."""

        if self.type == "industry" and self.industry_dependencies:
            raise ValueError("industry packs cannot declare industry_dependencies")
        identities = [
            (dependency.source, dependency.name, dependency.version, dependency.path)
            for dependency in self.industry_dependencies
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("industry_dependencies contains a duplicate exact reference")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessCatalogData(BaseModel):
    """Portable process and document vocabulary for one business workflow."""

    process_names: list[str] = Field(default_factory=list)
    document_terms: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessCatalogEntry(BaseModel):
    """One process-vocabulary export."""

    description: str = ""
    data: ProcessCatalogData = Field(default_factory=ProcessCatalogData)

    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationCatalogData(BaseModel):
    """Portable application-family metadata."""

    category: str
    protocols: list[Literal["http", "https", "ssh", "smb", "smtp", "database"]] = Field(
        default_factory=list
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationCatalogEntry(BaseModel):
    """One application-family export."""

    description: str = ""
    data: ApplicationCatalogData

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationEndpoint(BaseModel):
    """One synthetic domain and its stable address pool."""

    domain: str
    ips: list[str] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationCatalogData(BaseModel):
    """Portable destination-family metadata adapted to the DNS registry."""

    tags: list[str] = Field(default_factory=list)
    service: str | None = None
    endpoints: list[DestinationEndpoint] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationCatalogEntry(BaseModel):
    """One external or internal destination-family export."""

    description: str = ""
    data: DestinationCatalogData = Field(default_factory=DestinationCatalogData)

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficConnection(BaseModel):
    """Portable baseline connection shape for a persona."""

    role: str = "_external"
    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"
    service: str | None = None
    weight: int = Field(default=1, ge=1)
    emit_dns: bool = False
    dns_tags: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficCatalogData(BaseModel):
    """Portable persona traffic contribution."""

    audience: list[str] = Field(default_factory=list)
    cadence: str = ""
    outbound: list[TrafficConnection] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficCatalogEntry(BaseModel):
    """One traffic-profile export."""

    description: str = ""
    data: TrafficCatalogData = Field(default_factory=TrafficCatalogData)

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageFileType(BaseModel):
    """One weighted file type in a storage vocabulary."""

    extension: str = Field(pattern=r"^\.[A-Za-z0-9]+$")
    mime: str
    weight: int = Field(default=1, ge=1)

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageCatalogData(BaseModel):
    """Portable SMB corpus vocabulary adapted to storage profiles."""

    directories: list[str] = Field(min_length=1)
    subjects: list[str] = Field(min_length=1)
    files: list[StorageFileType] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageCatalogEntry(BaseModel):
    """One storage corpus export."""

    description: str = ""
    data: StorageCatalogData

    model_config = ConfigDict(extra="forbid", frozen=True)


class PersonaCatalogDocument(BaseModel):
    """Predictable persona catalog file contract."""

    persona_catalog: dict[str, Persona] = Field(default_factory=dict)

    @model_validator(mode="after")
    def keys_match_personas(self) -> PersonaCatalogDocument:
        """Keep the catalog key and exported persona identity aligned."""

        mismatches = [key for key, value in self.persona_catalog.items() if key != value.name]
        if mismatches:
            raise ValueError("persona_catalog keys must match each persona's name")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessCatalogDocument(BaseModel):
    """Predictable process catalog file contract."""

    process_catalog: dict[str, ProcessCatalogEntry] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationCatalogDocument(BaseModel):
    """Predictable application catalog file contract."""

    application_catalog: dict[str, ApplicationCatalogEntry] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationCatalogDocument(BaseModel):
    """Predictable destination catalog file contract."""

    destination_catalog: dict[str, DestinationCatalogEntry] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficCatalogDocument(BaseModel):
    """Predictable traffic catalog file contract."""

    traffic_catalog: dict[str, TrafficCatalogEntry] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageCatalogDocument(BaseModel):
    """Predictable storage catalog file contract."""

    storage_catalog: dict[str, StorageCatalogEntry] = Field(default_factory=dict)
    model_config = ConfigDict(extra="forbid", frozen=True)


class EnvironmentFragment(BaseModel):
    """Partial organization environment merged before scenario-local fields."""

    environment: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_unknown_environment_fields(self) -> EnvironmentFragment:
        """Reject typos while allowing a partial environment."""

        from evidenceforge.models.scenario import Environment

        unknown = sorted(set(self.environment) - set(Environment.model_fields))
        if unknown:
            raise ValueError("unknown environment field(s): " + ", ".join(unknown))
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class BaselineActivityFragment(BaseModel):
    """Partial organization baseline merged before scenario-local fields."""

    baseline_activity: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_unknown_baseline_fields(self) -> BaselineActivityFragment:
        """Reject typos while allowing a partial baseline."""

        from evidenceforge.models.scenario import BaselineActivity

        unknown = sorted(set(self.baseline_activity) - set(BaselineActivity.model_fields))
        if unknown:
            raise ValueError("unknown baseline_activity field(s): " + ", ".join(unknown))
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class ScenarioV1Document(BaseModel):
    """Explicit authored Scenario 1.0 document wrapper."""

    scenario: Scenario

    @model_validator(mode="after")
    def require_v1(self) -> ScenarioV1Document:
        """Keep this wrapper exclusive to the legacy authored contract."""

        if self.scenario.version != "1.0":
            raise ValueError("ScenarioV1Document requires version: '1.0'")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class ScenarioV2Document(BaseModel):
    """Validated Scenario 2.0 authored envelope before runtime compilation."""

    scenario_version: Literal["2.0"]
    composition: CompositionSpec = Field(default_factory=CompositionSpec)
    authored: dict[str, Any]

    model_config = ConfigDict(extra="forbid", frozen=True)


class EffectiveConfig(BaseModel):
    """Immutable, serializable configuration snapshot for one compilation."""

    project_root: str
    packaged_defaults: dict[str, Any] = Field(default_factory=dict)
    catalogs: dict[str, dict[str, Any]] = Field(default_factory=dict)
    project_overlays: dict[str, Any] = Field(default_factory=dict)
    families: dict[str, str] = Field(default_factory=dict)
    embedded_yaml_assets: dict[str, str] = Field(default_factory=dict)
    ambient_overlay_compat: bool = Field(
        default=False,
        description=(
            "Compatibility escape hatch for callers that construct Scenario directly instead "
            "of compiling an authored document."
        ),
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


class SelectedPack(BaseModel):
    """Resolved pack identity and integrity metadata."""

    source: PackSource
    type: PackType
    name: str
    version: str
    digest: str
    location: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class CompiledScenario(BaseModel):
    """Canonical runtime input plus all composition state for one run."""

    scenario: Scenario
    effective_config: EffectiveConfig
    assets: dict[str, str] = Field(default_factory=dict)
    selected_packs: tuple[SelectedPack, ...] = ()
    provenance: dict[str, Any] = Field(default_factory=dict)
    digests: dict[str, str] = Field(default_factory=dict)
    authored_kind: Literal["scenario-1.0", "scenario-2.0", "resolved"]

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)


class ResolvedScenarioDocument(BaseModel):
    """Self-contained authoritative generation input."""

    kind: Literal["evidenceforge.resolved-scenario"] = RESOLVED_SCENARIO_KIND
    schema_version: Literal["1.0"] = RESOLVED_SCENARIO_SCHEMA_VERSION
    generated: Literal[True] = True
    editable: Literal[False] = False
    scenario: dict[str, Any]
    effective_config: dict[str, Any]
    assets: dict[str, str] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    digests: dict[str, str] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", frozen=True)


class GenerationManifestDocument(BaseModel):
    """Authoritative generated-bundle identity and file-integrity contract."""

    kind: Literal["evidenceforge.generation-manifest"]
    schema_version: Literal["1.0"]
    created_at: str
    evidenceforge_version: str
    runtime: dict[str, str]
    scenario: str
    generation_seed: int = Field(ge=0, le=2**64 - 1)
    output_target: str
    formats: list[str]
    oob_hosts: list[str]
    overrides: dict[str, Any]
    selected_packs: list[SelectedPack]
    compiled_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resolved_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: dict[str, str]

    @model_validator(mode="after")
    def validate_file_hashes(self) -> GenerationManifestDocument:
        """Keep file names relative and hashes canonical."""

        invalid_paths = [
            path
            for path in self.files
            if Path(path).is_absolute() or ".." in Path(path).parts or path == ""
        ]
        invalid_hashes = [
            path for path, digest in self.files.items() if not re.fullmatch(r"[0-9a-f]{64}", digest)
        ]
        if invalid_paths:
            raise ValueError(f"manifest contains unsafe file path(s): {invalid_paths}")
        if invalid_hashes:
            raise ValueError(f"manifest contains invalid file hash(es): {invalid_hashes}")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)
