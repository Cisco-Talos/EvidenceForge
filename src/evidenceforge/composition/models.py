# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public models for authored scenario composition and resolved inputs."""

from __future__ import annotations

import re
from ipaddress import ip_address
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal, get_args, get_origin

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from evidenceforge.models.scenario import BaselineActivity, Environment, Persona, Scenario

PackSource = Literal["package", "project", "path"]
PackType = Literal["industry", "organization"]

PACK_SCHEMA_VERSION = "1.0"
RESOLVED_SCENARIO_KIND = "evidenceforge.resolved-scenario"
RESOLVED_SCENARIO_SCHEMA_VERSION = "1.0"

CATALOG_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]*$"
CATALOG_REFERENCE_PATTERN = r"^(?:[a-z0-9][a-z0-9-]*:)?[a-z0-9][a-z0-9_-]*$"
SEMVER_PATTERN = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"

CatalogId = Annotated[str, Field(pattern=CATALOG_ID_PATTERN)]
CatalogReference = Annotated[str, Field(pattern=CATALOG_REFERENCE_PATTERN)]
PublicServiceProtocol = Literal[
    "http",
    "https",
    "ssh",
    "smb",
    "smtp",
    "mssql",
    "mysql",
    "postgresql",
]

PUBLIC_SERVICE_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ssh": 22,
    "smb": 445,
    "smtp": 25,
    "mssql": 1433,
    "mysql": 3306,
    "postgresql": 5432,
}

PACK_COMMAND_PLACEHOLDERS = frozenset(
    {
        "doc_path",
        "document_name",
        "document_path",
        "document_term",
        "pdf_path",
        "spreadsheet_path",
        "username",
    }
)
PACK_DOCUMENT_PLACEHOLDERS = PACK_COMMAND_PLACEHOLDERS - {"username"}

STORAGE_MAX_DIRECTORIES = 128
STORAGE_MAX_SUBJECTS = 128
STORAGE_MAX_FILE_TYPES = 32
STORAGE_DIRECTORY_MAX_LENGTH = 128
STORAGE_SUBJECT_MAX_LENGTH = 64
STORAGE_EXTENSION_MAX_LENGTH = 16
STORAGE_MIME_MAX_LENGTH = 127

_STORAGE_RESERVED_DIRECTORY_CHARACTERS = frozenset('<>:"/\\|?*')
_STORAGE_MIME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$%&'*+.^_`|~-]*/"
    r"[A-Za-z0-9][A-Za-z0-9!#$%&'*+.^_`|~-]*$"
)
_STORAGE_CANONICAL_MIME_TYPES = {
    ".7z": "application/x-7z-compressed",
    ".csv": "text/csv",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".gz": "application/gzip",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".txt": "text/plain",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
    ".zip": "application/zip",
}


def _nonempty_unique_strings(values: list[str], field_name: str) -> list[str]:
    """Reject blank or duplicate strings in authored pack lists."""

    normalized = [value.strip() for value in values]
    if any(not value for value in normalized):
        raise ValueError(f"{field_name} cannot contain empty strings")
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field_name} cannot contain duplicate values")
    return normalized


def _validate_catalog_keys(values: dict[str, Any], field_name: str) -> dict[str, Any]:
    """Keep public catalog identities simple, local, and predictable."""

    invalid = sorted(key for key in values if re.fullmatch(CATALOG_ID_PATTERN, key) is None)
    if invalid:
        raise ValueError(
            f"{field_name} keys must be lowercase local IDs without colons: " + ", ".join(invalid)
        )
    return values


def _command_executable(command: str) -> str:
    """Return the leading executable token from one authored command."""

    stripped = command.strip()
    if not stripped:
        return ""
    if stripped[0] in {'"', "'"}:
        closing_quote = stripped.find(stripped[0], 1)
        if closing_quote < 2:
            raise ValueError("command executable has an unterminated quote")
        return stripped[1:closing_quote]
    return stripped.split(maxsplit=1)[0]


def _command_placeholders(command: str, field_name: str) -> set[str]:
    """Return supported placeholders while rejecting unknown or malformed braces."""

    placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", command))
    without_placeholders = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "", command)
    if "{" in without_placeholders or "}" in without_placeholders:
        raise ValueError(
            f"{field_name} contains malformed braces; use one supported {{placeholder}} token"
        )
    unknown = sorted(placeholders - PACK_COMMAND_PLACEHOLDERS)
    if unknown:
        raise ValueError(
            f"{field_name} contains unsupported command placeholder(s): {', '.join(unknown)}"
        )
    return placeholders


def _validate_native_executable(command: str, os_name: str, field_name: str) -> str:
    """Validate and return an OS-native command executable basename."""

    executable = _command_executable(command)
    if not executable or "{" in executable or "}" in executable:
        raise ValueError(f"{field_name} must begin with a concrete executable")
    if os_name == "windows":
        normalized = executable.replace("/", "\\")
        if "\\" in normalized and re.match(r"^[A-Za-z]:\\", normalized) is None:
            raise ValueError(f"{field_name} must use a Windows drive path or executable basename")
        basename = PureWindowsPath(normalized).name
        if PureWindowsPath(normalized).suffix.lower() not in {".bat", ".cmd", ".com", ".exe"}:
            raise ValueError(f"{field_name} must name a Windows executable")
        return basename.lower()

    if "\\" in executable or re.match(r"^[A-Za-z]:", executable):
        raise ValueError(f"{field_name} must use a POSIX executable")
    if "/" in executable and not executable.startswith(("/", "./")):
        raise ValueError(f"{field_name} must use an absolute, ./, or bare POSIX executable")
    basename = PurePosixPath(executable).name
    if PurePosixPath(executable).suffix.lower() in {".bat", ".cmd", ".com", ".exe"}:
        raise ValueError(f"{field_name} must not name a Windows executable on Linux")
    return basename


def _annotation_contains_model(annotation: Any) -> bool:
    """Return whether an annotation contains a nested Pydantic model."""

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return True
    return any(_annotation_contains_model(argument) for argument in get_args(annotation))


def _reject_unknown_fragment_fields(
    value: Any,
    annotation: Any,
    *,
    path: tuple[str, ...],
) -> None:
    """Reject unknown keys recursively before canonical models can discard them."""

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if not isinstance(value, dict):
            return
        unknown = sorted(set(value) - set(annotation.model_fields))
        if unknown:
            location = ".".join(path)
            raise ValueError(f"unknown field(s) at {location}: {', '.join(unknown)}")
        for field_name, field_value in value.items():
            _reject_unknown_fragment_fields(
                field_value,
                annotation.model_fields[field_name].annotation,
                path=(*path, field_name),
            )
        return

    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is list and isinstance(value, list) and arguments:
        for index, item in enumerate(value):
            _reject_unknown_fragment_fields(
                item,
                arguments[0],
                path=(*path, str(index)),
            )
        return
    if origin is dict and isinstance(value, dict) and len(arguments) == 2:
        for key, item in value.items():
            _reject_unknown_fragment_fields(
                item,
                arguments[1],
                path=(*path, str(key)),
            )
        return

    model_arguments = [argument for argument in arguments if _annotation_contains_model(argument)]
    if len(model_arguments) == 1:
        _reject_unknown_fragment_fields(value, model_arguments[0], path=path)


class _PackStrictEnvironment(Environment):
    """Pack-only Environment wrapper that forbids extras at every nested model."""

    @model_validator(mode="before")
    @classmethod
    def reject_nested_unknown_fields(cls, value: Any) -> Any:
        """Audit raw authored mappings before canonical Scenario 1 models parse them."""

        _reject_unknown_fragment_fields(value, Environment, path=("environment",))
        return value

    model_config = ConfigDict(extra="forbid")


class _PackStrictBaselineActivity(BaselineActivity):
    """Pack-only baseline wrapper that recursively forbids unknown fields."""

    @model_validator(mode="before")
    @classmethod
    def reject_nested_unknown_fields(cls, value: Any) -> Any:
        """Audit raw authored mappings before canonical baseline parsing."""

        _reject_unknown_fragment_fields(value, BaselineActivity, path=("baseline_activity",))
        return value

    model_config = ConfigDict(extra="forbid")


class PackReference(BaseModel):
    """An exact, persisted reference to one whole pack."""

    source: PackSource
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    version: str = Field(pattern=SEMVER_PATTERN)
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

    pack_schema_version: Literal["1.0"]
    type: PackType
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    version: str = Field(pattern=SEMVER_PATTERN)
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


class ProcessPeMetadata(BaseModel):
    """Source-native Windows PE identity for a custom process or loaded module."""

    file_version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    product: str = Field(min_length=1)
    company: str = Field(min_length=1)
    original_filename: str = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessLoadedModule(BaseModel):
    """One optional module in a custom Windows process profile."""

    path: str = Field(min_length=1)
    signed: bool = True
    signature: str | None = None
    signature_status: str | None = None
    pe_metadata: ProcessPeMetadata | None = None
    load_phase: Literal["startup", "runtime"] | None = None
    startup_probability: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("path")
    @classmethod
    def path_is_absolute_windows_path(cls, value: str) -> str:
        """Keep emitted module paths source-native and unambiguous."""

        normalized = value.replace("/", "\\")
        if re.match(r"^[A-Za-z]:\\", normalized) is None:
            raise ValueError("loaded module path must be an absolute Windows drive path")
        return normalized

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessPlatform(BaseModel):
    """One OS-specific implementation of a custom process."""

    image_path: str = Field(min_length=1)
    command_templates: list[str] = Field(min_length=1)
    pe_metadata: ProcessPeMetadata | None = None
    children: list[str] = Field(default_factory=list)
    loaded_modules: list[ProcessLoadedModule] = Field(default_factory=list)

    @field_validator("command_templates", "children")
    @classmethod
    def commands_are_nonempty_and_unique(cls, values: list[str], info: ValidationInfo) -> list[str]:
        """Reject command entries that would render blank or duplicate process evidence."""

        normalized = _nonempty_unique_strings(values, info.field_name)
        for command in normalized:
            _command_placeholders(command, info.field_name)
        return normalized

    model_config = ConfigDict(extra="forbid", frozen=True)


class CustomProcess(BaseModel):
    """A portable, typed executable definition owned by one process profile."""

    id: CatalogId
    display_name: str = Field(min_length=1)
    platforms: dict[Literal["windows", "linux"], ProcessPlatform] = Field(min_length=1)
    categories: list[Literal["user_app", "browser", "office", "code", "build", "query"]] = Field(
        min_length=1
    )
    system_types: list[Literal["workstation", "server", "domain_controller"]] | None = None
    selection_weight: int = Field(default=10, gt=0)
    singleton_per_session: bool = False

    @field_validator("categories", "system_types")
    @classmethod
    def enum_lists_are_unique(
        cls,
        values: list[str] | None,
        info: ValidationInfo,
    ) -> list[str] | None:
        """Reject repeated category and system-type declarations."""

        if values is not None and len(values) != len(set(values)):
            raise ValueError(f"{info.field_name} cannot contain duplicate values")
        return values

    @model_validator(mode="after")
    def validate_platform_contract(self) -> CustomProcess:
        """Require schedulable categories and source-native platform fields."""

        schedulable = {"user_app", "code", "build", "query"}
        if schedulable.isdisjoint(self.categories):
            raise ValueError(
                "custom process categories must include at least one schedulable category: "
                "user_app, code, build, or query"
            )
        windows = self.platforms.get("windows")
        if windows is not None:
            normalized = windows.image_path.replace("/", "\\")
            windows_path = PureWindowsPath(normalized)
            if (
                re.match(r"^[A-Za-z]:\\", normalized) is None
                or ".." in windows_path.parts
                or windows_path.suffix.lower() not in {".bat", ".cmd", ".com", ".exe"}
            ):
                raise ValueError("windows image_path must be an absolute Windows drive path")
            image_basename = windows_path.name.lower()
            for index, command in enumerate(windows.command_templates):
                command_basename = _validate_native_executable(
                    command,
                    "windows",
                    f"windows command_templates[{index}]",
                )
                if command_basename != image_basename:
                    raise ValueError(
                        "windows command_templates must launch the declared image_path executable"
                    )
            for index, command in enumerate(windows.children):
                _validate_native_executable(command, "windows", f"windows children[{index}]")
        linux = self.platforms.get("linux")
        if linux is not None:
            linux_path = PurePosixPath(linux.image_path)
            if (
                not linux.image_path.startswith("/")
                or "\\" in linux.image_path
                or ".." in linux_path.parts
                or linux_path.suffix.lower() in {".bat", ".cmd", ".com", ".exe"}
            ):
                raise ValueError("linux image_path must be an absolute POSIX path")
            if linux.pe_metadata is not None or linux.loaded_modules:
                raise ValueError("Linux process platforms cannot define Windows PE/module metadata")
            image_basename = linux_path.name
            for index, command in enumerate(linux.command_templates):
                command_basename = _validate_native_executable(
                    command,
                    "linux",
                    f"linux command_templates[{index}]",
                )
                if command_basename != image_basename:
                    raise ValueError(
                        "linux command_templates must launch the declared image_path executable"
                    )
            for index, command in enumerate(linux.children):
                _validate_native_executable(command, "linux", f"linux children[{index}]")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessCatalogData(BaseModel):
    """Runtime-effective process choices and scoped document terms for one workflow."""

    builtins: list[CatalogId] = Field(default_factory=list)
    custom: list[CustomProcess] = Field(default_factory=list)
    document_terms: list[str] = Field(default_factory=list)

    @field_validator("builtins")
    @classmethod
    def builtin_ids_are_nonempty_and_unique(cls, values: list[str]) -> list[str]:
        """Reject ambiguous or inert list entries."""

        return _nonempty_unique_strings(values, "builtins")

    @field_validator("document_terms")
    @classmethod
    def document_terms_are_safe(cls, values: list[str]) -> list[str]:
        """Keep data interpolated into commands safe as a bounded filename stem."""

        normalized = _nonempty_unique_strings(values, "document_terms")
        invalid = [
            value
            for value in normalized
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,63}", value) is None
        ]
        if invalid:
            raise ValueError(
                "document_terms must be 1-64 character safe filename stems using only "
                f"letters, digits, spaces, '_' or '-': {invalid}"
            )
        return normalized

    @model_validator(mode="after")
    def contains_a_process(self) -> ProcessCatalogData:
        """Every process profile must select at least one executable."""

        if not self.builtins and not self.custom:
            raise ValueError("process catalog data requires at least one of builtins or custom")
        custom_ids = [process.id for process in self.custom]
        if len(custom_ids) != len(set(custom_ids)):
            raise ValueError("custom process IDs must be unique within a process profile")
        if not self.document_terms:
            for process in self.custom:
                for platform in process.platforms.values():
                    for command in (*platform.command_templates, *platform.children):
                        if _command_placeholders(command, "command_templates") & (
                            PACK_DOCUMENT_PLACEHOLDERS
                        ):
                            raise ValueError(
                                "custom command document placeholders require non-empty "
                                "document_terms"
                            )
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProcessCatalogEntry(BaseModel):
    """One process-vocabulary export."""

    description: str = ""
    data: ProcessCatalogData = Field(default_factory=ProcessCatalogData)

    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationConnection(BaseModel):
    """One exact destination/service connection exposed by an application."""

    destination: CatalogReference
    service: CatalogId

    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationCatalogData(BaseModel):
    """Persona eligibility, process choices, and exact connections for an application."""

    personas: list[CatalogReference] = Field(min_length=1)
    processes: list[CatalogReference] = Field(min_length=1)
    connections: dict[CatalogId, ApplicationConnection] = Field(default_factory=dict)

    @field_validator("personas", "processes")
    @classmethod
    def references_are_unique(cls, values: list[str], info: ValidationInfo) -> list[str]:
        """Keep selection deterministic and diagnostics precise."""

        return _nonempty_unique_strings(values, info.field_name)

    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationCatalogEntry(BaseModel):
    """One application-family export."""

    description: str = ""
    data: ApplicationCatalogData

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationEndpoint(BaseModel):
    """One synthetic domain and its stable address pool."""

    domain: str = Field(min_length=1)
    ips: list[str] = Field(min_length=1)

    @field_validator("domain")
    @classmethod
    def domain_is_bare_hostname(cls, value: str) -> str:
        """Require a canonical bare DNS name rather than a URL or socket."""

        normalized = value.lower().rstrip(".")
        if (
            not normalized
            or "://" in normalized
            or any(character in normalized for character in "/: \t")
            or len(normalized) > 253
        ):
            raise ValueError("endpoint domain must be a bare hostname")
        labels = normalized.split(".")
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in labels
        ):
            raise ValueError(f"endpoint domain is not a valid hostname: {value!r}")
        return normalized

    @field_validator("ips")
    @classmethod
    def addresses_are_valid_and_unique(cls, values: list[str]) -> list[str]:
        """Normalize and validate stable IPv4/IPv6 address pools."""

        normalized: list[str] = []
        for value in values:
            try:
                normalized.append(str(ip_address(value)))
            except ValueError as exc:
                raise ValueError(f"invalid endpoint IP address: {value!r}") from exc
        if len(normalized) != len(set(normalized)):
            raise ValueError("endpoint IP address pool cannot contain duplicates")
        return normalized

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationService(BaseModel):
    """A typed service exposed by a destination, with a registry-backed default port."""

    protocol: PublicServiceProtocol
    port: int | None = Field(default=None, ge=1, le=65535)

    @property
    def resolved_port(self) -> int:
        """Return the authored override or public registry default."""

        return self.port or PUBLIC_SERVICE_DEFAULT_PORTS[self.protocol]

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationCatalogData(BaseModel):
    """Exact endpoint pools and typed services for one destination family."""

    tags: list[CatalogReference] = Field(default_factory=list)
    endpoints: list[DestinationEndpoint] = Field(min_length=1)
    services: dict[CatalogId, DestinationService] = Field(min_length=1)

    @field_validator("tags")
    @classmethod
    def tags_are_nonempty_and_unique(cls, values: list[str]) -> list[str]:
        """Keep DNS selection tags meaningful and deterministic."""

        return _nonempty_unique_strings(values, "tags")

    @model_validator(mode="after")
    def endpoints_are_unique(self) -> DestinationCatalogData:
        """Reject duplicate domain declarations inside one destination."""

        domains = [endpoint.domain for endpoint in self.endpoints]
        if len(domains) != len(set(domains)):
            raise ValueError("destination endpoint domains must be unique")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationCatalogEntry(BaseModel):
    """One external or internal destination-family export."""

    description: str = ""
    data: DestinationCatalogData = Field(default_factory=DestinationCatalogData)

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficConnection(BaseModel):
    """Low-level baseline connection escape hatch for processless/system traffic."""

    role: str = Field(default="_external", min_length=1)
    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"
    service: str | None = None
    weight: int = Field(default=1, ge=1)
    os: Literal["windows", "linux"] | None = None
    emit_dns: bool = False
    dns_tags: list[CatalogReference] = Field(default_factory=list)

    @field_validator("dns_tags")
    @classmethod
    def tags_are_nonempty_and_unique(cls, values: list[str]) -> list[str]:
        """Reject ambiguous low-level DNS selection tags."""

        return _nonempty_unique_strings(values, "dns_tags")

    @model_validator(mode="after")
    def dns_tags_require_dns(self) -> TrafficConnection:
        """Do not accept DNS-selection fields that generation would ignore."""

        if self.dns_tags and not self.emit_dns:
            raise ValueError("traffic connection dns_tags require emit_dns: true")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficApplicationBinding(BaseModel):
    """Weighted use of one named application connection."""

    application: CatalogReference
    connection: CatalogId
    weight: int = Field(default=1, gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


Weekday = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


class CadenceWindow(BaseModel):
    """One scenario-local wall-clock activity window, including cross-midnight windows."""

    start: str = Field(pattern=r"^\d{2}:\d{2}$")
    end: str = Field(pattern=r"^\d{2}:\d{2}$")

    @field_validator("start", "end")
    @classmethod
    def time_is_valid(cls, value: str) -> str:
        """Reject impossible wall-clock values while preserving canonical HH:MM text."""

        hour, minute = (int(part) for part in value.split(":"))
        if hour > 23 or minute > 59:
            raise ValueError("cadence window values must be valid HH:MM times")
        return value

    @model_validator(mode="after")
    def has_positive_duration(self) -> CadenceWindow:
        """Disallow ambiguous zero-length/full-day windows."""

        if self.start == self.end:
            raise ValueError("cadence window start and end must differ")
        return self

    @property
    def duration_minutes(self) -> int:
        """Return positive window duration, treating an earlier end as next day."""

        start_hour, start_minute = (int(part) for part in self.start.split(":"))
        end_hour, end_minute = (int(part) for part in self.end.split(":"))
        start_total = start_hour * 60 + start_minute
        end_total = end_hour * 60 + end_minute
        return (end_total - start_total) % (24 * 60)

    model_config = ConfigDict(extra="forbid", frozen=True)


def _default_cadence_windows() -> list[CadenceWindow]:
    """Return the existing weekday-business-hours window."""

    return [CadenceWindow(start="07:00", end="20:00")]


class _CadenceBase(BaseModel):
    """Fields shared by all structured persona-traffic cadences."""

    days: list[Weekday] = Field(default_factory=lambda: ["mon", "tue", "wed", "thu", "fri"])
    windows: list[CadenceWindow] = Field(default_factory=_default_cadence_windows, min_length=1)

    @field_validator("days")
    @classmethod
    def days_are_nonempty_and_unique(cls, values: list[str]) -> list[str]:
        """Require an unambiguous set of active weekdays."""

        if not values:
            raise ValueError("cadence days must not be empty")
        if len(values) != len(set(values)):
            raise ValueError("cadence days cannot contain duplicates")
        return values

    model_config = ConfigDict(extra="forbid", frozen=True)


class WeightedCadence(_CadenceBase):
    """Weighted stochastic placement within permitted local-time windows."""

    pattern: Literal["weighted"]


class PeriodicCadence(_CadenceBase):
    """Deterministic per-user interval anchors with bounded jitter."""

    pattern: Literal["periodic"]
    interval_minutes: int = Field(ge=5, le=1440)
    jitter_minutes: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def jitter_fits_interval(self) -> PeriodicCadence:
        """Keep periodic jitter within half the authored interval."""

        if self.jitter_minutes * 2 > self.interval_minutes:
            raise ValueError("periodic jitter_minutes cannot exceed half interval_minutes")
        return self


class BurstCadence(_CadenceBase):
    """A bounded number of events clustered inside each eligible window."""

    pattern: Literal["burst"]
    jitter_minutes: int = Field(default=0, ge=0)
    burst_count: tuple[int, int]

    @field_validator("burst_count")
    @classmethod
    def burst_count_is_positive_range(cls, value: tuple[int, int]) -> tuple[int, int]:
        """Require a positive ordered [minimum, maximum] range."""

        if len(value) != 2 or value[0] < 1 or value[1] < value[0] or value[0] > 50 or value[1] > 50:
            raise ValueError(
                "burst_count must be a positive [minimum, maximum] range with each bound <= 50"
            )
        return value

    @model_validator(mode="after")
    def jitter_fits_windows(self) -> BurstCadence:
        """Keep burst jitter within half of the shortest eligible window."""

        shortest_window = min(window.duration_minutes for window in self.windows)
        if self.jitter_minutes * 2 > shortest_window:
            raise ValueError("burst jitter_minutes cannot exceed half the shortest window")
        return self


TrafficCadence = Annotated[
    WeightedCadence | PeriodicCadence | BurstCadence,
    Field(discriminator="pattern"),
]


class TrafficCatalogData(BaseModel):
    """Runtime-effective application or low-level traffic for a persona audience."""

    audience: list[CatalogReference] = Field(min_length=1)
    applications: list[TrafficApplicationBinding] = Field(default_factory=list)
    outbound: list[TrafficConnection] = Field(default_factory=list)
    cadence: TrafficCadence | None = None

    @field_validator("audience")
    @classmethod
    def audience_is_unique(cls, values: list[str]) -> list[str]:
        """Reject duplicate persona selection."""

        return _nonempty_unique_strings(values, "audience")

    @model_validator(mode="after")
    def contains_runtime_traffic(self) -> TrafficCatalogData:
        """Require at least one runtime-effective traffic contribution."""

        if not self.applications and not self.outbound:
            raise ValueError("traffic catalog data requires applications or outbound")
        application_keys = [
            (binding.application, binding.connection) for binding in self.applications
        ]
        if len(application_keys) != len(set(application_keys)):
            raise ValueError("traffic application bindings must be unique")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficCatalogEntry(BaseModel):
    """One traffic-profile export."""

    description: str = ""
    data: TrafficCatalogData = Field(default_factory=TrafficCatalogData)

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageFileType(BaseModel):
    """One weighted file type in a storage vocabulary."""

    extension: str = Field(
        min_length=2,
        max_length=STORAGE_EXTENSION_MAX_LENGTH,
        pattern=r"^\.[A-Za-z0-9]+$",
    )
    mime: str = Field(min_length=3, max_length=STORAGE_MIME_MAX_LENGTH)
    weight: int = Field(default=1, ge=1)

    @field_validator("extension")
    @classmethod
    def normalize_extension(cls, value: str) -> str:
        """Normalize extensions so filesystem identity is case-insensitive."""

        return value.lower()

    @field_validator("mime")
    @classmethod
    def validate_mime_syntax(cls, value: str) -> str:
        """Require one parameter-free RFC token-style media type."""

        normalized = value.strip().lower()
        if _STORAGE_MIME_PATTERN.fullmatch(normalized) is None:
            raise ValueError("storage file MIME must use valid type/subtype syntax")
        return normalized

    @model_validator(mode="after")
    def enforce_known_extension_mime(self) -> StorageFileType:
        """Prevent familiar extensions from claiming a contradictory media type."""

        canonical_mime = _STORAGE_CANONICAL_MIME_TYPES.get(self.extension)
        if canonical_mime is not None and self.mime != canonical_mime:
            raise ValueError(
                f"storage extension {self.extension!r} requires canonical MIME {canonical_mime!r}"
            )
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageCatalogData(BaseModel):
    """Portable SMB corpus vocabulary adapted to storage profiles."""

    directories: list[str] = Field(min_length=1, max_length=STORAGE_MAX_DIRECTORIES)
    subjects: list[str] = Field(min_length=1, max_length=STORAGE_MAX_SUBJECTS)
    files: list[StorageFileType] = Field(min_length=1, max_length=STORAGE_MAX_FILE_TYPES)

    @field_validator("directories")
    @classmethod
    def directories_are_safe(cls, values: list[str]) -> list[str]:
        """Keep each directory as one bounded, relative filesystem component."""

        normalized: list[str] = []
        for value in values:
            directory = value.strip()
            if not directory:
                raise ValueError("storage directories cannot contain blank values")
            if len(directory) > STORAGE_DIRECTORY_MAX_LENGTH:
                raise ValueError(
                    f"storage directories cannot exceed {STORAGE_DIRECTORY_MAX_LENGTH} characters"
                )
            if any(ord(character) < 32 or ord(character) == 127 for character in directory):
                raise ValueError("storage directories cannot contain control characters")
            if (
                directory.startswith(("/", "\\"))
                or re.match(r"^[A-Za-z]:", directory)
                or directory in {".", ".."}
                or ".." in re.split(r"[/\\]", directory)
            ):
                raise ValueError(
                    "storage directories must be relative components without drive, UNC, or "
                    "traversal syntax"
                )
            if any(character in _STORAGE_RESERVED_DIRECTORY_CHARACTERS for character in directory):
                raise ValueError("storage directories cannot contain reserved path separators")
            if directory.endswith("."):
                raise ValueError("storage directories cannot end with a reserved period")
            normalized.append(directory)
        if len({value.casefold() for value in normalized}) != len(normalized):
            raise ValueError("storage directories cannot contain case-insensitive duplicates")
        return normalized

    @field_validator("subjects")
    @classmethod
    def subjects_are_safe(cls, values: list[str]) -> list[str]:
        """Keep generated file subjects as bounded, extension-free filename stems."""

        normalized = [value.strip() for value in values]
        invalid = [
            value
            for value in normalized
            if re.fullmatch(
                rf"[A-Za-z0-9][A-Za-z0-9 _-]{{0,{STORAGE_SUBJECT_MAX_LENGTH - 1}}}",
                value,
            )
            is None
        ]
        if invalid:
            raise ValueError(
                f"storage subjects must be 1-{STORAGE_SUBJECT_MAX_LENGTH} character safe "
                "filename stems using only letters, digits, spaces, '_' or '-'"
            )
        if len({value.casefold() for value in normalized}) != len(normalized):
            raise ValueError("storage subjects cannot contain case-insensitive duplicates")
        return normalized

    @model_validator(mode="after")
    def file_extensions_are_unique(self) -> StorageCatalogData:
        """Keep file selection unambiguous on case-insensitive filesystems."""

        extensions = [file_type.extension.casefold() for file_type in self.files]
        if len(extensions) != len(set(extensions)):
            raise ValueError("storage file extensions cannot contain case-insensitive duplicates")
        return self

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageCatalogEntry(BaseModel):
    """One storage corpus export."""

    description: str = ""
    data: StorageCatalogData

    model_config = ConfigDict(extra="forbid", frozen=True)


class PersonaCatalogDocument(BaseModel):
    """Predictable persona catalog file contract."""

    persona_catalog: dict[str, Persona] = Field(default_factory=dict)

    @field_validator("persona_catalog")
    @classmethod
    def keys_are_local_ids(cls, values: dict[str, Persona]) -> dict[str, Persona]:
        """Reject qualified or mixed-case authored catalog keys."""

        return _validate_catalog_keys(values, "persona_catalog")

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

    @field_validator("process_catalog")
    @classmethod
    def keys_are_local_ids(
        cls, values: dict[str, ProcessCatalogEntry]
    ) -> dict[str, ProcessCatalogEntry]:
        """Reject qualified or mixed-case authored catalog keys."""

        return _validate_catalog_keys(values, "process_catalog")

    model_config = ConfigDict(extra="forbid", frozen=True)


class ApplicationCatalogDocument(BaseModel):
    """Predictable application catalog file contract."""

    application_catalog: dict[str, ApplicationCatalogEntry] = Field(default_factory=dict)

    @field_validator("application_catalog")
    @classmethod
    def keys_are_local_ids(
        cls, values: dict[str, ApplicationCatalogEntry]
    ) -> dict[str, ApplicationCatalogEntry]:
        """Reject qualified or mixed-case authored catalog keys."""

        return _validate_catalog_keys(values, "application_catalog")

    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationCatalogDocument(BaseModel):
    """Predictable destination catalog file contract."""

    destination_catalog: dict[str, DestinationCatalogEntry] = Field(default_factory=dict)

    @field_validator("destination_catalog")
    @classmethod
    def keys_are_local_ids(
        cls, values: dict[str, DestinationCatalogEntry]
    ) -> dict[str, DestinationCatalogEntry]:
        """Reject qualified or mixed-case authored catalog keys."""

        return _validate_catalog_keys(values, "destination_catalog")

    model_config = ConfigDict(extra="forbid", frozen=True)


class TrafficCatalogDocument(BaseModel):
    """Predictable traffic catalog file contract."""

    traffic_catalog: dict[str, TrafficCatalogEntry] = Field(default_factory=dict)

    @field_validator("traffic_catalog")
    @classmethod
    def keys_are_local_ids(
        cls, values: dict[str, TrafficCatalogEntry]
    ) -> dict[str, TrafficCatalogEntry]:
        """Reject qualified or mixed-case authored catalog keys."""

        return _validate_catalog_keys(values, "traffic_catalog")

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageCatalogDocument(BaseModel):
    """Predictable storage catalog file contract."""

    storage_catalog: dict[str, StorageCatalogEntry] = Field(default_factory=dict)

    @field_validator("storage_catalog")
    @classmethod
    def keys_are_local_ids(
        cls, values: dict[str, StorageCatalogEntry]
    ) -> dict[str, StorageCatalogEntry]:
        """Reject qualified or mixed-case authored catalog keys."""

        return _validate_catalog_keys(values, "storage_catalog")

    model_config = ConfigDict(extra="forbid", frozen=True)


class EnvironmentFragment(BaseModel):
    """Partial organization environment merged before scenario-local fields."""

    environment: dict[str, Any] = Field(default_factory=dict)

    @field_validator("environment")
    @classmethod
    def validate_partial_environment(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Recursively validate every supplied field while allowing top-level omission."""

        identity = value.get("identity")
        identity_users = identity.get("users", {}) if isinstance(identity, dict) else {}
        synthetic_users = [
            {
                "username": username,
                "full_name": f"Pack validation user {username}",
                "email": f"{username.replace('$', '')}@pack-validation.invalid",
            }
            for username in identity_users
        ] or [
            {
                "username": "pack-validation",
                "full_name": "Pack Validation",
                "email": "pack-validation@pack-validation.invalid",
            }
        ]
        complete = {
            "description": "Pack fragment validation",
            "users": synthetic_users,
            "systems": [
                {
                    "hostname": "PACK-VALIDATION",
                    "ip": "192.0.2.254",
                    "os": "Windows 11",
                    "type": "workstation",
                }
            ],
            **value,
        }
        validated = _PackStrictEnvironment.model_validate(complete)
        return {field_name: getattr(validated, field_name) for field_name in value}

    model_config = ConfigDict(extra="forbid", frozen=True)


class BaselineActivityFragment(BaseModel):
    """Partial organization baseline merged before scenario-local fields."""

    baseline_activity: dict[str, Any] = Field(default_factory=dict)

    @field_validator("baseline_activity")
    @classmethod
    def validate_partial_baseline(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Recursively validate every supplied field while allowing top-level omission."""

        validated = _PackStrictBaselineActivity.model_validate(
            {
                "description": "Pack fragment validation",
                "intensity": "medium",
                "variation": "medium",
                **value,
            }
        )
        return {field_name: getattr(validated, field_name) for field_name in value}

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
    diagnostic_field_origins: dict[str, Path] = Field(
        default_factory=dict,
        exclude=True,
        repr=False,
        description=(
            "Process-local declaring files for diagnostics. Excluded from resolved artifacts "
            "and digests so absolute machine paths never enter authoritative documents."
        ),
    )

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
