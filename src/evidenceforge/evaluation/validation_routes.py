"""Explicit validation ownership for native logs and artifact parser sources."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.rules import Finding
from evidenceforge.models.exceptions import ConfigurationError, EvaluationError


class ValidationRoute(BaseModel):
    """Package-owned source validation contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str
    kind: Literal["native", "artifact"]
    validator: str


_NATIVE_SOURCES = (
    "bash_history",
    "cisco_asa",
    "ecar",
    "proxy_access",
    "snort_alert",
    "syslog",
    "web_access",
    "windows_event_security",
    "windows_event_sysmon",
    "zeek_conn",
    "zeek_dhcp",
    "zeek_dns",
    "zeek_files",
    "zeek_http",
    "zeek_ntp",
    "zeek_ocsp",
    "zeek_packet_filter",
    "zeek_pe",
    "zeek_reporter",
    "zeek_smb_files",
    "zeek_smb_mapping",
    "zeek_smtp",
    "zeek_ssl",
    "zeek_weird",
    "zeek_x509",
)
VALIDATION_ROUTES = tuple(
    ValidationRoute(source=name, kind="native", validator=name) for name in _NATIVE_SOURCES
) + (ValidationRoute(source="email_artifacts", kind="artifact", validator="email_manifest"),)


class EmailArtifact(BaseModel):
    """Known optional manifest fields; existing extension metadata remains supported."""

    # Artifact manifests have historically allowed extension metadata, unlike rule definitions.
    model_config = ConfigDict(extra="ignore", strict=True)
    message_id: str = ""
    sender: str = ""
    to: list[str] = []
    cc: list[str] = []
    bcc: list[str] = []
    subject: str = ""
    date: str = ""
    eml_path: str = ""
    artifact_export_status: str = ""
    artifact_export_reason: str = ""


def validate_email_artifact(record: ParsedRecord) -> list[Finding]:
    """Validate native manifest field types without requiring optional metadata."""
    try:
        EmailArtifact.model_validate(record.fields)
    except ValidationError as exc:
        return [
            Finding(
                rule_id="artifact.email.structure",
                format="email_artifacts",
                category="schema",
                fields=tuple(str(part) for part in error["loc"]),
                message=error["msg"],
            )
            for error in exc.errors(include_input=False)
        ]
    return []


ARTIFACT_VALIDATORS = {"email_manifest": validate_email_artifact}


def get_validation_route(source: str) -> ValidationRoute:
    """Reject unknown or ambiguous sources rather than silently omitting validation."""
    routes = [route for route in VALIDATION_ROUTES if route.source == source]
    if len(routes) != 1:
        raise ConfigurationError(
            f"Expected exactly one validation route for {source}; got {len(routes)}"
        )
    return routes[0]


def validate_route_inventory() -> None:
    """Check registry completeness and resolve every validation owner."""
    from evidenceforge.evaluation.parsers import _PARSER_CLASSES

    sources = {route.source for route in VALIDATION_ROUTES}
    if sources != set(_PARSER_CLASSES):
        raise ConfigurationError(
            f"Validation route/parser mismatch: {sorted(sources.symmetric_difference(_PARSER_CLASSES))}"
        )
    for source in sorted(sources):
        route = get_validation_route(source)
        if route.kind == "native":
            load_format(route.validator)
        elif route.validator not in ARTIFACT_VALIDATORS:
            raise ConfigurationError(f"Unknown artifact validator: {route.validator}")


def require_evaluated(finding: Finding) -> None:
    """Separate broken validation execution from invalid observed evidence."""
    if finding.outcome == "evaluation_error":
        raise EvaluationError(
            f"Rule {finding.rule_id} failed for source={finding.format} "
            f"variant={finding.variant or 'base'} fields={','.join(finding.fields)}: "
            f"{finding.message}"
        )
