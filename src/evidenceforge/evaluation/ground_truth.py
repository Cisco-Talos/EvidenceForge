"""Reconcile canonical consequences with independent parsed source records."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.ground_truth_occurrence import read_ground_truth_occurrences

logger = logging.getLogger(__name__)


def _pid(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16 if value.lower().startswith("0x") else 10)
        except ValueError:
            return None
    return None


def _endpoint_index(
    records: dict[str, list[ParsedRecord]],
) -> dict[tuple[str, str, int, str], list[ParsedRecord]]:
    result: dict[tuple[str, str, int, str], list[ParsedRecord]] = defaultdict(list)
    for format_name in ("ecar", "windows_event_security", "windows_event_sysmon"):
        for record in records.get(format_name, []):
            fields = record.fields
            kind = None
            if format_name == "ecar" and fields.get("object") == "PROCESS":
                kind = {"CREATE": "create", "TERMINATE": "terminate"}.get(fields.get("action"))
                if fields.get("action") == "MODIFY" and fields.get("operation") == "exec":
                    kind = "exec"
            elif format_name == "windows_event_security":
                kind = {4688: "create", 4689: "terminate"}.get(fields.get("EventID"))
            elif format_name == "windows_event_sysmon":
                kind = {1: "create", 5: "terminate"}.get(fields.get("EventID"))
            process_id = _pid(
                fields.get("NewProcessId") or fields.get("ProcessId") or fields.get("pid")
            )
            host = str(
                record.source_host
                or (
                    record.source_instance
                    if record.source_instance not in {None, "__direct__", "__artifact__"}
                    else None
                )
                or fields.get("hostname")
                or fields.get("Computer")
                or ""
            ).casefold()
            if kind and process_id is not None and not record.parse_errors:
                result[(format_name, host, process_id, kind)].append(record)
    return result


def _matching_endpoint(
    record: ParsedRecord, process: dict, format_name: str, observed_time: datetime | None
) -> bool:
    if observed_time is not None:
        if (
            record.timestamp is None
            or abs((record.timestamp - observed_time).total_seconds()) > 1.0
        ):
            return False
    fields = record.fields
    image = (
        fields.get("NewProcessName")
        or fields.get("Image")
        or fields.get("ProcessName")
        or fields.get("image_path")
    )
    if image != process.get("image"):
        return False
    if format_name == "ecar" and process.get("object_id"):
        return fields.get("objectID") == process["object_id"]
    return True


def reconcile_canonical_ground_truth(
    root: Path,
    document: GroundTruthDocument,
    records: dict[str, list[ParsedRecord]],
) -> tuple[set[str], list[str]]:
    """Reject missing consequences and mismatched observed network facts.

    Existing format and cross-source gates retain ownership of other native
    contracts. This check independently joins DNS/HTTP/transport consequences,
    including those produced by process actions rather than explicit connections.
    """
    invalid: set[str] = set()
    failures: list[str] = []
    expected = (
        {row.intent_id for row in document.intent_reconciliation.intents}
        if document.intent_reconciliation
        else set()
    )
    if document.event_stream is None:
        return expected, ["Schema-v4 ground truth has no canonical occurrence stream"]
    index: dict[tuple[str, str, str], list[ParsedRecord]] = defaultdict(list)
    endpoints = _endpoint_index(records)
    used_endpoints: set[int] = set()
    for format_name in ("zeek_conn", "zeek_http", "zeek_dns"):
        for record in records.get(format_name, []):
            if not record.parse_errors and record.fields.get("uid"):
                index[
                    (
                        format_name,
                        (record.source_host or record.source_instance or "").casefold(),
                        str(record.fields["uid"]),
                    )
                ].append(record)
    occurred: set[str] = set()
    try:
        for row in read_ground_truth_occurrences(root, document.event_stream):
            occurred.add(row.intent_id)
            if row.intent_id not in expected:
                invalid.update(expected)
                failures.append(f"Canonical occurrence has unexpected intent {row.intent_id}")
            network = row.facts.get("network")
            process = row.facts.get("process")
            phase = {
                "process_create": "create",
                "process_fork": "create",
                "process_exec": "exec",
                "process_terminate": "terminate",
            }.get(row.kind)
            if phase and isinstance(process, dict) and isinstance(process.get("pid"), int):
                for observation in row.observations:
                    if observation.status != "observed" or observation.format not in {
                        "ecar",
                        "windows_event_security",
                        "windows_event_sysmon",
                    }:
                        continue
                    aliases = {(observation.source_host or "").casefold()}
                    for key in ("src_host", "dst_host"):
                        host = row.facts.get(key)
                        if (
                            isinstance(host, dict)
                            and str(host.get("hostname") or "").casefold() in aliases
                        ):
                            if host.get("fqdn"):
                                aliases.add(str(host["fqdn"]).casefold())
                    candidates = [
                        record
                        for alias in aliases
                        for record in endpoints.get(
                            (observation.format, alias, process["pid"], phase), []
                        )
                    ]

                    matched = next(
                        (
                            record
                            for record in candidates
                            if id(record) not in used_endpoints
                            and _matching_endpoint(
                                record, process, observation.format, observation.observed_time
                            )
                        ),
                        None,
                    )
                    if matched is not None:
                        used_endpoints.add(id(matched))
                    else:
                        invalid.add(row.intent_id)
                        if len(failures) < 20:
                            failures.append(
                                f"Missing or inconsistent process consequence {row.occurrence_id} in {observation.source_instance}/{observation.format}"
                            )
            if not isinstance(network, dict):
                continue
            for observation in row.observations:
                if observation.status != "observed" or observation.format not in {
                    "zeek_conn",
                    "zeek_dns",
                    "zeek_http",
                }:
                    continue
                if observation.format == "zeek_conn" and network.get("application_layer_only"):
                    continue
                context_name = {"zeek_dns": "dns", "zeek_http": "http"}.get(observation.format)
                context = row.facts.get(context_name) if context_name else network
                if not isinstance(context, dict):
                    continue
                uid = observation.identifiers.get("zeek_uid", str(network.get("zeek_uid") or ""))
                candidates = index.get(
                    (observation.format, (observation.source_host or "").casefold(), uid), []
                )
                if observation.format == "zeek_http":
                    candidates = [
                        record
                        for record in candidates
                        if record.fields.get("method") == context.get("method")
                        and record.fields.get("uri") == context.get("uri")
                        and record.fields.get("trans_depth", 1) == context.get("trans_depth", 1)
                    ]
                    comparisons = {
                        key: context[key] for key in ("host", "status_code") if key in context
                    }
                elif observation.format == "zeek_dns":
                    candidates = [
                        record
                        for record in candidates
                        if record.fields.get("query") == context.get("query")
                    ]
                    comparisons = {"answers": context.get("answers", [])}
                else:
                    comparisons = {
                        key: observation.identifiers.get(field, network.get(field))
                        for key, field in (("id.orig_h", "src_ip"), ("id.resp_h", "dst_ip"))
                    }
                if not any(
                    all(
                        (record.fields.get(key) or []) == value
                        if key == "answers"
                        else record.fields.get(key) == value
                        for key, value in comparisons.items()
                    )
                    for record in candidates
                ):
                    invalid.add(row.intent_id)
                    if len(failures) < 20:
                        failures.append(
                            f"Missing or inconsistent canonical consequence {row.occurrence_id} in {observation.source_instance}/{observation.format}"
                        )
        for intent_id in expected - occurred:
            outcome = document.intent_outcomes.get(intent_id, {})
            if outcome.get("status") not in {"no_op", "modeled_outcome"}:
                invalid.add(intent_id)
                failures.append(f"Authored intent has no canonical occurrence: {intent_id}")
    except (OSError, ValueError) as exc:
        invalid.update(expected)
        failures.append(f"Invalid canonical ground truth: {exc}")
    return invalid, failures[:20]
