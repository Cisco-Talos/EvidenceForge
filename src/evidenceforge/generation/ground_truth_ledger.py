"""Disk-backed canonical facts and exact-source observation reconciliation.

Only authored activity is retained in detail. SQLite indexes own duration-growing
history; checkpoint row deltas and streamed export keep Python retention bounded.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import sqlite3
import tempfile
import weakref
from collections import Counter, defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import TYPE_CHECKING

from pydantic import JsonValue

from evidenceforge._windows_cleanup import remove_owned_tree
from evidenceforge.events.ground_truth_occurrence import (
    GROUND_TRUTH_EVENTS_FILENAME,
    GroundTruthCoverageGap,
    GroundTruthEventStream,
    GroundTruthExpectationContract,
    GroundTruthExpectationSummary,
    GroundTruthObservation,
    GroundTruthOccurrence,
    GroundTruthOutcome,
    GroundTruthRawExpectation,
    GroundTruthRelationship,
    GroundTruthSensorView,
    GroundTruthSourceExpectation,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid

if TYPE_CHECKING:
    from evidenceforge.events.base import CanonicalOccurrence
    from evidenceforge.events.dispatcher import EventDispatcher, _PreparedProjection
    from evidenceforge.events.observation import ObservationPolicy
    from evidenceforge.generation.collection_deployment import CompiledCollectionDeployment
    from evidenceforge.generation.intent_ledger import AuthoredIntentLedger
    from evidenceforge.models import Scenario

logger = logging.getLogger(__name__)

_CONTEXT_FIELDS: dict[str, tuple[str, ...]] = {
    "src_host": ("hostname", "fqdn", "ip", "os_category", "roles"),
    "dst_host": ("hostname", "fqdn", "ip", "os_category", "roles"),
    "process": (
        "pid",
        "parent_pid",
        "image",
        "command_line",
        "username",
        "logon_id",
        "start_time",
        "concurrency_group_id",
        "process_guid",
        "hostname",
    ),
    "auth": (
        "username",
        "logon_id",
        "source_ip",
        "source_port",
        "result",
        "failure_reason",
        "failure_status",
        "failure_substatus",
        "auth_session_ref",
        "session_kind",
        "session_id",
        "logon_type",
        "auth_protocol",
    ),
    "network": (
        "stable_id",
        "hostname",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "service",
        "zeek_uid",
        "conn_state",
        "started_at",
        "closed_at",
        "initiating_pid",
        "responding_pid",
        "application_layer_only",
        "link_local",
    ),
    "dns": ("query", "query_type", "answers", "TTLs", "rcode", "rejected", "trans_id", "rtt"),
    "file": ("path", "action", "pid", "previous_path"),
    "registry": ("key", "value", "value_type", "action", "pid"),
    "firewall": ("action", "access_group", "src_interface", "dst_interface", "enforcing_entities"),
    "nat": (
        "nat_type",
        "mapped_src_ip",
        "mapped_src_port",
        "mapped_dst_ip",
        "mapped_dst_port",
        "pre_nat_dst_ip",
        "pre_nat_dst_port",
    ),
    "email": (
        "message_id",
        "envelope_from",
        "to",
        "cc",
        "bcc",
        "expanded_rcptto",
        "mail_action",
        "outcome",
        "verdict",
    ),
    "smtp": (
        "mailfrom",
        "rcptto",
        "msg_id",
        "last_reply",
        "path",
        "tls",
        "trans_depth",
        "encrypted_message",
    ),
    "smb": (
        "phase",
        "operation",
        "purpose",
        "result",
        "requested_access",
        "session_id",
        "tree_id",
        "share_ref",
        "client_path",
        "server_path",
        "file_id",
    ),
    "http": (
        "host",
        "uri",
        "method",
        "status_code",
        "status_msg",
        "response_body_len",
        "request_body_len",
        "trans_depth",
        "orig_fuids",
        "resp_fuids",
        "request_stream_offset",
        "response_stream_offset",
    ),
    "proxy": (
        "client_ip",
        "host",
        "url",
        "method",
        "status_code",
        "cache_result",
        "proxy_fqdn",
        "tunnel_status_code",
    ),
    "ssl": ("server_name", "version"),
}


def _is_domain(value: str) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return True
    return False


def _json_value(value: object) -> JsonValue:
    if isinstance(value, Enum):
        return _json_value(value.value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    raise TypeError(f"Unsupported ground-truth fact type: {type(value).__name__}")


def _facts(event: CanonicalOccurrence) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for name, names in _CONTEXT_FIELDS.items():
        owner = event.protocol if name in {"http", "proxy", "ssl"} else event
        context = getattr(owner, name, None)
        if context is not None:
            result[name] = {
                field: _json_value(getattr(context, field))
                for field in names
                if hasattr(context, field)
            }
    for name in (
        "smb",
        "remote_thread",
        "process_access",
        "image_load",
        "syslog",
        "shell",
        "service",
        "scheduled_task",
        "group_membership",
        "account_management",
        "kerberos",
        "dhcp",
        "ntp",
        "weird",
        "macos_workspace",
        "macos_policy_refusal",
        "macos_ssh_authentication",
    ):
        context = getattr(event, name, None)
        if context is not None and is_dataclass(context):
            result[name] = {
                field.name: _json_value(value)
                for field in fields(context)
                if isinstance(
                    value := getattr(context, field.name),
                    (str, int, float, bool, datetime, type(None)),
                )
            }
    for name in ("x509_chain", "pe_analyses"):
        contexts = getattr(event.protocol, name, ())
        if contexts:
            result[name] = [
                {
                    field.name: _json_value(value)
                    for field in fields(context)
                    if isinstance(
                        value := getattr(context, field.name),
                        (str, int, float, bool, datetime, type(None), tuple, list),
                    )
                }
                for context in contexts
            ]
            if name == "x509_chain":
                from evidenceforge.generation.activity.tls_realism import certificate_file_size

                for item, context in zip(result[name], contexts, strict=True):
                    item["file_size"] = certificate_file_size(context)
    if event.ids_alerts:
        result["ids_alerts"] = [
            {"sid": item.sid, "gid": item.gid, "message": item.message} for item in event.ids_alerts
        ]
    result["local_only"] = event.local_only
    result["storyline_cluster_id"] = event.storyline_cluster_id
    actor = event.identity_plan.actor if event.identity_plan is not None else None
    if isinstance(actor, ProcessIdentity):
        result["actor_process"] = {
            "pid": actor.pid,
            "image": actor.image,
            "hostname": actor.hostname,
            "principal": actor.principal,
            "object_id": actor.object_id,
            "execution_id": actor.execution_id,
            "start_time": actor.started_at.isoformat(),
        }
    endpoint = event.network_endpoint
    if endpoint is not None:
        result["network_endpoint"] = {
            "role": endpoint.role,
            "initiated": endpoint.initiated,
            "hostname": endpoint.local_hostname,
            "ip": endpoint.local_ip,
        }
    for name in ("macos_workspace", "macos_policy_refusal", "macos_ssh_authentication"):
        context = getattr(event, name, None)
        native = getattr(context, "native", None)
        if native is not None:
            writer = getattr(context, "writer", None)
            callsite = getattr(native, "callsite", None)
            result["unified_log"] = {
                "message": native.message,
                "writer_pid": writer.pid if writer is not None else 0,
                "subsystem": getattr(callsite, "subsystem", None),
                "category": getattr(callsite, "category", None),
            }
    if event.lifecycle is not None:
        result["lifecycle"] = {
            "group_id": event.lifecycle.group_id,
            "parent_group_id": event.lifecycle.parent_group_id,
            "canonical_start": event.lifecycle.canonical_start.isoformat(),
        }
    if event.network is not None:
        result["traffic"] = {
            direction: {
                "payload_bytes": getattr(event.network.traffic, direction).payload_bytes,
                "packets": getattr(event.network.traffic, direction).packets,
                "ip_bytes": getattr(event.network.traffic, direction).ip_bytes,
            }
            for direction in ("orig", "resp")
        }
        http = event.protocol.http
        capture = (
            http.capture_traffic
            if http is not None and http.capture_traffic is not None
            else event.network.traffic
        )
        result["capture"] = {
            "identity": (
                http.capture_transaction_id
                if http is not None and http.capture_transaction_id
                else event.network.stable_id
            ),
            "history": (
                http.capture_history
                if http is not None and http.capture_history
                else event.network.history
            ),
            "protocol": event.network.protocol,
            "traffic": {
                **{
                    direction: {
                        key: getattr(getattr(capture, direction), key)
                        for key in ("payload_bytes", "packets", "ip_bytes")
                    }
                    for direction in ("orig", "resp")
                },
                "missed_orig_bytes": capture.missed_orig_bytes,
                "missed_resp_bytes": capture.missed_resp_bytes,
            },
        }
    transfers = event.protocol.file_transfers
    if transfers:
        result["file_transfers"] = [
            {
                name: _json_value(getattr(transfer, name))
                for name in (
                    "fuid",
                    "source",
                    "filename",
                    "content_identity",
                    "is_orig",
                    "mime_type",
                    "seen_bytes",
                    "total_bytes",
                    "missing_bytes",
                    "md5",
                    "sha1",
                    "sha256",
                    "timedout",
                    "wire_offset",
                    "wire_length",
                    "entity_body_len",
                )
            }
            for transfer in transfers
        ]
    refusal = event.macos_policy_refusal
    subject = event.identity_plan.subject if event.identity_plan is not None else None
    if subject is not None:
        result["subject_identity"] = {"object_id": subject.object_id}
    if isinstance(subject, ProcessIdentity) and isinstance(result.get("process"), dict):
        result["process"]["object_id"] = subject.object_id
        result["process"]["execution_id"] = subject.execution_id
    if event.event_type in {
        "process_exec",
        "process_audit_bind",
        "process_privilege_drop",
        "process_service_drop",
        "process_job_control",
    }:
        from evidenceforge.events.process import (
            process_credential_identities,
            process_exec_identities,
            process_job_control_identities,
        )

        before, after = (
            process_exec_identities(event)
            if event.event_type == "process_exec"
            else process_job_control_identities(event)
            if event.event_type == "process_job_control"
            else process_credential_identities(event)
        )
        transition: dict[str, JsonValue] = {
            "operation": str(event.event_type).removeprefix("process_")
        }
        for prefix, identity in (("previous_", before), ("", after)):
            transition[prefix + "execution_id"] = identity.execution_id
            transition[prefix + "image_path"] = identity.image
            transition[prefix + "command_line"] = identity.command_line
            transition[prefix + "process_principal"] = identity.principal
            if identity.credentials is not None:
                for key in (
                    "real_uid",
                    "effective_uid",
                    "real_gid",
                    "effective_gid",
                    "audit_uid",
                    "audit_session_id",
                ):
                    transition[prefix + key] = getattr(identity.credentials, key)
            if identity.job_control is not None:
                transition[prefix + "process_group_id"] = identity.job_control.pgid
                transition[prefix + "posix_session_id"] = identity.job_control.session.sid
        result["process_transition"] = transition
    if refusal is not None:
        result["application_control"] = {
            "reason": "policy_refused",
            "cause": "unclassified",
            "stage": "unclassified",
        }
    return result


def _outcome(facts: dict[str, JsonValue]) -> GroundTruthOutcome:
    host = facts.get("dst_host") or facts.get("src_host") or {}
    enforcing = str(host.get("hostname", "")) if isinstance(host, dict) else None
    if facts.get("application_control"):
        return GroundTruthOutcome(
            result="prevented",
            mechanism="application_control",
            enforcing_entity=enforcing,
            operation="process_launch",
            stage="unclassified",
            reason="policy_refused",
        )
    for name, mechanism, field, prevented in (
        ("firewall", "firewall_policy", "action", {"deny"}),
        ("proxy", "proxy_policy", "cache_result", {"DENIED", "AUTH_REQUIRED"}),
        ("auth", "authentication_rejected", "result", {"failure"}),
        ("smb", "authorization", "result", {"ACCESS_DENIED", "access_denied"}),
    ):
        context = facts.get(name)
        if isinstance(context, dict) and context.get(field) in prevented:
            return GroundTruthOutcome(
                result="prevented",
                mechanism=mechanism,
                enforcing_entity=(
                    context.get("enforcing_entities", [None])[0]
                    if name == "firewall" and len(context.get("enforcing_entities", [])) == 1
                    else None
                    if name == "firewall"
                    else str(context.get("proxy_fqdn") or enforcing or "") or None
                ),
                operation=name,
                stage=(
                    "tunnel_establishment"
                    if context.get("method") == "CONNECT"
                    else "inspected_request"
                    if context.get("tunnel_status_code") == 200
                    else "request"
                ),
                reason=str(context.get("access_group") or context[field]),
            )
    email = facts.get("email")
    if isinstance(email, dict):
        action = email.get("mail_action")
        if action in {"reject", "quarantine", "strip_attachment"}:
            return GroundTruthOutcome(
                result="partial" if action == "strip_attachment" else "prevented",
                mechanism="mail_policy",
                enforcing_entity=enforcing,
                operation="email_delivery",
                stage="attachment_delivery" if action == "strip_attachment" else "delivery",
                reason=str(action),
            )
        if email.get("outcome") in {"bounced", "deferred", "rejected"}:
            return GroundTruthOutcome(
                result="failed", operation="email_delivery", reason=str(email["outcome"])
            )
    http = facts.get("http")
    if isinstance(http, dict) and http.get("status_code") in {401, 403}:
        return GroundTruthOutcome(
            result="prevented",
            mechanism="origin_authorization",
            enforcing_entity=enforcing,
            operation="http_request",
            stage="request",
            reason=f"http_{http['status_code']}",
        )
    smb = facts.get("smb")
    if isinstance(smb, dict) and smb.get("result") not in {None, "success"}:
        return GroundTruthOutcome(
            result="failed", operation="storage_access", reason=str(smb["result"])
        )
    if isinstance(http, dict) and int(http.get("status_code") or 0) >= 400:
        return GroundTruthOutcome(
            result="failed", operation="http_request", reason=f"http_{http['status_code']}"
        )
    network = facts.get("network")
    if isinstance(network, dict) and network.get("conn_state") in {"S0", "REJ", "RSTO", "RSTR"}:
        return GroundTruthOutcome(
            result="failed", operation="connection", reason=str(network["conn_state"])
        )
    dns = facts.get("dns")
    if isinstance(dns, dict) and (dns.get("rcode") == "REFUSED" or dns.get("rejected")):
        network = facts.get("network")
        return GroundTruthOutcome(
            result="prevented",
            mechanism="dns_request_refused",
            enforcing_entity=str(network["dst_ip"])
            if isinstance(network, dict) and network.get("dst_ip")
            else None,
            operation="dns_lookup",
            stage="resolver",
            reason="refused_cause_unclassified",
        )
    if isinstance(dns, dict) and dns.get("rcode") != "NOERROR":
        return GroundTruthOutcome(
            result="failed", operation="dns_lookup", reason=str(dns.get("rcode"))
        )
    return GroundTruthOutcome()


def _close_journal(connection: sqlite3.Connection, directory: Path) -> None:
    connection.close()
    remove_owned_tree(directory)


class GroundTruthLedger:
    """Idempotent journal of committed authored occurrences and source decisions."""

    tables = (
        "occurrences",
        "observations",
        "intent_results",
        "background_counts",
        "background_ids",
        "resolutions",
        "ownership",
        "resolution_uses",
        "resolution_requests",
        "expectations",
        "metadata",
    )

    def __init__(self, authored: AuthoredIntentLedger) -> None:
        self._failed = False
        self._expectation_planner = None
        self._intents = {intent.intent_id: intent for intent in authored.intents}
        directory = Path(tempfile.mkdtemp(prefix="eforge-ground-truth-"))
        self._db = sqlite3.connect(directory / "facts.sqlite", check_same_thread=False)
        self._cleanup = weakref.finalize(self, _close_journal, self._db, directory)
        self._lock = RLock()
        self._db.executescript("""
            CREATE TABLE occurrences (id TEXT PRIMARY KEY, intent TEXT NOT NULL,
                action TEXT NOT NULL, time TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX occurrence_intent ON occurrences(intent);
            CREATE INDEX occurrence_action ON occurrences(action);
            CREATE TABLE observations (occurrence TEXT NOT NULL, source TEXT NOT NULL,
                format TEXT NOT NULL, payload TEXT NOT NULL,
                UNIQUE(occurrence, source, format));
            CREATE TABLE intent_results (intent TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE expectations (occurrence TEXT PRIMARY KEY, payload TEXT NOT NULL, gaps TEXT NOT NULL, views TEXT NOT NULL);
            CREATE TABLE metadata (key TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE background_counts (kind TEXT PRIMARY KEY, count INTEGER NOT NULL);
            CREATE TABLE background_ids (id TEXT PRIMARY KEY);
            CREATE TABLE resolution_requests (client TEXT NOT NULL, domain TEXT NOT NULL,
                ip TEXT NOT NULL, time REAL NOT NULL, resolver TEXT NOT NULL, mode TEXT NOT NULL, used_by TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(client,domain,ip,time));
            CREATE TABLE resolution_uses (connection TEXT PRIMARY KEY, resolution TEXT NOT NULL, ip TEXT NOT NULL, mode TEXT NOT NULL, transport TEXT NOT NULL);
            CREATE INDEX resolution_used ON resolution_uses(resolution);
            CREATE TABLE ownership (entity TEXT PRIMARY KEY, intent TEXT NOT NULL);
            CREATE TABLE resolutions (id TEXT PRIMARY KEY, client TEXT NOT NULL,
                domain TEXT NOT NULL, time REAL NOT NULL, expires REAL NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX resolution_lookup ON resolutions(client,domain,time);
        """)

    def configure_expectations(
        self,
        scenario: Scenario,
        deployment: CompiledCollectionDeployment,
        policy: ObservationPolicy,
    ) -> None:
        """Bind immutable run inputs once; checkpoint metadata owns the durable snapshot."""
        from evidenceforge.generation.ground_truth_expectations import GroundTruthExpectationPlanner

        self._expectation_planner = GroundTruthExpectationPlanner(scenario, deployment, policy)
        self._db.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?,?)",
            (
                "expectation_contract",
                self._expectation_planner.contract.model_dump_json(),
            ),
        )

    def expectation_contract(self) -> GroundTruthExpectationContract | None:
        """Read the captured source policy contract, including after recovery."""
        row = self._db.execute(
            "SELECT payload FROM metadata WHERE key='expectation_contract'"
        ).fetchone()
        return GroundTruthExpectationContract.model_validate_json(row[0]) if row else None

    def expectation_summary(self) -> GroundTruthExpectationSummary:
        """Aggregate predictions while retaining detailed history only on disk."""
        totals: Counter[str] = Counter()
        sources: dict[str, Counter[str]] = defaultdict(Counter)
        reasons: Counter[str] = Counter()
        for payload, gaps in self._db.execute("SELECT payload,gaps FROM expectations"):
            totals["coverage_gaps"] += len(json.loads(gaps))
            for item in json.loads(payload):
                totals[item["expected"]] += 1
                sources[item["source_instance"] + "/" + item["format"]][item["expected"]] += 1
                if item["reason"]:
                    reasons[item["reason"]] += 1
        return GroundTruthExpectationSummary(
            present=totals["present"],
            absent=totals["absent"],
            coverage_gaps=totals["coverage_gaps"],
            by_source={key: dict(sorted(value.items())) for key, value in sorted(sources.items())},
            exclusion_reasons=dict(sorted(reasons.items())),
        )

    def capture_expectations(
        self,
        event: CanonicalOccurrence,
        projection: _PreparedProjection,
        dispatcher: EventDispatcher,
    ) -> bool:
        """Capture only retained authored consequences, after canonical commitment."""
        if self._expectation_planner is None:
            return False
        row = self._db.execute(
            "SELECT payload FROM occurrences WHERE id=?", (event.occurrence_id,)
        ).fetchone()
        if row is not None:
            facts = GroundTruthOccurrence.model_validate_json(row[0]).facts
            expected, gaps, views = self._expectation_planner.capture(
                event, projection, facts, dispatcher
            )
            self._db.execute(
                "INSERT OR REPLACE INTO expectations VALUES (?,?,?,?)",
                (
                    event.occurrence_id,
                    json.dumps([item.model_dump(mode="json") for item in expected], sort_keys=True),
                    json.dumps([item.model_dump(mode="json") for item in gaps], sort_keys=True),
                    json.dumps(
                        {key: value.model_dump(mode="json") for key, value in views.items()},
                        sort_keys=True,
                    ),
                ),
            )
        return True

    def checkpoint_connection(self) -> sqlite3.Connection:
        """Return the quiescent journal for the incremental SQLite adapter."""
        if self._failed:
            raise StateError("Cannot checkpoint an incomplete ground-truth publication")
        self._db.commit()
        return self._db

    def close(self) -> None:
        """Release the owned database before removing its private directory."""
        self._cleanup()

    def note_dns_resolution(
        self,
        *,
        client: str,
        domain: str,
        selected_ip: str,
        at: datetime,
        resolver: str,
        cached: bool,
    ) -> None:
        """Record actual lookup/cache consumption at the DNS action owner."""
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO resolution_requests(client,domain,ip,time,resolver,mode) VALUES (?,?,?,?,?,?)",
                (
                    client,
                    domain.lower().rstrip("."),
                    selected_ip,
                    at.timestamp(),
                    resolver,
                    "cache_hit" if cached else "lookup",
                ),
            )

    def record(
        self,
        event: CanonicalOccurrence,
        intent_id: str | None,
    ) -> None:
        """Retain canonical truth before collection decisions, without inventing evidence."""
        key = event.occurrence_key
        assert key is not None
        entities: list[str] = []
        message_entity = (
            "email:" + event.email.message_id
            if event.email is not None and event.email.message_id
            else None
        )
        if message_entity is not None:
            entities.append(message_entity)
        if event.lifecycle is not None:
            entities.append("lifecycle:" + event.lifecycle.group_id)
            if event.lifecycle.parent_group_id:
                entities.append("lifecycle:" + event.lifecycle.parent_group_id)
        if event.network is not None:
            entities.append("transport:" + event.network.stable_id)
        host = event.src_host or event.dst_host
        if event.process is not None and host is not None and event.process.start_time is not None:
            entities.append(
                f"process:{host.hostname}:{event.process.pid}:{event.process.start_time.isoformat()}"
            )
        if event.auth is not None and host is not None and event.auth.logon_id:
            if str(event.event_type) in {"logon", "logoff"}:
                entities.append(f"session:{host.hostname}:{event.auth.logon_id}")
        with self._lock:
            if event.dns is not None and event.network is not None:
                dns = event.dns
                ttl = max(dns.TTLs, default=0)
                payload = {
                    "occurrence_id": event.occurrence_id,
                    "query": dns.query,
                    "query_type": dns.query_type,
                    "answers": list(dns.answers),
                    "ttls": list(dns.TTLs),
                    "rcode": dns.rcode,
                    "resolver_ip": event.network.dst_ip,
                    "client_ip": event.network.src_ip,
                    "time": event.timestamp.isoformat(),
                }
                self._db.execute(
                    "INSERT OR IGNORE INTO resolutions VALUES (?,?,?,?,?,?)",
                    (
                        event.occurrence_id,
                        event.network.src_ip,
                        dns.query.lower().rstrip("."),
                        event.timestamp.timestamp(),
                        event.timestamp.timestamp() + ttl,
                        json.dumps(payload, sort_keys=True),
                    ),
                )
            self._bind_dns_use(event)
            # An independent background message may borrow an authored mail
            # client's process. Only that same message can inherit its intent;
            # shared process/action identity alone does not establish causation.
            independent_mail = event.email is not None and not event.email.storyline_id
            if intent_id is None and independent_mail and message_entity is not None:
                owner = self._db.execute(
                    "SELECT intent FROM ownership WHERE entity=?", (message_entity,)
                ).fetchone()
                intent_id = owner[0] if owner else None
            if intent_id is None and not independent_mail:
                previous = self._db.execute(
                    "SELECT intent FROM occurrences WHERE action=? LIMIT 1", (key.action_id,)
                ).fetchone()
                intent_id = previous[0] if previous else None
            if intent_id is None and not independent_mail:
                for entity in entities:
                    owner = self._db.execute(
                        "SELECT intent FROM ownership WHERE entity=?", (entity,)
                    ).fetchone()
                    if owner is not None:
                        intent_id = owner[0]
                        break
            if intent_id is None:
                # Bounded by EventKind cardinality, not event duration.
                inserted = self._db.execute(
                    "INSERT OR IGNORE INTO background_ids VALUES (?)", (event.occurrence_id,)
                ).rowcount
                if inserted:
                    self._db.execute(
                        "INSERT INTO background_counts VALUES (?,1) ON CONFLICT(kind) "
                        "DO UPDATE SET count=count+1",
                        (str(event.event_type),),
                    )
                return
            intent = self._intents.get(intent_id)
            if intent is None:
                raise StateError(f"Canonical occurrence names unknown authored intent {intent_id}")
            for entity in entities:
                # Observing a borrowed service process does not make all of its
                # later unrelated activity a consequence of this authored intent.
                if entity.startswith("process:") and str(event.event_type) not in {
                    "process_create",
                    "process_fork",
                    "process_exec",
                }:
                    continue
                if entity.startswith("session:") and str(event.event_type) != "logon":
                    continue
                if event.lifecycle is not None and entity == "lifecycle:" + str(
                    event.lifecycle.parent_group_id
                ):
                    continue
                self._db.execute(
                    "INSERT OR IGNORE INTO ownership VALUES (?,?)", (entity, intent_id)
                )
            facts = _facts(event)
            if isinstance(facts.get("firewall"), dict):
                facts["firewall"]["enforcing_entities"] = list(event.firewall.enforcing_entities)
            row = GroundTruthOccurrence(
                occurrence_id=event.occurrence_id,
                action_id=key.action_id,
                intent_id=intent_id,
                storyline_id=intent.step_id,
                section=intent.section.value,
                kind=str(event.event_type),
                time=event.timestamp,
                facts=facts,
                outcome=_outcome(facts),
            )
            self._db.execute(
                "INSERT OR IGNORE INTO occurrences VALUES (?,?,?,?,?)",
                (
                    row.occurrence_id,
                    intent_id,
                    row.action_id,
                    row.time.isoformat(),
                    row.model_dump_json(),
                ),
            )

    def _bind_dns_use(self, event: CanonicalOccurrence) -> None:
        network = event.network
        if (
            network is None
            or event.dns is not None
            or network.dst_port == 53
            or not network.hostname
        ):
            return
        if self._db.execute(
            "SELECT 1 FROM resolution_uses WHERE connection=?", (event.occurrence_id,)
        ).fetchone():
            return
        request = self._db.execute(
            "SELECT resolver,mode,time FROM resolution_requests WHERE client=? AND domain=? AND ip=? AND time<=? AND used_by='' ORDER BY time DESC LIMIT 1",
            (
                network.src_ip,
                network.hostname.lower().rstrip("."),
                network.dst_ip,
                event.timestamp.timestamp(),
            ),
        ).fetchone()
        if request is None:
            if network.application_layer_only:
                previous = self._db.execute(
                    "SELECT resolution FROM resolution_uses WHERE transport=? AND ip=? LIMIT 1",
                    (network.stable_id, network.dst_ip),
                ).fetchone()
                if previous is not None:
                    self._db.execute(
                        "INSERT OR IGNORE INTO resolution_uses VALUES (?,?,?,?,?)",
                        (
                            event.occurrence_id,
                            previous[0],
                            network.dst_ip,
                            "existing_transport",
                            network.stable_id,
                        ),
                    )
            return
        for resolution_id, payload in self._db.execute(
            "SELECT id,payload FROM resolutions WHERE client=? AND domain=? AND time<=? ORDER BY time DESC,id",
            (network.src_ip, network.hostname.lower().rstrip("."), request[2]),
        ):
            answer = json.loads(payload)
            if answer["resolver_ip"] == request[0] and network.dst_ip in answer["answers"]:
                self._db.execute(
                    "INSERT INTO resolution_uses VALUES (?,?,?,?,?)",
                    (
                        event.occurrence_id,
                        resolution_id,
                        network.dst_ip,
                        request[1],
                        network.stable_id,
                    ),
                )
                self._db.execute(
                    "UPDATE resolution_requests SET used_by=? WHERE client=? AND domain=? AND ip=? AND time=?",
                    (
                        event.occurrence_id,
                        network.src_ip,
                        network.hostname.lower().rstrip("."),
                        network.dst_ip,
                        request[2],
                    ),
                )
                return

    def observe(self, event: CanonicalOccurrence, observation: GroundTruthObservation) -> None:
        """Record the exact source decision; retries replace the same source row."""
        with self._lock:
            if self._db.execute(
                "SELECT 1 FROM occurrences WHERE id=?", (event.occurrence_id,)
            ).fetchone():
                self._db.execute(
                    "INSERT INTO observations VALUES (?,?,?,?) "
                    "ON CONFLICT(occurrence,source,format) DO UPDATE SET payload=excluded.payload",
                    (
                        event.occurrence_id,
                        observation.source_instance,
                        observation.format,
                        observation.model_dump_json(),
                    ),
                )

    def record_raw(self, intent_id: str, request: object, status: str) -> None:
        """Retain a source-local escape-hatch receipt without inventing an occurrence."""
        from evidenceforge.events.base import RawProjectionRequest

        if not isinstance(request, RawProjectionRequest):
            raise TypeError("Raw ground truth requires a RawProjectionRequest")
        payload = {
            "version": 1,
            "time": request.timestamp.isoformat(),
            "format": request.target_format,
            "fields": _json_value(request.data),
            "datetime_fields": [
                key for key, value in request.data.items() if isinstance(value, datetime)
            ],
            "status": status,
        }
        self._db.execute(
            "INSERT OR REPLACE INTO metadata VALUES (?,?)",
            (
                "raw:" + intent_id,
                GroundTruthRawExpectation.model_validate(payload).model_dump_json(),
            ),
        )

    def finish_intent(self, intent_id: str, result: dict | None, event_type: str) -> None:
        """Distinguish modeled attempts/no-ops from unexpected unexecuted intent."""
        reason = (result or {}).get("skipped_reason")
        if reason and reason not in {
            "workstation_already_locked",
            "native_job_control_evidence_unavailable",
            "outside_collection_window",
            "execution_denied_before_spawn",
            "exec_failed_caller_preserved",
        }:
            self._unfulfilled(intent_id, str(reason))
            raise StateError(f"Authored intent {intent_id} could not execute: {reason}")
        count = self._db.execute(
            "SELECT count(*) FROM occurrences WHERE intent=?", (intent_id,)
        ).fetchone()[0]
        if count == 0 and not reason and not (result or {}).get("outcome") and event_type != "raw":
            self._unfulfilled(intent_id, "no_occurrence_or_modeled_outcome")
            raise StateError(
                f"Authored intent {intent_id} produced no occurrence or modeled outcome"
            )
        outcome = (result or {}).get("outcome")
        payload = {
            "status": "modeled_outcome"
            if outcome or event_type == "raw"
            else "no_op"
            if reason
            else "completed",
            "reason": reason,
            "outcome": outcome,
        }
        self._db.execute(
            "INSERT OR REPLACE INTO intent_results VALUES (?,?)",
            (intent_id, json.dumps(payload, sort_keys=True)),
        )
        if outcome in {"denied", "exec_failed", "policy_refused"} and count == 0:
            intent = self._intents[intent_id]
            row = GroundTruthOccurrence(
                occurrence_id=stable_uuid("attempt", intent_id),
                action_id=stable_uuid("attempt-action", intent_id),
                intent_id=intent_id,
                storyline_id=intent.step_id,
                section=intent.section.value,
                kind="process_attempt",
                time=result["time"],
                facts={
                    "attempt": {
                        key: _json_value(result[key])
                        for key in ("process_name", "command_line", "refused_target_pid")
                        if key in result
                    }
                },
                outcome=GroundTruthOutcome(
                    result="failed" if outcome == "exec_failed" else "prevented",
                    mechanism="execution_failure"
                    if outcome == "exec_failed"
                    else "application_control",
                    enforcing_entity=intent.system,
                    operation="process_launch",
                    stage="unclassified",
                    reason=str(reason or outcome),
                ),
                observations=[
                    GroundTruthObservation(
                        source_instance="unavailable:endpoint",
                        format="endpoint",
                        status="not_observed",
                        reason="missing_capability",
                    )
                ],
            )
            self._db.execute(
                "INSERT OR IGNORE INTO occurrences VALUES (?,?,?,?,?)",
                (
                    row.occurrence_id,
                    intent_id,
                    row.action_id,
                    row.time.isoformat(),
                    row.model_dump_json(),
                ),
            )

        if (
            count == 0
            and outcome == "success"
            and reason == "native_job_control_evidence_unavailable"
        ):
            intent = self._intents[intent_id]
            row = GroundTruthOccurrence(
                occurrence_id=stable_uuid("job-control", intent_id),
                action_id=stable_uuid("job-control-action", intent_id),
                intent_id=intent_id,
                storyline_id=intent.step_id,
                section=intent.section.value,
                kind="job_control",
                time=result["time"],
                facts={
                    "job_control": {
                        key: _json_value(result[key])
                        for key in (
                            "launchd_operation",
                            "launchd_label",
                            "process_object_ids",
                            "file_path",
                        )
                        if key in result
                    }
                },
                observations=[
                    GroundTruthObservation(
                        source_instance="unavailable:endpoint",
                        format="endpoint",
                        status="not_observed",
                        reason="missing_capability",
                    )
                ],
            )
            self._db.execute(
                "INSERT OR IGNORE INTO occurrences VALUES (?,?,?,?,?)",
                (
                    row.occurrence_id,
                    intent_id,
                    row.action_id,
                    row.time.isoformat(),
                    row.model_dump_json(),
                ),
            )

    def _unfulfilled(self, intent_id: str, reason: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO intent_results VALUES (?,?)",
            (
                intent_id,
                json.dumps(
                    {"status": "not_executed", "reason": reason, "outcome": None}, sort_keys=True
                ),
            ),
        )

    def write_failure_diagnostics(self, root: Path) -> None:
        """Retain explicitly partial evidence without a success manifest."""
        missing = self._intents.keys() - self.intent_results().keys()
        for intent_id in sorted(missing):
            count = self._db.execute(
                "SELECT count(*) FROM occurrences WHERE intent=?", (intent_id,)
            ).fetchone()[0]
            self._db.execute(
                "INSERT INTO intent_results VALUES (?,?)",
                (
                    intent_id,
                    json.dumps(
                        {
                            "status": "interrupted" if count else "not_executed",
                            "reason": "run_interrupted_before_intent_completion",
                            "outcome": None,
                        },
                        sort_keys=True,
                    ),
                ),
            )
        reference = self.export(root)
        destination = root / "GROUND_TRUTH_DIAGNOSTICS.json"
        if destination.is_symlink():
            raise PermissionError("Refusing to write diagnostics through a symlink")
        destination.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "event_stream": reference.model_dump(mode="json"),
                    "intent_outcomes": self.intent_results(),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def intent_results(self) -> dict[str, dict]:
        """Return one bounded result per authored specification."""
        results = {
            key: json.loads(payload)
            for key, payload in self._db.execute(
                "SELECT intent,payload FROM intent_results ORDER BY intent"
            )
        }
        for key, payload in self._db.execute(
            "SELECT key,payload FROM metadata WHERE key LIKE 'raw:%'"
        ):
            if key[4:] in results:
                results[key[4:]]["raw_expectation"] = json.loads(payload)
        return results

    def mark_failed(self) -> None:
        """Fence success/checkpoint publication after a failed post-commit capture."""
        self._failed = True

    def assert_complete(self) -> None:
        """Fail successful finalization if any authored intent was never accounted for."""
        if self._failed:
            raise StateError("Canonical ground-truth capture failed; the run cannot complete")
        missing = self._intents.keys() - self.intent_results().keys()
        for intent_id in sorted(missing):
            self._unfulfilled(intent_id, "not_scheduled_or_executed")
        if missing:
            raise StateError(f"Authored intents were not executed: {', '.join(sorted(missing))}")

    def background_counts(self) -> dict[str, int]:
        """Return bounded unrelated-background summaries."""
        return dict(self._db.execute("SELECT kind,count FROM background_counts ORDER BY kind"))

    def summary(self, intent_id: str, event_type: str, root_pid: int | None = None) -> dict:
        """Project bounded factual summary fields from the committed occurrence journal."""
        count = self._db.execute(
            "SELECT count(*) FROM occurrences WHERE intent=?", (intent_id,)
        ).fetchone()[0]
        result: dict = {"canonical_occurrence_count": count}
        statuses: set[int] = set()
        destinations: set[str] = set()
        for (payload,) in self._db.execute(
            "SELECT payload FROM occurrences WHERE intent=? ORDER BY time,id", (intent_id,)
        ):
            row = GroundTruthOccurrence.model_validate_json(payload)
            network = row.facts.get("network")
            if (
                isinstance(network, dict)
                and not row.facts.get("dns")
                and network.get("dst_port") != 53
            ):
                if len(destinations) < 64:
                    destinations.add(str(network.get("dst_ip")))
                if (
                    network.get("hostname")
                    and _is_domain(str(network["hostname"]))
                    and "hostname" not in result
                ):
                    result["hostname"] = network["hostname"]
            http = row.facts.get("http")
            if isinstance(http, dict) and http.get("status_code") is not None:
                statuses.add(int(http["status_code"]))
            process = row.facts.get("process")
            if (
                event_type == "process"
                and row.kind in {"process_create", "process_exec"}
                and isinstance(process, dict)
                and root_pid is not None
                and process.get("pid") == root_pid
                and "pid" not in result
            ):
                result.update(
                    pid=process["pid"],
                    process_name=process["image"],
                    command_line=process["command_line"],
                )
        if statuses:
            result["http_statuses"] = sorted(statuses)
        if destinations:
            result["network_destinations"] = sorted(destinations)
            if event_type in {"connection", "beacon", "web_scan"} and len(destinations) == 1:
                result["dst_ip"] = next(iter(destinations))
        return result

    def rows(self) -> Iterator[GroundTruthOccurrence]:
        """Stream deterministic rows with observations and actual-use relationships."""
        for (payload,) in self._db.execute("SELECT payload FROM occurrences ORDER BY time,id"):
            row = GroundTruthOccurrence.model_validate_json(payload)
            captured = self._db.execute(
                "SELECT payload,gaps,views FROM expectations WHERE occurrence=?",
                (row.occurrence_id,),
            ).fetchone()
            if captured:
                row = row.model_copy(
                    update={
                        "source_expectations": [
                            GroundTruthSourceExpectation.model_validate(item)
                            for item in json.loads(captured[0])
                        ],
                        "coverage_gaps": [
                            GroundTruthCoverageGap.model_validate(item)
                            for item in json.loads(captured[1])
                        ],
                        "source_views": {
                            key: GroundTruthSensorView.model_validate(value)
                            for key, value in json.loads(captured[2]).items()
                        },
                    }
                )
            observations = [
                *row.observations,
                *[
                    GroundTruthObservation.model_validate_json(item[0])
                    for item in self._db.execute(
                        "SELECT payload FROM observations WHERE occurrence=? ORDER BY source,format",
                        (row.occurrence_id,),
                    )
                ],
            ]
            relations: list[GroundTruthRelationship] = []
            network = row.facts.get("network")
            if (
                isinstance(network, dict)
                and not row.facts.get("dns")
                and network.get("dst_port") != 53
            ):
                hostname = str(network.get("hostname") or "")
                relations.append(
                    GroundTruthRelationship(
                        kind="connection_attempt",
                        facts={
                            "domain": hostname if _is_domain(hostname) else None,
                            "attempted_ip": network.get("dst_ip"),
                            "client_ip": network.get("src_ip"),
                            "connection_uid": network.get("zeek_uid"),
                            "transport_id": network.get("stable_id"),
                        },
                    )
                )
                if hostname and _is_domain(hostname):
                    relations.append(
                        GroundTruthRelationship(
                            kind="connection_target",
                            facts={
                                "domain": hostname,
                                "selected_ip": network.get("dst_ip"),
                                "client_ip": network.get("src_ip"),
                                "connection_uid": network.get("zeek_uid"),
                            },
                        )
                    )
                    binding = self._db.execute(
                        "SELECT r.payload,u.ip,u.mode FROM resolutions r JOIN resolution_uses u ON u.resolution=r.id WHERE u.connection=?",
                        (row.occurrence_id,),
                    ).fetchone()
                    if binding is not None:
                        resolved = json.loads(binding[0])
                        relations.append(
                            GroundTruthRelationship(
                                kind="dns_answer_use",
                                facts={
                                    **resolved,
                                    "resolution_mode": binding[2],
                                    "selected_ip": binding[1],
                                    "connection_uid": network.get("zeek_uid"),
                                },
                            )
                        )
            dns = row.facts.get("dns")
            if isinstance(dns, dict):
                selected = [
                    item[0]
                    for item in self._db.execute(
                        "SELECT DISTINCT u.ip FROM resolution_uses u JOIN occurrences o ON o.id=u.connection WHERE u.resolution=? ORDER BY u.ip",
                        (row.occurrence_id,),
                    )
                ]
                relations.append(
                    GroundTruthRelationship(
                        kind="dns_answer_set",
                        facts={"answers": dns.get("answers", []), "used_answer_ips": selected},
                    )
                )
            process = row.facts.get("process")
            if isinstance(process, dict) and isinstance(network, dict):
                relations.append(
                    GroundTruthRelationship(
                        kind="process_network_owner",
                        facts={
                            "pid": process.get("pid"),
                            "image": process.get("image"),
                            "start_time": process.get("start_time"),
                            "host": row.facts.get("src_host"),
                            "connection_uid": network.get("zeek_uid"),
                        },
                    )
                )
            proxy = row.facts.get("proxy")
            if isinstance(proxy, dict):
                relations.append(
                    GroundTruthRelationship(
                        kind="proxy_request",
                        facts={
                            "client_ip": proxy.get("client_ip"),
                            "proxy_host": proxy.get("proxy_fqdn"),
                            "requested_origin": proxy.get("host"),
                            "url": proxy.get("url"),
                            "decision": proxy.get("cache_result"),
                            "transport": network,
                        },
                    )
                )
            nat = row.facts.get("nat")
            if isinstance(nat, dict) and isinstance(network, dict):
                relations.append(
                    GroundTruthRelationship(
                        kind="address_translation",
                        facts={
                            "canonical_transport_id": network.get("stable_id"),
                            "nat_type": nat.get("nat_type"),
                            "original": {
                                "src_ip": network.get("src_ip"),
                                "src_port": network.get("src_port"),
                                "dst_ip": nat.get("pre_nat_dst_ip") or network.get("dst_ip"),
                                "dst_port": nat.get("pre_nat_dst_port") or network.get("dst_port"),
                            },
                            "translated": {
                                "src_ip": nat.get("mapped_src_ip"),
                                "src_port": nat.get("mapped_src_port"),
                                "dst_ip": nat.get("mapped_dst_ip"),
                                "dst_port": nat.get("mapped_dst_port"),
                            },
                        },
                    )
                )
            smtp = row.facts.get("smtp")
            email = row.facts.get("email")
            if isinstance(email, dict):
                relations.append(
                    GroundTruthRelationship(
                        kind="recipient_delivery",
                        facts={
                            "message_id": email.get("message_id"),
                            "requested": {key: email.get(key, []) for key in ("to", "cc", "bcc")},
                            "expanded_recipients": email.get("expanded_rcptto", []),
                            "attempted_recipients": smtp.get("rcptto", [])
                            if isinstance(smtp, dict)
                            else [],
                            "smtp_reply": smtp.get("last_reply")
                            if isinstance(smtp, dict)
                            else None,
                            "message_outcome": email.get("outcome"),
                            "policy_action": email.get("mail_action"),
                        },
                    )
                )
            if isinstance(smtp, dict):
                relations.append(GroundTruthRelationship(kind="smtp_recipient_attempt", facts=smtp))
            yield row.model_copy(update={"observations": observations, "relationships": relations})

    def export(self, root: Path) -> GroundTruthEventStream:
        """Write detailed facts as a streamed deterministic integrity-bound sidecar."""
        self._db.commit()
        root.mkdir(parents=True, exist_ok=True)
        destination = root / GROUND_TRUTH_EVENTS_FILENAME
        if destination.is_symlink():
            raise PermissionError("Refusing to write ground truth through a symlink")
        digest = hashlib.sha256()
        count = 0
        with destination.open("wb") as stream:
            for row in self.rows():
                data = (
                    json.dumps(row.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
                    + "\n"
                ).encode()
                stream.write(data)
                digest.update(data)
                count += 1
        return GroundTruthEventStream(count=count, sha256=digest.hexdigest())
