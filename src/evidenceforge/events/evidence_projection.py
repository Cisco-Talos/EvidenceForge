"""Declarative canonical-to-source evidence contracts, without rendering or RNG."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from evidenceforge.config.provider import _register_trusted_derived_cache
from evidenceforge.events.collection_policy import CollectionCapability
from evidenceforge.events.contracts import contract_for
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind


class NativeEvidenceRequirement(BaseModel):
    """One primary source row and its required semantic facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    selector: dict[str, JsonValue] = Field(default_factory=dict)
    required: dict[str, JsonValue] = Field(default_factory=dict)
    contains: list[str] = Field(default_factory=list)
    minimum: int = Field(default=1, ge=1)
    maximum: int | None = Field(default=1, ge=1)
    timing: Literal["point", "transport_close", "interval"] = "point"
    expected: Literal["present", "absent"] = "present"


@lru_cache(maxsize=1)
def source_event_contracts() -> dict:
    """Read the package-owned versioned semantic selector table."""
    from evidenceforge.config import get_evaluation_directory
    from evidenceforge.utils.yaml_loader import load_yaml_text

    # Semantic verification is engine policy. A captured generation configuration
    # must not restore an older verifier or hide newly recognized consequences.
    path = get_evaluation_directory() / "ground_truth_contracts.yaml"
    return load_yaml_text(path.read_text(), source=str(path))


_register_trusted_derived_cache(
    __name__, "source_event_contracts", globals(), source_event_contracts
)


def candidate_formats(kind: str, facts: dict) -> set[str]:
    """Return semantically applicable formats before deployment/output exclusions."""
    contract = contract_for(kind)
    formats = {item.value for item in contract.emitter_consumers} if contract else set()
    network = facts.get("network") or {}
    if kind == "logoff" and not (
        facts.get("syslog")
        and any(
            (facts.get(name) or {}).get("os_category") == "linux"
            for name in ("src_host", "dst_host")
        )
    ):
        formats.discard("syslog")
    for name in tuple(formats):
        if name.startswith("zeek_"):
            context = name.removeprefix("zeek_")
            needed = {
                "conn": bool(network) and not network.get("application_layer_only"),
                "files": bool(facts.get("file_transfers") or facts.get("x509_chain")),
                "smb_files": bool(facts.get("smb")),
                "smb_mapping": bool(facts.get("smb")),
                "x509": bool(facts.get("x509_chain")),
                "pe": bool(facts.get("pe_analyses")),
            }.get(context, bool(facts.get(context)))
            if not needed:
                formats.discard(name)
        elif name == "snort_alert" and not facts.get("ids_alerts"):
            formats.discard(name)
        elif name == "cisco_asa" and not (facts.get("firewall") or network):
            formats.discard(name)
        elif name == "proxy_access" and not facts.get("proxy"):
            formats.discard(name)
        elif name == "web_access" and not facts.get("http"):
            formats.discard(name)
        elif name in {"ecar", "windows_event_security", "windows_event_sysmon"}:
            if (
                kind not in source_event_contracts()[name]
                and not (name == "windows_event_sysmon" and facts.get("dns"))
                and not (name == "windows_event_security" and facts.get("smb"))
            ):
                formats.discard(name)
    return formats


def host_routes(format_name: str, kind: str, facts: dict) -> list[tuple[str, str]]:
    """Resolve host semantic roles without consulting emitters or their output."""
    descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
    if descriptor.owner is not SourceOwnerKind.HOST:
        return []
    src = facts.get("src_host") or {}
    dst = facts.get("dst_host") or {}
    if format_name == "ecar" and kind == "connection":
        hosts = [(src, "source_endpoint"), (dst, "destination_endpoint")]
    elif format_name == "web_access":
        hosts = [(dst, "host")]
    elif format_name == "proxy_access":
        proxy = facts.get("proxy") or {}
        name = str(proxy.get("proxy_fqdn") or "").casefold()
        hosts = [
            (
                next(
                    (
                        host
                        for host in (dst, src)
                        if name
                        in {
                            str(host.get("hostname", "")).casefold(),
                            str(host.get("fqdn", "")).casefold(),
                        }
                    ),
                    dst or src,
                ),
                "host",
            )
        ]
    elif kind in {"logon", "machine_logon", "failed_logon", "logoff", "ssh_session"} or (
        format_name == "windows_event_security"
        and (kind.startswith("kerberos") or facts.get("smb"))
    ):
        hosts = [(dst or src, "host")]
    elif format_name == "syslog":
        hosts = [
            (next((host for host in (dst, src) if host.get("os_category") == "linux"), {}), "host")
        ]
    else:
        hosts = [(src or dst, "host")]
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for host, role in hosts:
        name = host.get("hostname")
        if (
            name
            and str(name).casefold() not in seen
            and descriptor.applies_to_host(
                host.get("os_category", "unknown"), host.get("roles", [])
            )
        ):
            seen.add(str(name).casefold())
            result.append((str(name), role))
    return result


def projection_phase(format_name: str, kind: str, facts: dict) -> tuple[str | None, str]:
    """Name the real transport leg and source-native transaction phase."""
    if not facts.get("network"):
        return None, kind
    src, dst = facts.get("src_host") or {}, facts.get("dst_host") or {}
    if facts.get("proxy"):
        leg = "client_proxy" if "forward_proxy" in dst.get("roles", []) else "transparent_proxy"
    else:
        leg = "proxy_origin" if "forward_proxy" in src.get("roles", []) else "direct"
    if format_name == "zeek_http":
        phase = (
            "http_connect"
            if (facts.get("http") or {}).get("method") == "CONNECT"
            else "http_request_response"
        )
    elif format_name == "proxy_access":
        phase = (
            "proxy_connect_and_request"
            if (facts.get("proxy") or {}).get("tunnel_status_code") is not None
            else "proxy_request"
        )
    elif format_name == "zeek_dns":
        phase = "dns_transaction"
    elif format_name == "cisco_asa":
        phase = (
            "firewall_denial"
            if (facts.get("firewall") or {}).get("action") == "deny"
            else "firewall_connection_lifecycle"
        )
    else:
        phase = "transport" if format_name in {"zeek_conn", "ecar"} else format_name
    return leg, phase


def native_requirements(
    format_name: str,
    kind: str,
    facts: dict,
    identifiers: dict[str, str],
    role: str,
    source_rules: dict | None = None,
    seed: int = 42,
    native_id: int | None = None,
    source_view: dict | None = None,
) -> list[NativeEvidenceRequirement]:
    """Describe required native evidence from canonical facts; never render it."""
    from evidenceforge.events.evidence_source_rules import (
        native_projection_applicable,
        windows_smb_event_ids,
    )

    if not native_projection_applicable(format_name, kind, facts, seed):
        return []
    if format_name == "windows_event_security" and kind.startswith("smb_"):
        smb = facts["smb"]
        auth = facts.get("auth") or {}
        result = []
        for event_id in windows_smb_event_ids(kind, facts, seed):
            required = {
                "SubjectLogonId": auth.get("logon_id"),
                "SubjectUserName": auth.get("username"),
            }
            if event_id in {4656, 4663}:
                required["ObjectName"] = smb.get("server_path")
            if event_id == 5145:
                required["RelativeTargetName"] = smb.get("share_path")
            result.append(
                NativeEvidenceRequirement(
                    selector={"EventID": event_id, "SubjectLogonId": auth.get("logon_id")},
                    required={key: value for key, value in required.items() if value is not None},
                )
            )
        return result
    network = dict(facts.get("network") or {})
    network.update({k: v for k, v in identifiers.items() if k in {"src_ip", "dst_ip"}})
    process = facts.get("process") or facts.get("actor_process") or {}
    auth = facts.get("auth") or {}
    dns = facts.get("dns") or {}
    http = facts.get("http") or {}
    selector: dict[str, JsonValue] = {}
    required: dict[str, JsonValue] = {}
    contains: list[str] = []
    timing: Literal["point", "transport_close", "interval"] = "point"
    maximum: int | None = 1
    file_views = {item["canonical_id"]: item for item in (source_view or {}).get("files", [])}
    uid = identifiers.get("zeek_uid") or network.get("zeek_uid")
    if format_name.startswith("zeek_"):
        selector = {"uid": uid} if uid else {}
        if format_name == "zeek_conn":
            required = {
                "id.orig_h": network.get("src_ip"),
                "id.resp_h": network.get("dst_ip"),
                "id.orig_p": network.get("src_port"),
                "id.resp_p": network.get("dst_port"),
                "conn_state": network.get("conn_state"),
            }
            if source_view:
                traffic = source_view["traffic"]
                required.update(
                    {
                        native: traffic[direction][field]
                        + (
                            traffic["missed_" + direction + "_bytes"]
                            if field == "payload_bytes"
                            else 0
                        )
                        for direction in ("orig", "resp")
                        for native, field in (
                            (direction + "_bytes", "payload_bytes"),
                            (direction + "_pkts", "packets"),
                            (direction + "_ip_bytes", "ip_bytes"),
                        )
                    }
                )
        elif format_name == "zeek_http":
            selector["trans_depth"] = http.get("trans_depth", 1)
            required = {
                "method": http.get("method"),
                "uri": http.get("uri"),
                "host": http.get("host"),
                "status_code": http.get("status_code"),
            }
        elif format_name == "zeek_dns":
            selector["query"] = dns.get("query")
            required = {"answers": dns.get("answers", []), "rcode_name|rcode": dns.get("rcode")}
        elif format_name == "zeek_ssl":
            required = {"server_name": (facts.get("ssl") or {}).get("server_name")}
        elif format_name == "zeek_files":
            return [
                NativeEvidenceRequirement(
                    selector={
                        "fuid": identifiers.get("file:" + transfer["fuid"], transfer["fuid"])
                    },
                    required={
                        key: file_views.get(transfer["fuid"], transfer).get(key, transfer.get(key))
                        for key in ("seen_bytes", "total_bytes", "missing_bytes", "sha256")
                        if transfer.get(key) not in (None, "")
                        and (
                            key != "sha256"
                            or file_views.get(transfer["fuid"], {}).get("analyzers_visible", True)
                        )
                    },
                    timing="interval",
                )
                for transfer in [
                    *facts.get("file_transfers", []),
                    *[
                        {
                            "fuid": item["fuid"],
                            "total_bytes": item["file_size"],
                            "seen_bytes": item["file_size"],
                            "missing_bytes": 0,
                        }
                        for item in facts.get("x509_chain", [])
                    ],
                ]
            ]
        elif format_name == "zeek_smtp":
            smtp = facts.get("smtp") or {}
            selector["trans_depth"] = smtp.get("trans_depth", 1)
            if smtp.get("encrypted_message"):
                return [
                    NativeEvidenceRequirement(
                        selector=selector,
                        required={
                            "mailfrom": "",
                            "rcptto": [],
                            "tls": True,
                            "last_reply": smtp.get("last_reply"),
                        },
                    )
                ]
            required = {
                "mailfrom": smtp.get("mailfrom"),
                "rcptto": smtp.get("rcptto"),
                "last_reply": smtp.get("last_reply"),
            }
        elif format_name in {"zeek_pe", "zeek_x509"}:
            context = "pe_analyses" if format_name == "zeek_pe" else "x509_chain"
            field = "id"
            return [
                NativeEvidenceRequirement(
                    selector={
                        field: identifiers.get(
                            "file:" + str(item.get("id") or item.get("fuid")),
                            item.get("id") or item.get("fuid"),
                        )
                    },
                    timing="interval",
                    expected="present"
                    if file_views.get(str(item.get("id") or item.get("fuid")), {}).get(
                        "analyzers_visible", True
                    )
                    else "absent",
                )
                for item in facts.get(context, [])
            ]
        elif format_name in {"zeek_smb_files", "zeek_smb_mapping"}:
            required = (
                {
                    "action": "SMB::FILE_" + str((facts.get("smb") or {}).get("phase", "")).upper(),
                    "name": (facts.get("smb") or {}).get("share_path"),
                }
                if format_name == "zeek_smb_files"
                else {}
            )
            if format_name == "zeek_smb_files":
                selector["action"] = required["action"]
                selector["name"] = required["name"]
            maximum = 1
        elif format_name == "zeek_dhcp":
            selector = {"mac": (facts.get("dhcp") or {}).get("mac")}
            maximum = None
        else:
            # Native analyzers may produce several rows within one transport.
            maximum = None
            timing = "interval"
    elif format_name in {"windows_event_security", "windows_event_sysmon"}:
        event_id = source_event_contracts()[format_name].get(kind)
        if format_name == "windows_event_sysmon":
            from evidenceforge.config.sysmon_filters import load_sysmon_filters
            from evidenceforge.events.evidence_source_rules import sysmon_event_ids

            rules = source_rules if source_rules is not None else load_sysmon_filters()
            ids = sysmon_event_ids(kind, facts, rules, seed)
            if native_id is None and len(ids) > 1:
                return [
                    requirement
                    for item in sorted(ids)
                    for requirement in native_requirements(
                        format_name, kind, facts, identifiers, role, rules, seed, item, source_view
                    )
                ]
            event_id = native_id or next(iter(ids), None) or (22 if dns else event_id)
        if event_id == 22 and format_name == "windows_event_sysmon":
            required = {
                "QueryName": dns.get("query"),
                "QueryResults": dns.get("answers", []),
                "QueryStatus": source_event_contracts()["sysmon_dns_status"].get(
                    dns.get("rcode"), "0"
                ),
            }
        elif event_id == 7 and format_name == "windows_event_sysmon":
            required = {
                "ProcessId": process.get("pid"),
                "ImageLoaded": (facts.get("image_load") or {}).get("image_loaded"),
            }
        elif process and kind in {"process_create", "system_process_create", "process_terminate"}:
            pid_field = (
                "NewProcessId"
                if format_name == "windows_event_security" and kind != "process_terminate"
                else "ProcessId"
            )
            required = {
                pid_field: process.get("pid"),
                "NewProcessName|Image|ProcessName": process.get("image"),
            }
            if kind in {"process_create", "system_process_create"}:
                required["CommandLine"] = process.get("command_line")
        elif network and event_id in {3, 5156}:
            required = {
                "SourceAddress|SourceIp": network.get("src_ip"),
                "SourcePort": network.get("src_port"),
                "DestAddress|DestinationIp": network.get("dst_ip"),
                "DestPort|DestinationPort": network.get("dst_port"),
            }
        elif auth and kind in {
            "logon",
            "machine_logon",
            "failed_logon",
            "logoff",
            "ssh_session",
            "workstation_locked",
            "workstation_unlocked",
            "log_cleared",
            "explicit_credentials",
        }:
            required = {"TargetUserName|SubjectUserName": auth.get("username")}
            if kind != "failed_logon":
                required["TargetLogonId|SubjectLogonId"] = auth.get("logon_id")
        elif facts.get("file"):
            required = {
                "TargetFilename": facts["file"].get("path"),
                "ProcessId": facts["file"].get("pid"),
            }
        elif facts.get("registry"):
            required = {
                "TargetObject": facts["registry"].get("key"),
                "ProcessId": facts["registry"].get("pid"),
                "Details": "Binary Data"
                if facts["registry"].get("value_type") == "binary"
                else facts["registry"].get("value"),
            }
            if format_name == "windows_event_sysmon":
                required["User"] = (
                    auth.get("username") or process.get("username") or process.get("principal")
                )
        if event_id is not None:
            selector = {"EventID": event_id}
            if event_id == 22:
                selector["QueryName"] = dns.get("query")
            if event_id == 3:
                selector["Initiated"] = "false" if kind == "wfp_connection" else "true"
        elif facts.get("smb"):
            selector = {"EventID": 5140 if kind == "smb_tree_connect" else 4663}
        else:
            raise ValueError(f"No native event selector for {format_name}/{kind}")
    elif format_name == "ecar":
        obj, action = source_event_contracts()[format_name][kind]
        selector = {"object": obj, "action": action}
        if obj == "PROCESS":
            required = {"pid": process.get("pid"), "image_path": process.get("image")}
            if action == "CREATE" or kind == "process_exec":
                required["command_line"] = process.get("command_line")
            if kind == "process_exec":
                selector["operation"] = "exec"
            transition = facts.get("process_transition") or {}
            if kind in {
                "process_exec",
                "process_audit_bind",
                "process_privilege_drop",
                "process_service_drop",
                "process_job_control",
            }:
                selector["operation"] = kind.removeprefix("process_")
                if transition.get("execution_id"):
                    selector["execution_id"] = transition["execution_id"]
                required.update(
                    {
                        key: value
                        for key, value in transition.items()
                        if key not in {"operation", "execution_id"}
                        and not (
                            kind == "process_exec"
                            and key in {"process_principal", "previous_process_principal"}
                        )
                    }
                )
        elif obj == "FLOW":
            selector["direction"] = "INBOUND" if role == "destination_endpoint" else "OUTBOUND"
            required = {
                "src_ip": network.get("src_ip"),
                "dst_ip": network.get("dst_ip"),
                "src_port": network.get("src_port"),
                "dst_port": network.get("dst_port"),
            }
        elif obj == "USER_SESSION":
            required = {"principal": auth.get("username"), "logon_id": auth.get("logon_id")}
            if action == "LOGIN":
                required["outcome"] = "failure" if kind == "failed_logon" else "success"
        elif obj == "FILE":
            file = facts.get("file") or facts.get("smb") or {}
            required = {
                "file_path": file.get("path") or file.get("client_path")
                if role != "destination_endpoint"
                else file.get("server_path")
            }
        elif obj == "REGISTRY":
            required = {
                "registry_key": (facts.get("registry") or {}).get("key"),
                "registry_value": (facts.get("registry") or {}).get("value"),
                "pid": (facts.get("registry") or {}).get("pid"),
            }
            selector["registry_key"] = required["registry_key"]
            selector["pid"] = required["pid"]
        elif obj == "MODULE":
            required = {
                "file_path": (facts.get("image_load") or {}).get("image_loaded"),
                "pid": process.get("pid"),
            }
    elif format_name in {"proxy_access", "web_access"}:
        context = facts.get("proxy") if format_name == "proxy_access" else http
        context = context or {}
        selector = {"method": context.get("method")}
        if context.get("method") == "CONNECT":
            required = {
                "status|status_code": context.get("tunnel_status_code")
                or context.get("status_code")
            }
        else:
            selector["url|path"] = context.get("url") or context.get("uri")
            required = {"status|status_code": context.get("status_code")}
            if format_name == "proxy_access" and context.get("tunnel_status_code") is not None:
                from urllib.parse import urlsplit

                url = urlsplit(context.get("url", ""))
                authority = f"{url.hostname}:{url.port or (443 if url.scheme == 'https' else 80)}"
                return [
                    NativeEvidenceRequirement(
                        selector={"method": "CONNECT", "url|path": authority},
                        required={"status|status_code": context["tunnel_status_code"]},
                    ),
                    NativeEvidenceRequirement(
                        selector={
                            key: value for key, value in selector.items() if value is not None
                        },
                        required=required,
                    ),
                ]
    elif format_name == "cisco_asa":
        firewall = facts.get("firewall") or {}
        if firewall.get("action") == "deny":
            selector = {"msg_id": 106023}
        else:
            selector = {"msg_id": 302013 if network.get("protocol") == "tcp" else 302015}
        required = {
            "src_ip": network.get("src_ip"),
            "src_port": network.get("src_port"),
            "dst_ip": network.get("dst_ip"),
            "dst_port": network.get("dst_port"),
        }
        selector.update(required)
        if (
            firewall.get("action") != "deny"
            and source_view
            and network.get("protocol") in {"tcp", "udp"}
        ):
            selector.update(required)
            return [
                NativeEvidenceRequirement(selector=selector, required=required),
                NativeEvidenceRequirement(
                    selector={
                        **required,
                        "msg_id": 302014 if network.get("protocol") == "tcp" else 302016,
                    },
                    required=required,
                    expected="present"
                    if source_view.get("firewall_teardown_time")
                    and source_view.get("firewall_teardown_observed")
                    else "absent",
                    timing="transport_close"
                    if source_view.get("firewall_teardown_time")
                    and source_view.get("firewall_teardown_observed")
                    else "interval",
                ),
            ]
    elif format_name == "syslog":
        context = facts.get("syslog") or {}
        selector = {"app_name": context.get("app_name")}
        if context.get("message"):
            contains = [context["message"]]
        else:
            contains = [
                str(value)
                for value in ((facts.get("smb") or {}).get("server_path"), auth.get("username"))
                if value
            ]
        maximum = None
    elif format_name in {"bash_history", "zsh_history"}:
        shell = facts.get("shell") or {}
        contains = [
            str(
                shell.get("command")
                or shell.get("command_line")
                or process.get("command_line")
                or ""
            )
        ]
        selector = {"command": contains[0]}
        username = process.get("username") or (facts.get("actor_process") or {}).get("principal")
        if username:
            selector["username"] = username
    elif format_name == "snort_alert":
        return [
            NativeEvidenceRequirement(
                selector={"sid": item["sid"]},
                required={"dst_ip": network.get("dst_ip")},
                maximum=None,
                timing="interval",
            )
            for item in facts.get("ids_alerts", [])
        ]
    elif format_name == "macos_endpoint_security":
        event_types = source_event_contracts()["macos_native_selectors"]
        event_type, path = event_types[kind]
        selector = {"event_type": event_type}
        required = {path + ".audit_token.pid|" + path + ".audit_token.5": process.get("pid")}
        if kind in {"process_exec", "process_fork", "process_create"}:
            required[path + ".executable.path"] = process.get("image")
        file = facts.get("file") or {}
        if kind == "file_create":
            required["event.create.destination.existing_file.path"] = file.get("path")
        elif kind in {"file_close", "file_delete"}:
            operation = "close" if kind == "file_close" else "unlink"
            required[f"event.{operation}.target.path"] = file.get("path")
        elif kind == "file_rename":
            required["event.rename.source.path"] = file.get("previous_path")
            required[
                "event.rename.destination.existing_file.path|event.rename.destination.new_path"
            ] = file.get("path")
    elif format_name == "macos_unified_log":
        context = facts.get("unified_log") or {}
        if not context:
            # An unavailable native writer cannot publish a source record.
            selector = {"eventType": "logEvent"}
            required = {"processID": -1}
        else:
            required = {
                "processID": context.get("writer_pid"),
                "eventMessage": context.get("message"),
                "subsystem": context.get("subsystem"),
                "category": context.get("category"),
            }
    else:
        raise ValueError(f"Unsupported source evidence contract {format_name}/{kind}")
    for context, bindings in (
        source_event_contracts()["native_context_fields"].get(format_name, {}).items()
    ):
        if facts.get(context):
            required.update(
                {
                    key: facts[context][field]
                    for key, field in bindings.items()
                    if facts[context].get(field) not in (None, "")
                }
            )
    # Use immutable native identities for attribution; mutable facts remain required values.
    if format_name in {"windows_event_security", "windows_event_sysmon"}:
        if "TargetObject" in required:
            selector["TargetObject"] = required["TargetObject"]
        for native_identity in ("TargetFilename", "ImageLoaded"):
            if required.get(native_identity) is not None:
                selector[native_identity] = required[native_identity]
        for key in ("NewProcessId", "ProcessId"):
            if required.get(key) is not None:
                selector[key] = required[key]
        if event_id in {3, 5156}:
            selector.update(
                {
                    key: value
                    for key, value in required.items()
                    if key
                    in {
                        "SourceAddress|SourceIp",
                        "SourcePort",
                        "DestAddress|DestinationIp",
                        "DestPort|DestinationPort",
                    }
                }
            )
        if auth.get("logon_id") and kind in {"logon", "machine_logon", "logoff"}:
            selector["TargetLogonId|SubjectLogonId"] = auth["logon_id"]
    elif (
        format_name == "ecar"
        and process.get("pid") is not None
        and selector.get("object") == "PROCESS"
    ):
        selector["pid"] = process["pid"]
    elif format_name == "ecar" and selector.get("object") == "FLOW":
        selector.update(required)
    elif format_name == "ecar" and selector.get("object") == "USER_SESSION":
        if auth.get("logon_id"):
            selector["logon_id"] = auth["logon_id"]
        elif auth.get("source_ip"):
            selector["src_ip"] = auth["source_ip"]
    if format_name == "ecar" and selector.get("object") != "FLOW":
        subject = facts.get("subject_identity") or {}
        if subject.get("object_id"):
            selector["objectID"] = subject["object_id"]
        elif selector.get("object") == "MODULE":
            selector["file_path"] = required.get("file_path")
        if selector.get("object") == "MODULE" and process.get("pid") is not None:
            selector["pid"] = process["pid"]
    if (
        not any(value is not None for value in selector.values())
        and not any(value not in (None, "") for value in required.values())
        and not contains
    ):
        raise ValueError(f"No independently matchable facts for {format_name}/{kind}")
    return [
        NativeEvidenceRequirement(
            selector={key: value for key, value in selector.items() if value is not None},
            required={key: value for key, value in required.items() if value not in (None, "")},
            contains=[value for value in contains if value],
            maximum=maximum,
            timing=timing,
        )
    ]


def required_capabilities(
    format_name: str, kind: str, facts: dict, role: str
) -> CollectionCapability:
    """Declare hard collection capabilities for one semantic source projection."""
    from evidenceforge.events.collection_policy import CollectionCapability as Capability

    descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
    if descriptor.owner is SourceOwnerKind.SENSOR:
        analyzers = {
            "zeek_dns": Capability.DNS | Capability.DNS_ANALYZER,
            "zeek_http": Capability.HTTP | Capability.HTTP_ANALYZER,
            "zeek_ssl": Capability.TLS | Capability.TLS_ANALYZER,
            "zeek_x509": Capability.TLS | Capability.TLS_ANALYZER,
            "zeek_ocsp": Capability.TLS | Capability.TLS_ANALYZER,
            "zeek_files": Capability.FILE | Capability.FILE_ANALYZER,
            "zeek_pe": Capability.FILE | Capability.FILE_ANALYZER,
            "zeek_smb_files": Capability.SMB
            | Capability.FILE
            | Capability.SMB_ANALYZER
            | Capability.FILE_ANALYZER,
            "zeek_smb_mapping": Capability.SMB | Capability.SMB_ANALYZER,
            "snort_alert": Capability.IDS,
        }
        return Capability.NETWORK | analyzers.get(format_name, Capability.NONE)
    if format_name in {"web_access", "proxy_access"}:
        return Capability.NETWORK | Capability.HTTP
    result = Capability.NONE
    if kind in {"connection", "wfp_connection"}:
        result |= Capability.NETWORK
    if kind.startswith("process_") or kind in {
        "system_process_create",
        "create_remote_thread",
        "bash_command",
        "zsh_command",
        "macos_policy_refusal",
    }:
        result |= Capability.PROCESS
    if (
        kind in {"logon", "machine_logon", "logoff", "failed_logon", "ssh_session"}
        or format_name == "macos_unified_log"
        and facts.get("macos_ssh_authentication")
    ):
        result |= Capability.AUTHENTICATION
    if (
        kind in {"logon", "machine_logon", "logoff", "ssh_session", "macos_workspace_request"}
        or format_name == "macos_unified_log"
        and facts.get("macos_ssh_authentication")
    ):
        result |= Capability.SESSION
    for context, capability in (
        ("file", Capability.FILE),
        ("registry", Capability.REGISTRY),
        ("service", Capability.SERVICE),
        ("scheduled_task", Capability.TASK),
        ("account_management", Capability.ACCOUNT),
        ("group_membership", Capability.ACCOUNT),
    ):
        if facts.get(context):
            result |= capability
    if kind.startswith("smb_"):
        result |= Capability.SMB
        if kind.startswith("smb_file_"):
            result |= Capability.FILE
    if kind == "ssh_session" and format_name == "syslog":
        result |= Capability.SSH
    if role == "source_endpoint":
        result |= Capability.SOURCE_ENDPOINT
    elif role == "destination_endpoint":
        result |= Capability.DESTINATION_ENDPOINT
    return result
