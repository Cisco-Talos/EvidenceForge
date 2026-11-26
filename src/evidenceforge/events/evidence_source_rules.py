"""Read-only source admission predicates over canonical facts and captured rules."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidenceforge.events.base import CanonicalOccurrence


def source_admission_facts(event: CanonicalOccurrence) -> dict:
    """Read the small canonical subset used by source admission, without rendering."""
    fields = {
        "src_host": ("os_category", "hostname"),
        "dst_host": ("os_category", "hostname"),
        "network": ("application_layer_only",),
        "firewall": ("action",),
        "smb": (
            "provider",
            "server_platform",
            "audit",
            "result",
            "operation",
            "phase",
            "client_access",
            "client_path",
            "local_path",
        ),
        "auth": ("session_kind",),
        "process": ("pid",),
    }
    facts = {
        name: {field: getattr(context, field) for field in names}
        for name, names in fields.items()
        if (context := getattr(event, name, None)) is not None
    }
    if event.syslog is not None:
        facts["syslog"] = True
    return facts


def semantic_source_admission(format_name: str, kind: str, facts: dict, hostname: str = "") -> bool:
    """Qualify a source's semantic projection before collection policy is applied."""
    network = facts.get("network") or {}
    if format_name == "zeek_x509":
        return kind == "connection" and network.get("conn_state") == "SF"
    if format_name == "cisco_asa":
        return kind == "connection" and bool(network) and not network.get("application_layer_only")
    if format_name == "ecar":
        if (facts.get("firewall") or {}).get("action") == "deny":
            return False
        if (kind.startswith("smb_file_") or kind == "smb_directory_enumeration") and (
            (facts.get("smb") or {}).get("result", "success") != "success"
        ):
            return False
        if (
            facts.get("smb")
            and hostname
            and (kind.startswith("smb_file_") or kind == "smb_directory_enumeration")
        ):
            return bool(
                ecar_smb_projection_phases(
                    kind,
                    facts["smb"],
                    facts.get("src_host") or {},
                    facts.get("dst_host") or {},
                    facts.get("process") or {},
                    hostname,
                )
            )
        return not (
            (facts.get("firewall") or {}).get("action") == "deny"
            or kind == "connection"
            and network.get("application_layer_only")
        )
    if format_name == "syslog":
        smb = facts.get("smb") or {}
        destination = facts.get("dst_host") or {}
        if destination.get("os_category") != "linux" or not (
            smb.get("provider") == "samba"
            or smb.get("server_platform") == "linux"
            or (facts.get("auth") or {}).get("session_kind") == "smb"
        ):
            return bool(facts.get("syslog")) and any(
                (facts.get(host) or {}).get("os_category") == "linux"
                for host in ("src_host", "dst_host")
            )
        if kind in {"logon", "smb_tree_connect", "logoff"}:
            return True
        from evidenceforge.generation.activity.smb_profiles import (
            get_samba_audit_operation,
            samba_audit_enabled,
        )

        if get_samba_audit_operation(kind) is not None:
            return samba_audit_enabled(
                kind, smb.get("audit", "minimal"), smb.get("result", "success")
            )
        return bool(facts.get("syslog"))
    return True


def ecar_smb_projection_phases(
    kind: str, smb: dict, source: dict, destination: dict, process: dict, hostname: str
) -> tuple[str, ...]:
    """Name only SMB endpoint rows actually visible on this particular host."""
    phases: list[str] = []
    if hostname.casefold() == str(destination.get("hostname", "")).casefold() and kind in {
        "smb_file_read",
        "smb_file_write",
        "smb_file_rename",
        "smb_file_delete",
    }:
        phases.append("base")
    if hostname.casefold() != str(source.get("hostname", "")).casefold():
        return tuple(phases)
    copying = smb.get("operation") in {"copy", "move"}
    upload = bool(smb.get("local_path")) and smb.get("phase") == "write" and copying
    download = bool(smb.get("local_path")) and smb.get("phase") == "read" and copying
    mounted = (
        not upload
        and not download
        and (not copying or smb.get("phase") == "rename")
        and (smb.get("client_access"), source.get("os_category"))
        in {("cifs_mount", "linux"), ("macos_mount", "macos")}
        and smb.get("phase") in {"directory_enumeration", "read", "write", "rename", "delete"}
        and str(smb.get("client_path", "")).startswith("/")
        and process.get("pid", 0) > 0
    )
    if upload or download or mounted:
        phases.append("client_file")
    if upload and smb.get("operation") == "move":
        phases.append("client_delete")
    return tuple(phases)


HISTORY_DESTROYED_REASON = "destroyed_by_later_action"


def history_entry_admitted(expected: str, excluded_stages: Sequence[str]) -> bool:
    """Return whether a history entry reached its file before any later destruction."""
    return expected == "present" or (
        bool(excluded_stages) and all(stage == "retention" for stage in excluded_stages)
    )


def destroying_history_clear(
    entry_time: datetime, clears: Sequence[tuple[datetime, str]]
) -> str | None:
    """Return the first admitted clear ordered at or after an entry in the same history file.

    A clear erases itself and every entry ordered before it, so the entry is absent from the
    collected file. ``clears`` holds (time, occurrence_id) pairs for one host/user file.
    """
    later = [(time, occurrence) for time, occurrence in clears if time >= entry_time]
    return min(later)[1] if later else None


def ecar_samba_session(
    server_os_category: str | None,
    session_kind: str | None,
    smb_provider: str | None,
    smb_server_platform: str | None,
) -> bool:
    """Return whether a session is owned by a Linux Samba server rather than a Windows LSA.

    Samba sessions carry no Windows logon ID; eCAR keys them by their SMB session reference.
    """
    return server_os_category == "linux" and (
        session_kind == "smb" or smb_provider == "samba" or smb_server_platform == "linux"
    )


def ecar_samba_session_reference(auth_session_ref: str | None, smb_session_id: str | None) -> str:
    """Return the durable SMB session reference eCAR renders for a Samba session."""
    return auth_session_ref or smb_session_id or ""


ECAR_PORT_BEARING_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})


def endpoint_local_destination_ip(dst_ip: str | None, mapped_dst_ip: str | None) -> str | None:
    """Return the destination host's own address for a possibly translated transport.

    Host-based telemetry on the responder sees its interface address, not the static-NAT
    VIP the client addressed.
    """
    return mapped_dst_ip if mapped_dst_ip and mapped_dst_ip != dst_ip else dst_ip


def ecar_flow_endpoint_fields(
    protocol: str | None,
    src_ip: str | None,
    src_port: int | None,
    dst_ip: str | None,
    dst_port: int | None,
) -> dict[str, object]:
    """Return eCAR FLOW endpoint properties: ports only for port-bearing protocols."""
    fields: dict[str, object] = {"src_ip": src_ip, "dst_ip": dst_ip}
    normalized = (protocol or "").lower()
    if normalized in ECAR_PORT_BEARING_PROTOCOLS:
        fields["src_port"] = src_port
        fields["dst_port"] = dst_port
    elif normalized == "icmp":
        fields["icmp_type"] = 8
        fields["icmp_code"] = 0
    return fields


def native_zeek_connection_state(protocol: str, state: str | None) -> str | None:
    """Project transport outcome into native Conn::conn_state semantics."""
    return "OTH" if protocol == "icmp" else state


def native_zeek_connection_history(protocol: str, history: str) -> str:
    """Keep TCP/UDP histories without inventing them for native ICMP."""
    return "" if protocol == "icmp" else history


def native_zeek_connection_ports(
    protocol: str, source_port: int | None, destination_port: int | None
) -> tuple[int | None, int | None]:
    """Project ICMP type/code into Zeek tuple slots, preserving TCP/UDP ports."""
    if protocol == "icmp":
        return source_port or 8, destination_port or 0
    return source_port, destination_port


def _seed(key: str, generation_seed: int) -> int:
    if generation_seed != 42:
        key = f"seed:{generation_seed}:{key}"
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2**32)


def sysmon_event_ids(kind: str, facts: dict, rules: dict, seed: int) -> set[int]:
    """Describe admitted Sysmon native projections without invoking its renderer."""
    from evidenceforge.events.evidence_projection import source_event_contracts

    event_id = source_event_contracts()["windows_event_sysmon"].get(kind)
    if event_id is None:
        return set()
    process = facts.get("process") or facts.get("actor_process") or {}
    network = facts.get("network") or {}
    source = facts.get("src_host") or {}
    if source.get("os_category") != "windows":
        return set()
    if (
        kind == "wfp_connection"
        and (facts.get("network_endpoint") or {}).get("role") != "responder"
    ):
        return set()
    if kind in {"connection", "wfp_connection"}:
        result = set()
        cfg = rules.get("network_connect", {})
        constraints = {
            str(port): values for port, values in cfg.get("port_process_constraints", {}).items()
        }
        image = str(process.get("image", "")).replace("\\", "/").rsplit("/", 1)[-1].lower()
        valid_process = process.get("pid", 0) > 0 and image not in {"", "-"}
        allowed = (
            cfg.get("enabled", True) and valid_process and not network.get("application_layer_only")
        )
        if (
            allowed
            and cfg.get("mode", "include") == "include"
            and (facts.get("network_endpoint") or {}).get("role") != "responder"
        ):
            key = f"sysmon3_{source.get('hostname', '')}_{image}_{network.get('dst_ip')}_{network.get('dst_port')}_{network.get('zeek_uid')}"
            sample = (_seed(key, seed) & 0xFFFFFFFF) / 0xFFFFFFFF
            allowed = network.get("dst_ip") not in cfg.get("exclude_dest_ips", []) and (
                image in [value.lower() for value in cfg.get("include_images", [])]
                or image in [value.lower() for value in cfg.get("include_baseline_images", [])]
                and sample < cfg.get("baseline_sample_rate", 0.10)
                or image in [value.lower() for value in cfg.get("include_user_app_images", [])]
                and sample < cfg.get("user_app_sample_rate", 0.05)
                or network.get("dst_port") in cfg.get("include_dest_ports", [])
                and (
                    str(network.get("dst_port")) not in constraints
                    or image in [value.lower() for value in constraints[str(network["dst_port"])]]
                )
            )
        if allowed:
            result.add(3)
        dns = facts.get("dns") or {}
        cfg = rules.get("dns_query", {})
        if (
            kind == "connection"
            and dns
            and cfg.get("enabled", True)
            and not any(
                str(dns.get("query", "")).lower().endswith(value.lower())
                for value in cfg.get("exclude_query_suffixes", [])
            )
        ):
            result.add(22)
        return result
    if kind == "image_load":
        cfg = rules.get("image_loaded", {})
        image = facts.get("image_load") or {}
        excluded = (
            cfg.get("mode", "exclude") == "exclude"
            and any(
                str(image.get("image_loaded", "")).lower().startswith(value.lower())
                for value in cfg.get("exclude_image_loaded_prefixes", [])
            )
            and any(
                value.lower() in str(image.get("signature", "")).lower()
                for value in cfg.get("exclude_signatures", [])
            )
        )
        return {7} if cfg.get("enabled", True) and image and not excluded else set()
    if kind in {"file_create", "file_modify"}:
        cfg = rules.get("file_create", {})
        path = str((facts.get("file") or {}).get("path", "")).lower()
        allowed = (
            cfg.get("mode", "include") != "include"
            or any(value.lower() in path for value in cfg.get("include_target_paths", []))
            or any(path.endswith(value.lower()) for value in cfg.get("include_extensions", []))
        )
        return {11} if cfg.get("enabled", True) and allowed else set()
    if kind == "registry_modify":
        cfg = rules.get("registry_event", {})
        registry = facts.get("registry") or {}
        event_id = 13 if registry.get("value") or registry.get("action") == "modify" else 12
        allowed = (
            cfg.get("enabled", True)
            and not (registry.get("action") == "create" and not cfg.get("log_create_key", False))
            and (
                cfg.get("mode", "include") != "include"
                or any(
                    value.lower() in str(registry.get("key", "")).lower()
                    for value in cfg.get("include_key_patterns", [])
                )
            )
        )
        return {event_id} if allowed else set()
    return {event_id}


def windows_smb_event_ids(kind: str, facts: dict, seed: int) -> list[int]:
    """Declare sparse Windows share/object audit rows for a canonical SMB phase."""
    smb = facts.get("smb") or {}
    if not smb or not facts.get("auth") or smb.get("audit") == "minimal":
        return []
    if kind == "smb_tree_connect":
        return [5140]
    if smb.get("result") != "success":
        return [5145]
    if smb.get("audit") == "high" and kind == "smb_file_open":
        return [5145, 4656]
    if kind in {"smb_file_write", "smb_file_rename", "smb_file_delete"} or (
        smb.get("audit") == "high" and kind == "smb_file_read"
    ):
        key = f"smb-standard-object-audit:{smb.get('file_id')}:{smb.get('content_version')}"
        if smb.get("audit") != "high" and _seed(key, seed) % 100 >= 65:
            return []
        return [4663]
    if smb.get("audit") == "high" and kind == "smb_file_close":
        return [4658]
    return []


def windows_smb_handle_id(smb: dict, seed: int) -> str:
    """Project one retained SMB handle into its native Windows audit identity."""
    return f"0x{_seed(smb.get('handle_id') or smb.get('tree_id', ''), seed) & 0xFFFFFFFF:x}"


def native_projection_applicable(format_name: str, kind: str, facts: dict, seed: int) -> bool:
    """Declare source-native phase eligibility independently of emitter execution."""
    smb = facts.get("smb") or {}
    if format_name == "zeek_smb_mapping":
        return kind == "smb_tree_connect" and smb.get("result") == "success"
    if format_name == "zeek_smb_files":
        return (
            bool(smb)
            and not smb.get("encrypted")
            and smb.get("result") == "success"
            and smb.get("phase") in {"open", "read", "write", "rename", "delete"}
        )
    if format_name == "windows_event_security" and kind.startswith("smb_"):
        return bool(windows_smb_event_ids(kind, facts, seed))
    return True
