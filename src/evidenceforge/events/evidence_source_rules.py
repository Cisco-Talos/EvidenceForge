"""Read-only source admission predicates over canonical facts and captured rules."""

from __future__ import annotations

import hashlib


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
