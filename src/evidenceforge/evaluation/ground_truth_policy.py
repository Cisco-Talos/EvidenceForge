"""Independent verification of the versioned observation grouping protocol."""

from __future__ import annotations

import hashlib
import string

from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthOccurrence,
    GroundTruthSourceExpectation,
)
from evidenceforge.utils.ids import _has_synthetic_marker


def sensor_identifier(canonical: str, sensor: str) -> str:
    """Verify the version-1 SHA-256/base-62 sensor identity protocol."""
    if not canonical:
        return canonical
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    for counter in range(16):
        suffix = "" if counter == 0 else f":{counter}"
        digest = hashlib.sha256(f"{canonical}:{sensor}{suffix}".encode()).digest()
        value = canonical[0] + "".join(alphabet[byte % 62] for byte in digest[: len(canonical) - 1])
        if not _has_synthetic_marker(value):
            return value
    return value


def expected_loss_identity(
    row: GroundTruthOccurrence, expectation: GroundTruthSourceExpectation, *, format_specific: bool
) -> str:
    """Reconstruct the documented group key from facts, without calling generation."""
    source = expectation.family
    facts = row.facts
    network = facts.get("network") or {}
    process = facts.get("process") or {}
    auth = facts.get("auth") or {}
    syslog = facts.get("syslog") or {}
    src = facts.get("src_host") or {}
    dst = facts.get("dst_host") or {}
    host = str(
        (dst or src).get("hostname") or process.get("hostname") or network.get("src_ip") or ""
    )
    image = str(process.get("image", "")).replace("\\", "/").rsplit("/", 1)[-1]
    group = ""
    if source == "ecar" and process.get("concurrency_group_id"):
        group = "process-group:" + process["concurrency_group_id"]
    if source == "ecar" and not group and dst:
        port, ip, source_port = 0, "", 0
        if network.get("protocol") == "tcp" and network.get("dst_port") in {22, 3389}:
            port, ip, source_port = network["dst_port"], network["src_ip"], network["src_port"]
        elif (
            auth.get("source_ip")
            and auth.get("source_port")
            and row.kind in {"ssh_session", "logon", "logoff"}
        ):
            kind = auth.get("session_kind") or auth.get("auth_protocol")
            port = (
                22 if kind == "ssh" or row.kind == "ssh_session" else 3389 if kind == "rdp" else 0
            )
            if not kind and auth.get("logon_type") == 10:
                port = 3389 if dst.get("os_category") == "windows" else 22
            ip, source_port = auth["source_ip"], auth["source_port"]
        if port and ip and source_port:
            group = f"remote-session:{port}:{dst['hostname']}:{ip}:{source_port}:{dst.get('ip') or network.get('dst_ip')}"
    if not group and facts.get("lifecycle"):
        group = "action-lifecycle:" + facts["lifecycle"]["group_id"]
    if (
        not group
        and source == "ecar"
        and facts.get("storyline_cluster_id")
        and process.get("pid") is not None
    ):
        group = f"storyline-process:{facts['storyline_cluster_id']}:{process.get('username', '')}:{process['pid']}:{image}"
    if not group and source == "syslog":
        message, app = syslog.get("message", ""), syslog.get("app_name")
        session = bool(auth.get("username") and auth.get("logon_id") and auth.get("session_id"))
        session_message = (
            app == "sshd"
            and (
                message.startswith(("Connection from ", "Accepted "))
                or "pam_unix(sshd:session): session " in message
            )
            or app == "systemd-logind"
            and message.startswith(("New session ", "Removed session "))
        )
        if session and session_message:
            group = f"linux-ssh-session:{auth['username']}:{auth['logon_id']}:{auth['session_id']}"
        elif app == "sshd" and syslog.get("pid"):
            group = f"sshd:{syslog['pid']}"
    if not group:
        if network.get("zeek_uid"):
            group = "uid:" + network["zeek_uid"]
        elif source == "zeek" and facts.get("dns"):
            dns = facts["dns"]
            group = f"dns:{dns['query']}:{dns['query_type']}:{network.get('src_ip', '')}"
        elif process:
            group = f"process:{process.get('username', '')}:{process.get('pid', '')}:{process.get('process_guid', '')}:{image}"
        elif auth.get("logon_id"):
            group = f"session:{auth.get('username', '')}:{auth['logon_id']}"
        elif facts.get("registry"):
            group = f"registry:{facts['registry']['key']}:{facts['registry']['value']}"
        elif facts.get("file"):
            group = f"file:{facts['file']['path']}:{facts['file']['action']}"
        elif facts.get("ids_alerts"):
            group = "ids:" + ",".join(
                f"{alert['gid']}:{alert['sid']}:{alert.get('message', '')}"
                for alert in facts["ids_alerts"]
            )
        else:
            group = "event"
    if (
        format_specific
        and source == "zeek"
        and expectation.format == "zeek_http"
        and network.get("zeek_uid")
    ):
        return "|".join(
            [source, expectation.format, expectation.format, host, "uid:" + network["zeek_uid"], ""]
        )
    coherent = (
        group.startswith("action-lifecycle:")
        or source == "ecar"
        and group.startswith(("remote-session:", "storyline-process:", "process-group:"))
        or group.startswith("process:")
        and source in {"windows_security", "sysmon", "ecar"}
        or group.startswith("session:")
        and source in {"windows_security", "ecar", "syslog"}
        or group.startswith("uid:")
        and source in {"zeek", "ecar", "sysmon", "windows_security", "proxy", "asa", "ids"}
        or source == "syslog"
        and group.startswith(("sshd:", "linux-ssh-session:"))
        or source == "zeek"
        and group.startswith("dns:")
    )
    coherent = coherent and not format_specific
    return "|".join(
        [
            source,
            source if coherent else expectation.format,
            source if coherent else row.kind,
            host,
            group,
            "" if coherent else str(int(row.time.timestamp() * 1_000_000)),
        ]
    )
