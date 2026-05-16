# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Expansion rule base class and concrete rule implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from evidenceforge.generation.causal.engine import ExpandedEvent, ExpansionContext


def _timing_spec(
    key: str,
    *,
    default_min_ms: int,
    default_max_ms: int,
    default_position: Literal["before", "after"],
):
    """Return a TimingSpec from data-driven timing profiles."""
    from evidenceforge.generation.activity.timing_profiles import get_timing_window
    from evidenceforge.generation.causal.timing import TimingSpec

    window = get_timing_window(
        key,
        default_min_ms=default_min_ms,
        default_max_ms=default_max_ms,
        default_position=default_position,
    )
    return TimingSpec(
        min_ms=window.min_ms,
        max_ms=window.max_ms,
        position=window.position,
    )


@dataclass
class ExpansionRule(ABC):
    """Base class for causal expansion rules.

    Each rule checks whether it applies to a given event type and context,
    then returns zero or more expanded events to emit alongside the trigger.

    Attributes:
        name: Short identifier (e.g., "dns_before_connection").
        description: Human-readable explanation.
        priority: Lower values run first. Used to order rule evaluation.
    """

    name: str = ""
    description: str = ""
    priority: int = 100

    @abstractmethod
    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        """Return True if this rule should fire for the given event."""

    @abstractmethod
    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        """Return prerequisite/consequent events to emit."""


@dataclass
class KerberosBeforeLogon(ExpansionRule):
    """Emit DC-side Kerberos TGT/TGS events before domain logons.

    Reproduces the logic from ActivityGenerator._emit_dc_kerberos_for_logon().
    Fires when auth_package is "Kerberos", target is Windows, and the target
    system is not a DC. Delegates to the existing method which handles TGT
    and TGS emission. Elevated-session 4672 events are emitted with the
    target-host 4624, where the logon session is created.
    """

    name: str = field(default="kerberos_before_logon")
    description: str = field(default="Emit Kerberos TGT/TGS on DC before domain logons")
    priority: int = field(default=20)

    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        return (
            event_type == "logon"
            and ctx.auth_package == "Kerberos"
            and ctx.os_category == "windows"
        )

    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        from evidenceforge.generation.causal.engine import ExpandedEvent

        return [
            ExpandedEvent(
                method="_emit_dc_kerberos_for_logon",
                kwargs={
                    "user": ctx.actor,
                    "system": ctx.target_system,
                    "auth_package": ctx.auth_package,
                    "source_ip": ctx.src_ip or "",
                },
                timing=_timing_spec(
                    "auth.kerberos_before_logon",
                    default_min_ms=40,
                    default_max_ms=350,
                    default_position="before",
                ),
                description="Kerberos TGT + TGS on DC before logon",
            )
        ]


@dataclass
class DnsBeforeConnection(ExpansionRule):
    """Emit a DNS lookup before TCP connections to named hosts.

    Reproduces the logic from ActivityGenerator._emit_dns_lookup(), including
    DNS caching, SERVFAIL probability, multi-answer CDN responses, and NXDOMAIN
    companion queries. Connection prerequisites force an address lookup for the
    destination so DNS evidence always contains the IP used by the TCP flow.
    """

    name: str = field(default="dns_before_connection")
    description: str = field(default="Emit DNS query before TCP connections to named hosts")
    priority: int = field(default=10)

    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        return (
            event_type == "connection"
            and ctx.protocol == "tcp"
            and ctx.dst_port not in (53,)
            and ctx.dst_ip is not None
        )

    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        from evidenceforge.generation.causal.engine import ExpandedEvent

        kwargs = {
            "src_ip": ctx.src_ip,
            "dst_ip": ctx.dst_ip,
            "force_address": True,
        }
        if ctx.hostname:
            kwargs["hostname"] = ctx.hostname
        return [
            ExpandedEvent(
                method="_emit_dns_lookup",
                kwargs=kwargs,
                timing=_timing_spec(
                    "network.dns_before_tcp",
                    default_min_ms=20,
                    default_max_ms=1500,
                    default_position="before",
                ),
                description="DNS lookup for connection destination",
            )
        ]


@dataclass
class ProcessAccessAfterRemoteThread(ExpansionRule):
    """Emit Sysmon Event 10 (ProcessAccess) before CreateRemoteThread targeting lsass.

    When a process injects into lsass.exe via CreateRemoteThread (Sysmon Event 8),
    it must first obtain a handle to the target process. Sysmon Event 10 is the
    primary detection signal for that credential-dumping prerequisite. This rule
    centralizes the lsass check that was previously inline in
    StorylineMixin._execute_typed_event().
    """

    name: str = field(default="process_access_after_remote_thread")
    description: str = field(default="Emit ProcessAccess before CreateRemoteThread targeting lsass")
    priority: int = field(default=40)

    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        if event_type != "create_remote_thread":
            return False
        target = ctx.target_image or ""
        return "lsass" in target.lower()

    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        from evidenceforge.generation.causal.engine import ExpandedEvent

        return [
            ExpandedEvent(
                method="generate_process_access",
                kwargs={
                    "user": ctx.actor,
                    "system": ctx.target_system,
                    "source_pid": ctx.source_pid,
                    "source_image": ctx.source_image,
                    "target_pid": ctx.target_pid,
                    "target_image": ctx.target_image,
                    "granted_access": "0x1FFFFF",
                },
                timing=_timing_spec(
                    "process.remote_thread_lsass_access",
                    default_min_ms=1,
                    default_max_ms=75,
                    default_position="before",
                ),
                description="ProcessAccess for lsass credential dumping detection",
            )
        ]


@dataclass
class SupplementaryAuditEvents(ExpansionRule):
    """Emit Windows audit events inferred from command-line patterns.

    When a process executes an administrative command (net user /add, schtasks /create,
    sc create, wevtutil cl), Windows generates corresponding high-level audit events
    (4720, 4726, 4728, 4697, 4698, 1102). This rule centralizes the command-line
    pattern matching that was previously in StorylineMixin._emit_supplementary_events().

    Uses skip_types from ExpansionContext to avoid duplicating events that were
    explicitly declared in the storyline step.
    """

    name: str = field(default="supplementary_audit_events")
    description: str = field(default="Emit Windows audit events from command-line patterns")
    priority: int = field(default=60)

    def matches(self, event_type: str, ctx: ExpansionContext) -> bool:
        return (
            event_type == "process_create"
            and ctx.os_category == "windows"
            and bool(ctx.command_line)
        )

    def expand(self, event_type: str, ctx: ExpansionContext) -> list[ExpandedEvent]:
        import re

        from evidenceforge.generation.causal.engine import ExpandedEvent

        cmd = ctx.command_line or ""
        cmd_lower = cmd.lower()
        skip = ctx.skip_types
        expanded: list[ExpandedEvent] = []

        # Pick DC system: first available, or fall back to target_system
        dc_system = ctx.dc_systems[0] if ctx.dc_systems else ctx.target_system

        timing = _timing_spec(
            "windows.audit_from_admin_command",
            default_min_ms=100,
            default_max_ms=900,
            default_position="after",
        )

        def _domain_sid_prefix() -> str:
            for sid in ctx.sid_registry.values():
                if sid.startswith("S-1-5-21-") and sid.count("-") == 7:
                    return "-".join(sid.split("-")[:7])
            import random as _rng

            return (
                f"S-1-5-21-{_rng.randint(100000000, 999999999)}"
                f"-{_rng.randint(100000000, 999999999)}"
                f"-{_rng.randint(100000000, 999999999)}"
            )

        def _make_sid(rid: int | None = None) -> str:
            prefix = _domain_sid_prefix()
            if rid is None:
                import random as _rng

                rid = _rng.randint(1100, 9999)
            return f"{prefix}-{rid}"

        # net user <name> <password> /add -> 4720 (account created)
        match = re.search(r"net\s+user\s+(\S+)\s+\S+\s+/add", cmd_lower)
        if match and "account_created" not in skip:
            orig_match = re.search(r"net\s+user\s+(\S+)\s+\S+\s+/add", cmd, re.IGNORECASE)
            target_name = orig_match.group(1) if orig_match else match.group(1)
            target_sid = _make_sid()
            ctx.created_account_sids[target_name] = target_sid
            expanded.append(
                ExpandedEvent(
                    method="generate_account_created",
                    kwargs={
                        "actor": ctx.actor,
                        "system": dc_system,
                        "target_username": target_name,
                        "target_sid": target_sid,
                    },
                    timing=timing,
                    description="4720 account created from net user /add",
                )
            )

        # net user <name> /delete -> 4726 (account deleted)
        match = re.search(r"net\s+user\s+(\S+)\s+/delete", cmd_lower)
        if match and "account_deleted" not in skip:
            orig_match = re.search(r"net\s+user\s+(\S+)\s+/delete", cmd, re.IGNORECASE)
            target_name = orig_match.group(1) if orig_match else match.group(1)
            target_sid = _make_sid()
            expanded.append(
                ExpandedEvent(
                    method="generate_account_deleted",
                    kwargs={
                        "actor": ctx.actor,
                        "system": dc_system,
                        "target_username": target_name,
                        "target_sid": target_sid,
                    },
                    timing=timing,
                    description="4726 account deleted from net user /delete",
                )
            )

        # net group "<GroupName>" <user> /add -> 4728 (group member added)
        match = re.search(r'net\s+group\s+"?([^"]+)"?\s+(\S+)\s+/add', cmd, re.IGNORECASE)
        if match and "group_member_added" not in skip:
            group_name = match.group(1)
            member_name = match.group(2)
            group_rid = 512 if "admin" in group_name.lower() else None
            group_sid = _make_sid(group_rid)
            member_sid = (
                ctx.created_account_sids.get(member_name)
                or ctx.sid_registry.get(member_name)
                or _make_sid()
            )
            expanded.append(
                ExpandedEvent(
                    method="generate_group_membership_change",
                    kwargs={
                        "actor": ctx.actor,
                        "system": dc_system,
                        "action": "add",
                        "scope": "global",
                        "group_name": group_name,
                        "group_sid": group_sid,
                        "member_username": member_name,
                        "member_sid": member_sid,
                    },
                    timing=timing,
                    description="4728 group member added from net group /add",
                )
            )

        # schtasks /Create ... /TN "<TaskName>" -> 4698 (scheduled task)
        match = re.search(r'schtasks\s+/create\b.*?/tn\s+"?([^"]+)"?', cmd, re.IGNORECASE)
        if match and "scheduled_task_created" not in skip:
            task_name = match.group(1)
            tr_match = re.search(r'/tr\s+"?([^"]+)"?', cmd, re.IGNORECASE)
            task_action = tr_match.group(1) if tr_match else ""
            expanded.append(
                ExpandedEvent(
                    method="generate_scheduled_task",
                    kwargs={
                        "user": ctx.actor,
                        "system": ctx.target_system,
                        "task_name": task_name,
                        "action": "created",
                        "task_content": (
                            f"<Actions><Exec><Command>{task_action}</Command></Exec></Actions>"
                        ),
                        "source_command_line": cmd,
                    },
                    timing=timing,
                    description="4698 scheduled task from schtasks /create",
                )
            )

        # sc create <ServiceName> binPath= "<path>" -> 4697 (service installed)
        match = re.search(r'sc\s+create\s+(\S+)\s+binpath=\s*"?([^"]+)"?', cmd, re.IGNORECASE)
        if match and "service_installed" not in skip:
            svc_name = match.group(1)
            svc_path = match.group(2)
            service_start_type = "3"
            start_match = re.search(
                r"\bstart=\s*(delayed-auto|auto|demand|disabled|boot|system)\b",
                cmd,
                re.IGNORECASE,
            )
            if start_match:
                start_value = start_match.group(1).lower()
                service_start_type = {
                    "boot": "0",
                    "system": "1",
                    "auto": "2",
                    "delayed-auto": "2",
                    "demand": "3",
                    "disabled": "4",
                }[start_value]
            expanded.append(
                ExpandedEvent(
                    method="generate_service_installed",
                    kwargs={
                        "user": ctx.actor,
                        "system": ctx.target_system,
                        "service_name": svc_name,
                        "service_file_name": svc_path,
                        "service_start_type": service_start_type,
                    },
                    timing=timing,
                    description="4697 service installed from sc create",
                )
            )

        # wevtutil cl Security -> 1102 (log cleared)
        if "wevtutil" in cmd_lower and "cl" in cmd_lower and "log_cleared" not in skip:
            expanded.append(
                ExpandedEvent(
                    method="generate_log_cleared",
                    kwargs={
                        "user": ctx.actor,
                        "system": ctx.target_system,
                        "subject_logon_id": ctx.logon_id,
                    },
                    timing=timing,
                    description="1102 log cleared from wevtutil cl",
                )
            )

        return expanded
