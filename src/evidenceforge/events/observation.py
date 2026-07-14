# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-observation policy for optional collection gaps and delays."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from evidenceforge.config.observation_profiles import (
    get_observation_profile,
    observation_profile_exists,
)
from evidenceforge.events.base import RawLogEntry, SecurityEvent
from evidenceforge.utils.rng import _stable_seed

ObservationStatus = Literal["visible", "delayed", "dropped", "filtered", "out_of_window"]

SOURCE_FAMILIES: frozenset[str] = frozenset(
    {
        "windows_security",
        "sysmon",
        "ecar",
        "syslog",
        "bash_history",
        "zeek",
        "proxy",
        "web",
        "asa",
        "ids",
    }
)

_FORMAT_TO_SOURCE: dict[str, str] = {
    "windows_event_security": "windows_security",
    "windows_event_sysmon": "sysmon",
    "ecar": "ecar",
    "syslog": "syslog",
    "bash_history": "bash_history",
    "proxy_access": "proxy",
    "web_access": "web",
    "cisco_asa": "asa",
    "snort_alert": "ids",
}


@dataclass(frozen=True, slots=True)
class ObservationDecision:
    """Decision for one source rendering attempt."""

    status: ObservationStatus
    delay: timedelta = timedelta(0)


@dataclass(slots=True)
class ObservationSummary:
    """Aggregated source evidence status for a storyline/red-herring cluster."""

    visible: int = 0
    delayed: int = 0
    dropped: int = 0
    filtered: int = 0
    out_of_window: int = 0

    def record(self, status: ObservationStatus) -> None:
        """Increment the counter for an observation status."""
        setattr(self, status, getattr(self, status) + 1)

    def as_dict(self) -> dict[str, int]:
        """Return non-zero status counts."""
        return {
            status: count
            for status, count in {
                "visible": self.visible,
                "delayed": self.delayed,
                "dropped": self.dropped,
                "filtered": self.filtered,
                "out_of_window": self.out_of_window,
            }.items()
            if count
        }


def source_family_for_format(format_name: str) -> str:
    """Return the observation source family for an emitter format name."""
    if format_name.startswith("zeek_"):
        return "zeek"
    return _FORMAT_TO_SOURCE.get(format_name, format_name)


class ObservationPolicy:
    """Applies a named observation profile to rendered source evidence."""

    def __init__(self, profile_name: str = "complete") -> None:
        self.profile_name = profile_name or "complete"
        self.profile = get_observation_profile(self.profile_name)
        if not self.profile and not observation_profile_exists(self.profile_name):
            raise ValueError(f"Unknown observation_profile: {self.profile_name}")
        self.default = self.profile.get("default", {})
        self.sources = self.profile.get("sources", {})

    @property
    def is_complete(self) -> bool:
        """Return True when the profile preserves perfect source coverage."""
        return self.profile_name == "complete"

    def decide(self, format_name: str, event: SecurityEvent) -> ObservationDecision:
        """Return the source-observation decision for an event/emitter pair."""
        source = source_family_for_format(format_name)
        settings = self._settings_for_source(source)
        missingness = self._effective_missingness(source, format_name, event, settings)
        drop_identity = self._event_identity(
            source,
            format_name,
            event,
            force_format_specific=self._has_format_missingness(settings, format_name),
        )
        delay_identity = self._event_identity(source, format_name, event)
        drop_rng = random.Random(
            _stable_seed(f"observation.drop|{self.profile_name}|{drop_identity}")
        )
        if missingness > 0 and drop_rng.random() < missingness:
            return ObservationDecision(status="dropped")

        delay = self._sample_delay(source, event, settings, delay_identity)
        if delay > timedelta(0):
            return ObservationDecision(status="delayed", delay=delay)
        return ObservationDecision(status="visible")

    def decide_raw(self, entry: RawLogEntry) -> ObservationDecision:
        """Return the source-observation decision for a direct raw entry."""
        source = source_family_for_format(entry.target_emitter)
        settings = self._settings_for_source(source)
        missingness = self._effective_missingness_for_host(
            source,
            "",
            settings,
            format_name=entry.target_emitter,
        )
        identity = self._raw_identity(source, entry)
        drop_rng = random.Random(_stable_seed(f"observation.drop|{self.profile_name}|{identity}"))
        if missingness > 0 and drop_rng.random() < missingness:
            return ObservationDecision(status="dropped")
        return ObservationDecision(status="visible")

    def delay_bounds(self, source: str) -> tuple[timedelta, timedelta]:
        """Return configured observation-delay bounds for one source family."""

        settings = self._settings_for_source(source)
        delay = settings.get("delay_ms", {})
        if not isinstance(delay, dict):
            return timedelta(0), timedelta(0)
        min_ms = _safe_int(delay.get("min_ms", 0), 0, minimum=0, maximum=3_600_000)
        max_ms = _safe_int(delay.get("max_ms", 0), 0, minimum=0, maximum=3_600_000)
        if max_ms < min_ms:
            return timedelta(0), timedelta(0)
        return timedelta(milliseconds=min_ms), timedelta(milliseconds=max_ms)

    def maximum_delay_difference(
        self,
        earlier_source: str,
        later_source: str,
    ) -> timedelta:
        """Return the extra causal gap needed across two delayed source families."""

        _earlier_min, earlier_max = self.delay_bounds(earlier_source)
        later_min, _later_max = self.delay_bounds(later_source)
        return max(timedelta(0), earlier_max - later_min)

    def _settings_for_source(self, source: str) -> dict[str, Any]:
        settings = self.sources.get(source, {})
        if not isinstance(settings, dict):
            settings = {}
        if not isinstance(self.default, dict):
            return settings
        merged = dict(self.default)
        merged.update(settings)
        return merged

    def _effective_missingness(
        self, source: str, format_name: str, event: SecurityEvent, settings: dict[str, Any]
    ) -> float:
        if self._preserve_ssh_session_lifecycle(source, event):
            return 0.0
        if self._preserve_logind_session_lifecycle(source, event):
            return 0.0
        if self._preserve_ecar_cron_process_lifecycle(source, event):
            return 0.0
        host = self._host_key_for_event(event)
        return self._effective_missingness_for_host(source, host, settings, format_name=format_name)

    def _effective_missingness_for_host(
        self,
        source: str,
        host: str,
        settings: dict[str, Any],
        *,
        format_name: str | None = None,
    ) -> float:
        base = self._base_missingness(settings, format_name)
        multiplier_range = settings.get("host_missingness_multiplier", {})
        if not isinstance(multiplier_range, dict):
            multiplier_range = {}
        min_mult = _safe_float(multiplier_range.get("min", 1.0), 1.0, minimum=0.0, maximum=10.0)
        max_mult = _safe_float(multiplier_range.get("max", 1.0), 1.0, minimum=0.0, maximum=10.0)
        if max_mult < min_mult:
            min_mult, max_mult = 1.0, 1.0
        if min_mult == max_mult:
            multiplier = min_mult
        else:
            seed = _stable_seed(f"observation.host-mult|{self.profile_name}|{source}|{host}")
            multiplier = random.Random(seed).uniform(min_mult, max_mult)
        return max(0.0, min(base * multiplier, 1.0))

    @staticmethod
    def _base_missingness(settings: dict[str, Any], format_name: str | None) -> float:
        """Return source-level missingness with an optional format override."""
        if format_name:
            format_missingness = settings.get("format_missingness", {})
            if isinstance(format_missingness, dict) and format_name in format_missingness:
                return _safe_probability(format_missingness.get(format_name, 0.0))
        return _safe_probability(settings.get("missingness", 0.0))

    @staticmethod
    def _has_format_missingness(settings: dict[str, Any], format_name: str) -> bool:
        """Return True when a source profile overrides missingness for a format."""
        format_missingness = settings.get("format_missingness", {})
        return isinstance(format_missingness, dict) and format_name in format_missingness

    def _sample_delay(
        self,
        source: str,
        event: SecurityEvent,
        settings: dict[str, Any],
        identity: str,
    ) -> timedelta:
        if event.raw is not None:
            return timedelta(0)
        delay = settings.get("delay_ms", {})
        if not isinstance(delay, dict):
            return timedelta(0)
        min_ms = _safe_int(delay.get("min_ms", 0), 0, minimum=0, maximum=3_600_000)
        max_ms = _safe_int(delay.get("max_ms", 0), 0, minimum=0, maximum=3_600_000)
        if max_ms <= 0 or max_ms < min_ms:
            return timedelta(0)
        seed = _stable_seed(f"observation.delay|{self.profile_name}|{source}|{identity}")
        delay_ms = random.Random(seed).randint(min_ms, max_ms)
        return timedelta(milliseconds=delay_ms)

    def _event_identity(
        self,
        source: str,
        format_name: str,
        event: SecurityEvent,
        *,
        force_format_specific: bool = False,
    ) -> str:
        group = self._coherent_group_key(source, event)
        host = self._host_key_for_event(event)
        timestamp = int(event.timestamp.timestamp() * 1_000_000)
        coherent = self._uses_coherent_source_identity(source, group) and not force_format_specific
        return "|".join(
            [
                source,
                source if coherent else format_name,
                source if coherent else event.event_type,
                host,
                group,
                "" if coherent else str(timestamp),
            ]
        )

    def _raw_identity(self, source: str, entry: RawLogEntry) -> str:
        timestamp = int(entry.timestamp.timestamp() * 1_000_000)
        return "|".join(
            [
                source,
                entry.target_emitter,
                str(timestamp),
                str(sorted(entry.data.items()))[:500],
            ]
        )

    def _coherent_group_key(self, source: str, event: SecurityEvent) -> str:
        if source == "ecar":
            remote_session_group = self._ecar_remote_session_group_key(event)
            if remote_session_group:
                return remote_session_group
        if (
            source == "ecar"
            and event.storyline_cluster_id
            and event.process
            and event.process.pid is not None
        ):
            image = event.process.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            return (
                "storyline-process:"
                f"{event.storyline_cluster_id}:{event.process.username}:"
                f"{event.process.pid}:{image}"
            )
        if source == "ecar" and event.process and event.process.concurrency_group_id:
            return f"process-group:{event.process.concurrency_group_id}"
        if source == "syslog":
            ssh_session_group = self._syslog_ssh_session_group_key(event)
            if ssh_session_group:
                return ssh_session_group
        if source == "syslog" and event.syslog and event.syslog.app_name == "sshd":
            pid = event.syslog.pid if event.syslog.pid not in (None, "") else ""
            if pid:
                return f"sshd:{pid}"
        if event.network:
            uid = getattr(event.network, "uid", "") or getattr(event.network, "zeek_uid", "")
            if uid:
                return f"uid:{uid}"
        if source == "zeek" and event.dns:
            src_ip = event.network.src_ip if event.network else ""
            return f"dns:{event.dns.query}:{event.dns.query_type}:{src_ip}"
        if event.process:
            pid = event.process.pid if event.process.pid is not None else ""
            guid = getattr(event.process, "process_guid", "") or ""
            image = event.process.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            return f"process:{event.process.username}:{pid}:{guid}:{image}"
        if event.auth and event.auth.logon_id:
            return f"session:{event.auth.username}:{event.auth.logon_id}"
        if event.registry:
            return f"registry:{event.registry.key}:{event.registry.value}"
        if event.file:
            return f"file:{event.file.path}:{event.file.action}"
        if event.ids:
            return f"ids:{event.ids.sid}:{event.ids.message}"
        return "event"

    @staticmethod
    def _ecar_remote_session_group_key(event: SecurityEvent) -> str:
        """Return tuple-scoped eCAR grouping for remote session transport and login."""
        host = event.dst_host
        if host is None:
            return ""
        dst_port = 0
        src_ip = ""
        src_port = 0
        dst_ip = host.ip
        if event.network is not None:
            protocol = str(event.network.protocol or "").lower()
            if protocol != "tcp" or event.network.dst_port not in {22, 3389}:
                return ""
            dst_port = int(event.network.dst_port or 0)
            src_ip = str(event.network.src_ip or "")
            src_port = int(event.network.src_port or 0)
            dst_ip = dst_ip or str(event.network.dst_ip or "")
        elif event.auth is not None and event.auth.source_ip and event.auth.source_port:
            if event.event_type == "ssh_session":
                dst_port = 22
            elif event.event_type == "logon" and event.auth.logon_type == 10:
                dst_port = 3389
            else:
                return ""
            src_ip = str(event.auth.source_ip or "")
            src_port = int(event.auth.source_port or 0)
        if not src_ip or src_port <= 0 or dst_port <= 0:
            return ""
        return f"remote-session:{dst_port}:{host.hostname}:{src_ip}:{src_port}:{dst_ip}"

    @staticmethod
    def _uses_coherent_source_identity(source: str, group: str) -> bool:
        """Return whether observation delay/drop should be shared within a source group."""
        if source == "ecar" and group.startswith("remote-session:"):
            return True
        if group.startswith("process:") and source in {"windows_security", "sysmon", "ecar"}:
            return True
        if group.startswith("session:") and source in {"windows_security", "ecar", "syslog"}:
            return True
        if group.startswith("uid:") and source in {
            "zeek",
            "ecar",
            "sysmon",
            "windows_security",
            "proxy",
            "asa",
            "ids",
        }:
            return True
        if source == "syslog" and group.startswith("sshd:"):
            return True
        if source == "syslog" and group.startswith("linux-ssh-session:"):
            return True
        if source == "ecar" and group.startswith("storyline-process:"):
            return True
        if source == "ecar" and group.startswith("process-group:"):
            return True
        if source == "zeek" and (group.startswith("uid:") or group.startswith("dns:")):
            return True
        return False

    @staticmethod
    def _syslog_ssh_session_group_key(event: SecurityEvent) -> str:
        """Return a shared syslog observation key for one SSH session lifecycle."""
        if event.syslog is None or event.auth is None:
            return ""
        app_name = event.syslog.app_name
        message = event.syslog.message
        if app_name == "sshd":
            if not (
                message.startswith("Connection from ")
                or message.startswith("Accepted ")
                or "pam_unix(sshd:session): session " in message
            ):
                return ""
        elif app_name == "systemd-logind":
            if not (message.startswith("New session ") or message.startswith("Removed session ")):
                return ""
        else:
            return ""
        if not event.auth.username or not event.auth.logon_id or not event.auth.session_id:
            return ""
        return (
            f"linux-ssh-session:{event.auth.username}:{event.auth.logon_id}:{event.auth.session_id}"
        )

    @staticmethod
    def _preserve_ssh_session_lifecycle(source: str, event: SecurityEvent) -> bool:
        """Preserve SSH auth lifecycle rows that correlate with endpoint session rows."""
        if source != "syslog" or event.syslog is None:
            return False
        if event.syslog.app_name != "sshd":
            return False
        message = event.syslog.message
        return (
            message.startswith("Connection from ")
            or message.startswith("Accepted ")
            or message.startswith("Invalid user ")
            or message.startswith("Failed password ")
            or message.startswith("Connection closed by ")
            or "pam_unix(sshd:session): session " in message
        )

    @staticmethod
    def _preserve_logind_session_lifecycle(source: str, event: SecurityEvent) -> bool:
        """Preserve logind session rows that correlate with endpoint session rows."""
        if source != "syslog" or event.syslog is None:
            return False
        if event.syslog.app_name != "systemd-logind":
            return False
        message = event.syslog.message
        return message.startswith("New session ") or message.startswith("Removed session ")

    @staticmethod
    def _preserve_ecar_cron_process_lifecycle(source: str, event: SecurityEvent) -> bool:
        """Preserve eCAR cron process rows that are correlated with visible CRON syslog."""
        if source != "ecar" or event.process is None:
            return False
        return event.process.concurrency_group_id.startswith("cron:")

    def _host_key_for_event(self, event: SecurityEvent) -> str:
        host = event.dst_host or event.src_host
        if host:
            return host.hostname or host.ip
        if event.process and event.process.hostname:
            return event.process.hostname
        if event.network:
            return event.network.src_ip
        return ""


def _safe_probability(value: Any) -> float:
    return _safe_float(value, 0.0, minimum=0.0, maximum=1.0)


def _safe_float(value: Any, fallback: float, *, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def _safe_int(value: Any, fallback: int, *, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))
