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
        missingness = self._effective_missingness(source, event, settings)
        identity = self._event_identity(source, format_name, event)
        drop_rng = random.Random(_stable_seed(f"observation.drop|{self.profile_name}|{identity}"))
        if missingness > 0 and drop_rng.random() < missingness:
            return ObservationDecision(status="dropped")

        delay = self._sample_delay(source, event, settings, identity)
        if delay > timedelta(0):
            return ObservationDecision(status="delayed", delay=delay)
        return ObservationDecision(status="visible")

    def decide_raw(self, entry: RawLogEntry) -> ObservationDecision:
        """Return the source-observation decision for a direct raw entry."""
        source = source_family_for_format(entry.target_emitter)
        settings = self._settings_for_source(source)
        missingness = self._effective_missingness_for_host(source, "", settings)
        identity = self._raw_identity(source, entry)
        drop_rng = random.Random(_stable_seed(f"observation.drop|{self.profile_name}|{identity}"))
        if missingness > 0 and drop_rng.random() < missingness:
            return ObservationDecision(status="dropped")
        return ObservationDecision(status="visible")

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
        self, source: str, event: SecurityEvent, settings: dict[str, Any]
    ) -> float:
        if self._preserve_ssh_session_lifecycle(source, event):
            return 0.0
        host = self._host_key_for_event(event)
        return self._effective_missingness_for_host(source, host, settings)

    def _effective_missingness_for_host(
        self, source: str, host: str, settings: dict[str, Any]
    ) -> float:
        base = _safe_probability(settings.get("missingness", 0.0))
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

    def _event_identity(self, source: str, format_name: str, event: SecurityEvent) -> str:
        group = self._coherent_group_key(source, event)
        host = self._host_key_for_event(event)
        timestamp = int(event.timestamp.timestamp() * 1_000_000)
        coherent = self._uses_coherent_source_identity(source, group)
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
    def _uses_coherent_source_identity(source: str, group: str) -> bool:
        """Return whether observation delay/drop should be shared within a source group."""
        if source == "syslog" and group.startswith("sshd:"):
            return True
        if source == "zeek" and (group.startswith("uid:") or group.startswith("dns:")):
            return True
        return False

    @staticmethod
    def _preserve_ssh_session_lifecycle(source: str, event: SecurityEvent) -> bool:
        """Preserve SSH PAM lifecycle rows that correlate with endpoint session rows."""
        if source != "syslog" or event.syslog is None:
            return False
        if event.syslog.app_name != "sshd":
            return False
        return "pam_unix(sshd:session): session " in event.syslog.message

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
