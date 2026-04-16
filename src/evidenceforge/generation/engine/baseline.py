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

"""Baseline generation loop (hour-by-hour iteration).

Contains the BaselineMixin with methods for:
- Hour-by-hour baseline generation
- Event calculation and distribution
- Work-hour multiplier with sigmoid transitions
- User activity generation
- System traffic generation (DNS, NTP, SMB, Kerberos, syslog, etc.)
- Process termination and session logoff
"""

import logging
import math
import random
from datetime import UTC, datetime, timedelta
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.generation.activity.generator import _dns_rtt
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.suspicious_benign import (
    generate_after_hours_admin,
    generate_failed_logon_burst,
    generate_scheduled_scan_overlap,
    generate_service_account_anomaly,
    generate_suspicious_cli,
    generate_suspicious_dns,
    generate_temp_dir_execution,
    generate_unusual_outbound,
    generate_unusual_powershell,
    get_suspicious_event_count,
    pick_suspicious_pattern,
)
from evidenceforge.models.scenario import Persona, User
from evidenceforge.utils.rng import _get_rng, _stable_seed

logger = logging.getLogger(__name__)

# Day-of-week intensity multipliers (0=Monday, 6=Sunday).
# Models weekly rhythm: Monday login storms, Friday early departures,
# weekend near-zero (only sysadmin/oncall personas active).
_DAY_OF_WEEK_MULTIPLIERS = {
    0: 1.15,  # Monday: login storms, catching up
    1: 1.05,  # Tuesday: peak productivity
    2: 1.05,  # Wednesday: peak productivity
    3: 1.00,  # Thursday: normal
    4: 0.85,  # Friday: early departures, lighter load
    5: 0.08,  # Saturday: near-zero
    6: 0.05,  # Sunday: near-zero
}

# Personas that are active on weekends (IT operations, oncall)
_WEEKEND_ACTIVE_PERSONAS = {"sysadmin", "security_analyst", "help_desk"}

# Per-persona cluster configuration (legacy — used as fallback only)
PERSONA_CLUSTER_CONFIG = {
    "developer": {"cluster_size": (5, 15), "inter_gap_mean": 600},
    "executive": {"cluster_size": (2, 6), "inter_gap_mean": 300},
    "analyst": {"cluster_size": (4, 10), "inter_gap_mean": 480},
    "sysadmin": {"cluster_size": (3, 8), "inter_gap_mean": 360},
    "default": {"cluster_size": (3, 10), "inter_gap_mean": 420},
}

# Hawkes process parameters derived from risk_profile.
# No hardcoded persona names — new personas work automatically.
# Ratios tuned to produce CV > 1.0 for users with 30+ events.
_HAWKES_RISK_PARAMS = {
    "high": {"alpha_beta_ratio": 0.60, "beta": 0.06},  # moderate bursts, ~17s decay
    "medium": {"alpha_beta_ratio": 0.50, "beta": 0.07},  # mild bursts, ~14s decay
    "low": {"alpha_beta_ratio": 0.35, "beta": 0.10},  # gentle bursts, ~10s decay
}


def _pick_non_colliding_account_name(
    rng: random.Random,
    existing_accounts: set[str],
    base_names: list[str],
    max_numeric_suffix: int = 9,
) -> str:
    """Pick a synthetic account name that does not collide with scenario-defined accounts.

    Selection is deterministic for a given RNG state and never loops forever:
    1. Choose from base names and base+numeric suffix candidates when available.
    2. Fall back to deterministic underscore suffixes with a bounded search.
    """
    candidate_pool = [*base_names]
    for base_name in base_names:
        candidate_pool.extend(f"{base_name}{suffix}" for suffix in range(1, max_numeric_suffix + 1))

    available = [candidate for candidate in candidate_pool if candidate not in existing_accounts]
    if available:
        return rng.choice(available)

    fallback_base = base_names[0]
    for suffix in range(1, 10_001):
        candidate = f"{fallback_base}_{suffix}"
        if candidate not in existing_accounts:
            return candidate

    msg = "Unable to select non-colliding synthetic account name after bounded fallback search"
    raise ValueError(msg)


def _hawkes_params_from_persona(persona: Persona | None) -> dict:
    """Derive Hawkes kernel parameters from persona risk_profile.

    Returns dict with alpha_beta_ratio and beta. Caller computes:
        alpha = alpha_beta_ratio * beta
        mu = num_events / duration * (1 - alpha/beta)
    """
    risk = persona.risk_profile if persona and persona.risk_profile else "medium"
    return _HAWKES_RISK_PARAMS.get(risk, _HAWKES_RISK_PARAMS["medium"])


# Benign CreateRemoteThread pairs: (src_pid_key, src_image, tgt_pid_key, tgt_image)
_BENIGN_CRT_PAIRS = [
    (
        "msmpeng",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe",
        "explorer",
        r"C:\Windows\explorer.exe",
    ),
    (
        "msmpeng",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe",
        "runtime_broker",
        r"C:\Windows\System32\RuntimeBroker.exe",
    ),
    (
        "csrss_s0",
        r"C:\Windows\System32\csrss.exe",
        "svchost_local_system",
        r"C:\Windows\System32\svchost.exe",
    ),
    (
        "svchost_netsvcs",
        r"C:\Windows\System32\svchost.exe",
        "taskhostw",
        r"C:\Windows\System32\taskhostw.exe",
    ),
]

# Benign ProcessAccess pairs: (src_pid_key, src_image, tgt_pid_key, tgt_image, granted_access)
_BENIGN_PA_PAIRS = [
    (
        "msmpeng",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe",
        "explorer",
        r"C:\Windows\explorer.exe",
        "0x1410",
    ),
    (
        "msmpeng",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe",
        "svchost_netsvcs",
        r"C:\Windows\System32\svchost.exe",
        "0x1010",
    ),
    (
        "msmpeng",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe",
        "lsass",
        r"C:\Windows\System32\lsass.exe",
        "0x1410",
    ),
    (
        "csrss_s0",
        r"C:\Windows\System32\csrss.exe",
        "explorer",
        r"C:\Windows\explorer.exe",
        "0x1000",
    ),
    (
        "csrss_s0",
        r"C:\Windows\System32\csrss.exe",
        "svchost_local_system",
        r"C:\Windows\System32\svchost.exe",
        "0x1000",
    ),
    (
        "services",
        r"C:\Windows\System32\services.exe",
        "svchost_netsvcs",
        r"C:\Windows\System32\svchost.exe",
        "0x1000",
    ),
    (
        "services",
        r"C:\Windows\System32\services.exe",
        "msmpeng",
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe",
        "0x1000",
    ),
    (
        "svchost_local_system",
        r"C:\Windows\System32\svchost.exe",
        "lsass",
        r"C:\Windows\System32\lsass.exe",
        "0x1000",
    ),
    (
        "csrss_s0",
        r"C:\Windows\System32\csrss.exe",
        "lsass",
        r"C:\Windows\System32\lsass.exe",
        "0x1000",
    ),
    (
        "svchost_netsvcs",
        r"C:\Windows\System32\svchost.exe",
        "lsass",
        r"C:\Windows\System32\lsass.exe",
        "0x1000",
    ),
    (
        "services",
        r"C:\Windows\System32\services.exe",
        "lsass",
        r"C:\Windows\System32\lsass.exe",
        "0x1000",
    ),
]

# Synthetic SYSTEM user for baseline Event 8/10 generation
_SYSTEM_USER = User(
    username="SYSTEM",
    full_name="NT AUTHORITY\\SYSTEM",
    email="system@system.local",
)


_SCHEDULES_PATH = get_activity_directory() / "systemd_schedules.yaml"
_CACHED_SCHEDULES: list[dict[str, Any]] | None = None

_DAY_NAME_TO_INT = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}


def _merge_systemd_schedules(default: dict, overlay: dict) -> dict:
    """Merge overlay systemd schedules into defaults (keyed by service name)."""
    result = dict(default)
    if "schedules" in overlay:
        result["schedules"] = merge_keyed_list(
            default.get("schedules", []),
            overlay["schedules"],
            key_field="service",
        )
    return result


def _load_systemd_schedules() -> list[dict[str, Any]]:
    """Load systemd/cron schedule definitions from YAML. Cached after first call."""
    global _CACHED_SCHEDULES
    if _CACHED_SCHEDULES is not None:
        return _CACHED_SCHEDULES

    data = load_with_overlay(
        _SCHEDULES_PATH, "activity/systemd_schedules.yaml", _merge_systemd_schedules
    )
    _CACHED_SCHEDULES = data.get("schedules", [])
    return _CACHED_SCHEDULES


class BaselineMixin:
    """Mixin providing baseline activity generation methods."""

    # Make PERSONA_CLUSTER_CONFIG accessible as class attribute
    PERSONA_CLUSTER_CONFIG = PERSONA_CLUSTER_CONFIG

    def _generate_scheduled_tasks(
        self,
        current_hour: datetime,
        system: Any,
        rng: Any,
        sys_pids: dict,
        is_rhel_like: bool,
        has_web_role: bool,
    ) -> None:
        """Generate cron/systemd timer events at realistic frequencies.

        Each scheduled task fires at most once per day (or once per week for
        weekly tasks) instead of appearing randomly in every hourly loop.
        Per-host jitter is deterministic so the same host always runs tasks
        at the same time.
        """

        schedules = _load_systemd_schedules()

        for sched in schedules:
            # Filter by distro
            distro = sched.get("distro", "all")
            if distro == "debian" and is_rhel_like:
                continue
            if distro == "rhel" and not is_rhel_like:
                continue

            # Filter by role
            role = sched.get("role")
            if role == "web_server" and not has_web_role:
                continue

            service = sched["service"]
            frequency = sched.get("frequency", "daily")
            typical_hour = sched.get("typical_hour", 6)
            jitter_minutes = sched.get("jitter_minutes", 30)

            # Deterministic per-host jitter offset
            jitter_seed = _stable_seed(f"sched_{system.hostname}_{service}")
            jitter_offset_min = jitter_seed % max(1, jitter_minutes)

            if frequency == "daily":
                # Compute the actual fire hour for this host
                fire_hour = (typical_hour + jitter_offset_min // 60) % 24
                if current_hour.hour != fire_hour:
                    continue
                fire_minute = jitter_offset_min % 60
            elif frequency == "weekly":
                typical_day = _DAY_NAME_TO_INT.get(sched.get("typical_day", "monday"), 0)
                # Jitter can shift across days for weekly tasks
                fire_day = (typical_day + jitter_offset_min // (24 * 60)) % 7
                remaining = jitter_offset_min % (24 * 60)
                fire_hour = (typical_hour + remaining // 60) % 24
                fire_minute = remaining % 60
                if current_hour.weekday() != fire_day:
                    continue
                if current_hour.hour != fire_hour:
                    continue
            elif frequency == "30min":
                # Fires twice per hour at fixed offsets
                fire_minute_1 = jitter_offset_min % 30
                fire_minute_2 = fire_minute_1 + 30
                fire_minute = fire_minute_1  # use first slot
            else:
                continue

            # Compute event timestamp
            if frequency == "30min":
                # Generate two events per hour
                for fm in (fire_minute_1, fire_minute_2):
                    ts = current_hour + timedelta(minutes=fm, seconds=rng.uniform(0, 30))
                    self._emit_scheduled_event(sched, system, ts, rng, sys_pids, is_rhel_like)
            else:
                ts = current_hour + timedelta(minutes=fire_minute, seconds=rng.uniform(0, 59))
                self._emit_scheduled_event(sched, system, ts, rng, sys_pids, is_rhel_like)

    def _emit_scheduled_event(
        self,
        sched: dict,
        system: Any,
        ts: datetime,
        rng: Any,
        sys_pids: dict,
        is_rhel_like: bool,
    ) -> None:
        """Emit syslog/process events for a single scheduled task firing."""
        sched_type = sched.get("type", "systemd_timer")
        service = sched["service"]
        systemd_pid = sys_pids.get("systemd", 1)

        self.state_manager.set_current_time(ts)

        if sched_type == "systemd_timer":
            process_path = sched.get("process_path", f"/usr/lib/systemd/{service}")

            # Optional timer trigger message (from PID 1)
            timer_msg = sched.get("timer_message")
            if timer_msg:
                self.activity_generator.generate_syslog_event(
                    system=system,
                    time=ts - timedelta(seconds=rng.uniform(0.1, 1.0)),
                    app_name="systemd",
                    message=timer_msg,
                    pid=1,
                )

            # Starting message + process create
            start_msg = sched.get("start_message", f"Starting {service}.service.")
            svc_pid = self.activity_generator.generate_system_process(
                system=system,
                time=ts,
                process_name=process_path,
                command_line=process_path,
                parent_pid=systemd_pid,
                username="root",
                syslog_message=start_msg,
            )

            # Detail messages (e.g., logrotate per-file messages)
            detail_messages = sched.get("detail_messages")
            if detail_messages:
                distro_key = "rhel" if is_rhel_like else "debian"
                msgs = detail_messages.get(distro_key, [])
                detail_delay = rng.uniform(0.5, 2.0)
                for msg in msgs:
                    detail_ts = ts + timedelta(seconds=detail_delay)
                    self.activity_generator.generate_syslog_event(
                        system=system,
                        time=detail_ts,
                        app_name=service,
                        message=msg,
                        pid=svc_pid if svc_pid else rng.randint(10000, 60000),
                    )
                    detail_delay += rng.uniform(0.2, 1.0)

            # Finished message + process terminate
            finish_delay = rng.uniform(0.5, 5.0)
            finish_ts = ts + timedelta(seconds=finish_delay)
            self.state_manager.set_current_time(finish_ts)
            finish_msg = sched.get("finish_message", f"Finished {service}.service.")
            self.activity_generator.generate_system_process_termination(
                system=system,
                time=finish_ts,
                pid=svc_pid,
                process_name=process_path,
                parent_pid=systemd_pid,
                username="root",
                syslog_message=finish_msg,
            )

        elif sched_type == "cron":
            cron_user = sched.get("cron_user", "root")
            cron_commands = sched.get("cron_commands", {})
            # Pick the right command for this distro
            if is_rhel_like:
                cmd = cron_commands.get("rhel", cron_commands.get("all", ""))
            else:
                cmd = cron_commands.get("debian", cron_commands.get("all", ""))
            if not cmd:
                return

            self.activity_generator.generate_system_process(
                system=system,
                time=ts,
                process_name="/usr/sbin/cron",
                command_line=cmd,
                parent_pid=sys_pids.get("cron", 0),
                username=cron_user,
            )

    def _generate_hour(
        self,
        current_hour: datetime,
        enabled_users: list,
        *,
        emit_storylines: bool = True,
        flush_emitters: bool = True,
    ) -> None:
        """Generate one hour of baseline activity.

        Used by both the warm-up loop and the real baseline loop. During warm-up,
        storyline/red-herring execution and emitter flushing are skipped.
        """
        self.state_manager.set_current_time(current_hour)

        # Compute local weekday for day-of-week variation
        if hasattr(self, "_scenario_tz") and self._scenario_tz:
            local_dt = current_hour.replace(tzinfo=UTC).astimezone(self._scenario_tz)
        else:
            local_dt = current_hour
        local_weekday = local_dt.weekday()  # 0=Monday..6=Sunday
        is_weekend = local_weekday >= 5

        for user in enabled_users:
            persona = self._get_user_persona(user)
            user_offsets = self._user_time_offsets.get(user.username)

            # Weekend filtering: skip non-IT personas on weekends
            if is_weekend and persona:
                persona_key = (persona.name or "").lower()
                if persona_key not in _WEEKEND_ACTIVE_PERSONAS:
                    continue

            local_hour = local_dt.hour
            num_events = self._calculate_events_for_hour(
                user,
                current_hour=local_hour,
                persona=persona,
                user_offsets=user_offsets,
                weekday=local_weekday,
            )

            if num_events > 0:
                rng = _get_rng()
                if rng.random() < 0.20:
                    continue

                persona_name = user.persona if user.persona else None
                event_times = self._distribute_events_in_hour(
                    current_hour,
                    num_events,
                    persona_name=persona_name,
                    username=user.username,
                )

                for event_time in event_times:
                    self._generate_user_activity(user, event_time)

        # Pre-decide logoffs so profile traffic can bound persona timestamps
        planned_logoffs = self._plan_logoffs_for_hour(enabled_users, current_hour)

        self._generate_system_traffic(current_hour, planned_logoffs=planned_logoffs)
        self._generate_stale_account_noise(current_hour)
        self._generate_baseline_failed_logons(current_hour)
        self._generate_lateral_movement_noise(current_hour)
        self._generate_suspicious_noise(current_hour)
        self._generate_firewall_deny_baseline(current_hour)

        if emit_storylines:
            hour_key = int(current_hour.timestamp())
            for _event_time, event_idx in self._storyline_by_hour.get(hour_key, []):
                if event_idx not in self._storyline_executed:
                    self._execute_single_storyline_event(event_idx)
                    self._storyline_executed.add(event_idx)

            for _event_time, event_idx in self._red_herring_by_hour.get(hour_key, []):
                if event_idx not in self._red_herring_executed:
                    self._execute_single_red_herring_event(event_idx)
                    self._red_herring_executed.add(event_idx)

        self._terminate_stale_processes(current_hour)
        self._generate_logoffs_for_hour(enabled_users, current_hour, planned_logoffs)

        if flush_emitters:
            self._barrier_flush_all_emitters()

    def _generate_baseline(self) -> None:
        """Generate baseline activity for all enabled users.

        Iterates hour-by-hour through the time window, generating activity
        for each enabled user based on their persona, intensity, and variation.
        Optionally runs a warm-up phase first to pre-populate state.
        """
        logger.info("Starting baseline activity generation")

        enabled_users = [u for u in self.scenario.environment.users if u.enabled]
        logger.info(f"Generating baseline for {len(enabled_users)} enabled users")

        # Emit initial DHCP leases (during warm-up they're suppressed from output
        # but establish lease state for periodic renewals)
        self._emit_dhcp_leases()

        # --- Warm-up phase: pre-populate state without emitting ---
        warmup_hours = math.ceil(self.warmup_duration.total_seconds() / 3600)
        if warmup_hours > 0:
            logger.info(f"Running {warmup_hours}-hour warm-up for state pre-population")
            self._report_progress(
                "phase_start",
                {
                    "phase": "warmup",
                    "description": f"Warm-up: pre-populating state ({warmup_hours}h)",
                },
            )

            current_hour = self.warmup_start_time
            warmup_count = 0

            while current_hour < self.start_time:
                warmup_count += 1
                logger.debug(f"Warm-up hour {warmup_count}/{warmup_hours}: {current_hour}")

                self._report_progress(
                    "warmup_progress",
                    {
                        "hour": warmup_count,
                        "total_hours": warmup_hours,
                        "current_time": current_hour,
                    },
                )

                self._generate_hour(
                    current_hour, enabled_users, emit_storylines=False, flush_emitters=False
                )
                self.state_manager.sweep_closed_connections()
                current_hour += timedelta(hours=1)

            logger.info(f"Warm-up complete: processed {warmup_count} hours")
            self._report_progress("phase_end", {"phase": "warmup"})

        # --- Real baseline: emit sensor startup and begin output ---
        self._emit_sensor_startup()

        total_hours = int((self.end_time - self.start_time).total_seconds() / 3600)
        current_hour = self.start_time
        hour_count = 0

        while current_hour < self.end_time:
            hour_count += 1
            logger.debug(f"Processing hour {hour_count}: {current_hour}")

            self._report_progress(
                "hour_progress",
                {"hour": hour_count, "total_hours": total_hours, "current_time": current_hour},
            )

            self._generate_hour(current_hour, enabled_users)
            # Evict completed/failed connections to bound memory during long runs
            self.state_manager.sweep_closed_connections()
            current_hour += timedelta(hours=1)

        logger.info(f"Baseline generation complete: processed {hour_count} hours")

    def _generate_stale_account_noise(self, current_hour: datetime) -> None:
        """Generate noise events for stale/inactive accounts.

        Simulates multiple traces left by accounts that are disabled but still
        referenced by automated systems:
        - Failed network logons (~15%/hour): monitoring, backup trying cached creds
        - Kerberos pre-auth failures (~5%/hour): cached TGT renewal attempts on DC
        - Scheduled task failures (~3%/hour): lingering tasks configured with stale creds
        - Service startup failures (~2%/hour, first hour only): services using stale creds
        """
        stale_accounts = self.scenario.environment.stale_accounts
        if not stale_accounts:
            return

        rng = _get_rng()
        systems = self.scenario.environment.systems
        servers = [s for s in systems if s.type in ("server", "domain_controller")]
        dcs = [s for s in systems if s.type == "domain_controller"]
        windows_servers = [s for s in servers if "windows" in s.os.lower()]
        target_systems = servers if servers else systems

        # Check if this is the first hour of the scenario (for service startup failures)
        is_first_hour = current_hour == self.start_time

        for stale in stale_accounts:
            stale_user = User(
                username=stale.username,
                full_name=stale.username,
                email=f"{stale.username}@system.local",
                enabled=False,
            )

            # Pattern 1: Failed network logon (~15%/hour)
            if rng.random() < 0.15:
                target_system = rng.choice(target_systems)
                source_system = rng.choice(target_systems)
                event_time = current_hour + timedelta(seconds=rng.uniform(0, 3599))
                self.state_manager.set_current_time(event_time)
                self.activity_generator.generate_failed_logon(
                    user=stale_user,
                    system=target_system,
                    time=event_time,
                    logon_type=3,
                    source_ip=source_system.ip,
                )

            # Pattern 2: Kerberos pre-auth failure on DC (~15%/hour)
            if rng.random() < 0.15 and dcs:
                dc = rng.choice(dcs)
                source_system = rng.choice(target_systems)
                event_time = current_hour + timedelta(seconds=rng.uniform(0, 3599))
                self.state_manager.set_current_time(event_time)
                self.activity_generator.generate_kerberos_preauth_failed(
                    username=stale.username,
                    source_ip=source_system.ip,
                    dc_hostname=dc.hostname,
                    time=event_time,
                    status="0x12",  # KDC_ERR_CLIENT_REVOKED (disabled account)
                )

            # Pattern 3: Scheduled task failure (~3%/hour)
            if rng.random() < 0.03 and windows_servers:
                task_host = rng.choice(windows_servers)
                event_time = current_hour + timedelta(seconds=rng.uniform(0, 3599))
                self.state_manager.set_current_time(event_time)
                # Failed batch logon for the scheduled task
                self.activity_generator.generate_failed_logon(
                    user=stale_user,
                    system=task_host,
                    time=event_time,
                    logon_type=4,  # Batch logon (scheduled task)
                    source_ip=task_host.ip,
                )

            # Pattern 4: Service startup failure (first hour only, ~2%)
            if is_first_hour and rng.random() < 0.02 and windows_servers:
                svc_host = rng.choice(windows_servers)
                event_time = current_hour + timedelta(seconds=rng.randint(0, 300))
                self.state_manager.set_current_time(event_time)
                # Failed service logon
                self.activity_generator.generate_failed_logon(
                    user=stale_user,
                    system=svc_host,
                    time=event_time,
                    logon_type=5,  # Service logon
                    source_ip=svc_host.ip,
                )

    def _generate_baseline_failed_logons(self, current_hour: datetime) -> None:
        """Generate realistic baseline failed logon patterns.

        Three patterns:
        1. Password typo: 1-2 failed logons immediately before a successful one
        2. Scheduled task with stale creds: periodic failures on specific hosts
        3. Management sweep: burst of failures across multiple servers
        """
        rng = _get_rng()
        systems = self.scenario.environment.systems
        servers = [s for s in systems if s.type in ("server", "domain_controller")]
        if not servers:
            servers = systems
        enabled_users = [u for u in self.scenario.environment.users if u.enabled]
        if not enabled_users:
            return

        # Pattern 1: Password typo before successful logon (~3 per hour in
        # a medium environment). Pick a random user and system.
        n_typos = rng.randint(1, max(1, len(enabled_users) // 3))
        for _ in range(n_typos):
            if rng.random() > 0.15:  # ~15% chance per slot
                continue
            user = rng.choice(enabled_users)
            system = next(
                (s for s in systems if s.assigned_user == user.username),
                rng.choice(systems),
            )
            base_time = current_hour + timedelta(seconds=rng.uniform(0, 3599))
            self.state_manager.set_current_time(base_time)
            # 1-2 failures then success
            n_fails = rng.randint(1, 2)
            for i in range(n_fails):
                fail_time = base_time + timedelta(seconds=i * rng.randint(2, 8))
                self.activity_generator.generate_failed_logon(
                    user=user,
                    system=system,
                    time=fail_time,
                    logon_type=2,  # interactive
                )

        # Pattern 2: Scheduled task with stale creds (deterministic per scenario).
        # Pick 1-2 hosts and a plausible service account name.
        _sched_seed = _stable_seed(self.scenario.name + "_sched_fail")
        _sched_rng = random.Random(_sched_seed)
        _svc_names = ["svc_backup", "svc_monitor", "svc_report", "svc_deploy", "svc_scan"]
        # Ensure no collision with actual scenario accounts
        _existing = {u.username for u in self.scenario.environment.users} | set(
            self.scenario.environment.service_accounts
        )
        _sched_acct = _pick_non_colliding_account_name(
            rng=_sched_rng,
            existing_accounts=_existing,
            base_names=_svc_names,
        )
        _sched_user = User(
            username=_sched_acct,
            full_name=_sched_acct,
            email=f"{_sched_acct}@system.local",
            enabled=False,
        )
        n_sched_hosts = min(2, len(servers))
        _sched_hosts = _sched_rng.sample(servers, n_sched_hosts)
        # Fires every 1-2 hours (check if this hour is a firing hour)
        _sched_interval = _sched_rng.choice([1, 2])
        hour_idx = int((current_hour - self.start_time).total_seconds() / 3600)
        if hour_idx % _sched_interval == 0:
            for host in _sched_hosts:
                sched_time = current_hour + timedelta(
                    seconds=_sched_rng.randint(0, 300)  # first 5 minutes of hour
                )
                self.state_manager.set_current_time(sched_time)
                self.activity_generator.generate_failed_logon(
                    user=_sched_user,
                    system=host,
                    time=sched_time,
                    logon_type=4,  # batch (scheduled task)
                    source_ip=host.ip,
                )

        # Pattern 3: Management software sweep (1-2 per business day).
        # Use scenario-local time for business-hour gating.
        _local = current_hour
        if hasattr(self, "_scenario_tz") and self._scenario_tz and current_hour.tzinfo is not None:
            _local = current_hour.astimezone(self._scenario_tz)
        is_business = 0 <= _local.weekday() <= 4 and 8 <= _local.hour <= 17
        # Fire at ~10am and ~2pm (deterministic per scenario)
        if is_business and _local.hour in (10, 14) and rng.random() < 0.5:
            _mgmt_acct = _pick_non_colliding_account_name(
                rng=rng,
                existing_accounts=_existing,
                base_names=["svc_mgmt"],
            )
            _mgmt_user = User(
                username=_mgmt_acct,
                full_name=_mgmt_acct,
                email=f"{_mgmt_acct}@system.local",
                enabled=False,
            )
            n_targets = min(rng.randint(5, 15), len(servers))
            targets = rng.sample(servers, n_targets)
            sweep_start = current_hour + timedelta(seconds=rng.randint(0, 1800))
            for i, target in enumerate(targets):
                sweep_time = sweep_start + timedelta(seconds=i * rng.uniform(1.0, 3.0))
                self.state_manager.set_current_time(sweep_time)
                self.activity_generator.generate_failed_logon(
                    user=_mgmt_user,
                    system=target,
                    time=sweep_time,
                    logon_type=3,  # network
                    source_ip=rng.choice(servers).ip,
                )

        # Pattern 4: Active-user Kerberos pre-auth failure (password typo at lock screen).
        # ~2% chance per active user per hour → 0-2 events total in a 10-user scenario.
        dcs = [s for s in systems if s.type == "domain_controller"]
        if dcs:
            for user in enabled_users:
                if rng.random() < 0.02:
                    dc = rng.choice(dcs)
                    user_system = next(
                        (s for s in systems if s.assigned_user == user.username),
                        rng.choice(systems),
                    )
                    event_time = current_hour + timedelta(seconds=rng.uniform(0, 3599))
                    self.state_manager.set_current_time(event_time)
                    self.activity_generator.generate_kerberos_preauth_failed(
                        username=user.username,
                        source_ip=user_system.ip,
                        dc_hostname=dc.hostname,
                        time=event_time,
                        status="0x18",  # KDC_ERR_PREAUTH_FAILED (bad password)
                    )

    def _generate_lateral_movement_noise(self, current_hour: datetime) -> None:
        """Generate legitimate service account lateral movement between servers.

        Produces realistic inter-server traffic that analysts must distinguish
        from malicious lateral movement: backup agents, monitoring, patching,
        AD replication, application-to-database connections, etc.

        Each pattern is conditional on the environment having the required
        infrastructure (file servers, DB servers, DCs, Linux hosts, etc.).
        """
        rng = _get_rng()
        systems = self.scenario.environment.systems
        if len(systems) < 2:
            return

        # Classify systems by role and OS for pattern matching
        dcs = [s for s in systems if s.type == "domain_controller"]
        servers = [s for s in systems if s.type in ("server", "domain_controller")]
        workstations = [s for s in systems if s.type == "workstation"]
        windows_sys = [s for s in systems if "windows" in s.os.lower()]
        linux_sys = [s for s in systems if _get_os_category(s.os) == "linux"]

        # Role-based classification
        file_servers = [s for s in servers if "file_server" in s.roles]
        db_servers = [s for s in servers if "database" in s.roles or "db_server" in s.roles]
        web_servers = [s for s in servers if "web_server" in s.roles]
        mail_servers = [s for s in servers if "mail_server" in s.roles]
        print_servers = [s for s in servers if "print_server" in s.roles]
        dns_servers = [s for s in servers if "dns_server" in s.roles]
        nfs_servers = [s for s in linux_sys if "nfs_server" in s.roles]

        # Compute local hour for time-of-day gating
        if hasattr(self, "_scenario_tz") and self._scenario_tz:
            local_dt = current_hour.replace(tzinfo=UTC).astimezone(self._scenario_tz)
        else:
            local_dt = current_hour
        local_hour = local_dt.hour
        is_business_hours = 8 <= local_hour <= 18

        def _emit_conn(src_sys, dst_sys, port, service=None, proto="tcp", pattern_key=""):
            """Helper: emit a connection with hash-based periodic offset."""
            # Deterministic phase per (pattern, src, dst) triple for reproducibility
            phase_seed = f"lat_{pattern_key}_{src_sys.hostname}_{dst_sys.hostname}_{port}"
            phase = _stable_seed(phase_seed) % 3600
            jitter = rng.gauss(0, 60)  # ~1min jitter
            offset = max(0, min(3599, phase + jitter))
            ts = current_hour + timedelta(seconds=offset)
            self.state_manager.set_current_time(ts)
            self.activity_generator.generate_connection(
                src_ip=src_sys.ip,
                dst_ip=dst_sys.ip,
                time=ts,
                dst_port=port,
                proto=proto,
                service=service,
                duration=rng.uniform(0.1, 30.0),
                orig_bytes=rng.randint(200, 5000),
                resp_bytes=rng.randint(500, 50000),
                emit_dns=True,
                source_system=src_sys,
            )

        # === Windows Server Patterns ===

        # 1. Backup agent → file servers (SMB 445)
        if file_servers and servers:
            for fs in file_servers:
                if rng.random() < 0.40:  # 1-3/hour → ~40% per check
                    src = rng.choice([s for s in servers if s != fs] or servers)
                    _emit_conn(src, fs, 445, "smb")

        # 2. Backup agent → database servers (SQL 1433)
        if db_servers and servers:
            for db in db_servers:
                if rng.random() < 0.30:
                    src = rng.choice([s for s in servers if s != db] or servers)
                    _emit_conn(src, db, 1433, "sql")

        # 3. Monitoring agent → managed Windows hosts (WMI 135)
        if windows_sys and len(windows_sys) > 1:
            monitored = rng.sample(windows_sys, min(rng.randint(1, 3), len(windows_sys)))
            for target in monitored:
                if rng.random() < 0.50:
                    src = rng.choice([s for s in servers if s != target] or windows_sys)
                    _emit_conn(src, target, 135)

        # 4. Deployment/patching → app servers (WinRM 5985)
        if servers and len(servers) > 1:
            if rng.random() < 0.20:
                src = rng.choice(servers)
                dst = rng.choice([s for s in servers if s != src] or servers)
                _emit_conn(src, dst, 5985)

        # 5. Vulnerability scanner → hosts (multi-port, bursty)
        if rng.random() < 0.05 and len(systems) > 1:  # Rare — scan window
            targets = rng.sample(systems, min(rng.randint(2, 5), len(systems)))
            scanner = rng.choice(servers or systems)
            for target in targets:
                if target != scanner:
                    port = rng.choice([22, 80, 135, 443, 445, 3389, 8080])
                    _emit_conn(scanner, target, port)

        # 6. Log collector → hosts (TCP 9997)
        if servers and len(systems) > 1:
            if rng.random() < 0.30:
                collector = rng.choice(servers)
                target = rng.choice([s for s in systems if s != collector] or systems)
                _emit_conn(collector, target, 9997)

        # 7. AD replication between DCs (LDAP 389)
        if len(dcs) >= 2:
            for _ in range(rng.randint(2, 4)):
                src_dc, dst_dc = rng.sample(dcs, 2)
                _emit_conn(src_dc, dst_dc, 389, "ldap")

        # 8. Print server → workstations (SMB 445)
        if print_servers and workstations:
            if rng.random() < 0.25:
                ps = rng.choice(print_servers)
                ws = rng.choice(workstations)
                _emit_conn(ps, ws, 445, "smb")

        # 9. WSUS → Windows clients (HTTP 8530)
        if servers and workstations:
            if rng.random() < 0.10:
                wsus = rng.choice(servers)
                client = rng.choice(workstations)
                _emit_conn(wsus, client, 8530, "http")

        # 10. Certificate authority → servers (HTTPS 443)
        if servers and len(servers) > 1:
            if rng.random() < 0.05:
                ca = rng.choice(servers)
                target = rng.choice([s for s in servers if s != ca] or servers)
                _emit_conn(ca, target, 443, "ssl")

        # 11. DFS replication → file servers (RPC 135)
        if len(file_servers) >= 2:
            for _ in range(rng.randint(1, 3)):
                src_fs, dst_fs = rng.sample(file_servers, 2)
                _emit_conn(src_fs, dst_fs, 135)

        # 12. Exchange → DCs (LDAP 389)
        if mail_servers and dcs:
            for _ in range(rng.randint(3, 6)):
                ms = rng.choice(mail_servers)
                dc = rng.choice(dcs)
                _emit_conn(ms, dc, 389, "ldap")

        # === Application Patterns ===

        # 13. HR app → database (SQL 1433, business hours)
        if db_servers and servers and is_business_hours:
            if rng.random() < 0.50:
                app_srv = rng.choice([s for s in servers if s not in db_servers] or servers)
                db = rng.choice(db_servers)
                for _ in range(rng.randint(2, 5)):
                    _emit_conn(app_srv, db, 1433, "sql")

        # 14. Web app → database (various ports)
        if web_servers and db_servers:
            for ws in web_servers:
                num_queries = rng.randint(5, 15) if is_business_hours else rng.randint(1, 3)
                db = rng.choice(db_servers)
                port = rng.choice([1433, 3306, 5432])
                svc = {1433: "sql", 3306: "mysql", 5432: "postgresql"}.get(port, "sql")
                for _ in range(num_queries):
                    _emit_conn(ws, db, port, svc)

        # 15. CI/CD → build targets (SSH 22, business hours)
        if linux_sys and len(linux_sys) > 1 and is_business_hours:
            if rng.random() < 0.20:
                ci = rng.choice(linux_sys)
                target = rng.choice([s for s in linux_sys if s != ci] or linux_sys)
                _emit_conn(ci, target, 22, "ssh")

        # === Security Infrastructure ===

        # 16. EDR management → endpoints (HTTPS 443)
        if servers and len(systems) > 1:
            if rng.random() < 0.10:
                mgmt = rng.choice(servers)
                endpoint = rng.choice([s for s in systems if s != mgmt] or systems)
                _emit_conn(mgmt, endpoint, 443, "ssl")

        # 17. DNS zone transfers (TCP 53)
        if len(dns_servers) >= 2:
            if rng.random() < 0.30:
                primary, secondary = rng.sample(dns_servers, 2)
                _emit_conn(secondary, primary, 53, "dns")
        elif dcs and len(dcs) >= 2:
            if rng.random() < 0.30:
                primary, secondary = rng.sample(dcs, 2)
                _emit_conn(secondary, primary, 53, "dns")

        # 18. RADIUS auth (UDP 1812)
        if dcs and workstations:
            if rng.random() < 0.15:
                ws = rng.choice(workstations)
                dc = rng.choice(dcs)
                offset = rng.uniform(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                self.activity_generator.generate_connection(
                    src_ip=ws.ip,
                    dst_ip=dc.ip,
                    time=ts,
                    dst_port=1812,
                    proto="udp",
                    duration=rng.uniform(0.01, 0.1),
                    orig_bytes=rng.randint(100, 300),
                    resp_bytes=rng.randint(100, 300),
                    source_system=ws,
                )

        # 19. VPN concentrator → internal (matches remote user activity)
        # Modeled as external-to-internal connections through a server
        if servers and rng.random() < 0.10:
            vpn_gw = rng.choice(servers)
            internal = rng.choice([s for s in systems if s != vpn_gw] or systems)
            _emit_conn(vpn_gw, internal, rng.choice([443, 445, 3389]))

        # === Linux Patterns ===

        # 20. NFS mounts (TCP 2049)
        if nfs_servers and linux_sys:
            clients = [s for s in linux_sys if s not in nfs_servers]
            if clients:
                for client in rng.sample(clients, min(2, len(clients))):
                    if rng.random() < 0.40:
                        _emit_conn(client, rng.choice(nfs_servers), 2049, "nfs")

        # 21. Config management → Linux hosts (SSH 22)
        if linux_sys and len(linux_sys) > 1:
            if rng.random() < 0.20:
                mgmt = rng.choice(linux_sys)
                target = rng.choice([s for s in linux_sys if s != mgmt] or linux_sys)
                _emit_conn(mgmt, target, 22, "ssh")

        # 22. rsync backup between Linux servers (SSH 22)
        linux_servers = [s for s in linux_sys if s.type in ("server", "domain_controller")]
        if len(linux_servers) >= 2:
            if rng.random() < 0.20:
                src, dst = rng.sample(linux_servers, 2)
                _emit_conn(src, dst, 22, "ssh")

        # 23. Docker registry pull (HTTPS 443 or 5000)
        if linux_sys and len(linux_sys) > 1:
            if rng.random() < 0.15:
                puller = rng.choice(linux_sys)
                registry = rng.choice([s for s in linux_sys if s != puller] or linux_sys)
                _emit_conn(puller, registry, rng.choice([443, 5000]), "ssl")

        # 24. Cron SCP/SFTP transfers (SSH 22)
        if len(linux_sys) >= 2:
            if rng.random() < 0.15:
                src, dst = rng.sample(linux_sys, 2)
                _emit_conn(src, dst, 22, "ssh")

        # 25. Centralized syslog relay (TCP 514)
        if linux_sys and len(linux_sys) > 1:
            if rng.random() < 0.30:
                sender = rng.choice(linux_sys)
                collector = rng.choice([s for s in linux_sys if s != sender] or linux_sys)
                offset = rng.uniform(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                self.activity_generator.generate_connection(
                    src_ip=sender.ip,
                    dst_ip=collector.ip,
                    time=ts,
                    dst_port=514,
                    proto="tcp",
                    duration=rng.uniform(1.0, 60.0),
                    orig_bytes=rng.randint(500, 10000),
                    resp_bytes=rng.randint(50, 200),
                    source_system=sender,
                )

        # 26. LDAP client → directory server (389/636)
        if linux_sys and dcs:
            for lx in rng.sample(linux_sys, min(2, len(linux_sys))):
                if rng.random() < 0.25:
                    dc = rng.choice(dcs)
                    port = rng.choice([389, 636])
                    svc = "ldap" if port == 389 else "ssl"
                    _emit_conn(lx, dc, port, svc)

    def _ensure_session_on_system(self, user: User, system, time, rng) -> str:
        """Ensure the user has an active session on the target system.

        Returns the logon_id for the session. If no session exists on
        this specific system, creates a logon with an appropriate type
        (interactive for workstations, network/RDP for servers).
        """
        if hasattr(self, "world_planner"):
            session = self.world_planner.ensure_user_session(user, system, time, rng)
            return session.logon_id

        sessions = self.state_manager.get_sessions_for_user(user.username)
        session_on_system = next((s for s in sessions if s.system == system.hostname), None)
        if session_on_system:
            return session_on_system.logon_id

        logon_time = time - timedelta(seconds=rng.randint(1, 5))
        self.state_manager.set_current_time(logon_time)
        sys_type = (system.type or "workstation").lower()
        logon_type = (
            rng.choices([3, 10], weights=[70, 30], k=1)[0]
            if sys_type
            in (
                "server",
                "domain_controller",
            )
            else 2
        )
        return self.activity_generator.generate_logon(
            user=user,
            system=system,
            time=logon_time,
            logon_type=logon_type,
        )

    def _generate_suspicious_noise(self, current_hour: datetime) -> None:
        """Generate suspicious-but-benign ambient noise events.

        Creates events that look suspicious in isolation but have legitimate
        explanations: after-hours admin logins, PowerShell/cmd on non-admin
        workstations, failed logon bursts, service account anomalies.
        """
        noise_level = self.scenario.baseline_activity.suspicious_noise
        rng = _get_rng()

        num_events = get_suspicious_event_count(noise_level, rng)
        if num_events == 0:
            return

        enabled_users = [u for u in self.scenario.environment.users if u.enabled]
        systems = self.scenario.environment.systems
        personas = self.scenario.personas

        for _ in range(num_events):
            pattern_info = pick_suspicious_pattern(
                rng, enabled_users, systems, personas, current_hour
            )
            if not pattern_info:
                continue

            pattern_type = pattern_info["type"]

            if pattern_type == "after_hours_admin":
                result = generate_after_hours_admin(rng, enabled_users, systems, current_hour)
                if result:
                    self.activity_generator.generate_logon(
                        user=result["user"],
                        system=result["system"],
                        time=result["time"],
                        logon_type=result["logon_type"],
                    )

            elif pattern_type == "suspicious_cli":
                result = generate_suspicious_cli(rng, enabled_users, systems, current_hour)
                if result:
                    logon_id = self._ensure_session_on_system(
                        result["user"], result["system"], result["time"], rng
                    )
                    self.activity_generator.generate_process(
                        user=result["user"],
                        system=result["system"],
                        time=result["time"],
                        logon_id=logon_id,
                        process_name=result["process_name"],
                        command_line=result["command_line"],
                    )

            elif pattern_type == "failed_logon_burst":
                result = generate_failed_logon_burst(rng, enabled_users, systems, current_hour)
                if result:
                    # Generate failed logons followed by a success
                    user = result["user"]
                    system = result["system"]
                    base_time = result["time"]
                    for i in range(result["num_failures"]):
                        fail_time = base_time + timedelta(seconds=i * rng.randint(2, 8))
                        self.activity_generator.generate_failed_logon(
                            user=user,
                            system=system,
                            time=fail_time,
                            logon_type=2,  # Interactive (typing password wrong)
                        )
                    # Successful logon after the failures
                    success_time = base_time + timedelta(
                        seconds=result["num_failures"] * 5 + rng.randint(3, 15)
                    )
                    self.activity_generator.generate_logon(
                        user=user,
                        system=system,
                        time=success_time,
                        logon_type=2,
                    )

            elif pattern_type == "service_account_anomaly":
                result = generate_service_account_anomaly(rng, enabled_users, systems, current_hour)
                if result:
                    self.activity_generator.generate_logon(
                        user=result["user"],
                        system=result["system"],
                        time=result["time"],
                        logon_type=result["logon_type"],
                    )

            elif pattern_type == "suspicious_dns":
                result = generate_suspicious_dns(rng, enabled_users, systems, current_hour)
                if result:
                    # Emit DNS query via a UDP/53 connection with DnsContext
                    from evidenceforge.events.contexts import DnsContext

                    dns_ctx = DnsContext(
                        query=result["hostname"],
                        trans_id=rng.randint(1, 65535),
                        qtype=1,
                        query_type="A",
                        rcode="NOERROR",
                        rcode_num=0,
                        answers=[f"198.51.100.{rng.randint(1, 254)}"],
                        TTLs=[float(rng.randint(30, 300))],
                        rtt=_dns_rtt(rng),
                    )
                    dns_server_ips = getattr(
                        self.activity_generator, "_dns_server_ips", ["10.0.0.1"]
                    )
                    self.state_manager.set_current_time(result["time"])
                    self.activity_generator.generate_connection(
                        src_ip=result["system"].ip,
                        dst_ip=rng.choice(dns_server_ips),
                        time=result["time"],
                        dst_port=53,
                        proto="udp",
                        service="dns",
                        duration=rng.uniform(0.001, 0.05),
                        orig_bytes=rng.randint(40, 100),
                        resp_bytes=rng.randint(80, 400),
                        dns=dns_ctx,
                    )

            elif pattern_type == "unusual_outbound":
                result = generate_unusual_outbound(rng, enabled_users, systems, current_hour)
                if result:
                    self.state_manager.set_current_time(result["time"])
                    # Large transfers get bigger byte counts
                    if result.get("large_transfer"):
                        orig_bytes = rng.randint(500000, 5000000)
                        resp_bytes = rng.randint(1000, 50000)
                        duration = rng.uniform(10.0, 120.0)
                    else:
                        orig_bytes = rng.randint(500, 5000)
                        resp_bytes = rng.randint(1000, 50000)
                        duration = rng.uniform(0.5, 10.0)
                    self.activity_generator.generate_connection(
                        src_ip=result["system"].ip,
                        dst_ip=result["dst_ip"],
                        time=result["time"],
                        dst_port=result["dst_port"],
                        service=result["service"],
                        duration=duration,
                        orig_bytes=orig_bytes,
                        resp_bytes=resp_bytes,
                        emit_dns=True,
                        hostname=result.get("hostname"),
                    )

            elif pattern_type == "scheduled_scan_overlap":
                result = generate_scheduled_scan_overlap(rng, enabled_users, systems, current_hour)
                if result:
                    scanner = result["scanner"]
                    scan_ports = [22, 80, 135, 443, 445, 3389, 8080, 8443]
                    for target in result["targets"]:
                        for port in rng.sample(scan_ports, rng.randint(2, 4)):
                            scan_time = result["time"] + timedelta(seconds=rng.uniform(0, 30))
                            self.state_manager.set_current_time(scan_time)
                            self.activity_generator.generate_connection(
                                src_ip=scanner.ip,
                                dst_ip=target.ip,
                                time=scan_time,
                                dst_port=port,
                                proto="tcp",
                                duration=rng.uniform(0.01, 0.5),
                                orig_bytes=rng.randint(50, 200),
                                resp_bytes=rng.randint(50, 500),
                            )

            elif pattern_type in ("temp_dir_execution", "unusual_powershell"):
                gen_fn = (
                    generate_temp_dir_execution
                    if pattern_type == "temp_dir_execution"
                    else generate_unusual_powershell
                )
                result = gen_fn(rng, enabled_users, systems, current_hour)
                if result:
                    self.state_manager.set_current_time(result["time"])
                    logon_id = self._ensure_session_on_system(
                        result["user"], result["system"], result["time"], rng
                    )
                    self.activity_generator.generate_process(
                        user=result["user"],
                        system=result["system"],
                        time=result["time"],
                        logon_id=logon_id,
                        process_name=result["process_name"],
                        command_line=result["command_line"],
                    )

    def _terminate_stale_processes(self, current_hour: datetime) -> None:
        """Terminate processes that have exceeded their expected lifetime.

        Called per-hour. Process lifetime depends on type:
        - System processes (svchost, lsass, csrss, services, explorer): never
        - Browsers/editors (chrome, firefox, outlook, code): 1-4 hours
        - Build tools (msbuild, gcc, npm): 5-30 minutes
        - Other: 30min-2 hours
        """
        system_patterns = (
            # Windows core
            "svchost",
            "lsass",
            "csrss",
            "services.exe",
            "explorer.exe",
            "smss",
            "wininit",
            "winlogon",
            "fontdrvhost",
            "dwm.exe",
            "userinit.exe",
            "runtimebroker",
            "taskhostw",
            "searchindexer",
            "msmpeng",
            # Linux core
            "systemd",
            "cron",
            "crond",
            "sshd",
            "rsyslogd",
            "journald",
            "udevd",
            "logind",
            "snapd",
            "timesyncd",
            "networkmanager",
            "dbus-daemon",
            "bash",
            "agetty",
        )
        short_lived = ("msbuild", "gcc", "npm", "make", "dotnet", "cargo", "node.exe")

        # Collect all seeded system PIDs for this system as a safety net
        seeded_pids: dict[str, set[int]] = {}
        for hostname, pid_map in self._system_pids.items():
            seeded_pids[hostname] = set(pid_map.values())

        rng = _get_rng()
        for system in self.scenario.environment.systems:
            protected_pids = seeded_pids.get(system.hostname, set())
            processes = self.state_manager.get_processes_on_system(system.hostname)
            for proc in list(processes):
                proc_age_hours = (current_hour - proc.start_time).total_seconds() / 3600
                image_lower = proc.image.lower()

                # Never terminate seeded system processes (pattern match + PID safety net)
                if any(p in image_lower for p in system_patterns):
                    continue
                if proc.pid in protected_pids:
                    continue
                # Story processes handle their own termination
                if proc.story_created:
                    continue

                if any(p in image_lower for p in short_lived):
                    max_hours = rng.uniform(0.08, 0.5)
                elif any(
                    p in image_lower
                    for p in ("chrome", "firefox", "edge", "outlook", "teams", "code")
                ):
                    max_hours = rng.uniform(1.0, 4.0)
                else:
                    max_hours = rng.uniform(0.5, 2.0)

                if proc_age_hours > max_hours and rng.random() < 0.85:
                    actor = self._find_actor(proc.username)
                    if not actor:
                        continue

                    logon_id = proc.logon_id
                    if not logon_id:
                        sessions = self.state_manager.get_sessions_for_user(proc.username)
                        session = next(
                            (
                                candidate
                                for candidate in sessions
                                if candidate.system == system.hostname
                            ),
                            None,
                        )
                        logon_id = session.logon_id if session else "0x0"

                    term_offset = rng.uniform(0, 3599)
                    term_time = current_hour + timedelta(seconds=term_offset)
                    self.state_manager.set_current_time(term_time)
                    self.activity_generator.generate_process_termination(
                        user=actor,
                        system=system,
                        time=term_time,
                        pid=proc.pid,
                        process_name=proc.image,
                        logon_id=logon_id,
                    )

    def _evaluate_firewall_policy(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        sensor,
        segment_cidrs: dict,
    ) -> str:
        """Evaluate a connection against the firewall's policy rules.

        Walks rules in order (first match wins). Returns 'permit' or 'deny'.
        If no rule matches, returns sensor.default_action.
        """
        import ipaddress as _ipaddress

        def _resolve_segment(ip: str) -> str:
            """Resolve an IP to a segment name, or 'external' if not in any."""
            for seg_name, cidr in segment_cidrs.items():
                try:
                    if _ipaddress.ip_address(ip) in cidr:
                        return seg_name
                except (ValueError, KeyError):
                    continue
            return "external"

        def _matches_specifier(ip: str, ip_segment: str, spec: str) -> bool:
            """Check if an IP/segment matches a rule specifier."""
            if spec == "any":
                return True
            if spec == "external":
                return ip_segment == "external"
            if spec == ip_segment:
                return True
            # Try IP match
            try:
                if _ipaddress.ip_address(ip) == _ipaddress.ip_address(spec):
                    return True
            except ValueError:
                pass
            # Try CIDR match
            try:
                if _ipaddress.ip_address(ip) in _ipaddress.ip_network(spec, strict=False):
                    return True
            except ValueError:
                pass
            return False

        src_seg = _resolve_segment(src_ip)
        dst_seg = _resolve_segment(dst_ip)

        for rule in sensor.policy:
            if not _matches_specifier(src_ip, src_seg, rule.src):
                continue
            if not _matches_specifier(dst_ip, dst_seg, rule.dst):
                continue
            # Check port (empty list = any)
            if rule.ports:
                port_list = [int(p) if isinstance(p, int) else p for p in rule.ports]
                if "any" not in port_list and dst_port not in port_list:
                    continue
            return rule.action

        return sensor.default_action

    def _generate_firewall_deny_baseline(self, current_hour: datetime) -> None:
        """Generate denied connection events for firewall sensors.

        For each firewall-type sensor, generates deny events proportional to
        the estimated allow traffic (controlled by deny_ratio). Deny targets
        are connections that violate the sensor's policy rules.
        """
        if not self.scenario.environment.network or not self.scenario.environment.network.sensors:
            return

        rng = _get_rng()

        # Pre-compute segment CIDRs for IP matching
        import ipaddress

        segments = self.scenario.environment.network.segments
        segment_cidrs: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
        for seg in segments:
            try:
                segment_cidrs[seg.name] = ipaddress.ip_network(seg.cidr, strict=False)
            except ValueError:
                continue

        # Collect internal IPs from scenario systems
        internal_ips = [s.ip for s in self.scenario.environment.systems if s.ip]

        # Commonly targeted ports for external scanning
        _SCAN_PORTS = [22, 23, 80, 443, 445, 1433, 3389, 5432, 8080, 8443]
        # Ports rarely allowed in corporate firewalls
        _BLOCKED_PORTS = [23, 135, 137, 138, 139, 445, 1433, 3389, 5900, 6379]

        for sensor in self.scenario.environment.network.sensors:
            if sensor.type != "firewall" or "cisco_asa" not in sensor.log_formats:
                continue
            if sensor.deny_ratio <= 0:
                continue

            # Build public scan target pool from visibility engine
            _public_cidrs: list = []
            _vip_to_real: dict[str, str] = {}
            if hasattr(self, "dispatcher") and self.dispatcher.visibility_engine:
                _ve = self.dispatcher.visibility_engine
                _public_cidrs = _ve._public_cidrs
                _vip_to_real = _ve._vip_to_real_ip

            def _pick_public_scan_target(
                _cidrs: list = _public_cidrs,  # noqa: B006
            ) -> str:
                """Pick a random IP from the org's public address space."""
                if not _cidrs:
                    return rng.choice(internal_ips) if internal_ips else "10.0.10.1"
                # Weight by CIDR size (minimum 1 to handle /31 and /32)
                cidr = rng.choices(
                    _cidrs,
                    weights=[max(1, net.num_addresses) for net in _cidrs],
                    k=1,
                )[0]
                # Handle /32 (single host) and /31 (point-to-point)
                if cidr.num_addresses <= 2:
                    return str(cidr.network_address)
                offset = rng.randint(1, cidr.num_addresses - 2)
                return str(cidr.network_address + offset)

            # Estimate allow traffic: ~10-20 connections per internal system per hour
            estimated_allows = len(internal_ips) * rng.randint(10, 20)
            deny_count = int(estimated_allows * sensor.deny_ratio)
            if deny_count <= 0:
                continue

            from evidenceforge.events.contexts import FirewallContext

            sensor_interfaces = sensor.interfaces
            deny_conn_state = "REJ" if sensor.drop_mode == "reject" else "S0"

            def _resolve_iface(ip: str, _ifaces: dict = sensor_interfaces) -> str:  # noqa: B006
                for seg_name, cidr in segment_cidrs.items():
                    try:
                        if ipaddress.ip_address(ip) in cidr:
                            return _ifaces.get(seg_name, seg_name)
                    except ValueError:
                        continue
                return _ifaces.get("_default", "outside")

            # Generate deny events — only emit connections the policy would deny
            generated = 0
            attempts = 0
            max_attempts = deny_count * 5
            while generated < deny_count and attempts < max_attempts:
                attempts += 1

                # Choose deny pattern candidate
                roll = rng.random()
                if roll < 0.60:
                    # External -> public address space (scanner pool + public CIDRs)
                    src_ip = rng.choices(
                        self._external_scanner_ips,
                        weights=self._external_scanner_weights,
                        k=1,
                    )[0]
                    dst_ip = _pick_public_scan_target()
                    dst_port = rng.choice(_SCAN_PORTS)
                    proto = "tcp"
                elif roll < 0.80:
                    # Cross-segment blocked
                    if len(internal_ips) >= 2:
                        src_ip, dst_ip = rng.sample(internal_ips, 2)
                    else:
                        src_ip = internal_ips[0] if internal_ips else "10.0.10.1"
                        dst_ip = "10.0.20.1"
                    dst_port = rng.choice(_BLOCKED_PORTS)
                    proto = "tcp"
                elif roll < 0.90:
                    # Outbound blocked — only workstations generate suspicious outbound;
                    # servers never initiate random connections on scanning ports
                    workstation_ips = [
                        s.ip
                        for s in self.scenario.environment.systems
                        if (s.type or "workstation").lower() == "workstation" and s.ip
                    ]
                    if not workstation_ips:
                        continue
                    src_ip = rng.choice(workstation_ips)
                    dst_ip = self._generate_external_client_ip(rng)
                    dst_port = rng.choice(_BLOCKED_PORTS)
                    proto = "tcp"
                else:
                    # ICMP ping sweep from external (use scanner pool + public CIDRs)
                    src_ip = rng.choices(
                        self._external_scanner_ips,
                        weights=self._external_scanner_weights,
                        k=1,
                    )[0]
                    dst_ip = _pick_public_scan_target()
                    dst_port = 8  # ICMP echo request type
                    proto = "icmp"

                # Policy evaluation uses real (post-NAT) IPs for modern ASA.
                # Resolve VIP back to real_ip; non-VIP public IPs resolve to
                # "external" segment which always hits default deny.
                policy_dst_ip = _vip_to_real.get(dst_ip, dst_ip)
                if (
                    self._evaluate_firewall_policy(
                        src_ip, policy_dst_ip, dst_port, sensor, segment_cidrs
                    )
                    != "deny"
                ):
                    continue

                offset_sec = rng.uniform(0, 3600)
                ts = current_hour + timedelta(seconds=offset_sec)
                self.state_manager.set_current_time(ts)

                src_iface = _resolve_iface(src_ip)
                dst_iface = _resolve_iface(dst_ip)
                acl_name = f"{src_iface}_access_in"

                fw_ctx = FirewallContext(
                    action="deny",
                    msg_id=106023,
                    connection_id=0,
                    src_interface=src_iface,
                    dst_interface=dst_iface,
                    access_group=acl_name,
                )

                self.activity_generator.generate_connection(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    time=ts,
                    dst_port=dst_port,
                    proto=proto,
                    conn_state=deny_conn_state,
                    firewall=fw_ctx,
                )
                generated += 1

    def _plan_logoffs_for_hour(
        self,
        users: list[User],
        current_hour: datetime,
    ) -> dict[tuple[str, str], float]:
        """Pre-decide which sessions log off this hour and at what offset.

        Called before system traffic so profile traffic can bound persona
        connection timestamps to before the planned logoff.

        Returns:
            Dict mapping (system_hostname, logon_id) → offset_seconds within hour.
        """
        planned: dict[tuple[str, str], float] = {}
        for user in users:
            sessions = self.state_manager.get_sessions_for_user(user.username)
            if not sessions:
                continue

            persona = self._get_user_persona(user)
            is_outside_work_hours = False
            if persona and persona.work_hours_parsed:
                # Use scenario-local time for work-hour checks, not UTC.
                # Guard against naive datetimes (treat as UTC).
                _local_hour = current_hour
                if (
                    hasattr(self, "_scenario_tz")
                    and self._scenario_tz
                    and current_hour.tzinfo is not None
                ):
                    _local_hour = current_hour.astimezone(self._scenario_tz)
                is_outside_work_hours = _local_hour.hour not in persona.work_hours_parsed.get(
                    "hours", range(24)
                )

            for session in list(sessions):
                # Never baseline-close a storyline-created session — the
                # storyline controls when these sessions end.
                if session.storyline_protected:
                    continue
                sess_start = session.start_time
                hour_ts = current_hour
                if sess_start.tzinfo is not None and hour_ts.tzinfo is None:
                    hour_ts = hour_ts.replace(tzinfo=UTC)
                elif sess_start.tzinfo is None and hour_ts.tzinfo is not None:
                    sess_start = sess_start.replace(tzinfo=UTC)
                session_age_hours = (hour_ts - sess_start).total_seconds() / 3600
                if session_age_hours < 0.5:
                    continue

                rng = _get_rng()
                logoff_probability = (
                    0.6 if is_outside_work_hours else 0.3 if session_age_hours > 1 else 0.1
                )
                if rng.random() < logoff_probability:
                    logoff_offset = rng.uniform(0, 3599)
                    planned[(session.system, session.logon_id)] = logoff_offset
        return planned

    def _generate_logoffs_for_hour(
        self,
        users: list[User],
        current_hour: datetime,
        planned_logoffs: dict[tuple[str, str], float],
    ) -> None:
        """Execute pre-planned logoff events for sessions ending this hour."""
        # Build user/system lookup for logoff emission
        user_map = {u.username: u for u in users}
        for (_system_hostname, logon_id), offset in planned_logoffs.items():
            # Find the session to get username and logon_type
            session = self.state_manager.get_session(logon_id)
            if not session:
                continue
            # Re-check protection — storyline may have marked this session
            # as protected after logoff was planned earlier in the hour.
            if session.storyline_protected:
                continue
            user = user_map.get(session.username)
            if not user:
                continue

            # Resolve system from the session's host, not the user's primary system
            system = next(
                (s for s in self.scenario.environment.systems if s.hostname == session.system),
                None,
            )
            if not system:
                continue

            logoff_time = current_hour + timedelta(seconds=offset)
            self.state_manager.set_current_time(logoff_time)
            self.activity_generator.generate_logoff(
                user=user,
                system=system,
                time=logoff_time,
                logon_id=session.logon_id,
                logon_type=session.logon_type,
            )

    def _barrier_flush_all_emitters(self) -> None:
        """Flush all emitters and wait for completion (hour-level barrier).

        Ensures temporal consistency: all events for hour N are written
        before hour N+1 begins.
        """
        logger.debug("Barrier flush: waiting for all emitters to complete")
        for _format_name, emitter in self.emitters.items():
            emitter.barrier_flush()
        logger.debug("Barrier flush: all emitters complete")

    def _get_user_persona(self, user: User) -> Persona | None:
        """Resolve user.persona string to Persona object."""
        if not user.persona or not self.scenario.personas:
            return None
        for persona in self.scenario.personas:
            if persona.name == user.persona:
                return persona
        return None

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Sigmoid function for smooth temporal transitions."""
        return 1.0 / (1.0 + math.exp(-6.0 * x))

    def _work_hour_multiplier(
        self,
        hour: int,
        whp: dict,
        user_offsets: dict | None = None,
        weekday: int | None = None,
    ) -> float:
        """Calculate activity multiplier based on work hours with smooth transitions.

        Returns 0.0-1.5 multiplier (before day-of-week scaling). Uses sigmoid
        ramps for gradual transitions at work start/end and lunch, instead of
        binary on/off. When weekday is provided (0=Monday..6=Sunday), the result
        is further scaled by _DAY_OF_WEEK_MULTIPLIERS.
        """
        start = whp["start"]
        end = whp["end"]
        lunch = whp.get("lunch")
        peak_hours = whp.get("peak_hours") or []

        if user_offsets:
            start += user_offsets.get("start_offset", 0)
            end += user_offsets.get("end_offset", 0)
            if lunch:
                lunch_start = lunch[0] + user_offsets.get("lunch_start_offset", 0)
                lunch_dur_offset = user_offsets.get("lunch_duration_offset", 0)
                lunch_end = lunch[1] + user_offsets.get("lunch_start_offset", 0) + lunch_dur_offset
                lunch = (lunch_start, lunch_end)

        h = float(hour) + 0.5

        # Compute intra-day multiplier from work-hour sigmoid model
        if h < start - 1.5:
            base = 0.05
        elif h < start + 0.5:
            t = (h - (start - 1.0)) / 1.5
            base = 0.05 + 0.95 * self._sigmoid(t * 2 - 1)
        elif h > end + 1.5:
            base = 0.05
        elif h > end - 0.5:
            t = (h - (end - 0.5)) / 1.5
            base = 0.05 + 0.95 * (1.0 - self._sigmoid(t * 2 - 1))
        elif lunch:
            lunch_start, lunch_end = lunch
            lunch_mid = (lunch_start + lunch_end) / 2.0
            lunch_half = (lunch_end - lunch_start) / 2.0
            if lunch_start - 0.5 < h < lunch_end + 0.5:
                dist_from_mid = abs(h - lunch_mid)
                if dist_from_mid < lunch_half:
                    base = 0.5
                else:
                    t = (dist_from_mid - lunch_half) / 0.5
                    base = 0.5 + 0.5 * min(1.0, t)
            elif hour in peak_hours:
                base = 1.5
            else:
                base = 1.0
        elif hour in peak_hours:
            base = 1.5
        else:
            base = 1.0

        # Apply day-of-week scaling (Monday login storms, weekend near-zero)
        if weekday is not None:
            base *= _DAY_OF_WEEK_MULTIPLIERS.get(weekday, 1.0)

        return base

    def _calculate_events_for_hour(
        self,
        user: User,
        current_hour: int | None = None,
        persona: Persona | None = None,
        user_offsets: dict | None = None,
        weekday: int | None = None,
    ) -> int:
        """Calculate number of events for user this hour."""
        intensity_map = {"low": 5, "medium": 15, "high": 40}
        base_events = intensity_map[self.scenario.baseline_activity.intensity]

        if persona and persona.risk_profile:
            risk_mult = {"low": 0.7, "medium": 1.0, "high": 1.3}
            base_events = int(base_events * risk_mult.get(persona.risk_profile, 1.0))

        if persona and persona.work_hours_parsed and current_hour is not None:
            multiplier = self._work_hour_multiplier(
                current_hour, persona.work_hours_parsed, user_offsets, weekday=weekday
            )
            base_events = int(base_events * multiplier)

        if user_offsets and "intensity_bias" in user_offsets:
            base_events = int(base_events * user_offsets["intensity_bias"])

        rng = _get_rng()
        variation_map = {"low": 0.10, "medium": 0.25, "high": 0.50}
        stddev = base_events * variation_map[self.scenario.baseline_activity.variation]
        num_events = max(0, int(rng.gauss(base_events, stddev)))

        return num_events

    def _distribute_events_in_hour_uniform(
        self, hour_start: datetime, num_events: int
    ) -> list[datetime]:
        """Distribute events uniformly (legacy fallback)."""
        if num_events == 0:
            return []

        rng = _get_rng()
        interval = 3600 / num_events
        times = []
        for i in range(num_events):
            offset = interval * i + rng.uniform(-interval * 0.25, interval * 0.25)
            offset = max(0, min(3599, offset))
            times.append(hour_start + timedelta(seconds=offset))
        return sorted(times)

    def _distribute_events_in_hour(
        self,
        hour_start: datetime,
        num_events: int,
        persona_name: str | None = None,
        username: str | None = None,
    ) -> list[datetime]:
        """Distribute events using a Hawkes self-exciting process.

        Replaces the Phase 5.5 cluster model with a Hawkes process that
        produces self-exciting bursts with exponential decay. Parameters
        are derived from persona risk_profile, so new personas work
        automatically without code changes.

        Cross-hour continuity: intensity state carries across hours via
        _hawkes_states dict, so a burst at 9:55 naturally continues into 10:00.
        """
        if num_events == 0:
            return []

        from evidenceforge.utils.timing import hawkes_timestamps

        # Derive Hawkes parameters from persona
        persona = None
        if persona_name:
            for p in self.scenario.personas:
                if p.name == persona_name:
                    persona = p
                    break
        params = _hawkes_params_from_persona(persona)
        alpha_beta_ratio = params["alpha_beta_ratio"]
        beta = params["beta"]

        # Apply per-user biases
        if username and hasattr(self, "_user_time_offsets"):
            user_offsets = self._user_time_offsets.get(username, {})
            size_bias = 1.0 + user_offsets.get("cluster_size_bias", 0)
            alpha_beta_ratio = min(0.75, alpha_beta_ratio * size_bias)
            gap_bias = 1.0 + user_offsets.get("inter_gap_bias", 0)
            beta = max(0.03, beta * gap_bias)

        alpha = alpha_beta_ratio * beta
        # Adaptive mu: calibrate base rate so expected count ≈ num_events
        mu = num_events / 3600.0 * (1.0 - alpha_beta_ratio)
        mu = max(0.0001, mu)

        rng = _get_rng()

        # Retrieve cross-hour state
        state = None
        elapsed = 0.0
        state_key = username or "_default"
        if hasattr(self, "_hawkes_states"):
            prev_state = self._hawkes_states.get(state_key)
            if prev_state is not None:
                state = prev_state
                elapsed = 3600.0  # one full hour since last window

        offsets, new_state = hawkes_timestamps(
            num_events=num_events,
            duration=3600.0,
            mu=mu,
            alpha=alpha,
            beta=beta,
            rng=rng,
            state=state,
            elapsed_since_last=elapsed,
        )

        # Store state for next hour
        if hasattr(self, "_hawkes_states"):
            self._hawkes_states[state_key] = new_state

        if not offsets:
            return []

        # Convert offsets to datetimes
        times = [hour_start + timedelta(seconds=t) for t in offsets]

        # Dedup: max 5 events within 5 seconds (prevent multi-format collisions)
        final: list[datetime] = [times[0]]
        for ts in times[1:]:
            recent = sum(1 for prev in final[-5:] if (ts - prev).total_seconds() <= 5.0)
            if recent < 5:
                final.append(ts)
            else:
                final.append(final[-1] + timedelta(seconds=rng.uniform(5.1, 8.0)))

        return sorted(final)

    def _generate_user_activity(self, user: User, event_time: datetime) -> None:
        """Generate activity for user at specified time."""
        rng = _get_rng()
        if hasattr(self, "world_model"):
            system = self.world_model.pick_activity_system(user, rng)
        elif user.primary_system:
            systems = [
                s for s in self.scenario.environment.systems if s.hostname == user.primary_system
            ]
            system = systems[0] if systems else rng.choice(self.scenario.environment.systems)
        else:
            assigned_systems = [
                s for s in self.scenario.environment.systems if s.assigned_user == user.username
            ]
            if assigned_systems:
                system = rng.choice(assigned_systems)
            else:
                system = rng.choice(self.scenario.environment.systems)

        persona = self._get_user_persona(user)
        persona_name = user.persona if user.persona else None
        pattern = self.activity_generator.get_baseline_pattern(persona_name, persona=persona)

        pattern = list(pattern)
        rng.shuffle(pattern)

        if rng.random() < 0.15:
            return

        activities = []
        for activity_type, probability in pattern:
            if rng.random() < probability:
                if rng.random() < 0.20:
                    activities.extend([activity_type] * rng.randint(2, 4))
                else:
                    activities.append(activity_type)

        sessions = self.state_manager.get_sessions_for_user(user.username)
        has_session_on_system = any(s.system == system.hostname for s in sessions)
        if not has_session_on_system and activities:
            if hasattr(self, "world_planner"):
                self.world_planner.ensure_user_session(user, system, event_time, rng)
            else:
                self._ensure_session_on_system(user, system, event_time, rng)

        for activity_type in activities:
            jitter = timedelta(seconds=rng.randint(0, 55))
            t = event_time + jitter
            self.state_manager.set_current_time(t)
            self.activity_generator.execute_baseline_activity(
                user=user, system=system, time=t, activity_type=activity_type
            )

    def _get_server_ssh_users(self, system) -> list:
        """Return the subset of admin users who would SSH into this server.

        Sysadmins access all servers. Other personas are added based on
        server role (determined from services and hostname). Workstations
        return only their assigned user. Results are cached per hostname.
        """
        if hasattr(self, "world_model"):
            return self.world_model.get_remote_admin_users(system)

        if not hasattr(self, "_ssh_user_roster_cache"):
            self._ssh_user_roster_cache: dict[str, list] = {}
        if system.hostname in self._ssh_user_roster_cache:
            return self._ssh_user_roster_cache[system.hostname]

        from evidenceforge.generation.activity.bash_commands import _resolve_server_role

        enabled_users = [u for u in self.scenario.environment.users if u.enabled]

        # Workstations: only the assigned user
        if system.type == "workstation" and system.assigned_user:
            roster = [u for u in enabled_users if u.username == system.assigned_user]
            self._ssh_user_roster_cache[system.hostname] = roster
            return roster

        # Servers: sysadmins always, plus role-specific personas
        admin_personas = {"sysadmin", "help_desk"}
        sysadmins = [u for u in enabled_users if (u.persona or "").lower() in admin_personas]

        server_role = _resolve_server_role(system.hostname, system.services)
        role_personas: set[str] = set()
        if server_role == "db":
            role_personas = {"developer", "data_analyst", "analyst"}
        elif server_role == "web":
            role_personas = {"developer"}
        elif server_role == "log":
            role_personas = {"security_analyst"}

        role_users = [u for u in enabled_users if (u.persona or "").lower() in role_personas]

        # Deduplicate by username, preserving order
        seen = set()
        roster = []
        for u in sysadmins + role_users:
            if u.username not in seen:
                seen.add(u.username)
                roster.append(u)

        # Fallback: at least 2 admin users
        if len(roster) < 2:
            all_admins = [
                u
                for u in enabled_users
                if (u.persona or "").lower()
                in ("sysadmin", "help_desk", "developer", "security_analyst")
            ]
            for u in all_admins:
                if u.username not in seen:
                    seen.add(u.username)
                    roster.append(u)
                if len(roster) >= 2:
                    break

        self._ssh_user_roster_cache[system.hostname] = roster
        return roster

    # Service→DNS tag defaults for external resolution when dns_tags is absent
    _SERVICE_DNS_DEFAULTS: dict[str, tuple[str, ...]] = {
        "smtp": ("email",),
        "dns": ("background",),
        "ntp": ("background",),
    }

    def _resolve_role(
        self,
        role: str,
        exclude_ip: str,
        rng: Any,
        os_cat: str = "windows",
        dns_tags: list[str] | None = None,
        inbound: bool = False,
        src_host: str = "",
        service: str = "",
    ) -> tuple[str | None, str | None]:
        """Resolve a role name to (ip, hostname), excluding a specific IP.

        Works for both outbound (exclude_ip = source) and inbound
        (exclude_ip = destination). Returns (None, None) if no suitable
        system exists in the scenario.

        Args:
            inbound: If True, _external resolves to a random client IP
                (realistic for internet clients hitting a server).
                If False, _external resolves via dns_registry
                (realistic for outbound destinations like CDNs/APIs).
            src_host: Source hostname for DNS affinity (per-host IP caching).
            service: Network service (ssl, smtp, etc.) for default tag derivation.
        """
        if role == "_external":
            if inbound:
                ip = self._generate_external_client_ip(rng)
                return ip, None
            from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

            if dns_tags:
                tags = tuple(dns_tags)
            elif service in self._SERVICE_DNS_DEFAULTS:
                tags = self._SERVICE_DNS_DEFAULTS[service]
            else:
                tags = ("background", os_cat)
            domain, ip = pick_domain_and_ip(rng, *tags, src_host=src_host)
            return ip, domain

        if hasattr(self, "world_model"):
            src_system = next(
                (system for system in self.scenario.environment.systems if system.ip == exclude_ip),
                None,
            )
            if src_system is not None:
                return self.world_model.resolve_destination(
                    dest_role=role,
                    src_system=src_system,
                    rng=rng,
                    os_category=os_cat,
                    dns_tags=dns_tags,
                    service=service,
                )

        if role in ("_dc", "domain_controller"):
            dc_ips = self._infra_ips.get("dc", [])
            candidates = [ip for ip in dc_ips if ip != exclude_ip]
            return (rng.choice(candidates), None) if candidates else (None, None)
        if role == "_any_server":
            servers = [
                s.ip
                for s in self.scenario.environment.systems
                if s.ip != exclude_ip
                and s.type
                and s.type.lower() in ("server", "domain_controller")
            ]
            return (rng.choice(servers), None) if servers else (None, None)
        if role == "_any":
            others = [s.ip for s in self.scenario.environment.systems if s.ip != exclude_ip]
            return (rng.choice(others), None) if others else (None, None)
        # Named role: find a system with that role/type.
        # For database role, filter by service compatibility when a specific
        # DB service is requested (prevents MSSQL traffic to PostgreSQL hosts).
        candidates = [
            s.ip
            for s in self.scenario.environment.systems
            if s.ip != exclude_ip
            and (
                (s.type and s.type.lower() == role)
                or (s.roles and role in [r.lower() for r in s.roles])
            )
        ]
        if role == "database" and service and candidates and hasattr(self, "world_model"):
            _DB_SERVICE_MATCH = {
                "mssql": {"mssql", "sqlserver"},
                "postgresql": {"postgres", "postgresql"},
                "mysql": {"mysql", "maria", "mariadb"},
            }
            match_terms = _DB_SERVICE_MATCH.get(service, set())
            if match_terms:
                ip_to_host = {s.ip: s.hostname for s in self.scenario.environment.systems}
                filtered = []
                for ip in candidates:
                    hostname = ip_to_host.get(ip, "")
                    host = self.world_model.hosts.get(hostname)
                    if host and any(
                        term in svc.lower() for svc in host.services for term in match_terms
                    ):
                        filtered.append(ip)
                if filtered:
                    candidates = filtered
        result = (rng.choice(candidates), None) if candidates else (None, None)
        if result[0]:
            self._validate_ip_in_segments(result[0], f"_resolve_role({role})")
        return result

    def _validate_ip_in_segments(self, ip: str, context: str) -> None:
        """Warn if a private IP doesn't belong to any defined network segment."""
        import ipaddress as _ipa_val

        if not self.scenario.environment.network:
            return
        try:
            addr = _ipa_val.ip_address(ip)
        except ValueError:
            return
        if not addr.is_private:
            return  # External IPs don't need segment validation
        for seg in self.scenario.environment.network.segments:
            try:
                if addr in _ipa_val.ip_network(seg.cidr, strict=False):
                    return
            except ValueError:
                continue
        logger.warning("Internal IP %s not in any defined segment (%s)", ip, context)

    def _emit_smb_logon_pair(
        self,
        user: Any,
        file_server: Any,
        source_ip: str,
        time: datetime,
        rng: Any,
    ) -> str | None:
        """Emit type 3 network logon + logoff pair on a file server for SMB access.

        In real Windows, every authenticated SMB share access produces:
        - 4624 type 3 (network logon) on the file server
        - 4634 (logoff) after the file access session closes
        """
        from evidenceforge.generation.activity.generator import _get_os_category

        if _get_os_category(file_server.os) != "windows":
            return None

        logon_id = self.activity_generator.generate_logon(
            user=user,
            system=file_server,
            time=time,
            logon_type=3,
            source_ip=source_ip,
        )
        logoff_delay = rng.uniform(5.0, 60.0)
        logoff_time = time + timedelta(seconds=logoff_delay)
        self.activity_generator.generate_logoff(
            user=user,
            system=file_server,
            time=logoff_time,
            logon_id=logon_id,
            logon_type=3,
        )
        return logon_id

    def _generate_profile_traffic(
        self,
        current_hour: datetime,
        system: Any,
        rng: Any,
        os_cat: str,
        sys_pids: dict[str, int] | None = None,
        local_dt: Any = None,
        planned_logoffs: dict[tuple[str, str], float] | None = None,
    ) -> None:
        """Generate role-based and persona-based network connections from traffic profiles.

        Role traffic runs 24/7 (system-level). Persona traffic runs only during
        active user sessions on this host.
        """
        from evidenceforge.generation.activity.traffic_profiles import (
            get_persona_connections,
            get_role_connections,
        )

        # Pre-compute burst windows for realistic traffic burstiness.
        # Real enterprise traffic is self-similar with CV > 0.5.
        # 70% of connections cluster around 3-5 peaks per hour;
        # 30% are uniform background.
        _n_bursts = rng.randint(3, 5)
        _burst_centers = sorted(rng.sample(range(300, 3300, 60), _n_bursts))
        _burst_width = 180  # seconds

        def _burst_offset() -> float:
            if rng.random() < 0.70:
                center = rng.choice(_burst_centers)
                return max(0.0, min(3599.0, center + rng.gauss(0, _burst_width / 3)))
            return rng.uniform(0, 3599)

        # Use compiled world-model canonical roles (includes service/hostname-inferred
        # roles like 'database' from services=['postgresql']). Falls back to raw
        # scenario fields for engines without a world model.
        if hasattr(self, "world_model") and system.hostname in self.world_model.hosts:
            roles = list(self.world_model.hosts[system.hostname].canonical_roles)
        else:
            roles = [r.lower() for r in (system.roles or [])]
            if not roles:
                roles = [(system.type or "workstation").lower()]

        # Use scenario-local time for business-hour gating, not UTC.
        _local = local_dt if local_dt is not None else current_hour
        dow = _local.weekday()
        hour = _local.hour
        is_business = 0 <= dow <= 4 and 7 <= hour <= 19

        # --- Role traffic (system-level, 24/7) ---
        role_conns = get_role_connections(roles, os_cat)
        if role_conns:
            weights = [c.get("weight", 1) for c in role_conns]
            # Scale connection count by time-of-day (fewer at night)
            base_count = rng.randint(8, 20) if is_business else rng.randint(2, 6)

            for _ in range(base_count):
                conn = rng.choices(role_conns, weights=weights, k=1)[0]
                dst_ip, hostname = self._resolve_role(
                    conn["role"],
                    system.ip,
                    rng,
                    os_cat=os_cat,
                    dns_tags=conn.get("dns_tags"),
                    src_host=system.hostname,
                    service=conn.get("service", ""),
                )
                if not dst_ip:
                    continue
                offset = _burst_offset()
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                # Resolve initiating PID from the system process that handles this service
                _SERVICE_TO_PID_KEY = {
                    "kerberos": "lsass",
                    "ldap": "lsass",
                    "dns": "svchost_net_svc",
                    "smb": "svchost_netsvcs",
                    "ssl": "svchost_netsvcs",
                    "http": "svchost_netsvcs",
                    "smtp": "svchost_netsvcs",
                    "ntp": "svchost_local_svc",
                    "ssh": "sshd",
                }
                _pids = sys_pids or {}
                pid_key = _SERVICE_TO_PID_KEY.get(conn.get("service", ""), "")
                conn_pid = _pids.get(pid_key, -1) if pid_key else -1

                self.activity_generator.generate_connection(
                    src_ip=system.ip,
                    dst_ip=dst_ip,
                    time=ts,
                    dst_port=conn["port"],
                    proto=conn.get("proto", "tcp"),
                    service=conn.get("service"),
                    duration=rng.uniform(0.05, 5.0),
                    orig_bytes=rng.randint(200, 5000),
                    resp_bytes=rng.randint(500, 50000),
                    emit_dns=conn.get("emit_dns", False),
                    source_system=system,
                    hostname=hostname,
                    pid=conn_pid,
                )

        # --- Inbound traffic (connections TO this host from other roles/external) ---
        # Inbound profile traffic generates permitted connections that match
        # the host's role.  Each candidate connection is checked against
        # firewall policy — denied flows are skipped here because the deny
        # baseline (_generate_firewall_deny_baseline) already generates
        # ASA Deny / REJ records independently.
        from evidenceforge.generation.activity.traffic_profiles import (
            get_role_inbound_connections,
        )

        inbound_conns = get_role_inbound_connections(roles, os_cat)
        if inbound_conns:
            # Gate external inbound on segment exposure — internal-only
            # hosts must not receive internet client traffic.
            exposure = self._get_system_exposure(system)
            allows_external = exposure in ("external", "both")
            if not allows_external:
                inbound_conns = [c for c in inbound_conns if c["role"] != "_external"]

            # Pre-compute firewall policy context for per-connection checks
            import ipaddress as _ipa_inbound

            _inbound_segment_cidrs: dict = {}
            _inbound_fw_sensors: list = []
            if self.scenario.environment.network:
                for seg in self.scenario.environment.network.segments:
                    try:
                        _inbound_segment_cidrs[seg.name] = _ipa_inbound.ip_network(
                            seg.cidr, strict=False
                        )
                    except ValueError:
                        continue
                _inbound_fw_sensors = [
                    s for s in self.scenario.environment.network.sensors if s.type == "firewall"
                ]

            # VIP lookup for external inbound: use public VIP as dst_ip so
            # the NAT engine fires and outside sensors see the correct address.
            _inbound_vip: dict[str, str] = {}
            if hasattr(self, "dispatcher") and self.dispatcher.visibility_engine:
                _inbound_vip = self.dispatcher.visibility_engine._real_ip_to_vip

            # Helper to resolve firewall interface names for a given sensor
            def _fw_iface_for(ip: str, fw_sensor) -> str:
                import ipaddress as _ipa_fw

                for seg_name, cidr in _inbound_segment_cidrs.items():
                    try:
                        if _ipa_fw.ip_address(ip) in cidr:
                            return fw_sensor.interfaces.get(seg_name, seg_name)
                    except ValueError:
                        continue
                return fw_sensor.interfaces.get("_default", "outside")

            def _fw_is_on_path(fw_sensor, src_ip: str, dst_ip: str) -> bool:
                """Check if a firewall monitors segments containing src or dst."""
                import ipaddress as _ipa_fw

                for seg_name in fw_sensor.monitoring_segments:
                    cidr = _inbound_segment_cidrs.get(seg_name)
                    if cidr is None:
                        continue
                    try:
                        addr_s = _ipa_fw.ip_address(src_ip)
                        addr_d = _ipa_fw.ip_address(dst_ip)
                        if addr_s in cidr or addr_d in cidr:
                            return True
                    except ValueError:
                        continue
                return False

            if not inbound_conns:
                pass  # All entries were external and host is internal-only
            else:
                from evidenceforge.events.contexts import FirewallContext as _InboundFwCtx

                inbound_weights = [c.get("weight", 1) for c in inbound_conns]
                num_inbound = rng.randint(4, 15) if is_business else rng.randint(1, 4)
                for _ in range(num_inbound):
                    conn = rng.choices(inbound_conns, weights=inbound_weights, k=1)[0]
                    is_external_src = conn["role"] == "_external"
                    src_ip, hostname = self._resolve_role(
                        conn["role"],
                        system.ip,
                        rng,
                        os_cat,
                        inbound=True,
                    )
                    if not src_ip:
                        continue

                    # External clients connect to the public VIP, not the
                    # internal IP. Internal clients use system.ip directly.
                    if is_external_src:
                        vip = _inbound_vip.get(system.ip)
                        if vip:
                            effective_dst_ip = vip
                        elif not _ipa_inbound.ip_address(system.ip).is_private:
                            # System has a public IP directly (cloud/flat routing)
                            effective_dst_ip = system.ip
                        else:
                            # RFC1918 host with no VIP → unreachable from outside
                            continue
                    else:
                        effective_dst_ip = system.ip

                    # Evaluate firewall policy — only on firewalls in the path.
                    # Policy uses system.ip (real IP) — correct for modern ASA.
                    fw_denied = False
                    denying_sensor = None
                    if _inbound_fw_sensors:
                        for fw_sensor in _inbound_fw_sensors:
                            if not _fw_is_on_path(fw_sensor, src_ip, system.ip):
                                continue
                            action = self._evaluate_firewall_policy(
                                src_ip,
                                system.ip,
                                conn["port"],
                                fw_sensor,
                                _inbound_segment_cidrs,
                            )
                            if action == "deny":
                                fw_denied = True
                                denying_sensor = fw_sensor
                                break

                    offset = _burst_offset()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)

                    # Resolve source system object (None for external IPs)
                    src_sys = None
                    if hasattr(self, "activity_generator"):
                        ip_map = getattr(self.activity_generator, "_ip_to_system", {})
                        src_sys = ip_map.get(src_ip)

                    is_internal_src = src_sys is not None
                    # External clients use the public-facing hostname;
                    # internal clients use the internal FQDN.
                    dst_hostname = None
                    if is_external_src:
                        # Use public hostname if configured, otherwise suppress
                        # REVERSE_DNS to avoid leaking internal FQDNs.
                        if system.public_hostnames:
                            dst_hostname = rng.choice(system.public_hostnames)
                        else:
                            dst_hostname = ""
                    elif is_internal_src and hasattr(self, "world_model"):
                        dst_hostname = self.world_model.fqdn_for_system(system)

                    if fw_denied and denying_sensor:
                        # Emit as a deny record from the actual in-path firewall
                        deny_state = "REJ" if denying_sensor.drop_mode == "reject" else "S0"
                        self.activity_generator.generate_connection(
                            src_ip=src_ip,
                            dst_ip=effective_dst_ip,
                            time=ts,
                            dst_port=conn["port"],
                            proto=conn.get("proto", "tcp"),
                            service=conn.get("service"),
                            conn_state=deny_state,
                            firewall=_InboundFwCtx(
                                action="deny",
                                msg_id=106023,
                                connection_id=0,
                                src_interface=_fw_iface_for(src_ip, denying_sensor),
                                dst_interface=_fw_iface_for(system.ip, denying_sensor),
                                access_group=f"{_fw_iface_for(src_ip, denying_sensor)}_access_in",
                            ),
                            emit_dns=False,
                        )
                    else:
                        self.activity_generator.generate_connection(
                            src_ip=src_ip,
                            dst_ip=effective_dst_ip,
                            time=ts,
                            dst_port=conn["port"],
                            proto=conn.get("proto", "tcp"),
                            service=conn.get("service"),
                            duration=rng.uniform(0.05, 5.0),
                            orig_bytes=rng.randint(200, 5000),
                            resp_bytes=rng.randint(500, 50000),
                            source_system=src_sys,
                            emit_dns=is_internal_src,
                            hostname=dst_hostname,
                        )

                        # SMB access to file servers produces type 3 logon
                        if (
                            conn.get("service") == "smb"
                            and is_internal_src
                            and src_sys
                            and "file_server" in roles
                        ):
                            src_sessions = self.state_manager.get_sessions_on_system(
                                src_sys.hostname
                            )
                            for sess in src_sessions:
                                if sess.logon_type in (2, 10, 11):
                                    smb_user = next(
                                        (
                                            u
                                            for u in self.scenario.environment.users
                                            if u.username == sess.username
                                        ),
                                        None,
                                    )
                                    if smb_user:
                                        self._emit_smb_logon_pair(smb_user, system, src_ip, ts, rng)
                                        break

        # --- Persona traffic (user-level, during active sessions) ---
        # Only real interactive user sessions get persona traffic — skip
        # SYSTEM, LOCAL SERVICE, NETWORK SERVICE, machine accounts, etc.
        host_sessions = self.state_manager.get_sessions_on_system(system.hostname)
        for session in host_sessions:
            persona = None
            user_obj = None
            for u in self.scenario.environment.users:
                if u.username == session.username:
                    persona = u.persona
                    user_obj = u
                    break
            if persona is None:
                continue  # Not a scenario user — skip service/machine accounts
            # Only interactive sessions generate user-driven persona traffic
            if session.logon_type not in (2, 10, 11):
                continue
            # Remote admin sessions on other machines use _server_admin profile
            # instead of the user's normal persona (no Outlook/Teams on servers).
            is_own_workstation = system.assigned_user == session.username
            if not is_own_workstation and session.logon_type in (10, 11):
                persona_conns = get_persona_connections("_server_admin", os_cat)
            else:
                persona_conns = get_persona_connections(persona, os_cat)
            if not persona_conns:
                continue
            p_weights = [c.get("weight", 1) for c in persona_conns]
            # Fewer persona connections than role connections; scaled by activity
            num_persona = rng.randint(3, 10) if is_business else 0
            # Clamp timestamps to session lifetime within this hour
            session_start_sec = max(0.0, (session.start_time - current_hour).total_seconds())

            # Bound persona timestamps by planned logoff time (if any)
            _logoff_key = (system.hostname, session.logon_id)
            _max_offset = planned_logoffs.get(_logoff_key, 3599) if planned_logoffs else 3599

            for _ in range(num_persona):
                conn = rng.choices(persona_conns, weights=p_weights, k=1)[0]
                # Skip SSH/RDP — these require compound session evidence
                # (sshd syslog, 4624 type 10, bash history) that bare
                # connections don't provide. They're handled by dedicated
                # SSH/RDP generation paths instead.
                if conn.get("service") in ("ssh", "rdp"):
                    continue
                dst_ip, hostname = self._resolve_role(
                    conn["role"],
                    system.ip,
                    rng,
                    os_cat=os_cat,
                    dns_tags=conn.get("dns_tags"),
                    src_host=system.hostname,
                    service=conn.get("service", ""),
                )
                if not dst_ip:
                    continue

                # Compute timestamp with burst clustering, clamped to session window
                raw_offset = _burst_offset()
                offset = max(session_start_sec, min(_max_offset, raw_offset))
                ts = current_hour + timedelta(seconds=offset)

                persona_pid = -1
                # Thread effective persona so _server_admin sessions don't
                # get browser/SaaS processes attributed on servers.
                eff_persona = (
                    "_server_admin"
                    if (not is_own_workstation and session.logon_type in (10, 11))
                    else None
                )
                if user_obj and conn.get("service"):
                    persona_pid = self.world_planner.ensure_connection_process(
                        user=user_obj,
                        system=system,
                        session=session,
                        time=ts,
                        service=conn["service"],
                        rng=rng,
                        effective_persona=eff_persona,
                    )

                self.state_manager.set_current_time(ts)

                # For HTTP/HTTPS: generate browsing session with subresources,
                # referrer chains, and cross-domain CDN fan-out.
                svc = conn.get("service", "")
                if svc in ("ssl", "http") and hostname:
                    self._emit_browsing_session(
                        system=system,
                        user_obj=user_obj,
                        session=session,
                        hostname=hostname,
                        dst_ip=dst_ip,
                        conn=conn,
                        base_ts=ts,
                        persona_pid=persona_pid,
                        os_cat=os_cat,
                        rng=rng,
                    )
                else:
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=dst_ip,
                        time=ts,
                        dst_port=conn["port"],
                        proto=conn.get("proto", "tcp"),
                        service=conn.get("service"),
                        duration=rng.uniform(0.1, 10.0),
                        orig_bytes=rng.randint(200, 8000),
                        resp_bytes=rng.randint(500, 80000),
                        emit_dns=conn.get("emit_dns", False),
                        source_system=system,
                        hostname=hostname,
                        pid=persona_pid,
                    )

    def _emit_browsing_session(
        self,
        system: Any,
        user_obj: Any,
        session: Any,
        hostname: str,
        dst_ip: str,
        conn: dict,
        base_ts: datetime,
        persona_pid: int,
        os_cat: str,
        rng: Any,
    ) -> None:
        """Generate a multi-request browsing session for an HTTP/HTTPS persona connection.

        Replaces the single generate_connection() call with a session model
        that produces a landing page, subresource cascade, navigation, and
        referrer chains.
        """
        from evidenceforge.events.contexts import HttpContext
        from evidenceforge.generation.activity.browsing_session import (
            generate_browsing_session,
        )
        from evidenceforge.generation.activity.dns_registry import (
            get_domain_tags,
            pick_domain_and_ip,
        )

        domain_tags = get_domain_tags(hostname) if hostname else []

        # Resolve browsing intensity: user override > persona > default
        intensity = "normal"
        if user_obj and getattr(user_obj, "browsing_intensity", None):
            intensity = user_obj.browsing_intensity
        elif user_obj and user_obj.persona:
            for p in self.scenario.personas:
                if p.name == user_obj.persona:
                    intensity = getattr(p, "browsing_intensity", "normal")
                    break

        session_requests = generate_browsing_session(
            rng=rng,
            hostname=hostname,
            domain_tags=domain_tags,
            source_os=os_cat,
            browsing_intensity=intensity,
            port=conn.get("port", 443),
        )

        if not session_requests:
            return

        # Pick a consistent UA for the entire session
        if os_cat == "linux":
            _session_uas = [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            ]
        else:
            _session_uas = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            ]
        session_ua = rng.choice(_session_uas)

        for req in session_requests:
            req_ts = base_ts + timedelta(milliseconds=req.time_offset_ms)
            self.state_manager.set_current_time(req_ts)

            # Resolve destination IP for CDN subresources
            req_dst_ip = dst_ip
            req_hostname = hostname
            if req.hostname != hostname:
                req_hostname = req.hostname
                # Resolve CDN domain to an IP
                _, cdn_ip = pick_domain_and_ip(rng, "cdn", src_host=system.hostname)
                if cdn_ip:
                    req_dst_ip = cdn_ip

            http_ctx = HttpContext(
                method=req.method,
                host=req_hostname,
                uri=req.path,
                version="1.1",
                user_agent=session_ua,
                request_body_len=req.request_body_len,
                response_body_len=req.response_body_len,
                status_code=200,
                status_msg="OK",
                referrer=req.referrer,
                trans_depth=req.trans_depth,
                resp_mime_types=[req.content_type] if req.content_type else [],
                tags=[],
            )

            self.activity_generator.generate_connection(
                src_ip=system.ip,
                dst_ip=req_dst_ip,
                time=req_ts,
                dst_port=conn.get("port", 443),
                proto=conn.get("proto", "tcp"),
                service=conn.get("service"),
                duration=rng.uniform(0.05, 2.0),
                orig_bytes=req.request_body_len,
                resp_bytes=req.response_body_len,
                emit_dns=req.is_page_load,  # DNS only for page loads, not subresources
                source_system=system,
                hostname=req_hostname,
                pid=persona_pid,
                http=http_ctx,
            )

    def _generate_system_traffic(
        self,
        current_hour: datetime,
        planned_logoffs: dict[tuple[str, str], float] | None = None,
    ) -> None:
        """Generate system-initiated background traffic for all systems.

        Called once per hour. Generates DNS lookups, NTP syncs, SMB browsing,
        and scheduled task activity independently of user activity.

        Uses periodic-with-jitter timing to produce realistic autocorrelation
        in system event intervals.
        """
        from evidenceforge.generation.activity import _get_os_category

        rng = _get_rng()

        # Compute scenario-local time for business-hour gating
        if hasattr(self, "_scenario_tz") and self._scenario_tz:
            local_dt = current_hour.replace(tzinfo=UTC).astimezone(self._scenario_tz)
        else:
            local_dt = current_hour

        dns_ips = self._infra_ips.get("dns", ["10.0.0.1"])
        if isinstance(dns_ips, str):
            dns_ips = [dns_ips]
        ntp_ips = self._infra_ips.get("ntp", ["129.6.15.28"])
        if isinstance(ntp_ips, str):
            ntp_ips = [ntp_ips]

        for system in self.scenario.environment.systems:
            services = self._system_service_defaults.get(system.hostname, [])
            os_cat = _get_os_category(system.os)
            sys_pids = self._system_pids.get(system.hostname, {})
            is_rhel_like = any(
                d in system.os.lower() for d in ("centos", "rhel", "red hat", "rocky", "alma")
            )

            def _svc_pid(*keys: str, _pids: dict = sys_pids) -> int:  # noqa: B006
                """Resolve service PID from _system_pids, -1 if absent."""
                for k in keys:
                    if k in _pids:
                        return _pids[k]
                return -1

            # DNS lookups: truly periodic with small jitter, using global schedule
            if "dns-client" in services:
                dns_interval = 600 + (_stable_seed(f"dns_iv_{system.hostname}") % 1200)
                dns_phase = _stable_seed(f"dns_ph_{system.hostname}") % dns_interval
                hour_start_sec = (current_hour - self._generation_epoch).total_seconds()
                t = dns_phase
                while t < hour_start_sec:
                    t += dns_interval
                while t < hour_start_sec + 3600:
                    jitter = rng.gauss(0, dns_interval * 0.02)
                    ts = self._generation_epoch + timedelta(seconds=t + jitter)
                    self.state_manager.set_current_time(ts)
                    dns_pid = (
                        _svc_pid("svchost_net_svc")
                        if os_cat == "windows"
                        else _svc_pid("systemd_resolved")
                        if not is_rhel_like
                        else -1
                    )
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(dns_ips),
                        time=ts,
                        dst_port=53,
                        proto="udp",
                        service="dns",
                        duration=rng.uniform(0.001, 0.05),
                        orig_bytes=rng.randint(40, 120),
                        resp_bytes=rng.randint(80, 512),
                        source_system=system,
                        pid=dns_pid,
                    )
                    t += dns_interval

            # NTP sync: 1 per hour
            if "ntp-client" in services:
                offset = (_stable_seed(f"ntp_phase_{system.hostname}") % 3600) + rng.gauss(0, 5)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                # Deterministic NTP source per host (stable across hours)
                # Exclude the host's own IP — DCs don't NTP-sync to themselves
                ntp_candidates = [ip for ip in ntp_ips if ip != system.ip]
                ntp_ip = (
                    ntp_candidates[_stable_seed(f"ntp_src_{system.hostname}") % len(ntp_candidates)]
                    if ntp_candidates
                    else None  # This host IS the NTP server; skip NTP client traffic only
                )
                if ntp_ip:
                    ntp_pid = (
                        _svc_pid("svchost_local_svc")
                        if os_cat == "windows"
                        else _svc_pid("chronyd", "timesyncd")
                    )
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=ntp_ip,
                        time=ts,
                        dst_port=123,
                        proto="udp",
                        service="ntp",
                        duration=rng.uniform(0.01, 0.1),
                        orig_bytes=48,
                        resp_bytes=48,
                        source_system=system,
                        pid=ntp_pid,
                    )

            # DHCP lease renewal at T/2 with RFC 2131 jitter
            dhcp_state = getattr(self, "_dhcp_lease_state", {}).get(system.hostname)
            if dhcp_state and "zeek_dhcp" in self.emitters:
                lease_time = dhcp_state["lease_time"]
                # RFC 2131: renew at T1 ≈ T/2, with ±10% jitter per renewal
                base_renewal = lease_time / 2
                jitter_factor = 1.0 + rng.uniform(-0.10, 0.10)
                renewal_interval = base_renewal * jitter_factor
                last_renewal = dhcp_state["last_renewal"]
                hour_end_epoch = (current_hour + timedelta(hours=1)).timestamp()
                # Check if a renewal falls within this hour
                next_renewal = last_renewal + renewal_interval
                if next_renewal < hour_end_epoch:
                    from evidenceforge.utils.ids import generate_zeek_uid

                    renewal_ts = datetime.fromtimestamp(next_renewal, tz=current_hour.tzinfo)
                    # Randomize fractional seconds (OS timer imprecision)
                    renewal_ts = renewal_ts.replace(microsecond=rng.randint(0, 999999))
                    self.state_manager.set_current_time(renewal_ts)
                    self.activity_generator.generate_dhcp_lease(
                        system=dhcp_state["system"],
                        time=renewal_ts,
                        mac=dhcp_state["mac"],
                        lease_time=lease_time,
                        uid=generate_zeek_uid("C"),
                        msg_types=["REQUEST", "ACK"],  # Renewal, not discovery
                    )
                    dhcp_state["last_renewal"] = next_renewal

            # SMB browsing: Windows workstations to DCs (SYSVOL/GPO) and file servers
            dc_ips = self._infra_ips.get("dc", ["10.0.0.1"])
            if isinstance(dc_ips, str):
                dc_ips = [dc_ips]
            dc_targets = [ip for ip in dc_ips if ip != system.ip]

            # Include file servers in SMB targets for workstations
            fs_targets = [
                s
                for s in self.scenario.environment.systems
                if s.ip != system.ip and s.roles and "file_server" in [r.lower() for r in s.roles]
            ]

            if "smb-client" in services and os_cat == "windows" and dc_targets:
                # Combine DC + file server IPs as SMB targets
                smb_targets = list(dc_targets)
                for fs in fs_targets:
                    if fs.ip not in smb_targets:
                        smb_targets.append(fs.ip)

                smb_interval = 1200 + (_stable_seed(f"smb_iv_{system.hostname}") % 1800)
                smb_phase = _stable_seed(f"smb_ph_{system.hostname}") % smb_interval
                hour_start_sec = (current_hour - self._generation_epoch).total_seconds()
                t = smb_phase
                while t < hour_start_sec:
                    t += smb_interval
                while t < hour_start_sec + 3600:
                    offset = t - hour_start_sec + rng.gauss(0, smb_interval * 0.02)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    smb_dst_ip = rng.choice(smb_targets)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=smb_dst_ip,
                        time=ts,
                        dst_port=445,
                        proto="tcp",
                        service="smb",
                        duration=rng.uniform(0.1, 2.0),
                        orig_bytes=rng.randint(200, 2000),
                        resp_bytes=rng.randint(500, 5000),
                        emit_dns=rng.random() > 0.02,
                        source_system=system,
                        pid=4,  # SMB: kernel System process
                    )
                    # Emit type 3 logon on file server for SMB access
                    smb_dst_sys = next((s for s in fs_targets if s.ip == smb_dst_ip), None)
                    if smb_dst_sys:
                        # Find active user on this workstation
                        ws_sessions = self.state_manager.get_sessions_on_system(system.hostname)
                        for sess in ws_sessions:
                            if sess.logon_type in (2, 10, 11):
                                ws_user = next(
                                    (
                                        u
                                        for u in self.scenario.environment.users
                                        if u.username == sess.username
                                    ),
                                    None,
                                )
                                if ws_user:
                                    self._emit_smb_logon_pair(
                                        ws_user, smb_dst_sys, system.ip, ts, rng
                                    )
                                    break
                    t += smb_interval

            # Kerberos
            if "kerberos-client" in services and os_cat == "windows" and dc_targets:
                num_krb = rng.randint(1, 3)
                base_interval = 3600 / (num_krb + 1)
                for i in range(num_krb):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(dc_targets),
                        time=ts,
                        dst_port=88,
                        proto="tcp",
                        service="kerberos",
                        duration=rng.uniform(0.001, 0.05),
                        orig_bytes=rng.randint(200, 1500),
                        resp_bytes=rng.randint(200, 2000),
                        emit_dns=rng.random() > 0.02,
                        source_system=system,
                        pid=_svc_pid("lsass"),
                    )

            # LDAP
            if "ldap-client" in services and os_cat == "windows" and dc_targets:
                num_ldap = rng.randint(2, 5)
                base_interval = 3600 / (num_ldap + 1)
                for i in range(num_ldap):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(dc_targets),
                        time=ts,
                        dst_port=389,
                        proto="tcp",
                        service="ldap",
                        duration=rng.uniform(0.01, 0.5),
                        orig_bytes=rng.randint(100, 2000),
                        resp_bytes=rng.randint(500, 10000),
                        emit_dns=rng.random() > 0.02,
                        source_system=system,
                        pid=_svc_pid("lsass"),
                    )

            # Profile-driven traffic: role-based system connections + persona user connections
            # Replaces former HTTPS background + database traffic blocks
            self._generate_profile_traffic(
                current_hour,
                system,
                rng,
                os_cat,
                sys_pids,
                local_dt=local_dt,
                planned_logoffs=planned_logoffs,
            )

            # Independent system service processes (not tied to user activity)
            # Windows hosts spawn 3-8 service processes per hour
            if os_cat == "windows":
                from evidenceforge.generation.activity.system_processes import (
                    pick_system_service_process as _pick_svc,
                )

                sys_type_str = (system.type or "workstation").lower()
                num_svc = rng.randint(3, 8)
                for _si in range(num_svc):
                    svc_offset = rng.uniform(0, 3599)
                    svc_ts = current_hour + timedelta(seconds=svc_offset)
                    self.state_manager.set_current_time(svc_ts)
                    svc_image, svc_cmd, svc_parent_key = _pick_svc(rng, sys_type_str)
                    svc_parent = sys_pids.get(
                        svc_parent_key, sys_pids.get("services", sys_pids.get("wininit", 4))
                    )
                    self.activity_generator.generate_system_process(
                        system=system,
                        time=svc_ts,
                        process_name=svc_image,
                        command_line=svc_cmd,
                        parent_pid=svc_parent,
                        username="SYSTEM",
                    )

            # Windows scheduled tasks — diverse per-hour selection from YAML.
            # Linux scheduled tasks are handled by _generate_scheduled_tasks()
            # which uses realistic daily/weekly frequencies instead of the
            # legacy 2-5 per hour approach.
            if os_cat == "windows":
                from evidenceforge.generation.activity.system_processes import (
                    pick_scheduled_task,
                )

                host_seed = _stable_seed(f"task_phase_{system.hostname}") % 900
                num_tasks = rng.randint(2, 5)
                slot_bases = sorted(rng.sample(range(0, 3600, 300), min(num_tasks, 12)))
                for slot_base in slot_bases:
                    offset = slot_base + host_seed + rng.gauss(0, 30) + rng.uniform(0, 10)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    task_image, task_cmd, task_parent_key = pick_scheduled_task(rng)
                    parent_pid = sys_pids.get(
                        task_parent_key, sys_pids.get("services", sys_pids.get("wininit", 4))
                    )
                    cred_ts = ts - timedelta(milliseconds=rng.randint(5, 50))
                    self.activity_generator.generate_explicit_credentials(
                        user=_SYSTEM_USER,
                        system=system,
                        time=cred_ts,
                        target_username="SYSTEM",
                        target_server=system.hostname,
                        process_name=r"C:\Windows\System32\svchost.exe",
                        process_pid=parent_pid,
                    )
                    self.activity_generator.generate_system_process(
                        system=system,
                        time=ts,
                        process_name=task_image,
                        command_line=task_cmd,
                        parent_pid=parent_pid,
                        username="SYSTEM",
                    )

            # Sysmon Event 8 (CreateRemoteThread) baseline noise — Windows only
            if os_cat == "windows":
                num_crt = rng.randint(1, 3)
                for _ in range(num_crt):
                    src_key, src_image, tgt_key, tgt_image = rng.choice(_BENIGN_CRT_PAIRS)
                    src_pid = sys_pids.get(src_key, rng.randint(1000, 5000))
                    tgt_pid = sys_pids.get(tgt_key, rng.randint(1000, 5000))
                    if src_pid == tgt_pid:
                        continue
                    offset = rng.uniform(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_create_remote_thread(
                        user=_SYSTEM_USER,
                        system=system,
                        time=ts,
                        source_pid=src_pid,
                        source_image=src_image,
                        target_pid=tgt_pid,
                        target_image=tgt_image,
                    )

            # Sysmon Event 10 (ProcessAccess) baseline noise — Windows only
            if os_cat == "windows":
                num_pa = rng.randint(3, 8)
                for _ in range(num_pa):
                    src_key, src_image, tgt_key, tgt_image, access = rng.choice(_BENIGN_PA_PAIRS)
                    src_pid = sys_pids.get(src_key, rng.randint(1000, 5000))
                    tgt_pid = sys_pids.get(tgt_key, rng.randint(1000, 5000))
                    offset = rng.uniform(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_process_access(
                        user=_SYSTEM_USER,
                        system=system,
                        time=ts,
                        source_pid=src_pid,
                        source_image=src_image,
                        target_pid=tgt_pid,
                        target_image=tgt_image,
                        granted_access=access,
                    )

            # Sysmon Event 7 (ImageLoaded) baseline noise — Windows only
            # Uses data-driven DLL profiles from system_processes.yaml and
            # application_catalog.yaml. Picks from processes actually running
            # on this system (from StateManager) so PIDs are always valid.
            if os_cat == "windows":
                from evidenceforge.generation.activity.dll_load_profiles import (
                    get_dlls_for_process,
                )

                running = self.state_manager.get_processes_on_system(system.hostname)
                win_procs = [(p.pid, p.image) for p in running if "\\" in p.image]
                if win_procs:
                    num_dll = rng.randint(15, 40)
                    for _ in range(num_dll):
                        proc_pid, proc_image = rng.choice(win_procs)
                        exe_name = proc_image.rsplit("\\", 1)[-1]
                        dll_pool = get_dlls_for_process(exe_name)
                        if not dll_pool:
                            continue
                        dll = rng.choice(dll_pool)
                        offset = rng.uniform(0, 3599)
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)
                        self.activity_generator.generate_image_load(
                            user=_SYSTEM_USER,
                            system=system,
                            time=ts,
                            pid=proc_pid,
                            image=proc_image,
                            dll_path=dll["path"],
                            signed=dll["signed"],
                            signature=dll["signature"],
                            signature_status=dll["signature_status"],
                        )

            # ICMP monitoring pings are now handled by role_traffic profiles

            # SSH: connections to Linux servers
            sys_type = (system.type or "workstation").lower()
            if os_cat == "linux" and sys_type == "server":
                roster = self._get_server_ssh_users(system)
                if roster:
                    from evidenceforge.generation.activity.bash_commands import pick_bash_command

                    num_ssh = rng.randint(1, 3)
                    for _ in range(num_ssh):
                        ssh_user = rng.choice(roster)
                        offset = rng.uniform(0, 3599)
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)
                        self.world_planner.bootstrap_user_session(
                            user=ssh_user,
                            target_system=system,
                            time=ts,
                            rng=rng,
                            session_kind="ssh",
                            allow_existing=True,
                        )

                        persona_lower = (ssh_user.persona or "").lower()
                        if persona_lower == "sysadmin":
                            n_cmds = rng.randint(3, 8)
                        elif persona_lower == "developer":
                            n_cmds = rng.randint(2, 6)
                        else:
                            n_cmds = rng.randint(1, 4)
                        hour_end = current_hour + timedelta(hours=1)
                        cumulative_gap = 0
                        _SLOW_CMD_KEYWORDS = frozenset(
                            [
                                "build",
                                "make",
                                "pytest",
                                "cargo",
                                "docker",
                                "npm run",
                                "go build",
                                "gcc",
                                "compile",
                                "install",
                                "apt",
                                "yum",
                                "dnf",
                                "pip install",
                            ]
                        )
                        for _cmd_i in range(n_cmds):
                            cmd_offset = rng.randint(30, 600)
                            cmd = pick_bash_command(
                                rng,
                                ssh_user.persona or "",
                                system.hostname,
                                system.services,
                                username=ssh_user.username,
                            )
                            # Complexity-aware timing: build/install commands
                            # take longer than simple lookups (ls, cat, pwd)
                            is_slow = any(kw in cmd.lower() for kw in _SLOW_CMD_KEYWORDS)
                            if is_slow:
                                gap = rng.randint(30, 180)
                            else:
                                gap = rng.choices(
                                    [
                                        rng.randint(8, 25),
                                        rng.randint(30, 90),
                                        rng.randint(120, 300),
                                    ],
                                    weights=[35, 40, 25],
                                    k=1,
                                )[0]
                            cumulative_gap += gap
                            cmd_time = ts + timedelta(seconds=cmd_offset + cumulative_gap)
                            if cmd_time >= hour_end:
                                break
                            self.activity_generator.generate_bash_command(
                                ssh_user, system, cmd_time, cmd
                            )

        # RDP: IT admin connections to Windows servers/DCs
        for system in self.scenario.environment.systems:
            os_cat_rdp = _get_os_category(system.os)
            sys_type_rdp = (system.type or "workstation").lower()
            if os_cat_rdp != "windows" or sys_type_rdp not in ("server", "domain_controller"):
                continue

            # 1-3 RDP admin sessions per hour to servers, ~60% probability
            if rng.random() > 0.60:
                continue

            if not any(
                s.ip != system.ip and _get_os_category(s.os) == "windows"
                for s in self.scenario.environment.systems
            ):
                continue

            num_rdp = rng.randint(1, 3)
            roster = self._get_server_ssh_users(system)
            if not roster:
                continue
            for _ in range(num_rdp):
                offset = rng.uniform(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                rdp_user = rng.choice(roster)
                self.world_planner.bootstrap_user_session(
                    user=rdp_user,
                    target_system=system,
                    time=ts,
                    rng=rng,
                    session_kind="rdp",
                    allow_existing=True,
                )

        # Service logons (LogonType 5) and ANONYMOUS LOGONs on Windows systems
        for system in self.scenario.environment.systems:
            os_cat_svc = _get_os_category(system.os)
            if os_cat_svc != "windows" or "windows_event_security" not in self.emitters:
                continue

            sys_type_svc = (system.type or "workstation").lower()
            num_svc = rng.randint(2, 5) if sys_type_svc != "workstation" else rng.randint(1, 2)
            for _ in range(num_svc):
                offset = rng.uniform(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                svc_accounts = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]
                svc_user = rng.choice(svc_accounts)
                self.activity_generator.generate_service_logon(
                    system=system,
                    time=ts,
                    service_account=svc_user,
                )

            if sys_type_svc in ("server", "domain_controller"):
                num_anon = rng.randint(1, 3)
                for _ in range(num_anon):
                    offset = rng.uniform(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_anonymous_logon(
                        system=system,
                        time=ts,
                    )

        # Machine account ($) authentication to DCs
        dc_ips = self._infra_ips.get("dc", [])
        dc_hostnames = self._infra_ips.get("dc_hostnames", [])
        if isinstance(dc_ips, str):
            dc_ips = [dc_ips]
        if dc_ips and dc_hostnames:
            for system in self.scenario.environment.systems:
                os_cat = _get_os_category(system.os)
                if os_cat != "windows" or system.ip in dc_ips:
                    continue

                num_auth = rng.randint(2, 6)
                base_interval = 3600 / (num_auth + 1)
                for i in range(num_auth):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    dc_idx = rng.randint(0, len(dc_ips) - 1)
                    self.activity_generator.generate_machine_account_logon(
                        hostname=system.hostname,
                        machine_username=f"{system.hostname}$",
                        dc_hostname=dc_hostnames[dc_idx],
                        source_ip=system.ip,
                        dc_ip=dc_ips[dc_idx],
                        time=ts,
                    )

        # DC-side Kerberos event generation
        if dc_ips and dc_hostnames:
            windows_clients = [
                s
                for s in self.scenario.environment.systems
                if _get_os_category(s.os) == "windows" and s.ip not in dc_ips
            ]
            for _dc_idx, dc_hostname in enumerate(dc_hostnames):
                for client in windows_clients:
                    num_cycles = rng.randint(3, 8)
                    base_interval = 3600 / (num_cycles + 1)
                    for i in range(num_cycles):
                        offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.15)
                        offset = max(0, min(3599, offset))
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)

                        username = f"{client.hostname}$"
                        self.activity_generator.generate_kerberos_tgt(
                            username=username,
                            source_ip=client.ip,
                            dc_hostname=dc_hostname,
                            time=ts,
                        )
                        num_tgs = rng.randint(2, 5)
                        member_servers = [
                            s.hostname
                            for s in self.scenario.environment.systems
                            if _get_os_category(s.os) == "windows"
                            and s.ip not in dc_ips
                            and any(
                                svc in s.services
                                for svc in [
                                    "file-server",
                                    "sql-server",
                                    "web",
                                    "iis",
                                    "exchange",
                                    "sharepoint",
                                    "crm",
                                    "print",
                                ]
                            )
                        ] or [dc_hostname]
                        for tgs_i in range(num_tgs):
                            ts2 = ts + timedelta(
                                milliseconds=rng.randint(50, 200) + tgs_i * rng.randint(100, 500)
                            )
                            svc = rng.choice(["cifs", "ldap", "http", "host"])
                            if rng.random() < 0.60 and member_servers:
                                target = rng.choice(member_servers)
                            else:
                                target = dc_hostname
                            self.activity_generator.generate_kerberos_service_ticket(
                                username=username,
                                service_name=f"{svc}/{target}",
                                source_ip=client.ip,
                                dc_hostname=dc_hostname,
                                time=ts2,
                            )
                        if rng.random() < 0.10:
                            self.activity_generator.generate_ntlm_validation(
                                username=username,
                                workstation=client.hostname,
                                dc_hostname=dc_hostname,
                                time=ts,
                            )

        # TGT Renewal
        if not hasattr(self, "_last_tgt_time"):
            self._last_tgt_time: dict[str, datetime] = {}
        if dc_ips and dc_hostnames:
            renewal_interval = timedelta(hours=rng.uniform(8.0, 12.0))
            for client in windows_clients:
                username = f"{client.hostname}$"
                last_tgt = self._last_tgt_time.get(username)
                if last_tgt and (current_hour - last_tgt) >= renewal_interval:
                    offset = rng.uniform(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    dc_idx = rng.randint(0, len(dc_hostnames) - 1)
                    self.activity_generator.generate_kerberos_tgt_renewal(
                        username=username,
                        source_ip=client.ip,
                        dc_hostname=dc_hostnames[dc_idx],
                        time=ts,
                    )
                    self._last_tgt_time[username] = ts
                elif last_tgt is None:
                    self._last_tgt_time[username] = current_hour

        # Linux syslog diversity
        for system in self.scenario.environment.systems:
            os_cat = _get_os_category(system.os)
            if os_cat != "linux" or "syslog" not in self.emitters:
                continue

            sys_pids = self._system_pids.get(system.hostname, {})
            is_dmz = "dmz" in system.hostname.lower() or "web" in system.hostname.lower()
            is_rhel_like = any(
                d in system.os.lower() for d in ("centos", "rhel", "red hat", "rocky", "alma")
            )
            has_web_role = (
                any(r in (system.roles or []) for r in ("web_server", "forward_proxy"))
                or "web" in system.hostname.lower()
            )
            num_events = rng.randint(100, 300) if is_dmz else rng.randint(50, 120)

            scenario_start = self.scenario.time_window.start
            boot_uptime = self._kernel_boot_uptimes.get(system.hostname, 500000.0)

            # Generate scheduled tasks (cron/systemd timers) at real frequencies
            self._generate_scheduled_tasks(
                current_hour, system, rng, sys_pids, is_rhel_like, has_web_role
            )

            # Use Hawkes process for bursty syslog timing instead of uniform spread
            from evidenceforge.utils.timing import hawkes_timestamps

            _syslog_mu = max(0.001, num_events / 3600.0 * 0.7)
            _syslog_offsets, _ = hawkes_timestamps(
                num_events=num_events,
                duration=3600.0,
                mu=_syslog_mu,
                alpha=0.3,
                beta=0.8,
                rng=rng,
            )
            for offset in _syslog_offsets:
                ts = current_hour + timedelta(seconds=offset)
                uptime = int(boot_uptime + (ts - scenario_start).total_seconds())

                source_roll = rng.random()
                if source_roll < 0.25:
                    if is_dmz and rng.random() < 0.85:
                        src_ip = rng.choices(
                            self._external_scanner_ips,
                            weights=self._external_scanner_weights,
                            k=1,
                        )[0]
                        spt = rng.randint(1024, 65535)
                        dpt = rng.choice([22, 23, 25, 80, 443, 445, 3389, 8080])
                        msg = (
                            f"[{uptime}.{rng.randint(100000, 999999)}] [UFW BLOCK] "
                            f"IN=ens160 OUT= SRC={src_ip} DST={system.ip} "
                            f"LEN={rng.randint(40, 60)} TOS=0x00 PREC=0x00 TTL={rng.randint(40, 255)} "
                            f"ID={rng.randint(1, 65535)} PROTO=TCP SPT={spt} DPT={dpt} "
                            f"WINDOW={rng.choice([1024, 14600, 65535])} RES=0x00 SYN URGP=0"
                        )
                        # UFW block: connection (→ Zeek conn REJ) + syslog (→ kernel UFW)
                        # Both on the same SecurityEvent for cross-source correlation

                        self.activity_generator.generate_connection(
                            src_ip=src_ip,
                            dst_ip=system.ip,
                            time=ts,
                            dst_port=dpt,
                            proto="tcp",
                            conn_state="REJ",
                            src_port=spt,
                        )
                        # Paired syslog via canonical dispatch
                        self.activity_generator.generate_syslog_event(
                            system=system,
                            time=ts,
                            app_name="kernel",
                            message=msg,
                            pid=None,
                            facility=0,
                            severity=5,
                        )
                    else:
                        # AppArmor audit: only on hosts running MySQL (DB role)
                        has_db = "db" in system.hostname.lower() or "database" in (
                            system.roles or []
                        )
                        if has_db and not is_rhel_like:
                            self._audit_serials[system.hostname] = self._audit_serials.get(
                                system.hostname, 1000
                            ) + rng.randint(1, 5)
                            audit_serial = self._audit_serials[system.hostname]
                            msg = (
                                f"[{uptime}.{rng.randint(100000, 999999)}] audit: type=1400 "
                                f"audit({int(ts.timestamp())}.{rng.randint(100, 999)}:{audit_serial}): "
                                f'apparmor="ALLOWED" operation="open" profile="usr.sbin.mysqld"'
                            )
                            self.activity_generator.generate_syslog_event(
                                system=system,
                                time=ts,
                                app_name="kernel",
                                message=msg,
                                pid=None,
                                facility=0,
                                severity=5,
                            )
                elif source_roll < 0.45:
                    # Sequential session IDs per host (systemd-logind increments from boot)
                    if not hasattr(self, "_session_counters"):
                        self._session_counters = {}
                    self._session_counters.setdefault(system.hostname, 0)
                    self._session_counters[system.hostname] += 1
                    sid = self._session_counters[system.hostname]
                    # Use OS-appropriate usernames
                    session_users = ["root", "admin"]
                    if has_web_role:
                        session_users.append("www-data")
                    if not is_rhel_like:
                        session_users.append("ubuntu")
                    user = rng.choice(session_users)
                    action = rng.choice(
                        [f"New session {sid} of user {user}.", f"Removed session {sid}."]
                    )
                    self.activity_generator.generate_syslog_event(
                        system=system,
                        time=ts,
                        app_name="systemd-logind",
                        message=action,
                        pid=sys_pids.get("logind", rng.randint(400, 800)),
                    )
                elif source_roll < 0.65:
                    other_ips = [
                        s.ip for s in self.scenario.environment.systems if s.ip != system.ip
                    ]
                    ip = rng.choice(other_ips) if other_ips else system.ip
                    # Resolve source system for WFP 5156 emission and OS-aware port
                    src_sys_obj = next(
                        (s for s in self.scenario.environment.systems if s.ip == ip),
                        None,
                    )
                    from evidenceforge.generation.activity.generator import _ephemeral_port

                    _src_os = _get_os_category(src_sys_obj.os) if src_sys_obj else "linux"
                    port = _ephemeral_port(rng, _src_os)
                    self.activity_generator.generate_connection(
                        src_ip=ip,
                        dst_ip=system.ip,
                        time=ts,
                        dst_port=22,
                        proto="tcp",
                        service="ssh",
                        duration=rng.uniform(30.0, 1800.0),
                        orig_bytes=rng.randint(2000, 50000),
                        resp_bytes=rng.randint(5000, 200000),
                        src_port=port,
                        pid=sys_pids.get("sshd", -1),
                        source_system=src_sys_obj,
                    )
                    sshd_pid = rng.randint(5000, 60000)
                    ssh_user = rng.choice(
                        ["admin", "root", "ubuntu"] if not is_rhel_like else ["admin", "root"]
                    )
                    # Generate login + disconnect sequence (realistic sshd log)
                    if rng.random() < 0.5:
                        # Login sequence: connection → auth → session open
                        key_type = rng.choice(["RSA", "ED25519", "ECDSA"])
                        key_hash = f"SHA256:{''.join(rng.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', k=43))}"
                        if rng.random() < 0.7:
                            # Key-based auth (70%)
                            auth_msg = f"Accepted publickey for {ssh_user} from {ip} port {port} ssh2: {key_type} {key_hash}"
                        else:
                            # Password auth (30%)
                            auth_msg = (
                                f"Accepted password for {ssh_user} from {ip} port {port} ssh2"
                            )
                        login_msgs = [
                            f'Connection from {ip} port {port} on {system.ip} port 22 rdomain ""',
                            auth_msg,
                            f"pam_unix(sshd:session): session opened for user {ssh_user}(uid=0) by (uid=0)",
                        ]
                        for lm in login_msgs:
                            self.activity_generator.generate_syslog_event(
                                system=system,
                                time=ts + timedelta(milliseconds=rng.randint(10, 200)),
                                app_name="sshd",
                                message=lm,
                                pid=sshd_pid,
                                facility=10,
                            )
                    else:
                        # Disconnect sequence
                        msgs = [
                            f"Received disconnect from {ip} port {port}:11: disconnected by user",
                            f"Disconnected from user {ssh_user} {ip} port {port}",
                            f"pam_unix(sshd:session): session closed for user {ssh_user}",
                        ]
                        self.activity_generator.generate_syslog_event(
                            system=system,
                            time=ts,
                            app_name="sshd",
                            message=rng.choice(msgs),
                            pid=sshd_pid,
                            facility=10,
                        )
                elif source_roll < 0.80:
                    if is_rhel_like:
                        continue  # RHEL doesn't have snapd
                    self.activity_generator.generate_syslog_event(
                        system=system,
                        time=ts,
                        app_name="snapd",
                        message=rng.choice(
                            [
                                "autorefresh.go:540: auto-refresh: all snaps are up-to-date",
                                "daemon.go:460: gracefully waiting for running hooks",
                                "stateengine.go:150: state ensure starting",
                            ]
                        ),
                        pid=sys_pids.get("snapd", rng.randint(500, 2000)),
                    )
                elif source_roll < 0.88:
                    if is_rhel_like:
                        continue  # RHEL uses chronyd, not systemd-timesyncd
                    # Use the same deterministic NTP source as network-level NTP
                    ntp_candidates = [
                        ip
                        for ip in self._infra_ips.get("ntp", ["91.189.89.198"])
                        if ip != system.ip
                    ]
                    if not ntp_candidates:
                        continue  # This host IS the NTP server; skip timesyncd messages
                    ntp_ip = ntp_candidates[
                        _stable_seed(f"ntp_src_{system.hostname}") % len(ntp_candidates)
                    ]
                    if not hasattr(self, "_timesyncd_first_seen"):
                        self._timesyncd_first_seen = set()
                    if system.hostname not in self._timesyncd_first_seen:
                        msg = f"Synchronized to time server for the first time {ntp_ip}:123."
                        self._timesyncd_first_seen.add(system.hostname)
                    else:
                        msg = rng.choice(
                            [
                                f"Initial synchronization to time server {ntp_ip}:123.",
                                f"Timed out waiting for reply from {ntp_ip}:123.",
                                f"Synchronized to time server {ntp_ip}:123.",
                            ]
                        )
                    self.activity_generator.generate_syslog_event(
                        system=system,
                        time=ts,
                        app_name="systemd-timesyncd",
                        message=msg,
                        pid=sys_pids.get("timesyncd", rng.randint(400, 800)),
                    )
                elif source_roll < 0.94:
                    # Journald runtime statistics
                    machine_id = self._machine_ids.get(system.hostname, "0" * 32)
                    size = rng.randint(4, 128)
                    max_size = rng.choice([256, 512, 1024, 2048, 4096])
                    free = max_size - size
                    journal_type = rng.choice(["Runtime", "System"])
                    path = (
                        f"/run/log/journal/{machine_id}"
                        if journal_type == "Runtime"
                        else f"/var/log/journal/{machine_id}"
                    )
                    self.activity_generator.generate_syslog_event(
                        system=system,
                        time=ts,
                        app_name="systemd-journald",
                        message=f"{journal_type} Journal ({path}) is {size:.1f}M, max {max_size}M, {free:.1f}M free.",
                        pid=sys_pids.get("journald", rng.randint(200, 500)),
                    )
                else:
                    # Additional diverse syslog programs — loaded from YAML with
                    # role/distro tags for data-driven filtering.
                    from evidenceforge.generation.activity.extra_syslog import (
                        filter_syslog_messages,
                        load_extra_syslog_messages,
                    )

                    _all_programs = load_extra_syslog_messages()
                    filtered = filter_syslog_messages(_all_programs, is_rhel_like, system.roles)
                    if not filtered:
                        continue
                    app, msgs = rng.choice(filtered)
                    # Format placeholders vary by daemon
                    if app == "dhclient":
                        renewal = rng.choice([1800, 3600, 3600, 7200, 14400, 43200])
                        jitter = int(renewal * 0.05)
                        renewal += rng.randint(-jitter, jitter)
                        msg = rng.choice(msgs).format(ip=system.ip, renewal=renewal)
                    elif app == "NetworkManager":
                        # NM uses monotonic kernel uptime seconds in [brackets]
                        msg = rng.choice(msgs).format(uptime)
                    else:
                        msg = rng.choice(msgs).format(rng.randint(100000, 999999))
                    # Map syslog app names to sys_pids keys for persistent daemons.
                    # Only map to sys_pids entries that are the SAME daemon.
                    _APP_TO_PID_KEY = {
                        "NetworkManager": "networkmanager",
                        "dbus-daemon": "dbus",
                        "rsyslogd": "rsyslogd",
                        "systemd-logind": "logind",
                        "systemd-resolved": "systemd_resolved",
                        "cron": "cron",
                        "snapd": "snapd",
                    }
                    # Transient processes (forked per invocation) get random PIDs;
                    # persistent daemons get stable PIDs.
                    _TRANSIENT_APPS = {"sudo", "cron"}
                    pid_key = _APP_TO_PID_KEY.get(app)
                    if pid_key and pid_key in sys_pids:
                        pid = sys_pids[pid_key]
                    elif app in _TRANSIENT_APPS:
                        pid = rng.randint(1000, 60000)
                    else:
                        # Derive a stable per-host PID for persistent daemons not in sys_pids
                        import hashlib as _hl

                        _h = int(
                            _hl.md5(
                                f"{system.hostname}:{app}".encode(),
                                usedforsecurity=False,
                            ).hexdigest(),
                            16,
                        )
                        pid = 500 + (_h % 59500)  # range 500-59999
                    self.activity_generator.generate_syslog_event(
                        system=system,
                        time=ts,
                        app_name=app,
                        message=msg,
                        pid=pid,
                    )

        # ICMP ping between systems on same subnet
        systems = self.scenario.environment.systems
        if len(systems) >= 2:
            num_pings = rng.randint(1, 3)
            base_interval = 3600 / (num_pings + 1)
            for i in range(num_pings):
                src_sys = rng.choice(systems)
                dst_sys = rng.choice(systems)
                if src_sys.ip == dst_sys.ip:
                    continue
                if src_sys.ip.rsplit(".", 1)[0] != dst_sys.ip.rsplit(".", 1)[0]:
                    continue
                offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                self.activity_generator.generate_connection(
                    src_ip=src_sys.ip,
                    dst_ip=dst_sys.ip,
                    time=ts,
                    dst_port=0,
                    proto="icmp",
                    duration=rng.uniform(0.0005, 0.005),
                    orig_bytes=64,
                    resp_bytes=64,
                )

        # IDS false-positive alerts
        if "snort_alert" in self.emitters and self.scenario.environment.network:
            # Signatures keyed by protocol — each sig declares expected port and
            # direction ("in" = external→internal, "out" = internal→external).
            # Tuple: (sid, message, classification, priority, dst_port, direction)
            _FP_SIGS_BY_PROTO: dict[str, list[tuple[int, str, str, int, int, str]]] = {
                "icmp": [
                    (2100498, "GPL ICMP_INFO PING *NIX", "icmp-event", 3, 0, "in"),
                    (2100366, "GPL ICMP_INFO PING BSDtype", "icmp-event", 3, 0, "in"),
                    (2100480, "GPL ICMP_INFO PING Windows", "icmp-event", 3, 0, "in"),
                ],
                "tcp": [
                    # Outbound policy (internal host → external)
                    (
                        2013028,
                        "ET POLICY curl User-Agent Outbound",
                        "policy-violation",
                        3,
                        80,
                        "out",
                    ),
                    (
                        2010935,
                        "ET POLICY Outgoing Basic Auth Base64 HTTP Password detected",
                        "policy-violation",
                        2,
                        80,
                        "out",
                    ),
                    (
                        2025331,
                        "ET POLICY SSLv3 Outbound Connection Detected",
                        "policy-violation",
                        2,
                        443,
                        "out",
                    ),
                    (
                        2027316,
                        "ET INFO Observed Let's Encrypt Certificate",
                        "misc-activity",
                        3,
                        443,
                        "out",
                    ),
                    (
                        2013504,
                        "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
                        "policy-violation",
                        3,
                        80,
                        "out",
                    ),
                    (
                        2018959,
                        "ET POLICY PE EXE or DLL Windows file download HTTP",
                        "policy-violation",
                        2,
                        80,
                        "out",
                    ),
                    (
                        2016360,
                        "ET INFO Observed Discord Domain (discordapp.com)",
                        "misc-activity",
                        3,
                        443,
                        "out",
                    ),
                    (
                        2023882,
                        "ET INFO Observed Telegram Domain (t.me)",
                        "misc-activity",
                        3,
                        443,
                        "out",
                    ),
                    (
                        2025712,
                        "ET INFO External IP Lookup Domain (ipify.org)",
                        "misc-activity",
                        2,
                        443,
                        "out",
                    ),
                    (
                        2024897,
                        "ET INFO External IP Lookup (ipinfo.io)",
                        "misc-activity",
                        2,
                        443,
                        "out",
                    ),
                    (
                        2028401,
                        "ET JA3 Hash - Possible Malware - Various RAT",
                        "potentially-bad-traffic",
                        1,
                        443,
                        "out",
                    ),
                    # Inbound (external → internal)
                    (2024364, "ET INFO TLS Handshake Failure", "misc-activity", 3, 443, "in"),
                    (
                        2210044,
                        "SURICATA STREAM Packet with broken ack",
                        "protocol-command-decode",
                        3,
                        80,
                        "in",
                    ),
                    (
                        2210020,
                        "SURICATA STREAM ESTABLISHED retransmission packet",
                        "protocol-command-decode",
                        3,
                        443,
                        "in",
                    ),
                    (
                        2210054,
                        "SURICATA STREAM Packet with invalid timestamp",
                        "protocol-command-decode",
                        2,
                        80,
                        "in",
                    ),
                    (2002911, "ET SCAN Potential SSH Scan", "attempted-recon", 2, 22, "in"),
                    (
                        2010937,
                        "ET SCAN Suspicious inbound to mySQL port 3306",
                        "attempted-recon",
                        2,
                        3306,
                        "in",
                    ),
                    (
                        2010936,
                        "ET SCAN Suspicious inbound to MSSQL port 1433",
                        "attempted-recon",
                        2,
                        1433,
                        "in",
                    ),
                    (
                        2002910,
                        "ET SCAN Potential VNC Scan 5900-5920",
                        "attempted-recon",
                        2,
                        5900,
                        "in",
                    ),
                    (2019876, "ET INFO Packed Executable Download", "misc-activity", 2, 80, "in"),
                    (
                        2009582,
                        "ET WEB_SERVER SQL Injection Attempt SELECT FROM",
                        "web-application-attack",
                        1,
                        80,
                        "in",
                    ),
                    (
                        2009714,
                        "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
                        "web-application-attack",
                        1,
                        80,
                        "in",
                    ),
                    (
                        2024317,
                        "ET WEB_SERVER Possible CVE-2021-44228 Log4j RCE Attempt",
                        "web-application-attack",
                        1,
                        8080,
                        "in",
                    ),
                ],
                "udp": [
                    (
                        2016149,
                        "ET INFO Session Traversal Utilities for NAT (STUN Binding Request)",
                        "policy-violation",
                        3,
                        3478,
                        "out",
                    ),
                    (
                        2027865,
                        "ET DNS Query to a .top domain",
                        "potentially-bad-traffic",
                        2,
                        53,
                        "out",
                    ),
                    (2029706, "ET DNS Query to .cloud TLD", "misc-activity", 3, 53, "out"),
                ],
            }
            from evidenceforge.events.dispatcher import expand_formats

            segment_systems: dict[str, list] = {}
            for seg in self.scenario.environment.network.segments:
                seg_sys = [s for s in systems if s.hostname in (seg.systems or [])]
                if not seg_sys:
                    import ipaddress

                    net = ipaddress.ip_network(seg.cidr, strict=False)
                    seg_sys = [s for s in systems if ipaddress.ip_address(s.ip) in net]
                segment_systems[seg.name] = seg_sys

            for sensor in self.scenario.environment.network.sensors:
                if "snort_alert" not in expand_formats(sensor.log_formats):
                    continue
                monitored_systems = []
                for seg_name in sensor.monitoring_segments:
                    monitored_systems.extend(segment_systems.get(seg_name, []))
                if not monitored_systems:
                    continue
                num_alerts = rng.randint(5, 15)
                # For IDS sensors (typically perimeter), generate alerts with
                # external source IPs targeting monitored systems.
                _EXTERNAL_SCAN_IPS = getattr(
                    self,
                    "_external_scanner_ips",
                    [
                        "45.33.32.156",
                        "185.220.101.34",
                        "91.240.118.172",
                        "194.26.192.77",
                        "162.247.74.27",
                        "198.98.51.189",
                    ],
                )
                for _ in range(num_alerts):
                    offset = rng.uniform(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    # Pick protocol first, then choose a matching signature
                    alert_proto = rng.choice(["tcp", "udp", "icmp"])
                    sig = rng.choice(_FP_SIGS_BY_PROTO[alert_proto])
                    alert_dst_port = sig[4]  # port declared by signature
                    sig_direction = sig[5]  # "in" or "out"
                    local_sys = rng.choice(monitored_systems)
                    _weights = getattr(self, "_external_scanner_weights", None)
                    if _weights:
                        ext_ip = rng.choices(_EXTERNAL_SCAN_IPS, weights=_weights, k=1)[0]
                    else:
                        ext_ip = rng.choice(_EXTERNAL_SCAN_IPS)
                    from evidenceforge.events.contexts import IdsContext

                    # Direction: "in" = external→internal, "out" = internal→external
                    if sig_direction == "out":
                        src_ip = local_sys.ip
                        dst_ip = ext_ip
                    else:
                        src_ip = ext_ip
                        dst_ip = local_sys.ip
                    self.activity_generator.generate_connection(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        time=ts,
                        dst_port=alert_dst_port,
                        proto=alert_proto,
                        service={22: "ssh", 80: "http", 443: "ssl", 53: "dns"}.get(
                            alert_dst_port, ""
                        ),
                        duration=rng.uniform(0.001, 5.0),
                        orig_bytes=rng.randint(40, 2000),
                        resp_bytes=rng.randint(0, 1000),
                        ids=IdsContext(
                            sid=sig[0],
                            message=sig[1],
                            classification=sig[2],
                            priority=sig[3],
                        ),
                    )

        # Web access logs
        if "web_access" in self.emitters:
            _WEB_PATHS = [
                ("/", "GET", 200),
                ("/index.html", "GET", 200),
                ("/api/v1/health", "GET", 200),
                ("/favicon.ico", "GET", 200),
                ("/robots.txt", "GET", 200),
                ("/assets/main.css", "GET", 200),
                ("/assets/app.js", "GET", 200),
                ("/images/logo.png", "GET", 200),
                ("/wp-login.php", "GET", 404),
                ("/admin", "GET", 403),
                ("/.env", "GET", 403),
                ("/api/v1/data", "POST", 200),
                ("/phpmyadmin/", "GET", 404),
                ("/xmlrpc.php", "POST", 404),
            ]
            _WEB_UAS_BROWSER = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "curl/7.88.1",
                "python-requests/2.31.0",
            ]
            _WEB_UAS_BOT = [
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            ]
            for sys_obj in systems:
                if "web_server" not in (sys_obj.roles or []):
                    continue
                num_reqs = rng.randint(10, 30)

                internal_ips = [s.ip for s in systems if s.ip != sys_obj.ip]
                exposure = self._get_system_exposure(sys_obj)
                for _ in range(num_reqs):
                    offset = rng.uniform(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    path, method, status = rng.choice(_WEB_PATHS)
                    if exposure == "external":
                        client_ip = self._generate_external_client_ip(rng)
                    elif exposure == "both":
                        if rng.random() < 0.6:
                            client_ip = self._generate_external_client_ip(rng)
                        else:
                            client_ip = rng.choice(internal_ips) if internal_ips else "10.0.0.1"
                    else:
                        client_ip = rng.choice(internal_ips) if internal_ips else "10.0.0.1"
                    from evidenceforge.events.contexts import HttpContext

                    # Bots only from external IPs; browsers from anywhere
                    is_external_client = not client_ip.startswith(("10.", "172.", "192.168."))
                    # OS-aware UA selection for internal clients
                    ip_map = getattr(self.activity_generator, "_ip_to_system", {})
                    client_sys = ip_map.get(client_ip)
                    if client_sys and _get_os_category(client_sys.os) == "linux":
                        ua_pool = [
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                            "curl/7.88.1",
                            "python-requests/2.31.0",
                        ]
                    else:
                        ua_pool = _WEB_UAS_BROWSER + (_WEB_UAS_BOT if is_external_client else [])
                    resp_bytes = rng.randint(200, 50000) if status == 200 else rng.randint(100, 500)
                    _URI_MIME = {
                        "/": "text/html",
                        "/index.html": "text/html",
                        "/api/v1/health": "application/json",
                        "/favicon.ico": "image/x-icon",
                        "/robots.txt": "text/plain",
                        "/assets/main.css": "text/css",
                        "/assets/app.js": "application/javascript",
                        "/images/logo.png": "image/png",
                    }
                    mime = _URI_MIME.get(path, "text/html")
                    self.activity_generator.generate_connection(
                        src_ip=client_ip,
                        dst_ip=sys_obj.ip,
                        time=ts,
                        dst_port=80,
                        proto="tcp",
                        service="http",
                        duration=rng.uniform(0.01, 2.0),
                        orig_bytes=rng.randint(200, 2000),
                        resp_bytes=resp_bytes,
                        http=HttpContext(
                            method=method,
                            host=sys_obj.hostname,
                            uri=path,
                            version="1.1",
                            user_agent=rng.choice(ua_pool),
                            request_body_len=rng.randint(0, 500) if method == "POST" else 0,
                            response_body_len=resp_bytes,
                            status_code=status,
                            status_msg={200: "OK", 403: "Forbidden", 404: "Not Found"}.get(
                                status, "OK"
                            ),
                            resp_mime_types=[mime] if status == 200 else [],
                            tags=[],
                        ),
                    )
