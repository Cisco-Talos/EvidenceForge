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
from datetime import UTC, datetime, timedelta

from evidenceforge.models.scenario import Persona, User
from evidenceforge.utils.rng import _get_rng

logger = logging.getLogger(__name__)

# Per-persona cluster configuration
PERSONA_CLUSTER_CONFIG = {
    "developer": {"cluster_size": (5, 15), "inter_gap_mean": 600},
    "executive": {"cluster_size": (2, 6), "inter_gap_mean": 300},
    "analyst": {"cluster_size": (4, 10), "inter_gap_mean": 480},
    "sysadmin": {"cluster_size": (3, 8), "inter_gap_mean": 360},
    "default": {"cluster_size": (3, 10), "inter_gap_mean": 420},
}


class BaselineMixin:
    """Mixin providing baseline activity generation methods."""

    # Make PERSONA_CLUSTER_CONFIG accessible as class attribute
    PERSONA_CLUSTER_CONFIG = PERSONA_CLUSTER_CONFIG

    def _generate_baseline(self) -> None:
        """Generate baseline activity for all enabled users.

        Iterates hour-by-hour through the time window, generating activity
        for each enabled user based on their persona, intensity, and variation.

        Phase 1 Implementation:
        - Simple hour-by-hour iteration
        - Fixed activity patterns (no LLM)
        - Uniform distribution with jitter within each hour
        """
        logger.info("Starting baseline activity generation")
        self._emit_sensor_startup()
        self._emit_dhcp_leases()

        enabled_users = [u for u in self.scenario.environment.users if u.enabled]
        logger.info(f"Generating baseline for {len(enabled_users)} enabled users")

        total_hours = int((self.end_time - self.start_time).total_seconds() / 3600)

        current_hour = self.start_time
        hour_count = 0

        while current_hour < self.end_time:
            hour_count += 1
            logger.debug(f"Processing hour {hour_count}: {current_hour}")
            self.state_manager.set_current_time(current_hour)

            self._report_progress(
                "hour_progress",
                {"hour": hour_count, "total_hours": total_hours, "current_time": current_hour},
            )

            for user in enabled_users:
                persona = self._get_user_persona(user)
                user_offsets = self._user_time_offsets.get(user.username)

                local_hour = current_hour.hour
                if hasattr(self, "_scenario_tz") and self._scenario_tz:
                    utc_dt = current_hour.replace(tzinfo=UTC)
                    local_hour = utc_dt.astimezone(self._scenario_tz).hour
                num_events = self._calculate_events_for_hour(
                    user,
                    current_hour=local_hour,
                    persona=persona,
                    user_offsets=user_offsets,
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

            self._generate_system_traffic(current_hour)

            hour_key = int(current_hour.timestamp())
            for _event_time, event_idx in self._storyline_by_hour.get(hour_key, []):
                if event_idx not in self._storyline_executed:
                    self._execute_single_storyline_event(event_idx)
                    self._storyline_executed.add(event_idx)

            self._terminate_stale_processes(current_hour)
            self._generate_logoffs_for_hour(enabled_users, current_hour)
            self._barrier_flush_all_emitters()

            current_hour += timedelta(hours=1)

        logger.info(f"Baseline generation complete: processed {hour_count} hours")

    def _terminate_stale_processes(self, current_hour: datetime) -> None:
        """Terminate processes that have exceeded their expected lifetime.

        Called per-hour. Process lifetime depends on type:
        - System processes (svchost, lsass, csrss, services, explorer): never
        - Browsers/editors (chrome, firefox, outlook, code): 1-4 hours
        - Build tools (msbuild, gcc, npm): 5-30 minutes
        - Other: 30min-2 hours
        """
        system_patterns = (
            "svchost",
            "lsass",
            "csrss",
            "services.exe",
            "explorer.exe",
            "smss",
            "wininit",
            "winlogon",
            "fontdrvhost",
            "systemd",
            "cron",
            "sshd",
            "rsyslogd",
            "NetworkManager",
            "dbus-daemon",
            "bash",
            "agetty",
        )
        short_lived = ("msbuild", "gcc", "npm", "make", "dotnet", "cargo", "node.exe")

        rng = _get_rng()
        for system in self.scenario.environment.systems:
            processes = self.state_manager.get_processes_on_system(system.hostname)
            for proc in list(processes):
                proc_age_hours = (current_hour - proc.start_time).total_seconds() / 3600
                image_lower = proc.image.lower()

                if any(p in image_lower for p in system_patterns):
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

                if proc_age_hours > max_hours and rng.random() < 0.5:
                    actor = self._find_actor(proc.username)
                    if not actor:
                        continue

                    sessions = self.state_manager.get_sessions_for_user(proc.username)
                    logon_id = sessions[0].logon_id if sessions else "0x0"

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

    def _generate_logoffs_for_hour(
        self,
        users: list[User],
        current_hour: datetime,
    ) -> None:
        """Generate logoff events for sessions that should end this hour."""
        for user in users:
            sessions = self.state_manager.get_sessions_for_user(user.username)
            if not sessions:
                continue

            persona = self._get_user_persona(user)
            is_outside_work_hours = False
            if persona and persona.work_hours_parsed:
                is_outside_work_hours = current_hour.hour not in persona.work_hours_parsed.get(
                    "hours", range(24)
                )

            system = None
            if user.primary_system:
                systems = [
                    s
                    for s in self.scenario.environment.systems
                    if s.hostname == user.primary_system
                ]
                if systems:
                    system = systems[0]
            if not system:
                assigned = [
                    s for s in self.scenario.environment.systems if s.assigned_user == user.username
                ]
                system = assigned[0] if assigned else self.scenario.environment.systems[0]

            for session in list(sessions):
                session_age_hours = (current_hour - session.start_time).total_seconds() / 3600
                if session_age_hours < 0.5:
                    continue

                rng = _get_rng()
                logoff_probability = (
                    0.6 if is_outside_work_hours else 0.3 if session_age_hours > 1 else 0.1
                )
                if rng.random() < logoff_probability:
                    logoff_offset = rng.uniform(0, 3599)
                    logoff_time = current_hour + timedelta(seconds=logoff_offset)
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
    ) -> float:
        """Calculate activity multiplier based on work hours with smooth transitions.

        Returns 0.0-1.5 multiplier. Uses sigmoid ramps for gradual transitions
        at work start/end and lunch, instead of binary on/off.
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

        if h < start - 1.5:
            return 0.05
        if h < start + 0.5:
            t = (h - (start - 1.0)) / 1.5
            return 0.05 + 0.95 * self._sigmoid(t * 2 - 1)

        if h > end + 1.5:
            return 0.05
        if h > end - 0.5:
            t = (h - (end - 0.5)) / 1.5
            return 0.05 + 0.95 * (1.0 - self._sigmoid(t * 2 - 1))

        if lunch:
            lunch_start, lunch_end = lunch
            lunch_mid = (lunch_start + lunch_end) / 2.0
            lunch_half = (lunch_end - lunch_start) / 2.0
            if lunch_start - 0.5 < h < lunch_end + 0.5:
                dist_from_mid = abs(h - lunch_mid)
                if dist_from_mid < lunch_half:
                    return 0.5
                else:
                    t = (dist_from_mid - lunch_half) / 0.5
                    return 0.5 + 0.5 * min(1.0, t)

        if hour in peak_hours:
            return 1.5

        return 1.0

    def _calculate_events_for_hour(
        self,
        user: User,
        current_hour: int | None = None,
        persona: Persona | None = None,
        user_offsets: dict | None = None,
    ) -> int:
        """Calculate number of events for user this hour."""
        intensity_map = {"low": 5, "medium": 15, "high": 40}
        base_events = intensity_map[self.scenario.baseline_activity.intensity]

        if persona and persona.risk_profile:
            risk_mult = {"low": 0.7, "medium": 1.0, "high": 1.3}
            base_events = int(base_events * risk_mult.get(persona.risk_profile, 1.0))

        if persona and persona.work_hours_parsed and current_hour is not None:
            multiplier = self._work_hour_multiplier(
                current_hour, persona.work_hours_parsed, user_offsets
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
        """Distribute events in activity clusters within an hour.

        Phase 5.5: Replaces uniform spacing with realistic bursty clusters.
        Events within a cluster are spaced 0.5-3 seconds apart.
        Inter-cluster gaps follow exponential distribution.
        """
        if num_events == 0:
            return []

        config = self.PERSONA_CLUSTER_CONFIG.get(
            (persona_name or "").lower(), self.PERSONA_CLUSTER_CONFIG["default"]
        )
        cluster_min, cluster_max = config["cluster_size"]
        inter_gap_mean = config["inter_gap_mean"]

        if username and hasattr(self, "_user_time_offsets"):
            offsets = self._user_time_offsets.get(username, {})
            size_bias = 1.0 + offsets.get("cluster_size_bias", 0)
            cluster_min = max(2, int(cluster_min * size_bias))
            cluster_max = max(cluster_min + 1, int(cluster_max * size_bias))
            gap_bias = 1.0 + offsets.get("inter_gap_bias", 0)
            inter_gap_mean = max(60, inter_gap_mean * gap_bias)

        rng = _get_rng()
        times: list[datetime] = []
        remaining = num_events
        t = rng.expovariate(1.0 / 60)

        while remaining > 0:
            cluster_size = min(remaining, rng.randint(max(1, cluster_min - 1), cluster_max))
            for i in range(cluster_size):
                if i > 0:
                    t += rng.uniform(0.3, 2.0)
                if t < 3600:
                    times.append(hour_start + timedelta(seconds=t))
            remaining -= cluster_size
            t += rng.expovariate(1.0 / inter_gap_mean) + rng.expovariate(1.0 / inter_gap_mean)

        if not times:
            return []

        sorted_times = sorted(times)

        final: list[datetime] = [sorted_times[0]]
        for ts in sorted_times[1:]:
            recent = sum(1 for prev in final[-5:] if (ts - prev).total_seconds() <= 5.0)
            if recent < 5:
                final.append(ts)
            else:
                final.append(final[-1] + timedelta(seconds=rng.uniform(5.1, 8.0)))

        return sorted(final)

    def _generate_user_activity(self, user: User, event_time: datetime) -> None:
        """Generate activity for user at specified time."""
        rng = _get_rng()
        if user.primary_system:
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
        if not sessions and activities:
            logon_time = event_time - timedelta(seconds=rng.uniform(1.0, 5.0))
            self.state_manager.set_current_time(logon_time)
            self.activity_generator.execute_baseline_activity(
                user=user, system=system, time=logon_time, activity_type="logon"
            )

        for activity_type in activities:
            jitter = timedelta(seconds=rng.randint(0, 55))
            t = event_time + jitter
            self.state_manager.set_current_time(t)
            self.activity_generator.execute_baseline_activity(
                user=user, system=system, time=t, activity_type=activity_type
            )

    def _generate_system_traffic(self, current_hour: datetime) -> None:
        """Generate system-initiated background traffic for all systems.

        Called once per hour. Generates DNS lookups, NTP syncs, SMB browsing,
        and scheduled task activity independently of user activity.

        Uses periodic-with-jitter timing to produce realistic autocorrelation
        in system event intervals.
        """
        from evidenceforge.generation.activity import _get_os_category

        rng = _get_rng()
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

            # DNS lookups: truly periodic with small jitter, using global schedule
            if "dns-client" in services:
                dns_interval = 600 + (hash(f"dns_iv_{system.hostname}") % 1200)
                dns_phase = hash(f"dns_ph_{system.hostname}") % dns_interval
                hour_start_sec = (current_hour - self.start_time).total_seconds()
                t = dns_phase
                while t < hour_start_sec:
                    t += dns_interval
                while t < hour_start_sec + 3600:
                    jitter = rng.gauss(0, dns_interval * 0.02)
                    ts = self.start_time + timedelta(seconds=t + jitter)
                    self.state_manager.set_current_time(ts)
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
                    )
                    t += dns_interval

            # NTP sync: 1 per hour
            if "ntp-client" in services:
                offset = (hash(system.hostname) % 3600) + rng.gauss(0, 5)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                ntp_ip = rng.choice(ntp_ips)
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
                )

            # SMB browsing: Windows workstations only
            dc_ips = self._infra_ips.get("dc", ["10.0.0.1"])
            if isinstance(dc_ips, str):
                dc_ips = [dc_ips]
            dc_targets = [ip for ip in dc_ips if ip != system.ip]

            if "smb-client" in services and os_cat == "windows" and dc_targets:
                smb_interval = 1200 + (hash(f"smb_iv_{system.hostname}") % 1800)
                smb_phase = hash(f"smb_ph_{system.hostname}") % smb_interval
                hour_start_sec = (current_hour - self.start_time).total_seconds()
                t = smb_phase
                while t < hour_start_sec:
                    t += smb_interval
                while t < hour_start_sec + 3600:
                    offset = t - hour_start_sec + rng.gauss(0, smb_interval * 0.02)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(dc_targets),
                        time=ts,
                        dst_port=445,
                        proto="tcp",
                        service="smb",
                        duration=rng.uniform(0.1, 2.0),
                        orig_bytes=rng.randint(200, 2000),
                        resp_bytes=rng.randint(500, 5000),
                        source_system=system,
                    )
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
                        source_system=system,
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
                        source_system=system,
                    )

            # HTTPS background traffic
            if os_cat == "windows":
                _bg_https_ips = [
                    "23.196.25.38",
                    "13.107.4.50",
                    "93.184.220.29",
                    "23.45.101.50",
                    "52.114.128.40",
                    "204.79.197.200",
                ]
                num_https = rng.randint(8, 20)
                for _i in range(num_https):
                    offset = rng.randint(0, 3599) + rng.random()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(_bg_https_ips),
                        time=ts,
                        dst_port=443,
                        proto="tcp",
                        service="ssl",
                        duration=rng.uniform(0.1, 5.0),
                        orig_bytes=rng.randint(200, 5000),
                        resp_bytes=rng.randint(500, 50000),
                        emit_dns=True,
                        source_system=system,
                    )
            elif os_cat == "linux":
                _linux_https_ips = ["91.189.91.39", "185.125.190.39", "151.101.0.204"]
                num_https = rng.randint(3, 10)
                for _i in range(num_https):
                    offset = rng.randint(0, 3599) + rng.random()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(_linux_https_ips),
                        time=ts,
                        dst_port=443,
                        proto="tcp",
                        service="ssl",
                        duration=rng.uniform(0.1, 3.0),
                        orig_bytes=rng.randint(200, 3000),
                        resp_bytes=rng.randint(500, 30000),
                        emit_dns=True,
                        source_system=system,
                    )

            # Database traffic
            db_servers = self._infra_ips.get("db_servers", [])
            if db_servers and system.ip not in [d["ip"] for d in db_servers]:
                sys_type = (system.type or "workstation").lower()
                if sys_type in ("server", "domain_controller") or (
                    sys_type == "workstation" and rng.random() < 0.2
                ):
                    db = rng.choice(db_servers)
                    num_db = rng.randint(3, 10)
                    base_interval = 3600 / (num_db + 1)
                    for i in range(num_db):
                        offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                        offset = max(0, min(3599, offset))
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)
                        self.activity_generator.generate_connection(
                            src_ip=system.ip,
                            dst_ip=db["ip"],
                            time=ts,
                            dst_port=db["port"],
                            proto="tcp",
                            service=db["service"],
                            duration=rng.uniform(0.01, 2.0),
                            orig_bytes=rng.randint(200, 5000),
                            resp_bytes=rng.randint(500, 50000),
                            source_system=system,
                        )

            # Scheduled tasks
            host_seed = hash(system.hostname) % 900
            if os_cat == "windows":
                win_tasks = [
                    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
                    (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe /Run"),
                    (r"C:\Windows\System32\usoclient.exe", "usoclient.exe StartScan"),
                ]
                task_name, task_cmd = win_tasks[hash(system.hostname) % len(win_tasks)]
            else:
                os_str = (system.os or "").lower()
                is_rhel_task = any(
                    d in os_str for d in ("centos", "rhel", "red hat", "rocky", "alma")
                )
                if is_rhel_task:
                    linux_tasks = [
                        ("/usr/sbin/logrotate", "/usr/sbin/logrotate /etc/logrotate.conf"),
                        ("/usr/bin/dnf", "/usr/bin/dnf -y makecache --timer"),
                        ("/usr/bin/needs-restarting", "/usr/bin/needs-restarting -r"),
                    ]
                else:
                    linux_tasks = [
                        ("/usr/sbin/logrotate", "/usr/sbin/logrotate /etc/logrotate.conf"),
                        ("/usr/bin/apt-get", "/usr/bin/apt-get -qq update"),
                        (
                            "/usr/lib/update-notifier/apt-check",
                            "/usr/lib/update-notifier/apt-check --human-readable",
                        ),
                    ]
                task_name, task_cmd = linux_tasks[hash(system.hostname) % len(linux_tasks)]

            for slot_base in [0, 900, 1800, 2700]:
                offset = slot_base + host_seed + rng.gauss(0, 8) + rng.uniform(0, 3)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)

                if os_cat == "windows":
                    parent_pid = sys_pids.get("svchost_local_system", sys_pids.get("services", 4))
                    self.activity_generator.generate_system_process(
                        system=system,
                        time=ts,
                        process_name=task_name,
                        command_line=task_cmd,
                        parent_pid=parent_pid,
                        username="SYSTEM",
                    )
                else:
                    parent_pid = sys_pids.get("cron", 0)
                    self.activity_generator.generate_system_process(
                        system=system,
                        time=ts,
                        process_name=task_name,
                        command_line=task_cmd,
                        parent_pid=parent_pid,
                        username="root",
                    )

            # ICMP: monitoring pings between servers
            sys_type = (system.type or "workstation").lower()
            if sys_type in ("server", "domain_controller") and rng.random() < 0.7:
                targets = [
                    s.ip
                    for s in self.scenario.environment.systems
                    if s.ip != system.ip
                    and s.type
                    and s.type.lower() in ("server", "domain_controller")
                ][:5]
                if targets:
                    target_ip = rng.choice(targets)
                    offset = rng.randint(0, 3599) + rng.random()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=target_ip,
                        time=ts,
                        dst_port=0,
                        proto="icmp",
                        duration=rng.uniform(0.0001, 0.005),
                        orig_bytes=64,
                        resp_bytes=64,
                        source_system=system,
                    )

            # SSH: connections to Linux servers
            if os_cat == "linux" and sys_type == "server":
                ssh_sources = [
                    s.ip for s in self.scenario.environment.systems if s.ip != system.ip
                ][:10]
                if ssh_sources:
                    num_ssh = rng.randint(1, 3)
                    for _ in range(num_ssh):
                        src_ip = rng.choice(ssh_sources)
                        offset = rng.randint(0, 3599)
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)
                        self.activity_generator.generate_connection(
                            src_ip=src_ip,
                            dst_ip=system.ip,
                            time=ts,
                            dst_port=22,
                            proto="tcp",
                            service="ssh",
                            duration=rng.uniform(30.0, 3600.0),
                            orig_bytes=rng.randint(2000, 50000),
                            resp_bytes=rng.randint(5000, 200000),
                            source_system=system,
                        )

        # Service logons (LogonType 5) and ANONYMOUS LOGONs on Windows systems
        for system in self.scenario.environment.systems:
            os_cat_svc = _get_os_category(system.os)
            if os_cat_svc != "windows" or "windows_event_security" not in self.emitters:
                continue

            ad_domain = getattr(self.activity_generator, "_ad_domain", "corp.local")
            getattr(self.activity_generator, "_netbios_domain", "CORP")
            computer_fqdn = f"{system.hostname}.{ad_domain}"

            sys_type_svc = (system.type or "workstation").lower()
            num_svc = rng.randint(2, 5) if sys_type_svc != "workstation" else rng.randint(1, 2)
            for _ in range(num_svc):
                offset = rng.randint(0, 3599)
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
                    offset = rng.randint(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="windows_event_security",
                        system=system,
                        fields={
                            "EventID": 4624,
                            "TimeCreated": ts,
                            "Computer": computer_fqdn,
                            "Channel": "Security",
                            "Level": 0,
                            "ExecutionProcessID": 4,
                            "ExecutionThreadID": rng.randint(100, 500),
                            "SubjectUserSid": "S-1-0-0",
                            "SubjectUserName": "-",
                            "SubjectDomainName": "-",
                            "SubjectLogonId": "0x0",
                            "TargetUserSid": "S-1-5-7",
                            "TargetUserName": "ANONYMOUS LOGON",
                            "TargetDomainName": "NT AUTHORITY",
                            "TargetLogonId": f"0x{rng.randint(0x10000, 0xFFFFFFFF):x}",
                            "LogonType": 3,
                            "LogonProcessName": "NtLmSsp",
                            "AuthenticationPackageName": "NTLM",
                            "LmPackageName": "NTLM V2",
                            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                            "WorkstationName": "-",
                            "ProcessId": "0x0",
                            "ProcessName": "-",
                            "IpAddress": "-",
                            "IpPort": 0,
                        },
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
                    offset = rng.randint(0, 3599)
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
            sys_type = (system.type or "server").lower()
            is_dmz = "dmz" in system.hostname.lower() or "web" in system.hostname.lower()
            num_events = rng.randint(100, 300) if is_dmz else rng.randint(50, 120)

            scenario_start = self.scenario.time_window.start
            boot_uptime = self._kernel_boot_uptimes.get(system.hostname, 500000.0)

            for _ in range(num_events):
                offset = rng.uniform(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                uptime = int(boot_uptime + (ts - scenario_start).total_seconds())

                source_roll = rng.random()
                if source_roll < 0.20:
                    services = [
                        "logrotate",
                        "phpsessionclean",
                        "apt-daily",
                        "man-db",
                        "fstrim",
                        "motd-news",
                        "ua-timer",
                        "systemd-tmpfiles-clean",
                    ]
                    svc = rng.choice(services)
                    action = rng.choice(["Starting", "Finished"])
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="syslog",
                        system=system,
                        fields={
                            "timestamp": ts,
                            "hostname": system.hostname,
                            "app_name": "systemd",
                            "pid": sys_pids.get("systemd", 1),
                            "facility": 3,
                            "severity": 6,
                            "message": f"{action} {svc}.service - {svc.replace('-', ' ').title()}.",
                        },
                    )
                elif source_roll < 0.35:
                    cron_cmds = [
                        (
                            "root",
                            "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
                        ),
                        ("root", "command -v debian-sa1 > /dev/null && debian-sa1 1 1"),
                        ("root", "/usr/sbin/logrotate /etc/logrotate.conf"),
                        ("www-data", "/usr/bin/php /var/www/html/cron.php"),
                    ]
                    user, cmd = rng.choice(cron_cmds)
                    self.activity_generator.generate_system_process(
                        system=system,
                        time=ts,
                        process_name="/usr/sbin/cron",
                        command_line=cmd,
                        parent_pid=sys_pids.get("cron", 0),
                        username=user,
                    )
                elif source_roll < 0.50:
                    if is_dmz and rng.random() < 0.85:
                        src_ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                        spt = rng.randint(1024, 65535)
                        dpt = rng.choice([22, 23, 25, 80, 443, 445, 3389, 8080])
                        msg = (
                            f"[{uptime}.{rng.randint(100000, 999999)}] [UFW BLOCK] "
                            f"IN=ens160 OUT= SRC={src_ip} DST={system.ip} "
                            f"LEN={rng.randint(40, 60)} TOS=0x00 PREC=0x00 TTL={rng.randint(40, 255)} "
                            f"ID={rng.randint(1, 65535)} PROTO=TCP SPT={spt} DPT={dpt} "
                            f"WINDOW={rng.choice([1024, 14600, 65535])} RES=0x00 SYN URGP=0"
                        )
                        self.activity_generator.generate_connection(
                            src_ip=src_ip,
                            dst_ip=system.ip,
                            time=ts,
                            dst_port=dpt,
                            proto="tcp",
                            conn_state="REJ",
                            src_port=spt,
                            source_system=system,
                        )
                    else:
                        self._audit_serials[system.hostname] = self._audit_serials.get(
                            system.hostname, 1000
                        ) + rng.randint(1, 5)
                        audit_serial = self._audit_serials[system.hostname]
                        msg = (
                            f"[{uptime}.{rng.randint(100000, 999999)}] audit: type=1400 "
                            f"audit({int(ts.timestamp())}.{rng.randint(100, 999)}:{audit_serial}): "
                            f'apparmor="ALLOWED" operation="open" profile="usr.sbin.mysqld"'
                        )
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="syslog",
                        system=system,
                        fields={
                            "timestamp": ts,
                            "hostname": system.hostname,
                            "app_name": "kernel",
                            "pid": None,
                            "facility": 0,
                            "severity": 5,
                            "message": msg,
                        },
                    )
                elif source_roll < 0.65:
                    sid = rng.randint(100, 9999)
                    user = rng.choice(["root", "admin", "www-data", "ubuntu"])
                    action = rng.choice(
                        [f"New session {sid} of user {user}.", f"Removed session {sid}."]
                    )
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="syslog",
                        system=system,
                        fields={
                            "timestamp": ts,
                            "hostname": system.hostname,
                            "app_name": "systemd-logind",
                            "pid": sys_pids.get("logind", rng.randint(400, 800)),
                            "facility": 3,
                            "severity": 6,
                            "message": action,
                        },
                    )
                elif source_roll < 0.80:
                    other_ips = [
                        s.ip for s in self.scenario.environment.systems if s.ip != system.ip
                    ]
                    ip = rng.choice(other_ips) if other_ips else system.ip
                    port = rng.randint(49152, 65535)
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
                        source_system=system,
                    )
                    msgs = [
                        f"Received disconnect from {ip} port {port}:11: disconnected by user",
                        f"Disconnected from user admin {ip} port {port}",
                        "pam_unix(sshd:session): session closed for user admin",
                    ]
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="syslog",
                        system=system,
                        fields={
                            "timestamp": ts,
                            "hostname": system.hostname,
                            "app_name": "sshd",
                            "pid": rng.randint(5000, 60000),
                            "facility": 10,
                            "severity": 6,
                            "message": rng.choice(msgs),
                        },
                    )
                elif source_roll < 0.90:
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="syslog",
                        system=system,
                        fields={
                            "timestamp": ts,
                            "hostname": system.hostname,
                            "app_name": "snapd",
                            "pid": sys_pids.get("snapd", rng.randint(500, 2000)),
                            "facility": 3,
                            "severity": 6,
                            "message": rng.choice(
                                [
                                    "autorefresh.go:540: auto-refresh: all snaps are up-to-date",
                                    "daemon.go:460: gracefully waiting for running hooks",
                                    "stateengine.go:150: state ensure starting",
                                ]
                            ),
                        },
                    )
                else:
                    ntp_ip = rng.choice(["91.189.89.198", "91.189.89.199", "91.189.94.4"])
                    if not hasattr(self, "_timesyncd_first_seen"):
                        self._timesyncd_first_seen = set()
                    if system.hostname not in self._timesyncd_first_seen:
                        msg = f"Synchronized to time server for the first time {ntp_ip}:123 (ntp.ubuntu.com)."
                        self._timesyncd_first_seen.add(system.hostname)
                    else:
                        msg = rng.choice(
                            [
                                f"Initial synchronization to time server {ntp_ip}:123 (ntp.ubuntu.com).",
                                f"Timed out waiting for reply from {ntp_ip}:123 (ntp.ubuntu.com).",
                                f"Synchronized to time server {ntp_ip}:123 (ntp.ubuntu.com).",
                            ]
                        )
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="syslog",
                        system=system,
                        fields={
                            "timestamp": ts,
                            "hostname": system.hostname,
                            "app_name": "systemd-timesyncd",
                            "pid": sys_pids.get("timesyncd", rng.randint(400, 800)),
                            "facility": 3,
                            "severity": 6,
                            "message": msg,
                        },
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
                    source_system=system,
                )

        # IDS false-positive alerts
        if "snort_alert" in self.emitters and self.scenario.environment.network:
            _FP_SIGS = [
                (2100498, "GPL ICMP_INFO PING *NIX", "icmp-event", 3),
                (2013028, "ET POLICY curl User-Agent Outbound", "policy-violation", 3),
                (2024364, "ET INFO TLS Handshake Failure", "misc-activity", 3),
                (2210044, "SURICATA STREAM Packet with broken ack", "protocol-command-decode", 3),
                (2100366, "GPL ICMP_INFO PING BSDtype", "icmp-event", 3),
                (2002911, "ET SCAN Potential SSH Scan", "attempted-recon", 2),
                (2019876, "ET INFO Packed Executable Download", "misc-activity", 2),
                (2027865, "ET DNS Query to a .top domain", "potentially-bad-traffic", 2),
            ]
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
                sensor_host = sensor.hostname or sensor.name
                monitored_systems = []
                for seg_name in sensor.monitoring_segments:
                    monitored_systems.extend(segment_systems.get(seg_name, []))
                if not monitored_systems:
                    continue
                num_alerts = rng.randint(1, 3)
                # For IDS sensors (typically perimeter), generate alerts with
                # external source IPs targeting monitored systems.
                _EXTERNAL_SCAN_IPS = [
                    "45.33.32.156",
                    "185.220.101.34",
                    "91.240.118.172",
                    "194.26.192.77",
                    "162.247.74.27",
                    "198.98.51.189",
                ]
                for _ in range(num_alerts):
                    offset = rng.randint(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    sig = rng.choice(_FP_SIGS)
                    dst_sys = rng.choice(monitored_systems)
                    if sensor.direction == "inbound" or len(monitored_systems) < 2:
                        src_ip = rng.choice(_EXTERNAL_SCAN_IPS)
                    else:
                        src_sys = rng.choice(monitored_systems)
                        if src_sys.ip == dst_sys.ip:
                            continue
                        src_ip = src_sys.ip
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="snort_alert",
                        fields={
                            "timestamp": ts,
                            "sid": sig[0],
                            "message": sig[1],
                            "classification": sig[2],
                            "priority": sig[3],
                            "protocol": rng.choice(["TCP", "UDP", "ICMP"]),
                            "src_ip": src_ip,
                            "src_port": rng.randint(1024, 65535),
                            "dst_ip": dst_sys.ip,
                            "dst_port": rng.choice([22, 80, 443, 53, 8080]),
                            "_sensor_hostnames": [sensor_host],
                        },
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
            _WEB_UAS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "curl/7.88.1",
                "python-requests/2.31.0",
            ]
            for sys_obj in systems:
                if "web_server" not in (sys_obj.roles or []):
                    continue
                num_reqs = rng.randint(10, 30)

                internal_ips = [s.ip for s in systems if s.ip != sys_obj.ip]
                exposure = self._get_system_exposure(sys_obj)
                for _ in range(num_reqs):
                    offset = rng.randint(0, 3599)
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
                    self.activity_generator.generate_raw(
                        time=ts,
                        target_format="web_access",
                        system=sys_obj,
                        fields={
                            "timestamp": ts,
                            "client_ip": client_ip,
                            "method": method,
                            "path": path,
                            "protocol": "HTTP/1.1",
                            "status_code": status,
                            "bytes_sent": rng.randint(200, 50000)
                            if status == 200
                            else rng.randint(100, 500),
                            "referer": "-",
                            "user_agent": rng.choice(_WEB_UAS),
                        },
                    )
