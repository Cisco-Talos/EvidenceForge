# EvidenceForge Architecture

This document explains how EvidenceForge works — first at a high level for users, then in detail for contributors who want to extend it.

## Part 1: How It Works

### Two-Phase Hybrid Architecture

EvidenceForge uses a two-phase approach that combines LLM flexibility with deterministic reliability:

```
Phase 1: Scenario Creation (LLM-Assisted)
+--------------------------------------------------+
|  Claude Code Skills guide interactive authoring   |
|  - Research TTPs via MITRE ATT&CK                |
|  - Interview user about environment & attack      |
|  - Output: validated YAML scenario file           |
+--------------------------------------------------+
                     |
                     v
Phase 2: Log Generation (Deterministic)
+--------------------------------------------------+
|  eforge CLI executes the scenario plan            |
|  - No LLM calls, no API costs                    |
|  - Reproducible output (seeded RNG)              |
|  - Output: correlated multi-format log files      |
+--------------------------------------------------+
```

This separation means scenario creation benefits from LLM reasoning about attack techniques, while generation is fast, cheap, and reproducible.

### Generation Pipeline

```
┌─ Scenario YAML ──────────────────────────────────┐
│  Environment (users, systems, network topology)   │
│  Personas (behavioral patterns per user role)     │
│  Storyline (typed attack event declarations)      │
│  Output spec (which formats, where to write)      │
└──────────────────────┬────────────────────────────┘
                       │
                ┌──────▼──────────┐
                │   Validation    │
                │  Pydantic schema│
                │  Cross-refs     │
                │  Network topo   │
                └──────┬──────────┘
                       │
          ┌────────────▼────────────────┐
          │     GenerationEngine        │
          │  Hour-by-hour time loop     │
          │  Hawkes timing (user)       │
          │  Periodic timing (system)   │
          │  Day-of-week variation      │
          │  Storyline typing cadence   │
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────────┐
          │ WorldModel / WorldPlanner   │
          │  Compile host/user intent   │
          │  Resolve roles + services   │
          │  Pick session semantics     │
          │  Preallocate session state  │
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────────┐
          │    ActivityGenerator         │
          │  Emits evidence against     │
          │  planner-owned state and    │
          │  builds SecurityEvents      │
          │  with composable contexts   │
          │                              │
          │  CausalExpansionEngine       │
          │  auto-emits prerequisites   │
          │  (DNS, Kerberos, audit, etc)│
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────────┐
          │     EventDispatcher         │
          │  1. StateManager.apply()    │
          │  2. Route to emitters       │
          │     (format + visibility)   │
          └────────┬───────┬────────────┘
                   │       │
    ┌──────────────┘       └──────────────┐
    │                                     │
┌───▼────────┐  ┌──────────┐  ┌──────────▼──┐
│  Windows   │  │   Zeek   │  │   eCAR /    │
│  Events    │  │   Logs   │  │   Syslog /  │
│  (XML)     │  │  (NDJSON)│  │   Others    │
└────────────┘  └──────────┘  └─────────────┘
```

### Consistency by Construction

The core architectural principle is that **two emitters cannot disagree about shared fields because there is only one source of truth.**

A single `SecurityEvent` object carries all the data for one logical security event. When a user logs into a Linux system, ActivityGenerator creates one SecurityEvent with AuthContext + SyslogContext, and the EventDispatcher routes it to every relevant emitter. The syslog emitter renders from SyslogContext ("Accepted password for alice from ..."), and the eCAR emitter renders from AuthContext as a USER_SESSION record — all from the same object, so timestamps, usernames, and LogonIDs are guaranteed identical.

```
            ActivityGenerator
                   │
                   ▼
        ┌─── SecurityEvent ───┐
        │ timestamp: 09:15:23 │
        │ src_host: LNX-001   │
        │ auth:               │
        │   user: john.doe    │
        │   logon_id: 0x4A2B  │
        │ syslog:             │
        │   app: sshd         │
        │   msg: Accepted ... │
        └─────────┬───────────┘
                  │
      ┌───────────┼───────────┐
      ▼           ▼           ▼
  Syslog      eCAR        Zeek
  sshd msg   LOGIN       conn.log
  (from       (from       (from
  syslog)     auth)       network)
```

### Network Visibility Modeling

EvidenceForge models where network sensors are placed and what traffic they can observe:

- **SPAN ports** see all traffic in their monitored segments (including intra-segment)
- **TAP sensors** only see traffic crossing segment boundaries
- **Direction** controls whether a sensor sees inbound, outbound, or both

When a network connection event is dispatched, the NetworkVisibilityEngine determines which sensors can observe it based on the source/destination IPs and sensor placement. Only sensors with visibility produce log entries for that connection.

**Network Address Translation:** When firewall sensors have `nat_rules`, the dispatcher computes NAT translations for permitted cross-boundary connections. The `NatContext` on `SecurityEvent` carries mapped IPs. The ASA emitter renders both real and mapped addresses (305011/305012 + parenthesized IPs in Built messages). Zeek emitters swap IPs for post-NAT sensors via `_nat_swaps_by_sensor`, so inside sensors see real IPs while outside sensors see translated IPs.

---

## Part 2: Internals (For Contributors)

### SecurityEvent Canonical Model

The `SecurityEvent` dataclass (`src/evidenceforge/events/base.py`) is the central data structure:

```
SecurityEvent
├── timestamp: datetime (UTC)
├── event_type: str ("logon", "process_create", "connection", ...)
├── src_host: HostContext (originating system — hostname, IP, OS, domain, FQDN)
├── dst_host: HostContext (target system — hostname, IP, OS, domain, FQDN)
├── auth: AuthContext (logon_id, logon_type, SID, failure codes)
├── process: ProcessContext (pid, parent_pid, image, command_line, start_time)
├── remote_thread: RemoteThreadContext (target_pid, new_thread_id, start_address)
├── network: NetworkContext (src/dst IP/port, protocol, zeek_uid, bytes)
├── dns: DnsContext (query, type, response, TTL)
├── file: FileContext (path, hash, operation)
├── registry: RegistryContext (key, value, operation)
├── ids: IdsContext (signature, severity, classification)
├── syslog: SyslogContext (app_name, message, pid, facility, severity)
├── weird: WeirdContext (name, notice, peer, source)
├── kerberos: KerberosContext (ticket_type, service, encryption)
├── shell: ShellContext (command)
├── ... (27 context types total)
└── _sensor_hostnames_by_format: dict (network visibility metadata)
```

All contexts are `@dataclass(slots=True)` for memory efficiency. They're defined in `src/evidenceforge/events/contexts.py`.

**Key design decisions:**
- Host context uses a dual `src_host`/`dst_host` model — `src_host` is the system that originates or performs the action; `dst_host` is the target or receiver. For single-host events only one is set; for network events both may be set when both endpoints are known
- Contexts are composable — a logon event has Host + Auth + Syslog contexts; a process event has Host + Process + Syslog contexts
- All fields are optional except `timestamp` and `event_type` — emitters check for the contexts they need
- The syslog emitter renders from SyslogContext (app_name, message, pid, facility, severity). All syslog message construction is done by ActivityGenerator, not the emitter.
- `RawLogEntry` exists solely for the user-facing `raw` event type in scenario YAML. All internal engine code uses canonical SecurityEvent dispatch exclusively

### WorldModel and WorldPlanner

The compiled world-model layer (`src/evidenceforge/generation/world_model.py`) sits above the canonical event model and answers the realism question the event model does not: "why would this user/system do this here?"

- `WorldModel` compiles canonical host capabilities and user placement from scenario fields such as `user.primary_system`, `system.assigned_user`, `system.roles`, and `system.services`
- `WorldPlanner` centralizes session bootstrap for interactive, network, SSH, and RDP access, including remote source-host selection and planner-owned session allocation
- Baseline and storyline call this shared layer instead of maintaining separate SSH/RDP/logon heuristics
- `ActivityGenerator` then emits host/network evidence against that precomputed state using the canonical `SecurityEvent` pipeline

### EventDispatcher

The dispatcher (`src/evidenceforge/events/dispatcher.py`) routes events through two layers:

```
SecurityEvent
    │
    ├──▶ StateManager.apply(event)    [side effects: session/process/connection state]
    │
    ├──▶ Layer 1: Format Eligibility
    │    emitter.can_handle(event)     [checks event_type + required contexts]
    │
    └──▶ Layer 2: Network Visibility   [for network events only]
         Which sensors see this traffic?
         Sets _sensor_hostnames_by_format metadata
         │
         ▼
    Matching emitters receive the event
```

**Format groups** expand shorthand names: `"zeek"` expands to 13 individual emitters (zeek_conn, zeek_dns, zeek_http, etc.).

### StateManager

`StateManager` (`src/evidenceforge/generation/state_manager.py`) is the single source of truth for runtime state:

```
StateManager
├── Active Sessions    {logon_id → ActiveSession}
│   └── username, system, logon_type, explorer_pid, process_tree_root
├── Running Processes  {(system, pid) → RunningProcess}
│   └── pid, parent_pid, image, command_line, integrity_level
├── Open Connections   {conn_id → OpenConnection}
│   └── src/dst IP/port, protocol, zeek_uid, bytes, state
├── DNS Cache          {hostname → IP}
├── Boot Times         {system → datetime} (entity lifecycle validation)
└── Current Time       datetime (advances during generation)
```

**ID allocation pattern:**
1. `WorldPlanner` or `ActivityGenerator` calls `state_manager.create_session()` / `create_process()` / `open_connection()` to allocate durable IDs and ownership metadata
2. `ActivityGenerator` builds a `SecurityEvent` with those IDs
3. Dispatches the event
4. `StateManager.apply()` records state from the event (teardown, byte updates — never allocates IDs)

**Zeek UID correlation:** All Zeek log types for the same network connection share a `zeek_uid` stored on `OpenConnection`. This is the critical cross-log correlation key — conn.log, dns.log, http.log, ssl.log all reference the same UID.

**Thread safety:** RLock protects all public methods. Lock hold times are typically <1ms. Thread-local RNG (seeded by thread ID) ensures reproducibility across concurrent generation.

### Emitter Architecture

All emitters inherit from `LogEmitter` (`src/evidenceforge/generation/emitters/base.py`):

```
LogEmitter (ABC)
├── _supported_types: set[str]       # Which event types this emitter handles
├── can_handle(event) → bool         # Format eligibility check
├── emit(event: SecurityEvent)       # New path: type-safe, context-aware
├── emit_event(data: dict)           # Legacy path: raw dict rendering
├── emit_raw(entry: RawLogEntry)     # Escape hatch (user `raw` event type only)
├── _buffer: list                    # 10K event buffer before flush
└── _flush()                         # Write buffer to file
│
├── WindowsEventEmitter              # Security XML plus Snare/RFC3164 sidecar
├── SysmonEventEmitter               # Sysmon XML plus Snare/RFC3164 sidecar
├── ZeekEmitter                      # conn.log (base for 13 Zeek types)
│   ├── ZeekDnsEmitter               # dns.log
│   ├── ZeekHttpEmitter              # http.log
│   ├── ZeekSslEmitter               # ssl.log
│   └── ... (10 more Zeek types)
├── EcarEmitter                      # eCAR NDJSON (MITRE CAR model, objectID/actorID graph via EdrContext)
├── SyslogEmitter                    # Linux syslog (RFC3164, per-host/year)
├── BashHistoryEmitter               # Per-user bash history
├── SnortEmitter                     # Snort IDS alerts
├── CiscoAsaEmitter                  # Cisco ASA firewall syslog (Built/Teardown/Deny)
├── WebEmitter                       # Apache/Nginx access logs
└── ProxyEmitter                     # HTTP forward proxy access logs (W3C Extended)
```

**Sensor multiplexing:** Network emitters (Zeek family, Snort, Cisco ASA) use `SensorMultiplexEmitter` to route output to per-sensor directories. A single emitter instance manages output for multiple sensors. Zeek/Snort write to `<sensor_hostname>/<log_file>`; Cisco ASA is syslog-family output and writes to `<sensor_hostname>/<year>/cisco_asa.log`. The CiscoAsaEmitter also generates deny baseline traffic from the firewall sensor's policy rules.

**Proxy path modeling:** `environment.proxy.mode` controls whether proxy-routed HTTP/HTTPS keeps transparent client→origin network evidence or is split into explicit client→proxy and proxy→origin legs. Explicit mode dispatches each concrete leg through the normal sensor visibility engine so Zeek/IDS/firewall sources only contain the side of the proxy they can observe; the original logical client→origin request is not emitted as network evidence. Denied proxy requests emit only the client→proxy/proxy access evidence and do not create downstream origin-side transactions.

**Threading:** Each emitter optionally runs in a background thread with a bounded queue (50K max). Hour-level flush barriers ensure temporal consistency.

**Two rendering paths:**
- `emit(SecurityEvent)` — primary path for all event types (storyline + baseline)
- `emit_event(dict)` — legacy path for user `raw` event type in scenario YAML only

### Format Definition System

Log formats are defined declaratively in YAML files (`src/evidenceforge/formats/definitions/`), not in code:

```yaml
# Example: zeek_conn.yaml
name: zeek_conn
description: "Zeek connection log"
output_format: ndjson
fields:
  - name: ts
    type: timestamp
    required: true
  - name: uid
    type: string
    required: true
    constraints:
      pattern: "^C[A-Za-z0-9]{17}$"
  # ...
```

Each format YAML defines fields (name, type, constraints), event variants (for multi-event formats like Windows Security), and Jinja2 output templates. Adding a new log format requires:
1. A new YAML definition in `formats/definitions/`
2. An emitter class in `generation/emitters/`
3. A parser class in `evaluation/parsers/` (for eval support)

### Evaluation Engine

The evaluation system (`src/evidenceforge/evaluation/`) scores generated data across 4 pillars:

```
EvaluationEngine
├── Parsers (18 format parsers)
│   ├── WindowsEventParser (XML)
│   ├── ZeekBaseParser + 13 protocol-specific
│   ├── EcarParser (NDJSON)
│   ├── SyslogParser (regex)
│   └── ... (bash history, snort, web, proxy, cisco_asa)
│
├── Pillars (4 scoring modules — currently still 5 legacy scorers during transition)
│   ├── Parseability    (30%) — spec conformance, format constraints
│   ├── Plausibility    (25%) — OS/value correctness, co-occurrence, distributions,
│   │                           user diversity, benign anomaly rate
│   ├── Causality       (25%) — causal ordering, event presence, indicator accuracy,
│   │                           pivot linkability, storyline temporal integrity
│   └── Timing          (20%) — attack-chain timing, burstiness, diurnal patterns,
│                               volume adequacy, rate plausibility
│
├── Thresholds (config/evaluation/thresholds.yaml)
│   ├── minimum: hard gate — dataset fails if missed
│   └── aspirational: informational stretch target
│
└── QualityReport
    ├── overall_score: 0-100
    ├── pillars: list[PillarScore]
    ├── acceptance_criteria: pass/fail (hard gates only)
    ├── aspirational_met / aspirational_total
    ├── flags: list[str]
    └── supplementary: dict  ← includes host_log_profile diagnostic
```

Causal ordering rules are defined in `evaluation/rules/causal_pairs.yaml`. Rules support several evaluation features:

- **Grace period:** Events within the scenario's `logon_grace_period` (default 30m) from scenario start are exempt from causal ordering checks, since data collection begins mid-session with pre-existing user sessions.
- **Per-rule tolerance:** Rules can specify a `tolerance` fraction (e.g., 0.03 for DNS→TCP) allowing a percentage of failures without penalty. Used for intentional direct-IP baseline connections.
- **Account exclusions:** Rules list system accounts (SYSTEM, root, www-data, etc.) exempt from logon-before-process checks, since daemons run from boot without interactive logins.
- **Format groups:** Trace coverage uses format groups (host-local vs network) instead of checking all formats. Connection events expect traces in both groups; process/logon events only expect host-local traces.
- **Typed event detection:** Signal integrity uses typed EventSpec fields to identify event types instead of keyword-matching activity descriptions, with 15 record matchers covering all event types.

### Scenario Models

The Pydantic model hierarchy (`src/evidenceforge/models/scenario.py`):

```
Scenario (root)
├── environment: Environment
│   ├── timezone: TimeZone (default + system overrides)
│   ├── users: list[User] (username, email, persona, primary_system)
│   ├── systems: list[System] (hostname, IP, OS, type, services)
│   ├── groups: list[Group] (name, members, permissions)
│   └── network: NetworkConfig (optional)
│       ├── segments: list[NetworkSegment] (name, CIDR, systems)
│       └── sensors: list[NetworkSensor] (type, placement, direction, formats)
├── personas: list[Persona] (activities, work_hours, risk_profile)
├── time_window: TimeWindow (start, end/duration)
├── baseline_activity: BaselineActivity (intensity, variation)
├── storyline: list[StorylineEvent]
│   └── events: list[EventSpec] (discriminated union)
│       ├── ProcessEventSpec
│       ├── LogonEventSpec
│       ├── ConnectionEventSpec
│       ├── SshSessionEventSpec
│       └── ... (15+ event types)
└── output: OutputSpec (formats, destination)
```

**Storyline events** use a discriminated union — each event in the `events` list has a `type` field that selects a specific Pydantic model with validated per-type fields.

### Validation

Three layers of validation (`src/evidenceforge/validation/schema.py`):

1. **Pydantic schema validation** — types, formats, patterns, constraints
2. **Cross-reference validation** — users reference valid personas, storyline actors exist, systems have valid IPs, network segments are consistent
3. **Generation-time checks** — OS compatibility, builtin account validation

Builtin accounts (SYSTEM, root, NT AUTHORITY\SYSTEM, etc.) are always valid as storyline actors without being defined in the users list.

### Causal Expansion Engine

The `CausalExpansionEngine` (`src/evidenceforge/generation/causal/`) centralizes the logic for auto-generating prerequisite and consequent events. Instead of scattering DNS-before-connection checks, Kerberos TGT/TGS emission, and command-line pattern inference across ActivityGenerator and StorylineMixin, all causal relationships are defined as composable `ExpansionRule` dataclasses in a flat registry.

```
ActivityGenerator.generate_connection()
    │
    ├──▶ _expand_and_emit("connection", ...)
    │        │
    │        ├──▶ CausalExpansionEngine.expand()
    │        │        │
    │        │        ├── DnsBeforeConnection        (priority 10)
    │        │        ├── KerberosBeforeLogon         (priority 20)
    │        │        ├── ProcessAccessAfterRemoteThread (priority 40)
    │        │        └── SupplementaryAuditEvents    (priority 60)
    │        │
    │        └──▶ For each ExpandedEvent:
    │             compute timing offset → call generate_*()
    │             (recursion guard: _expanding flag prevents re-expansion)
    │
    └──▶ Build SecurityEvent → dispatch
```

**Key components:**
- `ExpansionRule` (ABC) — `matches(event_type, ctx) → bool` + `expand(event_type, ctx) → list[ExpandedEvent]`
- `ExpansionContext` — carries event params + engine state (DNS cache, Kerberos cache, SID registry, skip_types)
- `TimingSpec` — `(min_ms, max_ms, position: "before"|"after")` sampled from
  `config/activity/timing_profiles.yaml` for realistic inter-event timing
- `CausalExpansionEngine` — evaluates all matching rules, sorts by timing (before-events first), returns ordered list

The timing profile file is overlay-aware. Causal prerequisites, source latency,
teardown margins, and Windows/Sysmon same-timestamp collision spacing are data-driven
so tuning can happen at the relationship class without hardcoding one global delay.

**Currently registered rules:**

| Rule | Trigger | Emits | Timing |
|------|---------|-------|--------|
| `DnsBeforeConnection` | TCP connection (not port 53) | DNS query (UDP/53) | `network.dns_before_tcp` timing profile |
| `KerberosBeforeLogon` | Kerberos-auth Windows logon (not on DC) | TGT (4768) + TGS (4769) | `auth.kerberos_before_logon` timing profile; elevated-session 4672 remains tied to the target-host 4624 |
| `ProcessAccessAfterRemoteThread` | CreateRemoteThread targeting lsass | ProcessAccess (Sysmon 10) before the remote thread | `process.remote_thread_lsass_access` timing profile |
| `SupplementaryAuditEvents` | Process creation with admin commands | 4720/4726/4728/4697/4698/1102 | `windows.audit_from_admin_command` timing profile |

**Adding a new rule:** Create a new `ExpansionRule` subclass in `rules.py`, implement `matches()` and `expand()`, and add it to `default_rules()` in `registry.py`. The engine auto-creates with defaults — no wiring needed in ActivityGenerator or GenerationEngine.

**Recursion prevention:** The `_expanding` flag on ActivityGenerator prevents expansion-generated events from re-expanding (e.g., DNS query → connection → DNS query → ∞).

### Baseline Realism

The baseline generation engine includes several layers of realism beyond simple random event emission:

**Hawkes self-exciting temporal model:** User baseline events are distributed using a Hawkes process (`src/evidenceforge/utils/timing.py:hawkes_timestamps()`) — a self-exciting point process where each event temporarily increases the probability of more events nearby. Parameters are derived from persona `risk_profile` (not hardcoded per persona name), so new personas work automatically. Cross-hour state continuity prevents artificial gaps at hour boundaries. System/service traffic uses `periodic_timestamps()` with deterministic phase + jitter instead.

**Storyline typing cadence:** Multi-event storyline steps space events with human typing rhythm (`typing_cadence()`) — Gaussian inter-action delays (~1.5s mean) with 15% chance of thinking pauses (3-12s). Single-event steps are unaffected.

**Day-of-week variation:** Activity multipliers scale by weekday (Monday 1.15x login storms → Friday 0.85x early departures → Saturday/Sunday 0.05-0.08x near-zero). Non-IT personas are skipped entirely on weekends; only sysadmin, security_analyst, and help_desk remain active.

**Stale account enrichment:** Disabled accounts generate four types of evidence: failed network logons (15%/hour), Kerberos pre-auth failures on DC (5%/hour, status 0x12 KDC_ERR_CLIENT_REVOKED), scheduled task failures with batch logon (3%/hour), and service startup failures at scenario start (2%, first hour only).

**Legitimate lateral movement:** 26 patterns of inter-server traffic are auto-generated based on environment topology — backup agents, monitoring, AD replication, app-to-database connections, config management, etc. Patterns are conditional on the infrastructure (file servers, DCs, Linux hosts) and gated by time-of-day (app traffic peaks during business hours, backup traffic peaks overnight).

**Network-level red herrings:** Three suspicious-but-benign network patterns supplement the existing host-level red herrings: high-entropy DNS queries to CDNs/DoH providers, unusual outbound connections to dev tools/cloud regions/backup sync, and scheduled vulnerability scan bursts.

**Entity lifecycle validation:** StateManager tracks per-system boot times and validates that process injection events (Sysmon 8/10) target existing PIDs. Warnings are logged for impossible sequences without blocking generation.

**DNS before baseline connections:** System traffic TCP connections (SMB, Kerberos, LDAP, database) emit DNS queries via the causal expansion engine before each connection, with per-host DNS caching (TTL 60-600s) preventing duplicate queries. ~2% of connections are intentionally direct-IP to simulate hardcoded infrastructure configs. Scenario system IP→FQDN mappings are registered at setup time so DNS queries resolve to correct hostnames. All domain↔IP data lives in a single `dns_registry.yaml` (source of truth). The loader (`dns_registry.py`) builds REVERSE_DNS, FORWARD_DNS, and tag-based lookups. All external connections use domain-first selection via `pick_domain_and_ip()` — hostname is resolved once at the top of `generate_connection()` and shared by causal DNS expansion, SSL SNI, and proxy rendering. Background HTTPS traffic (Windows Update, Ubuntu packages, CRL checks) uses tag-based selection from the same registry. Storyline connections to raw C2 IPs skip DNS emission (realistic for direct-IP C2 beaconing).

**Per-system session management:** `WorldPlanner` checks for active sessions on the specific target system before generating processes. If no session exists, it bootstraps a context-aware session (interactive for a user's primary workstation, network for remote process execution, SSH for Linux admin access, RDP for Windows remote admin). This prevents processes appearing on systems where the user has no corresponding logon/session evidence and keeps session ownership consistent across baseline and storyline paths.

**Process→network correlation:** Baseline process creation triggers correlated network connections when the executable normally generates traffic (browsers→HTTPS, Office→cloud, DB clients→SQL, dev tools→registries). 60% emission probability with process PID carried for eCAR FLOW correlation.

**Linux syslog depth:** Linux hosts generate 18 categories of syslog messages including SSH login/key exchange (70% key / 30% password), package management (apt-daily / dnf-automatic), systemd timer execution, logrotate file detail, and journald statistics — alongside existing systemd lifecycle, cron, UFW, logind, snapd, NTP, and other daemon messages.

**Centralized image path resolution:** `resolve_image_path(exe_basename, os_category)` in `application_catalog.py` is the single source of truth for bare-name → full-path resolution. All fallback code paths (parent chain creation, connection process creation, Sysmon rendering) call this instead of hardcoding System32. The function checks the application catalog first (user apps → Program Files/AppData), then a curated set of known system binaries (→ System32), and only uses System32 as a last resort for truly unknown executables.

**Persona-aware application filtering:** The application catalog enforces role-appropriate software distribution. Each app declares which personas may use it (e.g., kubectl → `[developer, sysadmin]`). The legacy `PROCESS_TEMPLATES` fallback is restricted to `process_system` only — user app/code/build/query categories always go through the persona-filtered catalog path.

**Bidirectional traffic profiles:** Role-based traffic profiles in `traffic_profiles.yaml` define both `outbound` (connections the host initiates) and `inbound` (connections the host receives). The `role` field names the other end of the connection in both directions. Inbound traffic flows through the same visibility engine and firewall policy evaluation as outbound — DMZ hosts receive external HTTPS traffic while internal servers only receive connections from other internal roles. The unified `_resolve_role()` method handles both directions, resolving role names to concrete IPs while excluding the local host.

**Command pool diversification:** Process templates use `{placeholder}` syntax across all categories (not just queries). Parameterized values include project paths, solution names, document names, build configs, Git branches, and internal URLs. `{username}` substitution provides per-user path affinity.

**Rule-based process trees:** Parent-child relationships are defined in `src/evidenceforge/generation/activity/spawn_rules.yaml` — a data-driven mapping of which processes can spawn which children, with command-line templates, lifetime metadata (long/short), and spawn delay ranges. The `_resolve_parent()` method on ActivityGenerator transparently finds an existing valid parent from the user's process history or auto-creates intermediate chains (e.g., explorer→powershell→dotnet.exe) with realistic backward timing. Long-lived parents created early in the scenario (first 30 minutes) have a 70% chance of being registered as pre-existing (no Sysmon Event 1 emitted). Depth is limited to 3 auto-created levels. Falls back to legacy `_select_parent_pid()` for processes not in the rules. `ProcessContext.parent_command_line` is populated from the parent process's StateManager entry.

**PID allocation diversity:** PIDs use a lognormal distribution for gap sizes (Windows: `lognormvariate(1.2, 0.8)` in multiples of 4; Linux: `lognormvariate(0.5, 0.6)`), producing a heavy-tailed gap distribution with no fixed-set fingerprint. Wraparound at 65536 skips PIDs still held by running processes.

**Per-user bash history:** Baseline SSH sessions to Linux servers generate organic admin commands for realistic admin users, creating per-user `<username>.bash_history` files on all Linux hosts. Storyline process events inject 0-3 organic noise commands (pwd, ls, id, w, df -h, etc.) around each attack command via `generate_bash_command_with_noise()`.

### Key Patterns

**Thread-local RNG:** Each generation thread gets a `random.Random` instance seeded by `hash((thread_id, 42))`. This ensures reproducibility while enabling concurrent generation without GIL contention. LogonID generation uses per-host RNG seeding (`_stable_seed(f"logon_ids_{hostname}")`) to ensure unique LogonID sequences per system.

**Discriminated unions:** Storyline event specs use Pydantic discriminated unions — `type: "process"` selects `ProcessEventSpec`, `type: "logon"` selects `LogonEventSpec`, etc. This provides compile-time-like type safety for YAML input.

**Format groups:** The scenario declares `"zeek"` → the engine expands it to 13 individual emitters. Sensors reference format groups, not individual formats.

**Windows EventRecordID ordering:** Events are buffered as raw dicts, sorted by timestamp on flush, then assigned sequential EventRecordIDs. This matches real Windows behavior where RecordID always increases monotonically with time.
