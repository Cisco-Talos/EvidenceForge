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
          │  Persona-based activity     │
          │  Storyline event execution  │
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────────┐
          │    ActivityGenerator         │
          │  Builds SecurityEvents      │
          │  with composable contexts   │
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
        │ host: LNX-001       │
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

---

## Part 2: Internals (For Contributors)

### SecurityEvent Canonical Model

The `SecurityEvent` dataclass (`src/evidenceforge/events/base.py`) is the central data structure:

```
SecurityEvent
├── timestamp: datetime (UTC)
├── event_type: str ("logon", "process_create", "connection", ...)
├── host: HostContext (hostname, IP, OS, domain, FQDN)
├── auth: AuthContext (logon_id, logon_type, SID, failure codes)
├── process: ProcessContext (pid, parent_pid, image, command_line)
├── network: NetworkContext (src/dst IP/port, protocol, zeek_uid, bytes)
├── dns: DnsContext (query, type, response, TTL)
├── file: FileContext (path, hash, operation)
├── registry: RegistryContext (key, value, operation)
├── ids: IdsContext (signature, severity, classification)
├── syslog: SyslogContext (app_name, message, pid, facility, severity)
├── weird: WeirdContext (name, notice, peer, source)
├── kerberos: KerberosContext (ticket_type, service, encryption)
├── shell: ShellContext (command, exit_code)
├── ... (20+ context types total)
└── _sensor_hostnames_by_format: dict (network visibility metadata)
```

All contexts are `@dataclass(slots=True)` for memory efficiency. They're defined in `src/evidenceforge/events/contexts.py`.

**Key design decisions:**
- Contexts are composable — a logon event has Host + Auth + Syslog contexts; a process event has Host + Process + Syslog contexts
- All fields are optional except `timestamp` and `event_type` — emitters check for the contexts they need
- The syslog emitter renders from SyslogContext (app_name, message, pid, facility, severity). All syslog message construction is done by ActivityGenerator, not the emitter.
- `RawLogEntry` exists solely for the user-facing `raw` event type in scenario YAML. All internal engine code uses canonical SecurityEvent dispatch exclusively

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
└── Current Time       datetime (advances during generation)
```

**ID allocation pattern:**
1. ActivityGenerator calls `state_manager.create_session()` / `create_process()` / `open_connection()` to allocate unique IDs
2. Builds a SecurityEvent with those IDs
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
├── WindowsEventEmitter              # Security.evtx XML, 30 event IDs
├── SysmonEventEmitter               # Sysmon.evtx XML
├── ZeekEmitter                      # conn.log (base for 13 Zeek types)
│   ├── ZeekDnsEmitter               # dns.log
│   ├── ZeekHttpEmitter              # http.log
│   ├── ZeekSslEmitter               # ssl.log
│   └── ... (10 more Zeek types)
├── EcarEmitter                      # eCAR NDJSON (MITRE CAR model)
├── SyslogEmitter                    # Linux syslog (BSD format)
├── BashHistoryEmitter               # Per-user bash history
├── SnortEmitter                     # Snort IDS alerts
├── WebEmitter                       # Apache/Nginx access logs
└── ProxyEmitter                     # HTTP proxy access logs
```

**Sensor multiplexing:** Network emitters (Zeek family) use `SensorMultiplexEmitter` to route output to per-sensor directories. A single ZeekEmitter instance manages output for multiple sensors, each writing to `<sensor_hostname>/conn.json`.

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

The evaluation system (`src/evidenceforge/evaluation/`) scores generated data across 5 dimensions:

```
EvaluationEngine
├── Parsers (17 format parsers)
│   ├── WindowsEventParser (XML)
│   ├── ZeekBaseParser + 13 protocol-specific
│   ├── EcarParser (NDJSON)
│   ├── SyslogParser (regex)
│   └── ... (bash history, snort, web, proxy)
│
├── Dimensions (5 scoring modules)
│   ├── RecordFidelity     (15%) — parsability, co-occurrence, population stats
│   ├── CrossSource        (20%) — source correctness, trace coverage, agreement
│   ├── NoiseRealism       (25%) — volume, diversity, plausibility, anomalies
│   ├── TemporalRealism    (20%) — work hours, burstiness, causal ordering
│   └── SignalIntegrity    (20%) — event presence, accuracy, linkability
│
└── QualityReport
    ├── overall_score: 0-100
    ├── dimension_scores: list[DimensionScore]
    ├── acceptance_criteria: pass/fail
    └── flags: list[str]
```

Causal ordering rules are defined in `evaluation/rules/causal_pairs.yaml`.

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

### Key Patterns

**Thread-local RNG:** Each generation thread gets a `random.Random` instance seeded by `hash((thread_id, 42))`. This ensures reproducibility while enabling concurrent generation without GIL contention.

**Discriminated unions:** Storyline event specs use Pydantic discriminated unions — `type: "process"` selects `ProcessEventSpec`, `type: "logon"` selects `LogonEventSpec`, etc. This provides compile-time-like type safety for YAML input.

**Format groups:** The scenario declares `"zeek"` → the engine expands it to 13 individual emitters. Sensors reference format groups, not individual formats.

**Windows EventRecordID ordering:** Events are buffered as raw dicts, sorted by timestamp on flush, then assigned sequential EventRecordIDs. This matches real Windows behavior where RecordID always increases monotonically with time.
