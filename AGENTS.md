# AGENTS.md - EvidenceForge

This document provides AI coding agents with everything needed to write consistent, idiomatic code for the EvidenceForge project.

## Project Overview

EvidenceForge generates realistic synthetic security logs for cybersecurity threat hunting training and research. The system uses a two-phase hybrid architecture:

**Phase 1 - Scenario Creation (Skill-assisted):** Claude Code Skills guide users through scenario creation via structured interviews. Skills research TTPs via MITRE ATT&CK, expand high-level descriptions into detailed execution plans, and output structured YAML scenario files with companion research markdown.

**Phase 2 - Log Generation (Deterministic):** Generation engine executes the detailed scenario plan WITHOUT any LLM calls, producing large-scale, temporally consistent datasets across multiple log formats (Windows Event Logs, Zeek, Syslog, Snort/Suricata, web logs) with coordinated cross-references (matching LogonIDs, PIDs, session data).

This architecture combines LLM flexibility/realism with deterministic speed, cost-efficiency, and reproducibility.

**Key Principle:** The `eforge` CLI is a deterministic tool. Creative/interactive work happens through Claude Code Skills, not built-in LLM calls. Phase 2 is a deterministic renderer that executes the plan. Never call LLMs during generation. LLM integration is not built-in; scenario creation uses Claude Code Skills.

**Storyline Events (Phase 8.4):** Storyline entries use typed `events` lists, not free-text keyword matching. Each event has a `type` field (`process`, `logon`, `connection`, `ssh_session`, etc.) with per-type validated fields. The `activity` field is documentation only (for GROUND_TRUTH.md). See `docs/reference/scenario-reference.md` for the full event type reference.

**Baseline Realism:** The baseline engine includes: Hawkes self-exciting temporal model for bursty user activity (parameters derived from persona risk_profile), periodic+jitter timing for system/service traffic, day-of-week variation (Monday login storms, weekend near-zero), 26 legitimate lateral movement patterns (backup, monitoring, AD replication, app→DB, etc.), process→network correlation (browsers→HTTPS, DB clients→SQL, etc.), enriched stale account noise (Kerberos failures, lingering tasks, service startup failures), network-level red herrings (suspicious DNS, unusual outbound, scan overlaps), Linux syslog depth (18 categories including SSH login/key exchange, apt/dnf, systemd timers, logrotate, journald), diversified command pools with per-user parameterization, and entity lifecycle validation (boot time tracking, PID existence checks). Lateral movement patterns are conditional on environment topology — assign `roles` to systems to enable specific patterns.

**Causal Expansion Engine:** The `CausalExpansionEngine` (`src/evidenceforge/generation/causal/`) auto-generates prerequisite and consequent events via composable rules. DNS lookups before TCP connections, Kerberos/DC-bundle TGT/TGS evidence before domain logons, ProcessAccess after lsass injection, and supplementary audit events from command-line patterns are all handled automatically — scenario authors should NOT manually specify these as prerequisites. Authors CAN still specify these event types when they are part of the attack narrative itself (e.g., DNS tunneling, golden ticket forging). The validator warns on potentially redundant manual specifications. See `docs/ARCHITECTURE.md` § Causal Expansion Engine for implementation details.

## MANDATORY: Implementation State Tracking

**CRITICAL: Read this section first before doing ANY work on this project.**

This project uses `TODO.md` as the **persistent implementation plan and progress tracker**. This is NOT optional.

### Required Workflow for Every Session

1. **START OF SESSION (BEFORE ANY WORK):**
   - **ALWAYS read `TODO.md` first** to understand:
     - What phase/milestone the project is in
     - What's been completed
     - What's in progress
     - What's next to work on
   - If `TODO.md` doesn't exist, create it with the initial implementation plan based on the PRD

2. **BEFORE STARTING ANY TASK:**
   - Update the task status to `- [ ] **IN PROGRESS**` in `TODO.md`
   - This marks your claim on the work and provides visibility

3. **WHEN COMPLETING TASKS:**
   - **IMMEDIATELY** update `TODO.md` to mark the task as `- [x]` completed
   - Do NOT batch updates - update as soon as each item is done
   - Add notes if the implementation deviated from the plan

4. **WHEN ADDING NEW TASKS:**
   - Add them to `TODO.md` in the appropriate phase/section
   - Use `- [ ]` for pending tasks

### Changelog Workflow

When a phase is fully complete, collapse its tasks in `TODO.md` to a 2-3 line summary and move the detailed task history to `CHANGELOG.md`. This keeps `TODO.md` focused on active/future work while preserving the full development record.

## Tech Stack

**Core:**
- Python 3.11+ (required for latest type hint features including `Self`, `TypedDict` improvements)
- uv for package management, virtual environments, and script running
- Pydantic v2 for all data validation and schema management

**CLI & Output:**
- Typer for CLI framework (excellent Pydantic integration)
- Rich for progress bars, tables, and console formatting
- Jinja2 for log format templates
- PyYAML for configuration/scenario parsing
- pytz for timezone handling (UTC internal, configurable output)

**Testing:**
- pytest with pytest-cov, pytest-asyncio, pytest-mock, pytest-benchmark
- Default test runs should avoid coverage instrumentation: use `uv run pytest --no-cov`
  for normal local and feature-PR validation. Coverage is a release/readiness
  gate before `dev` → `main`, run explicitly with
  `uv run pytest --cov=evidenceforge --cov-report=term-missing --cov-report=xml --cov-fail-under=70`.
- Separate test markers: `@pytest.mark.slow` for large dataset/workload tests (not run by default). Run slow tests with `--no-cov` unless you are specifically profiling coverage behavior, because coverage instrumentation makes the generator workload much slower.
- Target coverage: 95%+ overall, 95%+ for core generation engine

**Format Support:**
- json-logic-qubit for format definition validation rules
- Standard library json/csv for text formats
- XML output via string templates (no python-evtx dependency)

## Dependency Management

Use `uv` for all dependency management (never `pip`). `pyproject.toml` is the source of truth.

## Code Style & Standards

### General Principles
- **Type hints everywhere** — all functions, methods, and variables must have type hints
- **Pydantic for data** — use Pydantic models for any structured data (configs, scenarios, API responses)
- **Explicit over implicit** — prefer clarity over cleverness
- **Fail fast** — validate inputs early, fail with clear error messages
- **No magic** — avoid metaclasses, dynamic imports, or other "clever" patterns unless absolutely necessary

### Commits
- **Conventional Commits** — prefix every commit message with a type: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`. See [CONTRIBUTING.md](/CONTRIBUTING.md#commit-messages) for details and examples.

### Versioning (Semantic Versioning)

The version is declared in three places that must always match:
- `pyproject.toml` → `version = "X.Y.Z"`
- `src/evidenceforge/__init__.py` → `__version__ = "X.Y.Z"`
- `uv.lock` → updated automatically by `uv sync` after editing `pyproject.toml`

**Bump rules (pre-1.0: breaking changes are allowed in MINOR bumps):**

| Commit type(s) on branch | Bump |
|--------------------------|------|
| Any `feat:` commit | MINOR (`0.x+1.0`) |
| Only `fix:` / `docs:` / `test:` / `refactor:` / `chore:` | PATCH (`0.x.y+1`) |

**When to bump:** Once per PR from `dev` to `main`, on the `dev` branch, as the last commit before opening that PR. Do not bump on feature branches or per-commit.

**How:** Before running `gh pr create` targeting `main`, inspect `git log main..dev --oneline`, determine the correct bump, update both version files, run `uv sync` to regenerate `uv.lock`, and commit all four (three version artifacts + CHANGELOG.md, see below) with:
```
chore: bump version to X.Y.Z
```

**Changelog update (required with every version bump):** as part of the same bump commit, prepend a new `## vX.Y.Z (YYYY-MM-DD)` section to `CHANGELOG.md` summarizing every commit since the previous version entry. Drive the summary from `git log main..dev --oneline` (or `git log vPREV..HEAD --oneline` if tagged). Group related commits into themed subsections (e.g., "Explicit proxy path modeling", "TLS & X.509 realism", "CLI & config"), cite the short SHAs inline in parentheses, and skip pure merge commits and unrelated dependabot bumps. Version-bump-only releases (no code changes) still get an entry noting that. The changelog entry and the version bump land in the same commit.

The version on `dev` between releases will be ahead of `main` by one unreleased bump — this is expected and correct. Feature branches never touch the version.

### Linting
- **Before committing:** always run `uv run ruff check .` and `uv run ruff format --check .` and fix any errors. A `pre-commit` hook enforces this, but verify manually when in doubt.
- Ruff configuration is in `pyproject.toml` — do not add `# noqa` comments without justification.

### Formatting
- Line length: 100 characters
- Indentation: 4 spaces
- Double quotes for strings (except to avoid escaping)
- Import order: stdlib, third-party, local (enforced by ruff's `I` rules)

### Type Hints
- Use modern Python 3.11+ built-in types: `list[User]`, `dict[int, str]` — not `typing.List`, `typing.Dict`
- Use `X | None` — not `Optional[X]`
- Always include return types on function signatures
- Annotate variables when the type isn't obvious from the assignment

### Docstrings
- Google-style docstrings for public functions/classes. Test functions: name is the doc.

### Error Handling
- Define specific custom exceptions inheriting from `EvidenceForgeError` base
- Place exceptions in appropriate modules (`models/scenario.py`, `generation/engine.py`, `validation/schema.py`)
- Provide actionable error messages: say what's wrong and how to fix it
- Never catch bare `Exception` — always use specific types

### Logging
- Use `logging.getLogger(__name__)` in every module
- Use `%s` formatting, not f-strings (lazy evaluation)
- Console output: `warning` and `error` only (configurable via `logging.console_level`)
- File output: all levels based on `logging.level` config (default: `info`); file location: `{output_dir}/generation.log`
- Never log secrets, credentials, or full exception tracebacks to users
- Log retries at DEBUG, final failure at ERROR, progress milestones at INFO

### Pydantic Models
- Use `Field()` for descriptions and constraints
- Use `field_validator` for complex validation
- Set `extra="forbid"` to catch typos/unknown fields
- Use `frozen=True` for immutable configs
- Provide clear error messages in validators

### Path Handling
- Always use `pathlib.Path`, never string paths. Resolve paths early at boundaries.

## Generation Realism Patterns

These rules prevent the recurring anti-patterns that make generated data look synthetic. Apply them to ALL generation code — engine, emitters, baseline, storyline.

### 1. Compute once, use everywhere
Derived values (hostname, hash, domain) must be computed **once** and attached to the SecurityEvent. Emitters must **never** independently derive shared values via `REVERSE_DNS`, `hashlib`, or RNG. If two log formats need the same value (e.g., DNS query domain = SSL SNI = proxy hostname), it must come from a single source on the event object.

**Anti-pattern:** Each emitter does its own `REVERSE_DNS.get(dst_ip)` → produces inconsistent results.
**Correct:** Resolve hostname once in `generate_connection()`, pass to all downstream consumers.

### 1a. Fix root causes at the owning layer
When generated output is wrong, fix the root cause where that truth is owned. Do not patch symptoms in one emitter when the bad value, timing, routing, or correlation was created upstream. Prefer canonical context, state, planner, generation, routing/visibility, or data-config fixes over emitter patches when the issue involves shared event truth, actor/session/process ownership, timing, correlation IDs, source/destination semantics, or cross-source evidence. Do not force every fix into context objects: bad event ordering belongs in planner/generator timing, bad host visibility belongs in routing/visibility, bad enumerables belong in YAML config + loaders/validation, and bad source-native formatting belongs in emitters/templates.

**Anti-pattern:** A Windows emitter rewrites a bad LogonID or source IP just before rendering.
**Correct:** The planner/generator builds the right `AuthContext`/state relationship, and the emitter renders the source-native view of that already-correct event.

### 1b. Add correlated sources through canonical events
When adding a new correlated log source or expanding an existing one, target the canonical event/context/state layer first, then add the emitter as a source-native renderer. New integrations should reuse or extend `SecurityEvent` contexts, state relationships, causal/timing rules, visibility/routing rules, and data-driven config so the new source agrees with existing evidence by construction. Avoid private low-level emitter pipelines for evidence that must correlate with auth, process, network, file, registry, DNS, proxy, firewall, IDS, or other shared activity. Direct emitter-only generation is acceptable for purely source-local health/status noise, source-specific rendering details, or explicit raw escape hatches that do not need cross-source correlation.

**Anti-pattern:** A new EDR-like source independently invents process IDs, parent images, hashes, and connection tuples inside its emitter.
**Correct:** The source renders existing `ProcessContext`, `NetworkContext`, `FileContext`, state IDs, and causal relationships, adding new canonical context fields only when the source needs facts that no existing context owns.

### 2. Data-driven, not code-driven
Enumerable pools (domains, processes, user agents, file paths, OUI prefixes, TLS issuers) belong in **YAML files** under `src/evidenceforge/config/` with cached loaders, not hardcoded Python lists. Follow the existing pattern:
- `src/evidenceforge/config/activity/spawn_rules.yaml` + `generation/activity/spawn_rules.py`
- `src/evidenceforge/config/activity/bash_commands.yaml` + `generation/activity/bash_commands.py`
- `src/evidenceforge/config/activity/tls_issuers.yaml` + `generation/activity/tls_issuers.py`
- `src/evidenceforge/config/activity/network_params.yaml`

**Anti-pattern:** `_ISSUERS = ["CN=R3, O=Let's Encrypt...", ...]` hardcoded in generator.py.
**Correct:** Load from YAML at module level, cache after first call. Use `from evidenceforge.config import get_activity_directory` for paths.

### 3. OS-aware defaults
Every function returning a fallback/default value must check `os_category`. Grep for hardcoded Windows paths (`C:\\`, `explorer.exe`, `svchost.exe`) outside explicitly Windows-only code blocks — each one is a potential Linux data corruption.

**Anti-pattern:** `return r"C:\Windows\explorer.exe"` without checking OS.
**Correct:** `return "/usr/bin/bash" if os_category == "linux" else r"C:\Windows\explorer.exe"`

### 4. Lifecycle completeness
Every event type that creates state must have a corresponding termination event with realistic timing:
- `logon` → paired `logoff` (immediate for type 3, end-of-day for type 2/10)
- `process_create` → `process_terminate`
- `dhcp_lease` (DISCOVER) → periodic renewals (REQUEST/ACK at T/2)
- `connection` → duration + close

**Anti-pattern:** `generate_machine_account_logon()` creates type 3 session but never generates 4634 logoff.
**Correct:** Emit paired logoff 1-30 seconds after type 3 logon.

### 5. No uniform distributions
Any generation loop must use randomized counts, probabilistic skipping, and per-entity jitter. Fixed counts, fixed intervals, and uniform iteration are tells that reveal synthetic generation.

**Anti-pattern:** `for slot_base in [0, 900, 1800, 2700]:` → exactly 4 events/hour on every host.
**Correct:** `num_tasks = rng.randint(2, 5); slots = sorted(rng.sample(range(0, 3600, 300), num_tasks))`

### 6. Deterministic but scoped
Use `_stable_seed(f"context_{scope_key}")` for all deterministic derivation. **Never** use:
- Python's `hash()` — non-deterministic across processes (PYTHONHASHSEED)
- Globally-seeded `random.Random(42)` — produces identical sequences for different entities

**Anti-pattern:** `hash(f"mac_{system.ip}")` for MAC generation; `Random(42)` for LogonIDs.
**Correct:** `_stable_seed(f"mac_{system.ip}")` for MAC; per-host RNG `Random(_stable_seed(f"logon_ids_{hostname}"))`.

## Key Architecture Patterns

### World Model Planning

`WorldModel` / `WorldPlanner` (`src/evidenceforge/generation/world_model.py`) sit above the canonical event model and compile environment intent into operational decisions:

- `WorldModel` resolves canonical host/user capabilities once from scenario fields such as `user.primary_system`, `system.assigned_user`, `system.roles`, and `system.services`
- `WorldPlanner` owns session bootstrap semantics (interactive, network, SSH, RDP) and may allocate session state in `StateManager` before `ActivityGenerator` emits the correlated host/network evidence
- Baseline and storyline code should call this layer for persona placement, remote admin source selection, and shared session bootstrap instead of re-implementing heuristics locally

### Action Bundles, SecurityEvents, and Contexts

Action bundles represent real-world activities that can produce multiple pieces of
evidence. They sit above `SecurityEvent` and are the preferred home for
cross-event lifecycle, timing, observation, and durable identity ownership.

A `SecurityEvent` represents one logical evidence-producing occurrence. It may
carry multiple contexts when those contexts describe facets of that same
occurrence and need to share truth. Contexts are not mini-event queues. Do not
cram a multi-phase activity into one `SecurityEvent` just because a context exists.
If an activity has distinct lifecycle phases (connection, auth accepted, session
opened, process created, command executed, session closed), model those as
distinct `SecurityEvent`s coordinated by an action bundle.

Use action bundles for correlated behavior families across storyline, baseline,
red herrings, and scanners. The source of intent may differ, but evidence
construction should share the same bundle/lifecycle/timing path.

For SSH specifically, modeled sessions from typed storyline events, baseline
remote-admin noise, and `scp` transfers to modeled Linux receivers should route
through the SSH action bundle. Keep transfer-specific receiver artifacts (for
example, target-side file creation) separate from the bundle only after the
bundle has owned SSH transport/auth/session timing. When source ports are
allocated during execution, use the resolved execution anchor rather than the
pre-reservation intent anchor for tuple-specific identity.

For RDP specifically, modeled remote interactive Windows sessions should route
through the RDP action bundle. The bundle owns the source-side RDP client process
when a modeled source host is available, the TCP/3389 transport, target Type 10
logon/session metadata, source-port reuse, and temporal ordering between
source-visible transport evidence and target authentication evidence. Do not
emit independent port 3389 connections or Type 10 logons for the same modeled RDP
session outside the bundle.

For Windows remote administration specifically, explicit credential use and
remote service installation should route through the Windows remote-admin action
bundles. The bundles own 4648 subject/caller-process alignment, source endpoint
semantics, source-visible caller timing, service-control transport, dropped
service-binary evidence, and target service-install records. Keep tool-specific
authoring (`runas`, `PsExec`, `wmic`, `schtasks`) in scenario/storyline layers;
the generated evidence semantics belong in the bundle path.

For explicit forward proxy traffic, logical client-to-origin HTTP/HTTPS requests
from hosts with explicit proxy routes should route through the proxy transaction
action bundle. The bundle owns client-to-proxy evidence, proxy access semantics,
tunnel reuse, cache/deny terminal behavior, proxy-origin DNS, proxy-to-origin
egress, and the timing relationship between source-visible proxy requests and
origin-side activity. Keep proxy format rendering in emitters and proxy route
selection in planning/config layers.

For canonical network connections, route connection orchestration through the
network-connection action bundle. The bundle owns the boundary for source and
destination semantics, source-port allocation, DNS/TLS/HTTP/file/proxy/firewall
metadata, IDS/EDR flow correlation, source endpoint process ownership, Zeek UID
and connection state identity, visibility handoff, and source-native timing.
Higher-level bundles may request connections through the public generator
entrypoint, but they should not duplicate tuple allocation, hostname resolution,
packet accounting, or endpoint-flow ownership locally.

For DHCP leases, route acquisition and renewal transactions through the DHCP
lease action bundle. The bundle owns lease identity, MAC/IP/server/domain
metadata, Zeek DHCP plus connection fan-out, link-local visibility semantics,
and Linux `dhclient` syslog companion ordering. Do not hand-roll separate DHCP
syslog or Zeek rows for the same lease transaction outside the bundle.

For automatic DNS lookups, route prerequisite resolver evidence through the DNS
lookup action bundle. The bundle owns resolver selection, cache behavior,
query/answer semantics, TTL observations, Zeek DNS plus UDP/53 connection
fan-out, Sysmon DNS visibility, AD SRV discovery companions, and low-volume
resolver companion questions. Storyline `dns_query`, `dga_queries`, and
`dns_tunnel` events may still model DNS as the attack narrative, but connection
prerequisite DNS should not be duplicated at call sites.

For browser-like HTTP/S sessions, page loads and their subresources should route
through the browser-session action bundle. The bundle owns request grouping,
transaction depth, referrer chains, page/subresource timing, static-asset cache
suppression, response metadata, and direct-vs-explicit-proxy handoff through
canonical connection generation. Single tool requests, raw storyline HTTP
events, and source-local web server noise may remain direct canonical events
unless they model a browser session.

For scanner/probe activity, typed `port_scan` and `web_scan` storyline events,
scheduled scanner-overlap suspicious noise, and nmap process side effects should
route through scanner/probe action bundles. The bundles own bulk target/request
expansion, scanner timing, per-probe connection profiles, firewall/IDS/HTTP
contexts, source process attribution when present, and ground-truth summaries.
They may still request canonical network connections through the generator; do
not duplicate scanner target fan-out, IDS scanner selection, or nmap transport
side effects at individual call sites.

For IDS alerts, build alert context through the IDS alert action bundle when a
data-driven signature or preset rule is attached to canonical network evidence.
The bundle owns `(gid, sid, rev)` identity, message/classification/priority
normalization, and signature-owned DNS payload construction for DNS alerts.
Emitters should only render `IdsContext`; they should not choose signatures or
invent alert/DNS payloads.

For modeled file transfers, use the file-transfer action bundles for transfer
identity, Zeek files.log metadata, receiver endpoint file evidence, and
source-visible timing. HTTP response bodies, substantial SMB reads/writes,
staged-archive SMB reads, and SCP receiver-side file creation should share the
bundle helpers instead of independently inventing FUIDs, hashes, filenames,
transfer direction, or target process ownership. SSH/RDP/proxy bundles still own
their transport/session semantics; file-transfer bundles own the transfer/file
evidence layered on top.

For Linux shell command execution, route bash-history emission and correlated
foreground process telemetry through the Linux shell-command action bundle. The
bundle owns the command execution sequence: resolve activity keys to concrete
commands, align commands after SSH/session readiness, schedule per-user
bash-history timestamps, emit bash history, and then emit optional process
telemetry through shared adapter hooks. Do not hand-roll separate bash-history
and process timing paths for the same modeled command.

For process execution, route canonical process create/terminate lifecycle and
process-owned side effects through the process-execution action bundle. The
bundle owns the boundary between modeled execution intent and `SecurityEvent`
evidence: session/parent ownership, source-visible create/terminate timing,
command-owned network effects, guaranteed process-image file evidence, and
probabilistic file/module/registry endpoint side effects. Other bundles may call
the public process entrypoints, but they should not duplicate process lifecycle
or side-effect generation locally.

For authentication and session lifecycle, route successful logons, failed
logons, and logoffs through the auth/session action bundles. The bundles own the
boundary for session allocation/reuse, logon IDs, source endpoint semantics,
transport/syslog companions, DC-side validation evidence, failure-network
companions, and session termination ordering. Other bundles may request logon or
logoff evidence, but they should not locally invent duplicate session IDs,
source ports, auth-package fields, or failure companion traffic.

For Kerberos/DC evidence, route domain-logon TGT/TGS companions, visible KDC-flow
audit repair, TGT requests, TGT renewals, service-ticket requests, and
pre-authentication failures through the Kerberos/DC action bundles. The bundles
own DC-side Kerberos source endpoint semantics, source-port reservation, TGT
cache behavior, service-principal identity, source-native ticket timing, and
optional companion KDC network evidence. Do not independently emit 4768, 4769,
4770, or 4771 rows at call sites or patch Kerberos source ports in emitters.

For Windows audit/account-management evidence, route log-cleared,
scheduled-task, account-created/deleted/changed, password reset/change,
group-membership, create-remote-thread, and process-access evidence through the
Windows audit action bundles. The bundles own subject/session ownership, target
identity, source timing, process/thread lifecycle validation, and shared
Sysmon/eCAR context. Do not duplicate 1102, 4698, 472x/4738/475x, Sysmon Event
8, or Sysmon Event 10 construction at storyline/causal call sites or patch
these fields in emitters.

When fixing realism defects:
- Cross-event ordering, lifecycle, source timing, observation, and durable
  identities belong in bundle/lifecycle/timing/observation layers.
- Use the temporal constraint graph for relationships that span multiple
  evidence timestamps or source observations. Local timestamp clamps are still
  acceptable at narrow boundaries, but new family-level timing ownership should
  express preferred times, hard bounds, lifecycle windows, and causal edges in
  the graph so dependent evidence cannot invert.
- Shared facts for one occurrence belong on `SecurityEvent` contexts.
- Emitters render source-native views; they do not invent shared facts or repair
  upstream lifecycle contradictions.

### Canonical Event Model

The generation engine uses a canonical event model — an intermediate representation between activity generation and log rendering. ActivityGenerator builds `SecurityEvent` objects carrying composable context dataclasses (`HostContext`, `AuthContext`, `ProcessContext`, `NetworkContext`, `DnsContext`, `FileContext`, `RegistryContext`, `IdsContext`, `SyslogContext`). An `EventDispatcher` routes each event to `StateManager.apply()` and to matching emitters based on `can_handle()` and network visibility.

**Core principle: consistency by construction, not by coordination.** Two emitters cannot disagree about a port number because there is only one port number — on the event object.

**Two-phase build + dispatch:** (1) Allocate IDs from StateManager in the responsible planning/generation layer (`WorldPlanner` for planner-owned sessions, `ActivityGenerator` for processes/connections and direct logons), (2) build a complete `SecurityEvent` with those IDs, (3) dispatch to emitters. `StateManager.apply()` records state from a fully-constructed event — it does NOT allocate IDs. `RawLogEntry` exists solely for the user-facing `raw` event type in scenario YAML. All internal engine code uses canonical SecurityEvent dispatch exclusively — including baseline IDS alerts, web access, syslog daemon messages, DHCP leases, anomaly records, anonymous logons, and sensor startup.

Full design details: `docs/design/event-model-prd.md`. Key types: `src/evidenceforge/events/`.

### State Management

`StateManager` (`src/evidenceforge/generation/state_manager.py`) is the single source of truth for runtime state:
- **Planning/generation layers write state** — `WorldPlanner` may allocate/register sessions; `ActivityGenerator` allocates processes/connections and may emit against preallocated sessions
- **Emitters only read state** — to get LogonIDs, PIDs for rendered events; never mutate StateManager
- **`apply(event)`** records state from a fully-constructed SecurityEvent — handles teardown (logoff, process termination) and updates (connection bytes); does NOT allocate IDs
- Events are transient (GC'd after dispatch); StateManager owns durable state
- Thread-safe for reads, single-threaded for writes

### Log Emitters

All emitters inherit from `LogEmitter` ABC (`src/evidenceforge/generation/emitters/base.py`):
- Each emitter declares `_supported_types` and implements `can_handle(event)` for dispatcher self-selection
- `emit()` receives `SecurityEvent` objects, builds a field dict via `_render_{event_type}()`, passes to Jinja2 template
- `emit_raw()` is the escape hatch for `RawLogEntry`
- Buffer writes (10K events), use atomic flush, always flush on close
- Handle timezone conversion (UTC → system/format timezone)
- OS-specific emitters check `event.host.os_category` in `can_handle()`
- Each emitter runs in separate thread, writes to separate file

### Format Definitions

Format definitions are YAML files in `src/evidenceforge/config/formats/`, not code. Each defines fields, variants, JSON Logic validators, and Jinja2 output templates. Loaded via `formats/loader.py`. Adding a new format requires only a new YAML file.

### YAML Data Directory Convention

All YAML lookup/reference data lives in `src/evidenceforge/config/` with subdirectories:
- `config/formats/` — format definitions (field schemas, validators, templates)
- `config/evaluation/` — evaluation rules (causal pairs, co-occurrence, distributions)
- `config/activity/` — activity generation data (DNS registry, spawn rules, TLS issuers, etc.)
- `config/personas/` — pre-built persona definitions

**Rule:** When adding new YAML data files, place them in the appropriate `config/` subdirectory. Never scatter YAML data files alongside Python code. Loader modules import path helpers from `evidenceforge.config` and handle caching/validation in their own domain.

**Pattern for new data files:**
1. Add the YAML file to the appropriate `config/` subdirectory
2. Create or update a loader in the relevant domain module
3. Use `from evidenceforge.config import get_{category}_directory` for path resolution
4. Follow the cached-loader pattern (module-level `_CACHED_DATA`, load-on-first-call)

### Timezone Handling
- Store all datetimes in UTC internally (`datetime.timezone.utc`)
- Convert to output timezone only when rendering logs
- Support per-system timezone overrides with pattern matching
- Default timezone from `environment.timezone.default`

### Event & Schema Change Checklist

When adding or significantly modifying event types, emitters, or the event schema, update ALL of the following:

1. **Documentation** — `docs/reference/EVIDENCE_FORMATS.md`, `docs/reference/scenario-reference.md`, `README.md`
2. **Architecture & design docs** — `docs/ARCHITECTURE.md` (emitter tree, event type list, causal expansion rules), `docs/design/event-model-prd.md` (supported types tables)
3. **Skills** — `commands/eforge/scenario.md` (event type list + examples), other skills as relevant
4. **Validation** — `src/evidenceforge/validation/schema.py` (event type sets, OS-gating, expansion redundancy)
5. **Evaluation** — `src/evidenceforge/evaluation/dimensions/` (signal_integrity, noise_realism), `src/evidenceforge/evaluation/rules/` (co_occurrence.yaml, causal_pairs.yaml)
6. **Causal expansion** — `src/evidenceforge/generation/causal/rules.py` (if the new event type needs auto-generated prerequisites), `src/evidenceforge/generation/causal/registry.py` (register new rules)
7. **Coverage test prompt** — `scenarios/COVERAGE-TEST-PROMPT.md` (event type count, storyline steps, format-specific verification sections)

## CLI Design Patterns

- Use Typer with `Annotated` type hints for all options/arguments
- Use Rich for progress bars (SpinnerColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn)
- Handle `KeyboardInterrupt` → exit code 130

**Exit codes (per PRD spec):**

| Code | Category | Description |
|------|----------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | Input Error | Malformed YAML or file I/O error |
| 2 | Schema Validation | Pydantic validation failure |
| 21 | Generation Error | Invalid state or unrecoverable generation failure |
| 22 | Format Error | Format definition loading/validation error |
| 130 | SIGINT | User interrupted (Ctrl+C) |

## Testing Requirements

**Organization:** `tests/unit/` (fast, no I/O), `tests/integration/` (file I/O OK), `tests/fixtures/` (shared data)

**Coverage targets:** 95%+ overall, 95%+ core engine, 90%+ formats, 85%+ CLI. Exclude: `__main__.py`, type stubs, test fixtures.

**Default validation:** run `uv run pytest --no-cov` for normal development and
feature PRs. Run the explicit coverage command only for release readiness before
opening or updating a `dev` → `main` PR.

**Conventions:**
- Test naming: `test_<function>_<scenario>_<expected_result>`
- Use Arrange/Act/Assert pattern
- Use `tmp_path` for all file I/O in tests
- No LLM calls during generation — all tests are deterministic
- Write deterministic tests: seed randomness, mock time, use fixed test data
- Use Hypothesis for property-based testing where appropriate (e.g., unique PIDs)
- Never use mutable default arguments

## Skills

Claude Code Skills handle the interactive, creative aspects of scenario creation.

**Location:** `commands/eforge/` directory

**Skills:**
- `/eforge scenario` — Guided scenario creation through a structured interview, producing a validated YAML scenario file
- `/eforge generate` — Generation workflow that validates a scenario and runs the deterministic engine
- `/eforge validate` — Validate a scenario file for schema correctness and cross-reference integrity
- `/eforge evaluate` — Run data quality evaluation on generated output

Skills are markdown prompt files (`.md`), not Python code. They run inside Claude Code, not inside the `eforge` CLI process. They follow a hybrid interview pattern (structured questions first, then free-form refinement) and reference `docs/reference/scenario-reference.md` for schema validity.

**Important:** When modifying the scenario schema (adding/removing/changing fields in Pydantic models or `docs/reference/scenario-reference.md`), always update the corresponding skills in `commands/eforge/` to reflect the changes — especially `scenario.md` (YAML templates and validation rules) and `validate.md` (error handling guidance).

### Adding a New Skill
1. Create `commands/eforge/{name}.md` with the skill prompt
2. Follow the hybrid interview pattern
3. Reference `docs/reference/scenario-reference.md` for output validity
4. Test interactively in Claude Code
5. Update `install-skills` command if needed

## Known Design Decisions (do not flag as bugs)

- **Sysmon Event 22 shows svchost.exe, not the originating process**: Windows DNS Client service (dnscache, hosted by svchost.exe) proxies all application DNS queries via DnsQuery_A()/getaddrinfo(). Real Sysmon Event 22 attributes to svchost.exe — this is correct Windows behavior, not a data loss bug.
- **StrictUndefined removed from Jinja templates**: Intentional (commit 5a4e7db). Templates use `| default(...)` for optional fields. SandboxedEnvironment remains for SSTI protection. Template completeness tests in `test_sysmon_new_events.py` catch variable name typos for required fields.
- **Overwrite swap uses backup-restore transaction**: Staging directory protects against generation failures. The final swap backs up old output, installs new output, and restores the backup on any failure (including KeyboardInterrupt). Old GROUND_TRUTH.md + new data would be semantically invalid, so the swap is all-or-nothing — both files are always kept as a matched pair.

## Reference

**Key docs:**
- Full PRD: `docs/design/PRD.md`
- Event model design: `docs/design/event-model-prd.md`
- Scenario schema: `docs/reference/scenario-reference.md`
- Evidence formats: `docs/reference/EVIDENCE_FORMATS.md`
- Data quality: `docs/design/data-quality-prd.md`
