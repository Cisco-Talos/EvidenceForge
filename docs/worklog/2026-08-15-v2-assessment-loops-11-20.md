# V2 Assessment Loops 11–20

## Loop 11 family contract — immutable Windows process authentication context

- **Owning abstraction:** Windows interactive logon/logoff action-bundle lifecycle plus the
  canonical `RunningProcess` authentication identity retained by `StateManager`.
- **Invariant:** A process termination preserves the username, SID, and LogonID established for
  that process at creation. Per-session `winlogon.exe` remains a SYSTEM/`0x3e7` process through
  teardown; the human LUID remains on session/logoff evidence and human-token children.
- **Entry paths:** baseline and storyline local interactive logons, RDP/Type 10 sessions,
  cached-interactive/Type 11 sessions, and late explorer bootstrap repair.
- **Consumers:** Windows Security 4688/4689, Sysmon process lifecycle, eCAR PROCESS
  CREATE/TERMINATE, session teardown ordering, and rendered auth-context probes.
- **Layer rationale:** process authentication identity is canonical process state, while the logoff
  bundle owns termination membership for a session. Rewriting Security or eCAR fields would only
  hide a state-model defect and would leave sibling sources inconsistent.
- **Sibling risks:** the fix must retain explicit teardown of the cross-auth SYSTEM `winlogon.exe`
  helper for both local and remote interactive sessions without terminating a shared boot process
  or losing child-before-parent ordering. Linux post-authentication enrichment is not changed.

## Loop 11 outcome

- Commit `4c7ea566`; full suite `5,959 passed, 22 skipped`; deterministic evaluation
  97.18870689794775 over 90,553 records with acceptance passed.
- The hard probe found zero Security or eCAR winlogon auth-context/session-ID mismatches. The
  targeted family did not recur in blind review.
- Initial blind synthetic-confidence scores were 91/79/74/32 (average 69.0). Deliberation revised
  the panel to 89/75/79/78 (average 80.25), unanimously Synthetic.
- Next target: durable proxy tunnel lifecycle cardinality, with Linux session-scoped parent
  ownership and source-native IPv6/path rendering immediately behind it.

## Loop 12 family contract — durable explicit-proxy tunnel lifecycle

- **Owning abstraction:** `BrowserSessionActionBundle` owns the planned same-origin HTTP request
  group; `ProxyTransactionActionBundle` owns the physical client-to-proxy CONNECT transport and
  its bounded application reuse state.
- **Invariant:** a successful inspected HTTPS tunnel has one durable CONNECT transport identity
  and may carry zero, one, or multiple request occurrences. The physical transport ledger and
  lifetime reserve the browser group's planned request capacity, while every proxy access row
  retains request-local method, URL, body, status, and byte semantics. Reuse never exceeds the
  reserved bytes, request count, close time, host, destination, or user-agent boundary.
- **Entry paths:** ordinary browser page-load groups, route-profile browser sessions, direct
  explicit-proxy HTTPS requests, authored connections, cache hits, denials, and tool/service
  clients. Only browser-style follow-on transactions with explicit group depth may consume a
  planned reusable tunnel.
- **Consumers:** proxy access CONNECT/request rows and tunnel IDs, the client-side Zeek/ASA/eCAR
  transport tuple, source-port allocation, proxy-origin evidence, HTTP transaction depth, and
  deterministic hard probes over request-count distributions.
- **Layer rationale:** the browser bundle already computes group counts, aggregate bodies, and
  group duration; the proxy bundle is the sole owner of explicit CONNECT transport identity and
  capacity. Emitter-side row grouping or fabricated reuse would not repair the canonical
  transport contract.
- **Sibling risks:** do not double-count large uploads, let aggregate tunnel bytes fall below
  visible child rows, reuse across user agents/hosts/errors, move requests beyond transport close,
  or create a second client transport for a reused request. Preserve setup-only and one-request
  paths alongside multi-request groups.

## Loop 12 outcome

- Commits `07882541` and `c13b8e41`; full suite `5,959 passed, 22 skipped` before the
  regeneration-exposed stale-caller follow-up, then focused proxy/session-bound tests passed.
- Deterministic evaluation remained 97/100 over 78,114 records. The hard probe found 498 inspected
  tunnels with depths 1–12, 358 multi-request tunnels, and zero setup, port, or capacity failures.
- The universal one-request proxy finding did not recur. Initial blind synthetic-confidence was
  63/23/34/87 (average 51.75); deliberation revised it to 68/49/46/72 (average 58.75), a mixed
  result with a synthetic lean.
- Next target: decouple cross-host eCAR FLOW observation milliseconds while retaining canonical
  tuple, actor, interval, and auth ordering. PackageKit singleton/identity and PAT allocation
  texture follow.

## Loop 13 family contract — endpoint-local eCAR FLOW observation clocks

- **Owning abstraction:** `SourceTimingPlanner` owns finalized source-native timestamps and
  identity-safety flags for each outbound and inbound eCAR endpoint observation.
- **Invariant:** paired endpoint FLOW views share canonical tuple/interval truth but render in their
  own host-clock frame with independent deterministic collection texture. Each finalized time stays
  inside the corresponding endpoint-clock-translated transport interval; network-sensor clocks do
  not clamp endpoint telemetry.
- **Entry paths:** all canonical baseline, storyline, scanner, browser, proxy, SSH, RDP, SMB, and
  Windows remote-auth connections that route to two modeled endpoints.
- **Consumers:** per-host eCAR FLOW records, actor PROCESS/CREATE floors, SSH/RDP/SMB/remote-auth
  FLOW-before-session ordering, source-window admission, and later endpoint lifecycle anchors.
- **Layer rationale:** canonical network state owns the interval; source timing translates that
  interval to each endpoint clock. The eCAR emitter must render the finalized plan without applying
  a second policy in the canonical or Zeek sensor clock frame.
- **Sibling risks:** preserve actor omission when process visibility is late, exact tuple and
  direction agreement, deterministic reruns, proxy child phase ordering, and independent Zeek and
  Windows timing. Do not extend or rewrite the canonical transport merely to create clock texture.
### Loop 13 outcome

- Fixed endpoint-local eCAR FLOW clock handling in `SourceTimingPlanner` and removed the emitter's second canonical/sensor-clock clamp.
- Verification: 5,962 tests passed, 22 skipped; Ruff checks passed; deterministic evaluation 97/100 over 78,114 records.
- Hard probe: exact-ms endpoint collisions fell to 8/5,520 unambiguous pairs (0.145%), with 2,223 distinct signed deltas.
- Frozen review corpus SHA-256 remained `1e8b1bd7499f285d36ca5fa8aa0e4a20e7f00ac158ded9c266c5aa81be2307c6` before and after blind review.
- Neutral deliberation revised the panel to 61/55/68/64 synthetic-confidence (mean 62), consensus Inconclusive leaning synthetic.
- The endpoint clock-collapse finding did not recur. Next target: canonical host process ownership and service-principal selection; durable SMB transport reuse remains the following strategic target.

## Loop 14 family contract — source-native host process ownership

- **Owning abstractions:** the polkit action family owns the authorizing subject process;
  typed resident-manager/worker service profiles own Postfix and IIS ancestry; the Linux shell
  command bundle owns inferred interactive command children.
- **Invariant:** foreground polkit clients retain the selected interactive principal and visible
  shell parent, resident daemons retain their service principal and singleton identity, Postfix
  SMTP workers descend from one root-owned Postfix master, IIS OWA workers descend from one
  WAS-hosting service process, and every process inferred from interactive bash history descends
  from that exact session shell. One executable path never determines ownership without its
  execution mode.
- **Entry paths:** baseline polkit action messages, PackageKit and NetworkManager authorization
  subjects, inbound/submission/outbound email process attribution, generic mail-server LDAP
  connection ownership, Exchange OWA access, and inferred Linux shell commands including
  service-named diagnostics such as `nginx -t`.
- **Consumers:** canonical `RunningProcess` parent/principal state, eCAR PROCESS CREATE and FLOW
  attribution, polkit syslog PID/owner text, Postfix syslog PIDs, and source-timing parent-before-
  child constraints.
- **Layer rationale:** polkit, service workers, and interactive commands carry different intent
  even when they share an executable name. The action family must supply that intent before the
  canonical process is created; emitter rewrites or a global executable-to-parent table would
  make daemon `nginx` and interactive `nginx -t` mutually contradictory.
- **Sibling risks:** preserve root/systemd ownership for true Linux daemons, do not duplicate the
  seeded NetworkManager, reuse only matching resident service managers, keep pre-window parents
  valid without requiring an in-window CREATE row, retain one-shot worker lifetimes, and avoid
  changing unrelated generic connection-owner or Windows service-singleton behavior.

## Loop 14 outcome

- Commits `120fe082`, `f8135d5c`, `cbdaaab9`, `283c86d1`, `109140fd`, and `fe88555d` implemented
  typed Postfix/IIS ancestry, session-owned inferred commands, and mode-aware polkit subjects.
- Full suite: 5,966 passed, 22 skipped; deterministic evaluation remained 97/100 over 81,281
  records. The service-ownership hard probe found zero visible singleton or ancestry violations.
- Frozen review corpus SHA-256 remained
  `0497a417270b2b8ea1db6ac89e58b87f14cc7bb9ffa2781a42c9b4e23129756a` before and after review.
- Deliberation revised the panel to 55/62/38/43 synthetic-confidence (mean 49.5), with an
  Inconclusive modal verdict. The completed service family did not recur.
- Highest-leverage next target: strict Windows Type 9/NewCredentials semantics. Typed remote-auth
  transport duration remains a prepared follow-on family.

## Loop 15 family contract — typed Windows remote-auth transport texture

- **Owning abstractions:** `WindowsRemoteAuthenticationPlanner` owns the transport interval and
  payload profile for one remote-authentication occurrence; baseline host-activity planning owns
  whether anonymous SMB and machine-account CIFS activity exists at all; the calling action owns
  the destination service selected for a generic Type 3 logon.
- **Invariant:** successful Windows remote-auth transports use deterministic, source/outcome-aware,
  right-skew duration profiles rather than one shared uniform cutoff. Anonymous SMB remains sparse,
  short-lived, unique, and limited to SMB-capable targets. Generic Type 3 logons do not fabricate a
  TCP/445 transport unless their owning activity explicitly identifies SMB; explicit semantic SMB,
  machine-account CIFS, failures, probes, and authored network events retain their own contracts.
- **Entry paths:** generic Windows Type 3 logons, failed remote Type 3 attempts, anonymous network
  logons, machine-account LDAP/CIFS authentication, semantic SMB activities that bind auth to an
  existing transport, baseline service/anonymous noise, and raw scanner or connection events.
- **Consumers:** Zeek/ASA/eCAR transport duration and service distributions, source-port identity,
  Windows 4624/4625/4634 correlation, remote-auth lifecycle plans, host-activity multipliers, config
  validation, and rendered duration/cardinality hard probes.
- **Layer rationale:** the remote-auth planner owns shared canonical transport texture, while
  baseline planning owns event cadence and service eligibility. Fixing Zeek rows or suppressing
  eCAR output would leave the canonical uniform sampler and excess anonymous occurrences intact.
  Conversely, generic Type 3 authentication cannot infer SMB solely from the logon type; the
  caller must declare the backing service when it has one.
- **Sibling risks:** failures, probes, anonymous enumeration, and one-shot administrative activity
  must remain short and newly allocated; semantic SMB must continue using its existing exact
  transport without a duplicate connection; durations must cover authentication ordering without
  creating long-lived sessions by implication; configuration overlays must merge and validate;
  deterministic generation and unrelated RDP/LDAP/Kerberos timing must remain unchanged.

### Loop 15 implementation handoff

- Replaced the shared successful/failed uniform transport-duration sampler with validated,
  overlay-aware lognormal profiles selected by remote-auth source and outcome. Machine-account
  success retains a bounded long tail; anonymous and failed attempts remain short.
- Generic Windows Type 3 logons now require an owning destination port before generating transport
  evidence. Semantic SMB explicitly declares port 445 and continues binding its existing exact
  transaction without a duplicate flow.
- Anonymous SMB baseline noise now uses a scoped deterministic cadence from the Windows auth
  realism config and only targets world-model hosts with `SMB_SERVER` capability; it no longer
  inherits the service-logon activity multiplier.
- Verification: 725 passed, 1 skipped, 1 deselected across the affected unit families and semantic
  SMB integration suite; `eforge validate-config` reported zero issues across 93 files; repository
  Ruff check and format check passed. No generation or blind review has yet been run for Loop 15.

### Loop 15 outcome

- Commit `ffe07d63`; full suite 5,974 passed, 22 skipped. Deterministic evaluation remained 97/100
  over 72,899 records with acceptance passed.
- The remote-auth hard probe passed: core TCP/445 fell from 272 to 127 rows, generic-human Type 3
  fell to zero, anonymous fell to 10, the machine-account tail exceeded 45 seconds, and semantic
  SMB retained 10/10 exact parents without tuple, timing, or endpoint-pair regressions.
- Frozen review corpus SHA-256 remained
  `0e213c88d0ed45e82af6915efaa0308d0e723326ccf3d882af4cb96c3637da73` before and after review.
- Deliberation revised the panel to 78/88/76/82 synthetic-confidence (mean 81), unanimously
  Synthetic. The fixed remote-auth family did not recur.
- New highest-leverage target: validate and repair native UserAssist payload encoding/timestamps,
  followed by application-scoped cache/profile identities. The prepared Type 9 family remains
  Loop 16 because it is a previously adjudicated source-native contradiction already in progress.

## Loop 16 family contract — Windows NewCredentials identity and session ownership

- **Owning abstractions:** the explicit-credential action family owns `runas /netonly` caller,
  outbound credential, and cloned-token identity; the authentication/session bundle admits only
  logon intents with enough facts to build a source-native session; shared Windows logon-type
  predicates own desktop, terminal-session, and local-source capability.
- **Invariant:** Type 9 clones an existing caller's local identity into a new LUID, carries a
  distinct outbound credential identity, has no remote source endpoint, and never creates or
  repairs `winlogon.exe`, `userinit.exe`, or `explorer.exe`. Only Windows Types 2, 10, and 11 are
  desktop-capable. A typed storyline Type 9 resolves the active/assigned desktop user as its local
  caller and the event actor as its outbound identity; ambiguous direct Type 9 requests fail fast.
- **Entry paths:** typed storyline logons and credential sprays, direct `generate_logon` calls,
  explicit-credential events, materialized `runas.exe /netonly` callers, later process-parent
  resolution, session-ID allocation, and successful-logon Security/eCAR projection.
- **Consumers:** canonical `ActiveSession` and `AuthContext`, Windows Security 4624/4648 fields,
  eCAR USER_SESSION identity/source properties, Security/Sysmon/eCAR process trees, logoff state,
  validation diagnostics, and rendered NewCredentials correlation probes.
- **Layer rationale:** caller identity, alternate outbound identity, source locality, and desktop
  capability are shared semantic truth. The action/session layer must own them before rendering;
  suppressing Explorer in one process path or rewriting self-IP in one emitter would preserve the
  contradictory canonical session and allow another entry path to recreate it.
- **Sibling risks:** preserve desktop bootstrap for Types 2, 10, and 11; preserve network/service
  parentage for Types 3 and 5; keep Types 4 and 8 non-desktop; keep Type 7 as re-authentication of
  an existing interactive LUID; retain Windows RDP and Linux SSH bundle ownership for Type 10;
  and do not turn every 4648 from PsExec, WMI, or scheduled tasks into Type 9.

### Loop 16 implementation handoff

- Added canonical outbound credential and cloned-caller identity, centralized Windows desktop and
  source predicates, and made Type 9 local, non-terminal, and non-desktop across state and lazy
  parent resolution.
- Materialized `runas.exe /netonly` explicit-credential activity now owns correlated 4648 and Type
  9 evidence; other explicit-credential tools do not. Existing typed Type 9 authoring remains
  compatible by resolving the host's active/assigned local desktop user as caller and the event
  actor as outbound identity. The benchmark scenario was not changed.
- Full suite: 5,997 passed, 22 skipped after correcting baseline's unsupported random Type 9 sample
  and synchronizing the canonical/public scenario references. Scenario validation passed with the
  existing 25 warnings; Ruff lint and formatting checks passed.
- A clean rendered probe found exactly one Type 9 on WS-AJOHNSON with local Aisha, outbound Marcus,
  `seclogo`/Negotiate, dash source/port, matched Security/eCAR LUIDs, and zero Type-9-owned
  `winlogon.exe`, `userinit.exe`, or `explorer.exe`. All rendered Type 2/10 siblings retained shell
  evidence; Type 11 remains covered by the focused state matrix.

### Loop 16 outcome

- Commit `52346e69`; deterministic evaluation remained 97/100 over 72,869 records with acceptance
  passed. The final NewCredentials hard probe passed every identity, source, lifecycle, and desktop
  sibling gate.
- Frozen review corpus SHA-256 remained
  `e6b384ce2ab14341de320253436dacba10476a896eb6480df031353789246d06` before and after review.
- Initial blind synthetic-confidence was 23/32/31/79. Deliberation revised it to 43/45/35/68
  (mean 47.75), an Inconclusive consensus. The Type 9 contradiction did not recur.
- Next targets: the already-started UserAssist native encoding repair, then application-scoped
  cache identities. Shell/TTY ownership and narrow TLS duration texture follow from this panel.

## Loop 17 family contract — canonical UserAssist and binary registry effects

- **Owning abstractions:** the registry-effect producer owns the occurrence timestamp, process,
  principal/session, value type, and canonical value bytes before dispatch; shared EDR pool
  materialization owns source-independent binary structure construction; Sysmon and eCAR remain
  source-native projections of that one canonical effect.
- **Invariant:** every modern UserAssist payload is one 72-byte v5 structure whose little-endian
  FILETIME at offset 60 is nonzero and no later than its owning registry occurrence. Repeated
  state for one host/user/value never moves its execution time or counters backward. Explorer
  shell artifacts retain the matching user's live `explorer.exe` and session ownership. Binary
  registry values never leak `.reg` export syntax into Sysmon; eCAR may retain useful canonical
  bytes without inventing a second value.
- **Entry paths:** ambient workstation registry noise and process-owned registry side effects,
  including overlay-provided UserAssist templates. DHCP-coupled HKLM writes remain outside the
  UserAssist family but continue using the shared registry-effect representation.
- **Consumers:** canonical `RegistryContext`, Sysmon Event 13 target/details projection, eCAR
  REGISTRY values and process provenance, registry-state deduplication, config validation, and
  rendered payload/ownership hard probes.
- **Layer rationale:** the defect is created before dispatch when a fixed-calendar UserAssist
  FILETIME is generated without the occurrence time. An emitter-only rewrite would leave sibling
  sources contradictory, while a baseline-only repair would miss process-side effects. The shared
  materialization/registry-effect boundary is the smallest layer that covers every producer.
- **Sibling risks:** preserve deterministic RNG behavior where practical; do not lose HKU/SID
  projection, process/session provenance, or useful eCAR detail; do not make historical shell
  state look like a new application execution; avoid counter regression and duplicate UserAssist
  weighting; keep `AccentPalette` a 32-byte binary palette and PIDL MRUs binary rather than
  four-byte strings when those low-risk siblings share the same owner.

### Loop 17 implementation handoff

- Added one occurrence-aware registry-effect materializer used by ambient, DHCP, and process-side
  producers. Modern UserAssist values remain 72-byte v5 payloads, but their offset-60 FILETIME now
  comes from the canonical occurrence rather than a fixed March 2024 interval. Process-side
  coverage confirms Explorer image, principal, and logon ownership are preserved.
- Added canonical registry value typing. Sysmon renders REG_BINARY Event 13 details opaquely as
  `Binary Data`, while eCAR retains the shared space-delimited canonical bytes. Removed the
  duplicate UserAssist pool entry and `.reg`-export strings; AccentPalette is now 32 bytes and
  PIDL/RecentDocs values use bounded binary shapes.
- Focused verification: 793 passed and 1 skipped across EDR pools, Sysmon, eCAR, baseline, and
  activity tests. The rendered projection tests prove opaque Sysmon binary details and retained
  eCAR bytes; non-March and repeated-time probes prove UserAssist FILETIME ordering. An additional
  76 canonical-context, EDR-diversity, and source-timing tests passed. `eforge validate-config`
  reported zero issues across 93 files. The full suite passed with 6,006 tests and 22 skips after
  making the multipart acceptance sensor explicitly lossless and allowing contract-valid omitted
  SMB FLOW actor identity when the client process is not yet source-visible. Repository-wide Ruff
  lint and formatting checks passed. No full scenario generation, evaluation, blind review, or
  commit has been run.

### Loop 17 outcome

- Commit `a487e795`; deterministic evaluation remained 97/100 over 77,125 records and passed all
  hard acceptance criteria. The rendered hard probe matched 51/51 UserAssist values across
  Sysmon/eCAR with zero future FILETIMEs and passed every AccentPalette/PIDL/RecentDocs gate.
- Frozen review corpus SHA-256 remained
  `768a414a06551e5d90bdd9ab09388a59d3ca2c532129febea63ce08ce3bcff44` before and after review.
- Initial blind synthetic-confidence was 63/43/28/47. Deliberation excluded post-window and
  bounded-completeness claims and revised the panel to 47/45/30/47 (mean 42.25), an Inconclusive
  consensus at 80 confidence.
- The UserAssist contradiction did not recur. The next highest-leverage valid finding is the
  cross-host 2.168–2.286-second public-key SSH authentication band, owned by SSH lifecycle timing.
