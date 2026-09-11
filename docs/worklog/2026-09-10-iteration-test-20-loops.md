# Iteration-Test 20-Loop Assessment

## Scope

- Branch: `codex/assess-20-loops-2026-09-10`, created from `dev` at `12988ce72`.
- Requested loops: 57 through 76, using `scenarios/iteration-test/scenario.yaml`.
- Prior loop-57 work was explicitly discarded and is not part of this effort.
- Every loop will preserve standalone four-reviewer blind scoring and automated evaluation.

## Loop 57 Family Contract

### DHCP source-local phase timing

- **Classification:** `family_level`; loop-56 `sibling_defect` in the DHCP action family.
- **Owning abstraction:** `DhcpLeaseActionBundle` owns transaction phases; the shared timing runtime owns deterministic source-observation variation.
- **Invariant:** endpoint `DHCPREQUEST`, `DHCPACK`, and bound records are independently timed, remain causally ordered, share one source-local observation decision, and keep ACK observation close to the canonical network transaction close without copying one timestamp's microsecond suffix.
- **Entry paths:** baseline initial acquisition and renewal scheduling, direct activity-generator requests, and any storyline/compatibility caller using `generate_dhcp_lease`.
- **Consumers:** Zeek DHCP, Linux syslog, network transaction state, deterministic eval, and blind timing review.
- **Layer rationale:** phase relationships belong to the DHCP bundle; emitter-only jitter would duplicate truth and could disagree with the canonical close.
- **Sibling risks:** acquisition and renewal are both covered. Per-sensor DNS RTT remains a separate source-timing family.

### Canonical process-parent principal

- **Classification:** `family_level`; loop-56 `sibling_defect` in canonical process ancestry.
- **Owning abstraction:** `ProcessContext` and exact deferred process materialization own parent identity; Sysmon renders that truth.
- **Invariant:** when an exact parent identity is available, every child process projection can render the parent's principal independently of whether mutable live state still contains the parent.
- **Entry paths:** deferred RDP session process publication and ordinary state-backed Windows session process creation; legacy/raw callers retain source-native fallback behavior.
- **Consumers:** Sysmon Event 1, eCAR process relationships, Security 4688, source-timing parent identity, and process-tree probes.
- **Layer rationale:** eCAR already proves the parent principal exists canonically; teaching only Sysmon about RDP would patch a rendered symptom.
- **Sibling risks:** RDP `userinit.exe` lifetime is not changed in this loop because exact process terminalization currently requires child-before-parent closure.

## Loop Ledger

| Loop | Selected family | Automated | Blind average | Outcome |
|---:|---|---:|---:|---|
| 57 | DHCP phase timing; canonical parent principal | 97.36 PASS | 69.00 initial / 82.25 deliberated | complete |
| 58 | UDP DNS close timing; RDP userinit lifecycle | 96.28 PASS | 71.75 initial / 86.75 deliberated | complete |
| 59 | Proxy phase causality; Windows token/session identity | 96.28 PASS | 65.00 initial / 77.50 deliberated | complete |
| 60 | UDP DNS packet identity; sub-ms WFP admission | 96.28 PASS | 61.00 initial / 71.50 deliberated | complete |

## Loop 57 Verification

- Commits: `759a46b33` (family fix) and `a8cbf1bf9` (rendered observation-order correction).
- Routine gate: 8,379 passed, 5 skipped; Ruff check and format check passed.
- Generated bundle: 122,545 records across 22 evaluated sources.
- Deterministic evaluation: 97.3622, acceptance PASS; pillars 100.00 parseability,
  96.86 plausibility, 97.53 causality, and 93.83 timing.
- Rendered DHCP probe: 18/18 transactions preserve phase order with 54 distinct
  microsecond suffixes. Seventeen visible cross-source pairs place endpoint ACK
  95.230-338.488 ms after Zeek close; one endpoint ACK has no nearby Zeek row under
  the configured observation profile.
- Rendered process probe: all 23 `userinit.exe` rows identify `winlogon.exe` as an
  `NT AUTHORITY\\SYSTEM` parent; no resolvable Sysmon parent-principal mismatch remains.
- Blind panel: initial scores 44/65/83/84 (mean 69.00); verdict disagreement and
  40-point spread triggered deliberation. Final scores 74/80/87/88 (mean 82.25),
  unanimously Synthetic.
- Next highest-impact families: packet-owned UDP DNS close timing and short-lived
  RDP `userinit.exe` terminalization.

## Loop 58 Family Contract

### Packet-owned UDP DNS close timing

- **Classification:** `family_level`; loop-57 `sibling_defect` in the canonical
  network-transaction family.
- **Owning abstraction:** `NetworkTransactionPlanner` owns DNS packet accounting,
  response RTT, and canonical transport close duration.
- **Invariant:** a response-bearing UDP DNS transaction whose `Dd` history proves
  one request and one response closes after the response plus only the modeled DNS
  close slack; a generic caller duration cannot create an unexplained idle tail.
- **Entry paths:** explicit `DnsContext` requests, hostname-synthesized DNS context,
  baseline resolver traffic, and compatibility callers using `generate_connection`.
- **Consumers:** Zeek `conn.log` and `dns.log`, source-timing constraints, canonical
  network state, deterministic evaluation, and blind packet-accounting review.
- **Layer rationale:** the canonical network transaction owns packet and close truth;
  changing only Zeek rendering would leave state and sibling consumers inconsistent.
- **Sibling risks:** TCP DNS and unanswered DNS retain their protocol-specific close
  behavior; response-bearing synthesized UDP DNS is the bounded target.

### Short-lived RDP session initializer

- **Classification:** `family_level`; loop-57 `sibling_defect` in the exact RDP
  lifecycle family.
- **Owning abstraction:** `RdpSessionActionBundle` and its authenticated exact
  lifecycle continuation own target process creation and termination.
- **Invariant:** initial Type 10 sessions terminate `userinit.exe` shortly after
  `explorer.exe` is ready, independently of the interactive session and transport
  close, while preserving the canonical winlogon -> userinit -> explorer ancestry.
- **Entry paths:** exact initial RDP publication and its continuation recovery path;
  reconnects do not create or terminate another session initializer.
- **Consumers:** state lifecycle, Windows Security 4688/4689, Sysmon 1/5, eCAR
  PROCESS CREATE/TERMINATE, and final RDP session teardown.
- **Layer rationale:** early initializer exit is lifecycle truth shared by every
  endpoint projection; emitter-specific terminal rows would orphan canonical state.
- **Sibling risks:** `winlogon.exe` and `explorer.exe` remain session-lived, and final
  teardown must naturally exclude the already-closed initializer.

## Loop 58 Verification

- Commit: `1840f0663` (canonical DNS duration and exact RDP lifecycle fix).
- Routine gate: 8,379 passed, 5 skipped; Ruff check and format check passed.
- Generated bundle: 122,916 records across 22 evaluated sources.
- Deterministic evaluation: 96.2817, acceptance PASS; pillars 100.00 parseability,
  96.82 plausibility, 93.95 causality, and 92.95 timing.
- Rendered DNS probe: all 3,255 matched response-bearing UDP DNS transactions close
  0.075-9.462 ms after response, with no negative or over-12.001 ms tail. Loop 57 had
  42 tails over 100 ms and a 4.902802-second maximum.
- Rendered RDP probe: all 15 visible Type 10 `userinit.exe` processes terminate
  1.150-3.408 seconds after creation. Loop 57's 18 matched processes all exceeded
  5.5 seconds and had a 2,514.518-second median lifetime.
- Blind panel: initial scores 44/70/91/82 (mean 71.75); verdict disagreement and a
  47-point spread triggered deliberation. Final scores 80/87/91/89 (mean 86.75),
  unanimously Synthetic.
- Next highest-impact families: explicit-proxy request/child phase causality and one
  canonical Windows process/session token identity across Security, Sysmon, and eCAR.

## Loop 59 Family Contract

### Explicit-proxy packet-phase causality

- **Classification:** `family_level`; loop-58 `hard_contradiction` in the explicit-proxy
  transaction family.
- **Owning abstraction:** `ProxyPhasePlanner` owns canonical CONNECT/origin phases, while
  `NetworkObservationPlanner` owns projection of those packet phases through each sensor clock.
- **Invariant:** for one transaction-bound tunnel at every common sensor, the observed CONNECT
  request precedes the proxy-origin TCP open and outbound TLS detection. HTTP `ts` represents the
  request packet time, not a later analyzer-queue delay. All child transports in one explicit-proxy
  action share the sensor-local route delay so canonical parent-before-child gaps survive projection.
- **Entry paths:** explicit CONNECT requests, inspected HTTPS tunnel setup, gateway attempts, and
  direct HTTP proxy requests; reused preexisting tunnels keep their explicit manager-owned path.
- **Consumers:** Zeek conn/http/ssl, proxy access, canonical tunnel state, deterministic timing
  evaluation, and exact-byte/SNI blind correlation.
- **Layer rationale:** the canonical planner already orders request and child phases; independent
  transport route delay and HTTP timestamp sampling invert them only at the source-observation
  owner. Emitter clamping would leave sibling sensors inconsistent.
- **Sibling risks:** ordinary unrelated transports retain independent route texture; only members
  sharing an explicit-proxy parent action share the offset. HTTP rows without a canonical request
  anchor retain their compatibility timing.

### Canonical Windows process/session token identity

- **Classification:** `family_level`; loop-58 `hard_contradiction` and `contract_gap` across the
  process and RDP families.
- **Owning abstraction:** canonical Windows token profiling owns integrity, elevation type, and
  mandatory label; deferred session composition owns the LogonGuid before endpoint publication.
- **Invariant:** one Windows process renders the same integrity truth in Security 4688 and Sysmon
  Event 1, with mandatory-label and elevation fields derived from that token. Every RDP
  `userinit.exe` and `explorer.exe` receives the same nonzero session LogonGuid as its Type 10 4624
  before any source is dispatched.
- **Entry paths:** ordinary process generation, exact initial RDP session composition, system and
  user processes, and deferred publication/recovery.
- **Consumers:** Windows Security 4688, Sysmon Event 1, eCAR PROCESS CREATE, state identities, and
  cross-source process/session joins.
- **Layer rationale:** token and session identity are shared canonical truth. Deriving defaults in
  individual emitters caused Medium/High disagreement and zero-to-nonzero GUID transitions.
- **Sibling risks:** SYSTEM and built-in service tokens retain Default/System semantics; a High user
  token uses Full elevation unless a future canonical alternate-token model explicitly says
  otherwise. Non-RDP compatibility events may still use zero GUID when no session owns one.

## Loop 59 Verification

- Commit: `7b947962f` (explicit-proxy observation causality and canonical Windows
  token/session identity).
- Routine gate: 8,380 passed, 5 skipped; Ruff check and format check passed.
- Generated bundle: 122,916 records across 22 evaluated sources.
- Deterministic evaluation: 96.2817, acceptance PASS; pillars 100.00 parseability,
  96.82 plausibility, 93.95 causality, and 92.95 timing.
- Rendered proxy probe: all 522 exact-byte/SNI-matched successful tunnels on the DMZ
  sensor place CONNECT before origin TCP and TLS; minimum gaps are 8.074 ms and
  31.597 ms. Loop 58 had 392 origin and 115 TLS inversions in the same 522-tunnel set.
- Rendered Windows probe: all 969 exact Security 4688/Sysmon Event 1 joins agree on
  integrity, no High user token has a non-Full elevation type, and all 30 matched Type
  10 `userinit.exe`/`explorer.exe` rows share the nonzero session LogonGuid.
- Blind panel: initial scores 44/72/72/72 (mean 65.00); verdict disagreement triggered
  deliberation. Final scores 70/78/82/80 (mean 77.50), unanimously Synthetic.
- Next highest-impact families: packet-derived Zeek DNS query/response identity, unified
  SSH session/history/process timing, and KDC-local AS/TGS/logon ordering.

## Loop 60 Family Contract

### Packet-derived single-exchange UDP DNS identity

- **Classification:** `family_level`; loop-59 `hard_contradiction` in the canonical DNS
  transaction and source-observation family.
- **Owning abstraction:** `NetworkTransactionPlanner` owns canonical DNS request/response packet
  timing; `NetworkObservationPlanner` freezes the same packet anchors for each Zeek sensor.
- **Invariant:** for a response-bearing UDP DNS transaction rendered with history `Dd` and exactly
  one origin and one response packet, `dns.ts == conn.ts` and
  `dns.ts + dns.rtt == conn.ts + conn.duration` at every sensor. Query and response are the two
  packets that define the transport interval; neither source projection nor the emitter may add
  an independent analyzer delay or close slack. TCP DNS, retransmitted/multipacket UDP DNS, and
  unanswered queries retain their protocol-specific phase models.
- **Entry paths:** authored `DnsContext` connections, synthesized resolver transactions, baseline
  DNS, explicit-proxy destination lookups, causal DNS prerequisites, and direct emitter fixtures.
- **Consumers:** Zeek conn/dns rows, canonical network state, source-window admission, deterministic
  evaluation, proxy DNS dependencies, and packet-level forensic probes.
- **Layer rationale:** the contradiction is shared request/response packet truth. Repairing only
  `dns.log` would leave canonical duration and `conn.log` inconsistent; retaining emitter-local
  jitter would recreate the defect after sensor projection.
- **Sibling risks:** DNS retries, truncation/TCP fallback, response loss, and true multipacket
  exchanges must not be collapsed into the single-exchange contract.

### Sub-millisecond Windows WFP transport admission

- **Classification:** `family_level`; generation-discovered `sibling_defect` in endpoint
  source timing exposed by the exact DNS packet interval.
- **Owning abstraction:** `SourceTimingPlanner` owns admission of Windows WFP observations into
  their source-local canonical transport interval.
- **Invariant:** a WFP 5156 observation is at or after the source-local transport open and strictly
  before transport close. The planner reserves only source timestamp precision at the close edge;
  it must not require the generic 1 ms lifecycle ordering gap when the complete transport is shorter
  than 1 ms.
- **Entry paths:** source- and destination-side Windows WFP projections for UDP and TCP connections,
  including packet-derived DNS exchanges and remote-authentication transports.
- **Consumers:** Windows Security 5156, endpoint admission state, remote-auth transport anchors,
  authentication timing, and rendered cross-source transport probes.
- **Layer rationale:** the impossible interval is created by generic source timing before rendering;
  changing Windows emitter timestamps would bypass frozen timing and admission state.
- **Sibling risks:** process-create/dependent ordering keeps its 1 ms lifecycle gap. WFP process
  attribution is retained only when its already-modeled process lifecycle is valid; this fix does
  not fabricate or move process identity.

## Loop 60 Verification

- Commits: `b5b9617f0` (packet-derived DNS timing) and `1cb4fbfcb` (sub-millisecond
  WFP source-admission sibling fix).
- Routine gate: 8,381 passed, 5 skipped; Ruff check and format check passed across
  769 files.
- Generated bundle: 122,916 records across 22 evaluated sources.
- Deterministic evaluation: 96.2817, acceptance PASS; pillars 100.00 parseability,
  96.82 plausibility, 93.95 causality, and 92.95 timing.
- Rendered DNS probe: all 3,863 qualifying one-query/one-response UDP transactions
  across core, DB, and DMZ sensors have exact query-start and response-close equality
  between `dns.json` and `conn.json`, with zero mismatches.
- Generation-discovered WFP sibling: a valid 463 microsecond DNS transport initially
  failed because WFP admission reserved a generic 1 ms close margin. A WFP-specific
  1 microsecond precision boundary now admits the interval; the exact regression and
  complete regeneration pass.
- Blind panel: initial scores 56/86/34/68 (mean 61.00); verdict disagreement and a
  52-point spread triggered deliberation. Final scores 68/88/53/77 (mean 71.50), with
  three Synthetic verdicts and one Inconclusive, synthetic-leaning verdict.
- Next highest-impact families: host-specific Windows execution metadata, browser
  process action lifecycles, and source-coherent SSH observation.

## Loop 61 Family Contract

### Host/provider Windows execution metadata

- **Classification:** `family_level`; loop-60 `distribution_texture` fingerprint in Windows
  Security source-native metadata.
- **Owning abstraction:** `WindowsEventEmitter` owns the Security provider's `System/Execution`
  projection; its deterministic provider-thread lifecycle derives from canonical host, provider
  process, source time, and occurrence identity.
- **Invariant:** execution ThreadIDs are four-byte aligned, stable for one deterministic
  host/provider thread lifetime, reused across related event families through that provider, and
  independently populated per host. Successful and failed authentication must not use visibly
  disjoint hard-coded pools, and high-volume WFP events must not exhaust the same finite range on
  every system.
- **Entry paths:** all canonical Windows Security renderers, including WFP 5156, authentication,
  Kerberos, process auditing, SMB auditing, account management, workstation transitions, service
  and task management, and compatibility rows that already carry explicit execution metadata.
- **Consumers:** Windows XML and Snare projections, parser validation, exact source publication,
  source-finalization replay, and metadata-distribution probes.
- **Layer rationale:** Execution PID/TID is source-local provider metadata rather than canonical
  activity truth. Central normalization in the Windows emitter keeps every event family and output
  projection consistent without polluting shared events.
- **Sibling risks:** direct compatibility fixtures without a canonical occurrence retain their
  explicit values. Thread identity must remain order-, worker-, retry-, and checkpoint-independent;
  it must not introduce mutable renderer state or change event timestamps.

### Installation-specific NT device-volume identity

- **Classification:** `family_level`; loop-60 sibling `distribution_texture` in the same Windows
  source-native host identity family.
- **Owning abstraction:** Windows Security path projection owns drive-letter to NT device-volume
  rendering, keyed by the concrete host installation and drive.
- **Invariant:** one host/drive maps consistently to one `HarddiskVolumeN`, different drives on one
  host do not alias, and a heterogeneous fleet does not collapse every C: path to Volume1. Existing
  NT device paths and the kernel `System` image pass through unchanged.
- **Entry paths:** outbound and inbound WFP 5156 application paths and direct path-conversion
  compatibility calls.
- **Consumers:** Windows Security 5156, WFP policy bucketing, endpoint-flow joins, and source-native
  field probes.
- **Layer rationale:** the mapping is installation-local rendering truth; canonical process images
  correctly remain drive-letter paths shared with Sysmon and eCAR.
- **Sibling risks:** this loop does not claim to model dynamic volume remounting. The stable mapping
  is scoped to the six-hour host installation and preserves path identity within that scope.

## Loop 61 Verification

- Implementation commit: `bbd007373` (`fix: diversify Windows provider metadata`).
- Routine gate: 8,383 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 122,916 records across 22 evaluated sources.
- Deterministic evaluation: 96.2817, acceptance PASS; pillars 100.00 parseability,
  96.82 plausibility, 93.95 causality, and 92.95 timing.
- Rendered Windows probe: all 18,232 Security rows have aligned execution ThreadIDs;
  per-host WFP populations contain 307–799 unique IDs with zero identical host-pair sets.
  Ten Windows hosts use seven stable installation-specific NT volume identities instead of
  universal `HarddiskVolume1`.
- Blind panel: scores 84/66/68/83 (mean 75.25), unanimously Synthetic. Deliberation was not
  triggered: average verdict confidence was 87.25 and score spread was 18.
- The repaired execution-thread and NT-volume fingerprints were absent from every report.
- Next highest-impact families: source-native identifier entropy across proxy/eCAR/Postfix,
  Sysmon Event 8 target-thread semantics, and command-derived process/scan execution.

## Loop 62 Family Contract

### Source-native deterministic identifier entropy

- **Classification:** `new_family`; loop-61 `hard_contradiction` / probable generator-identity
  leak spanning otherwise unrelated visible source families.
- **Owning abstraction:** a seed-scoped deterministic digest utility owns full-width entropy;
  the proxy renderer, storage-world compiler, and Postfix activity owner independently choose
  their source-native prefix, width, alphabet, and semantic identity inputs.
- **Invariant:** a requested N-hex-character identifier contains N digest-derived characters,
  rather than formatting a 32-bit seed into a wider zero-padded slot. Values remain stable for
  the same generation seed and semantic identity, change with that identity or public seed, and
  use separate namespaces across products. Proxy tunnel children retain one tunnel identifier,
  one storage file retains one canonical identity across its consumers, and all Postfix lifecycle
  lines and SMTP replies retain the same per-hop queue ID.
- **Entry paths:** explicit-proxy HTTPS child rendering and tunnel summarization; default compiled
  SMB/storage files projected into eCAR and server evidence; Postfix receive, delivery, removal,
  SMTP reply, and Received-header paths.
- **Consumers:** proxy grouping/checkpoint replay, eCAR file object correlation, storage/share
  registries, SMB/File projections, Postfix queue state, SMTP evidence, parsers, and blind
  distribution probes.
- **Layer rationale:** canonical identity ownership and source-native syntax are distinct. The
  shared utility provides deterministic entropy only; each owning product layer selects its own
  visible shape and correlation scope instead of exposing one global identifier convention.
- **Sibling risks:** internal action/cohort IDs, Zeek UIDs/FUIDs, UUID-shaped lifecycle identities,
  and intentionally 32-bit protocol fields are not widened merely because they use deterministic
  seeds. The material output change requires a behavior-manifest revision and exact retry,
  checkpoint, storage, mail, and proxy regression coverage.

## Loop 62 Verification

- Implementation commit: `ab6c55e0a` (`fix: diversify source-native identifiers`).
- Behavior contract: revision 25, surface digest
  `1ffc409e1424464935982502f3beec72a6ed61e54ee90a482605b77ca0eff1c6`.
- Routine gate: 8,390 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 129,460 records across 22 evaluated sources.
- Deterministic evaluation: 97.2286, acceptance PASS; pillars 99.9992 parseability,
  96.4484 plausibility, 97.2176 causality, and 94.0615 timing.
- Rendered identifier probe: 1,964 proxy tunnel-ID rows and 111 compact eCAR storage-file rows
  have zero former `00000000` prefixes; 138 Postfix lifecycle rows use 30 native-width queue IDs
  with ordinary leading-zero variation.
- Blind initial panel: 68/58/89/74 (mean 72.25), unanimously Synthetic. Deliberation was triggered
  by the 31-point score spread and produced 76/70/89/80 (mean 78.75).
- The repaired identifier fingerprint was absent from all reports.
- Next highest-impact families: SSH continuation/session identity, canonical public IPv6 identity,
  UFW host-clock/scanner texture, and process-termination outcomes.

## Loop 63 Family Contract

### Observation-orphaned systemd-logind close identity

- **Classification:** `exact_regression`; loop-62 `hard_contradiction` against the existing
  canonical SSH/logind session-identity contract.
- **Owning abstraction:** canonical session allocation owns the logind session ID; the syslog
  renderer may order and format rows but must not replace that shared identity during terminal
  normalization.
- **Invariant:** every visible `New session N` or `Removed session N` row preserves the canonical
  `AuthContext.session_id` used by eCAR `USER_SESSION` and process lifecycle rows. If observation
  drops a matching opener, the orphaned closer keeps `N`; final rendering must not guess that it
  represents a pre-window session and synthesize a different ID. Repair of duplicate or
  backward-moving visible `New session` rows remains scoped to genuinely noncanonical compatibility
  input and carries a rewritten ID only to an explicitly matched visible closer.
- **Entry paths:** deferred and compatibility SSH action bundles, baseline remote administration,
  storyline SSH, SCP receiver sessions, local Linux logons, pre-window sessions, and direct syslog
  compatibility fixtures.
- **Consumers:** systemd-logind syslog, eCAR `USER_SESSION` and process rows, SSH/PAM lifecycle
  joins, blind-review correlation, terminal host normalization, checkpoint replay, and SOF-ELK®
  rendering.
- **Layer rationale:** the continuation and canonical event already agree on the ID. The defect is
  introduced only by terminal syslog rewriting after observation, so the smallest owning-layer fix
  is to preserve unmatched close IDs rather than mutate canonical planning or patch SSH messages.
- **Sibling risks:** matched rewritten compatibility sessions must still keep New/Removed parity;
  malformed oversized IDs remain nonfatal; genuine pre-window closes remain valid orphan rows and
  are not fabricated into visible opens.

## Loop 63 Verification

- Implementation commit: `f1caae5cd` (`fix: preserve logind close identities`).
- Behavior contract: revision 26, surface digest
  `7f62ff26bd8f880b68bd475b06ef88ee9c573cf709247013767bfaf795f3717b`.
- Routine gate: 8,391 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 129,460 records across 22 evaluated sources.
- Deterministic evaluation: 97.2286, acceptance PASS; pillars 99.9992 parseability,
  96.4484 plausibility, 97.2176 causality, and 94.0615 timing.
- Rendered SSH probe: five visible eCAR termination/logind removal lifecycle joins retain one
  canonical session ID, with zero mismatches. The four exact loop-62 mismatches are repaired.
- Blind initial panel: 29/71/66/92 (mean 64.50), with one Real and three Synthetic verdicts.
  Deliberation was triggered by verdict disagreement and a 63-point spread; final scores were
  64/82/78/93 (mean 79.25), unanimously Synthetic.
- The repaired cross-source SSH ID substitution was absent from every report. The highest-impact
  next families are canonical binary content identity, Event 4648 host ownership, and Zeek
  analyzer declarations.

## Loop 64 Family Contract

### Canonical process-binary hashes and PE metadata

- **Classification:** `family_level`; loop-63 repeated `hard_contradiction` spanning installed
  third-party releases and build-owned Windows system binaries.
- **Owning abstraction:** `ProcessContext.binary_identity`, populated by the deployment/local
  artifact registries at dispatch preparation, owns executable content digests and optional PE
  version resources. The Sysmon renderer owns only source-native projection of that exact identity.
- **Invariant:** one `BinaryReleaseIdentity` or `LocalArtifactBinaryIdentity` renders one complete
  hash set at every installation path, user, and host. Distinct release/build/architecture/artifact
  keys render distinct digest sets. PE metadata and hashes come from the same binary identity;
  unresolved and virtual-kernel identities never acquire fabricated file hashes or VERSIONINFO.
- **Entry paths:** baseline, storyline, remote administration, scheduled tasks, services, browser
  and application activity, retained local executable publication, image loads, and compatibility
  events that omit an attached production identity.
- **Consumers:** Sysmon Event 1 and Event 7, Security/eCAR process joins, deployment audits,
  checkpoint/retry replay, blind cross-host release probes, and future source-native hash renderers.
- **Layer rationale:** canonical release and local-artifact identities already exclude placement and
  include content-owning build dimensions. The defect is introduced when Sysmon ignores the attached
  identity and hashes a path-derived fallback, so the fix is to render existing canonical truth
  rather than create a second emitter-local identity model.
- **Sibling risks:** direct unit/legacy callers without dispatch preparation retain deterministic
  compatibility projection. Genuine local artifacts remain content-specific. Signed module fallback
  metadata must not override an attached exact module identity, and hashes must remain uppercase in
  Sysmon's source-native `Hashes` field.

## Loop 64 Verification

- Renderer implementation commit: `28cccc2ce` (`fix: render canonical binary identities`).
- Production binding commit: `9eb47c99b` (`fix: bind canonical binary deployment`).
- Behavior contracts: revisions 27 and 28, final surface digest
  `183fe16017b29d7948159af482152fcbf2526b8907749ed57fbacdf5f62ba487`.
- Routine gate: 8,395 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 127,148 evaluated records across 22 sources.
- Deterministic evaluation: 96.5904, acceptance PASS; pillars 99.9992 parseability,
  96.9310 plausibility, 94.8004 causality, and 93.2886 timing.
- Rendered binary probe: five cross-host application-release groups and eight OS binary/build
  groups had zero hash violations. Slack, Teams, OneDrive, and FileSyncShell64 identities are
  placement independent; winlogon/userinit identities are build specific.
- Blind initial panel: 49/71/68/87 (mean 68.75), with one Inconclusive and three Synthetic
  verdicts. Deliberation was triggered by verdict disagreement and a 38-point spread; final scores
  were 66/78/74/90 (mean 77.00), unanimously Synthetic.
- The repaired cross-host application release identity was absent from the final prioritized
  evidence, but the panel exposed incomplete host-build coverage for other Windows inbox binaries.
- Highest-impact next families: unified Linux PID allocation, complete host-build Windows binary
  inventory, and HTTP redirect/DNS source-native contracts.

## Loop 65 Family Contract

### Host-local Linux transient process identity

- **Classification:** `family_level`; loop-64 `hard_contradiction` and `distribution_texture`
  findings in Linux process identity across syslog and eCAR.
- **Owning abstraction:** `StateManager` owns one time-aware PID namespace and hidden workload
  progression per Linux host. Lifecycle generators must request process identity from that owner;
  source renderers may only project the allocated PID.
- **Invariant:** a newly started one-shot process consumes a PID from the same host/time namespace
  as every other canonical or syslog-only transient process. Its follow-on messages and termination
  retain that PID. Hidden churn has stable host-specific workload magnitude as well as minute/hour
  variation, so unrelated hosts do not converge on one fleet-wide PID/time slope.
- **Entry paths:** anacron lifecycle, scheduled CRON shell/workload processes, SSH and sudo
  transients, ordinary Linux system/user processes, deferred baseline generation, and direct
  transient syslog allocation.
- **Consumers:** eCAR process create/terminate records, RFC 5424 syslog APP-NAME/PROCID fields,
  process parent/lifecycle state, checkpoint/retry replay, blind chronology probes, and PID-wrap
  validation.
- **Layer rationale:** the low anacron PID was introduced by bypassing process materialization and
  selecting a private random number in baseline code. Routing it through `StateManager` repairs the
  shared truth; host workload texture belongs in the allocator rather than any source renderer.
- **Sibling risks:** durable boot daemons retain their fixed boot PIDs, explicit PID namespaces
  remain valid, out-of-order 30-second allocation lanes retain capacity, PID wrap/reuse rules stay
  unchanged, and anacron source rows remain one coherent daily lifecycle.

## Loop 65 Verification

- Implementation commits: `e13597b6d` (`fix: unify Linux transient process identity`) and
  `441077661` (`fix: preserve authored Linux shell anchors`).
- Behavior contract: revision 29, surface digest
  `df044281d87ab2a3adff9c8149d3a054a0e3397b4d091325091351ed4ed5a6cf`.
- Routine gate: 8,396 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 125,715 evaluated records across 22 sources.
- Deterministic evaluation: 96.6689, acceptance PASS; pillars 99.9992 parseability,
  96.8782 plausibility, 95.6657 causality, and 92.6659 timing.
- Rendered PID probe: all ten anacron hosts retained one PID across five syslog rows plus eCAR
  create/terminate, with zero violations. Eleven Linux host PID slopes ranged from 1.8850 to
  3.4776 PIDs/second, a 1.8449x spread.
- Blind initial panel: 86/67/36/71 (mean 65.00), with three Synthetic and one Real verdict.
  Deliberation was triggered by verdict disagreement and a 50-point spread; final scores were
  92/83/58/85 (mean 79.50), with three Synthetic and one Inconclusive verdict.
- The repaired low-PID anacron contradiction and fleet-wide narrow PID slope did not recur in the
  final prioritized evidence. The panel exposed an RDP session-before-use inversion and a visible
  Nmap-command/target-expansion mismatch as the highest-impact next families.
- Highest-impact next families: RDP session lifecycle ordering, Nmap semantic target expansion,
  and complete host-build Windows PE metadata.

## Loop 66 Family Contract

### RDP session publication before dependent user activity

- **Classification:** `family_level`; loop-65 `hard_contradiction` spanning Windows Security,
  Sysmon, and eCAR session/process evidence.
- **Owning abstraction:** the RDP action bundle owns the session authentication frontier through
  `SessionMaterializationPlan.source_ready_time`; the storyline scheduler owns applying that
  frontier before dispatching dependent authored activity.
- **Invariant:** a remote-interactive transport and successful Type 10 login are observable before
  any non-bootstrap process or command uses the resulting logon ID. Source-native delay may not
  invert that relationship in Security, Sysmon, or eCAR. The bundle's `winlogon.exe` bootstrap may
  precede authentication, while `userinit.exe`, `explorer.exe`, and authored user activity retain
  their lifecycle order after the authentication frontier.
- **Entry paths:** typed `rdp_session`, legacy/compatibility `logon_type: 10`, baseline remote
  administration, successful remote-interactive authentication, reconnect/session reuse, and
  deferred RDP publication/recovery.
- **Consumers:** Security 4624/4688, Sysmon Event 1, eCAR USER_SESSION/PROCESS/FLOW, session state,
  source-timing planners, follow-on storyline placement, checkpoint/retry replay, and blind
  cross-source chronology probes.
- **Layer rationale:** the exact RDP bundle already owns and persists the authentication-ready
  frontier. The contradiction is introduced when one storyline entry path ignores that canonical
  truth, so the repair belongs in storyline scheduling rather than emitter timestamp rewriting.
- **Sibling risks:** preserve source-side `mstsc.exe` and TCP/3389 transport-before-auth ordering,
  successful-flow semantics, bootstrap process order, explicit logoff/session close, reconnect
  behavior, source publication deadlines, and exact deferred continuation recovery.

## Loop 66 Verification

- Implementation commit: `a9d2b7bfb` (`fix: publish remote session readiness before child
  activity`).
- Behavior contract: revision 30, surface digest
  `9ad3c48fa5b74e270d2ba31d3da22649500cb5a703f62999e6db564f576780f2`.
- Routine gate: 8,397 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 125,914 evaluated records across 22 sources.
- Deterministic evaluation: 96.2339, acceptance PASS; pillars 99.9992 parseability, 96.8682
  plausibility, 94.2708 causality, and 92.2471 timing.
- Rendered RDP probe: transport at 15:20:19.944, Type 10 login for `0x27015bf` at
  15:20:25.365, and dependent `cmd.exe`/`whoami.exe` creates at 15:20:25.366/15:20:26.200;
  Windows Security retains the same `10.10.1.99:58332` tuple and post-login ordering.
- Blind panel: 73/92/89/86 (mean 85.00), unanimously Synthetic. Deliberation was not triggered:
  average verdict confidence was 89.5 and score spread was 19.
- The repaired same-LUID process-before-login inversion did not recur. The panel exposed one
  fixed Explorer 19041 identity across incompatible host builds, command-inconsistent Nmap
  application/discovery behavior, and post-disconnect RDP activity as the highest-impact families.
- Next highest-impact families: complete host-build Windows PE identity, Nmap semantic target and
  protocol expansion, and remote-interactive reconnect/control ownership.

## Loop 67 Family Contract

### Host-build-owned Windows PE identity coverage

- **Classification:** `family_level`; loops 64–66 repeated `hard_contradiction` and
  `schema_or_format` findings across Windows inbox binaries.
- **Owning abstraction:** the deployment content registry owns one `BinaryReleaseIdentity` per
  exact Windows build, architecture, and artifact. The system/application catalogs own the
  executable's VERSIONINFO vocabulary; Sysmon only renders the attached canonical identity.
- **Invariant:** an OS-owned executable on one host uses that host's resolved Windows build in its
  release key and FileVersion, and its hashes derive from that exact release. The same executable
  on different builds has different content digests, while adjacent inbox components on one host
  remain in one build family. Known OS binaries do not lose all PE fields merely because one
  generation entry path used a system-process descriptor instead of an application descriptor.
- **Entry paths:** interactive/RDP bootstrap, baseline system services and scheduled tasks,
  storyline commands, remote administration, application-catalog Windows Explorer/RDP tools,
  loaded modules, and direct compatibility rendering.
- **Consumers:** Sysmon Event 1/Event 7, Security/eCAR process joins, deployment audits,
  application assignment, checkpoint/retry replay, and blind cross-host build/hash probes.
- **Layer rationale:** the contradiction originates in split catalog ownership: Explorer is
  compiled as one fixed application release while many native descriptors omit VERSIONINFO and
  fall back to emitter-local tables. Consolidating source data into the deployment catalogs and
  binding host build there repairs canonical truth rather than rewriting rendered rows.
- **Sibling risks:** third-party/versioned releases must remain version-owned rather than inherit
  the Windows build; unresolved or artifact-local binaries may legitimately lack PE resources;
  compatibility callers retain deterministic data-driven metadata; paths and OriginalFileName
  casing remain source-native; deployment overrides and architecture separation stay intact.

## Loop 67 Verification

- Implementation commits: `de59b2c60` (`fix: bind Windows PE identity to host builds`) and
  `cdb161208` (`fix: materialize native deployment metadata paths`).
- Behavior contract: revision 31, surface digest
  `7be368c84bf4e383e2cb7d1e6b27bfb027b8fbcfcff9433428097ba185c5df44`.
- Routine gate: 8,398 passed, 5 skipped; Ruff check and format check passed across 769 files.
- Generated bundle: 125,914 evaluated records across 22 sources.
- Deterministic evaluation: 96.2339, acceptance PASS; pillars 99.9992 parseability, 96.8682
  plausibility, 94.2708 causality, and 92.2471 timing.
- Rendered PE probe: all-five-field Sysmon Event 1 gaps fell from 691/938 rows and 51 images to
  104/938 rows and 29 images. Explorer resolves four build-specific versions with one digest per
  version and zero cross-version digest overlap.
- Blind panel: 72/76/65/90 (mean 75.75), unanimously Synthetic. Deliberation was not triggered:
  average verdict confidence was 82.75 and score spread was 25.
- The repaired fixed Explorer 19041 identity did not recur as a prioritized finding. The panel
  exposed a near-universal KDC-before-WFP inversion, cloned Linux IRQ inventories, invalid-SSH
  timestamp suffix locking, and repeated network/content distribution fingerprints.
- Next highest-impact families: KDC/WFP causality, per-host Linux hardware inventory, and
  source-native SSH/IDS timestamp construction. Nmap command semantics remains queued from loops
  65–66.

## Loop 68 Family Contract

### KDC processing after exact packet-admission evidence

- **Classification:** `family_level`; loop-67 `hard_contradiction` across Windows Security 5156
  and Kerberos 4768/4769/4771 on both domain controllers.
- **Owning abstraction:** the canonical network-connection bundle owns the KDC transport tuple and
  transaction identity; `SourceTimingPlanner` owns the source-local WFP-admission frontier and the
  dependent KDC audit timestamp.
- **Invariant:** when a visible successful client-to-DC port-88 transaction produces both target
  WFP and KDC audit evidence, the exact target-side Event 5156 renders before every 4768, 4769, or
  4771 bound to that transport. Both rows remain inside the canonical transport lifetime after the
  DC clock and source latency are applied.
- **Entry paths:** baseline Kerberos connections, connection-triggered TGT/TGS repair, explicit
  fresh-account exchanges, failed pre-authentication with wire evidence, machine-account traffic,
  and higher-level authentication bundles that delegate to the network contract.
- **Consumers:** Windows Security rendering, KDC/WFP tuple joins, machine-logon ticket ordering,
  source-timing checkpoint/retry state, deterministic causality probes, and blind detection review.
- **Layer rationale:** canonical connection materialization already owns the exact tuple and WFP
  dependent event. The inversion occurs because connection-triggered KDC audits publish before the
  target WFP frontier is admitted and carry no exact transport dependency. Bind that canonical
  transport to the KDC occurrence and constrain it in shared source timing; do not rewrite emitter
  timestamps.
- **Sibling risks:** cached-TGT flows may legitimately omit 4768; standalone KDC audit events
  without modeled transport retain their existing timing; denied/unanswered connections must not
  acquire successful WFP/KDC evidence; short transports must fail safely rather than render audit
  rows after close; source-side WFP and remote-auth ordering remain unchanged.

## Loop 68 Result

- **Fix:** successful KDC audit intent now travels through the canonical port-88 connection
  request. Target-side 5156 publication precedes transport-bound 4768/4769/4771 source timing,
  including outbound/inbound baseline profiles, DC cycles, logon tickets, machine-account traffic,
  and visible failed pre-authentication.
- **Implementation commits:** `ec461d22f` and `b7624c7cf`.
- **Behavior contract:** revision 32, surface digest
  `921a464f493e07f915d0be797cf97bd48becb090e2503481f30aac8c9cdbf5bb`.
- **Verification:** 8,401 routine tests passed, 5 skipped, 2,009 deselected; Ruff check and format
  check passed for 769 files; 92 config files validated; scenario validation retained 24 existing
  informational findings.
- **Rendered probe:** DC-01 1,302/1,302 and DC-02 1,386/1,386 exact matched KDC rows followed target
  WFP admission; zero inversions.
- **Automated eval:** PASS, 96.38261128510587 over 122,597 records. Pillars: parseability
  99.9991843193553, plausibility 96.86081360171023, causality 94.37888817496561, timing
  92.8646527256516.
- **Initial blind panel:** Threat 68 (Synthetic/80), Detection 43 (Inconclusive/82), Network 29
  (Real/73), Host 92 (Synthetic/96); mean 58.0, mixed/inconclusive.
- **Deliberation:** triggered by verdict disagreement and 63-point spread. Revised scores: Threat
  82, Detection 78, Network 58, Host 93; mean 77.75, likely synthetic.
- **Fix regression:** the loop-67 KDC/WFP inversion did not recur in any initial report.
- **Next family:** make controlling terminal identity immutable for each continuing interactive
  shell; the panel found 71 sudo rows across 14 shells and 11 hosts rotating among multiple
  `pts/*` devices without a new shell/session transition.

## Loop 69 Family Contract

### Immutable controlling terminal for a continuing Linux session shell

- **Classification:** `family_level`; loop-68 `hard_contradiction` across eCAR process identity and
  sudo syslog on 11 Linux hosts.
- **Owning abstraction:** the Linux sudo session route owns the exact logon/session-to-TTY binding;
  the per-session shell and all sudo children consume that binding.
- **Invariant:** one live Linux interactive or SSH session and its continuing shell process may
  publish at most one controlling terminal. A later sudo request routed to that same session must
  reuse its existing `pts/*`; a different terminal requires a separately owned session and shell.
- **Entry paths:** baseline extra-syslog sudo activity, typed sudo action bundles, pre-window
  carried-in sessions, SSH-owned sessions, and direct generator compatibility calls.
- **Consumers:** syslog sudo command rendering, PAM open/close rows, eCAR parent/child process
  identity, foreground serialization, strict lifecycle retention, checkpoint state, and blind host
  correlation.
- **Layer rationale:** syslog already renders the effective TTY returned by the generator. The
  contradiction is created earlier when different requested TTYs are allowed to bind to one reused
  session shell, so enforcement belongs in the session-route owner rather than the emitter.
- **Sibling risks:** concurrent sessions for one user must retain distinct terminals; closed
  sessions must release their routes; a malformed multi-TTY reverse route must fail closed;
  foreground timing and strict lifecycle rollback remain unchanged.

## Loop 69 Result

- **Implementation commit:** `72de4fb4e` (`fix: keep Linux session TTY identity stable`).
- **Behavior contract:** revision 33,
  `a1de251c88268c81cd920a8d23ff49da1ca08eb36b1b35a8d9f6067c2f28f7ff`.
- **Verification:** 8,402 routine tests passed, 5 skipped, and 2,009 deselected; Ruff check and
  format check passed across 769 files; all 92 configuration files validated; the scenario remained
  valid with the existing 24 informational pivot notes.
- **Rendered invariant:** 78 sudo rows correlated across 18 continuing shells and 11 hosts; maximum
  controlling terminals per shell was one, with zero violations. Two source-locally unobserved eCAR
  creates were excluded from the join.
- **Automated evaluation:** 97.04987119847662 PASS across 124,332 records (parseability
  99.99919570183059, plausibility 96.85872154275857, causality 97.12464221795368, timing
  92.77135773874691).
- **Initial panel:** Threat Hunter 44 (Inconclusive, 79 verdict confidence), Detection Engineer 76
  (Synthetic, 86), Network Forensics 65 (Synthetic, 82), Host/EDR 72 (Synthetic, 84); mean 64.25.
- **Deliberation:** triggered by verdict disagreement and a 32-point spread. Revised scores were
  68, 78, 72, and 77; mean 73.75 with four Synthetic verdicts.
- **Target-family disposition:** the loop-68 multi-TTY continuing-shell contradiction did not recur
  in the rendered probe or any initial expert report.
- **Next family:** replace the 120-of-120 integer-millisecond SMB mapping offsets with
  source-native, microsecond-textured tree-connect timing owned by the SMB action/timing layer.
