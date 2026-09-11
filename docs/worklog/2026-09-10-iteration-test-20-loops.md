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
