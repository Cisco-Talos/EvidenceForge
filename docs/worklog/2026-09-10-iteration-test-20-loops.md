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
