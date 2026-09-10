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
- **Invariant:** endpoint `DHCPREQUEST`, `DHCPACK`, and bound records are independently timed, remain causally ordered, and keep ACK observation close to the canonical network transaction close without copying one timestamp's microsecond suffix.
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
| 57 | DHCP phase timing; canonical parent principal | pending | pending | in progress |
