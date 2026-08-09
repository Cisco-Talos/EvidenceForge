# World Capability and Distribution-State Remediation

Date: 2026-08-07

Branch: `codex/batch4-world-capabilities`

Parent: `b2f1dd68` (`fix: enforce network transaction projection contracts`)

## Scope

This is Batch 4 of the approved complete-realism remediation roadmap. It addresses
`REAL-008` (silent infrastructure role collapse) and `REAL-012` (fixed or independently sampled
source fingerprints). It does not reorder the master roadmap in response to blind-review scores.

## Executable contract

### World capabilities

- `WorldModel` is the sole compiler of host capabilities used by baseline and storyline planning.
- DHCP server, DNS resolver, domain controller, forward proxy, SSH receiver, and RDP receiver are
  distinct typed capabilities, derived once from scenario host type, roles, and services.
- Capability lookup excludes the requesting host whenever the real activity requires a distinct
  peer. An empty result remains empty; it never becomes `10.0.0.1`, `DC-01`, or the sole endpoint.
- Optional baseline activity skips a family when the required scenario capability is absent.
- An authored `dhcp_lease` action requires a distinct modeled DHCP server and fails scenario
  validation otherwise. This batch does not invent a public synthetic-infrastructure policy field;
  such a schema addition would require its own reviewed contract.
- Public infrastructure explicitly shipped as data configuration (for example public recursive DNS
  and NTP endpoints) is an external capability, not a synthesized scenario host, and is eligible
  only for activity that can realistically use public infrastructure.
- Renderers do not choose or repair infrastructure ownership.

### Scoped distribution state

- DHCP T1 is selected once per lease lifecycle. Renewals retain that lease-specific T1 interval;
  they do not independently resample the policy at each hour or renewal.
- OCSP response-file duration is planned per transaction from response size, responder-scoped
  transfer characteristics, and bounded deterministic jitter; it is not a constant renderer value.
- Ordinary DNS produces stable per-name AAAA capability and negative/NODATA texture while explicit
  authored answers remain authoritative.
- Linux IRQ/device evidence selects a coherent device profile as one unit instead of independently
  sampling IRQ, device, and CPU placeholders.
- GPO refresh behavior is host-scoped and data-driven, with ordinary refreshes dominating rare
  forced or target-specific invocations.

## Required gates

1. Unit tests for capability compilation, distinct-peer selection, missing-capability validation,
   no self-DHCP in one-host worlds, and public resolver fallback.
2. Unit/property tests for stable DHCP T1, non-degenerate OCSP duration, negative AAAA texture,
   coherent IRQ/device profiles, and varied GPO command morphology.
3. Minimal and mixed-role generations with the realism probe proving no infrastructure self-edge.
4. Integrated 24-hour complete and enterprise-standard runs, deterministic repeat comparison,
   evaluation, and targeted multi-day distribution probes.
5. Ruff checks and the complete non-slow suite before commit.

## Progress

- [x] Created feature branch from the completed Batch 3 commit.
- [x] Bound absent-capability behavior without adding an unreviewed public schema field.
- [x] Implement typed host capabilities and remove role-collapse fallbacks.
- [x] Implement lifecycle-aware distribution state.
- [x] Run empirical and regression gates.
- [x] Update the durable review package and commit the batch.

## Implemented ownership changes

- Added a typed `HostCapability` vocabulary and compiled DHCP, DNS, domain-controller, proxy,
  SSH, and RDP capability membership once in `WorldModel`.
- Removed synthetic or self-referential fallback peers from infrastructure discovery. Optional
  baseline families skip when no eligible peer exists; authored DHCP intent is rejected when a
  distinct modeled DHCP server is unavailable.
- Moved public recursive resolvers into validated `network_params.yaml` data and kept scenario
  hosts authoritative for private/domain resolution.
- Made DHCP renewal cadence lease-scoped, OCSP transfer duration transaction-scoped, ordinary
  AAAA availability stable per owner/name, IRQ/device/CPU morphology atomic, and GPO cadence and
  command morphology host-scoped.
- Preserved one observation decision across an OCSP transaction's Zeek HTTP, file, and OCSP rows.

## Verified sibling defects found by the gate

- Baseline scheduled-task definitions were materialized in configuration order, which could make
  Linux PID allocation appear to move backward in time. Occurrences are now planned and sorted by
  timestamp before process creation.
- SSH shell parent selection could create two `bash` processes for one session when the planned
  shell began milliseconds after a caller's preliminary anchor. Session shell lookup now reuses
  the single bundle-owned shell; dependent events clamp to its readiness time.
- Enterprise observation could retain the OCSP HTTP/file companions while dropping `ocsp.log`.
  The dispatcher now makes that source-local transaction decision coherently, and the realism
  probe verifies every OCSP HTTP file reference exists in `ocsp.log`.
- A no-internal-DNS host rotated queries among four unrelated public recursive resolver operators.
  Public fallback selection is now stable per client and operator, while retaining primary/secondary
  addresses within providers that publish both. The expanded probe reproduced one error in the old
  minimal output and three in the old seven-day output, then zero in both regenerated datasets.

## Empirical evidence

- Minimal output: `/private/tmp/eforge-batch4-minimal-v2`; zero probe errors and one stable Google
  public resolver family instead of four rotating operators.
- Six-hour mixed-role output: `/private/tmp/eforge-batch4-branch-office`; zero probe errors, one
  distinct modeled DHCP server, non-degenerate OCSP duration, and mixed AAAA answer/NODATA shape.
- Twenty-four-hour complete output: `/private/tmp/eforge-batch4-24h-complete-v3`; zero probe
  errors; evaluation passed with 91.981 over 173,812 records.
- Seven-day baseline output: `/private/tmp/eforge-batch4-7d-baseline-v3`; zero probe errors;
  evaluation passed with 96.111 over 199,734 records, and each of the three clients remains within
  one public recursive-DNS operator family.
- Enterprise-standard output: `/private/tmp/eforge-batch4-24h-enterprise-v5-final`; zero probe
  errors; evaluation passed with 92.341 over 167,854 records, including 100 cross-source
  agreement. It is byte-identical to the independently repeated post-OCSP output.

The evaluator's remaining indicator/pivot/diurnal notices are pre-existing scenario/evaluator
behavior outside this batch. An earlier seven-day output also exposed heuristic
process-termination pairing notices without a lifecycle-probe contradiction; evaluator treatment
of that proof gap remains scheduled for Batch 5.

## Final gates

- `uv run eforge validate-config`: 0 errors, 0 warnings, 0 info items across 87 files.
- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: 453 files already formatted.
- Focused final suites: 655 passed, 1 skipped.
- Targeted parallel slow suite: 5 passed.
- Complete non-slow suite: 5,172 passed, 41 skipped in 236.33 seconds.
