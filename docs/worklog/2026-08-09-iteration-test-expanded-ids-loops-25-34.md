# Iteration Test Expanded IDS Assessment Loops 25-34

Scenario: `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded-ids/scenario.yaml`

The scenario is read-only. Every loop regenerates fresh output, runs automated
evaluation, and gives only the current data plus collection profile to four
independent blind reviewers. Deliberation runs on disagreement, low confidence,
or a synthetic-confidence spread above 30 points.

## Loop 25 Family Contract

- **Selected family:** Windows failed-authentication attempt identity and
  mechanism-native Event 4625 semantics.
- **Finding classification:** `new_family` near-hard cadence and schema defect.
- **Owning abstraction:** failed-logon action bundle and Windows authentication
  realism configuration.
- **Invariant:** overlapping producers cannot emit duplicate native rows for one
  credential attempt; distinct interactive retries have human-scale cadence;
  batch failures use task-scheduler initiator fields rather than network-auth
  `NtLmSsp`/LSASS fields.
- **Entry paths:** baseline password typos, stale scheduled credentials,
  management sweeps, suspicious-benign bursts, and storyline failed logons.
- **Consumers:** Windows 4625, eCAR failed LOGIN, DC validation companions,
  source observation, and temporal evaluation.
- **Sibling risks:** preserve remote Type-3 transport/validation semantics,
  disabled/unknown account substatus, Linux SSH failures, deterministic output,
  and intentionally separate human retries.

## Loop 25 Outcome

- **Commit:** `cfd6e10a fix: model Windows authentication attempts`.
- **Verification:** 156 focused tests passed; config validation reported zero
  issues across 87 files; the full suite passed with 5,100 tests and 41 skips;
  repository-wide Ruff lint and format checks passed.
- **Generation and eval:** 80,540 records; automated score
  95.88367001274926, PASS across every hard gate.
- **Hard probe:** 26 Event 4625 rows across 13 attempt-identity groups; zero
  adjacent same-identity pairs within 500 milliseconds; minimum rendered
  interactive retry gap 1.947 seconds; all three Type 4 rows used
  Advapi/Negotiate/svchost with no network-origin fields.
- **Blind panel:** Threat Hunter 14, Detection Engineer 22, Network Forensics
  19, and Host Forensics 32; standalone average 21.75 (`mostly realistic`). All
  four verdicts were Real, every verdict confidence was at least 60, and score
  spread was 18, so deliberation did not trigger.
- **Target result:** no reviewer repeated the prior Event 4625 duplicate-attempt
  or mechanism-native schema finding.
- **Highest next root contract:** deployment-level software compatibility and
  role placement for remote-access/SASE and backup platforms.

## Loop 26 Family Contract

- **Selected family:** deployment-level enterprise-software compatibility and
  role-aware placement.
- **Finding classification:** `new_family` distribution and environment defect.
- **Owning abstraction:** activity software catalogs and host-role-aware process
  selection.
- **Invariant:** a deployment cohort uses one ordinary remote-access/SASE stack
  and one backup platform; simultaneous competing control planes require an
  explicit, time-bounded migration state; server-side backup binaries run only
  on eligible infrastructure roles, while workstations receive product-native
  endpoint agents where modeled.
- **Entry paths:** baseline service processes, workstation startup applications,
  monitoring/backup activity, and any storyline process using catalog entries.
- **Consumers:** eCAR process/module evidence, Windows 4688/Sysmon Event 1,
  software-presence hunting, host-role inference, and blind host review.
- **Sibling risks:** preserve deterministic per-environment selection, product
  diversity between deployments, legitimate endpoint agents, explicit attack
  processes, process lifecycles, and Linux/Windows OS constraints.

## Loop 26 Outcome

- **Commits:** `f17096f0 test: correct private IPv6 expectation` and
  `c0a01395 fix: constrain enterprise software deployments`.
- **Verification:** 241 focused tests passed; config validation and Ruff passed;
  final full suite passed with 5,102 tests and 41 skips.
- **Generation and eval:** 82,753 records; automated score
  95.9570292254711, PASS across every hard gate.
- **Hard probe:** one background remote-access stack (Zscaler), one backup
  platform (Commvault), zero competing background stacks, and zero Veeam
  server processes on workstations.
- **Blind panel:** initial 14/30/18/68, average 32.5. Deliberation triggered on
  disagreement and 54-point spread, ending Synthetic 3-1 at 56.5 with final
  scores 62/58/30/76.
- **Target result:** background services passed, but user applications remained
  an uncovered sibling entry path and reproduced the cross-vendor defect.

## Loop 27 Family Contract

- **Selected family:** stateful deployment-scoped endpoint control software
  across service and user-application catalogs.
- **Finding classification:** `existing_family_sibling` plus singleton lifecycle
  defect.
- **Owning abstraction:** shared application compatibility metadata and durable
  running-process state.
- **Invariant:** service agents and user UIs select the same deployment stack;
  one UI instance may be live per product, principal, and logon context; a new
  instance requires prior termination unless an explicit migration state exists.
- **Entry paths:** system service noise, persona user applications, session
  startup, spawn rules, and catalog-driven process effects.
- **Consumers:** eCAR, Security 4688, Sysmon Event 1, module loads, process
  network correlation, and host software inventory.
- **Sibling risks:** preserve multiple principals/sessions, explicit storyline
  processes, deterministic cohort selection, process termination, application
  diversity outside compatibility groups, and Linux behavior.
