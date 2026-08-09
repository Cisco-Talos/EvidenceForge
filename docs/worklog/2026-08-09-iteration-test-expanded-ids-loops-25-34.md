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

## Loop 27 Outcome

- **Commits:** `b96a96be fix: unify endpoint control software state`,
  `4a816bcc fix: preserve endpoint singleton planning`,
  `d5c6900a fix: enforce software cohort for network owners`, and
  `b7275437 fix: claim endpoint singleton intervals atomically`.
- **Verification:** final full suite passed with 5,105 tests and 41 skips;
  repository-wide Ruff lint and format checks passed.
- **Generation and eval:** 84,268 records; automated score
  96.25815833259675, PASS across every hard gate.
- **Hard probe:** Cisco was the only endpoint-control family (nine records),
  GlobalProtect and Zscaler were absent, and seven UI session groups had zero
  same-session visible overlaps.
- **Blind panel:** initial scores were 12/64/17/42, average 33.75. Deliberation
  triggered on verdict disagreement and a 52-point spread, ending Synthetic
  3-1 at 51.25 with final scores 54/67/26/58.
- **Target result:** every reviewer recognized the coherent endpoint-control
  cohort; none repeated the prior cross-vendor or singleton-overlap finding.
- **Highest next root contract:** idempotent Event 4672 privileged-authentication
  companion ownership per qualifying host and Logon ID occurrence.

## Loop 28 Family Contract

- **Selected family:** Windows Event 4672 privileged-authentication companion
  cardinality and timestamp repair.
- **Finding classification:** `new_family` canonical cardinality/timing defect.
- **Owning abstraction:** successful-logon action bundle plus Windows Security
  source-timing repair for reused interactive Logon IDs.
- **Invariant:** one qualifying 4624 occurrence produces at most one 4672
  companion; timestamp repair pairs that companion with its triggering 4624,
  never relocates earlier same-LUID companions beside a later unlock, and
  concurrent compatibility entry paths cannot duplicate the occurrence.
- **Entry paths:** interactive logon, workstation unlock Type 7, network/service/
  batch logon, RDP, remote-auth compatibility, and machine-account logon.
- **Consumers:** Windows Security XML, privileged-session detections, record-ID
  sequencing, auth timelines, and blind detection review.
- **Sibling risks:** preserve distinct privilege assignments for distinct logon
  occurrences, stable reused LUID semantics, 4624-before-4672 ordering after
  source delay, source-native submillisecond spacing, and standalone explicit
  4672 storyline events.

## Loop 28 Outcome

- **Commit:** `5c7786d6 fix: bind privilege events to logon occurrences`.
- **Verification:** 459 focused endpoint/emitter tests passed; final full suite
  passed with 5,107 tests and 41 skips; Ruff lint and format checks passed.
- **Generation and eval:** 84,268 records; automated score
  96.25815833259675, PASS across every hard gate.
- **Hard probe:** 1,080 Event 4624 rows and 379 Event 4672 rows; zero same-LUID
  excess 4672 companions without an intervening 4624.
- **Blind panel:** initial scores 11/30/17/42, average 25.0, all Real.
  Deliberation triggered only because the spread was 31 points and confirmed
  Real unanimously at 25.5 with final scores 14/29/20/39.
- **Target result:** Windows duplicate checks were clean and no reviewer repeated
  the prior privilege-companion cluster or record-ID timing finding.
- **Highest next root contract:** durable per-principal/session bootstrap
  ownership for long-lived desktop applications.

## Loop 29 Family Contract

- **Selected family:** long-lived desktop application bootstrap ownership and
  lifecycle reuse.
- **Finding classification:** `existing_family_sibling` beyond endpoint-control
  UIs.
- **Owning abstraction:** application-catalog lifecycle metadata and atomic
  per-principal/session singleton planning.
- **Invariant:** Google Drive, Slack, Zoom, Teams, VPN UIs, and comparable
  long-lived desktop applications have one bootstrap owner per host, principal,
  and logon session; later activity reuses the live instance, emits a legitimate
  child, or follows an observed terminate/restart transition.
- **Entry paths:** session startup, persona application sampling, network-process
  ownership, spawn rules, and catalog-driven background activity.
- **Consumers:** eCAR PROCESS lifecycle, Security 4688/4689, Sysmon Event 1/5,
  module loads, network attribution, and host forensic timelines.
- **Sibling risks:** preserve explicit multi-process helper architectures,
  separate user sessions, crash/restart behavior, updater children, storyline
  process intent, and atomic planning under parallel generation.

## Loop 29 Outcome

- **Commits:** `2942320d fix: preserve desktop application bootstrap owners`
  and `f5604488 fix: enforce desktop and session lifecycle ownership`.
- **Verification:** 407 focused lifecycle tests passed; final full suite passed
  with 5,114 tests and 41 skips; Ruff lint and format checks passed.
- **Generation and eval:** 83,152 records; automated score
  96.39949670786655, PASS across every hard gate.
- **Hard probe:** 34 top-level singleton application starts across 34 ownership
  groups, with zero overlapping owners.
- **Blind panel:** initial scores 18/32/17/58, average 31.25, and a 3-1 Real
  vote. Mandatory verdict/spread deliberation ended Synthetic 3-1 at 51.5 with
  final scores 56/54/29/67.
- **Target result:** reviewers found clean process/session lifecycles and did not
  repeat the desktop bootstrap overlap finding.
- **Highest next root contract:** durable role-aware state ownership for
  privileged host-configuration mutations.

## Loop 30 Family Contract

- **Selected family:** privileged host-configuration mutation state, beginning
  with timezone changes.
- **Finding classification:** `new_family` canonical state/lifecycle defect.
- **Owning abstraction:** host configuration state plus a privileged mutation
  action bundle that owns command intent and source-native companions.
- **Invariant:** each host has one durable effective timezone; a mutation is
  role-appropriate, changes from the current value to a new value, persists for
  later events, and cannot be contradicted by another baseline mutation without
  an explicit corrective workflow.
- **Entry paths:** baseline maintenance commands, catalog shell activity,
  systemd/timedate services, administrator sessions, and explicit storyline
  configuration changes.
- **Consumers:** eCAR PROCESS and configuration evidence, Linux syslog/polkit/
  systemd records, bash history, command attribution, and host timelines.
- **Sibling risks:** retain legitimate one-time provisioning, explicit attack or
  remediation mutations, regional host defaults, reboot persistence, correct
  privileged actor/session ownership, and cross-source ordering.

## Loop 30 Outcome

- **Commit:** `bfbe3ed3 fix: preserve host timezone configuration state`.
- **Verification:** 7 focused polkit tests and 14 extra-syslog configuration
  tests passed; all 87 config files validated; final full suite passed with
  5,115 tests and 41 skips; Ruff lint and format checks passed.
- **Generation and eval:** 81,856 records; automated score
  95.97420986025638, PASS across every hard gate.
- **Hard probe:** zero server timezone mutations, one workstation mutation, and
  zero repeated or contradictory host mutations.
- **Blind panel:** unanimous Real at 19/31/16/45, average 27.75; no deliberation
  trigger fired.
- **Target result:** no reviewer repeated the production-host timezone mutation
  finding.
- **Highest next root contract:** perimeter source-family observation-window
  clipping, independently selected by the threat and detection reviewers.

## Loop 31 Family Contract

- **Selected family:** perimeter collection/export window enforcement.
- **Finding classification:** `existing_family_sibling` repeated across Loops 28
  through 30 and now promoted to the sole target.
- **Owning abstraction:** source-observation profile boundary before native
  perimeter rendering.
- **Invariant:** no ASA or IDS record timestamp may exceed its declared source-
  family window; a connection opened in-window and closed after cutoff retains
  its in-window opening evidence while its unobserved teardown is absent.
- **Entry paths:** ASA build/teardown, NAT translation lifecycle, ACL deny,
  transport close, IDS alert delay, and source-observation jitter.
- **Consumers:** ASA syslog, IDS exports, collection-profile conformance checks,
  connection/NAT detections, and blind perimeter timelines.
- **Sibling risks:** preserve canonical transport duration for Zeek/endpoint
  sources with later windows, retain in-window partial lifecycles, avoid moving
  close events earlier, and apply clipping after source-native delay decisions.

## Loop 31 Outcome

- **Commit:** `e5f5aac8 fix: clip perimeter teardown observations`.
- **Verification:** 164 focused observation/ASA/dispatcher tests passed; final
  full suite passed with 5,117 tests and 41 skips; Ruff checks passed.
- **Generation and eval:** 81,851 records; automated score
  95.97420986025638, PASS across every hard gate.
- **Hard probe:** zero ASA rows at or after the half-open 18:00 endpoint.
- **Blind panel:** initial unanimous Real at 17/24/14/45. Mandatory 31-point
  spread deliberation confirmed Real 4-0 at 23/30/18/47, average 29.5.
- **Target result:** threat, detection, and network reviewers explicitly found
  the perimeter lifecycle/window behavior clean.
- **Highest next root contract:** durable per-principal/session/resource state
  for resident helpers and nominal singleton applications.

## Loop 32 Family Contract

- **Selected family:** resident desktop helper and nominal singleton lifecycle
  ownership (`gvfsd-smb-browse`, Outlook `/recycle`, and siblings).
- **Finding classification:** `existing_family_sibling` extending Loop 29's
  desktop bootstrap ownership to resource-scoped Linux helpers and Office apps.
- **Owning abstraction:** canonical process lifecycle state keyed by host,
  principal, logon session, executable, and resource identity.
- **Invariant:** one live resident owner exists for a session/resource key;
  repeated activity reuses it until an observed termination, while distinct
  shares, profiles, sessions, and helper roles remain independent.
- **Entry paths:** SMB browsing/mount activity, Linux desktop helpers, Office
  application catalog launches, spawn rules, session startup, and network owner
  materialization.
- **Consumers:** eCAR process/file/flow evidence, Windows Security/Sysmon process
  rows, bash history, SMB attribution, and host forensic timelines.
- **Sibling risks:** preserve legitimate multi-process Office helpers, separate
  SMB shares/resources, separate sessions, crash/restart behavior, explicit
  storyline processes, and bounded foreground commands.

## Loop 32 Outcome

- **Commits:** `b3cd49a0 fix: preserve resident desktop resource owners` and
  `07751e47 fix: reuse resident mail client owners`.
- **Verification:** final full suite passed with 5,120 tests and 41 skips; Ruff
  and configuration checks passed.
- **Generation and eval:** 83,526 records; automated score
  96.11941703495413, PASS across every hard gate.
- **Hard probe:** 13 resident-helper/mail-client ownership groups and zero
  overlapping owners.
- **Blind panel:** unanimous Real at 16/29/13/36, average 23.5; no deliberation
  trigger fired.
- **Target result:** no reviewer repeated the resident-helper or Outlook
  singleton-overlap finding.
- **Highest next root contract:** explicit proxy CONNECT accounting scope and
  canonical tunnel transfer totals.

## Loop 33 Family Contract

- **Selected family:** explicit forward-proxy CONNECT accounting.
- **Finding classification:** `contract_gap` in source-native accounting.
- **Owning abstraction:** proxy transaction action bundle and canonical
  client-to-proxy transport lifecycle.
- **Invariant:** CONNECT control-message bytes are unmistakably distinguished
  from full client-to-proxy tunnel transfer totals; duration and directional
  totals derive from the canonical transport, with documented units/scope.
- **Entry paths:** explicit HTTPS proxy setup, reused tunnels, denied/auth
  terminal outcomes, and raw compatibility events.
- **Consumers:** proxy access logs, Splunk JSON, SIEM parsers, bandwidth hunting,
  and Zeek/proxy cross-source pivots.
- **Sibling risks:** do not double count application rows, preserve cache/deny
  semantics, keep raw-event compatibility, and avoid inventing origin totals
  when the canonical transport does not expose them.

## Loop 33 Outcome

- **Commits:** `76421d75 fix: clarify proxy tunnel accounting`, `1f9e4f5d
  fix: annotate authored proxy tunnels`, `1f854be8 fix: omit unavailable proxy
  tunnel totals`, and `998d9942 fix: define proxy tunnel accounting fields`.
- **Verification:** 67 focused proxy/parser tests passed with 11 skips; config
  validation found zero issues across 87 files; full suite passed with 5,120
  tests and 41 skips; Ruff checks passed.
- **Generation and eval:** 83,526 records; automated score
  96.11941703495413, PASS across every hard gate.
- **Hard probe:** all 806 CONNECT rows declared control-message byte scope; 803
  exposed canonical tunnel totals/duration and three omitted unavailable totals.
- **Blind panel:** initial Real 3-1 at 23/29/12/92. Mandatory disagreement and
  80-point-spread deliberation ended Synthetic 4-0 at 80/79/64/94, average
  79.25.
- **Target result:** successful tunnel accounting correlated tightly, but failed
  terminal-state gating remained a narrower sibling gap.
- **Highest next root contract:** durable, causally triggered Linux daemon state
  telemetry, selected unanimously in deliberation.

## Loop 34 Family Contract

- **Selected family:** Linux daemon health and state-transition telemetry,
  beginning with rsyslog.
- **Finding classification:** `new_family` causal state defect.
- **Owning abstraction:** durable per-host daemon state plus explicit
  service/configuration mutation consequences.
- **Invariant:** reload, socket reacquisition, worker reconfiguration, and retry
  recovery messages require an owning state transition; ambient health rows may
  report only durable queue/checkpoint state and must evolve monotonically or by
  bounded stateful updates.
- **Entry paths:** ambient extra-syslog generation, service commands, config-file
  mutations, package/config management, SIGHUP, restart, and forwarding errors.
- **Consumers:** Linux syslog timelines, eCAR process/configuration evidence,
  shell history, SIEM daemon-health detections, and host forensics.
- **Sibling risks:** preserve daemon PID continuity, legitimate startup/reload
  evidence, role-aware services, bounded queue variation, deterministic output,
  and avoid fixed per-host caps as a new distribution fingerprint.

## Loop 34 Outcome

- **Commits:** `481a48d1 fix: preserve durable rsyslog health state` and
  `772ebabc fix: vary rsyslog health observation volume`.
- **Verification:** 154 focused system-traffic/config tests passed; config
  validation found zero issues across 87 files; final full suite passed with
  5,121 tests and 41 skips; Ruff checks passed.
- **Generation and eval:** 85,372 fresh records across 20 sources; automated
  score 96.416020607975, PASS across every hard gate, with 100% event presence.
- **Hard probe:** zero ambient reload/socket/worker/retry state-transition rows;
  50 durable rsyslog health observations across nine hosts with varied per-host
  counts from 2 to 10 and monotonic checkpoints.
- **Blind panel:** initial Real 3-1 at 17/30/12/89. Mandatory disagreement and
  77-point-spread deliberation ended Synthetic 3-1 at 68/63/31/93, average
  63.75.
- **Target result:** no reviewer repeated the unsupported rsyslog transition
  defect; the selected family passed.
- **Next backlog family:** stateful, role-aware monitoring with stable dependency
  inventories and supervised attempt lifecycles (bounded timeout, retry/backoff,
  cancellation, and worker replacement consequences).
