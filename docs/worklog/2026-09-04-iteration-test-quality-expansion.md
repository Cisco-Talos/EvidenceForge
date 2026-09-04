# Iteration-Test Quality Expansion

## Scope

Expand the six-hour iteration benchmark around data-quality coverage: a second domain
controller, a Linux Samba server, a centralized log/monitoring server, database SPAN
visibility, cross-platform SMB activity, correlated remote administration, multipart
archive exfiltration, and a late benign SSH investigation. Preserve the historical
Meridian 1.0.0 pack and all prior blind-assessment reports.

## Authored changes

- Created project-local organization pack
  `project:davidjbianco:organization:meridian-healthcare-solutions@1.1.0` by copying
  the packaged 1.0.0 release.
- Added `DC-02`, `FILE-LNX-01`, and `LOG-MON-01`, Linux SMB clients and mappings,
  the XFS-backed `ClinicalResearch` Samba share, and `zeek-db`.
- Added the planned malicious and benign storyline beats while retaining the six-hour
  window, seed, warmup, observation profile, and output formats.
- Updated the attack-free environment briefing and scenario pack reference.

## Engine findings and fixes

1. Linux SMB source-only eCAR projection failed generation because endpoint source
   timing incorrectly required a target-local transport-close deadline. The source
   timing planner now accepts its preferred timestamp when that target-local deadline
   does not exist. A focused regression test covers the source-only projection.
2. Explicit DC-01 to DC-02 remote service installation originally selected the user's
   primary workstation for SMB/RPC. `service_installed` now accepts an optional
   `source_ip`, resolves it through the world model, and passes the resulting system to
   the Windows remote-service action bundle. The bundle remains the canonical owner of
   the SMB/RPC transport. A focused test verifies that an authored source overrides the
   user's primary system.

## Validation and generation

- Pack validation: valid. Meridian 1.1.0 digest:
  `3cbe51326bbb8bab04b6936c5e2d853d76eafb2bf73ddf5a24994db2e29ebec4`.
- Locked technology dependency unchanged:
  `11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.
- Scenario validation: 0 errors, 0 warnings, 24 informational pivot suggestions.
- Resolved composition: 21 systems, 49 storyline events, 10 red herrings, six sensors.
- Generation succeeded through hour 6 and atomically replaced the prior output.
- Generated corpus: 111,598 records across 22 parsed source families.

## Automated evaluation

- Overall: 95.8753 (96 rounded).
- Parseability: 99.9202.
- Plausibility: 97.0032.
- Causality: 92.2298.
- Timing: 92.9550.
- The requested overall threshold is met and no pillar is at or below 90.
- The evaluator's independent hard gate remains failed for temporal integrity
  (81.6327, threshold 85). Its reported misses are mainly pre-existing event-presence,
  pivot, and timing behavior; retain this as follow-up engine-quality work rather than
  expanding the current scenario-data effort.

## Focused evidence verification

- DC-01 to DC-02 now has Zeek SMB and DCE/RPC flows immediately before the target
  network logon and `DirectoryCacheSvc` creation/process evidence. Cleanup commands
  use the same target session context.
- `zeek-db` observes application-to-database MySQL traffic.
- Samba server syslog/eCAR and Zeek SMB records preserve Linux paths, XFS share
  identity, principals, authentication protocols, outcomes, and cross-platform client
  paths for mounted and direct clients.
- The staged ZIP read is owned by the generated `curl.exe` PID; proxy and ground-truth
  metadata agree on URI, multipart filename/MIME, decoded size 18,782,613 bytes, and
  the 2,048-byte response body (proxy wire bytes include protocol overhead).
- Priya's SSH transport/authentication precedes `journalctl`; no explicit authored
  logoff exists, and the action-owned lifecycle closes at the collection boundary.

## Assessment

A new standalone blind assessment was saved as `v2-loop-31`; prior loops and reports
remain unchanged. All four reviewers returned Synthetic verdicts with synthetic-confidence
scores of 95, 88, 96, and 86 (average 91.25). Deliberation was not needed because the verdicts
were unanimous and the score spread was only 10 points.

Final acceptance is blocked by new P0/P1 contradictions in the expanded families: inconsistent
Type 9 local-file principal ownership, Samba transfer effects attached to a directory-creation
process, impossible bidirectional/zero-payload UDP syslog accounting, and destination-as-source
Windows network-logon fields on the new DC. The full prioritized list is in
`scenarios/iteration-test/blind-test/v2-loop-31/REPORT.md`; lower-severity findings remain for
later engine-quality loops.

## Assessment loop 32 — endpoint effect ownership

### Family contract

- **Owning abstraction:** canonical process/session state and the HTTP-upload and SMB action
  bundles that attach endpoint file/network effects to a process.
- **Invariant:** a local file effect uses the owning process's local token principal even when
  the same process has outbound NewCredentials, and every SMB effect with PID/process identity
  is owned by a process whose executable/command can perform that SMB operation.
- **Entry paths:** storyline connection multipart staging, baseline and storyline HTTP uploads,
  Windows-native SMB, mounted-CIFS SMB, direct `smbclient`, causal file effects, and raw
  storyline process references.
- **Consumers:** eCAR process/file/flow records, Windows Security/Sysmon process companions,
  Samba audit, Zeek SMB/files/conn, ground truth, and endpoint ownership probes.
- **Layer rationale:** process state owns the local token and action bundles own effect-causing
  process selection. Renderer-only rewriting would leave sibling sources and future callers
  contradictory.
- **Sibling risks:** the fix must cover non-sample upload and SMB operations, avoid changing the
  remote SMB credential/effective identity, and preserve explicit capable process ownership.
  Broader actor-native Windows registry/file side effects remain outside this loop.

### Result

- Focused generated-data probe passed: local archive effects retain Aisha's local token,
  outbound upload credentials remain Marcus, the Windows SMB client uses Explorer rather than
  the unrelated `New-Item` PID, and Samba retains Marcus as the remote principal.
- Automated evaluation was 95.8246 across 111,587 records; temporal integrity remained below
  its hard gate.
- The blind panel returned four Synthetic verdicts with scores 99, 97, 94, and 98 (average
  97.0). The next dominant blocker is a repeated Sysmon native timestamp contradiction.

## Assessment loop 33 — atomic Sysmon process timing

### Family contract

- **Owning abstraction:** `SourceTimingPlanner`'s host-shared Sysmon process lifecycle pair.
- **Invariant:** Event 1 and Event 5 payload `UtcTime` and provider-envelope `TimeCreated` are
  projections of the same exact occurrence; an instance-local retained envelope may not be
  combined with a separately resolved native timestamp.
- **Entry paths:** baseline process starts/stops, storyline processes, RDP/SSH client processes,
  services, causal process companions, and collection-boundary finalization.
- **Consumers:** Sysmon Event 1/5, Security 4688/4689 ordering, eCAR process correlation,
  ProcessGuid identity, and dependent Sysmon Event 3/7/11/22 ordering.
- **Layer rationale:** the planner owns both timestamps as one canonical source-native pair.
  Repairing XML after rendering would leave ProcessGuid and sibling timing contracts stale.
- **Sibling risks:** preserve parent-before-child and create-before-dependent ordering, provider
  latency, deterministic rendering, exact-publication replay, and termination containment.
