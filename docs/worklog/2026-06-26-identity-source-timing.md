# Identity Directory and Source Timing Realism

## Goal

Implement two Host/EDR reviewer-driven root-cause fixes on
`codex/host-edr-root-cause-fixes`:

- Model logical people separately from Windows and Linux platform accounts via a
  central identity directory while keeping existing scenario files valid.
- Add endpoint host-clock realism to source timing so Windows Security, Sysmon,
  syslog/bash history, and host-resident eCAR share host clocks, while network
  sensors remain independent appliance clocks.

## Initial Findings

- `EmitterSetupMixin._build_sid_registry()` owns the current Windows SID map and
  should become a compatibility export of the identity directory.
- Linux UID derivation is duplicated in the activity generator and SSH bundle,
  with syslog fallbacks using a third local implementation.
- `SourceTimingPlanner` already owns canonical-to-source render timestamps and
  is the correct root-cause layer for endpoint host-clock adjustment.
- Windows Security 4688 and eCAR PROCESS/CREATE are explicitly constrained after
  Sysmon Event 1 today, which creates a one-directional timing bias reviewers
  keep noticing.

## Implementation Summary

- Added `IdentityDirectory` as the central logical-person and platform-account
  model. Scenario users now default to Windows domain accounts when a domain/DC
  exists, host-local Windows accounts in workgroup environments, and
  directory-backed Linux accounts with stable UIDs unless overridden.
- Added optional `environment.identity` overrides with validation for duplicate
  explicit Windows SIDs and Linux UIDs.
- Replaced duplicated Linux UID helpers and Windows SID registry construction
  with identity-directory lookups. The existing `sid_registry` remains available
  as a compatibility export for emitters and older tests.
- Added endpoint host-clock timing to timing profiles. Windows Security, Sysmon,
  and host-resident eCAR now share a Windows host clock; syslog, bash history,
  and host-resident eCAR on Linux share a Linux host clock. Network sensors keep
  independent clock domains.
- Removed global one-way Sysmon-before-Security/eCAR process-create timestamp
  constraints. Causality still constrains lifecycle ordering, but sibling source
  timestamps now vary by source and host clock.
- Fixed a Host-review-discovered Windows 4624 issue where target Type 3/10
  events could copy the source host's local LUID into the target host's
  `SubjectLogonId`. Remote successful-logon subject fields now use the target
  host's local SYSTEM subject unless the event explicitly models a different
  subject.

## Validation

- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.
- Focused identity/timing/SID/config tests passed: 131 passed.
- Affected logon/activity tests passed: 44 passed.
- Full regression suite passed: 4530 passed, 19 skipped.
- `uv run eforge validate-config` passed: 0 errors, 0 warnings, 0 info items
  across 79 files.
- `uv run eforge validate scenarios/iteration-test/scenario.yaml` passed with
  the scenario's existing 16 standing warnings.
- Generated `scenarios/iteration-test/scenario.yaml` successfully after the
  fixes and `uv run eforge eval scenarios/iteration-test/output` scored 97/100
  over 77,848 records.

## Probes

- Process timestamp probe after host-clock changes found mixed source ordering
  instead of a universal Sysmon-first bias:
  - Security/Sysmon matched pairs: 777; Security before Sysmon: 511; after
    Sysmon: 266; equal: 0.
  - eCAR/Sysmon matched pairs: 772; eCAR before Sysmon: 473; after Sysmon: 299.
- Windows remote-logon subject probe after the 4624 fix found 0 copied source
  session LUIDs and 0 non-SYSTEM remote-logon subjects.
- Blind Host review before the 4624 subject fix scored synthetic-confidence 72.
  Its primary finding was target Windows 4624 Type 3/10 records leaking
  source-host local LUIDs in `SubjectLogonId`.
- Blind Host review after the 4624 fix scored synthetic-confidence 43 with an
  inconclusive verdict. It called Windows Security/Sysmon/eCAR, SSH, and bash
  correlations strong. Remaining findings focused on Linux syslog texture:
  high-volume journald capacity messages, regular sysstat cadence, thin UFW
  scanner long-tail texture, and a weak signal around Windows-like Linux eCAR
  session IDs. Those are follow-on realism backlog items rather than blockers
  for the identity and endpoint host-clock plan.
