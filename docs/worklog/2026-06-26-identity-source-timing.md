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

## Follow-Up Host Review Variance

Three additional blind Host-only reviews were run against the same post-change
dataset using neutral temp copies and no prior review context:

| Run | Assessment | Verdict confidence | Synthetic-confidence score |
| --- | --- | ---: | ---: |
| 1 | Synthetic | 76 | 66 |
| 2 | Real | 64 | 28 |
| 3 | Real | 61 | 34 |

Average synthetic-confidence score across these three reviews was 42.7. Including
the prior post-fix Host review score of 43, the four-review average was 42.8.

Common agreement:

- All reviewers praised endpoint lifecycle and cross-source correlation.
- All reviewers found no hard endpoint causality contradiction.
- Linux maintenance/syslog cadence remained the most repeated realism pressure.

Why reviewer 1 scored higher:

- Reviewer 1 weighted dataset-wide background texture much more heavily than the
  other two reviewers.
- Reviewer 1 found multiple medium/high-impact families in one pass: dense Linux
  journald capacity messages, GUI polkit agent churn on server roles, abstract
  DC remote-command ownership, Windows maintenance utility runtimes, and compact
  LSASS call-trace palettes.
- Reviewers 2 and 3 anchored more heavily on lifecycle correctness and treated
  the remaining findings as weak or explainable texture.

Reviewer 1 finding priority order:

1. Reduce high-volume Linux `systemd-journald` capacity-message filler. This is
   the highest-leverage item because it is dataset-wide, repeated across Linux
   server roles, and was also noticed by lower-scoring reviewers as related
   syslog cadence texture.
2. Gate Linux GUI/polkit authentication-agent records by desktop-capable host
   role and active graphical sessions. This is lower volume than journald, but it
   creates a clearer host-role plausibility tell on DB, proxy, app, and web
   servers.
3. Route DC remote-command execution through concrete owners such as PsExec, WMI,
   WinRM, Task Scheduler, or a service binary instead of generic
   `svchost.exe -k netsvcs` parentage. This repeated in reviewer 3 as a weak
   signal and is already in the roadmap as a P1 root-cause family.
4. Tune Windows maintenance utility runtime/cadence by host role and executable.
   Reviewer 1 called out `CompatTelRunner.exe` and `cleanmgr.exe`; this is
   medium leverage but broader and riskier than the first two Linux syslog fixes.
5. Diversify or source-image-bind Sysmon Event ID 10 LSASS call traces. This was
   a low-impact weak signal in reviewer 1 only, so it should follow the broader
   texture and ownership fixes.
