# Iteration Test Expanded IDS Assessment Loops 55-59

Scenario: `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded-ids/scenario.yaml`

This set begins at commit `90a997db`. Per user direction, Loop 55 uses the latest Loop 54
findings as its starting context and first validates the committed process-native Windows file
change. Each loop still regenerates the corpus, runs automated evaluation, and uses an isolated
data-only blind panel before selecting the following family fix.

## Starting Priorities From Loop 54

1. Verify generic numeric `C:\Windows\Temp` Event 11 creation is absent while installer/update
   and user-shell process-native temp artifacts remain.
2. Complete SSH and finite-command process lifecycles.
3. Remove universal one-direction source timestamp signatures.
4. Make SSH concurrency and DHCP renewal behavior stateful rather than host-periodic.

## Loop 55

- Generated 82,076 records from commit `90a997db`; automated evaluation scored 95.64
  (Parseability 100.00, Plausibility 97.24, Causality 88.84, Timing 95.60).
- The Loop 54 process-native file probe passed: 11 Sysmon Event 11 records and zero generic
  five-digit `C:\\Windows\\Temp` artifacts.
- Fresh initial synthetic-confidence scores were 48 (Threat Hunter), 68 (Detection), 32
  (Network), and 74 (Host/EDR), averaging 55.5. Verdict disagreement triggered deliberation;
  revised scores were 60/76/49/78, averaging 65.75.
- The panel ranked a bare, 43-minute `runas.exe` process that nevertheless produced successful
  Event 4648 evidence as the strongest hard contradiction.

### Explicit-Credential Family Contract

- **Owner:** `ExplicitCredentialUseActionBundle` owns the generated caller process, successful
  Event 4648 occurrence, and one-shot caller lifecycle.
- **Invariant:** a successful generated `runas.exe` caller exposes `/user:<target>` and a target
  command; Security, Sysmon, and eCAR share its PID/image; a bundle-created caller terminates
  within seconds. A caller supplied by another action retains that action's lifecycle ownership.
- **Entry paths:** baseline administrative activity, typed storyline `explicit_credentials`,
  command-derived explicit credential use, and direct activity-generator compatibility calls.
- **Consumers:** Security 4648/4688/4689, Sysmon 1/5, and eCAR process create/terminate and auth.
- **Sibling risk:** MMC, PowerShell, PsExec, WMIC, and scheduled-task credential callers must not
  gain misleading command semantics or have externally owned processes terminated by this bundle.

## Loop 56

- Generated 84,790 records from commit `17f73d05`; automated evaluation scored 95.99
  (Parseability 100.00, Plausibility 97.20, Causality 90.21, Timing 95.70).
- The Loop 55 explicit-credential probe passed: the only generated `runas.exe` contained
  `/netonly`, `/user:marcus.chen`, and a target command, and terminated after 6.304 seconds.
- Fresh initial synthetic-confidence scores were 36 (Threat Hunter), 24 (Detection), 66
  (Network), and 67 (Host/EDR), averaging 48.25. Verdict disagreement and a 43-point spread
  triggered deliberation; revised scores were 45/34/58/64, averaging 50.25.
- The panel ranked repeated SSH persona/host activity as the broadest concern. The selection
  rubric first prioritizes the confirmed P1 lifecycle defect: one SCP transfer split receiver
  authentication and file ownership across two sibling `sshd` processes and left one unclosed.

### SSH Receiver Lifecycle Family Contract

- **Owner:** `SshSessionActionBundle` owns the receiver transport/auth/session process lifecycle;
  `ScpReceiverFileActionBundle` consumes that live tuple-owned responder for file evidence.
- **Invariant:** one modeled SSH tuple has one privileged responder identity; dependent SCP file
  evidence uses that identity before the responder terminates; every visible closed responder
  produces matching process-termination evidence.
- **Entry paths:** typed storyline SSH, storyline SCP, baseline remote administration, generic
  Linux SSH compatibility, and deferred session finalization.
- **Consumers:** Linux sshd/PAM/logind syslog, eCAR FLOW/USER_SESSION/PROCESS/FILE, and Zeek SSH
  transport evidence.
- **Layer rationale:** lifecycle and tuple identity belong to the SSH action bundle and state;
  receiver file generation is an adapter that must run before bundle-owned closure.
- **Sibling risk:** SSH activity frequency and role placement remain distribution concerns; this
  fix does not reduce session count or redesign administrator destination policy.

## Loop 57

- Generated 84,789 records from commit `00a36029` plus the public SSH-adapter correction;
  automated evaluation scored 95.99 (Parseability 100.00, Plausibility 97.20, Causality 90.21,
  Timing 95.70).
- The selected Loop 56 SCP contract passed: its file artifact used the authentication-owned
  receiver PID, only one receiver process was created for that tuple, and it terminated.
- A broader diagnostic found 120 closed SSH responder incarnations with visible process
  creation; 85 had visible termination and 35 did not. These were compatibility-owned sessions,
  not a failure of the selected deferred-SCP path.
- Fresh initial synthetic-confidence scores were 53 (Threat Hunter), 29 (Detection), 68
  (Network), and 34 (Host/EDR), averaging 46.0. Verdict disagreement and a 39-point spread
  triggered deliberation.
- Deliberation revised the scores to 57/42/69/45 (mean 53.25) and selected routine SSH/RDP
  scheduling and role affinity as the top family-level improvement.

### Routine SSH Scheduling Family Contract

- **Owner:** the world-planned Linux remote-administration scheduler owns routine session
  admission, administrator/target placement, reuse, and command activity; `SshSessionActionBundle`
  owns the resulting transport/auth/process lifecycle.
- **Invariant:** ambient syslog generation cannot independently create remote-admin sessions.
  Each admitted routine SSH session must arise from one role-aware scheduling decision and may
  reuse an already valid session instead of adding an unrelated short connection.
- **Entry paths:** hourly Linux remote administration through `WorldPlanner`; typed storyline and
  explicit SSH/SCP events remain separate authored intent, not baseline noise.
- **Consumers:** source client processes, Zeek/endpoint FLOW, receiver sshd/PAM/logind, shell
  commands, and process termination evidence.
- **Layer rationale:** session admission and role affinity belong above canonical events; syslog is
  a renderer/ambient source family and must not be an independent behavior planner.
- **Sibling risk:** RDP density and the still-open compatibility SSH responder lifecycle remain
  follow-up concerns; this consolidation deliberately does not change authored attack sessions.

## Loop 58

- Generated 78,878 records from commit `316f0da7`; automated evaluation scored 95.77
  (Parseability 100.00, Plausibility 96.70, Causality 89.57, Timing 96.00). The evaluator's
  overall acceptance failed because pivot linkability was 50.0 against an 80.0 hard threshold.
- The selected routine-SSH scheduling probe passed. Successful core SSH sessions fell from 133
  to 48 (63.9%); the top three clients fell from 46.2 to 27.57 aggregate session-hours, and their
  peak concurrency changed from 7/7/5 to 6/4/2.
- Fresh initial synthetic-confidence scores were 58 (Threat Hunter), 25 (Detection), 69
  (Network), and 76 (Host/EDR), averaging 57.0. Deliberation revised them to 68/51/73/82
  (mean 68.5) and selected closed SSH responder lifecycle as the top hard contract gap.

### Compatibility SSH Responder Lifecycle Contract

- **Owner:** `SshSessionActionBundle` binds the tuple-scoped receiver `sshd` process to the
  canonical SSH session; the generic logoff bundle owns closure for compatibility sessions.
- **Invariant:** when a successful SSH close is visible, the exact receiver `sshd` incarnation is
  discoverable through the session index and produces coherent process termination evidence.
- **Entry paths:** generic Linux Type 10 logon compatibility, world-planned SSH bootstrap,
  immediate action-bundle closure, deferred SCP closure, and later generic logoff.
- **Consumers:** eCAR PROCESS/USER_SESSION/FLOW and Linux sshd/PAM/logind syslog.
- **Layer rationale:** the responder is materialized before auth assigns final session identity;
  late binding belongs in `StateManager`, which must also refresh its session secondary index.
- **Sibling risk:** long-lived taskhostw processes and domain-controller outbound role leakage are
  independent families and remain queued for the final loop.

## Loop 59

- Generated 78,916 records from commit `84294984`; automated evaluation scored 95.72
  (Parseability 100.00, Plausibility 96.50, Causality 89.57, Timing 96.00). Pivot linkability
  remained the sole hard acceptance failure at 50.0 versus the 80.0 threshold.
- The selected SSH responder lifecycle contract passed: 45 successful SSH closes were visible;
  all seven whose exact responder process creation was also visible had the matching process
  termination, with zero missing.
- Fresh initial synthetic-confidence scores were 74 (Threat Hunter), 69 (Detection), 24
  (Network), and 72 (Host/EDR), averaging 59.75. Deliberation revised them to 78/76/46/79
  (mean 69.75) and selected endpoint application/file ownership as the top hard contradiction.

### Email Endpoint File-Ownership Family Contract

- **Owner:** the modeled recipient access application owns message-cache and attachment paths;
  email endpoint generation selects those paths from the actual process image.
- **Invariant:** Outlook alone may own `RoamCache` and `Content.Outlook`; Chrome/Edge use their
  browser cache and Downloads paths; Thunderbird and Windows Mail retain application-native
  locations. Actor/path cross-products that cannot occur are forbidden.
- **Entry paths:** recipient delivery/read evidence over OWA/browser, Outlook, Thunderbird, or
  Windows Mail, including messages with attachments.
- **Consumers:** Sysmon Event 11 and eCAR FILE records, their actor process identity, and hunting
  pivots from message/attachment artifacts.
- **Layer rationale:** the owning application is already canonical process truth, so path
  selection belongs in email endpoint artifact generation before emitters render it.
- **Sibling risk:** RuntimeBroker generic file ownership and `taskhostw.exe` lifecycle remain
  broader endpoint families; Loop 59 is the last requested loop, so this final fix has focused
  unit verification but no Loop 60 regenerated corpus.

## Post-Loop 59 Pivot Contract Corrections

The five remaining Loop 59 pivot failures reduced to two distinct code defects rather than five
generator failures:

- Four edges touched `evt-024`, a workstation-lock request issued while Aisha's existing
  interactive session was already locked. Suppressing a second Windows 4800 was realistic, but
  the storyline ground truth incorrectly labeled the authored request as emitted and evaluation
  therefore required phantom evidence.
- The fifth edge touched `evt-032`, whose account deletion was correctly rendered as Windows 4726
  for `svc_mhsync`; the causality matcher recognized account creation (4720) but not account
  deletion (4726).

The workstation-lock action bundle now returns a typed outcome. Storyline execution records
`workstation_already_locked` as an emitted-false ground-truth no-op, and coverage/pivot evaluation
excludes such generation-contract no-ops while reconnecting the surrounding expected-visible
narrative. The Windows matcher now recognizes 4726 with host and target-account agreement.

Fresh generation from the canonical scenario produced 78,920 parsed records across 20 sources.
`evt-024` was recorded with `emitted: false` and
`skipped_reason: workstation_already_locked`; `evt-032` remained emitted with target account
`svc_mhsync`. Deterministic evaluation scored 97.73 overall and 97.83 for causality, passed every
hard acceptance criterion, and raised pivot linkability from the prior 31/62 (50.0) to 67/67
(100.0) with no pivot failures. Event presence was 45/45 expected-visible events (100.0), with the
single truthful no-op reported separately from the raw 45/46 result. Affected-family validation
passed 699 tests, and the complete non-slow suite passed 5,327 tests with 41 skips.
