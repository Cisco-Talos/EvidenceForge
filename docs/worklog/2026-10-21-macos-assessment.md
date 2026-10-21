# macOS assessment and implementation follow-through

The user authorized the complete sequence: create a durable mixed-fleet Mac
benchmark, assess supported sources first, complete ES metadata integration,
create a separate native-source benchmark revision, assess again, use findings
to guide behavior/catalog work, and finish acceptance/documentation. Commits and
pushes are checkpoints, not requests to stop. Existing local logs remain off limits
without asking; fresh synthetic output from these runs is authorized for review.

## Initial benchmark and reviewer preparation

- Starting implementation: `72870121` on `codex/macos-workstation-support`.
- Existing implementation handoff remains
  `docs/worklog/2026-10-15-macos-workstation-implementation.md`, revision 326.
- CLI-created Schema 3 draft UUID: `65a8d457-254d-4664-bceb-11d42bda468b`.
  Complete tracked snapshot: `scenarios/macos-assessment/revisions/01-supported/`.
  Original managed draft retained under `.eforge/artifacts/drafts/`.
- Scenario-local fictional software company, three users/four systems, six hours
  plus one-hour warmup, seed 327, complete observation, default output target.
  Revision 1 is frozen for comparisons after loop 1 starts. ES is unselected.
- Validation: no errors, one intentional no-firewall warning, four informational
  pivot advisories between independent user/maintenance activities.
- Updated personal `eforge-assess` skill in place: shared platform/collection
  interpretation, macOS expertise in all four personas, conditional companion
  expectations, process/exec/audit ownership and launch/policy lifecycle semantics.
  Changes preserve scoring and blindness rules. `quick_validate.py` passes under
  the project's uv runtime (system Python lacks PyYAML).
- Reviewed replacement files and original backups are retained at
  `/private/tmp/eforge-assess-macos-reviewers-20261021/`; originals in `original/`.
  Installed files: `SKILL.md`, `references/expert-briefing.md`,
  `references/expert-personas.md` under `/Users/dabianco/.codex/skills/eforge-assess`.

## Loop 1

- Fresh bundle requested at `/private/tmp/eforge-macos-assessment-20261021-loop1`
  using `--checkpoint-hours 1`. No existing output was replaced.
- First generation failed at collection hour 1: baseline sudo selected the
  Windows-based administrator on the Linux server, but the deployment compiler
  had no exact target-host user profile. Checkpoint retained; no local logs read.
- Family contract before repair: deployment compilation owns runtime user-profile
  eligibility. Every planner-eligible SSH administrator and explicitly authored
  session/process actor needs an exact target-host/platform profile before runtime
  artifact publication. Ordinary activity placement continues to own user software
  installation; remote eligibility must not install every user's applications.
  Entry paths: baseline SSH/sudo and authored logon/SSH/RDP/process events.
  Consumers: session/process bundles, runtime content, deployment identity and all
  rendered endpoint sources. This is a compiler-to-world-model integration repair,
  not a renderer workaround. Disabled/unplaced/noneligible users remain excluded.
  Raw records and system-owned artifacts retain their separate contracts.
- First completed baseline, quantitative evaluation and blind-panel details follow below.

The next fresh attempt reached SSH close and failed because the exact SSH terminal
publication participant allowlist excluded the already-supported Windows client
process sources. Family owner: dispatcher source transaction admission. Invariant:
all selected built-in endpoint sinks for a canonical SSH close participate in the
same authenticated journal, including Windows-source clients; omissions preserve
the existing observation/collection contract. Entry paths are baseline/authored
SSH and transfer clients sharing teardown; consumers are eCAR, Syslog, Security
and Sysmon. Use existing Windows/Sysmon exact sink authentication. Do not drop
Windows rows or redirect teardown into a separate publication path. Native ES
exit remains outside this profile.

The initial authored user-shell denial caller was unavailable: fresh instrumented
canonical state showed a foreground `emacs -nw` with no modeled end occupying that
shell. Rejecting another foreground command was correct. The speculative shared
readiness change was removed. Before establishing the first successful baseline,
the authored denial was corrected to use the already retained root maintenance
caller at +3h20m; no nonexistent child/caller is fabricated. The first completed
baseline will freeze this authored revision. Foreground baseline scheduling remains
an assessment topic; generated records were not edited. Instrumentation lived only
in `/private/tmp/eforge-macos-assessment-debug.py` and read fresh canonical state.

An early full routine run was interrupted for investigation after 89 passes;
it also found the format inventory count stale after ES registration (27 versus
28). The count and explicit ES-source membership assertion are corrected.

## Frozen supported-source baseline

- Successful fresh bundle: `/private/tmp/eforge-macos-assessment-20261021-loop1-attempt10`.
  CLI exit 0, hourly checkpoints, 24 data files / 6,355,572 bytes. No existing output
  was replaced (the CLI staging finalizer prints its generic replacement message).
- Frozen authored SHA-256: `57d395c554077b1c4afc8a58a9fb0255fabba3879bd1ad650da7d1ccd9bd3299`.
  Manifest SHA-256: `6866fd518c6c864ebcde485728aa3900a93d150f8c562f7edd7b3c73242aab11`.
  Full provenance is under `scenarios/macos-assessment/blind-test/loop-1/`.
- Neutral reviewer directory: `/private/tmp/field-study-20261021-a/dataset`.
  Only the freshly generated `data/` tree was copied; no manifests, ground truth,
  authored input, eval reports, implementation notes or diagnostic logs.
- Authored-source evaluation initially falsely rejected a format-order difference:
  the manifest sorts its inventory but unfiltered runtime input preserves order.
  Evaluation now applies the verified resolved runtime's ordered format selection
  before comparison. Actual source changes still reject. Five CLI evaluation tests
  pass, including the two new match/drift cases. No mismatch override was used.
- Initial quantitative evaluation: 11,409 records / 17 families; overall 90.0,
  acceptance FAIL, 8 eCAR format-constraint failures. Schemas parse 100%; canonical
  invariants and declared completeness 100%; distribution/realism diagnostics 64.
  All eight failures are the already-rendered bounded Mac SSH PROCESS/MODIFY
  operations missing from the old object/action combination rule. Preserve this
  baseline report; assess a constrained validator repair in the next loop.
- Six native Studio helper/ownership tests pass unsandboxed (16.59s). The preceding
  sandboxed full run was stopped after 1,133 passes and native helper readiness
  failures; the complete routine gate is now running outside the sandbox.
- Focused gates: 28 deployment tests; 80 combined deployment/format/session tests
  (the speculative session change was later removed); 607 process/activity/behavior
  tests; four slow denial/exact Windows SSH cases (28.84s); four existing slow
  exact SSH admission/capacity cases (1.31s). Final frozen validation is pending.
- Blind panel completed with four isolated fresh-context reviewers and the updated
  briefing. Verdicts unanimously Synthetic; synthetic-confidence 82, 82, 84, 84
  (average 83); verdict confidence 94, 90, 94, 93 (average 92.75). No deliberation
  triggered. Unchanged reports, canonical scores and the prioritized REPORT.md are
  retained. No prior findings/eval scores were supplied to reviewers.
- The full unsandboxed routine run finished: 16,045 passed, 50 skipped, 2,299
  deselected, four failures in 996.89s. All four were stale registration fixtures:
  ES missing from reviewed format inventory, positive flat-header witnesses and
  codec-emitter ownership expectations; merged configuration file count 97→99.
  The reviewed census adds only the traced ES adapter, preserving earlier manual
  path annotations; wholesale static regeneration would lose dynamic traces.
  The fixture repairs retain strict closed inventory assertions and the separate
  complete nested native-codec contract. All 324 corrected contract/routing gates
  pass. Ruff, formatting (1,314 files), whitespace and revision-327 manifest checks
  pass. The next chronology regression is intentionally red and not included in
  the baseline checkpoint commit.

## Next assessment-fix family contracts

Source-visible process birth is owned by SourceTimingPlanner. All eCAR process
starts (ordinary, system and POSIX fork) must publish their final admitted birth
after session, parent and execution constraints. Later image, credential,
job-control, endpoint dependents and termination must consume that same frontier;
parent close must contain child birth. Do not confuse fork actor/parent with the
subject/child. Entry paths include authored/baseline SSH, transfer receivers,
ordinary processes and system starts. Source omissions remain source-local, and
Sysmon native/envelope clocks remain distinct. A real production-timing Mac SSH
fixture reproduces the five loop-1 inversions; test both supported login shells.

eCAR record validation separately owns the finite PROCESS/MODIFY vocabulary.
Admit exec/audit_bind/privilege_drop/service_drop/job_control only with bounded
before/after identities and operation-specific facts. Unsupported operations and
inconsistent execution identities/images must still fail. Validator repair alone
does not resolve the source-visible lifecycle defect or improve the frozen data.

## Next engineering joins after the frozen baseline

Native fork admission still needs the real SSH metadata producers. Keep static
signing separate from runtime validation, known unauthenticated audit origin
separate from absence, and fork inheritance separate from later authentication.
Source gates remain ES-R1 (native macOS 26 exec/exit reference) and GK-R1 (terminal
Gatekeeper denial reference); do not infer completion from synthetic fields.

Primary static-vocabulary evidence found without inspecting local binaries/logs:
Apple's OpenSSH `xcconfigs/base.xcconfig` declares the product identifier from its
actual target name; the project names SSH helpers individually. Source:
https://github.com/apple-oss-distributions/OpenSSH/blob/main/xcconfigs/base.xcconfig
and https://github.com/apple-oss-distributions/OpenSSH/blob/main/OpenSSH.xcodeproj/project.pbxproj.
Public source copies for investigation are in `/private/tmp/eforge-macos-base.xcconfig`,
`eforge-macos-openssh.xcconfig`, and `eforge-macos-openssh-project.pbxproj`.
This supplies build vocabulary, not proof of a current-build signature or trust
outcome. Do not copy `CODE_SIGN_IDENTITY = -` from this developer build into native
production claims. Known modeled validation must be selected independently.

SSH wrapper launch currently lacks canonical environment/directory/security and
explicit unauthenticated audit facts; its exec phases bypass the metadata producer.
The existing launchd/root equality guard assumes unknown audit origin. Any change
must preserve legacy unknown state and distinguish explicit model facts. SSH
launchd-inetd standard I/O refers to the transport, so do not label it /dev/null to
satisfy a complete descriptor requirement. Fork notifications do not require an
invented complete exec descriptor table. Native ES exec remains separately gated.
