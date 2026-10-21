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

Native SSH metadata family: the frozen execution profile and canonical launch/exec
producer own system audit origin, responsibility, environment, directory, image
and validation choices. Boot, SSH wrapper launch and all SSH image replacements
must consume those owners. A selected explicit XNU default audit origin is
`AU_DEFAUDITID=uint32(-1), AU_DEFAUDITSID=0`, independent of an authenticated user;
older inputs with no policy stay unknown. Root admission and service privilege
drop must preserve that exact distinction and never manufacture authentication.
Primary vocabulary references (not current-host measurements):
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/bsm/audit.h and
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/security/audit/audit_session.c.
OpenSSH helper signing identifiers follow Apple's target-name vocabulary above;
hashes, signatures and successful validation are explicit synthetic model facts.
No private receiver renderer or native-row completion defaults are permitted.
Fork-only SSH startup may leave socket descriptor observations unknown; native
exec requires its existing strict descriptor contract and separate ES-R1 gate.

Cross-platform assessment contracts: NewCredentials owns a new authentication
LUID while preserving the caller's terminal session, without a second desktop
bootstrap. Failed-logon generation owns SSH mechanism and the single source tuple
for Linux network attempts, including self-directed SSH; the full existing SSH
failure lifecycle must render both views. eCAR should honor those explicit facts
rather than reclassifying same-host addresses as console input. Canonical TLS
construction owns both handshake progress and connection byte/packet accounting;
ServerHello requires responder payload, and all currently modeled full TLS 1.2
ciphers use ECDHE, requiring its key-exchange step. Fix these shared owners before
source rendering; preserve local console failures and TLS resumption/1.3 behavior.

Process/network ownership family: the process-network map owns whether an
executable may generate ambient traffic or be selected to own it. Destination-
bound CLI tools require a concrete parsed endpoint or an explicit canonical
connection/PID; neither a generic HTTPS role nor an already running CLI is enough.
Both forward correlation and inverse WorldPlanner attribution, including exact
application lists and compatibility entry, consume the same policy. Defaults
preserve old configurations; packaged Git/package/container/Kubernetes CLI entries
opt out of ambient traffic. Explicit authored/command-owned network intent stays
available. This prevents sibling local queries from inheriting unrelated SaaS
connections without matching specific hosts or reviewer commands.

## Revision 328 candidate and native benchmark preparation

- The real engine's ordinary successful SSH path produces three strict native
  fork/v10 records, with output selected or filtered independently of canonical
  State. Shared metadata supplies wrapper launch, each image replacement and
  current-directory observations at fork. Login shell HOME/USER/directory select
  the resolved account; transport socket descriptor observations remain unknown.
- Root admission, startup retention and credential projection accept only legacy
  unknown or explicit XNU default unauthenticated origins. Service drops preserve
  the exact origin; authentication adopts the modeled user ASID/AUID later.
- Focused validation: 335 metadata/boot/source/record tests; 531 activity/auth/TLS
  tests; 56 final targeted producer/ordering/ownership tests pass. Five selected
  slow native source/output/Windows SSH cases pass (11.12s). The complete routine
  suite is running unsandboxed against frozen implementation.
- `validate-config --json`: 99 files, no errors/warnings. Ruff and formatting pass
  (1,317 files), as do whitespace and behavior-against-HEAD checks. Candidate
  revision 328 digest: `e5c0520ae90c350ab1a8db9ad832324732878682b3e595cd4dfcbe38532fb30c`.
- Fresh baseline family probe independently reproduces 42 failures: five process
  transitions before birth, one child before parent birth, three NewCredentials
  terminal mismatches, 30 ECDHE histories missing key exchange and three
  ServerHello-without-payload cases. Persisted under loop 1; no old data changed.
- Native coverage is a separate CLI-created draft, UUID
  `9066de90-8a34-4cb9-a70c-645254ff53ed`, at `revisions/02-native/`. Same seed,
  environment, activities and window; adds ES explicitly. Validation has no errors,
  the same intentional firewall warning and four informational pivot advisories.
- Capture proposal and two independent C probes are prepared under
  `docs/design/macos-workstation-feasibility/native-reference-capture/`.
  Both compile with `-std=c11 -Wall -Wextra -Werror -pedantic`; neither ran. No
  native logs, local captures, settings, permissions or services were inspected or
  changed. The asynchronous lab/reference question remains pending.

## Historical engineering joins identified after the frozen baseline

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

## Native reference decision and final revision-328 gates

On 2026-10-21 the user explicitly chose **keep those native features gated for
now** for ES-R1 and GK-R1. No capture, local-log inspection, collector activation,
permission change or lab execution is authorized. The proposal and unexecuted
probe sources remain a future option; these evidence gates are a declared scope
boundary for the current sequence rather than pending implementation permission.

The earlier routine process ended before its final result could be recovered from
the tool session. Three stale test expectations found during that run were fixed
and passed their focused gates: Type 9 terminal placement, modeled SSH signing
selectors, and the native-format witness census/extension. A fresh complete
routine run is now executing against frozen production source. Two additional
slow gates exercise nonempty native output through the CLI, parser, source
filtering, fresh-process determinism and exact checkpoint suspension/resume.

Both new slow gates pass (44.59s): nonempty ordinary CLI fork output, fresh hash
seeds, ES-only filtering, strict ingestion, and exact suspended/resumed output
including six forks across the recovery boundary. The broad run found two further
bounded integration expectations: the self-directed SSH test must select the
failed-auth occurrence rather than a later lifecycle row, and canonical skill
references exceeded their existing line budgets. Both are corrected; the complete
affected gate passes 132 tests with one existing skip. No production source was
edited while the broad suite or checkpoint generators ran.

## Bounded developer-catalog contract for the next checkpoint

The remaining developer variants must name the actual loaded native runtime:
MSBuild through the existing .NET SDK host, npm through Node plus the bundled
`npm-cli.js`, pytest/pip through one selected CPython framework executable with
explicit `-m` module arguments, and platform-appropriate PowerShell queries through
the publisher's arm64 `pwsh`. A logical application installation selects its
module; it does not reconstruct a Homebrew private virtualenv, shebang wrapper,
shell script, filesystem inventory or native exec record. Shared runtimes retain
one product/release/content identity across logical applications. Query templates
must have bounded foreground lifetimes and no inferred package/network effects.
Generic network attribution must honor logical application identity as well as
the runtime basename, so an npm module cannot become an ambient browser owner
merely because its executable is Node.

Primary sources: the Homebrew `python@3.14` and `node` formulae, CPython's
`Mac/Makefile.in`/`Mac/Tools/pythonw.c`, pytest invocation and pip user-guide
documentation, and Microsoft's `dotnet-msbuild` and macOS PowerShell installation
documentation. These establish static invocation vocabulary and distributions;
they are not host inventory or native capture. New variants use an explicit
2026-10-21 availability boundary, preserving the frozen October-20 benchmark's
application population. Current Zscaler Mac/Apple-Silicon support does not by itself
prove a native arm64 executable; its old M1 reference explicitly used Rosetta.
Keep that variant unavailable pending qualifying native-architecture evidence.

Revision-328 final gate: the full routine run completed in 992.72s with **16,145
passed, 50 skipped, 2,299 deselected and two failures**. Both failures were the
already-corrected self-directed SSH occurrence selector and reference line-budget
contract; the final affected gate passes **132 tests, one existing skip**. The
separate session/catalog/reference gate passes 37 tests. No production source
changed after the complete run began. This is a full run plus focused repair
evidence, not a claim that its original exit status was green. Ruff check/format
(1,319 files), whitespace and revision-328 behavior checks pass. The installer
refreshed all 99 generated project skill files. Personal assessment skill and
its retained replacement files remain byte-identical.

The runtime-catalog join exposed a related launch-policy contract: CPython's
actual native image is inside Python.app, but that spelling does not make a
module query a GUI launch. An optional explicit `spawn_rules.launch_kind` owns
shell versus GUI placement. Baseline shell bootstrap, parent resolution and
foreground occupancy must consume the same decision; legacy profiles preserve
their existing path-based fallback. Bounded lifetime matching stays independent
of launch kind, so an unrecognized command cannot acquire a fabricated close.
The shared CLI network policy also covers loaded interpreter/runtime basenames,
requiring explicit network intent for Node/Python/.NET/PowerShell queries and
avoiding an ambient-ownership escape through a logical module name.

Real-engine catalog acceptance exposed the next owner join: deployment compilation
already preserves multiple logical installations while selecting one exact
path/content binding for a shared runtime. Installed Mac stat provisioning must
consume that chosen physical binding once, rather than allocating a separate
inode/spec for each logical entry. Conflicting content or distinct physical
ownership remain errors; logical module names never duplicate one file object.

## Remaining timing-family contracts

The short-HTTP transport floor currently replaces varied OCSP response durations
with the same worst-case HTTP source-delay bound plus only 0–25ms of slack. The
network transaction planner owns this whole-family artifact. Move its bounded,
right-skew close slack to a validated frozen network profile and use the same
maximum in admission/headroom calculations. Explicit longer caller durations
remain unchanged; legacy snapshots without the new profile keep their old
parameters. Do not fix this with an OCSP-emitter timestamp or one benchmark UID.
Independent user activity also loses fractional time in the shared baseline
scheduler's integer-second jitter. Preserve its existing interval and per-user
RNG ownership with fractional jitter in both planning/execution passes; periodic
service schedules retain their own timing contracts.

Automated guardrail investigation: revision 328 passes all acceptance criteria;
its 89.76 score reflects distribution/volume/regularity diagnostics rather than a
new parser or causal failure. One OCSP identity comparison lacks an analyzer row
for a matching HTTP/file transaction whose connection explicitly reports three
missed bytes. This is not evidence of mismatched decoded identities; leave the
evaluator and source selection unchanged pending stronger evidence. No synthetic
record is added simply to raise that score.

## Loop-2 owner contracts and native-gate decision

The user chose to keep ES exec/exit and Gatekeeper reference gates closed for now.
The disposable-lab capture proposal is retained but no capture is authorized or run.
The final routine and slow runs for the uncommitted revision-329 candidate were
cleanly interrupted before further production edits when the fresh panel exposed
additional confirmed defects. Their partial pass counts are not completed gates.

The next family fixes consume existing owners rather than adding renderer patches:

- Application-instance policy belongs in the platform catalog and compiled
  deployment descriptor. Baseline application selection reuses the existing
  session singleton claim for selected Mac main GUI processes; Windows/Linux
  defaults and explicitly separate executions retain their current behavior.
  Both compiled and legacy catalog lookups must agree. Consumers are process,
  network ownership and endpoint lifecycle evidence. Short-lived forwarding
  helpers and arbitrary multi-instance launches remain outside this bounded fix.
- Journal directory identity belongs to the engine's canonical machine-ID map.
  Generic and service file-effect templates may use that identity only when
  supplied by their caller. Ambient churn and native housekeeping must agree;
  optional journal effects without identity are omitted. Random temporary-path
  hex values keep their existing semantics. Consumers are Linux eCAR file paths
  and native journald messages, including sibling runtime/persistent paths.
- Explicit-credential SMB session timing belongs to the action bundle and the
  committed canonical transport interval. Auth, close and caller lifetime must
  follow the resolved interval even if source-process admission moved the
  requested connection time. Native syslog, eCAR and Windows lifecycle rows
  consume that shared plan; source-local timing remains source-owned.

History/process timing and command-owned file effects are also being traced at
their shared action owners before any correction. The Chrome-version finding
is a separate inventory/request binding issue, not a native Mac admission gate.

Confirmed history root cause: the shared source planner moved a backdated command
to the last delivered session-dependent row. History carries embedded execution
time, so Bash and zsh now retain that canonical fact while advancing only the
maximum session-closure frontier. This covers out-of-order activity delivery
without fabricating execution delays or changing native history serialization.
Mac process preflight no longer treats execution as evidence that the process
created its executable; explicit artifact and command/transfer owners retain
their own file effects. Chrome and Firefox request identity now consumes the
loaded content-version reference, avoiding fresh path resolution after updates.
Unknown versions preserve existing behavior. Chromium's reduced version keeps
the real major and zero minor/build/patch; Firefox's product and rv tokens agree.
References: https://www.chromium.org/updates/ua-reduction/ and
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent/Firefox.

The broader focused gate passed **701 tests, four deselected**. It exposed an HTTP
reuse sibling: transport-floor slack was being applied a second time to an
application-only child after parent admission. Reused requests retain their
existing bounded application duration and immutable physical parent; only a new
physical transport receives the physical close-floor distribution. The existing
persistent-HTTP transaction regression now passes without enlarging its parent.

Revision-329 extended acceptance passes **38 tests in 297.09s** across mixed-fleet
fresh-process/filter equivalence, SSH, root persistence and SMB. The two native
fork CLI/exact-checkpoint tests separately pass in 40.18s. The routine run exposed
four narrow RNG doubles lacking the scheduler's new fractional `uniform` draw;
the 62-test terminal-admission file passes after updating those doubles. That
routine run was cleanly interrupted and restarted on unchanged production source
to obtain a complete green gate. No source changed during checkpoint generation.
The frozen revision-329 surface is
`dafe0214f71bb625b2ba0c2c4414ff58adce2b9ef4aaf170365c1f2827f59a25`.

The complete final routine run took **998.15s**: **16,176 passed, 50 skipped,
2,301 deselected, three failures**. All failures were the same fixture contract:
the platform file-churn test's `SimpleNamespace` did not carry the engine-owned
machine-ID map. Its repaired fixture supplies an explicit canonical ID and now
also asserts that the shared selector receives it on all three platforms.
Production source did not change. Final acceptance uses the full run plus the
affected-file repair gate, not a claim that the original full exit was green.
The final repaired platform/journal/skill/manifest gate passes **108 tests, one
slow deselection**. Ruff check/format (1,323 files), whitespace, behavior digest
and all 99 config files pass; generated project skills were refreshed.
