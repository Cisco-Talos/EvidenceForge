# macOS 27 native process generation

## Authorized scope and privacy

The user privately identified the only additional exec payload member as
`entitlements`. The shared v2 diagnostic establishes that additional values
were null, all expected exec fields and baseline values pass, and named audit
tokens, numeric signing category, timestamp-string process births, fork/exit
payloads and known envelope fields pass. Full hashes were absent. The earlier
v3 acquisition report passed controlled fork/exec/exit linkage, inputs, FDs,
normal/signal exit agreement, failed-exec control, delivery and sequence checks.
No agent has read a native record, private file, private directory or local log.
The no-sensitive-disclosure/no-captures-in-Git requirement remains absolute.

Apple documents `es_exec_entitlements` as returning an XPC dictionary or null
when no entitlements exist:
https://developer.apple.com/documentation/endpointsecurity/es_exec_entitlements%28_%3A%29
This establishes API meaning, not the complete JSON codec. The human's reviewed
shape/field-name results supply the bounded JSON reference. Nonnull entitlement
exports and full hashes remain unsupported; do not invent or pad those facts.

The user selected a macOS 27 generation profile, then explicitly requested
retiring the macOS 26 generation profile because no 26 test system is available.
Current packaged generation should have one active profile, macOS 27 arm64,
in a multi-profile-capable catalog. Keep historical wire decoding and frozen
input/recovery compatibility where applicable. Never silently render 27 native
records for a newly authored 26 host. No release version bump or publishing is
authorized. Commit and push at concrete implementation milestones.

## Implementation sequence

1. Add a strict message-11 decoder for fork/exec/exit, with required null
   entitlements on exec, named audit tokens and numeric validation categories.
   Preserve v6/v9/v10 codec optionality and reject unknown/non-null extensions.
2. Compile explicit no-entitlements facts at the canonical binary owner; project
   them through existing exact exec/fork/exit preparation and collector journal
   paths. Unknown metadata must not become an empty entitlements claim.
3. Replace the packaged generation policy with a validated selectable catalog
   containing only the macOS 27 profile. Route normal canonical fork/exec and
   termination publication through the existing process-batch/exit machinery,
   retaining observation/filtering/counter and recovery ownership.
4. Test invented wire cases, normal CLI-equivalent commands, filtering, canonical
   identity agreement, failure rollback, threaded output and exact checkpoint
   recovery. Do not inspect user logs or run native collectors/private reviewers.
5. Reconcile references/validation/skills and active roadmap, record limits and
   tests, commit/push. Gatekeeper remains a separate gate. Any required final
   private reference verification must remain human-only and fixed-vocabulary.

## Decoder milestone (pushed as `74e87fdb`)

The user additionally requires any newly validated scenario declaring macOS 26
to fail validation, regardless of chosen output formats. The current authored
target is therefore macOS 27, not a 26 host projected as a newer collector.

The strict v11 wire codec is implemented: fork/exec/exit use named tokens and
required numeric code-validation category; exec requires its dyld path and
the explicitly present null entitlements member. A distinct ESExecV11 model
preserves historical exec optionality and serialization. Missing entitlements,
nonnull values (including an empty dictionary), unknown null extensions,
full hashes, array tokens and unqualified v11 file families are rejected.

All 319 selected tests pass, including 29 new v11 contracts, 42 versioned codec
tests and the unchanged 148 offline-review/100 capture-kit tests. Full Ruff
check and formatting pass (1,331 files). All inputs are invented. No native
records were inspected or copied. No new private kit or live check has been
run. That commit enables decoding only. The generation, validation and recovery
implementation is recorded in the next section.

## Active profile and validation milestone

The packaged policy is now a versioned collection containing one active target,
`modeled-macos27-arm64-process-v1`. Selection requires explicit macOS 27,
arm64 and workstation semantics. An explicit build is retained when supplied;
otherwise the declared OS label supplies the modeled release key. There is no
adjacent-version fallback. Scenario validation rejects
every unsupported Mac target independently of output selection. Engine setup
also rejects retired targets before activating processes. Old wire codecs remain;
historical 26 assessment evidence is preserved, not relabeled or silently replayed
as a 27 host. Current authored examples and Studio guidance move to 27.

Canonical binary signing facts now distinguish unknown entitlements from explicit
modeled absence. The latter survives binary/artifact serialization and changes
the signing identity namespace; old three-field signatures retain their original
identity. The explicitly enumerated synthetic CLI catalog supplies absence as a
model choice, not a claim about every real Apple binary's entitlements.

Exact process publication now composes the existing v11 fork/exec/exit preparers,
finite client inventory, canonical boot clock, collector counters and native sink
with the existing State/lifecycle/artifact journal. The source never turns an
aggregate process start into a fork or exec. Qualified exec retains argv, env,
cwd, loaded image, descriptor table, before/after execution identities and null
entitlements. Exit uses an explicit completed outcome, never an automatic zero.

Unsupported phases keep counter-only observations. For mixed batches the registry
authenticates an omission map alongside the native bytes and canonical token;
there are no placeholder native records. Visible/delayed observations may never
omit bytes. The known fork in a chain remains exportable when its exec is unknown.
Completed retries retain the same map and bytes; changing an omission map invalidates
the source proof. Filtered single observations can bind counters without asserting
native metadata, only under the active bounded source profile.

The integrated command tests exposed an existing timing inversion: subtracting
fork latency from an already reserved foreground readiness instant could put a
new fork before the previous process closed. Process planning now begins the
fork at readiness and places exec after the sampled latency, independent of
selected output formats.

### Explicit coverage limits

This milestone enables the bounded fully specified native process path. It does
not make every ordinary command a native exec record. Existing SSH startup leaves
its inherited descriptors unknown; those commands retain native fork and eCAR
exec evidence. Local GUI launches still lack a qualified audit-origin producer.
Automatic process termination callers often retain unknown terminal results.
Those phases remain nonexported, with no empty FD, empty-entitlements or successful
exit defaults. Completing these canonical producers is further coverage work;
it is not a remaining schema-version evidence gate. Nonnull entitlements, full
hashes, other ES event families, Gatekeeper and external SIEM qualification remain
outside this bounded profile. Unified Log remains a modeled workspace-entry-only
policy, not newly captured native fidelity.

All validation uses invented unit fixtures. No private capture directory, native
record or user log was inspected, copied or committed. No collector or private
review tool was run by the agent.

## Verification resumed on 2026-10-26

The target rule is an allowlist through the active catalog, not a special-case
exclusion of 26. Regression cases reject 26, 26.1, 28, Darwin aliases and
unspecified Mac versions across eCAR, history and native output selections;
explicit 27, 27.0 and 27.1.2 targets pass target admission. A supported Mac sibling
does not make a retired host valid. CLI JSON and direct engine checks exercise
the same boundary. Windows and Linux retain their existing platform rules.

The complete invented process-chain tests cover v11 fork/exec/exit, unknown
entitlements and exit results, exact counter gaps, and interruptions before and
after native sink writes. Sparse projection proofs reject changed omission maps
and missing visible bytes. Installed-only exec preparation requires no unrelated
runtime artifact owner; runtime-backed phases still require their exact owner.

The Studio schema fixture includes the new explicit entitlement-absence fact.
The Asset Browser tests and TypeScript check pass. The canonical validation and
Mac references were regenerated into the ignored project skills; their frontmatter
and local reference links were checked. No installer or product release was made.

The clean routine run completed with **16,632 passing tests**, 50 skips and 2,301
tests excluded by the normal tier selection. Its single failure was the canonical
validation guide's length contract. The guide was shortened to 148 lines without
removing its validation, repair or safety boundaries; the 56 validation-skill and
installer contract tests then passed. No generation code changed after that run.
All 16 Asset Browser tests, TypeScript, full Ruff checks/formatting (1,334 files),
the revision-333 behavior digest and whitespace checks pass. The three focused
slow source/CLI/fresh-process checkpoint tests also passed during the October 24
implementation checks. No coverage or full release/soak gate is claimed here.

## Next producer: GUI audit identity

The user requested collecting evidence for each remaining coverage item first,
one at a time. A separate own-process-only GUI audit experiment is prepared;
see the [private GUI reference worklog](2026-10-26-macos-gui-audit-reference.md)
for the code-only kit handoff and strict human-only collection boundary.
No agent has run its native probe, platform preflight or private reviewer.

The human has now shared successful iTerm2 identity and same-boot GUI-relogin
comparisons. Revision 334 implements login-owned GUI audit origins and explicit
launch/child inheritance with rollback/recovery checks. The linked worklog records
the bounded evidence and remaining GUI responsibility/native-startup limits.
