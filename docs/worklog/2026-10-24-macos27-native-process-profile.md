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

## Current progress

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
run. Generation profile/source admission, canonical no-entitlements facts,
macOS 26 rejection and integrated recovery checks are the next implementation
milestone; the codec alone does not enable generation.
