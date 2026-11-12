# Issue 478: macOS ES contribution review and bounded checks

## Scope and decisions

Reviewed issue #478 and PR #479 at `18373e34981e70d26e743bd510aa0cbf2795cb56`
against dev `4df3c2ae`. The user requested bounded reference-Mac ordering tests,
verification of sequence behavior, an investigation proposal for PID versions and
fork timing, an inventory of shipped scenarios, and implementation-scope estimates.
The user subsequently authorized posting both approved responses, integrating only
slash escaping with contributor credit, and closing #479 after integration. Replies
are posted as David J. Bianco on [issue #478](https://github.com/Cisco-Talos/EvidenceForge/issues/478#issuecomment-6830162318)
and [PR #479](https://github.com/Cisco-Talos/EvidenceForge/pull/479#issuecomment-6830156031).
The issue opening uses the requested phrase "analysis on a real MacOS 27 system".
The later sections retain investigation and decision history; these current
authorization and publication facts supersede earlier chat-only instructions.

User decisions, using the issue's numbering:

1. Fix slash escaping. Decide object ordering only after native tests; additional
   serialization cost is a consideration, not an automatic rejection.
2. Wants a PR for native stat realism; assess whether smaller slices are easier
   to implement internally.
3. Investigate PID-version and fork-time claims internally before soliciting a PR.
4. Verify actual counter behavior; do not dismiss gaps as modeled loss without
   accounting for the missing deliveries.
5. Wants a PR for bounded general file open/write coverage.
6. Wants a PR for BTM, OpenSSH and loginwindow ES event families.
7. Asked what actually ships; no new example library or packaging change selected.

The slash-only fix is committed as `3a01cbea` on `codex/issue478-macos-es-review`. It retains the
existing Pydantic serialization and escapes solidus characters afterward, with no
key permutation or additional JSON parse/encode pass. Revision 510 records this
localized format change under its own slash-only behavior identifier and digest;
the contributor's broader ordering implementation is excluded. Sydney receives a
co-author trailer. Product versions remain unchanged.

## Slash-only integration validation

The focused contracts, v11, ingress, native sink, dispatch and behavior-manifest
checks pass: 213 tests. Both slow filesystem/workstation recovery checks pass
(84.29 seconds), including exact resumed and filtered output. Additional process
identity investigation checks pass (133 tests). Whole-repository Ruff lint/format
checks and the generation-behavior manifest check pass. Full routine and slow
suites were started, then canceled when the user expanded integration to include
all open Dependabot PRs; final broad checks run on the combined inputs. The tests
cover slash spelling, decoded equality, literal
backslashes, Unicode, entitlement member order, repeatability and NDJSON framing.

## Combined dependency integration

The user subsequently requested all open Dependabot updates in `dev` and asked
whether to validate them together. Review found five PRs, all targeting `dev` and
changing only `uv.lock`: #472 Pydantic 2.14.1 -> 2.14.3 (core 2.50.1 -> 2.50.4),
#473 websockets 17.2 -> 17.4, #474 pytest 9.1.1 -> 9.2.0, #475 platformdirs
4.9.4 -> 4.14.5, and #476 python-dotenv 1.2.3 -> 1.2.4. Parsed package-level
comparisons confirm there are no other dependency changes. All original bot
commits are retained in integration merge `4bfe750a`; there were no conflicts.
`uv sync --locked --all-extras` installs all six changed packages successfully.

Reviewed release notes and the upstream websockets/platformdirs changelogs.
Pydantic includes serialization/schema/security fixes, so wire and recovery tests
remain relevant. Pytest introduces keyword-only parametrization options, checked
through full collection. Platformdirs changes XDG/media/runtime handling, checked
through Studio workspace tests. Websockets adds a fragmented-message limit and
connection fixes; Studio service tests cover its application integration. Dotenv
fixes empty-value parsing and CLI expansion precedence. No product version bump.

PR #480 is the combined maintainer integration vehicle. Canceled the earlier
slash-only CI runs 43264948230 and 43264949744 and local full suites before
starting the final combined CI inputs. Full routine checks run on Linux/Windows;
the slow/portability workflow is dispatched on the same combined branch. Merge
only after the checks pass. Preserve history when merging so the original
Dependabot commits reach `dev`; close #479 after its slash portion is integrated.
Issue #478 remains open for the separately scoped work.

### Contributor replies after publication

The contributor [accepted slash-only integration](https://github.com/Cisco-Talos/EvidenceForge/pull/479#issuecomment-6830248577)
and agreed that per-record shuffling overshoots the observed native variation.
The [issue reply](https://github.com/Cisco-Talos/EvidenceForge/issues/478#issuecomment-6830249186)
provides a new reproducer, not yet investigated: bundled `macos-workstation-example`
from 2.2.0a6 (`bbcf9cd6`), seed 42, no overrides, output
`MAC-01.example.test/macos_endpoint_security.ndjson`. Three of nine forks are
zsh -> zsh at `2026-10-19T14:16:17Z`, `14:17:31Z`, and `15:27:22Z`, with child
PIDs 11031, 11166, and 18758 and whole-second event/birth times. The persistence
example with partial process coverage reportedly shares the middle case.
The contributor's shell-history-granularity explanation is a hypothesis.

Reported global sequence starts at 23, with gaps at 28, 31 and 37; per-family
fork/exec sequences remain consecutive. The contributor agrees this fits
filtering and warmup, subject to accounting for those exact omitted deliveries.
They plan one stat PR for flags/package timestamps and directory link counts,
using canonical metadata owners, and proposed models before device/identity code.
Do not treat this new reproducer as confirmed by the earlier, different probes.

Combined-dependency local verification passes: 192 native-contract/manifest/Studio
service tests, 52 v11 contracts, and both slow filesystem/workstation exact-recovery
tests (77.80 seconds). Full default collection succeeds with pytest 9.2.0:
20,283 selected of 22,736 collected. Ruff and the behavior manifest remain current.

### Final CI result and explicit user waiver

[Combined routine/Studio CI](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43265383233)
passed on `154c0f6a`, including all Linux/Windows routine shards, macOS/Linux
Studio checks, native recovery and Windows durability.
[Slow/portability CI](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43265418143)
passed three slow shards and Python 3.12 -> 3.13 checkpoint portability. Its only
failing test was
`tests/unit/test_evaluation_storage.py::test_full_evaluation_exceeds_old_record_cap_and_detects_last_failure`:
all functional assertions passed, but measured peak RSS was 734,343,168 bytes
against the unchanged 512 MiB threshold. The failing shard reported 1 failed,
532 passed and 2 skipped; the aggregate release check failed consequently.

The user explicitly authorized accepting this sole failure and integrating anyway.
This overrides the earlier all-green merge plan for this integration only. The
assertion checks peak memory, not dataset-size limits, and is retained unchanged.
Whether it reflects evaluator growth or inherited Linux pre-exec RSS remains
unresolved; do not label it obsolete or confirmed unrelated to dependencies.
The Linux manual documents resource accounting across exec; a macOS 160 MiB
parent probe does not reproduce inheritance there. No production/test fix is
included and no gate or threshold is weakened. Follow-up should reproduce on
Linux with a clean launch and compare the reported peak against evaluator usage.

An optional Linux diagnostic was started from the isolated, temporary branch
`codex/diagnose-eval-memory` (run 43273429102); it is not part of the integration.
The user-waiver decision ends that detour. The final additional changes are only
this worklog; verify the same tested-input digest before merging #480 with history
preserved. Close #479 after its slash portion reaches `dev`; retain #478 for the
separately scoped features and new reproducer follow-up.

## Reference Mac: two finite process captures

The existing authorized second Mac is macOS 27.0.1 build 26A434, arm64.
Used its existing fixed-command privileged collector guard, without changing the
guard, sudo policy or privacy settings. A fresh unprivileged scratch probe reports
its own audit token, process birth and executable device/inode, waits for commands,
then forks and execs only `/usr/bin/true`. Each child is waited/reaped. The probe's
alarm is 25 seconds; each runner is bounded to 20 seconds and the existing guard
also cancels on stdin closure. Two runs, no further capture loop.

The bounded streaming filter authenticates the exact root execution and extends
ownership only through its native fork/exec graph. Ambient data is discarded
before persistence. Global/per-event counters are checked before filtering.
Only owned native rows and controls persist in owner-only remote directories;
only technical summaries returned locally. Invented controls verified acceptance
of the authenticated root and rejection of changed PID or executable inode before
deployment. All controls and cleanup passed in both runs.

Local scratch: `/private/tmp/eforge-issue478.BQHYBB`.
Remote kit: `/private/tmp/eforge-es-spelling.cfXl6t`.
Retained private runs: `run-f23vp17y` and `run-md57i0cq` under that kit.
Each run retains native data, controls, fixed report, hashes and provenance.
Runner SHA256: `cb36bc230b18819c1b2f462a4121fa922a72b4499e7d5584252afcffe1cc5e75`.
Probe source SHA256: `7fff1c0a192e20c520ba7220d0e2fba79362ede4c7585c53887d8873a38923fa`.
Support is an unchanged copy of `scripts/macos_remote_filesystem_reference.py`.
No private source row, environment, captured identity or host file metadata is in Git.

Both runs retained exactly 88 records: 29 forks, 29 execs and 30 exits. Thirty
controlled child executions completed; the first occurs during collector startup,
so its unobserved start is not counted as covered. The final extra exit is the
probe's own termination. This is a spelling/ordering sample, not full start coverage.

| Measurement | Run 1 | Run 2 |
| --- | ---: | ---: |
| Envelope key orders | 3 (44/43/1 records) | 3 (44/43/1 records) |
| Process key orders | 3 (44/43/1) | 2 (87/1) |
| Audit-token key orders | 2 (87/1) | 2 (87/1) |
| Executable-stat key orders | 2 (87/1) | 2 (87/1) |
| Escaped / unescaped solidus characters | 990 / 0 | 990 / 0 |
| First global sequence | 0 | 0 |
| Global / per-type sequence gaps | 0 / 0 | 0 / 0 |
| Fractional fork / child-birth timestamps | 29 / 29 | 29 / 29 |
| Exec changes PID version / preserves birth | 29 / 29 | 29 / 29 |
| Observed child PID versions below PID | 0 | 0 |

An offline remote comparison applies the PR's exact seed/rank algorithm to each
owned native capture without exporting or rewriting the raw records. In both
88-record runs, native envelope/audit-token/stat order counts are **3/2/2**;
the PR algorithm produces **88/88/88**. Decoded values remain equal. This directly
confirms the excess ordering variability on the same records, beyond the earlier
Foundation-only approximation.

The actual key permutations differ between collector invocations. Within a run,
layouts mostly recur. Identical decoded audit-token/stat subobjects can have more
than one order. Thus the contributor's observation of native variation is valid,
but the PR's whole-record-content seed is not qualified by this sample. Earlier
Foundation-only testing had 1 versus 100 key orders when changing only mach_time;
that probe did not reproduce eslogger's dictionary construction. Keep these claims
separate. The evidence favors slash-only integration now; any ordering model needs
an explicit bounded approximation and a cost justification, not a native-equivalence claim.

## Lossless generated counter checks

Fresh runs use the unchanged authored files from the current project context,
normal CLI options, new scratch output roots and checkpoint cadence 0. Validation
ran first. The native smoke fixture has its expected pre-window setup warnings;
no input repairs or policy changes were made.

An external diagnostic wrapper records final ingress deliveries without changing
their decisions, sequence allocation or output. The registry's actual prepared
observations are joined to immutable ingress reasons and published rows.

| Input | Exported rows | Collector deliveries | Exported global range | Unexplained internal gaps |
| --- | ---: | ---: | --- | ---: |
| `tests/fixtures/scenarios/macos-native-smoke.yaml` | 16 | 26 | 10–25 | 0 |
| `scenarios/macos-persistence-example/native-system-job.yaml` | 8 | 8 | 0–7 | 0 |

Smoke deliveries 0–9 are before collection: 4 forks, 5 execs and 1 exit. All are
explicitly `out_of_window`, including one unknown-result exit. There is no modeled
kernel loss. Every visible native delivery matches its exported sequence; every
counter increments consecutively. System-job has no omitted deliveries at all.
Both bundles complete with authoritative generation manifests. Counter checks are
mechanical joins, not independent full-bundle quality evaluations.

Conclusions: starting above zero is expected when the collector was active during
warmup. The native reference starts at zero, contradicting the issue's universal
start-at-one claim. Internal global gaps in a complete lossless in-window stream
still require an exact omitted-delivery explanation. Unknown native facts can cause
intentional projection omissions even without configured loss; those are capability
limits, not evidence that real eslogger lost messages. Never renumber the exported
subset to hide an omission. These two cases do not prove every scenario is gap-free.

## PID-version and fork-time investigation

The generated smoke's 5/5 forks and system-job's 2/2 forks retain nonzero fractional
times. Current fork rendering preserves canonical microseconds, appending three zero
digits for the native nanosecond spelling. A systematic whole-second fork defect
was not reproduced. If another workload shows it, trace the exact canonical birth
through planner, action bundle, ingress and rendered event; distinguish process
birth (`start_time`) from event occurrence (`time`) and authored exact-time intent.

The small PID-version scale is reproduced: smoke has versions 1–30 with PIDs up to
2475; system-job has versions 1–18 with PIDs up to 9653. These are invented generated
identities. `MacosAuditIdentityLedger.seal` assigns host-local `row_number()` over
only committed modeled allocation facts. It preserves chronological order and
references, but has no preexisting boot-history/hidden-exec budget. Real XNU fork
and exec share a host-wide allocation counter independently of PID allocation.

Next bounded investigation should compare:

1. Native owned fork → same-PID exec → exit contracts against generated canonical,
   native and eCAR identities; include parent/responsible references and PID reuse.
2. Canonical boot age, initial inventories, modeled/hidden PID allocation history and
   audit-version reservations. Determine the missing shared chronology, rather than
   imposing a `pidversion >= PID` invariant or adding emitter-local random offsets.
3. Collection-window/warmup changes, exact checkpoint restoration and output filtering,
   to ensure a boot-owned solution does not renumber historical identities by export.

The likely issue is host-history realism, not broken exec identity transitions.
No change to identity allocation or fork timing is made on this branch.

## Scope and contribution boundaries

| Work | Scope assessment | Recommendation |
| --- | --- | --- |
| Slash escaping | Tiny serializer change plus regression/manifest | Prepared internally; narrow/reconcile #479 before integration. |
| Key ordering | Small code, unresolved fidelity policy and performance tradeoff | Defer decision; no costly whole-record shuffle justified by these captures. |
| Protected-file flags/package times | Small-to-medium config/schema/provider slice | Suitable bounded contribution; exact provenance rules and negative controls. |
| Directory nlink | Small-to-medium canonical state slice | Model initial population and create/unlink/replacement deltas together. Current document workload updates directory size/times but not link count. |
| Volume/device layout | Medium filesystem/provider change | Existing device IDs are already scoped per host, not a universal literal 1311. Define required sealed/data/devfs relationships before expanding volume topology. |
| PID versions | Medium shared allocation/history work | Investigate internally first; changes require identity/recovery/filter contracts. |
| General open/write | Medium-to-large canonical file/descriptor work | Focused external PR(s); define bounded producer scope, offsets/sizes, actual mutations and source timing before broad coverage. |
| BTM / SSH / graphical session ES | Three medium vertical slices | Separate PRs over persistence, SSH and GUI-session owners; native references and semantic/correlation tests per family. |
| Attack examples and Splunk searches | Small per example if existing features suffice | Useful contribution; split unsupported engine capabilities from example content. Include benign controls, expected results and version/target assumptions. |

BTM registration is not launch execution. OpenSSH ES login/logout are connection-level,
not one per command/channel. Loginwindow events are graphical-session events, not
generic SSH logons. An open does not prove a read; write notifications do not supply
byte counts. All new correlated evidence should project canonical owners.

## Scenario distribution inventory

`git ls-files scenarios` contains **24 scenario-root YAML files** (counting twins,
revisions and diagnostics separately). This excludes YAML includes, workload specs,
ignored/untracked user scenarios and test fixtures. The source checkout contains:

- One branch-office exercise.
- Two LLM-injection demo twins (injected and clean).
- Six workstation examples: baseline, mixed fleet, native workspace entry, SMB
  client, SSH client and shell-history exposure.
- Three persistence examples: lifecycle stages, group cleanup and native system job.
- One denied-launch example and one returning-exec-failure example.
- One Mac-to-Mac SSH example.
- One spillage full-matrix harness.
- Eight assessment/regression inputs: iteration-test; iteration-test-macos plus its
  diagnostic variant; two macos-assessment revisions; macos27-native-assessment;
  workstation acceptance; workstation recovery.

Only a small portion is a polished attack-exercise library. Many are capability
demonstrations or engineering workloads. The wheel selects `src/evidenceforge` and
force-includes `commands/eforge`; repository `scenarios/` is not bundled. Studio
installers package that wheel/runtime and UI. Thus the packaged application has no
bundled scenario library; source users receive the above repository content.

## Verification

Slash-only focused contracts, ingress, exact native publication, source integration,
dispatch and behavior-manifest tests: **213 passed**, 4 extended cases deselected.
Whole-repository Ruff check/format and behavior digest pass.
On 10,000 representative exec serializations, old serialization is 0.1432 s and
slash-only is 0.1518 s (1.060×). This is a local serializer microbenchmark, not a
whole-generation speed guarantee. The combined PR previously measured about 10.4×.
Exact filesystem/workstation checkpoint-resume and source-filter integration:
**2 passed in 84.29 seconds**, including positive filesystem activity and evaluation.

## Follow-up: per-event ordering and completed internal investigation

The user requested clarification of per-event key ordering, completion of the
internal identity/timing investigation, and these future contributor directions:

- Request flags/timestamps and directory link-count PRs, either together or separate.
  Ask for the proposed volume/device relationship model before implementation.
- Treat sequence loss/filtering as a likely explanation, but ask for an example
  scenario, seed/options and affected output to reproduce the reported behavior.
  Our observed warmup offset is not itself kernel loss; do not state that the
  contributor's unexplained gaps have been diagnosed.
- Request a bounded first open/write PR with canonical descriptors, mutations,
  metadata, timing, source correlation and recovery/observation scope.
- Prefer three BTM/OpenSSH/loginwindow PRs; a combined PR is acceptable if their
  shared implementation makes separation impractical. Keep their semantics distinct.
- Put contributed attack examples/searches under existing `scenarios/` for now.
  Better example distribution, including Studio, is future design work and may be
  mentioned to the contributor. No publishing or posting is authorized yet.

### Per-event ordering result

Offline analysis of the same two private owned captures, with no new collection:

| Native event | Run 1 envelope orders | Run 2 envelope orders |
| --- | --- | --- |
| fork, 29 rows | 3 (1/14/14) | 3 (1/14/14) |
| exec, 29 rows | 2 (15/14) | 2 (15/14) |
| exit, 30 rows | 2 (15/15) | 2 (15/15) |

Exact permutations also differ between the two collector runs. Exec audit-token
and stat order is stable across all 29 rows within each run, but differs between
runs. Process-object order differs twice within run 1 and remains one layout for
exec/exit in run 2. Thus aggregate variation was not just mixing event types.
These are field orders within records, never a claim about event-arrival order.

Known behavior is documented by primary sources:

- [Apple NSDictionary allKeys](https://developer.apple.com/documentation/foundation/nsdictionary/allkeys)
  explicitly leaves key order undefined.
- [Apple Swift Dictionary](https://developer.apple.com/documentation/swift/dictionary)
  promises stability between mutations but otherwise unpredictable order.
- [Swift Hasher implementation](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/Hasher.swift)
  documents per-execution random seeding and per-instance table perturbation.
- [Swift native dictionary implementation](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/NativeDictionary.swift)
  hashes keys with the table's own storage seed.
- [Foundation JSONSerialization implementation](https://github.com/swiftlang/swift-corelibs-foundation/blob/main/Sources/Foundation/JSONSerialization.swift)
  enumerates dictionaries unless sorted keys are requested. This is corroborating
  open-source Foundation behavior, not proof of the exact shipped macOS serializer.

Static `otool -L` inspection confirms reference eslogger links Swift, Foundation and
CoreFoundation. The particular allocation/mutation paths causing the observed few
layouts remain unproven; Swift hashing is a supported explanation of possible
variation, not a demonstrated reconstruction of eslogger's proprietary implementation.
The observed 2/3-layout pattern is not an API contract or a universal Mac rule.

A cheaper deterministic approximation is feasible: source/collector-scoped seed,
cached permutations keyed by object shape and a bounded construction-variant model,
preserving arrays and using neither whole-record contents nor Python hash/address
randomization. It must remain invariant under output filtering, threads and resume.
This is a proposal, not an approved or implemented ordering change. Do not simply
hardcode one layout per event type or claim measured variants explain every build.

The slash fix was independently prepared as one `.replace("/", "\\/")` after the
existing Pydantic serialization. It uses the same escaping operation as #479, but
the PR was not cherry-picked and its parsing/hash/key-permutation implementation
was not imported. Resolve integration/attribution with #479 before merging anything.

### Internal PID-version investigation result

Public XNU [fork](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c)
and [exec](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_exec.c)
share `nextpidversion`, while PID allocation has its own wrapping namespace. Versions
are host process-history identities, not counters belonging to an eslogger client.

Our actual owning paths differ:

1. `StateManager._preview_pid_allocator` initializes the Mac PID position from a
   host-scoped 8000–42000 draw. Mac allocation then uses `_preview_linux_pid` with
   elapsed boot time, shared hidden-churn prefixes and a 100–99999 cyclic namespace.
2. `_preview_macos_audit_pid_version` reserves versions only for explicit modeled
   process allocations/execs. `MacosAuditIdentityLedger.seal` publishes their
   chronological `row_number()` starting at 1, omitting implicit hidden churn.
3. Consequently both the preexisting PID history and ongoing hidden PID churn are
   disconnected from the public audit-generation history. An initial offset alone
   cannot reconcile the ongoing difference.

A scratch canonical-state experiment holds the explicit create/fork/exec sequence
constant and changes only registered boot age:

| Boot age | Parent PID | Child/exec PID | Published versions |
| --- | ---: | ---: | --- |
| 0 | 19536 | 19545 | 1, 2, 3 |
| 1 hour | 44227 | 44228 | 1, 2, 3 |
| 1 day | 8922 | 8923 | 1, 2, 3 |
| 1 week | 28703 | 28712 | 1, 2, 3 |

All four preserve fractional child birth `.123456`, same PID/object through exec,
changed exec version, and exact full checkpoint restoration of identities and the
chronological allocation ledger. These are isolated allocator diagnostics, not
realistic full host inventories. The first attempted scratch snapshot used the
head-only helper, which omits segmented ledger history; it was corrected to the
existing full head-plus-segments checkpoint helper. No engine recovery defect was
inferred from that incomplete diagnostic.

The finding is confirmed canonical host-history realism debt, not an emitter bug.
A candidate repair should use one boot-owned logical history/budget for hidden and
explicit forks/execs, preserve immutable reservation proofs and chronological
native/eCAR references, and cover pre-window inventory plus ongoing activity.
Do not tie versions numerically to PID, add a renderer offset, copy real host
counters, or emit masses of fake visible processes to fill the gap. Exact hidden
fork/exec budgeting and integration scope require discussion with the user before
implementation. No PID/version behavior has changed on this branch.

### Fork-time conclusion and verification

The native fork producer takes `child.process.started_at` and authenticates it
against the cohort and collector occurrence. ES ingress rejects a different native
time. Rendering preserves canonical microseconds; process `start_time` separately
uses six fractional digits. There is no whole-second truncation in these paths.
Explicit second-aligned authored/canonical inputs can still legitimately yield
`.000000000`; broader rounding needs a reproducible workload before repair.
The previous two engine cases retain 7/7 fractional forks; the native runs have
58/58. The canonical diagnostic preserves the nonzero fraction through exec and
full checkpoint restoration. General nanosecond event precision remains bounded
by the model's microsecond clock, a distinct limitation from whole-second rounding.

The focused identity/allocation/projection/audit-binding/boot/fork-preparation suite
passes **133 tests**, 2 extended cases deselected. Existing tests cover rollback,
PID reuse, source selection, historical parent/responsible projections and exact
checkpoint history. The earlier exact full-engine recovery/filter tests remain
passed. This follow-up changes documentation only.

## Further online research and current contributor guidance

The user requested deeper online research because describing ordering as random
was unclear. They also selected narrowing #479 to slash escaping and explicitly
require **no mention of the locally prepared implementation** in contributor-facing
messages. Discuss PID-version requirements with the contributor; state that the
whole-second timestamp issue could not be reproduced and ask for a scenario that
demonstrates it. Chat-only/no-posting authorization remains in force.

The stronger primary sources are:

- [Standard-library author's process-seeding announcement](https://forums.swift.org/t/psa-the-stdlib-now-uses-randomly-seeded-hash-values/10789):
  hash randomization protects against accidental/deliberate collision attacks.
- [Standard-library author's per-instance-seeding explanation](https://forums.swift.org/t/psa-per-instance-seeding-for-set-and-dictionary/16442):
  process seed, table size and insertion history affect order; separate table seeds
  prevent quadratic union/merge behavior. The implementation mixes storage identity
  into a table's seed and preserves necessary copy-on-write semantics.
- [Current Swift HashTable implementation](https://github.com/swiftlang/swift/blob/main/stdlib/public/core/HashTable.swift),
  `hashSeed(for:scale:)`: new/resized tables get a seed based on the storage object's
  address under ordinary hashing. A random process seed supplies unpredictability;
  table addresses themselves need not be fully random. Copy-on-write copies preserve
  the seed. The comments explain both the performance purpose and the cheaper
  address-derived seed.
- [Implemented SE-0206](https://github.com/swiftlang/swift-evolution/blob/main/proposals/0206-hashable-enhancements.md)
  specifies per-execution random hashing and treats the particular algorithm as an
  implementation detail.
- [Apple's sortedKeys option](https://developer.apple.com/documentation/foundation/jsonserialization/writingoptions/sortedkeys)
  explicitly requests a sorted JSON representation when callers need that property.

This is structured hash-table variation, not an independent uniform permutation on
every serialization. Repeated serialization of the same unchanged Swift dictionary
is stable; independently constructed equal dictionaries can differ, including in
one process. Changed values do not themselves define key placement. Allocator reuse
can plausibly reproduce a few layouts rather than a fresh permutation per row.
That last connection is an inference about the eslogger captures, not an established
reconstruction of eslogger's Foundation/Swift bridging and allocation paths.

Concrete proposed approximation, still unimplemented and undecided:

1. Derive one deterministic synthetic process seed for each modeled collector epoch
   from the existing generation seed and exact source identity. Resume/filtering
   retain that logical epoch; real Python hash seeds, memory addresses and wall
   clock never influence output.
2. Define object-construction classes (envelope, process snapshot, audit token,
   file stat), their actual key sets and a bounded set of reusable synthetic table
   slots. These represent dictionary allocation/reuse, not event-family values.
3. Compute/cache key layouts from the process seed, slot identity, key set and
   modeled construction history. Order is independent of timestamps, PID values,
   paths and other payload contents. New tables/resizing may select a different
   layout; reuse preserves it. Nested dictionary classes may have different reuse
   patterns from the envelope. Arrays retain their order.
4. Source-local deterministic construction decisions select slots against canonical
   collector deliveries, including omitted deliveries. Thus filtering, threads and
   checkpoint boundaries cannot advance a separate mutable serialization RNG or
   resample previously frozen records. Do not hardcode universal two-slot or
   alternating behavior from the tiny capture.
5. Serialize once in the chosen cached orders and apply slash escaping; avoid the
   PR's model-JSON parse, whole-record hash and per-field hashing on every record.
   Verify values, bounded cache size, source invariance, checkpoint bytes, observed
   ordering characteristics and end-to-end cost before adopting it.

Illustration: one collector might emit envelopes in recurring A/B layouts while
most stat dictionaries use S; a different collector can use A'/B'/S'. The same
dataset seed recreates its choices. This is a model of container construction,
not a byte-for-byte Swift hash-table emulator or a statement that all eslogger
builds have two layouts. Exact slot population/reuse policy still needs agreement.

Future contributor discussion of PID requirements should include boot history and
ongoing hidden fork/exec activity, a shared chronological allocation owner, native
and eCAR parent/responsible/execution references, independent host namespaces,
rollback and PID reuse, and exact filtered/threaded/checkpoint replay. Do not set a
numerical PID/version inequality or merely adjust the renderer. Request a proposed
model before implementation. Timestamp reproduction should include scenario,
EvidenceForge revision, seed/options and the affected fields/rows.

## Decision: handle key ordering internally as P1

The user selected internal key-order work and explicitly requested a P1 roadmap
item. Future contributor wording should summarize native ordering and its known
hash-table basis, then say we will address ordering ourselves and no contributor
PR is needed for that part. Continue requesting that #479 narrow to slash escaping;
do not mention the local slash implementation. Nothing is posted to GitHub.

The preferred scope is now the simpler collector-scoped cached ordering proposal,
generated from schema keys. A hand-maintained native-layout catalog and detailed
allocation/reuse simulation are not required. This approximation captures variation
between collectors and intentionally does not reproduce every within-run variation.
Runtime serialization cost still needs measurement even though layout generation
is cached. The new P1 entry supersedes the earlier recommendation to defer ordering.

Chat draft:

> We checked eslogger on our reference Mac and confirmed that JSON field order can
> vary between collector runs and also within the same event type during a run,
> although layouts often recur. This is consistent with Swift/Foundation's
> unordered dictionaries: hash-table layout depends on process/table seeds,
> capacity and construction history. Swift documents process randomization for
> collision resistance and per-table seeding for performance; it is not a fresh
> arbitrary shuffle every time a record is serialized. We have not reconstructed
> eslogger's exact internal allocation paths. We'll handle a lightweight,
> deterministic approximation internally, so no additional PR is needed for key
> ordering. Please narrow #479 to slash escaping and its tests.

## Correction: evaluate ordering cost before deciding adoption

The latest user correction makes adoption conditional: internally prototype/evaluate
key ordering against serialization and end-to-end performance, then decide whether
its training value warrants implementation. The P1 roadmap now records an evaluation,
not a commitment to ship key-order variation. No contributor ordering PR is requested.

The user requests complete chat drafts for issue #478 and PR #479, without posting.
Issue item 1 should only point to the separate PR response. Put the native ordering
summary, slash-only narrowing request and conditional internal evaluation in the PR
draft. Preserve all other agreed contribution boundaries and omit any mention of the
local slash implementation. The issue draft's past-tense statement about replying
on the PR is proposed publication wording, not a claim that anything has been posted.
