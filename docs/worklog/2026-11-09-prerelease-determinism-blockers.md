# Prerelease determinism blockers

## Scope

Diagnose the nine slow failures in a5 release run `42699295865` before choosing
release fixes. PR #468 is merged at `cf2b3cb9`, and its merged-dev routine CI is
green. The initial investigation used the equivalent local source tree at
`144b4ec8` and left engine/test source and release tags unchanged. The subsequent
implementation is based on `origin/dev` at `cf2b3cb9`.

## SSH: incomplete checkpoint restoration in the test harness

All eight variants of
`test_legacy_ssh_checkpoint_resume_is_byte_identical` reproduce locally in 4.38s.
Decoded output comparison isolates the difference to the second receiver session's
logind session ID and its derived eCAR login/logout row IDs; process/transport
evidence matches in the inspected case.

The test calls `StateManagerParticipant.restore_checkpoint(state_seal.head.payload,
())`, dropping `state_seal.segments`. The used-logind-ID ledger is intentionally
stored in incremental segments. `_preview_linux_logind_session_id` includes the
used-ID count in its deterministic allocation scope, so the incomplete restore
changes the next ID (163 versus 133 in the inspected case).

An isolated copy of the existing test restoring the head plus every segment
passes all eight unchanged byte-equality assertions in 4.39s. The repair belongs
in the test harness: restore the complete participant seal and explicitly assert
used-ID ledger equality. Do not alter the production session-ID allocator to
compensate for discarded checkpoint data.

Probe: `/private/tmp/eforge-ssh-segment-probe/test_ssh_segment_probe.py`.

## Artifact round trip: weighted sampling depends on mapping insertion order

`test_cli_only_publication_round_trip_generation_and_evaluation` reproduces locally
in 38.77s. All seven other generated data files match; Sysmon differs. There are
48 versus 47 Sysmon rows, with subsequent writer ThreadIDs, record IDs and
record-dependent 100ns timestamp digits affected.

The first upstream difference is one ambient Defender file modification. The
unpublished/default configuration iterates Windows file-churn weights as
`read: 58, modify: 30, create: 12`; publication serializes the same mapping in
sorted order, `create: 12, modify: 30, read: 58`. These mappings are semantically
equal, but `_emit_ecar_file_churn` builds the weighted population from
`action_weights.items()` in insertion order. The same RNG draw can therefore
produce a different canonical file action after publication.

An instrumented generation from each retained resolved scenario confirms the
first Sysmon divergence is this file action before rendering. One run reaches
the Event 11 filter and emits the modification; the other does not. Sysmon's
sequential writer-thread allocator then advances differently, explaining the
header changes. A direct ThreadID or timestamp patch would address the symptom.

The owning-layer repair is canonical ordering of action/weight pairs before
weighted selection in baseline file-churn generation, keeping each weight bound
to its action. Add a narrow insertion-order invariance regression and retain the
full publication/import/generation byte-equality test. Audit analogous weighted
mapping consumers without changing unrelated generation behavior.

Trace files: `/private/tmp/eforge-sysmon-{legacy,portable}-trace.jsonl`.
Isolated round-trip probe: `/private/tmp/eforge-order-probe/`; it normalizes only
the file-churn action-weight mapping for both CLI invocations, leaving emitters
unchanged. The existing full publication/import/generation byte-equality test
passes with that change alone in 38.67s.

## Release consequence

The eight SSH failures are harness defects; the artifact failure establishes an
actual order-dependent generation defect. After the repairs are merged, prepare
the next immutable alpha snapshot rather than moving tag `v2.2.0a5`.

## Implementation and authorized follow-through

The user authorized implementing both repairs, opening/monitoring the PR into
`dev`, resolving CI errors, and carrying the prerelease through publication.
The selected next snapshot is `2.2.0a6`; preserve a5's tag and source unchanged.
Branch: `codex/prerelease-determinism-fixes`.

- Sort action/weight pairs in baseline file-churn generation before weighted
  selection. Keep each action's configured weight and the RNG draw count intact.
  Declare localized generation behavior revision 500 with a refreshed digest.
- Restore the full StateManager seal in the SSH compatibility checkpoint test,
  retaining its existing byte comparisons and explicitly checking the used-ID
  ledger before subsequent allocation.
- Add routine regression coverage for all six mapping insertion orders on Windows
  and Linux under seeds 31 and 137, comparing canonical occurrence sequences and
  final RNG states. All four cases fail before the fix and pass afterward.
- A narrow audit of weighted sampling in the baseline owner found no other direct
  weight-map population construction of this form; ordered profile lists retain
  their authored order. No Sysmon rendering or production SSH allocator changes.

Local validation: 268 related routine tests pass, one skips, and one slow case is
excluded by the routine tier. All nine original slow failures pass on the actual
repository changes in 42.63s. The generation-behavior declaration validates
against `origin/dev`.

Next: require PR CI and the full Linux slow/portability gate, merge into `dev`,
prepare the synchronized a6 version/changelog commit, then tag that immutable
snapshot. Monitor all release gates and the three installer builds through verified
publication; retain every required check and all six installer/checksum assets.

## Integration and recurring Studio timing failure

PR #469 merged into `dev` as `e9df6a30` after routine/native CI run
`42747375110` and full slow/portability run `42747376175` passed. The initial
ARM64 Studio frontend run hit the recurring first AssetBrowser test's one-second
query deadline while the component still reported loading. Rerunning failed jobs
passed on unchanged source; all four slow shards and portability passed directly.

Harden that initial readiness wait to five seconds and the enclosing test to ten
seconds. Cold category resolution includes two 200ms debounced loads; keep every
pagination, lazy-detail and search assertion unchanged. All sixteen AssetBrowser
tests pass locally. Carry this bounded test-only adjustment in the final a6 source
before its version commit so no additional intermediate full-suite cycle is needed.
