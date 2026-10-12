# Issue #444: scenario-relative authored scheduling

## Scope and release decision

The user requested a root-cause fix before deciding whether to include it in 2.2.0a2,
then approved inclusion on October 12. The implementation is based on `dev` at `a820b75e`.
The existing unpublished 2.2.0a2 changelog now includes this correction. The product version
is unchanged, and no tag or publication is authorized by inclusion.
Existing installer previews do not contain this correction. Including it requires rebuilding
the installers and retaining the user's x86_64 acceptance and normal release gates.

## Reproduction and root cause

[Issue #444](https://github.com/Cisco-Talos/EvidenceForge/issues/444) is valid on current `dev`.
A scratch copy of `scenarios/branch-office-example/scenario.yaml` with only the start changed
to `2026-10-09T09:59:00Z` passes validation and fails Splunk generation with exit 21:
`Lifecycle materialization session is not registered and live`.
The equivalent `2026-10-09T12:00:00Z` control succeeds.

`GenerationEngine._initialize` indexed both storyline and red-herring entries by truncated
clock hours. Baseline passes and their consumers instead use scenario-relative hour starts:
09:59, 10:59, 11:59, etc. Their keys therefore never match for a non-hour-aligned start.
Debug reproduction confirms all six storyline groups were postponed to the remaining-storyline
tail after baseline completion. The eventual beacon's proxy client process then tries to use
a historically valid session that the lifecycle registry has already closed. The lifecycle
guard correctly rejects this; it is not the faulty layer.

The same index also feeds authored workstation lock ownership and current/next-pass RDP
bootstrap fences. Correcting the index fixes those sibling consumers together.

## Owning-layer correction

- Add one scenario-relative hour-key helper in `generation/engine/core.py` and use it for
  both authored indexes. Calculate the containing pass with timedelta floor division,
  retaining the scenario start's minutes, seconds and microseconds.
- Preserve nominal authored timestamps, event ordering, once-only execution, warm-up policy,
  baseline pass boundaries, and the lifecycle checks. Do not round or rewrite the scenario.
- Keep existing index consumers and checkpoint schemas unchanged. The indexes are declared
  rebuilt state in the checkpoint owner inventory, so recovery reconstructs the same corrected
  scheduling from captured inputs.
- Declare generation behavior revision 162 as a localized scheduling correction. This is
  generation compatibility metadata, not a product release version bump.

The production engine diff has 13 added and 3 removed lines in one file, plus its behavior
declaration. No emitter, process/session lifecycle, authored schema or persistent layout changes
are needed.

## Verification

- New routine tests initialize the real event indexes and execute actual pass lookups.
  Five non-aligned cases fail before the correction; the aligned control passes.
  All six pass afterward, covering both reported dates, seconds/fractional seconds,
  midnight crossing and a non-UTC offset. They also cover relative and absolute event times,
  exact pass boundaries, a final partial pass, chronological ties, duplicate prevention,
  workstation ownership and current/next-pass RDP fences.
- Full six-hour branch-office Splunk regressions pass for both reported 09:59 dates
  (127.37 seconds combined). They assert all authored groups execute before the baseline
  returns and verify the beacon's proxy evidence; successful tail replay is insufficient.
- A slow checkpoint regression at `09:59:17.125Z` passes suspension/resume with authored
  processes on either side of the checkpoint. Resumed and uninterrupted deterministic bundle
  members match byte for byte (20.35 seconds).
- The existing two-hour baseline/authored RDP monotonicity regression passes.
- Focused timing, baseline, lifecycle, behavior manifest, checkpoint and process/session
  suites total 341 distinct routine passes and one existing skip. All changed routine
  regressions pass again after adding absolute-time and RDP-fence coverage.
- Before/after noon controls have all 41 generated data and ground-truth files byte-identical.
- Repository Ruff lint/format, whitespace checks and the behavior manifest check against
  `HEAD` pass. The full release coverage/slow/portability and native installer gates have not
  been run for this local correction.

Scratch inputs, original failures and diagnostic runs are retained under
`/private/tmp/eforge-444-k8rdc519/`. No user scenario or existing generated bundle was modified.

## Dependabot PR #443

The user also requested addressing [PR #443](https://github.com/Cisco-Talos/EvidenceForge/pull/443).
It targets `main` and updates only `uv.lock`: virtualenv 21.2.0 to 21.7.13 and its transitive
python-discovery dependency 1.2.0 to 1.6.1. Both complete lock entries, including distribution
URLs, hashes and dependencies, already match `dev` exactly. Commit `9c7d01bb` integrated this
update and is an ancestor of `dev`. The installed development environment also uses these
versions, and `uv lock --check --offline` passes.

The PR's routine Linux/Windows, lint, checkpoint durability, slow shards and portability checks
passed. Its sole failure is the release-version guard on its `main` target. No additional
dependency change or main merge is needed; the update will reach main through the normal
stable release integration. Closing the redundant PR preserves that release boundary.
