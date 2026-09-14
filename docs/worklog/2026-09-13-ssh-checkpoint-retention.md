# SSH checkpoint retention correction

## Scope and starting evidence

Branch `codex/fix-ssh-checkpoint-retention` starts at clean
`2bf815e1582c78365d7c9b760e1ff91a73e78901` (2.0.1).
The original commit is preserved at `/private/tmp/eforge-ssh-fix-baseline-2bf815e1`.
No version, authored schema, dependency, fingerprint algorithm, or checkpoint representation
changed. The original failed FOR668 run remains untouched at
`~/TEMP/FOR668-data/scenario-3_1`.

The 56-day scenario, seed 42, failed at its first 24-hour checkpoint (eight warmup hours
plus 16 collection hours). There is no committed recovery point. Its stored resolved
document hash is `9cb33e32d8bf117658b57921bb465c290b1ab948fb2db6ccca38d40332d76568`.

An unchanged-input diagnostic replay found the broken reference at the first collection-hour
boundary: `help01 -> webapp02`, user `tmarsh`, PID 7540, process start
`2026-03-01T00:57:40.458804Z`, SSH open `00:58:02.730870Z`, transport close
`01:20:40.953388Z`. Its source identity was already absent from both State indexes.
The replay stopped after 715.75 seconds. Diagnostics and partial replay evidence are retained
under `/private/tmp/eforge-ssh-checkpoint-diagnosis`.

The mail-sync red herring expands 56 days of periodic events inside collection hour one.
`set_current_time()` previously expired all ended identity history against each event's
timestamp, including the April ticks, although March 1 SSH continuations were unfinished.
Returning the event cursor to March cannot reconstruct the evicted authority. Original and
diagnostic partial Zeek output both contain ticks through April 25, confirming lookahead.

Two additional bounded probes exposed SSH checkpoint weaknesses: an ended-but-retained
source could be replaced with an empty-LogonID context; PID reuse could either fail capture
or silently serialize the wrong instance when image and LogonID matched. The two existing
SSH checkpoint tests passed; the compatibility test had no source process identity.

## Implementation boundary

- Event cursor assignment/advancement no longer retires identities. The existing monotonic
  PID-allocation watermark, advanced at each completed baseline hour behind the 24-hour
  scheduling window, owns expiry using the unchanged 48-hour late-reference interval.
  It already persists in checkpoint State; no second clock or schema field is introduced.
- SSH transport state binds one canonical process identity and projects its context from it.
  Capture authenticates that identity through its durable object ID and checks the projected
  host, PID, image, LogonID and start time. The existing serialized source-identity slot is
  retained and hydration restores the binding. An unverified image/PID pair is not promoted
  into a process identity.
- The hard retained-identity capacity limits remain. Focused retirement/retention tests and
  checkpoint comparisons must establish bounded cleanup and unchanged unaffected evidence.

## Validation

Six new characterization cases failed on the original implementation and pass with the initial
fix: future lookahead under seeds 42/137, different/same-image PID reuse, retained source binding,
and rejection when canonical object authority is missing. The original 45-day State retention
test now advances the explicit completed-work frontier.

An initial test collection attempt used the wrong CheckpointError import; it was corrected
before characterization. One focused-suite invocation named a nonexistent test module and ran
no tests; the corrected focused invocation passed below. The unsuccessful invocations are
not counted as passing gates.

No complete 56-day replay has been run. Disk availability at diagnosis was about 18 GiB;
the full-run forecast was 19 GiB expected/29 GiB upper peak, so bounded acceptance runs use
separate temporary roots and do not overwrite historical outputs.

### Intermediate results

- Focused State/checkpoint tests: 266 passed. SSH slow regressions: 144 passed.
- Added eight byte-identical legacy SSH resume combinations: modeled/unmodeled source,
  seeds 42/137, and serial/threaded emission. Modeled-source cases visit 56 days ahead
  before capture and restore. All eight pass. Four initial threaded cases exposed a test
  setup error: `flush()` did not quiesce workers before capture. Using the existing
  `barrier_flush()` checkpoint contract corrected the tests.
- Eight new retention/SSH cases pass, including process/session/thread expiry after the
  completed frontier advances, PID reuse, missing authority rejection, and no fabricated
  context for an unknown process.
- First standard run: 8 failures, 8,616 passes, 27 skips, 2,011 deselections (329.07s).
  Three failures observed a cached behavior manifest while an input-validation preservation
  edit changed the source digest during the run; the final declaration was recomputed.
  Five failures depended on event-cursor movement to force retention expiry. Their explicit
  retirement setup now advances the watermark, preserving original assertions, including
  the SMB terminal pin surviving expiry until acknowledgement. The affected modules and
  new regressions then passed all 178 tests. Complete stable-source results follow below.
- Checkpoint matrix: 12 successful, byte-identical resumes (six original-build compatible,
  six final-source exact), six exact-policy rejections, all original bundles unchanged.
  Both seeds and all three targets passed; all 12 participant hydration checks passed.
  Report: `/private/tmp/eforge-ssh-checkpoint-diagnosis/checkpoint-matrix/acceptance.json`.
- Targeted 30-day SSH retention soak: 1 passed, 19 deselected (7.04s). Full soak excluded.
- Ruff lint and formatting pass (858 files); behavior revision 81 validates against
  `2bf815e1`, surface SHA-256
  `d812799a7e7f1f69a13d4103b00060e0644087186563eb516d8ed9c58bc1a5ec`.

Retention now uses the same 48-hour grace behind the already sealed scheduling frontier,
which trails completed engine hours by 24 hours. Ordinary history can therefore cover roughly
72 hours behind the collection cursor instead of 48. This is intentional retention of valid
authority, not unbounded growth; existing hard caps remain. The tests establish bounded
retirement and terminal pin behavior, not immunity to arbitrary overload beyond those caps.

### Completed routine and evidence gates

- Delivery standard suite: **8,628 passed, 27 skipped, 2,018 deselected** (300.77s),
  following the earlier stable-source run of 8,626 passes (328.47s).
  Skips comprise four opt-in external-parser tests, 22 unavailable gitignored sample-data
  tests, and one existing web-access fixture guard requiring full engine setup.
- **44/44 raw-byte comparisons passed** against `2bf815e1`: 32 core matrix cases and
  12 typed-handler/periodic cases. Evidence and ground-truth file sets and bytes match;
  all recorded artifact hashes verify. Only the existing manifest creation-time exception
  and runtime generation log exclusion are used. No golden evidence changed.
  Full file hashes: `/private/tmp/eforge-ssh-checkpoint-diagnosis/raw-byte-comparisons.json`.
- The real FOR668 acceptance replay uses unchanged input, seed 42, default target,
  authored formats and 24-hour checkpoint cadence. It reproduces resolved-scenario
  SHA-256 `9cb33e32d8bf117658b57921bb465c290b1ab948fb2db6ccca38d40332d76568`.
  An early process snapshot showed about 1.2 GiB RSS, above the CLI's 678 MiB forecast
  upper estimate. This is an observation under concurrent testing, not a controlled
  performance comparison or a claim that the correction alone caused the excess.
- Full slow suite: **1,787 passed, 8,884 deselected** (1,246.60s). No slow failures or
  skips. The full soak tier remains excluded; the targeted 30-day SSH soak passed above.

### Actual FOR668 checkpoint and resumed evidence

The unchanged scenario reached and committed simulated hour **24**, passing the original crash
point. All **21 participants** hydrated, with zero dangling process parents, no compatibility
differences and no verification warnings. Two byte-verified copies resumed under exact policy
to hour **25**, suspended through the public control API, and again hydrated successfully.
Their **19 recorded evidence files match byte-for-byte**. Both the original failed evidence
and the new hour-24 checkpoint remain unchanged.

The first run took 2,427.82 seconds (about 40.5 minutes). The supplied failed run reported
36:36. Standard/slow suites and comparison workloads overlapped part of the new run, so these
are operational observations, not an isolated speed comparison. Each copied resume plus
verification took about four minutes (245.31s and 242.44s). No slowdown rejection gate applies.

The temporary first-run harness initially asserted exit zero after deliberately sending
SIGINT at the post-checkpoint barrier. The CLI correctly returned its documented exit **130**
and retained a valid suspension at hour 24. The harness assertion was corrected; the completed
checkpoint was independently verified rather than repeating 40 minutes solely for that
incorrect test expectation. This was not another generation crash.

Suspended bundles contain ordered emitter spools, not published output files. Comparisons
therefore hydrate into disposable scratch runtimes and close only the restored emitters to
render already-recorded rows. They do **not** call generator lifecycle finalizers or generate
terminal events. The first warmup-only renderer probe correctly had no visible evidence and
was rejected as empty; the actual collection checkpoints render 19 files. These are partial
evidence projections, not complete published bundles or completed ground truth.

### Intentional SMB consequences of corrected identity retention

Against the failed run's 19 files (342,689,697 bytes), **15 files are identical**. Four files
change **20 connection rows and 69 SMB file rows**. Public connection/file IDs, record counts,
connection tuples, connection intervals and canonical payload totals remain unchanged.

The old premature expiration also removed ended `userinit.exe` parent identities belonging
to still-running Explorer clients. A bounded reproduction demonstrates that only
`PersistentSmbClientProcessPreparation.parent_object_id` becomes empty after the old expiry;
the corrected cursor movement preserves the entire client recipe. That scalar participates
in `PersistentSmbRootIntent.identity_snapshot()` and the existing full network-request hash.
Network observation uses this request identity to seed capture loss and Zeek file timing.
Preserving the real parent therefore changes these deterministic samples without changing the
fingerprint algorithm, sampler, canonical file sizes or transport amounts.

Every differing field was checked. Connection changes are limited to capture loss, observed
byte/packet accounting and its history markers. File changes are limited to source timestamps,
durations, seen/missing bytes and whether complete-file analyzers/hashes are available.
For every affected row, observed bytes plus missing bytes reproduce the same canonical total.
The sampling variations themselves are not additional realism repairs; they follow from the
corrected parent identity. No output patch, normalization or golden replacement was applied.

Two added SMB characterization cases (seeds 42/137) preserve the ended parent and exact
client recipe used by the root identity snapshot across 56-day lookahead. Both pass (final
focused rerun: 6.01s). Early versions of this test used an incomplete standalone network
request; fixture construction was simplified to exercise the real client preparation without
inventing physical transaction owners. Final Ruff checks and behavior-manifest validation pass.

### Retained acceptance reports

All paths below are relative to `/private/tmp/eforge-ssh-checkpoint-diagnosis`:

| Report | SHA-256 |
|---|---|
| `raw-byte-comparisons.json` (44 cases, 1,107 artifacts) | `73bcc976ef965f67e894d0b4dc0379b08df511faf10affc4698e2244ce0ef162` |
| `checkpoint-matrix/acceptance.json` (12 resumes, 6 rejections) | `12db4b0a049323a1e8560c9c95927a4eea478ac9113909b10f34d5c2065dafe4` |
| `for668-checkpoint-acceptance.json` (actual hour 24 plus two hour-25 resumes) | `96a0b624554197687c9f05064307d40343f075a990749f4577078dcca99c0d3c` |
| `for668-hour24-comparison.json` | `5e505a36b8820e1ffb9ee15f5da37797565bfeed95c34cef9a9ea43074d73c6f` |
| `for668-hour24-attribution.json` | `32bb0071dc54a5bf9267e3bf16468a27388c81ced2962914e4dedf97a526a97e` |
| `for668-hour25-comparison.json` | `d910ba9d87bea172c062593913cf6fa4d1a05fd010f0c62848511c5ea9b0e3fb` |

The original failed run has no recovery checkpoint to resume. The new verified recovery
is `for668-fixed-hour24`; the disposable resumed copies are `for668-fixed-resume25-a` and
`for668-fixed-resume25-b`. A full 56-day run, additional long-scenario seeds, and overload
beyond the existing hard retention caps remain outside this bounded verification.
