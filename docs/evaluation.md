# Evaluation resources and scaling

`eforge eval` reads the full dataset without fixed corpus-byte, file-count, or record-count
ceilings. It runs independently of generation and does not modify the input bundle.

```bash
uv run eforge eval /path/to/bundle --format json
uv run eforge eval /path/to/bundle --memory-budget-mib 128 --scratch-dir /path/to/scratch
```

The scratch directory must already exist and be writable. Each run creates its own private
subdirectory and removes that directory after success, failure, or interruption. Evaluation never
cleans unrelated files in the selected parent. Scratch storage is disposable, without a persistent
cache or resume contract. A forcibly killed process can leave an abandoned private directory.

## Memory and disk

The default 256 MiB budget controls retained evaluation working state. It is a spill threshold,
not a hard total-RSS ceiling. Runtime allocations, captured scenario/compact authored metadata,
individual parser records, SQLite caches, and temporarily active iterators also consume memory.
The detailed canonical occurrence sidecar is streamed. Existing per-record and metadata input
protections remain enforced.

The evaluator parses each source record once and validates it during ingestion. It shares user,
service, distribution, process-frequency and source-identity facts across checks. Source records
have run-local stable identities so disk spill cannot change duplicate detection or schema-invalid
record exclusion. Growing collections and ordering work move to SQLite; small later working sets
can continue using available memory. Complete failure counters remain separate from bounded
report examples. Existing statistical score definitions and sampling contracts are unchanged;
large corpora do not select a reduced-coverage evaluation mode.

Scratch consumption grows with the facts/indexes required by the dataset and can exceed the input
size. A smaller memory budget can increase disk I/O. Unavailable storage fails the evaluation with
an actionable diagnostic and no completed report; there is no silent truncation or partial pass.
CLI JSON stdout remains one report on success, with progress/errors on stderr.

`report.supplementary.evaluation_resources` records the selected working-memory threshold, the
estimated peak retained scoring state, and whether the scoring workspace spilled. Integrity
verification uses a separate workspace with the same resource policy. The estimate is not measured
process RSS. Elapsed phase timings are exposed through progress callbacks and benchmark measurements.

## Compatibility

- CLI and Studio use the same default resource policy.
- `--allow-large-evaluation` is accepted as a deprecated no-op for historical queued commands.
- The Python `EvaluationLimits` constructor type remains available for compatibility; its legacy
  corpus ceilings no longer reject input. Use `EvaluationEngine(memory_budget_bytes=...,
  scratch_dir=...)` for resource controls.
- Existing score definitions, applicability, source attribution, acceptance gates, and legacy
  schema-3/4 behavior remain. Removing corpus ceilings does not waive per-record validation,
  source restrictions, bundle integrity, or scenario-comparison checks.
- Persistent caching, parallel workers, and generation/evaluation overlap are outside this change.

## Verification

The evaluator's regression oracle in `tests/fixtures/eval/reference-f93a25bf.json` was produced by
an untouched export of pre-change dev commit `f93a25bf`, using the tracked good corpus and retail
scenario. Tests compare both new memory and forced-spill paths against that saved report, excluding
only `evaluated_at` and the additive resource diagnostic.

The implementation worklog records larger retained-bundle old/new comparisons, memory and timing
measurements, including performance limitations. Fresh-process measurements include integrity
verification and scoring; an ordinary operating-system file cache may be warm. No benchmark needs
to regenerate a dataset.

Measure an existing bundle and compare it with a previously saved reference report:

```bash
uv run python scripts/benchmark_evaluation.py /path/to/bundle \
  --output-dir /path/to/measurements --label candidate \
  --compare-report /path/to/reference-report.json
```

Use identical scenario/configuration inputs and compatibility flags for both runs. Measurements
must be written outside the input bundle. Labels cannot overwrite earlier measurements.

### Fixed workload memory regression gate

The large-corpus correctness test separately verifies all 500,002 records, including a malformed
final record, exact denominators, spill and scratch cleanup. It does not impose a total-RSS limit.

Run the resource gate in its own process, outside pytest and coverage:

```bash
uv run python -m scripts.check_evaluation_memory --output-dir /path/to/new-memory-results
```

The versioned profile in `tests/fixtures/eval/memory-workloads.yaml` fixes three corpus sizes,
two workload families and a 16 MiB working-state budget. Distinct process identities stress
cardinality; correlated eCAR and Zeek rows exercise process, file, tuple, UID, DNS and TLS indexes.
Each case must retain exact source populations, pass schema validation, spill and clean its scratch.
The gate then checks both absolute RSS and the largest growth above the smallest corpus in each
family. These envelopes apply to the fixed fixtures, not arbitrary user scenarios or the default
256 MiB working-state budget, and finite scaling checks do not prove bounds for every input.

Each evaluator starts in a fresh process, prepares its inputs/imports, reports readiness and waits
until the external observer is sampling. RSS is sampled every 10 ms during evaluation, with the
baseline and final resident set also included. Very brief peaks between samples can be missed.
Process-lifetime `ru_maxrss` remains diagnostic: on Linux it can retain pre-exec parent history.
Do not subtract two high-water marks to estimate evaluation memory. A controlled retained-parent
probe checks that unrelated parent allocations do not inflate the sampled worker metric; later
workers may have lower startup RSS. Import bytecode and OS caches may be warm.

The extended release workflow requires separate native memory jobs on Linux x86_64/ARM64,
macOS ARM64 and Windows x86_64 using Python 3.12. Reports retain source/harness/profile identities,
input hashes, interpreter details, baseline/peak RSS, sample counts and evaluator resource facts,
including on envelope failure. Ordinary OS caches may be warm; no persistent evaluator cache is
used. Recalibration requires inspecting complete native measurements and documenting headroom,
rather than raising a limit until CI passes. `--measure-only` collects calibration evidence without
enforcing candidate limits; release workflow calls cannot select that bypass.
Recovery of a historical tagged source without this harness retains its original
gates through an explicit source-bound compatibility policy. That policy rejects
current sources containing the harness and cannot excuse a failed memory job.
