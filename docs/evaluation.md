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
