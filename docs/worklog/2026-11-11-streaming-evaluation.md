# Standalone bounded-memory evaluation

Approved plan: remove whole-corpus evaluation ceilings while retaining scoring semantics and input
protections. Priorities: accuracy, resource efficiency, speed. Evaluation must never overlap or
modify generation. Persistent caching and worker parallelism are explicitly deferred.

Implementation branch: `codex/streaming-evaluation`, based on dev `f93a25bf`, in an isolated
worktree so the primary checkout's uncommitted generation/realism work remains untouched.

## Architecture

- Shared evaluation workspace, stable record IDs, 256 MiB working-state spill threshold.
- Stream parsers into compact retained facts, with SQLite-backed collections/indexes and ordering.
- Preserve validation exclusions and all existing check applicability/acceptance semantics.
- Replace unbounded intermediate containers and corpus text concatenation; retain exact counters
  and bounded diagnostic examples.
- CLI memory/scratch controls, compatible deprecated override, Studio setting migration.
- Equivalence, forced spill, skew/lifecycle, resource/scaling, and cleanup verification.

## Progress

Grounding found object-identity-dependent exclusions, repeated corpus scans/index construction,
per-user timestamp arrays, and whole-format payload strings. Existing ground-truth relationship
verification already uses disposable SQLite. File discovery also retains the full path inventory.

Implementation, compatibility, scale and full routine validation pass.

## Correctness evidence so far

Reference runtime is a clean `git archive f93a25bf src` export at
`/private/tmp/eforge-evaluation-reference`, using the existing installed dependencies with an
explicit PYTHONPATH. The primary checkout's uncommitted source is never the reference oracle.
Retained benchmark bundles were not modified. Large inputs were written only in disposable test
fixtures; generation was not run for these benchmarks.

- Tracked 20-record fixture: saved the complete old report (excluding evaluated_at) as
  `tests/fixtures/eval/reference-f93a25bf.json`; both memory and forced-spill tests match it.
- Retained legacy schema-3 `iteration-test/blind-test/v2-loop-60/review-data`: 122,916 records;
  exact old/new report equality after excluding evaluated_at and additive evaluation_resources.
- Retained schema-5 `iteration-test/blind-test/loop-89/bundle`: 148,961 records, 6,197 canonical
  occurrences; exact old/new report equality with the same exclusions.
- Initial broader selection: 557 tests passed, including evaluation/ground-truth and Studio
  settings/queue contracts. Further changes still require fresh checks.

Initial measurements exposed a real speed regression and are not acceptance results:
legacy reference 18.74 s / 841,646,080 bytes peak RSS vs early spill 53.26 s / 380,796,928 bytes;
schema-5 reference 41.29 s / 1,012,793,344 bytes vs intermediate hybrid 93.74 s / 472,645,632 bytes.
These are fresh-process measurements with a potentially warm OS file cache, not cold-disk claims.
The 235-second cProfile run is instrumentation evidence, not a runtime benchmark.

Profiling isolated repeated record-size traversals, per-record Path.resolve(), redundant IP
normalization and repeated model hydration. Repairs cache record sizes, hoist file-owned
paths, short-circuit exact string equality, bound IP-normalization caching, reuse small RAM
working sets after corpus spill, share ordered buckets, and return schema validity directly from
validation to avoid rebuilding the valid corpus. A schema-5 missing-bucket bug was found and
fixed with a regression test. Performance and resource-scaling measurements are recorded below.


## Current acceptance measurements

Fresh processes, potentially warm OS file caches, Apple Silicon macOS; timings are measurements,
not throughput guarantees. Both engines used the explicit compatibility flag so the existing
`evaluation_capacity.limits_overridden` field also matches. Every old/new report field matches
exactly except `evaluated_at` and the additive `supplementary.evaluation_resources` object.

| Retained corpus | Records | Old eval seconds | New eval seconds | Old peak RSS bytes | New peak RSS bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| schema-3 v2-loop-60 | 122,916 | 18.741 | 44.373 | 841,646,080 | 408,633,344 |
| schema-5 loop-89 | 148,961 | 41.287 | 56.010 | 1,012,793,344 | 416,153,600 |

The 256 MiB default substantially reduces RAM but has a measured disk/correlation time cost.
This remains an explicit tradeoff, not a claim of improved wall-clock time over the unbounded
old evaluator. The CLI exposes a larger working-memory budget for users choosing more RAM.
Before the final direct-map lookup optimization, the two corpora measured 42.639 and 56.635
seconds respectively. A 512 MiB schema-5 run also matched exactly, at 53.053 seconds and
668,188,672 bytes peak RSS, versus 56.532 seconds / 420,741,120 bytes at 256 MiB on that revision.
The modest speed gain did not justify doubling the default budget given the resource-efficiency
priority. Final map lookups avoid redundant SQL existence/length queries, but produced no material
end-to-end speed gain. The final table and the budget comparison overlapped the routine test suite;
they are corroborating measurements rather than isolated throughput guarantees.
The workspace includes bounded in-run record hydration/IP normalization caches, not persistent
verified-result caches. Source validation, local plausibility/co-occurrence, distributions,
user/service timing, anomaly context and pivot indexes share ingestion. Legacy host/time queries
batch and deduplicate candidates before hydration while preserving first-match ordering.
Additional final checks cover nonalphabetical source insertion order through spill and valid
JSON numbers split within their decimal/exponent across stream chunks.
Directory discovery and authoritative inventory verification use streaming `scandir` traversal,
avoiding `Path.iterdir()`'s Python-3.12 directory-sized filename list. A separate slow check
verified a 10,005-file inventory using a 64 KiB working-state threshold (passed in 5.02 seconds).
Final affected checks passed after those changes: 179 evaluation/ground-truth tests and 23 storage
tests, including explicit missing-counter-key semantics and the pre-change report oracle.

The relevant slow tests passed (2 tests, 253.83 seconds, without coverage):
- A fresh process evaluated **500,002 records**, including 500,001 valid, distinct process IDs
  and a malformed final record. It reported that final failure at line 500002, failed the hard
  acceptance gate, and retained full denominators. Peak RSS was **161,218,560 bytes** with a
  **16,777,216-byte working-state budget**; scratch cleanup passed.
- An 18 MiB email artifact manifest streamed successfully with per-message protections retained.

Other completed checks: affected UI **118 passed**, TypeScript no-emit, generated API-type parity,
canonical skill conversion/installation, Ruff check/format and whitespace checks. A sandboxed
routine run stopped on localhost binding denial in native Studio helpers (211 passed before
that boundary). The native rerun completed with **20,168 passed, 72 skipped, 2,452 deselected**
in **2,118.06 seconds**, including the three helper/ownership cases, using localhost access.
The earlier failures were environment permissions, not product defects; no gate was weakened.
The final affected rerun passed **573 tests, 3 deselected, in 12.04 seconds**, covering the later
traversal/map refinements, all evaluation/ground-truth tests, and Studio evaluation behavior.

Retained input `iteration-test/blind-test/v2-loop-60/review-data` manifest SHA-256: `5d27e88e7f94963778104d92efb9409035e97e7dd177b3466a41c3d524c8432f`.

Retained input `iteration-test/blind-test/loop-89/bundle` manifest SHA-256: `bb59fd94083f683da1fb3c03bf826107f01cb3f8a9538c54777076322b823fc0`.
