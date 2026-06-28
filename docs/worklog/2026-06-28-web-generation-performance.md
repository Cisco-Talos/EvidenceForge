# Web/proxy generation performance

## Context

The scenario at `/tmp/scenario.yaml` reproduces progressive slowdown during
web/proxy-heavy generation. A 4h slice completes in roughly 30 seconds, while a
12h pre-fix run from `dev` reached only Hour 9/12 after 8:23 and was interrupted
to avoid spending the implementation session waiting on the known hot path.

The hotspot is recent 5-tuple tracking in `ActivityGenerator`: once the cache
crosses 100,000 entries, each additional reservation can rebuild the whole dict.
Dense web/proxy sessions allocate many short-lived connections, so the cost grows
with accumulated scenario history instead of the active reuse window.

## Fix

Replace count-triggered whole-dict pruning with event-time lazy pruning:

- keep `_recent_connection_tuples` as the source-of-truth dict for compatibility;
- add a min-heap of `(seen_at, tuple_key)` expiration candidates;
- prune only entries older than the existing 24h reuse window relative to the
  candidate event time;
- preserve future tuple reservations for non-monotonic generation order;
- ignore stale heap entries when the dict has a newer timestamp for the same key.

## Validation Notes

Completed:

- Exact pre-fix `dev` 4h SOF-ELK® run:
  `/private/tmp/eforge-equivalence/before-4h-exact`, 27.72s.
- Fixed-branch 4h SOF-ELK run:
  `/private/tmp/eforge-equivalence/after-4h`, 27.99s.
- 4h generated-output equivalence:
  byte-identical and normalized multiset-identical across `data/`,
  `GROUND_TRUTH.json`, and `OBSERVATION_MANIFEST.json`.
- Pre-fix `dev` 12h SOF-ELK run:
  interrupted at Hour 9/12 after 8:23 because it reproduced the known slowdown.
- Fixed-branch 12h SOF-ELK run:
  `/private/tmp/eforge-equivalence/after-12h`, 44.36s, 6,147 web rows and
  1,696 proxy rows.
- Fixed-branch full 48h SOF-ELK run:
  `/private/tmp/eforge-equivalence/after-48h`, 117.49s, 23,347 web rows and
  2,307 proxy rows.
- `eforge eval` on the 48h fixed output parsed 25,654 records and scored
  88/100 overall. Acceptance failed for existing scenario/evaluator reasons:
  SOF-ELK proxy combined rows are currently flagged as invalid ISO timestamps by
  strict `proxy_access` validation, and storyline event presence is not matched
  for this web/proxy-only scenario. This is not attributed to the tuple-cache
  optimization.
- Blind reviewer sampling was skipped after the clean 4h before/after gate proved
  byte-identical generated output for an exact `dev` baseline.
- Focused tests:
  `uv run --no-sync pytest --no-cov tests/unit/test_activity.py tests/unit/test_dns_realism.py tests/unit/test_zeek_activity_contexts.py tests/unit/test_storyline_command_networks.py tests/unit/test_output_equivalence.py tests/unit/test_install_skills.py`
  passed with 548 tests.
- Style gates:
  `uv run --no-sync ruff check .` and `uv run --no-sync ruff format --check .`
  passed.
