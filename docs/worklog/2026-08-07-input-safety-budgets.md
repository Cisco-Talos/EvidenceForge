# Batch 6: input safety, budgets, authoring, and reproducibility

## Scope and baseline

- Branch: `codex/batch6-input-safety-budgets`
- Parent: Batch 5 commit `c139c77a`
- Findings: `REAL-013`, `REAL-014`, `SEC-001` through `SEC-010`, and
  `SEC-DEFER-001`
- Constraint: remediate validated findings without generator-side realism changes outside the
  approved contracts. Preserve seed `42` as the compatibility stream.

## Validated patch contracts

### YAML and scenario composition (`REAL-013`, `SEC-005`)

- Attacker input: scenario, include, overlay, persona, and email-corpus YAML mappings.
- Source-to-sink: PyYAML mapping construction and recursive include merging before Pydantic
  validation.
- Required invariant: one authored value per mapping key; source bytes, include files/depth, and
  expanded YAML nodes are bounded before model construction.
- Compatibility: safe YAML tags and all unique-key documents retain their current data shape.
  Existing include limits remain 32 files deep, 256 files, and 16 MiB; the new expanded-node cap is
  1,000,000 logical nodes. A trusted caller may supply a different explicit include budget.

### Filesystem boundaries (`SEC-001`, `SEC-007`, `SEC-008`, `SEC-010`)

- Attacker input: email artifact IDs, corpus references, generated-log trees, and supplied Splunk
  app trees.
- Source-to-sink: scenario-controlled paths reach file reads/writes or external-parser staging.
- Required invariant: scenario assets are regular, non-symlink files below the scenario root;
  output artifacts are one validated filename created exclusively below the artifact root; staging
  never follows a symlink or copies a special file.
- Compatibility: valid relative corpus references, new artifact names, and ordinary regular-file
  trees retain their behavior. Existing artifact overwrite is rejected because an opaque artifact
  identity must be unique within one run.

### Workload and attachment budgets (`SEC-002`, `SEC-003`, `SEC-004`)

- Attacker input: duration/rate/count fields, port-scan CIDRs and ports, attachment sizes/content,
  and enabled format fan-out.
- Source-to-sink: compact scenario fields expand into canonical occurrences, rendered records,
  in-memory MIME payloads, and output bytes.
- Required invariant: generation performs an allocation-free `WorkloadEstimate` before emitter or
  attachment allocation; network sampling is O(requested targets); email payload creation is
  bounded per attachment/message/run.
- Default supported envelope: 31-day primary window; 1,000,000 ticks for one periodic event;
  5,000,000 explicit storyline occurrences; 20,000,000 estimated canonical occurrences;
  200,000,000 estimated rendered records; 25 MiB per attachment; 35 MiB per message; 256 MiB of
  email artifacts per run. The estimator reports every exceeded measure. A named trusted override
  can bypass resource limits, is exposed in both CLI and library APIs, and is recorded in run
  metadata; it never bypasses path safety.
- Compatibility: ordinary scenarios and the reviewed 30-day workload remain inside the envelope.
  IPv4/IPv6 host sampling preserves `ipaddress.hosts()` semantics and deterministic ordering.

### Generation seed (`REAL-014`)

- Attacker/operator input: public integer seed from scenario or CLI override.
- Source-to-sink: global helper calls, thread-local sequential RNG, stable UUID derivation, and
  emitter worker threads.
- Required invariant: one immutable run seed controls every stochastic stream for the run and is
  propagated through worker contexts; two engines cannot silently share a mutable global seed.
- Compatibility: seed `42` preserves the previous stable-hash, stable-UUID, and sequential RNG
  streams. A non-default seed namespaces every stochastic derivation and is recorded in collection
  metadata.

### Evaluation records and capacity (`SEC-006`, `SEC-DEFER-001`)

- Attacker input: generated or third-party log files supplied to `eforge eval`.
- Source-to-sink: record framing and format parsers build `ParsedRecord` lists and pillar indexes.
- Required invariant: individual records are parsed in linear time under a 16 MiB hard record cap;
  evaluation rejects an input corpus before parsing when it exceeds 512 MiB, 10,000 files, or
  500,000 parsed records. A named trusted override is explicit at the evaluator boundary.
- Capacity basis: isolated 25k/50k/100k retained-eCAR probes measured a stable worst observed
  2,958.62 bytes of RSS growth per record. That projects to about 1.48 GB at 500,000 records before
  scorer headroom; the rejected 2,000,000-record proposal projected to 5.92 GB. Results are stored
  in `docs/design/realism-review/evaluator-capacity-results.json`.
- Compatibility: the largest reviewed corpus (453,560 records) remains supported, while default
  evaluation now has a measured capacity envelope.

### Splunk archives (`SEC-009`)

- Attacker input: operator-selected ZIP/TAR application packages.
- Source-to-sink: archive metadata and compressed streams become staged application files.
- Required invariant: paths are contained and regular; no links/devices; no more than 10,000
  members, 2 GiB total expanded bytes, 512 MiB per member, or 200:1 compression ratio. Extraction
  streams through byte counters and cleans partial output on failure.
- Compatibility: ordinary Splunk apps remain accepted; callers may pass an explicit trusted
  archive budget but cannot disable type, symlink, or containment checks.

## Verification order

1. Malicious regression plus legitimate control for each boundary.
2. Focused unit modules and fixture-wide scenario validation.
3. Default non-slow suite and targeted slow/capacity tests.
4. Ruff check/format, deterministic repeat and alternate-seed probes, and review-package update.

## Implementation result

Batch 6 implements every validated contract above without a public schema migration or version
bump. The durable empirical ledger is
`docs/design/realism-review/batch6-results.json`; the standalone capacity measurements are in
`docs/design/realism-review/evaluator-capacity-results.json`.

Key owning-layer changes:

- `utils/yaml_loader.py` is the shared duplicate-rejecting SafeLoader; include composition also
  enforces an expanded-node budget. A scan of 102 shipped YAML documents exposed three duplicate
  site definitions in `activity/site_maps.yaml`; those definitions were reconciled into one truth
  per site instead of preserving last-key-wins shadowing.
- `utils/paths.py` and `utils/assets.py` own no-follow regular-file reads and exclusive contained
  writes. Email corpus validation/runtime and `.eml` materialization use these boundaries.
- `generation/workload.py` owns allocation-free generation and email-expansion estimates. Validation
  and execution share the same limits, and collection metadata records trusted overrides.
- `utils/rng.py` owns the run-scoped seed context. Seed 42 preserves the compatibility stream;
  alternate seeds namespace stable derivations and propagate through emitter worker contexts.
- `evaluation/limits.py` and the shared parser line iterator own corpus and per-record bounds. The
  Snare field parser is now single-pass.
- The Splunk harness rejects symlinks/special files in logs and application directories, preflights
  ZIP/TAR metadata, streams through extraction counters, and cleans partial staging trees.

The site-map repair is the only intentional default-output change in this batch: routes previously
hidden by duplicate mapping keys can now be selected. The seed-42 algorithms and all unique-key
configuration documents otherwise preserve their established streams and shapes.

## Verification results

- Final unrestricted non-slow suite: `5227 passed, 41 skipped` in 251.50 seconds.
- Fixture contract: all 9 scenario fixtures pass schema and semantic validation after built-in
  persona composition.
- Determinism contract: same/default seeds repeat byte-identically; a different seed changes the
  generated data.
- Capacity probe on macOS arm64 / Python 3.12.12: 25k, 50k, and 100k retained eCAR records measured
  73,859,072, 147,554,304, and 295,862,272 bytes of RSS growth. The worst measured slope was
  2,958.62 bytes per record.
- Ruff: all checks passed; all 460 files were already formatted.
- JSON ledgers parse and `git diff --check` is clean.
- Licensed Splunk runtime ingestion remains unavailable; bounded filesystem/archive and loopback
  harness controls passed.

## Handoff

Batch 6 is complete on `codex/batch6-input-safety-budgets`. Batch 7 may now inspect remaining
compatibility fields and documentation claims, but any public API or scenario-schema removal still
requires a separately approved migration rather than silent deletion.
