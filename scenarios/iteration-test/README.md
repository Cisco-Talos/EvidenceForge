# Canonical iteration-test benchmark

The active Scenario 2.0 benchmark now includes the Mac-supported mixed fleet:
9 named users, 23 systems (two macOS 27 arm64 workstations), and a six-hour window
starting November 2, 2026 at 13:00 UTC, with two hours of warmup. The pinned
`evidenceforge/technology@1.0.0` industry pack, include structure, baseline and
existing Windows/Linux storyline are retained. The Mac epoch updates the inherited
raw Apache timestamp to agree with the collection window.

## Mac timing

Compact introductory terminal queries use human typing cadence. Longer local and
SSH inspection groups use jittered intervals around their former approximate span.
Chrome helper starts use variable automated delays (300ms–2s). Six explicit inventory
activations now declare successful completion after a variable 100–750ms delay,
replacing six exact two-second lifetimes. These are bounded modeling choices, not
native timing measurements. The existing canonical scheduling and lifecycle owners
keep native ES, eCAR and shell history aligned; no output timestamps are rewritten.
Complete Mac process-start coverage remains required.

## References and output status

- The exact previous Windows/Linux inputs are preserved under
  [`tests/fixtures/scenarios/iteration-test-pre-macos`](../../tests/fixtures/scenarios/iteration-test-pre-macos/README.md),
  including their original names, relative includes and SHA-256 manifest.
- [`ORIGIN.json`](ORIGIN.json) records promotion and per-group timing changes.
- [`ENVIRONMENT.md`](ENVIRONMENT.md) describes the current attack-free environment.
- The retained [`iteration-test-macos`](../iteration-test-macos/README.md) variant
  has matching timing policies and contains the historical assessment reports.

Existing adjacent generation manifests, data and eval results belong to the previous
input. They have not been rewritten and are stale for this scenario. Likewise, Mac
assessment loops 1–42 predate these timing edits; none establishes a new score for
the revised benchmark. Generate into a fresh output directory for new comparisons.
The intentionally low baseline retains its known noise-to-signal validation warning.
