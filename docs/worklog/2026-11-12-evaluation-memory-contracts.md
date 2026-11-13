# Evaluator memory measurement and fixed workload gates

The user approved separating full-corpus correctness from resource testing,
investigating the RSS measurement and qualifying fixed workload scaling on native
CI platforms. Work is on `codex/evaluation-memory-contracts`, from merged dev
`f67712c2`. No product version or generation behavior change is intended.

The old slow test evaluates 500,001 distinct process records and a malformed final
record with a 16 MiB spill budget. Its coverage, exact denominator, last-record
failure, spill and cleanup checks are retained. Only its process-lifetime RSS
assertion is removed; removing dataset limits did not make those contracts obsolete.

Native CI had reported 732,835,840 bytes from `ru_maxrss`. The new harness records
that metric before and after evaluation, but gates RSS sampled externally at 10 ms
only after input preparation/imports and an explicit ready/start handshake. It does
not subtract high-water marks. A controlled 256 MiB retained-parent probe compares
the same worker with and without unrelated parent pressure.

Two deterministic workloads use 24,000, 72,000 and 216,000 records at the same
16 MiB spill budget: distinct process identities, and correlated eCAR process/file/
flow plus Zeek connection/DNS/TLS/file identities. Full evaluation counts, exact
source populations, schema validity, spill and cleanup must hold before either an
absolute RSS envelope or growth allowance can pass. Negative controls distinguish
constant excessive overhead, sustained/intermediate growth and incomplete work.

The memory gate runs separately from pytest/coverage on native Linux x86_64/ARM64,
macOS ARM64 and Windows x86_64. Its reusable workflow is required by the extended
release gate; diagnostic-only calibration is available solely on explicit manual
dispatch. Reports are uploaded even when a gate fails.

## Native calibration

[Actions run 43331641707](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43331641707)
on `11a74d5e` completed every workload at every size on all four platforms. All
cases retain exact counts, 100% schema conformance, spill and scratch cleanup.
The following are externally sampled RSS in MiB; growth is the maximum above the
smallest size, not merely the last-size difference.

| Platform | Process peaks: 24k / 72k / 216k | Correlated peaks: 24k / 72k / 216k | Largest growth | Peak envelope |
| --- | --- | --- | --- | --- |
| Linux x86_64 | 155.91 / 156.79 / 156.77 | 154.33 / 157.34 / 159.07 | 4.74 | 224 |
| Linux ARM64 | 152.53 / 152.59 / 150.59 | 148.81 / 150.83 / 153.35 | 4.54 | 192 |
| macOS ARM64 | 154.25 / 155.78 / 152.31 | 153.48 / 156.45 / 155.66 | 2.97 | 224 |
| Windows x86_64 | 144.86 / 144.24 / 136.52 | 143.89 / 146.05 / 144.45 | 2.16 | 192 |

Peak envelopes add 25% to the measured platform/family maximum and round up to
32 MiB. Growth adds 16 MiB to observed growth and rounds up to 16 MiB, with a
32 MiB minimum. Both families independently satisfy the resulting limits. These
are fixed workload regression envelopes, not universal evaluator memory caps.

### Lifetime RSS diagnosis and negative control correction

Linux x86_64's retained-parent control reports startup lifetime RSS **297.90 MiB**
while the ready evaluator's sampled peak is **137.13 MiB**. Linux ARM64 similarly
reports **293.94 MiB** versus **133.64 MiB**. This reproduces contamination from
pre-exec history and establishes that a subprocess's lifetime high-water mark is
not an isolated evaluation measurement. It does not prove the precise contribution
to the earlier 732,835,840-byte CI reading without that run's startup counters.

The first probe worker had a higher readiness baseline than subsequent workers,
consistent with cold-import/bytecode-cache differences: clean-to-retained differences
were -38.21 MiB, -35.29 MiB and -80.36 MiB on Linux x86_64, Linux ARM64 and macOS.
The candidate control incorrectly rejected
both increases and decreases over 32 MiB, causing three jobs to fail despite valid
workload results. Corrected it to reject inflation only; added positive and negative
regressions. No memory envelope was raised to accommodate these failures. Python
bytecode and OS caches may be warm in the fixed matrix; startup lifetime counters
and readiness baselines remain visible in the reports.

Routine CI also exposed an older exact release-job-set assertion. It now requires
the additional memory gate, preserving its existing shard and portability checks.
Windows checkout preserves fixture bytes explicitly.

## Verification

- The 500,002-record correctness test passes in 242.48 seconds without coverage.
- The initial 63 focused checks and expanded 189-check evaluation/CI selection pass.
- The corrected history controls, actual worker fixtures and workflow contracts pass
  all 41 focused checks.
- The final combined evaluation, storage, worker and CI selection passes 196 checks
  (three slow checks deselected). Ruff, formatting, whitespace and behavior-manifest
  verification pass.
- A separate local macOS matrix has no failures: process peaks 154.42/153.30/152.88
  MiB and correlated peaks 154.70/157.80/152.86 MiB. Its retained-parent difference
  is 1.44 MiB. Native input hashes are checked against these exact fixture bytes.
- The final calibrated profile and control corrections are rerun natively before
  the draft PR is marked ready. Generation behavior remains revision 512.
