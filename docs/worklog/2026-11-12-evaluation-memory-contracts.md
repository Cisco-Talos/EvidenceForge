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
dispatch. Reports are uploaded even when a gate fails. Initial 512 MiB/64 MiB
envelopes are calibration candidates, not accepted measurements.
