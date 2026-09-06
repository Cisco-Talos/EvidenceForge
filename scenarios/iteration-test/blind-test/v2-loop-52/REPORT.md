# Iteration-Test Blind Assessment — Loop 52

## Outcome

- Initial verdicts were one Real and three Synthetic, with synthetic-confidence scores 32, 78,
  84, and 93 (average 71.75; spread 61).
- Required deliberation ended unanimously Synthetic, with scores 79, 91, 92, and 96 (average
  89.5).
- The loop-51 proxy-upload contradiction did not recur: both successful legs conserve the same
  authored multipart body with only bounded source-native framing differences.

## Deterministic Evaluation

- Overall score: 96.2705 across 114,409 records; all hard acceptance gates passed.
- Pillars: parseability 99.9991, plausibility 96.9156, causality 93.3705, timing 93.4960.

## Hard-Contract Result

The 18,782,613-byte archive rendered as 18,783,009 proxy client bytes, 18,783,476 Zeek
client-to-proxy bytes, and 18,813,517 Zeek proxy-to-origin bytes. Both legs report zero capture
loss; the 30,041-byte transport delta is bounded TLS/framing overhead rather than divergent body
truth. ASA teardown totals remain directionally compatible.

## Newly Prioritized Findings

- Repeated Snort HTTP User-Agent alerts contradict the sole Zeek HTTP User-Agent on the same
  tuple, and two content alerts are attached to TLS-only origin flows without visible decryption.
- Machine accounts reacquire successful TGTs every few minutes instead of reusing cache state.
- One same-session workstation lock/unlock pair lasts only 0.635 ms and lacks a nearby Type 7
  companion.
- Every Windows host exhausts the same 38-value WFP ThreadID pool; TiWorker ancestry and Linux
  subsystem quotas also repeat across unlike hosts.

## Reports

- `threat-hunter.md`
- `detection-engineer.md`
- `network-forensics.md`
- `host-forensics.md`
- `deliberation.md`
