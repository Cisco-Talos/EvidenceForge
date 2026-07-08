# Rejected Attempt 60-a — Monotonic Blind Loop

## Decision

Rejected. The standalone blind-review average was 44.0, worse than the accepted loop-59 baseline of 38.25. Per the experiment protocol, no deliberation was run and the candidate fix is being reverted.

## Candidate Fix

- Commit under test: `3b43c998 fix: add ASA hidden connection-id volume`
- Target finding: loop-59 Detection Engineer P1 ASA connection-ID bounded 1-5 gap texture
- Owning layer: Cisco ASA source-native emitter
- Intended invariant: visible ASA Built/Teardown IDs remain monotonic and paired, but adjacent visible IDs include deterministic hidden-volume gaps instead of exposing a tiny bounded synthetic increment range

## Verification

- `uv run pytest --no-cov tests/unit/test_cisco_asa_emitter.py`: 60 passed
- `uv run ruff check src/evidenceforge/generation/emitters/cisco_asa.py tests/unit/test_cisco_asa_emitter.py`: passed
- `uv run ruff format --check src/evidenceforge/generation/emitters/cisco_asa.py tests/unit/test_cisco_asa_emitter.py`: passed
- `uv run eforge generate scenarios/iteration-test-expanded/scenario.yaml --output scenarios/iteration-test-expanded/data --force`: passed
- `uv run eforge eval scenarios/iteration-test-expanded/data/data --scenario scenarios/iteration-test-expanded/scenario.yaml --verbose`: PASS, 96/100, 96,389 records
- Hard probe: `hard_probe_asa_connection_ids.json`

## Blind Scores

| Reviewer | Assessment | Verdict Confidence | Synthetic-Confidence Score |
|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 66 | 45 |
| Detection Engineer | Inconclusive | 64 | 43 |
| Network Forensics | Inconclusive | 66 | 56 |
| Host/EDR Forensics | Inconclusive | 68 | 32 |
| Average |  |  | 44.0 |

## Score Movement

- Loop 59 accepted baseline average: 38.25
- Attempt 60-a average: 44.0
- Delta: +5.75, where higher is worse
- Result: reject and revert candidate fix

## Findings to Carry Forward

- Detection Engineer: eCAR FLOW timing repeatedly lags Zeek/syslog transport evidence, including SSH sessions and short DNS flows.
- Network Forensics: repeated `mail-fin.meridianhcs.com` proxy-origin path mismatch; DNS answers internal `10.10.2.27`, but proxy-origin TLS/ASA goes to `54.230.228.12`.
- Threat Hunter: one SSH tuple has endpoint session close roughly 15 minutes before Zeek TCP close, plus repeated rsyslog reload and Sysmon static registry texture.
- Host/EDR: endpoint telemetry mostly realistic; minor bash-history timestamp backstep and filtered Windows Security EventRecordID gaps.

## Notes

The ASA probe showed the intended distribution improvement, and the Detection Engineer no longer flagged the old bounded ASA connection-ID gap. The overall blind average still worsened because new network/timing issues dominated this run, so the monotonic protocol rejects the candidate.
