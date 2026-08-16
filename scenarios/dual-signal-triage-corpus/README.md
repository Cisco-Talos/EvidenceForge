# Dual-signal SnortML + signature + Splunk-notable triage corpus

Labeled evaluation corpus for **composite confidence and disposition** training —
not flat malicious/benign labels.

SnortML documentation and agentic-SOC practice require that an **ML probability is
not equivalent to a signature true positive**. Corpora that flatten both into a
single “bad” label teach the wrong automation habit (false containment, agent
compute burn, FP feedback starvation).

This pack is a static, deterministic answer key for triage / decision-plane eval.
It does **not** claim to generate full IDS/SIEM log streams; pair it with
EvidenceForge scenario generation when you need correlated wire-format noise.

## Cases

| `case` | Signal | Ground-truth disposition |
|---|---|---|
| `signature_only_high` | Classic signature (GID ≠ 411) | `fix_now` |
| `snortml_gid411_high_ml_only` | GID 411, high `ml_score`, no SID | `escalate` (**never** `fix_now` / auto-contain) |
| `signature_plus_ml_corroboration` | Signature + high ML | `fix_now` |
| `snortml_low` | GID 411, low `ml_score` | `accept` |
| `splunk_notable_high_risk` | Splunk-notable shaped | `triage_t2` |
| `splunk_notable_low` | Splunk-notable shaped | `triage_t1` |

Corpus metadata always sets `never_equate_ml_to_signature: true`.

## Files

| Path | Role |
|---|---|
| [`corpus/labeled_events.json`](corpus/labeled_events.json) | Labeled events |
| [`corpus/schema.json`](corpus/schema.json) | JSON Schema for the envelope |
| [`../../scripts/validate_dual_signal_triage_corpus.py`](../../scripts/validate_dual_signal_triage_corpus.py) | Policy validator (schema + ML≠signature rules) |

## Validate

```bash
uv run python scripts/validate_dual_signal_triage_corpus.py \
  scenarios/dual-signal-triage-corpus/corpus/labeled_events.json

# Or run the unit suite
uv run pytest tests/unit/test_dual_signal_triage_corpus.py --no-cov
```

The validator **fails** if any `ml_only` event with high ML score is labeled
`fix_now`, `auto_contain`, or otherwise treated as a signature TP.

## Safety

- Synthetic IPs and rule IDs only (RFC 5737 / documentation ranges).
- No exploit payloads, no ungated malware samples, no PSIRT/CVE claims.
- Engine parser memory-safety issues belong in Cisco PSIRT — not this corpus.

## Production consumer

Aegis Decision Fabric consumes this envelope for composite confidence, gated
remediation, and FP/TP feedback packs:
<https://github.com/AAH20/aegis-decision-fabric>
