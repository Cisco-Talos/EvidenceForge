# Dual-signal SnortML + signature + Splunk-notable triage corpus

Labeled evaluation corpus for **composite confidence and disposition** training —
not flat malicious/benign labels.

SnortML documentation and agentic-SOC practice require that an **ML probability is
not equivalent to a signature true positive**. Corpora that flatten both into a
single “bad” label teach the wrong automation habit (false containment, agent
compute burn, FP feedback starvation).

This pack is a deterministic answer key for triage / decision-plane eval, and
every event is paired with real, generated underlying evidence — not just an
asserted label. `evidence-scenario.yaml` (run with `--seed 1234`) generates the
correlated web access, Zeek, Snort/IDS, and Windows-security evidence each
labeled event actually derives from: the two SQLi cases that claim a fired
signature really do have a matching `snort_alert.log` line for the real
Emerging Threats SID (`2009714`), the ML-only case really is a request the
same curated signature set does **not** match (a genuine detection blind spot,
not an invented absence), and the two Splunk-notable-shaped cases are grounded
in real Windows 4625 failed-logon volume (61 attempts vs. 2) rather than a
hand-picked risk score. `validate_dual_signal_triage_corpus.py` checks this by
reading the generated files directly — see [Evidence](#evidence) below.

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
| [`corpus/labeled_events.json`](corpus/labeled_events.json) | Labeled events, each with an `evidence` pointer |
| [`corpus/schema.json`](corpus/schema.json) | JSON Schema for the envelope, including the `evidence` shape |
| [`evidence-scenario.yaml`](evidence-scenario.yaml) | EvidenceForge scenario that generates the underlying evidence |
| `evidence/` | Generated output of `evidence-scenario.yaml --seed 1234` (not checked in generation artifacts like `.venv`/`__pycache__`; `GROUND_TRUTH.json` and `data/` are) |
| [`../../scripts/validate_dual_signal_triage_corpus.py`](../../scripts/validate_dual_signal_triage_corpus.py) | Policy validator (schema + ML≠signature rules + evidence verification) |

## Evidence

Each event's `evidence` field names a `ground_truth_record_id` (a record in
`evidence/GROUND_TRUTH.json`) and one or more `sources`: a file path plus a
literal `match` substring, optionally with `min_count`/`max_count`. The
validator does not trust these — it opens each file and checks the substring
is actually there, and cross-checks `ids_alert` presence in
`GROUND_TRUTH.json` against what `signal_class` claims (`signature_only` /
`signature_plus_ml` must have a fired signature; `ml_only` must not). A corpus
event that drifts from what the generator actually produced — the wrong
`ground_truth_record_id`, a match string that isn't in the file, an `ml_only`
label pointing at a request that actually fired the signature — fails
validation instead of silently shipping.

The SQLi variant that fires the signature vs. the one that doesn't is decided
by `adversarial_payload`'s per-event seed-based variant selection (see
[`adversarial_payload.md`](../../docs/reference/adversarial_payload.md)), not
hand-picked after the fact — `evidence_seed: 1234` in the corpus pins which
outcome landed on which event. Regenerating with a different seed can change
that mix; re-run the validator after any regeneration.

To regenerate the evidence from scratch:

```bash
uv run eforge generate scenarios/dual-signal-triage-corpus/evidence-scenario.yaml \
  --seed 1234 -o scenarios/dual-signal-triage-corpus/evidence
```

## Validate

```bash
uv run python scripts/validate_dual_signal_triage_corpus.py \
  scenarios/dual-signal-triage-corpus/corpus/labeled_events.json

# Schema/policy checks only, skip the on-disk evidence check
uv run python scripts/validate_dual_signal_triage_corpus.py \
  scenarios/dual-signal-triage-corpus/corpus/labeled_events.json --no-evidence-check

# Or run the unit suite
uv run pytest tests/unit/test_dual_signal_triage_corpus.py --no-cov
```

The validator **fails** if any `ml_only` event with high ML score is labeled
`fix_now`, `auto_contain`, or otherwise treated as a signature TP, or if any
event's `evidence` doesn't check out against the generated files (see
[Evidence](#evidence)).

## Safety

- Synthetic IPs and rule IDs only (RFC 5737 / documentation ranges).
- No exploit payloads, no ungated malware samples, no PSIRT/CVE claims.
- Engine parser memory-safety issues belong in Cisco PSIRT — not this corpus.

## Production consumer

Aegis Decision Fabric consumes this envelope for composite confidence, gated
remediation, and FP/TP feedback packs:
<https://github.com/AAH20/aegis-decision-fabric>
