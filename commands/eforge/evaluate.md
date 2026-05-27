---
name: eforge-evaluate
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
description: >
  Run EvidenceForge data quality evaluation on generated log output, interpret results, review records
  for realism, and suggest improvements. Use this skill whenever the user wants to evaluate generated
  data quality, check their logs for issues, review eval scores, assess hunting feasibility, or improve
  a scenario's output. Also trigger when the user says "evaluate", "check quality", "how did the data
  turn out", "review the output", or "eforge eval".
---

# EvidenceForge Data Quality Evaluator

You are helping the user evaluate the quality of generated synthetic security log datasets using EvidenceForge's evaluation framework. The eval command scores datasets across **4 pillars** with 20 sub-scores, all deterministic and statistical. Your job is to run the eval, interpret the results, review sample records for realism, and provide actionable improvement suggestions.

## Quick Start

If the user has a generated output directory and scenario file:

```bash
eforge eval scenarios/<slug>/data --scenario scenarios/<slug>/scenario.yaml --verbose
```

If they don't have generated output yet, suggest using `/eforge generate` first.

For detailed field documentation and known limitations of each log format, use the `/eforge:references:evidence-formats` skill.

## Workflow

### Step 1: Locate the Output

The user needs to provide (or you can infer) the scenario directory. The standard layout is:

```
scenarios/<scenario-name>/
  scenario.yaml
  ENVIRONMENT.md
  artifacts/         ← optional authored collateral, not eval input
  GROUND_TRUTH.md
  OBSERVATION_MANIFEST.json  ← optional, generated for source-observation-aware eval
  data/              ← this is the output_dir for eforge eval
```

If the user provides the scenario directory (e.g., `scenarios/retail-store-ftp-attack/`), derive:
- Data directory: `scenarios/<name>/data/`
- Scenario file: `scenarios/<name>/scenario.yaml`

Ignore optional `artifacts/` contents for evaluation; they are exercise collateral, not generated log output.

If they don't specify, look for scenario directories under `scenarios/`. Ask if you can't find it.

### Step 2: Run the Evaluation

Run both text and JSON output:

```bash
eforge eval scenarios/<name>/data/ --scenario scenarios/<name>/scenario.yaml --verbose
```

Also capture the JSON for programmatic analysis:

```bash
eforge eval scenarios/<name>/data/ --scenario scenarios/<name>/scenario.yaml --format json 2>/dev/null
```

### Step 3: Interpret Results

Present a clear summary of the evaluation results. The report shows two tiers for each acceptance criterion:
- **Minimum** (hard gate): must pass or the dataset fails overall
- **Aspirational** (informational): a stretch target; failure here is noted but does not fail the dataset

If the scenario uses `observation_profile` other than `complete`, check whether the report says
the observation manifest was loaded. With a manifest, coverage-style causality sub-scores may be
adjusted for expected source gaps and will show a `raw` score when the adjusted score differs.
Do not describe this as a lowered threshold: visible contradictions, parseability failures,
source-native field mismatches, and evidence marked `visible` or `delayed` remain real failures.

For each pillar, explain what the score means in practical terms:

**Pillar 1: Parseability (weight 0.30)**
- Spec Conformance: Does every record parse cleanly under strict-mode rules? Missing required fields? Type violations? `eforge eval` reads `OUTPUT_TARGET.txt` to choose target-specific variants, treating a missing marker as legacy/default. Windows/Sysmon XML and SOF-ELK® Snare syslog both map to the canonical Windows buckets; default RFC5424 syslog and SOF-ELK RFC3164/year syslog both map to `syslog`; typed columns for Zeek; schema-strict for eCAR.
- Format Constraints: Do records satisfy `FormatDefinition` constraints (field ranges, enum values, structural rules)?

**Pillar 2: Plausibility (weight 0.25)**
- Value & OS Plausibility: Are field values and OS/platform combinations realistic? (bash_history from a Windows host, Linux paths in Windows process events, IPs outside expected subnets — all failures here.)
- Co-occurrence Rules: Do field combinations make sense? (Network logons have IP addresses; TLS version matches cipher suite; no body in CONNECT tunnels.)
- Distribution Fit: Are event-type proportions realistic for each format?
- Cross-Source Field Agreement: When the same event appears in multiple log sources, do shared fields agree? Uses pivot-key joins defined in `cross_source_pairs.yaml` — pairs include Windows 4688 ↔ eCAR PROCESS/CREATE (same PID+host → same process name), zeek_conn ↔ Cisco ASA (same 4-tuple), web_access/proxy ↔ zeek_http (same client+URI+10s bucket → same status/method), zeek_ssl ↔ zeek_x509 (cert chain fuids → server_name ∈ SAN). A score below 100 means real field disagreements were found.
- User Behavioral Diversity: Do different users behave differently, or are they cookie-cutter clones?
- Benign Anomaly Rate: Is there a realistic 1–5% rate of anomalous-but-benign events? Zero anomalies is as implausible as 50%.

**Pillar 3: Causality (weight 0.25)**
- Causal Ordering: Are logon→process→logoff and lock→reauth→unlock sequences correctly ordered? DNS before TCP? Kerberos/DC TGT/TGS before domain logons? NTLM/DC validation and Windows audit/process-access companions after their owning evidence?
- Storyline Event Presence: Are all expected-visible storyline events visible in at least one log source? For non-`complete` observation profiles with a manifest, source rows marked `dropped`, `filtered`, or `out_of_window` are excluded from this coverage denominator.
- Indicator Accuracy: Do traces carry the correct IPs, usernames, hostnames from the scenario?
- Pivot Linkability: Can a hunter pivot between consecutive expected-visible attack steps using shared field values?
- Storyline Temporal Integrity: Are expected-visible attack events in the right relative order at the right times?
- Storyline Trace Coverage: For each expected-visible log format group on each involved host, does the storyline leave a trace?

**Pillar 4: Timing (weight 0.20)**
- Attack-Chain Timing: Do elapsed times between consecutive storyline steps fall within plausible bounds? Bounds come from `timing_bounds.yaml` — default 5s–2h, with per-action-type overrides (e.g., lateral movement: 30s–1h, exfiltration: 60s–24h). First matching keyword in the step activity wins.
- Human Inter-arrival (Burstiness): Are inter-event times bursty (realistic) or metronomic (robotic)?
- System Regularity: Do automated/system processes show appropriate inter-event regularity?
- Diurnal Pattern: Do user events cluster within persona-defined work hours and day-of-week patterns? Scored via Jensen-Shannon divergence between a 2D (weekday × hour) observed histogram and the persona's reference profile. Penalizes both off-hours concentration AND artificially uniform distributions (which indicate robotic, non-human timing).
- Volume Adequacy: Is there enough background noise relative to the attack signal?
- Rate Plausibility: No impossible rates (≤20 events/5-sec per user; ≤10 Gbps Zeek transfers)?

**Supplementary: Host Log Profile**

The report also shows a diagnostic "Host Log Profile" section (not scored). For each host, it lists which log formats were expected (based on the host's OS and scenario configuration) and which were actually present. Use this section to diagnose missing coverage, not as a scored gate.

### Step 4: Qualitative Record Review

Sample ~10 records from the output directory across different formats. Read them and assess:

1. **Record Realism** — Do individual records look like they came from a real system? Flag anything that looks synthetic, implausible, or templated.
2. **Narrative Coherence** — Read 15-20 events around a storyline step. Does the sequence tell a coherent story? Any gaps or contradictions?
3. **Hunting Feasibility** — Given the scenario description and data, could a hunter realistically discover this attack? What approach would work? What obstacles exist?

Present these as qualitative observations, clearly separated from the numeric scores.

For blind realism reviews, inspect only the generated data unless the user explicitly asks to use
the scenario or `GROUND_TRUTH.md`. Tell reviewers that the dataset is a bounded collection-window
extract: sessions, processes, connections, leases, or other state may have started before the
visible window, so missing pre-window initiators are not automatically impossible. Still flag a
visible initiating event that appears later than a dependent event for the same identifier, such as a
same-host `4688` process event before a later `4624` for the same LogonID.
Do not treat a Type 7 Windows `4624` unlock as the original session creation event; it can
legitimately appear after earlier in-window process activity for a session that began before the
collection window.

### Step 5: Suggest Improvements

For any sub-score below 70, provide specific, actionable suggestions:

| Common Issue | Suggestion |
|-------------|-----------|
| Low spec conformance | Check for empty required fields, type mismatches, or invalid enum values in the generator |
| Low value/OS plausibility | Look for cross-OS contamination (Linux paths in Windows logs, Windows events on Linux hosts) |
| Low volume adequacy | Increase `baseline_activity.intensity` or add more users/systems |
| Low user diversity | Add more persona types with different work patterns and activities |
| Low burstiness | Known generator limitation — events are near-uniformly distributed with some Hawkes process noise |
| Low diurnal pattern | Check persona work_hours definitions; may need off-hours event tuning. If the sub-score shows N/A, the scenario span is <24 h or covers only one weekday — too short to measure; this is expected and not a failure. |
| Low benign anomaly rate | Generator may need more variation in baseline (failed logons, errors, access denials) |
| Low cross-source agreement | Real field mismatches between paired formats (e.g., proxy status ≠ zeek_http status). Sample failures show the specific disagreeing field+value pairs. If proxy and Zeek disagree on status codes, the generator may use different status assignment logic per format. |
| Low attack-chain timing | Consecutive storyline events too fast (< min_seconds) or too slow (> max_seconds). Check `timing_bounds.yaml` overrides; adjust storyline timing or add intermediate steps. |

If multiple issues trace back to the same root cause (e.g., generator limitations), group them and explain the root cause once.

### Step 6: Acceptance Criteria

Report whether hard acceptance criteria pass or fail:
- Spec Conformance ≥ 95% (hard gate)
- Value & OS Plausibility ≥ 95% (hard gate)
- Causal Ordering ≥ 90% (hard gate)
- Storyline Event Presence ≥ 85% (hard gate)

If any hard criterion fails, explain what would need to change to pass. Report aspirational targets as a summary line: how many were met out of total.

## Command Reference

```
eforge eval <output_dir> --scenario <scenario.yaml> [--format json|text] [--verbose] [--real-parsers]
```

- `--format text` (default): Rich terminal output with colored scores
- `--format json`: Machine-readable JSON (status messages go to stderr)
- `--verbose`: Show sample failures and detailed sub-score information
- `--real-parsers`: Reserved flag — real parser backend not yet implemented (no-op, exits cleanly)
