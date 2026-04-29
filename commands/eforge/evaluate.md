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

You are helping the user evaluate the quality of generated synthetic security log datasets using EvidenceForge's evaluation framework. The eval command scores datasets across 5 dimensions with 23 sub-scores, all deterministic and statistical. Your job is to run the eval, interpret the results, review sample records for realism, and provide actionable improvement suggestions.

## Quick Start

If the user has a generated output directory and scenario file:

```bash
eforge eval <output_dir> --scenario <scenario.yaml> --verbose
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
  GROUND_TRUTH.md
  data/              ← this is the output_dir for eforge eval
```

If the user provides the scenario directory (e.g., `scenarios/retail-store-ftp-attack/`), derive:
- Data directory: `scenarios/<name>/data/`
- Scenario file: `scenarios/<name>/scenario.yaml`

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

Present a clear summary of the evaluation results. For each dimension, explain what the score means in practical terms:

**Dimension 1: Record-Level Fidelity (weight 0.15)**
- Tier A (Parsability): Can every record be parsed? Missing fields? Type errors?
- Tier B (Co-occurrence): Do field combinations make sense? (e.g., network logons have IP addresses)
- Tier C (Distributions): Are event type distributions realistic?

**Dimension 2: Cross-Source Coherence (weight 0.25)**
- Source Correctness: Are records in the right log sources for the system's OS?
- Trace Coverage: Do storyline events leave traces in all expected formats?
- Field Agreement: Do timestamps and identifiers match across sources?

**Dimension 3: Background Noise Realism (weight 0.25)**
- Volume Adequacy: Is there enough background noise relative to the attack signal?
- User Diversity: Do different users behave differently, or are they cookie-cutter? (Command pool diversification gives each user unique project paths and document names.)
- Activity Plausibility: Are activities appropriate for the system/OS/persona? Includes 26 lateral movement patterns (backup, monitoring, AD replication, app→DB, etc.) auto-generated from environment topology.
- Anomaly Rate: Is there a realistic 1-5% rate of anomalous-but-benign events?

**Dimension 4: Temporal Realism (weight 0.15)**
- Work Hours: Do user events cluster in persona-defined work hours? Day-of-week variation is now modeled (Monday login storms, Friday departures, weekend near-zero).
- Burstiness: Are inter-event times bursty (realistic) or metronomic (robotic)? The Hawkes self-exciting temporal model produces natural burst-and-idle patterns; scores should be 80+ with the current engine.
- Causal Ordering: Are logon→process→logoff sequences correctly ordered? Are DNS queries before TCP connections? Are Kerberos TGT/TGS before domain logons? (Expanded by the causal expansion engine — these should score near 100% when the engine is active.)
- Timing Plausibility: No impossible timing (50 commands in 3 seconds)?

**Dimension 5: Signal Integrity (weight 0.20)**
- Event Presence: Are all storyline events visible in the logs?
- Indicator Accuracy: Do traces carry the correct IPs, usernames, hostnames?
- Pivot Linkability: Can a hunter pivot between consecutive attack steps?
- Temporal Integrity: Are attack events in the right order at the right times?

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
| Low parsability | Check for empty required fields in the generator (e.g., empty SIDs) |
| Low volume adequacy | Increase `baseline_activity.intensity` or add more users/systems |
| Low user diversity | Add more persona types with different work patterns and activities |
| Low burstiness | Known generator limitation — events are near-uniformly distributed |
| Low work hour distribution | Check persona work_hours definitions; may need off-hours event generation |
| Low anomaly rate | Generator may need more variation in baseline (failed logons, errors) |

If multiple issues trace back to the same root cause (e.g., generator limitations), group them and explain the root cause once.

### Step 6: Acceptance Criteria

Report whether hard acceptance criteria pass or fail:
- Parsability ≥ 98%
- Source Correctness ≥ 95%
- Causal Ordering ≥ 99%
- Event Presence ≥ 90%

If any hard criterion fails, explain what would need to change to pass.

## Command Reference

```
eforge eval <output_dir> --scenario <scenario.yaml> [--format json|text] [--verbose]
```

- `--format text` (default): Rich terminal output with colored scores
- `--format json`: Machine-readable JSON (status messages go to stderr)
- `--verbose`: Show sample failures and detailed sub-score information
