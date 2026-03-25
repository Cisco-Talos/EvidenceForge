# EvidenceForge Data Quality Evaluation — PRD

> **Status:** ✅ COMPLETE (Phase 4, implemented 2026-03-16)

## Context

EvidenceForge generates synthetic security log datasets for threat hunting training. To improve our generation quality, we need a systematic way to evaluate generated datasets. This PRD defines quality criteria, scoring methodology, and the design of an evaluation tool (`forge eval` or similar) that produces actionable quality reports.

**Primary use case**: threat hunting training (most demanding; if we satisfy this, AI training and demo use cases are also covered).

**Key principle**: the evaluation framework is format-agnostic at the criteria level. Specific check implementations will be format-aware, but the dimensions and scoring model apply broadly as new log formats are added.

---

## Quality Dimensions

### Dimension 1: Record-Level Fidelity (weight: 0.15)

Each record must be syntactically valid, contain realistic field values, and have internally consistent field combinations.

**Sub-scores:**

| Sub-score | What it measures | How to score |
|-----------|-----------------|--------------|
| **Tier A: Parsability & Structure** (0.40) | Record parses, required fields present, types correct (valid IPs, ports 0-65535, timestamps parse, etc.) | `100 * passing_records / total_records` |
| **Tier B: Co-occurrence Rules** (0.35) | Field combinations that must co-occur or are mutually exclusive (e.g., Win 4624 LogonType=3 requires non-empty IpAddress; Zeek `service: dns` requires `id.resp_p: 53`) | `100 * records_passing_all_rules / records_with_applicable_rules` |
| **Tier C: Population Statistics** (0.25) | Aggregate distributions match realistic profiles (event type distribution, user agent diversity, process name frequency power-law) | Compare observed vs reference distributions; normalized divergence score |

**Implementation notes:**
- Tier B rules are built incrementally — start with 5-10 high-value rules per format, expand over time
- Existing format validator at `src/evidenceforge/formats/validator.py` covers Tier A checks; extend for Tier B
- Tier C requires reference distribution profiles per format (can be derived from real-world datasets or expert knowledge)
- All checks are deterministic/statistical — no LLM calls

---

### Dimension 2: Cross-Source Coherence (weight: 0.25)

Events must leave appropriate traces in all sources that have visibility, and must NOT appear in sources that shouldn't see them. Each source has a specialized view of what occurred; they must all agree within their visibility limits.

**Visibility model**: built from the scenario's declared topology — which hosts have which logging, which network sensors exist and where they're placed, which systems run web servers. The scenario schema already supports this (system services, sensor placement like "core-switch-tap" for Zeek).

**Sub-scores:**

| Sub-score | What it measures | How to score |
|-----------|-----------------|--------------|
| **Source Correctness** (0.20) | Records belong in the source where they appear (no Windows commands in bash_history, no syslog from Windows hosts, no events from nonexistent hosts) | `100 * correct_records / total_records` |
| **Storyline Trace Coverage** (0.20) | Each storyline event has expected traces in all sources with visibility | `100 * found_traces / expected_traces` |
| **Cross-Source Field Agreement** (0.20) | Events appearing in multiple sources have consistent timestamps (UTC-normalized, with tolerance for timezone differences), IPs, usernames | `100 * agreeing_pairs / total_correlated_pairs` |
| **Baseline Coherence — Sampled** (0.20) | Random 5-10% sample of baseline events checked for cross-source traces | Same as Storyline Trace Coverage, applied to sample |
| **Baseline Coherence — Aggregate** (0.20) | Per-user and per-system event counts are proportional across sources | Ratio consistency score across sources |

**Implementation notes:**
- Timezone normalization is critical — scenario defines per-system timezones via `environment.timezone.systems`
- Tolerance for timestamp correlation: ~30 seconds for cross-source matching
- Source Correctness checks: OS-to-format mapping (bash_history = Linux/Mac only, Windows events = Windows only), hostname existence in scenario, IP existence in scenario network (external IPs excepted)

---

### Dimension 3: Background Noise Realism (weight: 0.25)

The background noise must make hunting genuinely challenging. Malicious activity must be hard to separate from normal activity.

**Sub-scores:**

| Sub-score | What it measures | How to score |
|-----------|-----------------|--------------|
| **Volume Adequacy** (0.25) | Noise-to-signal ratio appropriate for declared intensity. Expected ratios: low ~500:1, medium ~5,000:1, high ~10,000:1+ | Score based on meeting threshold; diminishing returns above target |
| **User Behavioral Diversity** (0.25) | Different users behave differently; no cookie-cutter patterns | Pairwise similarity of per-user event type distributions; high entropy = high score |
| **Activity Plausibility** (0.25) | Activities make contextual sense — users access assigned systems, commands match OS, tool usage matches persona/role | Rule-based checks against scenario user/system/persona definitions |
| **Organic Anomaly Rate** (0.25) | Background noise contains realistic anomalous-but-benign activity (false leads for hunters) | Run statistical anomaly detection on background; expect 1-5% flagged as anomalous |

**Anomaly detection approach** (for Organic Anomaly Rate):
- Events outside persona work hours
- Rarely-occurring processes/commands (long tail)
- Failed operations (failed logons, 403/404s, permission denied)
- Connections to ports not associated with declared services
- Score: if 0% anomalous = too clean (low score), 1-5% = realistic (high score), >10% = chaotic (low score)

**Future enhancement**: scenario-defined near-misses — if the scenario explicitly declares expected false-lead events, grade their presence.

---

### Dimension 4: Temporal Realism (weight: 0.15)

Time patterns must reflect how real environments behave. Humans are bursty; systems are periodic.

**Sub-scores:**

| Sub-score | What it measures | How to score |
|-----------|-----------------|--------------|
| **Work Hour Distribution** (0.20) | User events cluster in persona-defined work hours (80-95%), with realistic tails outside | Compare observed distribution to expected; penalize if too flat or too sharp |
| **Human Burstiness** (0.20) | Inter-event timing per user shows burst-and-idle patterns, not metronomic spacing | Coefficient of variation of inter-event times; CV 1-3 = realistic |
| **System Process Regularity** (0.20) | Automated/system events show periodic patterns (cron, scheduled tasks) | Autocorrelation of system-generated event timestamps |
| **Causal Ordering** (0.20) | Known causal pairs are correctly sequenced (logon before activity, process create before file write, logoff after last activity) | `100 * correct_pairs / total_causal_pairs` |
| **Timing Plausibility** (0.20) | No physically impossible timing (50 human commands in 3 seconds, instant multi-GB transfers) | `100 * plausible_events / total_events` |

**Known gap**: current generators largely assume even distribution over time. Human Burstiness and Work Hour Distribution will likely score poorly initially — this is intentional and will drive generator improvements.

---

### Dimension 5: Signal Integrity (weight: 0.20)

The attack storyline must actually materialize correctly in the data, within sensor visibility limits.

**Sub-scores:**

| Sub-score | What it measures | How to score |
|-----------|-----------------|--------------|
| **Event Presence** (0.25) | Storyline events that should be visible (within sensor coverage) produced at least one trace | `100 * found / expected_visible` |
| **Indicator Accuracy** (0.25) | Present storyline events carry the correct indicators (IPs, usernames, hostnames, process names as specified in scenario) | `100 * correct_indicators / total_indicators` |
| **Pivot Linkability** (0.25) | Consecutive storyline steps share at least one common indicator a hunter could pivot on | `100 * linkable_pairs / consecutive_pairs` |
| **Storyline Temporal Integrity** (0.25) | Storyline events appear in correct order at approximately correct times | `100 * correctly_timed / total_storyline_events` (with tolerance) |

**Note**: not all storyline events need to produce traces — realistic gaps are acceptable. Acceptance threshold: Event Presence >= 90%.

---

## Overall Scoring Model

### Composite Score (0-100)

```
Overall = (Dim1 * 0.15) + (Dim2 * 0.25) + (Dim3 * 0.25) + (Dim4 * 0.15) + (Dim5 * 0.20)
```

Each dimension score = weighted average of its sub-scores.

### Acceptance Criteria (separate pass/fail layer)

**Hard requirements** (fail = dataset rejected):
- Dim 1 Tier A (Parsability) >= 98%
- Dim 2 Source Correctness >= 95%
- Dim 4 Causal Ordering >= 99%
- Dim 5 Event Presence >= 90%

**Quality targets** (fail = flagged for improvement):
- Overall score >= 70
- Each dimension >= 60
- Dim 3 Organic Anomaly Rate between 1-5%

### Supplementary Metrics (measured, not scored)

- **Difficulty Estimate**: how hard is the storyline to discover? Based on indicator distinctiveness, signal-to-noise ratio. Reported as a property, not judged as good/bad.
- **Scenario Coverage Assessment**: pre-generation check — does the topology support discovery of the storyline? (Not a data quality score; a scenario authoring concern. Update the scenario creation skill to flag issues.)

### LLM Spot-Check Layer (optional, supplementary)

Enabled via `--llm-review` flag. Runs after all deterministic/statistical scoring. Samples 20-50 records and asks the LLM for qualitative assessment. Does NOT produce a numeric score or affect the composite — produces commentary appended to the report.

**Implementation approach**: all 23 sub-scores are fully deterministic or statistical. Zero LLM calls are needed for scoring. The spot-check layer is a qualitative audit on top.

**Three spot-check types:**

1. **Record Realism**: sample ~10 records per format. "Do these look like they came from a real system? Flag anything synthetic or implausible."
2. **Narrative Coherence**: extract a timeline of 15-20 events around each storyline step. "Does this sequence tell a coherent story? Any gaps or contradictions?"
3. **Hunting Feasibility**: provide scenario description + storyline + data sample. "Could a hunter realistically discover this attack? What approach would you use? What obstacles exist?"

**Cost control**: small sample sizes. This is a quality audit, not per-record checking.

---

## Report Format

```
=== EvidenceForge Data Quality Report ===
Scenario: retail-store-ftp-attack
Generated: 2026-03-16T14:30:00Z
Total records: 47,832 across 5 sources

Overall Quality Score: 78/100

Dimension Scores:
  1. Record-Level Fidelity:       92/100
     Tier A (Parsability):        100/100  [Accept: >=98 PASS]
     Tier B (Co-occurrence):       88/100
     Tier C (Distributions):       82/100
  2. Cross-Source Coherence:       74/100
     Source Correctness:           97/100  [Accept: >=95 PASS]
     Storyline Trace Coverage:     82/100
     Cross-Source Field Agreement: 71/100
     Baseline Coherence (Sample):  65/100
     Baseline Coherence (Agg):     55/100
  3. Background Noise Realism:     71/100
     Volume Adequacy:              85/100
     User Behavioral Diversity:    68/100
     Activity Plausibility:        74/100
     Organic Anomaly Rate:         57/100  [Target: 1-5% FLAG]
  4. Temporal Realism:             65/100
     Work Hour Distribution:       72/100
     Human Burstiness:             32/100
     System Process Regularity:    78/100
     Causal Ordering:             100/100  [Accept: >=99 PASS]
     Timing Plausibility:          95/100
  5. Signal Integrity:             89/100
     Event Presence:               92/100  [Accept: >=90 PASS]
     Indicator Accuracy:           95/100
     Pivot Linkability:            83/100
     Storyline Temporal Integrity: 86/100

Acceptance: PASS (all hard requirements met)
Flags:
  - Human Burstiness: 32/100 (near-uniform inter-event distribution)
  - Organic Anomaly Rate: 0.3% (background noise too clean)

Supplementary:
  Difficulty Estimate: MODERATE (indicator distinctiveness: high, signal ratio: 1:12,400)

LLM Spot-Check (optional):
  Record Realism: "Windows events look authentic. One Zeek record
    has an unusually high duration (86400s) for a DNS query."
  Narrative Coherence: "Lateral movement sequence is well-connected.
    2-hour gap between initial access and recon is unusual."
  Hunting Feasibility: "Attack discoverable via unusual PowerShell
    on SRV-02. High volume of legit admin PS usage adds challenge."
```

---

## Implementation Notes

### New CLI Command: `forge eval`

```
forge eval <output_directory> --scenario <scenario.yaml> [--format json|text] [--verbose] [--llm-review]
```

Reads generated output + original scenario, produces quality report.

### Architecture

```
src/evidenceforge/evaluation/
    __init__.py
    engine.py              # Orchestrates all dimensions, produces report
    report.py              # Report formatting (text, JSON)
    dimensions/
        __init__.py
        record_fidelity.py     # Dimension 1
        cross_source.py        # Dimension 2 (builds visibility model)
        noise_realism.py       # Dimension 3
        temporal.py            # Dimension 4
        signal_integrity.py    # Dimension 5
    rules/
        __init__.py
        co_occurrence.py       # Tier B rules per format (incremental)
        distributions.py       # Tier C reference profiles
        causal_pairs.py        # Known causal ordering rules
    visibility.py              # Builds sensor/source visibility model from scenario
    anomaly.py                 # Lightweight anomaly detection for Dim 3
```

### Computability Analysis

All 23 sub-scores are computable without LLM calls:

**Fully deterministic** (rule-based): D1 Tier A, D2 Source Correctness, D4 Causal Ordering, D4 Timing Plausibility, D5 Event Presence, D5 Indicator Accuracy, D5 Storyline Temporal Integrity

**Deterministic with authored rules** (rules live in YAML alongside format definitions): D1 Tier B (co-occurrence rules, start 5-10 per format), D2 Storyline Trace Coverage (activity-to-source mappings), D2 Cross-Source Field Agreement (matching logic + tolerances), D3 Activity Plausibility (persona-to-activity mappings), D5 Pivot Linkability (pivotable indicator definitions per format)

**Statistical** (computable, needs reference data or thresholds): D1 Tier C (reference distribution profiles per format), D3 Volume Adequacy (threshold per intensity), D3 User Behavioral Diversity (entropy thresholds), D3 Organic Anomaly Rate (statistical outlier detection), D4 Work Hour Distribution (expected distribution shape), D4 Human Burstiness (CV target range 1-3), D4 System Process Regularity (autocorrelation threshold)

**Main investment areas:**
1. Rule authoring — co-occurrence rules, activity-to-source mappings, causal pair definitions (YAML data files)
2. Reference profiles — "normal" distributions for Tier C (start as educated guesses, refine over time)
3. Visibility model — translating scenario topology into "which source sees what" (deterministic logic)

### Key Existing Code to Reuse

- `src/evidenceforge/formats/validator.py` — Tier A validation (parsability, field types, constraints); extend for Tier B
- `src/evidenceforge/formats/definitions/*.yaml` — format field definitions, required fields, type info
- `src/evidenceforge/models/scenario.py` — Pydantic models for parsing scenario YAML (environment, storyline, personas, systems)
- `src/evidenceforge/validation/schema.py` — scenario cross-reference validation patterns

### Incremental Delivery

1. **Phase 1**: Dimension 1 (Record-Level Fidelity) + report framework + `forge eval` CLI command
2. **Phase 2**: Dimension 5 (Signal Integrity) — depends on scenario parsing, simplest cross-source work
3. **Phase 3**: Dimension 4 (Temporal Realism) — statistical checks, independent of cross-source
4. **Phase 4**: Dimension 2 (Cross-Source Coherence) — requires visibility model, most complex
5. **Phase 5**: Dimension 3 (Background Noise Realism) — requires anomaly detection, persona analysis

### Verification

- Unit tests per dimension with known-good and known-bad fixture datasets
- Run `forge eval` on existing test scenarios (minimal, attack, retail-store) to establish baselines
- Verify report output matches expected scores for hand-crafted edge cases
- Integration test: `forge generate` + `forge eval` pipeline

### Scenario Skill Update

Update the scenario creation skill (`commands/eforge/scenario.md`) to check for coverage issues during authoring — flag when storyline events may not be discoverable given the declared sensor topology.
