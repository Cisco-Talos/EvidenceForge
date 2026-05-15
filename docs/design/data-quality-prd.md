# EvidenceForge Data Quality Evaluation — PRD

> **Status:** ⚠️ SUPERSEDED — the 5-dimension design below was replaced by the 4-pillar restructure in v0.5.1 (2026-04-30). See the decision log at the bottom of this file for rationale. The 4-pillar design is implemented and is the current state of `eforge eval`.

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
    engine.py              # Orchestrates all pillars, produces report
    report.py              # Report formatting (text, JSON)
    pillars/
        __init__.py
        parseability.py        # Pillar 1: spec_conformance + format_constraints
        plausibility.py        # Pillar 2: value_plausibility, co_occurrence, distribution_fit, field_agreement, user_diversity, anomaly_rate
        causality.py           # Pillar 3: causal_ordering, event_presence, indicator_accuracy, pivot_linkability, temporal_integrity, storyline_trace_coverage
        timing.py              # Pillar 4: attack_chain_timing, burstiness, system_regularity, diurnal_pattern, volume_adequacy, rate_plausibility
    _shared.py             # Shared helpers (field maps, username/hostname extractors, JSD)
    storyline.py           # resolve_storyline(), ResolvedEvent dataclass
    rules/
        __init__.py
        co_occurrence.py       # Co-occurrence rules per format
        distributions.py       # Reference distribution profiles
        causal_pairs.py        # Known causal ordering rules
    visibility.py              # Builds sensor/source visibility model from scenario
    anomaly.py                 # Lightweight anomaly detection for anomaly_rate
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

---

## 4-Pillar Redesign (v0.5.1, 2026-04-30)

### Motivation

The 5-dimension model accumulated sub-scores organically and had two problems:

1. Several sub-scores did not measure what their names suggested (Cross-Source Field Agreement's `_timestamps_agree` was a near-no-op; Baseline Coherence had a tautology concern — the evaluator and generator share the same `VisibilityModel`).
2. Hard gates at 98/95/99/90 were aspirational rather than empirically grounded.

The framework was refocused on four concrete goals that describe what makes generated logs useful for threat hunting training:

- **Parseability** — logs parse under the same rules real downstream parsers use
- **Plausibility** — field values and combinations are realistic; no impossible or highly improbable situations
- **Causality** — ordered relationships between events are correct
- **Timing** — attack-chain timing and background noise distributions are plausible

### Decision Log

| Sub-score | Decision | Rationale |
|-----------|----------|-----------|
| D2.4 Baseline Coherence Sampled | Demoted to supplementary `host_log_profile` diagnostic | Generator and evaluator share the same `VisibilityModel`; scoring it creates a tautology. Kept as an informational debug view. |
| D2.5 Baseline Coherence Aggregate | Merged with D2.4 → `host_log_profile` | Same tautology concern. |
| D2.3 Cross-Source Field Agreement | Kept under Plausibility; implementation to be rewritten | Good concept (same event in multiple sources should show matching shared fields), broken implementation (timestamp heuristic was a near-no-op). Rewrite uses `cross_source_pairs.yaml` + pivot-key joins. |
| D3.2 User Behavioral Diversity | Kept under Plausibility | Homogeneous user populations are implausible. |
| D3.4 Organic Anomaly Rate | Kept under Plausibility; decoupled from red-herring count | Zero-anomaly datasets are implausible. Red herrings are pre-declared storyline injections, not organic background anomalies — they were incorrectly inflating the rate. |
| D4.5 Old Timing Plausibility | Kept under Timing as `rate_plausibility` | Per-actor rate caps are a distinct actionable signal; kept separate from co-occurrence checks. |
| D4.1 Work Hours | Replaced by planned `diurnal_pattern` | Work hours is a 1D check; diurnal_pattern adds day-of-week axis and KL divergence against persona profiles. |

### 4-Pillar Structure

| Pillar | Weight | Hard gates |
|--------|--------|-----------|
| 1. Parseability | 0.30 | spec_conformance ≥ 95 |
| 2. Plausibility | 0.25 | value_plausibility ≥ 95 |
| 3. Causality | 0.25 | causal_ordering ≥ 90, event_presence ≥ 85 |
| 4. Timing | 0.20 | none (aspirational only) |

### Two-Tier Thresholds

Every sub-score now has:
- **minimum**: hard gate; `acceptance_passed=False` if any gated sub-score misses its minimum
- **aspirational**: informational stretch target; failure is noted but does not fail the dataset

Thresholds are stored in `src/evidenceforge/config/evaluation/thresholds.yaml` for tuning without code changes. Calibration against purpose-built scenarios is deferred to a separate pass.

Datasets generated with non-`complete` observation profiles include `OBSERVATION_MANIFEST.json`.
When present, eval uses it to adjust coverage-style causality sub-scores for evidence that was
intentionally `dropped`, `filtered`, or `out_of_window`. Hard correctness gates remain strict:
observation profiles do not excuse parse failures, impossible values, source-native contradictions,
or evidence marked `visible`/`delayed` but missing from logs.

### Calibration Plan

Thresholds are currently judgment-based. After the restructure is stable, the plan is to design purpose-built calibration scenarios (known-good and known-bad), run `eforge eval` against them, and use the results to propose empirically grounded threshold values. Out of scope for v0.5.1.

---

## event_presence Root-Cause Analysis (2026-04-30)

Investigation of the apt-healthcare-breach baseline dataset (42 storyline events).

### Confirmed eval bugs fixed in this pass

| Bug | Root cause | Fix |
|-----|-----------|-----|
| FQDN hostname mismatch | Signal integrity index keyed records as `ws-dev-02.meridianhcs.com` but lookup used `ws-dev-02`. Records with FQDN Computer fields were never found. | Added bare-hostname (prefix before first `.`) as a second index key in `_build_host_time_index`. Affected formats: windows_event_security, windows_event_sysmon, syslog. |
| Beacon timing window too tight | TIME_TOLERANCE (120s) applied symmetrically; beacons start within their first interval (up to 30m), so the first record missed the window. | For `_DURATION_EVENT_TYPES` (beacon, dns_tunnel, dga_queries, web_scan), extend forward search window by `min(interval, 1h)`. |
| `logoff` type unmatched | `logoff` event type had no `_record_matches` branch — fell through to `return False`. | Added matcher: Windows 4634/4647, syslog "session closed"/"Disconnected from", bash_history `exit`/`logout`. |
| `raw` type unmatched | Raw cleanup events (no specific type) had no branch. | Added matcher: accept any record on the declared host (raw means no specific signature). |

### Remaining failures after fixes (6 of 42 events)

| Event | Type | Category | Detail |
|-------|------|----------|--------|
| Event 3: rogue DHCP | `dhcp_lease` | **(c) Generator gap** | Generator doesn't produce a DHCP record with the rogue laptop's IP/MAC from the storyline event spec. |
| Event 24: DC-01 beacon +5h45m | `beacon` | **(c) Generator gap** | DC-01 (server VLAN) never generated outbound connections to the C2 IP. No path through proxy for server-class systems. |
| Event 25: DC-01 beacon +6h | `beacon` | **(c) Generator gap** | Same as above (deny variant — firewall blocks). |
| Event 36: standalone DNS | `dns_query` | **(c) Generator gap** | DC-01 never emitted zeek_dns queries for the specified FQDN targets at `+10h`. |
| Event 37: WEB-EXT-01 beacon +10h | `beacon` | **(c) Generator gap** | The `+10h` repetition is outside the confirmed first-beacon window; WEB-EXT-01 may have stopped generating them. |
| Event 38: DC-01 late beacon +12h | `beacon` | **(c) Generator gap** | Same root cause as Events 24/25 — DC-01 has no C2 outbound path. |

**Score after fixes**: 69.05 → 85.71 (36/42 events found). `acceptance_passed: True`.

### Threshold decision

The 85% minimum hard gate (6 events missing = 14%) appropriately flags the generator gaps listed above. No threshold change from the provisional value.
