# Evaluation Rules Configuration Reference

> **This is a reference document for the /eforge:config skill.** If you are trying to add, modify, or remove config entries, invoke /eforge:config instead of using this reference directly. This file contains schema details that the config skill reads during execution.
>
> To discover config file paths, run `eforge info <field>` (e.g., `eforge info paths.activity`). Run `eforge info --fields` to see all available fields.

Schema documentation for data quality evaluation rule files in `src/evidenceforge/config/evaluation/`.

## Table of Contents

1. [thresholds.yaml](#thresholdsyaml)
2. [co_occurrence.yaml](#co_occurrenceyaml)
3. [distributions.yaml](#distributionsyaml)
4. [causal_pairs.yaml](#causal_pairsyaml)
5. [timing_bounds.yaml](#timing_boundsyaml)
6. [cross_source_pairs.yaml](#cross_source_pairsyaml)

---

## thresholds.yaml

Controls the two-tier acceptance model for `eforge eval`. Each sub-score has a **minimum** (hard gate: dataset fails if below) and an **aspirational** target (informational stretch goal). Pillar weights must sum to 1.0.

When a generated dataset includes `OBSERVATION_MANIFEST.json` beside `GROUND_TRUTH.md`,
`eforge eval` automatically applies observation-aware coverage scoring. Non-`complete`
profiles can adjust only coverage-style causality sub-scores (`event_presence`,
`pivot_linkability`, `temporal_integrity`, and `storyline_trace_coverage`) by excluding
evidence that the manifest marks `dropped`, `filtered`, or `out_of_window`. Source-native
correctness gates such as parseability, value plausibility, field agreement, and visible causal
ordering remain strict. Adjusted sub-scores expose `raw_score` in JSON and show `raw:<score>` in
the text report.

### Structure

```yaml
overall:
  minimum: 70          # Overall weighted score must reach this to pass
  aspirational: 85     # Stretch target for overall score

pillars:
  parseability:
    weight: 0.30
    sub_scores:
      spec_conformance:
        minimum: 95
        aspirational: 99
        hard_gate: true    # Causes acceptance_passed=False if missed
      format_constraints:
        minimum: 90
        aspirational: 98
        hard_gate: false

  plausibility:
    weight: 0.25
    sub_scores:
      value_plausibility:
        minimum: 95
        aspirational: 99
        hard_gate: true
      co_occurrence:
        minimum: 85
        aspirational: 95
        hard_gate: false
      # ... etc.
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `overall.minimum` | float | Weighted overall score floor |
| `overall.aspirational` | float | Weighted overall stretch target |
| `pillars.<name>.weight` | float | Pillar weight (all must sum to 1.0) |
| `pillars.<name>.sub_scores.<key>.minimum` | float | Hard floor; `acceptance_passed=False` if missed and `hard_gate=true` |
| `pillars.<name>.sub_scores.<key>.aspirational` | float | Informational stretch target |
| `pillars.<name>.sub_scores.<key>.hard_gate` | bool | Whether missing `minimum` fails the whole evaluation |

### Sub-score keys (current)

| Pillar | Key | Hard gate? |
|--------|-----|-----------|
| parseability | `spec_conformance` | yes |
| parseability | `format_constraints` | no |
| plausibility | `value_plausibility` | yes |
| plausibility | `co_occurrence` | no |
| plausibility | `distribution_fit` | no |
| plausibility | `field_agreement` | no |
| plausibility | `user_diversity` | no |
| plausibility | `anomaly_rate` | no |
| causality | `causal_ordering` | yes |
| causality | `event_presence` | yes |
| causality | `indicator_accuracy` | no |
| causality | `pivot_linkability` | no |
| causality | `temporal_integrity` | no |
| causality | `storyline_trace_coverage` | no |
| timing | `attack_chain_timing` | no |
| timing | `burstiness` | no |
| timing | `system_regularity` | no |
| timing | `diurnal_pattern` | no (skipped when scenario span <24 h or covers only one weekday) |
| timing | `volume_adequacy` | no |
| timing | `rate_plausibility` | no |

---

## co_occurrence.yaml

Pillar 2 (Plausibility) co-occurrence checks. Each rule verifies that when a condition matches in a generated record, required field constraints hold. These catch records where fields are inconsistent with each other, including impossible combinations.

### Structure

```yaml
format_name:                                    # Top-level key matches format name
  - name: "Network logon (type 3) requires valid IP"  # Human-readable rule name
    condition:                                   # When this condition matches...
      EventID: 4624
      LogonType: 3
      exclude:                                   # Optional exclusion filter
        TargetUserName: "ANONYMOUS LOGON"
    checks:                                      # ...these constraints must hold
      - field: IpAddress
        not_equal: "-"
      - field: IpAddress
        not_equal: ""
```

### Condition Fields

| Field | Type | Description |
|-------|------|-------------|
| `{field_name}: value` | any | Field must equal this value for the rule to apply |
| `exclude` | object | If any exclusion field matches, skip this rule |

### Check Types

| Check | Type | Description |
|-------|------|-------------|
| `not_equal` | any | Field value must NOT equal this |
| `present` | bool | Field must be present (if `true`) |
| `min_length` | int | Field string length must be at least this |
| `matches` | string | Field must match this regex pattern |

### Impossible-combo rules (examples to add)

- `LogonType: 3` + workstation target → should not originate from the same workstation (lateral movement indicator, not a co-occurrence violation per se, but `IpAddress` must differ from `Computer`)
- TLS 1.0 + ECDHE or CHACHA20 cipher suites → impossible combination
- Zeek `conn` with `SF` state + `duration: 0` → connection with data but zero duration
- HTTP `CONNECT` method + non-empty response body in `zeek_http` → tunneled connections don't have bodies

---

## distributions.yaml

Pillar 2 (Plausibility) population statistics checks. Defines expected distributions for field values across all generated records, with divergence tolerances. Used to verify that the overall data mix is realistic.

### Structure

```yaml
format_name:                          # Top-level key matches format name
  - field: EventID                    # Field to check distribution of
    reference:                        # Expected distribution (proportions sum to ~1.0)
      4624: 0.20                      # Logon events = 20%
      4625: 0.03                      # Failed logon = 3%
      4634: 0.15                      # Logoff = 15%
      4688: 0.20                      # Process creation = 20%
      4689: 0.12                      # Process termination = 12%
    tolerance: 0.30                   # Max divergence from reference (0.30 = 30%)
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `field` | string | yes | Field name to check distribution of |
| `reference` | object | yes | Map of value -> expected proportion. Should sum to ~1.0. |
| `tolerance` | float | yes | Maximum acceptable divergence (e.g., 0.30 = 30% deviation from reference). Uses Jensen-Shannon divergence. |

### Conventions

- Proportions are educated estimates, not ground truth
- Values don't need to sum to exactly 1.0 (they represent relative proportions)
- Higher `tolerance` means more lenient checking
- Formats to add: `zeek_http`, `zeek_ssl`, `cisco_asa`

---

## causal_pairs.yaml

Pillar 3 (Causality) temporal ordering checks. Each pair defines a "before" event and an "after" event that must be correctly ordered when they share matching field values.

### Structure

```yaml
pairs:
  - name: "Logon before process creation"        # Human-readable pair name
    before:
      format: windows_event_security              # Format of the "before" event
      condition:
        EventID: 4624                             # Condition to match
    after:
      format: windows_event_security              # Format of the "after" event
      condition:
        EventID: 4688
    match_fields:                                  # Fields that must match to form a pair
      before: TargetLogonId                       # Field name in the "before" event
      after: SubjectLogonId                       # Field name in the "after" event
    extra_match: hostname                          # Optional: additional field that must match
    exclude_accounts:                              # Optional: accounts to skip
      - "SYSTEM"
      - "LOCAL SERVICE"
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable description of the causal relationship |
| `before` | object | yes | The event that must occur first |
| `before.format` | string | yes | Format name |
| `before.condition` | object | yes | Field-value pairs to match |
| `after` | object | yes | The event that must occur second |
| `after.format` | string | yes | Format name |
| `after.condition` | object | yes | Field-value pairs to match |
| `match_fields` | object | yes | Which fields link the two events |
| `match_fields.before` | string | yes | Field name in the before event |
| `match_fields.after` | string | yes | Field name in the after event |
| `extra_match` | string | no | Additional field that must match in both events |
| `exclude_accounts` | list[string] | no | Account names to exclude from checking |

### Conventions

- Causal pairs must be logically sequential (logon -> process creation, not the reverse)
- `exclude_accounts` should list system accounts that don't follow normal causal chains
- Cross-format pairs are supported (e.g., eCAR LOGIN before PROCESS CREATE)
- `match_fields` links the events — the before event's field value must equal the after event's field value

---

## timing_bounds.yaml

Per-storyline-transition elapsed-time bounds for the `attack_chain_timing` sub-score. The scorer checks that the time between consecutive storyline events falls within the applicable bounds.

Activity matching is case-insensitive substring match on `StorylineEvent.activity`. The first matching `action_overrides` key wins; defaults apply when no override matches.

### Structure

```yaml
defaults:
  min_seconds: 5         # Minimum realistic gap between any two consecutive attack steps
  max_seconds: 7200      # Maximum (2 hours default); longer gaps fail

action_overrides:
  lateral_movement:
    min_seconds: 30
    max_seconds: 3600
  exfiltration:
    min_seconds: 60
    max_seconds: 86400   # 24 hours — slow exfil is realistic
  recon:
    min_seconds: 1
    max_seconds: 1800
  # ... add more keywords as needed
```

### How to add a custom override

Add a new key under `action_overrides`. The key is a substring of the storyline `activity` field (case-insensitive). Example: adding `"deploy"` covers activities like "Deploy persistence mechanism" or "Deploy beacon stager".

---

## cross_source_pairs.yaml

Maps pairs of log formats to the fields that must agree when the same underlying event appears in both. Used by the `field_agreement` sub-score (pivot-key join approach).

Each pair definition joins format_a and format_b on a pivot key, then checks that `agree_on` fields carry matching values.

### Full Structure

```yaml
pairs:
  - name: "Human-readable pair label"
    format_a: <format name>
    format_b: <format name>
    condition_a:                   # optional: filter format_a records
      FieldName: value
    condition_b:                   # optional: filter format_b records
      msg_id_in: [302013, 302014]  # special: match msg_id against a list
    pivot_key:
      # Single-field pivot:
      a_field: NewProcessId
      b_field: pid
      coerce: hex_to_int           # optional: "hex_to_int" converts "0x1A2B" → 6699
      require_hostname_match: true # optional: join only records on same host
      time_window_seconds: 60      # optional: discard matches >N seconds apart
      # Multi-field pivot (AND join):
      a_fields: ["id.orig_h", "id.resp_p"]
      b_fields: [src_ip, dst_port]
      # list_contains pivot (a_field is a list, each element → lookup b_field):
      a_field: cert_chain_fuids
      b_field: id
      list_contains: true
    agree_on:
      - a_field: NewProcessName
        b_field: image_path
        b_nested: properties       # optional: b_field is inside a nested dict
        normalize: path_basename_ci  # optional: "lower", "path_basename_ci", "cn_from_dn"
        tolerance: 0.10            # optional: numeric ±fraction tolerance
        b_is_list: true            # optional: b_field is a list; a_field must appear in it
```

### Implemented pairs

| Pair | Pivot | agree_on |
|------|-------|----------|
| Windows 4688 ↔ eCAR PROCESS/CREATE | PID + hostname (60s window) | process basename, username |
| Zeek conn ↔ Cisco ASA flow | 4-tuple (orig_h/resp_h/orig_p/resp_p ↔ src/dst/port) | *(pivot match itself is the assertion)* |
| web_access ↔ zeek_http | (client_ip, path/uri, 10s bucket) | status_code, method |
| proxy_access ↔ zeek_http | (client_ip, url/uri, 10s bucket); CONNECT rows excluded | status_code, method |
| zeek_ssl ↔ zeek_x509 | cert_chain_fuids list → x509 id; leaf certs only (host_cert=true) | server_name ∈ san.dns |

### Loader

Uses the shared `load_rules_file("cross_source_pairs.yaml")` from `evidenceforge.evaluation.rules`.
