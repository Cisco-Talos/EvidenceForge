# Evaluation Rules Configuration Reference

Schema documentation for data quality evaluation rule files in `src/evidenceforge/config/evaluation/`.

## Table of Contents

1. [co_occurrence.yaml](#co_occurrenceyaml)
2. [distributions.yaml](#distributionsyaml)
3. [causal_pairs.yaml](#causal_pairsyaml)

---

## co_occurrence.yaml

Tier B record-level fidelity checks. Each rule verifies that when a condition matches in a generated record, required field constraints hold. These catch records where fields are inconsistent with each other.

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

### Conventions

- Group rules under the format name they apply to
- Rule names should describe what's being validated in plain English
- Use `exclude:` to skip known edge cases (e.g., ANONYMOUS LOGON has no IP)
- Each rule should test one logical constraint

---

## distributions.yaml

Tier C population statistics checks. Defines expected distributions for field values across all generated records, with divergence tolerances. Used to verify that the overall data mix is realistic.

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
- Add distributions for new formats when there's enough understanding of expected proportions

---

## causal_pairs.yaml

Temporal realism checks (Dimension 4). Each pair defines a "before" event and an "after" event that must be correctly ordered when they share matching field values.

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
