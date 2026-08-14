# Persona overlays

Read this reference only for project-local persona configuration. Sector-wide personas belong in an
industry pack; one scenario's concrete users belong in that scenario.

## Location and merge behavior

Store one persona per file at `.eforge/config/personas/<name>.yaml`. The filename stem must equal
`name`; a mismatch is skipped and validation fails. A new name adds a persona. A name matching a
packaged persona deep-merges supplied fields into that persona: scalars replace, mappings recurse,
and lists append. Scenario-inline persona definitions have final precedence.

Read the matching packaged persona before overriding it. For a new persona, provide every required
field:

```yaml
name: nurse
description: Clinical nurse using EHR and routine web applications
typical_activities:
  - Review patient charts
  - Coordinate care
work_hours: 7am-7pm
application_usage:
  - Chrome
  - EHR Client
risk_profile: medium
browsing_intensity: light
```

## Fields

| Field | Contract |
|---|---|
| `name` | Required identifier; must match the filename. |
| `description` | Required human-readable role description. |
| `typical_activities` | Required list of normal activities. |
| `work_hours` | Required `9am-5pm`-style range; half-hours and optional `(lunch 12pm-1pm)` are supported. |
| `application_usage` | Required descriptive list. It does not grant application access. |
| `risk_profile` | `low`, `medium`, or `high`; affects baseline event volume and Hawkes burstiness. |
| `browsing_intensity` | `light`, `normal`, or `heavy`; affects browsing-session depth and subresources. |

Risk is not an authorization level. Application eligibility is controlled by each entry's
`personas` list in `application_catalog.yaml`.

Current browsing-session ranges are:

| Intensity | Pages | Navigations | Subresources per page |
|---|---:|---:|---:|
| `light` | 1 | 0 | 3-6 |
| `normal` | 1-2 | 0-1 | 5-10 |
| `heavy` | 2-4 | 1-3 | 8-15 |

## Dependencies and repair policy

- Query `eforge info personas --project-root <root>` before choosing a name.
- If the user names exact applications, adding the persona to those existing applications is a
  directly implied repair: apply it and report it.
- Do not infer application access from `application_usage`, risk, title, or typical activities. Ask
  which applications should include the persona.
- Persona names do not need to match every key in `bash_commands.yaml`. That file contains shared
  command roles such as `dba`, `webadmin`, and `security`, and maps personas to them at runtime.
- Add `persona_traffic` only when the user requests reusable persona-specific network behavior.

After any mutation, run `eforge validate-config --project-root <root> --json` in a fresh process.
