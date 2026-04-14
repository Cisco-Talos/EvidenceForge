# Persona Configuration Reference

Schema documentation for persona definition files in `src/evidenceforge/config/personas/`.

---

## Overview

Each persona is a single YAML file that defines a user role's behavior profile. The filename must match the persona name (e.g., `developer.yaml` defines persona `developer`). Personas are referenced by name in:

- `application_catalog.yaml` `personas:` lists — controls which apps the persona can spawn
- `traffic_profiles.yaml` `persona_traffic:` section — custom network patterns
- `bash_commands.yaml` role keys — Linux command vocabularies
- Scenario YAML `users:` entries — assigns personas to users

## Schema

```yaml
name: developer                               # Must match filename (without .yaml)
description: "Software engineer who writes     # Free-text role description
  code, runs builds, and uses version
  control frequently"
typical_activities:                            # List of activity descriptions
  - "Write and edit source code"
  - "Run builds and tests"
  - "Push/pull from git repositories"
  - "Browse documentation and Stack Overflow"
  - "Attend video meetings"
work_hours: "9am-6pm (lunch 12pm-1pm)"        # Work schedule with lunch break
application_usage:                             # List of app display names (informational)
  - "VS Code"
  - "Terminal"
  - "Chrome"
  - "Docker"
  - "Git"
risk_profile: "high"                           # low, medium, or high
browsing_intensity: "heavy"                    # light, normal, or heavy
```

## Field Reference

| Field | Type | Required | Valid Values | Description |
|-------|------|----------|-------------|-------------|
| `name` | string | yes | Must match filename | Persona identifier, referenced across config files |
| `description` | string | yes | Free text | Human-readable description of the role |
| `typical_activities` | list[string] | yes | Free text | What this person does day-to-day |
| `work_hours` | string | yes | Format: "Xam-Ypm (lunch Xpm-Ypm)" | Active working period. Engine generates activity only during these hours. |
| `application_usage` | list[string] | yes | App display names | Informational list of apps this persona uses. Actual app access is controlled by `application_catalog.yaml` `personas:` lists. |
| `risk_profile` | string | yes | `low`, `medium`, `high` | Controls activity diversity and access level |
| `browsing_intensity` | string | yes | `light`, `normal`, `heavy` | Controls proxy session depth — how many pages and subresources per browsing session |

## Risk Profile Meanings

| Value | What It Controls |
|-------|-----------------|
| `low` | Minimal system access, simple activity patterns, few applications. Typical: receptionist, intern. |
| `medium` | Standard access, moderate activity diversity. Typical: sales, marketing, HR, project manager. |
| `high` | Elevated access, diverse tools including admin/dev tools, more varied activity. Typical: developer, sysadmin, security analyst. |

## Browsing Intensity Meanings

| Value | Session Behavior |
|-------|-----------------|
| `light` | 1-2 pages per session, few subresources. Low proxy log volume. |
| `normal` | 3-5 pages per session, typical subresource loading. Moderate proxy log volume. |
| `heavy` | 5-10+ pages per session, deep navigation, many subresources. High proxy log volume. |

## Creating a New Persona

1. Create `personas/{name}.yaml` with ALL required fields
2. Add the persona name to `personas:` lists in relevant `application_catalog.yaml` entries
3. Consider whether the persona needs:
   - Custom traffic patterns → add to `traffic_profiles.yaml` `persona_traffic:` section
   - Custom bash commands (Linux users) → add role entry to `bash_commands.yaml`
4. The `application_usage:` list is informational — actual app spawning is controlled by the `application_catalog.yaml` `personas:` field

## Built-In Personas

| Name | Risk | Browsing | Typical Use |
|------|------|----------|-------------|
| `developer` | high | heavy | Software engineers |
| `sysadmin` | high | normal | IT infrastructure |
| `security_analyst` | high | normal | SOC analysts |
| `analyst` | medium | normal | Business analysts |
| `data_analyst` | medium | normal | BI/data teams |
| `executive` | medium | normal | C-suite/directors |
| `project_manager` | medium | normal | PMs/scrum masters |
| `accountant` | medium | normal | Finance/accounting |
| `sales` | medium | normal | Sales reps |
| `marketing` | medium | normal | Marketing staff |
| `hr` | medium | normal | Human resources |
| `help_desk` | medium | normal | IT support |
| `legal_counsel` | low | light | Legal/compliance |
| `receptionist` | low | light | Front desk |
| `intern` | low | light | Interns/trainees |

## Common Mistakes

- Filename doesn't match `name:` field (persona won't resolve correctly)
- Missing `browsing_intensity:` (engine may fall back to default, but it's a required field)
- Listing apps in `application_usage:` but forgetting to add the persona to those apps' `personas:` lists in `application_catalog.yaml` (the persona will never actually spawn them)
- Using `work_hours:` format without lunch break (engine expects the parenthetical lunch notation)
