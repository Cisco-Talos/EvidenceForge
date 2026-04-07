# Personas

Pre-built user persona definitions. Each YAML file defines a single persona
that can be referenced by name in scenario files (e.g., `persona: developer`).

## Loader

`evidenceforge.utils.personas` — loads all `*.yaml` files from this directory,
merges them into scenario data at load time. Inline personas defined in scenario
YAML take precedence over pre-built ones with the same name.

## File Structure

```yaml
name: persona_name           # Required — referenced by scenario users
description: "Human-readable role description"
typical_activities:
  - "Activity description 1"
  - "Activity description 2"
work_hours: "8am-5pm (lunch 12pm-1pm)"
application_usage:
  - "Application1"
  - "Application2"
risk_profile: "low"          # low | medium | high — drives Hawkes timing parameters
```

## Adding a New Persona

1. Create `{name}.yaml` in this directory following the structure above.
2. The persona is automatically available for use in scenarios — no code changes needed.
3. Reference it in scenario YAML: `persona: {name}`.
