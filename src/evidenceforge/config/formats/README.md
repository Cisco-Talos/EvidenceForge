# Format Definitions

Each YAML file in this directory defines a single log format for EvidenceForge.
The filename (without `.yaml`) is the format name used throughout the system.

## Loader

`evidenceforge.formats.loader` — loads and validates these files against the
`FormatDefinition` Pydantic model. Results are cached in memory.

## File Structure

```yaml
name: format_name
version: "1.0"
description: "Human-readable description"
category: host | network | ids    # Where this format originates
fields:
  - name: field_name
    type: string | integer | float | datetime | boolean | ip_address | enum
    required: true | false
    description: "Field description"
    constraints:            # Optional validation rules
      min_length: 1
      allowed_values: [...]
variants:                   # Optional event-type variants
  - name: variant_name
    condition: { ... }      # JSON Logic condition
    fields: [...]           # Additional/overriding fields
output:
  format: text | json | xml | csv
  template: "Jinja2 template string"
  file_extension: ".log"
```

## Adding a New Format

1. Create `{name}.yaml` in this directory following the structure above.
2. See `docs/reference/EVIDENCE_FORMATS.md` for the full field type and constraint reference.
3. Run `uv run pytest tests/unit/test_format_loader.py` to validate.
