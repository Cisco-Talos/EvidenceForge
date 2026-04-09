# EvidenceForge Configuration Data

This directory is the centralized location for all YAML lookup and reference
data used by EvidenceForge. Each subdirectory contains a specific category of
data files, with its own README explaining the file format and structure.

## Subdirectories

| Directory | Contents | Loader Module |
|-----------|----------|---------------|
| `formats/` | Log format field definitions, validators, and templates | `evidenceforge.formats.loader` |
| `evaluation/` | Data quality evaluation rules (causal pairs, co-occurrence, distributions) | `evidenceforge.evaluation.rules` |
| `activity/` | Activity generation lookup tables (DNS, processes, commands, TLS, etc.) | Various modules in `evidenceforge.generation.activity` |
| `personas/` | Pre-built user persona definitions | `evidenceforge.utils.personas` |

## Adding New Data Files

1. Place the YAML file in the appropriate subdirectory above.
2. Create or update a loader in the relevant domain module.
3. Use `from evidenceforge.config import get_{category}_directory` for path resolution.
4. Follow the cached-loader pattern (module-level `_CACHED_DATA`, load-on-first-call).

See `AGENTS.md` § "YAML Data Directory Convention" for the full pattern.
