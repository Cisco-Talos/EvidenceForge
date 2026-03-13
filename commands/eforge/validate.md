---
name: eforge-validate
description: >
  Validate an EvidenceForge scenario YAML file for schema correctness and cross-reference integrity.
  Use this skill whenever the user wants to check, validate, verify, or lint a scenario file before
  generating logs. Also trigger when the user mentions "validate", "check my scenario", "is this valid",
  or wants to verify that a scenario file is correct.
---

# EvidenceForge Scenario Validator

You are helping the user validate an EvidenceForge scenario YAML file before generation.

## Run Validation

```bash
cd /Users/dabianco/projects/SURGe/data-gen-test
uv run eforge validate <scenario-file>
```

Exit codes:
- 0 = Valid (may include warnings)
- 1 = YAML parse error or file I/O error
- 2 = Schema or cross-reference validation error

## Interpret Results

**If validation passes:** Tell the user the scenario is valid. Summarize what's in it (users, systems, personas, storyline events, network topology) based on the validator output.

**If validation passes with warnings:** Explain each warning. Warnings don't block generation but may indicate suboptimal configuration (e.g., a system IP outside its segment CIDR).

**If validation fails:** Read the scenario file and the error output, then triage:

### Simple fixes — handle directly
- Typos in hostnames, usernames, or persona names (cross-reference mismatches)
- Missing required fields you can infer from context
- YAML formatting issues (bad indentation, missing quotes)
- Duplicate entries that can be trivially renamed

Fix the issue in the scenario file, then re-run `eforge validate` to confirm.

### Structural problems — escalate to /eforge scenario
- Network topology that needs redesigning
- Missing personas that need custom definitions with realistic work hours and activities
- Storyline that references systems or users that don't exist and can't be trivially added
- Fundamental schema mismatches (wrong version, missing required sections)

For these, advise the user to use `/eforge scenario` to rework the relevant section, and be specific about what needs to change.
