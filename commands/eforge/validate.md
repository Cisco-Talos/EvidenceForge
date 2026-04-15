---
name: eforge-validate
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
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
eforge validate <scenario-file>
```

Exit codes:
- 0 = Valid (may include warnings)
- 1 = YAML parse error or file I/O error
- 2 = Schema or cross-reference validation error

## Interpret Results

**If validation passes:** Tell the user the scenario is valid. Summarize what's in it (users, systems, personas, storyline events, network topology) based on the validator output.

**If validation passes with warnings:** Explain each warning. Warnings don't block generation but may indicate suboptimal configuration (e.g., a system IP outside its segment CIDR, OS/format mismatches, missing logon events before process execution, causal expansion redundancy — see below).

**Causal expansion redundancy warnings:** The validator detects when storyline events manually specify prerequisites that the causal expansion engine auto-generates (e.g., a DNS query alongside a TCP connection, or Kerberos events alongside a logon). These are warnings, not errors. The fix is to remove the redundant manual events UNLESS they are part of the attack narrative itself (e.g., DNS tunneling, golden ticket forging).

**If validation passes with info-level notes:** Info-level issues (shown with ℹ) are informational observations, not problems. For example, consecutive storyline events that don't share an obvious pivot indicator. Mention them briefly but don't suggest fixes unless the user asks.

**If validation fails:** Read the scenario file and the error output, then triage:

### Simple fixes — handle directly
- Typos in hostnames, usernames, or persona names (cross-reference mismatches)
- Missing required fields you can infer from context
- YAML formatting issues (bad indentation, missing quotes)
- Duplicate entries that can be trivially renamed (including duplicate storyline event IDs)
- Missing storyline event `id` fields
- Typed event field errors (extra/missing fields caught by Pydantic validation)
- Invalid IP addresses in connection events

Fix the issue in the scenario file, then re-run `eforge validate` to confirm.

### Structural problems — escalate to /eforge scenario
- Network topology that needs redesigning
- Missing personas that need custom definitions with realistic work hours and activities
- Storyline that references systems or users that don't exist and can't be trivially added
- Fundamental schema mismatches (wrong version, missing required sections)

### Known optional fields
The following optional fields are valid and should not be flagged as unknown:
- `time_window.warmup` — warm-up duration for state pre-population (default "8h", minimum "1h")

For these, advise the user to use `/eforge scenario` to rework the relevant section, and be specific about what needs to change.
