---
name: eforge-generate
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
description: >
  Run EvidenceForge log generation from a scenario file, monitor output, diagnose errors, and suggest fixes.
  Use this skill whenever the user wants to generate logs, run a scenario, produce security training data,
  or troubleshoot generation issues. Also trigger when the user says "generate", "run the scenario",
  "create the logs", "eforge generate", or refers to producing output from an existing scenario file.
---

# EvidenceForge Log Generator

You are helping the user generate synthetic security log datasets from an EvidenceForge scenario YAML file using the `eforge` CLI.

## Quick Start

If the user has a scenario file ready:

```bash
eforge validate scenarios/<slug>/scenario.yaml
eforge generate scenarios/<slug>/scenario.yaml --verbose --force
```

If they don't have a scenario file yet, suggest using `/eforge scenario` to create one first.

## Command Reference

### eforge validate

Checks schema and cross-references without generating any logs. Fast — use this to catch issues before committing to a full generation run.

```bash
eforge validate <scenario.yaml>
```

Exit codes:
- 0 = Valid
- 1 = YAML parse error or file I/O error
- 2 = Schema or cross-reference validation error

### eforge generate

Generates log files from a validated scenario.

```bash
eforge generate <scenario.yaml> [options]

Options:
  --output, -o <dir>     Override the bundle root for generated sidecars and data.
                         By default, current eforge writes beside the scenario file.
  --config, -c <file>    Path to config.yaml
  --formats, -F <list>   Comma-separated format filter. Only generates formats present in both
                         this list and the scenario's output.logs. Supports group names (zeek,
                         windows) and individual format names (zeek_conn, cisco_asa). Use
                         `eforge info format_groups` to see available groups. Example:
                         `eforge generate scenario.yaml --formats zeek_conn,zeek_dns` to
                         generate only Zeek connection and DNS logs.
  --target <name>        Output target: default or sof-elk. The default target is SIEM-neutral.
                         Use sof-elk when generating SOF-ELK-compatible file layouts.
  --force, -f            Overwrite existing output without prompting
  --verbose, -v          INFO-level logging
  --debug, -d            DEBUG-level logging
```

Exit codes:
- 0 = Success
- 1 = Input error (file not found, bad path)
- 2 = Schema validation failed
- 3 = User declined overwrite (aborted)
- 21 = Generation error
- 130 = User interrupted (Ctrl+C)

## Workflow

### 1. Pre-flight Check

Before running generation:
- Verify the scenario file exists and is valid YAML
- Read the scenario to understand what will be generated (users, systems, time window, formats)
- Run `eforge validate <scenario-file>` to catch issues early
- Give the user a brief summary: "This will generate ~X hours of logs for Y users across Z formats"

### 2. Run Generation

```bash
eforge generate scenarios/<slug>/scenario.yaml --verbose --force
```

Always use `--verbose` so you can see progress and diagnose issues. Always use `--force` to skip the interactive overwrite prompt — without it, re-running a scenario will block waiting for user input.

For the canonical skill-created layout, the scenario file is `scenarios/<slug>/scenario.yaml` and generation writes to the same scenario root. If the user has a legacy flat scenario file directly under `scenarios/`, recommend moving it into the bundle root before generating. Use `--output <dir>` only when the user explicitly requests a nonstandard bundle root.

The output target never changes the directory path. `--target default|sof-elk` changes source-native file rendering inside the bundle and writes `OUTPUT_TARGET.txt`; it must not create target-named directories.

**Warm-up phase:** Generation begins with a warm-up period (default 8 hours, minimum 1 hour, configurable via `time_window.warmup`). During warm-up, the engine runs baseline generation to pre-populate DNS cache, process trees, active sessions, and other internal state — but warm-up events are **not** written to output files. This ensures the first minutes of output look like a running system rather than a cold start. Progress output distinguishes the warm-up phase from real generation.

Generation writes log files to a `data/` subdirectory alongside the scenario file:

```
scenarios/<scenario-name>/
  scenario.yaml          ← input
  ENVIRONMENT.md         ← created by /eforge scenario
  artifacts/             ← optional authored collateral, not eval input
  GROUND_TRUTH.md        ← generated answer key (empty for benign baseline-only runs)
  OBSERVATION_MANIFEST.json ← generated source-observation sidecar
  OUTPUT_TARGET.txt      ← "default" or "sof-elk"
  data/                  ← generated log files
    <host>/
      windows_event_security.xml      ← default target Windows Security
      windows_event_sysmon.xml        ← default target Sysmon
      syslog.log                      ← default target Linux syslog
      <year>/
        windows_event_security_snare.log ← sof-elk target Windows Security
        windows_event_sysmon_snare.log   ← sof-elk target Sysmon
        syslog.log                       ← sof-elk target Linux syslog
    zeek/
      conn.json
      dns.json
    ...
```

If generated output (`data/`, `GROUND_TRUTH.md`, or `OBSERVATION_MANIFEST.json`) already exists, the CLI prompts before overwriting. Use `--force` to skip the prompt (for automation / AI use). `ENVIRONMENT.md` is scenario-authored and is preserved.

### 3. Post-Generation

After successful generation:
- List the generated files and their sizes
- Check that expected formats were produced
- Note that `GROUND_TRUTH.md`, `OBSERVATION_MANIFEST.json`, `OUTPUT_TARGET.txt`, and `data/` were generated under `scenarios/<slug>/`. For baseline-only runs, `GROUND_TRUTH.md` explicitly says no malicious events were generated.
- `ENVIRONMENT.md` (created by `/eforge scenario`) is already in the same directory — no copying needed
- Optional `artifacts/` contents are exercise collateral created by `/eforge scenario`, not generated log output
- Note that the causal expansion engine auto-generates prerequisite events (DNS lookups before connections, Kerberos TGT/TGS before logons, audit events from command patterns, etc.) — these appear in the logs but are not explicitly listed in the scenario YAML
- Summarize the output for the user

### 4. Diagnose Errors

If generation fails, diagnose based on exit code and error output:

**Exit 2 — Schema Validation Failed:**

Try to fix simple issues directly — typos in hostnames, missing cross-references you can infer, obvious YAML formatting problems. Read the scenario file, fix the issue, and re-run `eforge validate` to confirm.

Common simple fixes:
- "references undefined persona" → Add the persona to the `personas:` section or use a pre-built one from `personas/`
- "references undefined system" → Check hostname spelling in user.primary_system or storyline.system
- "references undefined user" → Check username spelling in system.assigned_user or group.members
- "Duplicate username/hostname/IP" → Find and rename the duplicate
- "references undefined actor" → Storyline actor must be a username or literal "attacker"
- "references undefined segment" → Check segment names in sensor.monitoring_segments

For structural problems that require rethinking the scenario design — like a fundamentally broken network topology, missing personas that need custom definitions, or a storyline that references systems/users that don't exist and can't be trivially added — advise the user to revisit with `/eforge scenario` to rework that section.

If generation succeeds but the output looks implausible, inspect the environment metadata before blaming the engine. Missing or vague `user.primary_system`, `system.roles`, and `system.services` often degrade session placement, infrastructure selection, and remote-session realism even when validation passes.

Read the full error output — validation issues include the field path and often a suggestion for how to fix it.

**Exit 1 — Input Error:**
- File not found → Check the path
- Permission denied → Check file permissions
- Invalid YAML syntax → Look for indentation errors, missing quotes, or bad characters

**Exit 21 — Generation Error:**
- Usually an internal error — read the traceback
- Try with `--debug` for more detail

### 5. Suggest Improvements

After reviewing output, you can suggest:
- Adding more log formats for better coverage
- Adjusting baseline intensity if the noise-to-signal ratio seems too low or high
- Adding network topology for more realistic network log generation
- Spacing out attack events for more realism

## Available Log Formats

| Format | Description | Generated For |
|--------|-------------|---------------|
| windows | Windows Event Logs — default target XML, SOF-ELK target Snare syslog. Security (30 event IDs) + Sysmon (Events 1, 3, 5, 7, 8, 10, 11, 12, 13, 22) | Windows systems |
| zeek | Zeek logs (NDJSON) — conn/dns/http/ssl/files/ntp per sensor | Network connections via sensors |
| ecar | EDR/XDR telemetry in eCAR format (NDJSON) — PROCESS, FILE, FLOW, REGISTRY, MODULE, USER_SESSION | Any OS (optional EDR layer) |
| syslog | Linux syslog — default target RFC5424 flat per-host, SOF-ELK target RFC3164/BSD per-host/year | Linux systems |
| bash_history | Bash command history | Linux systems |
| snort_alert | Snort/Suricata alerts (fast format) | Network IDS via sensors |
| cisco_asa | Cisco ASA firewall syslog — default target flat per-sensor, SOF-ELK target per-sensor/year | Firewall sensors |

When `nat_rules` are configured on the firewall sensor, `cisco_asa.log`
also includes 305011/305012 NAT translation records alongside the normal
Built/Teardown connection records.

| web_access | Apache/Nginx combined access logs | Web servers |

Use the `/eforge:references:evidence-formats` skill for detailed field documentation, output paths, and known limitations for each format.

## Performance Expectations

- Small scenarios (5 users, 4 hours): a few seconds
- Medium scenarios (100 users, 8 hours): ~14 seconds
- The engine uses parallel threaded emitters — one thread per log format
- Memory stays under 500MB even for large datasets
