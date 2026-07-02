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

Default to `eforge` for all CLI execution. If `eforge` is not found and you are
in an EvidenceForge source checkout, retry the same command with
`uv run eforge ...`.

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
  --output, -o <dir>     Override the bundle root for generated reports and data.
                         By default, current eforge writes beside the scenario file.
  --formats, -F <list>   Comma-separated format filter. Only generates formats present in both
                         this list and the scenario's output.logs. Supports group names (zeek,
                         windows) and individual format names (zeek_conn, cisco_asa). Use
                         `eforge info format_groups` to see available groups. Example:
                         `eforge generate scenario.yaml --formats zeek_conn,zeek_dns` to
                         generate only Zeek connection and DNS logs.
  --target <name>        Output target: default or sof-elk. The default target is SIEM-neutral.
                         Use sof-elk when generating SOF-ELK®-compatible file layouts.
  --force, -f            Overwrite existing output without prompting
  --verbose, -v          INFO-level logging
  --debug, -d            DEBUG-level logging
  --oob-host <host>      LIVE-CALLBACK out-of-band testing for adversarial_payload events:
                         register an operator-controlled host (Burp Collaborator /
                         interactsh / sinkhole) so a vulnerable target calls back to YOU.
                         Must be a concrete registrable domain (e.g. oast.fun) or an IP
                         literal. Replaces the inert canary; allowlists your fuzzer
                         payloads. Repeatable. Passing it is the explicit opt-in. NEVER
                         pass --oob-host unless the user explicitly asks for live/OOB
                         callback testing against systems they are authorized to test.
                         Off by default — payloads use the inert, non-resolving canary
                         `canary.eforge.invalid`; EvidenceForge writes payload text only
                         and never executes it or calls out during generation.
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

Scenario-local `environment.network_identities` are applied in memory during
generation before package DNS, so authored host/IP ownership is shared by
baseline affinities, storyline events, DNS, HTTP, TLS/SNI, proxy, Zeek, firewall,
and endpoint flow rendering. `baseline_activity.traffic_affinities` produce
baseline traffic only; they should not appear as storyline or red-herring leads
in the generated ground truth.

Generated fallback identities are deterministic but data-driven. Baseline email
domains/local-parts, public mail replacement domains, omitted storyline external
IP pools, suspicious-benign DNS/connection targets, and command URL/host
placeholders come from overlay-aware files under `activity/`. Inspect them with
`eforge info identity_pools` and validate overlays with `eforge validate-config`.
The generator still never calls an LLM.

Generation writes log files to a `data/` subdirectory alongside the scenario file:

```
scenarios/<scenario-name>/
  scenario.yaml          ← input
  ENVIRONMENT.md         ← created by /eforge scenario
  artifacts/             ← generated sidecar artifacts and optional authored collateral
    email/
      EMAIL_ARTIFACTS.json
      <artifact-id>.eml
  GROUND_TRUTH.md        ← generated human-readable answer key (baseline-only runs
                           still include the standard "no malicious events" report)
  GROUND_TRUTH.json      ← generated canonical machine-readable ground-truth document;
                           written for every successful run and used to derive
                           GROUND_TRUTH.md
  OBSERVATION_MANIFEST.json ← generated source-observation manifest for eval
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
      smtp.json
      files.json
    ...
```

If generated output (`data/`, `GROUND_TRUTH.md`, `GROUND_TRUTH.json`, `OBSERVATION_MANIFEST.json`, or `artifacts/email/`) already exists, the CLI prompts before overwriting. Use `--force` to skip the prompt (for automation / AI use). `ENVIRONMENT.md` is scenario-authored and is preserved.

### 3. Post-Generation

After successful generation:
- List the generated files and their sizes
- Check that expected formats were produced
- Note that `GROUND_TRUTH.json`, `GROUND_TRUTH.md`, `OBSERVATION_MANIFEST.json`, `OUTPUT_TARGET.txt`, and `data/` were generated under `scenarios/<slug>/`. `GROUND_TRUTH.json` is the canonical machine-readable report; `GROUND_TRUTH.md` is rendered from it. For baseline-only runs, `GROUND_TRUTH.md` explicitly says no malicious events were generated.
- `ENVIRONMENT.md` (created by `/eforge scenario`) is already in the same directory — no copying needed
- Email artifacts under `artifacts/email/` are generated sidecars when `environment.email.artifacts` enables them; `EMAIL_ARTIFACTS.json` is written for modeled messages, `.eml` files are written according to artifact mode, and plaintext SMTP MIME parts can also appear in Zeek `files.json`. The manifest is production-facing and omits storyline IDs, exercise verdict labels, and local filesystem paths; use `GROUND_TRUTH.json` for scenario correlation.
- Note that the causal expansion engine auto-generates prerequisite events (DNS lookups before connections, auth/session-bundle validation, Kerberos/DC-bundle TGT/TGS evidence before domain logons, Windows-audit-bundle events from command patterns, etc.) — these appear in the logs but are not explicitly listed in the scenario YAML
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
- "references undefined actor" → Storyline actor must be a defined username, a well-known built-in account such as `SYSTEM`, `root`, or `www-data`, or a name listed in `environment.service_accounts`
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
| zeek | Zeek logs (NDJSON) — conn/dns/http/smtp/ssl/files/ntp per sensor | Network connections via `type: network` sensors |
| ecar | Simulated EDR telemetry using the eCAR record format (NDJSON) — PROCESS, FILE, FLOW, REGISTRY, MODULE, USER_SESSION | Any OS (optional EDR layer) |
| syslog | Linux syslog — default target RFC5424 flat per-host, SOF-ELK target RFC3164/BSD per-host/year | Linux systems |
| bash_history | Bash command history | Linux systems |
| snort_alert | Snort/Suricata alerts (fast format) | Network IDS via sensors |
| cisco_asa | Cisco ASA firewall syslog — default target flat per-firewall, SOF-ELK target per-firewall/year | Firewall entries (`type: firewall`) |
| web_access | Apache/Nginx combined access logs | Web servers |
| proxy_access | HTTP forward proxy access logs (Apache/Nginx combined) | Forward proxy systems |

When `nat_rules` are configured on the firewall sensor, `cisco_asa.log`
also includes 305011/305012 NAT translation records alongside the normal
Built/Teardown connection records.

`environment.network.sensors` is optional for host-only, web-only, or
proxy-only output. If `output.logs` requests `zeek`, concrete `zeek_*`,
`snort_alert`, or `cisco_asa`, the scenario must define a matching
`type: network`, `type: ids`, or `type: firewall` entry. `proxy_access` is
generated from systems with `roles: [forward_proxy]`, not from network sensors.

Use the `/eforge:references:evidence-formats` skill for detailed field documentation, output paths, and known limitations for each format.

## Performance Expectations

- Runtime scales with emitted evidence volume, selected formats, scenario length, warm-up
  length, host count, and traffic rates. Web/proxy-heavy scenarios can emit many dependent
  requests per top-level action.
- For long scenarios, scope `output.logs` or use `--formats` to generate only the sources
  needed for the exercise.
- The engine uses parallel threaded emitters — one thread per log format
- If a run slows down progressively by hour, capture the scenario and generated format mix;
  that usually points to a generator hot path rather than normal output-volume scaling.
