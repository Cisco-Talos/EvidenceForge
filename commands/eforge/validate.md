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

Default to `eforge` for all CLI execution. If `eforge` is not found and you are
in an EvidenceForge source checkout, retry the same command with
`uv run eforge ...`.

Exit codes:
- 0 = Valid (may include warnings)
- 1 = YAML parse error or file I/O error
- 2 = Schema or cross-reference validation error

## Interpret Results

**If validation passes:** Tell the user the scenario is valid. Summarize what's in it (users, systems, personas, storyline events, network topology) based on the validator output.

**If validation passes with warnings:** Explain each warning. Warnings don't block generation but may indicate suboptimal configuration (e.g., a system IP outside its segment CIDR, OS/format mismatches, missing logon events before process execution, causal expansion redundancy, or `proxy_access` requested without any system using `roles: [forward_proxy]` — see below).

Network identity warnings are advisory unless they describe an actual conflict.
Custom hostnames in storyline/red-herring/domain-aware fields should normally be
declared under `environment.network_identities`; undeclared custom domains warn
and resolve through the deterministic fallback, while duplicate identity IDs,
duplicate hosts, malformed host/IP values, and declared host/IP mismatches are
errors or warnings with field paths. Raw IP-only events are allowed without a
network identity.

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

### Spillage event errors

`spillage` events (a credential leaked into a semantic `surface`) have extra
validation. Common errors and fixes:

- **"exactly one of family or value"** — a spillage event needs `family:` (synthesize
  from a known family) XOR `value:` (a literal). Remove one.
- **unknown `family`** — must be a family in `secret_families.yaml` (e.g. `aws_iam`,
  `db_uri`). Run `eforge validate-config` to list/validate families.
- **non-allowlisted host / no poison marker / real-looking credential / control
  character** (`SpillageSafetyError`) — a literal `value:` must be provably fake: carry
  a poison marker (e.g. `EvidenceForgeFake`) *inside* any credential-shaped token, embed
  only reserved hosts (RFC 2606/5737/3849/1918), and be single-line and control-free.
  Fix the literal or switch to a `family:`.
- **http_request_url/http_referrer with no web_server** — these surfaces send a request
  to a `web_server`-role host; add a system with `roles: [web_server]`.
- **http_request_url/http_referrer with incompatible `scheme`** — an explicit
  `scheme: http` needs a web server whose `services` include `http`; an explicit
  `scheme: https` needs `https`, `ssl`, or `tls`. Generic web servers with no
  explicit scheme marker support both for legacy compatibility.
- **`scheme` on a non-HTTP surface** — remove `scheme` from `shell_history`,
  `process_command_line`, or `syslog_message`; it is only valid on
  `http_request_url` and `http_referrer`.
- **shell_history/syslog_message on a Windows host** — these surfaces are Linux-modeled;
  put the actor on a Linux host (process_command_line and http_* are cross-OS).

### Adversarial payload event errors

`adversarial_payload` events (a log-pipeline weakness payload injected into a
semantic `surface`) have the same shape of extra validation. Common errors:

- **"exactly one of family or value"** — needs `family:` (synthesize from a known
  family) XOR `value:` (a literal). Remove one.
- **unknown `family`** — must be a family in `payload_families.yaml` (e.g.
  `ansi_escape`, `crlf_log_forging`, `csv_formula`, `log4shell`, `xss_reflection`).
- **family "does not model surface"** — a `family` only declares certain surfaces
  (e.g. `csv_formula` does not model `http_user_agent`). Pick a surface the family
  declares, or use a different family.
- **unsafe value** (`AdversarialPayloadSafetyError`) — control bytes are allowed, but
  a literal `value:` must carry a poison marker (e.g. `EFORGE_TEST`) on **every
  physical line** (so a CRLF-forged line stays synthetic), and any embedded host must
  be the canary (`canary.eforge.invalid`) or an RFC-reserved domain/address.
- **http_* with no web_server** — add a system with `roles: [web_server]`.
- **syslog_message / auth_user on a non-Linux host** — both are Linux-modeled; put the
  actor on a Linux host (process_command_line, http_*, and dns_qname are cross-OS).
- **dns_qname with no network sensor** — `dns_qname` lands only in the network sensor's
  Zeek `dns.log` (a host keeps no DNS log of its own); add an `environment.network`
  sensor whose `log_formats` include `zeek`, or the payload would never be emitted.
- **literal `value:` pointing at an operator out-of-band host** — by default `eforge
  validate` uses the inert canary and rejects a non-reserved host as unsafe. To validate
  a live-callback scenario whose literal payload targets your own OOB host, pass `eforge
  validate scenario.yaml --oob-host <host>` to allowlist it exactly as `generate
  --oob-host` does (a concrete registrable domain or IP literal; validation only, no
  callback is ever made). Never pass `--oob-host` unless the user explicitly asks for
  live/OOB callback testing.

These are typically simple, directly-fixable errors. Only escalate to `/eforge scenario`
if the environment lacks a host of the required OS/role and one cannot be trivially added.

### Structural problems — escalate to /eforge scenario
- Network topology that needs redesigning
- Missing personas that need custom definitions with realistic work hours and activities
- Storyline that references systems or users that don't exist and can't be trivially added
- Fundamental schema mismatches (wrong version, missing required sections)

### Known optional fields
The following optional fields are valid and should not be flagged as unknown:
- `time_window.warmup` — warm-up duration for state pre-population (default "8h", minimum "1h")
- `environment.network_identities` — scenario-local host/IP ownership registry
- `baseline_activity.traffic_affinities` — authored benign baseline traffic rules
- `baseline_activity.traffic_suppression` — scoped down-ranking/removal of default baseline traffic

For these, advise the user to use `/eforge scenario` to rework the relevant section, and be specific about what needs to change.
