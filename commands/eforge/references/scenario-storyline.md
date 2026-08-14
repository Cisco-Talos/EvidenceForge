---
description: "Typed storyline, red-herring, timing, and causal-expansion guidance"
---

# Scenario Storyline

Build a coherent narrative from typed events. Every storyline entry requires a unique `id`, a
time, a resolvable actor and system, documentation-only `activity`, and a nonempty `events` list.
Red herrings use the same typed events plus an instructor-facing `explanation`.

```yaml
storyline:
  - id: evt-discovery
    time: "+2h"
    actor: marcus.chen
    system: WS-DEV-01
    activity: "Enumerate the current user"
    events:
      - type: process
        process_name: 'C:\Windows\System32\whoami.exe'
        command_line: whoami
```

`activity` and event descriptions never generate evidence. Read the exact event-type schema and
author the required structured fields. Query only the type in scope with
`eforge info storyline_event_schemas.<type> --json --project-root <root>`; list current types
through `storyline_event_types`.

## Narrative design

Include only phases relevant to the requested hunt: access, execution, persistence, escalation,
evasion, credential access, discovery, movement, collection/exfiltration, and impact. Make omitted
phases intentional. Add capability-appropriate fumbles, pauses, wrong turns, or access failures
instead of an unrealistically perfect chain unless the user requests one.

Use relative times such as `+15m` or `+1h30m`. Human sequences need plausible pauses; automated
families need realistic interval, termination, and jitter. Use bulk families such as `port_scan`,
`web_scan`, `credential_spray`, `beacon`, DGA, or DNS tunnel instead of expanding hundreds of
children manually.

## Actors, systems, and identities

An `actor` is a modeled user, service account, or appropriate built-in identity such as `SYSTEM`
or `root`; it is not an arbitrary threat label. A `system` is a modeled victim-controlled host.
Use `source_ip`, destination fields, email identities, and `network_identities` to describe
external origin or infrastructure.

Use mundane attacker-controlled names unless a known tool name is itself important. Prefer
realistic lab-owned or non-reserved public identities for realism-bound data; reserve obvious
poison identities for safety-test payloads.

## Causal ownership

Author the primary real-world intent. Action bundles and causal expansion own ordinary DNS,
transport, TLS/HTTP/proxy/firewall/IDS fan-out, authentication/session prerequisites, audit
companions, and lifecycle closures. Do not manually recreate renderer rows or ordinary siblings.

For a Windows `process`, `supplementary: auto` (the default) infers supported account, group,
service, scheduled-task, and log-clear audit companions from recognized commands. Add a typed
sibling only when it is independently part of the narrative or exact authored fields are needed;
then use `supplementary: none` when necessary to prevent duplicate ownership.

Specialized events such as `process_access`, `create_remote_thread`, explicit DNS tunneling, or
forged authentication material remain appropriate when they are the narrative itself. Prefer a
typed `connection`, SSH/RDP session, or SMB activity over raw per-source rows.

## ATT&CK mappings

Technique metadata is optional and instructor-facing. Never guess an ID. Verify uncertain names
and IDs against an authoritative MITRE ATT&CK source; otherwise omit the field and tell the user.

## Final storyline review

Check access and privilege continuity, OS-native syntax, topology reachability, sensor coverage,
time-window containment, stable identities, event ownership, and detection opportunity. Repair
root causes in the modeled intent rather than adding raw output-shaped evidence.
