---
name: eforge-scenario
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
description: >
  Create EvidenceForge scenario YAML files for realistic synthetic security-log datasets, including
  selecting and consuming existing Scenario 2.0 industry or organization packs. Use this skill for
  concrete exercises, attack simulations, threat-hunting datasets, storylines, red herrings, time
  windows, output selection, and scenario-local environments. Route reusable pack creation or
  changes to the industry-pack or organization-pack skill.
---

# EvidenceForge Scenario Creator

Create a concrete, technically detailed scenario that the deterministic `eforge generate` engine
can render without LLM calls. The authored result normally consists of
`scenarios/<slug>/scenario.yaml`, an attack-free `ENVIRONMENT.md`, and optional authored collateral.

EvidenceForge supports canonical Windows, Zeek, eCAR, syslog, bash-history, Snort, web-access,
proxy-access, and Cisco ASA outputs. Keep target-specific rendering such as SOF-ELK® out of YAML;
choose it at generation with `eforge generate --target default|sof-elk`.

Default to `eforge` for CLI calls. If it is unavailable in an EvidenceForge source checkout, retry
the same command with `uv run eforge`. For pack-backed work, resolve one absolute project root and
pass it consistently with `--project-root`.

## Load the Authoring Contract

Before writing scenario files, read `/eforge:references:scenario-authoring` completely. It contains
the detailed interview topics, practical skeleton, persona table, event guidance, safe encoding
commands, `ENVIRONMENT.md` template, realism review, and sensor-coverage checks.

Read `/eforge:references:scenario-reference` for exact schema fields, typed-event contracts,
storage selectors, multipart HTTP, firewall/IDS policies, and validation constraints. Read
`/eforge:references:evidence-formats` when exact emitted fields, paths, or known source limitations
matter.

Use any organization-include layout in the schema reference only as a file-local compatibility
pattern. The pack-first ownership rules below are authoritative for new reusable organization
content.

Before listing, selecting, consuming, or diagnosing packs, read
`/eforge:references:pack-reference` completely.

## Choose the Authoring Boundary

Classify content ownership before interviewing for field details. Packs and includes solve
different problems and may be used together.

- Use an existing pack for reusable, versioned industry or organization context.
- Use scenario `includes` to split or share section-oriented source files controlled with the
  scenario. Includes are not versioned catalogs and are not overrides.
- Use one monolithic scenario file for a small, one-off exercise.

If the boundary is unclear, ask one question: should this environment or vocabulary be reusable and
independently versioned across scenarios, or belong only to this exercise?

Do not discover packs for an existing Scenario 1.0 document or when the user chooses no-pack
authoring. Packs are optional. Scenario 1.0 and monolithic Scenario 2.0 remain valid and pack-silent.

### Route reusable authoring

This skill consumes existing packs; it does not create or modify substantive pack content.

- Route reusable sector vocabulary—personas, processes, applications, destinations, traffic, or
  storage profiles—to `/eforge industry-pack`.
- Route a reusable concrete organization—exact industry dependencies, organization-specific
  catalogs, users, systems, groups, topology, services, email or SMB environment, and baseline
  activity—to `/eforge organization-pack`.
- Use `/eforge pack` for inventory, inspection, comparison, lifecycle operations, validation, and
  composition diagnosis.
- Keep the concrete exercise, time window, storyline, red herrings, output, collection choices,
  safety authorization, and scenario-local exceptions here.

If an existing pack is close but needs a reusable change, route that change to the matching
pack-authoring skill. Resume scenario authoring after it returns an exact new reference. Do not copy
reusable content into a scenario merely to avoid versioning the pack.

### Select an existing pack

Reuse a suitable existing pack before proposing new reusable content. Use machine-readable
inventory and inspect candidate identity, dependencies, exports, and digest:

```bash
eforge pack list --project-root <absolute-project-root> --json
eforge pack show <exact-pack-ref> --project-root <absolute-project-root> --json
```

Persist the exact `source`, `name`, and `version` reported by the CLI; include `path` only for
`source: path`. Never infer a latest version or reconstruct inventory by scanning directories.

A direct industry selection supplies reusable vocabulary but needs a scenario-local concrete
environment and normally a local baseline:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: package
      name: finance
      version: "1.0.0"
```

An organization selection normally supplies its reusable environment, baseline, catalogs, and
exactly pinned industry dependencies:

```yaml
scenario_version: "2.0"
composition:
  organization:
    source: package
    name: northstar-health
    version: "1.0.0"
```

Select direct `industries` or one `organization`, never both. Do not repeat an organization pack's
industry dependencies in the scenario. Use exact qualified catalog references such as
`<pack-name>:<local-name>`.

A pack-backed scenario may still use `includes` for local `storyline` or `red_herrings`. Include
paths resolve relative to the file that declares them. Included and declaring files must own
disjoint fields; duplicate fields are validation errors, not overrides.

## Scenario Bundle Layout

Derive a stable slug and keep the complete exercise under one root:

```text
scenarios/<slug>/
  scenario.yaml
  ENVIRONMENT.md
  includes/                  # Optional authored, section-oriented fragments
    storyline.yaml
    red_herrings.yaml
  artifacts/                 # Optional authored/generated collateral
  ARTIFACTS_MANIFEST.json    # Generated when artifacts exist
  GROUND_TRUTH.md            # Generated
  GROUND_TRUTH.json          # Generated
  OBSERVATION_MANIFEST.json  # Generated
  OUTPUT_TARGET.txt          # Generated
  RESOLVED_SCENARIO.yaml     # Authoritative generated input
  GENERATION_MANIFEST.json   # Authoritative run identity; written last
  data/                      # Generated logs for every output target
```

Do not write a lone YAML file directly under `scenarios/`, create repo-root environment/artifact
files, or use target-named dataset roots. `default` and `sof-elk` change rendering inside the bundle,
not the bundle location.

## Interview Flow

Let the user describe the exercise first, then fill material gaps conversationally.

**Ask exactly one question per message.** Use `AskUserQuestion` when available; otherwise ask one
conversational question. After an answer, acknowledge it in at most one sentence and move to the
next unresolved decision. Never repeat information the user already supplied.

Cover, as needed:

- The attack story, ATT&CK techniques by name and ID, difficulty, attacker polish, and parallel
  paths.
- Organization type, pack or local environment, scale, users, systems, roles, services, timezone,
  duration, and business hours.
- Network segments, sensor/firewall placement, victim log boundary, and required output formats.
- Email, SMB, browsing, named network identities, traffic volume, observation profile, and stale
  accounts where relevant.
- Explicit red herrings, expected noise-to-signal ratio, and whether every attack step should be
  observable or some blind spots are intentional.

Infer ordinary details when that does not change the requested exercise. State material assumptions
before writing.

## Core Authoring Invariants

### Deterministic specificity

The engine does not embellish vague input. Author accurate commands, image paths, file paths,
addresses, hostnames, ports, timing, users, and relationships. Every user needs a valid
`primary_system`; important infrastructure needs meaningful `roles` and `services`.

When network output is requested, keep sensor requirements explicit. The essential shape includes:

```yaml
environment:
  network:
    segments: []
    sensors:                       # Optional unless output requires Zeek/IDS/ASA evidence
      - type: network
        monitoring_segments: []
        placement: span
        log_formats: [zeek]
```

Do not add placeholder Zeek sensors for proxy-only labs that only request `proxy_access`.

### Identities and defender visibility

Use natural user names and one organization-wide username convention. External attackers normally
use a compromised legitimate account or a system identity, not a victim user named `attacker`.
Keep third-party and attacker infrastructure out of `environment.systems`; the defender sees its
own endpoint, network, firewall, proxy, and contracted application evidence, not a vendor's or C2
server's OS logs.

### Typed intent and correlation

Storyline `activity` is documentation only. Put generation intent in validated typed `events`.
Prefer typed events over `raw`. Pair commands that contact a domain with a typed connection using
the client-facing hostname so DNS/TLS/HTTP/proxy evidence correlates.

Action bundles own transport, DNS, TLS, proxy, firewall, IDS, authentication/session, process
lifecycle, and other correlated siblings. Do not duplicate their output rows manually. Causal
expansion supplies ordinary prerequisites such as connection DNS, Kerberos ticket evidence, and
supplementary Windows audit events unless that evidence is itself part of the attack narrative.

For authored IDS matches, use `ids_alerts` on the owning typed transport. A tuple does not alert by
itself, and encrypted traffic is not inspected. Read the exact event and policy schema before use.

### Safety

Use only fictional, synthetic exercise data. `spillage` values must remain poison-marked or
vendor-published fakes with reserved embedded hosts. Every physical line of an
`adversarial_payload` must remain poison-marked; its default callback is the inert,
non-resolving `canary.eforge.invalid`. Generation writes these values as data and never executes
them.

**Live callbacks are generation-time only.** OOB mode is an `eforge generate --oob-host <host>` or
`eforge validate --oob-host <host>` option, never a scenario-YAML field. Never author an operator
host into a payload value. Enable OOB only when the user explicitly requests live callback testing
against systems they are authorized to test; otherwise preserve the inert canary behavior.

Treat encoded payloads as untrusted input. Never interpolate them into shell source. Use the quoted
here-document encoders in `/eforge:references:scenario-authoring`, paste the real result, and verify
that it decodes exactly.

### Student context

Create `scenarios/<slug>/ENVIRONMENT.md` from the final effective environment, including selected
pack content. It must contain zero attack-storyline or suspicious-activity information. Keep it at
the scenario root, not in `artifacts/`; organization packs do not own this scenario-facing file.

## Author, Review, Resolve, and Validate

1. Create the scenario root and author `scenario.yaml`, optional section-oriented includes,
   `ENVIRONMENT.md`, and requested collateral under `artifacts/`.
2. Check schema references while writing rather than guessing fields. Keep every event inside the
   time window and every actor/system/persona/reference resolvable.
3. Review the effective scenario for attack logic, technical accuracy, naming, environment
   consistency, victim log boundary, timing, attacker messiness, signal quality, bundle ownership,
   and sensor coverage. Repair issues and tell the user what changed.
4. For a pack-backed scenario, resolve and inspect the exact selected packs, digests, qualified
   exports, merge result, and field origins:

```bash
eforge resolve scenarios/<slug>/scenario.yaml \
  --output <temporary-resolved.yaml> \
  --project-root <absolute-project-root> \
  --explain-composition --json
```

5. Validate the authored scenario. Show effective storage when SMB is material:

```bash
eforge validate scenarios/<slug>/scenario.yaml \
  --project-root <absolute-project-root>

eforge validate scenarios/<slug>/scenario.yaml \
  --project-root <absolute-project-root> --show-storage
```

6. Fix every validation error and re-run validation. If a coverage gap is intentional, report the
   exact invisible event/source boundary rather than silently inventing a sensor.
7. Summarize the scenario root, composition references, environment size, time window, narrative,
   output formats, optional artifacts, validation result, and any accepted blind spots.

If the user wants logs immediately, hand off to `/eforge generate` or run
`eforge generate <scenario-file>`. Explain that generated ground truth, manifests, resolved input,
and `data/` remain under the same scenario root.
