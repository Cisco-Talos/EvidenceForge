# Overlay merge and dependency reference

Read this reference when a change spans families or when merge behavior is unclear. Package defaults,
selected packs, project overlays, and scenario-local fields have different contracts; this document
covers only `.eforge/config` overlays.

## Merge strategies

Never infer a merge mode from YAML shape. Read the package default and existing overlay first.

| Strategy | Families | Effect |
|---|---|---|
| Keyed entry merge | `dns_registry.domains` (`domain`), `application_catalog.applications` (`id`), `tls_issuers.issuers` (`name`), `ids_signatures.signatures` (`sid`), RSAT `tools` (`id`), generated identity pools | A matching entry deep-merges; list fields append. `_replace: true` replaces fields present on that entry while preserving omitted fields. New keys append. |
| Deep mapping merge | traffic/spawn rules, proxy URI/User-Agent, site maps, beacon, storage, HTTP file, auth, endpoint, host activity, observation, timing, Kerberos, TLS realism, traffic rates | Mappings recurse; scalar values replace; lists append. Supply only the affected branch. |
| Append list | process-network mappings, ProcessAccess pairs, CreateRemoteThread pairs/locations, extra syslog programs, systemd schedules, selected network pools | Overlay entries append. Avoid duplicate identities because later lookup may be last-wins even though the stored list contains both. |
| Whole top-level section replacement | `sysmon_filters.yaml`, `edr_pools.yaml`, `calltrace_patterns.yaml` | Every supplied top-level section replaces that entire packaged section. Copy and edit the complete section you intend to replace. Omitted sections remain packaged defaults. |
| Named object replacement | `web_scan_presets.yaml` | A supplied preset name replaces that entire preset; other presets remain. |
| Specialized safety merge | `secret_families.yaml`, `payload_families.yaml` | Families merge by `name`; safety markers/allowlists extend and cannot weaken packaged safeguards. Follow validation diagnostics exactly. |
| Persona merge | `personas/<name>.yaml` | Same-name persona fields deep-merge; a new name adds a persona. |

`_replace` is not a general deletion language. Use it only on documented keyed-list entries. There is
no project-overlay `_delete` operation.

## Common dependency decisions

| Primary change | Check, but do not invent |
|---|---|
| Reusable DNS domain or tag | Traffic selectors, proxy URI templates, site maps, TLS destination selectors, public DNS behavior. A domain does not automatically need all of them. |
| Application | Persona eligibility; platform image/command; spawn parent/children; process-network mapping when the app actually opens network connections. |
| Persona | Exact applications selected by the user; optional persona traffic. `application_usage` is descriptive only. |
| Process image or module palette | Application/system-process ownership and Sysmon filtering. Do not add module visibility merely because a module exists. |
| Web visitor or scan behavior | Site maps, web session profiles, traffic rates, timing, and IDS policy when explicitly desired. |
| TLS issuer/OCSP behavior | DNS identity for responder hosts and compatible TLS realism chain profiles. |
| Public DNS behavior | `dns_registry.yaml`, `public_dns_profiles.yaml`, and `network_params.yaml` have separate ownership: names, provider-style answers, and resolver/server pools respectively. |
| Identity fallback pool | Keep public domains/IPs realism-valid and distinct by role; scenario-authored values still take precedence. |
| Storage vocabulary | `storage_catalog.yaml` supplies internal defaults; portable sector/org vocabulary belongs in a pack's public `storage_catalog`. |
| Observation or timing | Scenario selects an observation profile; timing remains source-native. Neither family changes evaluator policy. |
| IDS signature cadence | Signature `alert_policy` sets a default only; scenario attachment policy can replace it. It never attaches IDS to unrelated traffic or decrypts encrypted payloads. |

## Repair classification

- **Mechanical:** syntax/formatting or creation of the confirmed overlay path. Apply automatically.
- **Directly implied:** an exact dependency named by the user, such as persona `nurse` being added to
  explicitly selected applications. Apply and report.
- **Semantic:** a new behavior choice such as tags, routes, site paths, parents, rates, or alert
  cadence. Ask before writing.

Informational validation messages are not mandates. Missing optional proxy or site-map content may be
intentional because generic fallbacks exist.

## Precedence and composed scenarios

For Scenario 2.0 compilation, effective precedence is packaged defaults, selected industry packs,
the organization pack, project overlay, then scenario-local fields. Project overlays use internal
filenames and must not be referenced as portable pack exports. Peer pack collisions fail rather than
being resolved by overlay order.

After a cross-family mutation, run `eforge validate-config --project-root <root> --json` in a fresh
process. If a scenario is supplied, validate it with the same root and inspect composition provenance
when the project overlay touches a pack-exported identity.
