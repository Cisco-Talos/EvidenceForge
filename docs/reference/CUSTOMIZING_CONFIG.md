# Customizing EvidenceForge Configuration

EvidenceForge ships with 50+ YAML configuration files that control data-driven generation such as
DNS domains, applications, personas, traffic profiles, and spawn rules. You can customize the
project-safe families without modifying the installed package. Safety, evaluation, resource, OOB,
and runtime policy remain engine-owned.

Scenario 2.0 industry and organization packs are also data-driven configuration, but they are not
ordinary `.eforge/config` overlays. Packs use stable public catalogs under `.eforge/packs`, are
selected explicitly by a scenario, and cannot override engine safety/evaluation/resource policy.
Use overlays for project-wide internal configuration tuning; use packs for versioned, composable
scenario context. See [Scenario 2.0 and composable packs](SCENARIO_PACKS.md).

## Choose between a scenario, pack, and overlay

| Need | Authoring layer |
|---|---|
| One exercise's users, systems, identities, time, storyline, or output | Scenario |
| Reusable sector personas, applications, destinations, traffic, or storage vocabulary | Industry pack |
| Reusable concrete organization environment and baseline | Organization pack |
| Project-wide tuning of an existing internal config family | `.eforge/config` overlay |

Packs have versioned public schemas and explicit Scenario 2.0 selection. Overlays use internal
configuration filenames and implicitly affect every scenario compiled under that project root.
Do not make a pack depend on an overlay-only ID: other users may select the pack without that
project configuration. Use a pack catalog export or a stable packaged-only built-in ID instead.

## The overlay system

EvidenceForge uses a **project-local overlay** at `<project-root>/.eforge/config/`. Overlay files
contain only your additions or changes; the compiler snapshots them into the immutable per-run
effective configuration and merges them with package defaults through family-specific rules.

```
your-project/
├── .eforge/config/              ← Your customizations (survives package upgrades)
│   ├── activity/
│   │   ├── dns_registry.yaml    ← Only your new domains
│   │   └── smb_profiles.yaml    ← Optional SMB process/provider/audit overrides
│   └── personas/
│       └── nurse.yaml           ← A custom persona
├── scenarios/
│   └── hospital-breach/
│       └── scenario.yaml
```

**How merging works:**
- New entries (new domain, new app, new persona) are appended to package defaults
- Entries matching an existing key (same domain name, same app ID) are merged field-by-field — list fields are extended (appended), scalar fields are replaced, unmentioned fields are preserved
- Add `_replace: true` to an overlay entry to switch list fields from extend to replace (e.g., to retag a domain instead of adding a tag)
- Package defaults you don't override pass through unchanged

Your overlay is never touched by package upgrades. Run `eforge info overlay.exists` to check if you have one.

Scenario `validate`, `resolve`, and `generate` choose the project root deterministically: explicit
`--project-root`, otherwise the nearest ancestor of the root scenario containing `.eforge`,
otherwise the root scenario's directory. They do not fall back to the shell's working directory.
Pass an absolute `--project-root` in automation and chat-driven workflows.

Standalone `eforge info` and `eforge validate-config` retain the ambient overlay compatibility
workflow and inspect `.eforge/config` in the current working directory. Run those commands from
the project root.

## Recommended: use the matching skill

The easiest way to customize configuration is through the Claude Code skill:

```
/eforge:config add a new persona called nurse for a healthcare scenario
```

```
/eforge:config add notion.so to the DNS registry as a SaaS domain
```

```
/eforge:config add Slack as a desktop application for developers and analysts
```

```
/eforge:config validate my config files
```

The skill automatically:
- Creates the overlay directory if it doesn't exist
- Writes partial overlay files with only your changes
- Handles cross-file dependencies (adding a domain also sets up proxy templates, site maps, etc.)
- Verifies consistency and auto-fixes simple issues

**Tip:** Always use `/eforge:config` explicitly — the skill may not auto-trigger on short prompts like "add a persona."

Use `/eforge:industry-pack` or `/eforge:organization-pack` instead when the data must be portable,
versioned, and selected explicitly by Scenario 2.0. Use `/eforge:pack` for discovery, inspection,
copying, versioning, and validation. In ChatGPT and Codex, the corresponding names are
`eforge-industry-pack`, `eforge-organization-pack`, and `eforge-pack`.

## Inspecting Current Configuration

The `eforge info` command shows what's configured, including overlay customizations:

```bash
# See everything
eforge info

# Query specific fields
eforge info personas          # List all persona names (package + overlay)
eforge info dns_tags          # List all DNS tags in use
eforge info application_ids   # List all application IDs
eforge info identity_pools    # Summarize generated identity-pool config files
eforge info overlay.exists    # Check if an overlay is active
eforge info overlay.files     # List files in the overlay
eforge info paths.activity    # Path to the activity config directory

# Discover all available fields
eforge info --fields

# Machine-readable output
eforge info --json
```

### Public pack inventories

Pack schemas deliberately expose only stable packaged inventories, not whatever internal IDs an
author happens to have in an overlay. Before authoring pack process or low-level traffic entries,
inspect:

```bash
eforge info pack_builtin_application_ids
eforge info pack_builtin_dns_tags
```

Each process-catalog entry's `data.builtins` list accepts IDs from the first inventory. Pack
low-level outbound DNS selection accepts tags from the second inventory or tags defined by that
pack. Overlay-only application IDs and DNS tags are not portable pack dependencies.

When a Scenario 2.0 composition and project overlay are both present, the effective order is:

1. Installed EvidenceForge defaults.
2. Direct industry packs.
3. The organization pack.
4. Project `.eforge/config` overlays.
5. Scenario-local model fields and authored overrides.

Each public pack catalog and internal overlay family has an explicit adapter or merge rule. There
is no universal recursive pack merge. Peer industry export collisions fail instead of depending on
selection order.

## Manual Editing

If you prefer to edit YAML files directly instead of using the skill:

### 1. Create the overlay directory

```bash
mkdir -p .eforge/config/activity .eforge/config/personas
```

### 2. Add a custom persona

Create `.eforge/config/personas/nurse.yaml`:

```yaml
name: nurse
description: "Clinical nurse who uses EHR and basic web browsing"
typical_activities:
  - "Access electronic health records"
  - "Review patient charts"
  - "Browse medical reference sites"
work_hours: "7am-7pm (lunch 12pm-1pm)"
application_usage:
  - "Chrome"
  - "EHR Client"
risk_profile: "low"
browsing_intensity: "light"
```

All fields are required. Valid `risk_profile`: low, medium, high. Valid `browsing_intensity`: light, normal, heavy.

### 3. Add a custom domain

Create `.eforge/config/activity/dns_registry.yaml`:

```yaml
domains:
  - domain: ehr.meridianhealth.local
    ips: ["10.50.1.100"]
    tags: [internal]
```

Valid tags: `web`, `saas`, `cdn`, `email`, `git`, `background`, `windows`, `linux`, `internal`, `storage`, `dev`, `social`.

### 4. Add a persona to existing applications

Create `.eforge/config/activity/application_catalog.yaml`:

```yaml
applications:
  - id: chrome
    personas: [nurse]
  - id: outlook
    personas: [nurse]
```

This is a **partial overlay** — it adds `nurse` to Chrome's and Outlook's persona lists without replacing any other fields. The engine merges these with the package defaults.

### 5. Verify

```bash
eforge info personas    # Should include "nurse"
eforge info dns_tags    # Should include your new tags

# Run full validation across merged package + overlay config
eforge validate-config
```

### SMB client and server profiles

`activity/smb_profiles.yaml` owns source-native process, presentation, and transport-attribution
metadata for Windows Explorer, Linux GVFS background texture, direct `smbclient`, kernel-mounted
CIFS, Windows LanmanServer, and Samba. Scenario YAML owns the storage topology, mappings,
credential mode, principal selection, audit level, and explicit `smb_activity.client_access`; use
this config only to tune reusable process/lifecycle morphology.

The packaged document has `schema_version: 1` plus six top-level mappings:
`advertised_filesystem_defaults`, `samba_audit`, `client_defaults`, `client_profiles`,
`server_defaults`, and `server_profiles`. The advertised-filesystem map separates a server's
wire-visible label from its backing filesystem. The Samba audit map assigns source-native labels
and audit-profile eligibility to canonical operations, including the profiles that retain failed
operations. All six mappings are keyed, so an overlay can replace one nested field without copying
the full package file:

```yaml
# .eforge/config/activity/smb_profiles.yaml
client_profiles:
  linux_cifs_mount:
    weight: 55.0
  linux_smbclient:
    weight: 15.0
```

This family always deep-merges keyed mappings and extends list fields. It does not interpret the
generic entry-level `_replace` convention, so use unique aliases when extending a service-alias
list and define a separate profile ID rather than expecting an overlay to replace a list.

Client profiles declare `os_category`, `access_mode` (`explorer`, `desktop`, `direct`, or
`mounted`), `path_style`, `transport_attribution` (`process`, `kernel`, or `none`), service aliases,
weight/system eligibility, optional protocol-specific `auth_options`, and either one resident
`process` or operation-specific processes. Operation profiles may also declare their credential
source and `remote`, `upload`, `download`, `rename`, or `transfer` operand mode. `transfer` is for
mounted copy/move processes and requires native `{source_path}` and `{destination_path}` operands.
Server profiles declare service aliases, a service-lifecycle listener, and—on Linux—a required
per-transport `smbd` worker.

Keep ownership semantics intact when overriding profiles:

- Mounted CIFS must remain kernel-attributed; `mount.cifs` establishes a mount but does not own
  every later file operation. Its copy/move profiles use resolved native transfer operands rather
  than fixed home-directory paths.
- Direct `smbclient` operations use operation-lifecycle processes.
- Explorer and desktop/GVFS profiles use resident processes, but GVFS is background
  transport/process texture only and never owns canonical typed file activity.
- Samba uses a durable listener plus one transport-lifecycle worker profile.
- Process images must be absolute and native to the profile OS. Templates accept only `server`,
  `share`, `path`, `client_path`, `local_path`, `source_path`, `destination_path`, `username`,
  `smb_principal`, `auth_options`, `operation`, and `client_ip` placeholders.

Run `eforge validate-config` after every overlay change. Validation merges the overlay first, then
rejects unknown roots/fields, invalid defaults, missing operation profiles, unsupported template
placeholders, unsafe advertised-filesystem labels, incomplete Samba audit mappings, incompatible
path/access/transport combinations, and invalid process lifecycles.

## Cross-File Dependencies

Configuration files are interconnected. When you add an entry to one file, other files may need updates:

For a domain that belongs only to one portable scenario or hunt exercise, prefer
`environment.network_identities` in the scenario YAML. Use
`.eforge/config/activity/dns_registry.yaml` when building a reusable local domain
library that should influence many scenarios.

| When you add... | Also update... |
|----------------|----------------|
| A reusable config domain | `proxy_uri_templates.yaml` (URI paths), `site_maps.yaml` (browsing depth) |
| Certificate/update/telemetry proxy behavior | `proxy_uri_templates.yaml` (`domain_class`, infra-specific paths/content types, and `referrer_policy: none`; non-browser classes are excluded from site-map browsing sessions) |
| New proxy User-Agent behavior | `proxy_user_agents.yaml` (workstation/server UA pools, package-manager host bindings, domain-specific update/cert/telemetry overrides) |
| Beacon behavior profiles | `beacon_profiles.yaml` (synthetic behavior-shaped HTTP sequences, method/status/byte ranges, User-Agent pools, and deterministic token templates for scenario `beacon.profile`) |
| Inbound web visitor mix | `web_session_profiles.yaml` (visitor classes, configured tool/API requests, and User-Agent pools). Human visitor sessions use `site_maps.yaml`; timing lives in `timing_profiles.yaml`; `traffic_rates.yaml` `web` counts top-level actions only. |
| New TLS issuer behavior | `tls_issuers.yaml` (issuer validity, key-type weights, and domain CA overrides). RSA-branded issuer names should only advertise RSA key types unless matching `tls_realism.yaml` subject-key profiles distinguish issuer signature algorithm from leaf public-key algorithm. |
| New TLS OCSP responder or chain behavior | `tls_realism.yaml` (`ocsp.responders`, response-size/throughput/duration bounds, `certificate_chains.templates`, and `certificate_chains.subject_key_profiles`) plus `dns_registry.yaml` for each responder hostname. Subject key profiles must include issuer family, key type/size, and compatible child signature algorithms. |
| Kerberos TGT pre-auth realism | `kerberos_realism.yaml` (`tgt_success.pre_auth_types`, ticket options, encryption types, and PKINIT certificate profiles). Run `eforge validate-config`; PKINIT (`PreAuthType: 15`) requires populated certificate profile support. |
| Windows auth realism | `windows_auth_realism.yaml` (`workstation_lock.min_unlock_gap_seconds`, failed-logon local/network profiles, optional companion network connection rates, and host-scoped `gpo_refresh` cadence/command profiles) |
| Baseline auth noise | `auth_noise.yaml` (stale scheduled-credential account pools, host counts, recurrence intervals, jitter, skips, and backoff) |
| Endpoint background noise | `endpoint_noise.yaml` (Windows scheduled-process trigger windows, host drift, skip probability, and DHCP registry emission policy) |
| Host/persona/role volume realism | `host_activity_profiles.yaml` (coarse rate-family multipliers, firewall deny burst shaping, and data-driven artifact variants) |
| Generated identity pools | `email_background.yaml`, `mail_public_identities.yaml`, `external_actor_profiles.yaml`, `suspicious_benign.yaml`, and `command_parameter_pools.yaml` (baseline email senders/recipients, reserved public mail replacements, omitted storyline external IPs, suspicious-benign DNS/connection targets, and command URL/host placeholders). Scenario-authored IPs/domains still override fallback pools. |
| IDS signatures and default alert cadence | `ids_signatures.yaml` (`alert_policy` supports Snort-style `detection_filter` and `event_filter`; scenario `ids_alerts[].policy` replaces the signature default) |
| Observation/source coverage | `observation_profiles.yaml` (named source-level missingness/delay profiles selected by scenario `observation_profile`; default `complete` keeps perfect coverage; non-complete decisions are coherent per source-local process, session, and same-UID network group; optional collection batching/window knobs belong here) |
| Causal/source-native timing | `timing_profiles.yaml` (`relationships` for causal prerequisites, source latency, teardown margins, Zeek analyzer offsets and TLS duration floors, endpoint host-clock profiles shared by OS logs and host-resident eCAR, independent network sensor clock/path profiles, plus Windows/Sysmon collision spacing) |
| Public DNS/NTP fallback servers and DNS tunnel timing | `network_params.yaml` (`public_dns_resolvers`, `public_ntp_servers`, `dns_tunnel_rtt`; scenario-defined internal/domain infrastructure still takes precedence) |
| Public DNS owner/AAAA behavior | `public_dns_profiles.yaml` (`generic_aaaa_probability` plus provider-style NS/SOA answer profiles); the AAAA decision is stable per owner/name, not sampled per query. |
| Linux ambient syslog texture | `extra_syslog_messages.yaml` for role/distro daemon message pools and atomic `parameter_profiles` such as coherent IRQ/device/CPU tuples; journald capacity/vacuum/rotation messages are generated by the engine as sparse host-state housekeeping rather than high-frequency filler. Polkit desktop auth-agent messages are gated to desktop-capable Linux hosts; server-side polkit authorization messages remain sparse. |
| SMB provider defaults and client/server morphology | `smb_profiles.yaml` (advertised-filesystem defaults, Samba audit operation mappings, OS/access/path presentation, service aliases, auth/process templates and lifecycles, transport attribution, weighted client selection, and listener/worker metadata). Scenario storage, mappings, identity, audit profile selection, and `client_access` remain in scenario/organization schema. |
| A new application | `spawn_rules.yaml` (process tree), `process_network_map.yaml` (if it generates traffic) |
| Canonical process image paths | `application_catalog.yaml` for user applications, or `system_processes.yaml` for OS binaries; storyline bare executable names resolve through these catalogs |
| A DLL load profile | Add `loaded_modules` to the app in `application_catalog.yaml`, or to the process entry in `system_processes.yaml`. Overlay entries extend the DLL pool (deep merge adds new modules alongside defaults). |
| Windows maintenance/background process cadence | `system_processes.yaml` scheduled-task entries may optionally set `weight`, `system_types`, `max_per_host_window`, `cooldown_seconds`, and `cooldown_hours`. Defaults are optional and existing entries remain valid; use these controls for utility-specific rarity and host-role eligibility. |
| A new persona | `application_catalog.yaml` (add persona to relevant apps' `personas:` lists) |
| Bash typo/noise behavior | `bash_commands.yaml` (`typo_model` plus role command pools) |
| Sysmon filter rules | `sysmon_filters.yaml` — overlay replaces entire top-level sections (e.g., `network_connect:` replaces all Event 3 rules). Standalone, no cascades. |
| EDR background events | `edr_pools.yaml` — overlay replaces entire sections (e.g., `file_paths_windows:` replaces the full file path pool). Use `{user}` and `{rand}` templates. |
| Sysmon/eCAR ProcessAccess call traces | `calltrace_patterns.yaml` — `patterns:` define named module/offset palettes and `source_families:` maps source process families such as Defender, CSRSS, services, svchost, WMI, and suspicious tools to those palettes. Fields are optional/defaulted by package config; scenario YAML does not need call-trace directives. |

The `/eforge:config` skill handles these dependencies automatically. If editing manually, run `/eforge:config validate my config files` to check for missing cross-references.

## Generated Identity Pools

EvidenceForge keeps realism-sensitive fallback identities in data files under
`activity/` instead of hardcoded Python lists:

| File | Overlay path | Purpose |
|------|--------------|---------|
| `email_background.yaml` | `.eforge/config/activity/email_background.yaml` | Weighted external domains and inbound/outbound local-parts for baseline email. |
| `mail_public_identities.yaml` | `.eforge/config/activity/mail_public_identities.yaml` | Public SMTP provider profiles and reserved-domain replacement domains for public mail infrastructure. |
| `external_actor_profiles.yaml` | `.eforge/config/activity/external_actor_profiles.yaml` | Public IP fallback pools for storyline logons, failed logons, and omitted C2 destinations. |
| `suspicious_benign.yaml` | `.eforge/config/activity/suspicious_benign.yaml` | Suspicious-looking but legitimate DNS names and outbound connection targets. |
| `command_parameter_pools.yaml` | `.eforge/config/activity/command_parameter_pools.yaml` | URL and host substitution pools for generated command lines that may appear in endpoint artifacts. |

Run `eforge info identity_pools` to inspect counts and overlay paths. Run
`eforge validate-config` after edits; validation rejects empty pools, duplicate
keys, malformed domains/IPs, invalid weights, reserved public domains in
realism-bound pools, and malformed command URLs.

## Customizing Data Quality Evaluation

The `eforge eval` scoring rules are also YAML-based and can be tuned per-project:

| File | Purpose |
|------|---------|
| `thresholds.yaml` | Hard-gate minimums and aspirational targets for each sub-score |
| `co_occurrence.yaml` | Co-occurrence rules (field combinations that must/must not occur together) |
| `distributions.yaml` | Reference distributions for format field populations |
| `causal_pairs.yaml` | Before/after event pairs that must be correctly ordered |
| `timing_bounds.yaml` | Min/max elapsed-time bounds between consecutive storyline steps |
| `cross_source_pairs.yaml` | Format pairs and fields that must agree when the same event appears in both |

All eval config files live in `src/evidenceforge/config/evaluation/`. They are **not** overlaid from `.eforge/config/` — edit them in-place if you want project-specific tuning, or copy the package files into your project and set the `EFORGE_EVAL_CONFIG_DIR` environment variable to point to your copies.

Generated scenario directories may also include `OBSERVATION_MANIFEST.json` beside
`GROUND_TRUTH.json` and `GROUND_TRUTH.md`. `eforge eval` loads this manifest automatically when present. For
non-`complete` observation profiles, causality coverage metrics use the manifest to exclude
source evidence that was intentionally `dropped`, `filtered`, or `out_of_window`, while still
failing visible contradictions, parse errors, value mismatches, and missing evidence that the
manifest marks `visible` or `delayed`. Text and JSON reports keep the adjusted score and expose
the raw score for affected sub-scores.

IDS output has an additional zero-weight `ids_integrity` hard gate fixed at
100%. It reconciles sensor-local Snort counts and ordered normalized digests with
`GROUND_TRUTH.json.ids_evaluation`, then checks filtering and observation totals
against `OBSERVATION_MANIFEST.json`. Because its weight is zero, it does not
move the overall numeric score; any contradiction still fails acceptance.
Legacy datasets without an IDS summary skip the check unless the supplied
scenario contains authored `ids_alerts`.

For full schema documentation for each file, see the skill reference: `/eforge:references:config-evaluation`.

## Reference Documentation

For full field schemas and conventions, see the reference docs installed with the skills:

| Topic | Skill Reference |
|-------|----------------|
| DNS, traffic, proxy, site maps | `/eforge:references:config-dns-network` |
| Applications, spawn rules, processes | `/eforge:references:config-apps-processes` |
| Persona file structure | `/eforge:references:config-personas` |
| Host activity (bash, systemd, syslog) | `/eforge:references:config-host-activity` |
| SMB client/server profiles | `/eforge:references:config-host-activity` |
| Cross-file dependency map | `/eforge:references:config-dependency-graph` |
| Validation checks | `/eforge:references:config-validation` |
| Industry/organization pack fields and workflows | `/eforge:references:pack-reference` |

### IDS signature alert-policy overlays

IDS signature entries merge by `sid`, so an overlay can add or replace only the
default policy while preserving the packaged identity and metadata:

```yaml
# .eforge/config/activity/ids_signatures.yaml
signatures:
  - sid: 2002910
    alert_policy:
      event_filter: {type: both, track: by_src, count: 5, seconds: 60}
```

An omitted policy (or `every`) alerts for every visible candidate. Policy objects
support `detection_filter`, `event_filter`, or both; track is `by_src`/`by_dst`,
and event-filter type is `limit`/`threshold`/`both`. Counts and seconds are strict
positive integers. Run `eforge validate-config` after editing. See the installed
`references/config-ids.md` skill reference for exact semantics.

These defaults apply when an attachment omits `policy` on any supported typed
transport owner (`connection`, `beacon`, SSH/RDP sessions, authored DHCP,
port/web scans, and DNS query families). They do not cause unattached network
events to alert and do not imply IDS decryption.
