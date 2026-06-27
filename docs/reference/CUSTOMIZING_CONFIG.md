# Customizing EvidenceForge Configuration

EvidenceForge ships with 50+ YAML configuration files that control every aspect of realistic log generation — DNS domains, applications, personas, traffic profiles, spawn rules, and more. You can customize these to match your scenario's environment without modifying the installed package.

## The Overlay System

EvidenceForge uses a **project-local overlay** at `.eforge/config/` in your working directory. Overlay files contain only your additions or changes — the engine merges them with package defaults at load time.

```
your-project/
├── .eforge/config/              ← Your customizations (survives package upgrades)
│   ├── activity/
│   │   └── dns_registry.yaml    ← Only your new domains
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

**Important:** The overlay is discovered from the current working directory. Always run `eforge` commands from your project root (where `.eforge/config/` lives). Running from a subdirectory will miss the overlay and fall back to package defaults silently.

## Recommended: Use `/eforge:config`

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

## Inspecting Current Configuration

The `eforge info` command shows what's configured, including overlay customizations:

```bash
# See everything
eforge info

# Query specific fields
eforge info personas          # List all persona names (package + overlay)
eforge info dns_tags          # List all DNS tags in use
eforge info application_ids   # List all application IDs
eforge info overlay.exists    # Check if an overlay is active
eforge info overlay.files     # List files in the overlay
eforge info paths.activity    # Path to the activity config directory

# Discover all available fields
eforge info --fields

# Machine-readable output
eforge info --json
```

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
| Inbound web visitor mix | `web_session_profiles.yaml` (visitor classes, configured tool/API requests, and User-Agent pools). Human visitor sessions use `site_maps.yaml`; timing lives in `timing_profiles.yaml`; `traffic_rates.yaml` `web` counts top-level actions only. |
| New TLS issuer behavior | `tls_issuers.yaml` (issuer validity, key-type weights, and domain CA overrides). RSA-branded issuer names should only advertise RSA key types unless matching `tls_realism.yaml` subject-key profiles distinguish issuer signature algorithm from leaf public-key algorithm. |
| New TLS OCSP responder or chain behavior | `tls_realism.yaml` (`ocsp.responders`, `certificate_chains.templates`, and `certificate_chains.subject_key_profiles`) plus `dns_registry.yaml` for each responder hostname. Subject key profiles must include issuer family, key type/size, and compatible child signature algorithms. |
| Kerberos TGT pre-auth realism | `kerberos_realism.yaml` (`tgt_success.pre_auth_types`, ticket options, encryption types, and PKINIT certificate profiles). Run `eforge validate-config`; PKINIT (`PreAuthType: 15`) requires populated certificate profile support. |
| Windows auth realism | `windows_auth_realism.yaml` (`workstation_lock.min_unlock_gap_seconds`, failed-logon local/network profiles, and optional companion network connection rates) |
| Baseline auth noise | `auth_noise.yaml` (stale scheduled-credential account pools, host counts, recurrence intervals, jitter, skips, and backoff) |
| Endpoint background noise | `endpoint_noise.yaml` (Windows scheduled-process trigger windows, host drift, skip probability, and DHCP registry emission policy) |
| Host/persona/role volume realism | `host_activity_profiles.yaml` (coarse rate-family multipliers, firewall deny burst shaping, and data-driven artifact variants) |
| Observation/source coverage | `observation_profiles.yaml` (named source-level missingness/delay profiles selected by scenario `observation_profile`; default `complete` keeps perfect coverage; non-complete decisions are coherent per source-local process, session, and same-UID network group; optional collection batching/window knobs belong here) |
| Causal/source-native timing | `timing_profiles.yaml` (`relationships` for causal prerequisites, source latency, teardown margins, Zeek analyzer offsets and TLS duration floors, endpoint host-clock profiles shared by OS logs and host-resident eCAR, independent network sensor clock/path profiles, plus Windows/Sysmon collision spacing) |
| Public NTP fallback servers and DNS tunnel timing | `network_params.yaml` (`public_ntp_servers`, `dns_tunnel_rtt`; scenario-defined internal/domain NTP servers still take precedence) |
| Linux ambient syslog texture | `extra_syslog_messages.yaml` for role/distro daemon message pools; journald capacity/vacuum/rotation messages are generated by the engine as sparse host-state housekeeping rather than high-frequency filler. Polkit desktop auth-agent messages are gated to desktop-capable Linux hosts; server-side polkit authorization messages remain sparse. |
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

For full schema documentation for each file, see the skill reference: `/eforge:references:config-evaluation`.

## Reference Documentation

For full field schemas and conventions, see the reference docs installed with the skills:

| Topic | Skill Reference |
|-------|----------------|
| DNS, traffic, proxy, site maps | `/eforge:references:config-dns-network` |
| Applications, spawn rules, processes | `/eforge:references:config-apps-processes` |
| Persona file structure | `/eforge:references:config-personas` |
| Host activity (bash, systemd, syslog) | `/eforge:references:config-host-activity` |
| Cross-file dependency map | `/eforge:references:config-dependency-graph` |
| Validation checks | `/eforge:references:config-validation` |
