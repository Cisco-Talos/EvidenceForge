# Customizing EvidenceForge Configuration

EvidenceForge uses data-driven YAML for realistic baseline generation. Supported project-wide
customizations belong in `<project-root>/.eforge/config`; package defaults remain read-only. Safety,
evaluation, output-format, resource, runtime, and OOB policy are engine-owned.

## Choose the right authoring layer

| Need | Layer |
|---|---|
| One exercise's users, systems, identities, time, storyline, or output | Scenario |
| Reusable sector personas, processes, applications, destinations, traffic, or storage vocabulary | Industry pack |
| Reusable concrete organization environment and baseline | Organization pack |
| Pack inventory, copying, validation, versioning, or provenance | Pack management |
| Project-wide tuning of an existing internal generation family | `.eforge/config` overlay |

Packs use stable public schemas and explicit Scenario 2.0 references. Overlays use internal
filenames and implicitly affect every scenario compiled under that project root. Do not make a pack
depend on an overlay-only identity; it would not be portable. See
[Scenario 2.0 and composable packs](SCENARIO_PACKS.md).

## Project overlays

An overlay mirrors package-relative paths and contains only the sections being changed:

```text
your-project/
├── .eforge/
│   └── config/
│       ├── activity/
│       │   ├── dns_registry.yaml
│       │   ├── application_catalog.yaml
│       │   └── smb_profiles.yaml
│       └── personas/
│           └── nurse.yaml
└── scenarios/
    └── hospital-breach.yaml
```

Scenario validation, resolution, generation, pack management, and config inspection use the
current working directory as their implicit project root. Run from the intended project directory.
Use `--project-root <absolute-root>` only as an explicit override; EvidenceForge never searches
scenario ancestors, working-directory ancestors, home directories, installed packages, or source
trees for `.eforge`. A scenario stored elsewhere does not select a neighboring project overlay.

Never edit installed package YAML for a project customization. Package upgrades may replace it, and
compiled Scenario 2.0 runs snapshot the selected project's overlay into immutable effective config.

## Use through AI chat

Ask the `eforge-config` skill to inspect, validate, or edit an explicit project overlay, for example:

```text
Validate the config overlay in /work/hospital-lab.
```

```text
In /work/hospital-lab, add the reusable nurse persona to Chrome and our existing EHR app.
```

```text
Explain how this project's EDR pool overlay changes the packaged defaults. Do not edit it.
```

The skill first determines whether the request belongs in a scenario, pack, or overlay; establishes
one project root; reads only the relevant family reference; preserves unrelated content; and runs
fresh machine-readable validation after authorized mutations. It does not invent site paths,
application access, process parentage, traffic rates, or policy merely to silence advisory messages.

See [Configuration Compatibility and Migration](config-compatibility.md) for supported legacy
shapes, current replacements, and warning behavior.

Use `eforge-industry-pack`, `eforge-organization-pack`, or `eforge-pack` when the request concerns
portable pack content or lifecycle.

## Inspect current configuration

```bash
# Run from the intended project directory and query only the needed inventory
eforge info personas
eforge info dns_tags
eforge info application_ids
eforge info identity_pools
eforge info overlay.files

# Discover fields, retrieve several as JSON, or inspect the overlay-family contract
eforge info --fields
eforge info --json
eforge info config_families --json
```

`config_families` reports each supported overlay path's ownership, merge mode, validation command,
and focused skill reference. It is useful for unfamiliar or cross-family work; query smaller fields
for routine changes.

For portable pack authoring, use the packaged-only inventories rather than overlay-dependent IDs:

```bash
eforge info pack_builtin_application_ids
eforge info pack_builtin_dns_tags
```

## Merge behavior is family-specific

There is no universal recursive merge:

| Mode | Examples | Behavior |
|---|---|---|
| Keyed entry merge | DNS domains, applications, TLS issuers, IDS signatures, RSAT tools | Matching key deep-merges and new keys append. Supported keyed entries may use `_replace: true` to replace supplied fields, including lists. |
| Deep mapping merge | Traffic, spawn, proxy, site map, auth, observation, timing, HTTP, storage, SMB profiles | Nested mappings merge; scalar values replace; lists append. |
| Append list | Process-network mappings, schedules, selected process relationship pools | Entries append; avoid duplicate identities. |
| Whole-section replacement | Sysmon filters, EDR pools, CallTrace | Every supplied top-level section replaces that complete packaged section. |
| Named-object replacement | Web scan presets | A supplied preset replaces the complete preset. |
| Specialized safety merge | Secret and adversarial-payload families | Families merge by name; safety markers/allowlists can extend but cannot weaken safeguards. |

Fields omitted from an overlay remain packaged defaults. `_replace` is not a deletion language; it
also does not replace list fields inside the deep-mapped SMB profile family.

## Manual examples

### Add a persona

Create `.eforge/config/personas/nurse.yaml`:

```yaml
name: nurse
description: Clinical nurse using EHR and routine web applications
typical_activities:
  - Review patient charts
  - Coordinate care
work_hours: 7am-7pm
application_usage: [Chrome, EHR Client]
risk_profile: medium
browsing_intensity: light
```

The filename must match `name`. Lunch notation such as `(lunch 12pm-1pm)` is optional. Risk affects
event volume and burstiness; it does not grant application access. Add the persona to exact
`application_catalog.yaml` entries when that access is intended.

### Add a reusable domain

Create or update `.eforge/config/activity/dns_registry.yaml`:

```yaml
domains:
  - domain: ehr.example.test
    ips: [198.51.100.20]
    tags: [web, internal]
```

Query `eforge info dns_tags` for the live tags. Add a custom tag under
`valid_tags` before using it. A domain needed by one scenario belongs in
`environment.network_identities` instead.

Adding a domain does not automatically require a proxy URI template or site map. Add those only
when the intended behavior calls for them; generic fallbacks can be valid.

### Extend application access

```yaml
# .eforge/config/activity/application_catalog.yaml
applications:
  - id: chrome
    personas: [nurse]
```

This keyed entry appends `nurse` while preserving omitted Chrome fields. Use `_replace: true` only
when a supplied list should replace rather than extend.

### Tune SMB client or server morphology

`activity/smb_profiles.yaml` owns advertised-filesystem provider defaults, Samba audit-operation
policy, and source-native client/server process morphology. It does not own storage topology,
mappings, credential identity, audit-profile selection, or `smb_activity.client_access`; those are
scenario or organization-pack fields.

The strict `schema_version: 1` document contains `advertised_filesystem_defaults`, `samba_audit`,
`client_defaults`, `client_profiles`, `server_defaults`, and `server_profiles`. These keyed mappings
deep-merge, so an overlay can change one nested field:

```yaml
# .eforge/config/activity/smb_profiles.yaml
client_profiles:
  linux_cifs_mount:
    weight: 55.0
  linux_smbclient:
    weight: 15.0
```

List fields extend; add only unique service aliases/system types. Preserve the ownership model:

- mounted CIFS is kernel-attributed and uses operation-scoped native actors; `mount.cifs` owns only
  the mount lifecycle;
- direct `smbclient` is operation-scoped and owns its transport;
- Explorer and GVFS are resident, but GVFS supplies background texture rather than typed file
  activity; and
- Samba uses a service-lifecycle listener plus a per-transport `smbd` worker.

Operation process templates may use only `server`, `share`, `path`, `client_path`, `local_path`,
`source_path`, `destination_path`, `username`, `smb_principal`, `auth_options`, `operation`, and
`client_ip`. Operand modes are `remote`, `upload`, `download`, `rename`, and `transfer`; mounted
copy/move `transfer` commands require both native source and destination operands.

Samba's configured operation and failure audit lists exclude lifecycle-only `minimal`; any list
containing `standard` also contains `high`. The operation map must remain complete. Backing
filesystem and wire-advertised filesystem remain distinct. Run `eforge validate-config` after every
overlay change.

### Change an IDS signature's default cadence

```yaml
# .eforge/config/activity/ids_signatures.yaml
signatures:
  - sid: 2002910
    alert_policy:
      event_filter:
        type: both
        track: by_src
        count: 5
        seconds: 60
```

Signature entries merge by SID, but `alert_policy` is replaced as one policy. Scenario attachment
policy has final precedence. A default policy neither attaches IDS to unrelated traffic nor decrypts
payloads.

Use `eforge info ids_signatures` to inspect the effective curated signature catalog before adding
or changing an entry. It includes project-overlay changes, so do not copy a SID list from package
files or another installation.

## Important families

| Area | Files |
|---|---|
| DNS and traffic | `dns_registry.yaml`, `traffic_profiles.yaml`, `traffic_rates.yaml`, `network_params.yaml`, `public_dns_profiles.yaml` |
| Web and proxy | `proxy_uri_templates.yaml`, `proxy_user_agents.yaml`, `proxy_phase_profiles.yaml`, `site_maps.yaml`, `web_session_profiles.yaml`, `web_scan_presets.yaml`, `http_file_profiles.yaml` |
| Applications/processes | `application_catalog.yaml`, `spawn_rules.yaml`, `process_network_map.yaml`, `system_processes.yaml`, `rsat_tools.yaml` |
| Endpoint diversity | `sysmon_filters.yaml`, `edr_pools.yaml`, `calltrace_patterns.yaml`, `process_access_patterns.yaml`, `create_remote_thread_patterns.yaml` |
| Host/auth activity | `bash_commands.yaml`, `systemd_schedules.yaml`, `extra_syslog_messages.yaml`, `kerberos_realism.yaml`, `windows_auth_realism.yaml`, `auth_noise.yaml`, `endpoint_noise.yaml`, `host_activity_profiles.yaml` |
| Collection/timing | `observation_profiles.yaml`, `timing_profiles.yaml` |
| Generated identities | `email_background.yaml`, `mail_public_identities.yaml`, `external_actor_profiles.yaml`, `suspicious_benign.yaml`, `command_parameter_pools.yaml` |
| SMB provider/process profiles | `smb_profiles.yaml` |
| SMB corpus defaults | `storage_catalog.yaml`; portable storage vocabulary belongs in a pack |

The config skill's focused references document schemas, merge behavior, and dependencies. Always
prefer current package data and CLI inventories over copied lists in prose.

## Validate and recover

Run full merged validation after every change in a fresh process:

```bash
eforge validate-config --json
```

Errors block use; warnings require review; informational messages are suggestions. Validation is not
file-scoped, so do not silently rewrite unrelated pre-existing diagnostics. Fix YAML/overlay-shape
errors first, confirm the family's merge mode, repair errors attributable to the current change, and
rerun. If a scenario uses the overlay, validate that scenario from the same working directory
afterward. Repeat an explicit project-root override only when one was deliberately selected.

## Engine-owned configuration

Evaluation rules and output-format definitions are versioned with EvidenceForge because evaluator
code, parsers, emitters, ground truth, and safety contracts must agree. They are not supported
`.eforge/config` overlays, pack content, or environment-variable overrides. Changing them is a
source-code development task with matching tests—not a per-project tuning workflow.

For Scenario 2.0, effective precedence is packaged defaults, selected industry packs, organization
pack, project overlay, then scenario-local fields. Peer pack collisions fail deterministically; a
project overlay cannot change engine-owned safety, evaluation, resource, runtime, or OOB policy.
