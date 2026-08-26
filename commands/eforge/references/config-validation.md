# Config validation and recovery

`eforge validate-config` validates the complete effective package-plus-project configuration. It is
not file-scoped, and it is distinct from `eforge validate`, which validates a scenario.

## Standard workflow

For inspection-only requests, run once and report without modifying files. After every authorized
mutation, start a fresh process so cached configuration cannot hide the change:

```bash
eforge validate-config --json
```

Interpret the result as follows:

- `errors`: block use of the changed configuration; repair errors caused by the current change.
- `warnings`: review for realism or coverage impact; do not rewrite semantics automatically.
- `info`: optional richness suggestions; never invent content merely to remove them.

The command exits successfully with warnings/info and uses a schema-validation exit when errors are
present. JSON is the machine contract; do not scrape human-formatted text.

## What validation covers

- Safe YAML parsing, mapping roots, recognized overlay paths, expected top-level keys, duplicate
  keyed entries, and persona filename/name agreement.
- Pydantic field types and bounds for supported config families.
- DNS tags/domains/IPs, proxy/site-map references, application/persona/process relationships, and
  traffic/service references.
- Timing/rate/probability ranges, observation-profile source families, auth/TLS/Kerberos coherence,
  endpoint pools, RSAT tools, web-scan IDS rules, and signature identity/policy.
- SMB profile schema/defaults, advertised-filesystem and Samba audit maps, OS/access/path/transport
  compatibility, native process templates, operation operands, and listener/worker lifecycles.
- Generated identity pools including `command_parameter_pools.yaml`, email identities, public actor
  IPs, and suspicious-benign host/IP pairs.
- Secret/payload family synthesis, poison markers, reserved-host safety, and carrier rendering.

Validation is authoritative for acceptance, but it cannot determine whether an invented site route,
application assignment, process parent, traffic rate, or IDS cadence is semantically correct.

## SMB profile validation

The fully merged `.eforge/config/activity/smb_profiles.yaml` document is strict and versioned.
Its only top-level keys are `schema_version`, `advertised_filesystem_defaults`, `samba_audit`,
`client_defaults`, `client_profiles`, `server_defaults`, and `server_profiles`; unknown roots or
fields are errors. Scenario storage and `smb_activity` validation is separate.

Advertised-filesystem defaults must cover each supported Windows/Linux backing filesystem with a
safe wire label. The Samba map must cover every required canonical SMB operation with a
source-native label. Successful-operation and failure eligibility reject lifecycle-only `minimal`;
either list containing `standard` must also contain `high`.

Ownership checks are deliberate: mounted CIFS requires kernel transport attribution and explicit
operation-scoped actors; direct `smbclient` uses operation lifecycles and process-owned transport;
Explorer/GVFS use resident processes; listeners use service lifecycle; and Linux Samba requires a
per-transport worker. GVFS remains background transport/process texture, not a typed SMB file mode.

Process images must be absolute and OS-native. Templates accept only `server`, `share`, `path`,
`client_path`, `local_path`, `source_path`, `destination_path`, `username`, `smb_principal`,
`auth_options`, `operation`, and `client_ip`, without conversions, traversal, or format
specifications. The `remote`, `download`, `upload`, and `rename` operand modes require their
corresponding wire/local fields; `transfer` requires both `{source_path}` and
`{destination_path}` for mounted copy/move commands.

## Repair classes

1. **Mechanical auto-repair:** syntax/indentation in the affected file, the confirmed overlay
   directory, or another meaning-preserving correction.
2. **Directly implied auto-repair plus report:** an exact dependency already selected by the user.
3. **Semantic decision:** tags, access, parentage, site paths, traffic, timing, missingness, and
   policy. Ask one focused question.

Do not auto-create proxy templates, site maps, persona application access, spawn rules, or process
network mappings. Generic fallbacks and intentionally sparse configuration are valid.

## Recovery order

1. Confirm the working directory and `eforge info overlay.path`.
2. Fix overlay YAML/shape errors first; merged validation stops when an overlay cannot be loaded
   safely.
3. Read the packaged default and existing overlay for the reported family.
4. Confirm that the family's merge mode did not replace a complete section unexpectedly.
5. Repair only current-change errors, rerun in a fresh process, and preserve unrelated existing
   diagnostics for the report.
6. If a supplied scenario depends on the overlay, validate it from the same working directory after
   config validation passes.

Never weaken engine-owned safety, evaluation, resource, runtime, or OOB policy to silence an error.
