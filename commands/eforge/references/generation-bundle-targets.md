---
description: "Generated bundle, sidecar, and output-target reference"
---

# Generated Bundle And Output Targets

## Contents

- [Bundle Layout](#bundle-layout)
- [Compiled Collection Identity](#compiled-collection-identity)
- [Output Targets](#output-targets)
- [Replacement And Verification](#replacement-and-verification)

Read this reference when the question is about generated paths, authoritative artifacts, target
rendering, replacement scope, or bundle integrity. Read a family-specific evidence reference for
record fields and source behavior.

## Bundle Layout

One successful current run writes one matched bundle. Some source files only exist when their
format, topology, or feature is active.

```text
<bundle-root>/
  data/
    <hostname.domain>/
      windows_event_security.xml
      windows_event_sysmon.xml
      ecar.json
      syslog.log
      bash_history/<username>.bash_history
      web_access.log
      proxy_access.log
      <year>/windows_event_security_snare.log
      <year>/windows_event_sysmon_snare.log
      <year>/syslog.log
    <sensor-name>/
      conn.json
      dns.json
      http.json
      ssl.json
      files.json
      smtp.json
      ...
    <ids-sensor-name>/snort_alert.log
    <firewall-name>/cisco_asa.log
    <firewall-name>/<year>/cisco_asa.log
  artifacts/email/<artifact-id>.eml
  GROUND_TRUTH.json
  GROUND_TRUTH.md
  OBSERVATION_MANIFEST.json
  COLLECTION_PROFILE.json
  STORAGE_MANIFEST.json
  ARTIFACTS_MANIFEST.json
  OUTPUT_TARGET.txt
  RESOLVED_SCENARIO.yaml
  GENERATION_MANIFEST.json
  ENVIRONMENT.md
```

`data/`, both ground-truth files, the observation manifest, collection profile, output-target
marker, resolved scenario, and generation manifest are core current outputs. The storage manifest,
artifact manifest, and `artifacts/` appear only when applicable. `ENVIRONMENT.md` is optional
authored collateral; generation does not create it.

`GROUND_TRUTH.json` is canonical and `GROUND_TRUTH.md` is its human-readable projection.
`RESOLVED_SCENARIO.yaml` is the self-contained authoritative generation input. It no longer needs
the authored include graph, packs, project configuration, or discovery directory. It remains
generated/non-editable and cannot authorize live callbacks.

`GENERATION_MANIFEST.json` is the run identity and is committed last. It records the effective
target, seed, formats, runtime/build identity, selected pack identities and digests, resolved-file
hash, and output hashes. An absent manifest means the current transactional bundle did not finish
successfully. A copied bundle must keep every hashed file with this manifest.

## Compiled Collection Identity

Before rendering, generation compiles the requested formats into immutable exact source instances
and fixed capability sets. Canonical projection targets are then filtered by source deployment,
topology visibility, coherent missingness, source timing/batching, and only then rendered.

`OBSERVATION_MANIFEST.json` records aggregate source-observation outcomes. When exact source
overrides are part of the effective scenario, `source_deployment_digest` binds those diagnostics to
the immutable compiled deployment. `COLLECTION_PROFILE.json` records the primary collection window,
observation profile, family tail policy, and export ordering. Projection envelopes themselves are
ephemeral; the bundle does not retain one decision object per candidate record.

When diagnosing absence, distinguish an undeployed source, missing capability, invisible topology,
coherent drop/filter, and an out-of-window record. Do not change scenario collection policy to hide
a lifecycle, effect, content, channel, or timing defect.

## Output Targets

`eforge generate --target default|sof-elk|splunk` selects one rendering for the run. It changes
paths or record shapes under `data/`; it does not create a target-named bundle root. Scenario
`output.logs` and `--formats` continue to use canonical format names.

| Family | `default` | `sof-elk` | `splunk` |
| --- | --- | --- | --- |
| Windows Security | Rooted `<host>/windows_event_security.xml` | `<host>/<year>/windows_event_security_snare.log` | `<host>/windows_event_security.xml`, one complete Event per line |
| Windows Sysmon | Rooted `<host>/windows_event_sysmon.xml` | `<host>/<year>/windows_event_sysmon_snare.log` | `<host>/windows_event_sysmon.xml`, one complete Event per line |
| Linux syslog | `<host>/syslog.log`, RFC5424 | `<host>/<year>/syslog.log`, RFC3164/BSD | `<host>/syslog.log`, RFC5424 |
| Cisco ASA | `<firewall>/cisco_asa.log` | `<firewall>/<year>/cisco_asa.log` | `<firewall>/cisco_asa.log` |
| Web access | Combined text | Combined text | Apache TA-compatible JSON in `web_access.log` |
| Proxy access | Extended combined text | Plain combined text | Apache TA-compatible proxy JSON with CIM tagging in `proxy_access.log` |
| Zeek, IDS, eCAR, bash | Source-native files | Unchanged | Unchanged |

`OUTPUT_TARGET.txt` contains the chosen target. A missing marker identifies legacy/default output
to evaluation. `COLLECTION_PROFILE.json` does not disclose storyline labels or truth.

When storage is configured, `STORAGE_MANIFEST.json` uses schema version 3. Host file sets are unique
canonical populations, share bindings are aliases rather than duplicate storage, and volumes identify server
platform, native root, and backing filesystem. Shares keep provider/platform, network and
server-native roots, backing and wire-advertised filesystems, case policy, and audit profile.
Mappings retain compatibility `drive`/`mount` fields plus resolved platform/type/root
presentations, credential mode, and non-secret principal identity. Resolved storyline targets keep
wire/share-relative, client-presented, and server-local path views separate. The manifest never
contains credential secrets or file payloads.

## Replacement And Verification

An approved `--force` run replaces engine-owned data, reports, manifests, generated artifacts, and
resolved scenario as one unit. A format-filtered overwrite still replaces the entire `data/`
directory; it does not retain formats from an older run. Unregistered authored collateral is
preserved.

Inspect the generation manifest after exit code 0 and report its effective values, not merely the
requested flags. Use `eforge eval <bundle-root>` for independent integrity verification: evaluation
checks containment, sidecar hashes, the resolved document, and compiled identity before scoring.
Run manifests include a timestamp, so deterministic evidence replays need not have byte-identical
manifest files.
