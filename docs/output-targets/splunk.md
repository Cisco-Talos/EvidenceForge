# Splunk Output Target

The `splunk` target renders generated data for Splunk file monitoring and the
EvidenceForge Splunk external parser harness. The harness starts an ephemeral
`splunk/splunk:10.2.3` container, installs generated EvidenceForge-owned config,
optionally stages caller-supplied apps, and validates ingest with REST searches.

EvidenceForge does not vendor Splunk, Splunkbase apps, TAs, or CIM content.

## High-Level Format Differences

The Splunk target keeps source-native shapes when Splunk and the supplied apps
can parse them, and changes rendering where file monitoring or CIM validation
needs a different shape.

| Family | Splunk rendering |
| --- | --- |
| Windows Security | `<host>/windows_event_security.xml`, one complete `<Event>...</Event>` per physical line. |
| Windows Sysmon | `<host>/windows_event_sysmon.xml`, one complete `<Event>...</Event>` per physical line. |
| Linux syslog | `<host>/syslog.log` as RFC5424 with full timestamp year. |
| Cisco ASA | `<firewall>/cisco_asa.log`, native ASA syslog content in a flat firewall-sensor file. |
| Zeek | Unchanged NDJSON under concrete sensor directories. |
| Web access | Target-specific JSON records for the Apache TA `apache:access:json` sourcetype. |
| Proxy access | Target-specific JSON records for `apache:access:json`, plus EvidenceForge-generated proxy eventtype/tag config for CIM `Web.Proxy`. |
| eCAR | Custom NDJSON under host directories. |

No binary EVTX is generated in v1. The Linux Docker harness validates Windows
Event XML file ingest instead.

## Required Splunk Apps For CIM Validation

EvidenceForge does not vendor, download, or redistribute Splunkbase apps. To run
`--cim require`, download the needed apps from Splunkbase yourself, then pass the
local app directories or archives with repeated `--splunk-app <path>` arguments.
Splunkbase may require login before it allows archive downloads.

The current CIM dataset checks cover Windows Security authentication, Sysmon
process lifecycle, Zeek network/web records, Cisco ASA network traffic, web
access, and proxy access. Linux syslog and eCAR receive base Splunk
ingest/field validation only, so the Splunk Add-on for Unix and Linux is not
required by the current CIM checks.

| Validation area | Splunk app/add-on | Download page |
| --- | --- | --- |
| CIM data models | Splunk Common Information Model (CIM) | <https://splunkbase.splunk.com/app/1621> |
| Windows Security | Splunk Add-on for Microsoft Windows | <https://splunkbase.splunk.com/app/742> |
| Windows Sysmon | Splunk Add-on for Sysmon | <https://splunkbase.splunk.com/app/5709> |
| Cisco ASA | Splunk Add-on for Cisco ASA | <https://splunkbase.splunk.com/app/1620> |
| Zeek connection and HTTP logs | TA for Zeek | <https://splunkbase.splunk.com/app/5466> |
| Web and proxy access logs | Splunk Add-on for Apache Web Server | <https://splunkbase.splunk.com/app/3186> |

## Generate And Validate

Base ingest validation:

```bash
uv run eforge generate <scenario.yaml> --target splunk
uv run python scripts/external_parser.py <scenario-output>/data \
  --backend splunk \
  --accept-splunk-license \
  --work-dir /tmp/eforge-splunk-validation
```

CIM validation with caller-supplied local apps:

```bash
uv run python scripts/external_parser.py <scenario-output>/data \
  --backend splunk \
  --accept-splunk-license \
  --cim require \
  --splunk-app /path/to/splunk-common-information-model-cim.tgz \
  --splunk-app /path/to/splunk-add-on-for-microsoft-windows.spl \
  --splunk-app /path/to/splunk-add-on-for-sysmon.tgz \
  --splunk-app /path/to/splunk-add-on-for-cisco-asa.spl \
  --splunk-app /path/to/ta-for-zeek.tgz \
  --splunk-app /path/to/splunk-add-on-for-apache-web-server.spl
```

See [Required Splunk Apps For CIM Validation](#required-splunk-apps-for-cim-validation)
for the official download pages for those local app archives.

`--backend auto` also selects Splunk when `OUTPUT_TARGET.txt` contains
`splunk`.

## Licensing And Apps

`--accept-splunk-license` is required before the container starts. The generated
Compose file accepts the Splunk license and Splunk General Terms for that
ephemeral validation run. The caller remains responsible for Splunk container
licensing and any Splunkbase app terms.

`--splunk-app <path>` may point to a local app directory or archive. Apps are
copied or unpacked only into the run work directory. EvidenceForge never
downloads them silently.

## CIM Mode

| Mode | Behavior |
| --- | --- |
| `--cim auto` | Default. Run base ingest validation. If apps are supplied, also run CIM checks. If apps are absent, mark CIM skipped. |
| `--cim require` | Fail early unless at least one app is supplied. |
| `--cim off` | Skip CIM checks even when apps are supplied. |

Use `require` when the goal is to prove CIM visibility. Use `auto` for a
pipeline smoke that should still succeed when local TA paths are unavailable.

## Ingest Config

The harness writes an EvidenceForge-owned Splunk app under:

```text
<work-dir>/splunk/runtime-config-src/apps/evidenceforge_parser_validation/
```

Important generated files:

| File | Purpose |
| --- | --- |
| `inputs.conf` | File monitors with explicit `index`, `host`, `source`, and `sourcetype`. |
| `props.conf` | Line breaking, timestamp hints, XML/JSON modes, and base extractions. |
| `transforms.conf` | Header/comment filtering and parser helpers. |
| `indexes.conf` | Dedicated `eforge` index. |
| `eventtypes.conf` and `tags.conf` | EvidenceForge-owned proxy/web classification needed for current validation. |

For manual ingestion outside the harness, mirror the generated app config or
use it as the source of truth for sourcetypes and line breaking.

## Validation Status

| Family | Splunk sourcetype | Ingest status | CIM status |
| --- | --- | --- | --- |
| Windows Security | `XmlWinEventLog` with `source=XmlWinEventLog:Security` when the Windows TA is present | Supported, count and core fields validated | Authentication events validated in `Authentication.Authentication`; non-auth Security events are parsed but not CIM-validated. |
| Windows Sysmon | `XmlWinEventLog` with `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` when the Sysmon TA is present | Supported, count and core fields validated | Event IDs 1 and 5 validated in `Endpoint.Processes`; 7, 8, and 10 enter the data model but remain partial-CIM for now. |
| Zeek `conn` | `bro:conn:json` | Supported | Validated in `Network_Traffic.All_Traffic`. |
| Zeek `http` | `bro:http:json` | Supported | Validated in `Web.Web`. |
| Zeek `dns`, `dhcp`, `files`, `ssl`, `x509`, `ntp`, `ocsp`, `pe`, `weird`, `packet_filter`, `reporter` | `bro:<log>:json` | Supported | Parsed-only for now. |
| Cisco ASA | `cisco:asa` | Supported | Validated in `Network_Traffic.All_Traffic`. |
| Linux syslog | `syslog` | Supported | Parsed-only for now. |
| Web access | `apache:access:json` | Supported | Validated in `Web.Web`. |
| Proxy access | `apache:access:json` | Supported | Validated in `Web.Proxy`. |
| eCAR | `evidenceforge:ecar:json` | Supported | Custom format, no CIM claim. |
| Snort/Suricata fast alert | Not staged in Splunk v1 | Unsupported | Not CIM-normalized. |
| Bash history | Not staged in Splunk v1 | Unsupported | Not CIM-normalized. |

## What CIM Validation Proves

For families marked CIM validated, the harness proves:

- The records were indexed at the expected count.
- Splunk search can find the expected sourcetype/source family.
- Required base fields were extracted.
- The relevant CIM data model and object returned the expected event subset.
- Required CIM fields were populated for the validated event families.
- Splunk `_internal` searches did not report ingest or parser warnings that the
  harness treats as fatal.

For parsed-only families, the harness proves ingest and basic field visibility,
but it does not claim data-model normalization.

## Reports And Troubleshooting

Useful paths under `--work-dir`:

| Path | Purpose |
| --- | --- |
| `splunk/parsed/splunk_validation_report.json` | Success report. |
| `splunk/parsed/splunk_parser_failures.json` | Structured failure report. |
| `splunk/search-results/*.jsonl` | Raw REST search/export rows used for validation. |
| `splunk/stage/data/...` | Exact staged files as Splunk monitored them. |
| `splunk/pipeline-logs/splunkd.log` | Recent Splunk daemon log. |
| `splunk/pipeline-logs/btool-*.txt` | Effective Splunk config snapshots. |
| `splunk/runtime-config-src/` | Generated app config and ephemeral supplied app copies. |
| `splunk/compose.yaml` | Generated Compose topology. |

Common failure interpretations:

- Count mismatch: file monitor, line breaking, CRC, source path, or unsupported
  source-family issue.
- Required base field missing: generated config or record shape issue.
- `_internal` parser warning: timestamp, line breaking, tailing, or monitor
  issue.
- CIM data-model count mismatch: app visibility, search shape, tags/eventtypes,
  or source/sourcetype mismatch.
- CIM field missing: either the TA does not map that event family to the field,
  or the generated native record is missing data the TA expects.

For implementation details, see
[../external-parser-validation/splunk-harness.md](../external-parser-validation/splunk-harness.md).
