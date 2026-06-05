# SOF-ELK® Output Target

The `sof-elk` target renders generated data for the EvidenceForge SOF-ELK
external parser harness. The harness runs SOF-ELK Filebeat and Logstash without
Elasticsearch, validates parser output, and writes structured reports.

EvidenceForge does not vendor SOF-ELK assets. The harness clones the pinned
SOF-ELK repository inside Compose-managed ephemeral volumes and writes only
EvidenceForge-owned wrapper configuration to the host work directory.

## High-Level Format Differences

The SOF-ELK target changes the generated layout for families that need SOF-ELK
parser-compatible envelopes or archive paths. Families that SOF-ELK already
accepts in their source-native shape generally stay unchanged.

| Family | SOF-ELK rendering |
| --- | --- |
| Windows Security | `<host>/<year>/windows_event_security_snare.log` as Snare-style Windows Event Log fields in an RFC3164 syslog envelope. |
| Windows Sysmon | `<host>/<year>/windows_event_sysmon_snare.log` as Snare-style Windows Event Log fields in an RFC3164 syslog envelope. |
| Linux syslog | `<host>/<year>/syslog.log` as RFC3164/BSD syslog. |
| Cisco ASA | `<firewall>/<year>/cisco_asa.log`, keeping native ASA syslog content. |
| Zeek | Unchanged NDJSON under concrete sensor directories. |
| Web access | Apache/Nginx combined log text. |
| Other families | Unchanged, but not necessarily supported by this backend. |

## Generate And Validate

```bash
uv run eforge generate <scenario.yaml> --target sof-elk
uv run python scripts/external_parser.py <scenario-output>/data \
  --backend sof-elk \
  --work-dir /tmp/eforge-sof-elk-validation
```

`--backend auto` also selects SOF-ELK when `OUTPUT_TARGET.txt` contains
`sof-elk`.

## Required Runtime

You need Docker Compose v2 or Podman Compose. The harness handles staging,
wrapper configs, parser startup, report generation, and cleanup.

Extra requirements and gotchas:

- The run environment needs access to the pinned SOF-ELK repository and pinned
  Elastic OSS container images.
- The dataset must have `OUTPUT_TARGET.txt = sof-elk`.
- Reusing a work directory clears parser-owned `sof-elk/*` runtime directories.
- Year-partitioned paths matter for syslog-family files because SOF-ELK recovers
  the event year from the archive path.

## Validation Status

| Family | SOF-ELK ingest status | Parser/normalization status |
| --- | --- | --- |
| Zeek `conn`, `dns`, `http`, `files`, `ssl`, `x509`, `weird` | Supported | Dedicated SOF-ELK filters validate counts and required parsed fields. |
| Zeek `dhcp`, `ntp`, `ocsp`, `packet_filter`, `pe`, `reporter` | Supported | JSON ingest and count validation through supplemental EvidenceForge inputs. |
| Cisco ASA | Supported | SOF-ELK Cisco ASA filter validates parse completion and required fields. |
| Web access | Supported | SOF-ELK HTTPD filters validate parse completion; documented optional enrichment misses may be ignored. |
| Linux syslog | Supported | Syslog filters validate parse completion, required fields, and staged year. |
| Windows Security Snare | Supported | Snare/syslog filters validate `winlog.*` fields, provider/channel metadata, and staged year. |
| Sysmon Snare | Supported | Snare/syslog filters validate `winlog.*` fields, provider/channel metadata, and staged year. |
| Proxy access | Unsupported in SOF-ELK backend | Detected outside this backend's supported validation scope. |
| eCAR | Unsupported in SOF-ELK backend | Custom format with no stable SOF-ELK parser target. |
| Snort/Suricata fast alert | Unsupported in SOF-ELK backend | Generated when IDS sensors exist, but not validated here. |
| Bash history | Unsupported in SOF-ELK backend | Command history text, not a parser-normalized log family. |

## Reports And Troubleshooting

Useful paths under `--work-dir`:

| Path | Purpose |
| --- | --- |
| `sof-elk/parsed/sof_elk_parser_failures.json` | Structured failure report. |
| `sof-elk/parsed/*.jsonl` | Parsed events and raw parser tags. |
| `sof-elk/stage/logstash/...` | Exact staged files as SOF-ELK saw them. |
| `sof-elk/pipeline-logs/filebeat.log` | Filebeat runtime log. |
| `sof-elk/pipeline-logs/logstash.log` | Logstash runtime log. |
| `sof-elk/runtime-config-src/` | EvidenceForge-owned wrapper and supplemental configs. |
| `sof-elk/compose.yaml` | Generated Compose topology. |

Failures usually mean one of five things:

- The dataset was generated with the wrong target.
- Compose, image pull, or SOF-ELK checkout failed.
- SOF-ELK line breaking or parsing produced fatal tags.
- Required normalized fields were missing.
- A source family appeared that the backend intentionally does not support.

For implementation details, see
[../external-parser-validation/sof-elk-harness.md](../external-parser-validation/sof-elk-harness.md).
