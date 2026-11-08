# Default Output Target

The `default` target is the neutral EvidenceForge output. It is intended for
manual review, custom ingestion experiments, and `eforge eval`, not for proving
that a specific third-party parser accepts the data without extra configuration.

## High-Level Format Differences

The default target keeps each family in a source-readable, SIEM-neutral shape.
It does not add parser-specific envelopes, year-partitioned archive paths, or
Splunk-specific JSON records.

| Family | Default output | Notes |
| --- | --- | --- |
| Windows Security | `<host>/windows_event_security.xml` | Rooted XML document with `<Events>...</Events>`. |
| Windows Sysmon | `<host>/windows_event_sysmon.xml` | Rooted XML document with `<Events>...</Events>`. |
| Linux syslog | `<host>/syslog.log` | RFC5424 with full timestamp year. |
| Cisco ASA | `<firewall>/cisco_asa.log` | Native ASA syslog payload from a firewall entry. |
| Zeek | `<sensor>/<log>.json` | NDJSON, emitted only for configured Zeek sensors. |
| Web access | `<web-host>/web_access.log` | Apache/Nginx combined log format. |
| Proxy access | `<proxy-host>/proxy_access.log` | Apache/Nginx combined forward proxy log. |
| eCAR | `<host>/ecar.json` | Custom simulated EDR NDJSON. |
| Snort/Suricata | `<ids-sensor>/snort_alert.log` | Fast alert style, emitted only for configured IDS sensors. |
| Bash history | `<host>/bash_history/<user>.bash_history` | Explicit interactive Bash on Linux/Mac. |
| Zsh history | `<host>/zsh_history/<user>.zsh_history` | Experimental interactive Mac submissions. |
| Mac Endpoint Security | `<host>/macos_endpoint_security.ndjson` | Qualified v11 process and bounded regular-file events. |
| Mac Unified Log | `<host>/macos_unified_log.ndjson` | Selected workspace, policy-refusal and SSH authentication messages. |

## Generate

```bash
uv run eforge generate <scenario.yaml> --target default
```

Omitting `--target` also uses the default target. New datasets write
`OUTPUT_TARGET.txt` with `default`; older legacy datasets with no marker are
treated as default by EvidenceForge.

## Ingest Expectations

The default target does not ship target-specific Splunk, SOF-ELK®, or other SIEM
configuration. If you ingest it manually, choose sourcetypes, line breaking,
timestamp extraction, host/source metadata, and normalization rules yourself.

Non-obvious gotchas:

- Default Windows XML is a single rooted XML document per host. A file monitor
  that expects one event per physical line should use `--target splunk` instead.
- Default Linux syslog and Cisco ASA logs are not year-partitioned. SOF-ELK
  validation expects `--target sof-elk` for those families.
- Default web and proxy access logs are combined text. The Splunk target uses
  JSON for Apache TA compatibility, plus generated EvidenceForge proxy
  eventtype/tag config.

## Validation Status

| Family | Default ingest status | Normalization status |
| --- | --- | --- |
| Windows Security | Generated only | No external parser claim. |
| Windows Sysmon | Generated only | No external parser claim. |
| Linux syslog | Generated only | No external parser claim. |
| Cisco ASA | Generated only | No external parser claim. |
| Zeek | Generated only | No external parser claim for this target. |
| Web access | Generated only | No external parser claim for this target. |
| Proxy access | Generated only | No external parser claim for this target. |
| eCAR | Generated only | Custom format. |
| Snort/Suricata | Generated only | No external parser claim. |
| Bash/zsh history | Generated only | Interactive submissions, not a parser-normalized log family. |
| Mac ES/ULF | Generated only | Internal native codecs/evaluation; no external native parser/normalization claim. |

For supported-family parser validation, regenerate with [sof-elk.md](sof-elk.md) or
[splunk.md](splunk.md). Mac ES/ULF and zsh history remain outside those harnesses
and their discovery patterns; target selection does not establish ingestion support.
