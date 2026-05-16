# Coverage Matrix

This matrix tracks which generated log families currently have third-party
parser validation and which SOF-ELK filters are used.

## Supported

| EvidenceForge output | Validator | SOF-ELK input | SOF-ELK filters | Notes |
| --- | --- | --- | --- | --- |
| Zeek `conn` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `2051-zeek_conn-netflow.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter. |
| Zeek `dns` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `6200-zeek_dns.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter; optional answer-IP enrichment misses are ignored only for `_grokparsefail_6200-01`. |
| Zeek `http` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `6201-zeek_http.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter. |
| Zeek `files` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `6202-zeek_files.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter. |
| Zeek `ssl` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `6203-zeek_ssl.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter. |
| Zeek `x509` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `6204-zeek_x509.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter. |
| Zeek `weird` | `sof-elk-zeek` | `zeek.yml` | `1000-preprocess-all.conf`, `1001-preprocess-json.conf`, `1200-preprocess-zeek.conf`, `6276-zeek_weird.conf`, `8000-postprocess-zeek.conf`, `8999-postprocess-all.conf` | Dedicated SOF-ELK filter. |
| Zeek `dhcp` | `sof-elk-zeek` | `zeek.yml` | JSON preprocess and Zeek postprocess filters | Filebeat-covered JSON ingestion and count validation; no dedicated SOF-ELK DHCP Zeek filter in the pinned config. |
| Zeek `ntp` | `sof-elk-zeek` | Supplemental EvidenceForge input | JSON preprocess and Zeek postprocess filters | JSON ingestion and count validation. |
| Zeek `ocsp` | `sof-elk-zeek` | Supplemental EvidenceForge input | JSON preprocess and Zeek postprocess filters | JSON ingestion and count validation. |
| Zeek `packet_filter` | `sof-elk-zeek` | Supplemental EvidenceForge input | JSON preprocess and Zeek postprocess filters | JSON ingestion and count validation. |
| Zeek `pe` | `sof-elk-zeek` | Supplemental EvidenceForge input | JSON preprocess and Zeek postprocess filters | JSON ingestion and count validation. |
| Zeek `reporter` | `sof-elk-zeek` | Supplemental EvidenceForge input | JSON preprocess and Zeek postprocess filters | JSON ingestion and count validation. |
| Cisco ASA `cisco_asa.log` | `sof-elk-cisco-asa` | `syslog.yml` | `1000-preprocess-all.conf`, `1100-preprocess-syslog.conf`, `6018-cisco_asa.conf`, `8999-postprocess-all.conf` | Staged under `/logstash/syslog/<year>/<sensor>/cisco_asa.log`; requires `got_cisco` and `parse_done`. |
| Web access `web_access.log` | `sof-elk-web-access` | `httpdlog.yml` | `1000-preprocess-all.conf`, `6100-httpd.conf`, `8060-postprocess-useragent.conf`, `8110-postprocess-httpd.conf`, `8999-postprocess-all.conf` | Optional page classification miss `_grokparsefail_8110-01` is ignored. |
| Linux `syslog.log` | `sof-elk-syslog` | `syslog.yml` | `1000-preprocess-all.conf`, `1100-preprocess-syslog.conf`, `6012-dhcpd.conf`, `6013-bindquery.conf`, `6015-sshd.conf`, `6016-pam.conf`, `6017-iptables.conf`, `8100-postprocess-syslog.conf`, `8999-postprocess-all.conf` | Generated RFC3164 files should live under `<host>/<year>/syslog.log`; staged year is validated against parsed `@timestamp`. |

## Unsupported

| EvidenceForge output | Validator | Notes |
| --- | --- | --- |
| Windows Event Security XML | NONE | EvidenceForge emits plain text XML, not binary EVTX. Needs a parser that expects the same XML shape. |
| Sysmon XML | NONE | Same XML constraint as Windows Event Security. |
| Snort/IDS alert logs | NONE | Detected as unsupported so they are not silently skipped. |
| Proxy access logs | NONE | Detected as unsupported so they are not silently skipped. |
| eCAR JSON | NONE | Detected as unsupported so it is not silently skipped. |
| Bash history | NONE | Detected as unsupported. This is command history text, not a parser-normalized log family. |

Contributor rule: when adding a generated log family with no parser support,
update this matrix and keep discovery warnings visible.
