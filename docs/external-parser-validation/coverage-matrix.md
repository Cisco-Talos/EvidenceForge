# Coverage Matrix

This matrix tracks which generated log families currently have third-party
parser validation and which SOF-ELK® filters are used.

The developer-facing SOF-ELK runner requires datasets generated with
`eforge generate --target sof-elk`. The script reads `OUTPUT_TARGET.txt` and
exits before discovery/staging if the marker is missing, invalid, or anything
other than `sof-elk`.

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
| Cisco ASA `cisco_asa.log` | `sof-elk-cisco-asa` | `syslog.yml` | `1000-preprocess-all.conf`, `1100-preprocess-syslog.conf`, `6018-cisco_asa.conf`, `8999-postprocess-all.conf` | `sof-elk` target only; generated under `<sensor>/<year>/cisco_asa.log`, staged under `/logstash/syslog/<year>/<sensor>/cisco_asa.log`, and requires `got_cisco` plus `parse_done`. |
| Web access `web_access.log` | `sof-elk-web-access` | `httpdlog.yml` | `1000-preprocess-all.conf`, `6100-httpd.conf`, `8060-postprocess-useragent.conf`, `8110-postprocess-httpd.conf`, `8999-postprocess-all.conf` | Optional page classification miss `_grokparsefail_8110-01` is ignored. |
| Linux `syslog.log` | `sof-elk-syslog` | `syslog.yml` | `1000-preprocess-all.conf`, `1100-preprocess-syslog.conf`, `6012-dhcpd.conf`, `6013-bindquery.conf`, `6015-sshd.conf`, `6016-pam.conf`, `6017-iptables.conf`, `8100-postprocess-syslog.conf`, `8999-postprocess-all.conf` | `sof-elk` target only; generated RFC3164 files live under `<host>/<year>/syslog.log`, and staged year is validated against parsed `@timestamp`. |
| Windows Security `windows_event_security_snare.log` | `sof-elk-windows-security-snare` | `syslog.yml` | `1000-preprocess-all.conf`, `1010-preprocess-snare.conf`, `1100-preprocess-syslog.conf`, `6010-snare.conf`, `8999-postprocess-all.conf` | `sof-elk` target only; generated under `<host>/<year>/windows_event_security_snare.log`, staged under `/logstash/syslog/<year>/<host>/...`, and requires `snare_log`, `parse_done`, and normalized `winlog.*` fields. |
| Sysmon `windows_event_sysmon_snare.log` | `sof-elk-windows-sysmon-snare` | `syslog.yml` | `1000-preprocess-all.conf`, `1010-preprocess-snare.conf`, `1100-preprocess-syslog.conf`, `6010-snare.conf`, `8999-postprocess-all.conf` | `sof-elk` target only; validates `winlog.event_id`, provider, channel, computer, and staged source year. |

## Unsupported

| EvidenceForge output | Validator | Notes |
| --- | --- | --- |
| Windows Event Security XML (`default` target) | NONE | XML remains generated and evaluated internally; SOF-ELK validation requires `--target sof-elk` Snare syslog output instead. |
| Sysmon XML (`default` target) | NONE | XML remains generated and evaluated internally; SOF-ELK validation requires `--target sof-elk` Snare syslog output instead. |
| Linux syslog (`default` target) | NONE | Default output is flat RFC5424; SOF-ELK validation expects `--target sof-elk` RFC3164 year-partitioned syslog. |
| Cisco ASA (`default` target) | NONE | Default output is flat per-sensor ASA syslog; SOF-ELK validation expects `--target sof-elk` year-partitioned ASA syslog. |
| Snort/IDS alert logs | NONE | Detected as unsupported so they are not silently skipped. |
| Proxy access logs | NONE | Detected as unsupported so they are not silently skipped. |
| eCAR JSON | NONE | Officially unsupported for external-parser validation because there is no stable third-party standard parser target. |
| Bash history | NONE | Officially unsupported for external-parser validation because command history text is not a parser-normalized log family. |

Contributor rule: when adding a generated log family with no parser support,
update this matrix and keep discovery warnings visible.
