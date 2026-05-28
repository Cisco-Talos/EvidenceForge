# Ignored Parser Tags

External parser tags are ignored only when they are explicit optional
enrichment misses or scoped parser limitations, and the normalized source
record still parsed. Unknown `_grokparsefail*` tags remain fatal by default.

| Tag | Validator | Log type | Ignore condition | SOF-ELK® context | Why this is ignored |
| --- | --- | --- | --- | --- | --- |
| `_grokparsefail_6200-01` | `sof-elk-zeek` | `zeek_dns` | Always, after required DNS fields validate | `configfiles/6200-zeek_dns.conf` | Optional `dns.answers.ip` extraction from `dns.answers.data`; non-address answer types such as `NS`, `PTR`, `MX`, and `SOA` are valid DNS records. |
| `_dateparsefailure` | `sof-elk-zeek` | `zeek_x509` | Only when raw `certificate.not_valid_before` and `certificate.not_valid_after` are valid epoch seconds and at least one is after the signed 32-bit Unix timestamp boundary but still within RFC 5280's UTCTime window through 2049 | `configfiles/6204-zeek_x509.conf` | Zeek `x509.log` correctly represents certificate validity as epoch seconds. RFC 5280 permits UTCTime certificate dates through 2049, but this SOF-ELK/Logstash date path cannot parse post-2038 epoch values. |
| `_grokparsefail_8110-01` | `sof-elk-web-access` | `web_access` | Always, after required HTTP access fields validate | `configfiles/8110-postprocess-httpd.conf` | Optional page/not-page URL path classification after the HTTP access record already parsed. |
| `_grokparsefail_6018-01` | `sof-elk-syslog` | `syslog` | Always for Linux syslog events, after required syslog envelope fields validate | `configfiles/6018-cisco_asa.conf` | SOF-ELK's Cisco ASA filter opportunistically runs on ordinary syslog rows; a miss does not mean the Linux syslog record failed. |
| `_grokparsefailure_6015-01` | `sof-elk-syslog` | `syslog` | Only when the event is an `sshd` `pam_unix(sshd:session)` open/close record that has `got_pam` and `parse_done` | `configfiles/6015-sshd.conf` and `configfiles/6016-pam.conf` | SOF-ELK's SSHD filter runs before the PAM filter on `appname=sshd`; the PAM record can parse successfully while retaining the earlier SSHD miss. |
| `_grokparsefail_6016-02` | `sof-elk-syslog` | `syslog` | Only when the event is a parsed `pam_unix(...:auth)` authentication failure with `got_pam` and `parse_done` | `configfiles/6016-pam.conf` | SOF-ELK parses the PAM auth envelope, but the second-stage remainder enrichment does not cover common authentication failure detail fields. |
| `_grokparsefail_6010-01` | `sof-elk-windows-security-snare` | `windows_event_security_snare` | Only when the Snare row has `snare_log`, `parse_done`, and required `winlog.*` fields | `configfiles/6010-snare.conf` | SOF-ELK's second-stage expanded-data enrichment can retain a grok miss after the Snare CSV row and required Windows fields parsed. |
| `_grokparsefail_6010-01` | `sof-elk-windows-sysmon-snare` | `windows_event_sysmon_snare` | Only when the Snare row has `snare_log`, `parse_done`, and required `winlog.*` fields | `configfiles/6010-snare.conf` | SOF-ELK's second-stage expanded-data enrichment can retain a grok miss after the Snare CSV row and required Sysmon fields parsed. |

Fatal defaults include `_jsonparsefailure`, `_dateparsefailure`,
`_rubyexception`, `_grokparsefailure`, and any unclassified tag beginning with
`_grokparsefail`. The `zeek_x509` `_dateparsefailure` rule above is deliberately
narrow; other date parse failures remain fatal.

When adding a new ignored tag:

1. Add a scoped rule in `src/evidenceforge/external_parsers/tag_policy.py`.
2. Add or update a test proving that exact condition is ignored.
3. Add or update a test proving nearby unclassified tags remain fatal.
4. Update this table.
