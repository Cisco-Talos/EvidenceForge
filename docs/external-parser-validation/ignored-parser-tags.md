# Ignored Parser Tags

External parser tags are ignored only when they are explicit optional
enrichment misses and the normalized source record still parsed. Unknown
`_grokparsefail*` tags remain fatal by default.

| Tag | Validator | Log type | Ignore condition | SOF-ELK context | Why this is ignored |
| --- | --- | --- | --- | --- | --- |
| `_grokparsefail_6200-01` | `sof-elk-zeek` | `zeek_dns` | Always, after required DNS fields validate | `configfiles/6200-zeek_dns.conf` | Optional `dns.answers.ip` extraction from `dns.answers.data`; non-address answer types such as `NS`, `PTR`, `MX`, and `SOA` are valid DNS records. |
| `_grokparsefail_8110-01` | `sof-elk-web-access` | `web_access` | Always, after required HTTP access fields validate | `configfiles/8110-postprocess-httpd.conf` | Optional page/not-page URL path classification after the HTTP access record already parsed. |
| `_grokparsefail_6018-01` | `sof-elk-syslog` | `syslog` | Always for Linux syslog events, after required syslog envelope fields validate | `configfiles/6018-cisco_asa.conf` | SOF-ELK's Cisco ASA filter opportunistically runs on ordinary syslog rows; a miss does not mean the Linux syslog record failed. |
| `_grokparsefailure_6015-01` | `sof-elk-syslog` | `syslog` | Only when the event is an `sshd` `pam_unix(sshd:session)` open/close record that has `got_pam` and `parse_done` | `configfiles/6015-sshd.conf` and `configfiles/6016-pam.conf` | SOF-ELK's SSHD filter runs before the PAM filter on `appname=sshd`; the PAM record can parse successfully while retaining the earlier SSHD miss. |
| `_grokparsefail_6016-02` | `sof-elk-syslog` | `syslog` | Only when the event is a parsed `pam_unix(...:auth)` authentication failure with `got_pam` and `parse_done` | `configfiles/6016-pam.conf` | SOF-ELK parses the PAM auth envelope, but the second-stage remainder enrichment does not cover common authentication failure detail fields. |

Fatal defaults include `_jsonparsefailure`, `_dateparsefailure`,
`_rubyexception`, `_grokparsefailure`, and any unclassified tag beginning with
`_grokparsefail`.

When adding a new ignored tag:

1. Add a scoped rule in `src/evidenceforge/external_parsers/tag_policy.py`.
2. Add or update a test proving that exact condition is ignored.
3. Add or update a test proving nearby unclassified tags remain fatal.
4. Update this table.
