# Threat Hunter - Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 66
**Synthetic-Confidence Score:** 43

## Executive Summary

This dataset is mostly production-like: source formats are credible, timestamps are coherent, and the suspicious activity has believable cross-source support rather than impossible sequencing. I found a few synthetic-leaning issues, especially around collection-profile consistency and the DC Security log-clear sequence, but not enough hard contradiction to call it confidently synthetic.

## Evidence For Synthetic

- `[schema_or_format]` `DC-01.meridianhcs.local/windows_event_security.xml` shows `cmd.exe /c wevtutil cl Security` at `2024-03-18T17:41:50.663545Z`, `wevtutil cl Security` at `17:41:51.368545Z`, then EventID `1102` at `17:41:51.6978749Z`; the next Security event continues with high monotonic `EventRecordID` `29139485` at `17:41:52.2651871Z`. In a raw local Security log this is suspicious; a forwarded/normalized collection could explain it.
- `[environment_or_collection_plausibility]` `COLLECTION_PROFILE.json` advertises a `mail_artifacts` family with `email_artifacts` and `eml`, but no matching files appear in the dataset. That is a profile consistency issue, not just thin coverage.
- `[distribution_texture]` Endpoint background activity has some templated texture: identical Windows process command lines such as `taskhostw.exe /Run`, `wsqmcons.exe`, `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\service-health.ps1`, and several `dllhost.exe /Processid:{...}` commands recur across most Windows hosts.
- `[weak_signal]` Linux bash histories reuse a small admin command pool across unrelated servers, especially resolver, `journalctl`, `ss`, `systemctl`, and `/var/log/auth.log` checks. This is explainable as admin work, but the repetition is a mild synthetic signal.
- `[weak_signal]` `WS-LNGUYEN-01.meridianhcs.local/bash_history/lina.nguyen.bash_history` has a timestamp-order anomaly around `1710779524`, then `1710777916`, then `1710779574`. Multiple shell sessions can explain this, so I score it low.

## Evidence For Real

- Zeek companion integrity is strong: DNS, HTTP, SSL, SMTP, files, DHCP, and NTP companion UIDs all resolve to parent `conn.json` rows in the checked sensors.
- The DB exfil/pivot sequence is coherent: `DB-PROD-01` root bash history records `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz` at epoch `1710783044`; eCAR records `/usr/bin/scp` at `17:30:45.240Z` and FLOW `10.10.4.10:46080 -> 10.10.2.30:22` at `17:30:48.179Z`; `APP-INT-01` syslog records the SSH connection and accepted public key at `17:30:46-17:30:48Z`; Zeek core records the same SSH flow at `17:30:45.862Z`.
- Perimeter noise is credible: `WEB-EXT-01` web logs show a Nikto-like scan from `185.70.41.45` beginning around `12:31Z`, and Snort logs matching ET scan alerts from the same source during that period.
- Host lifecycle checks did not find visible impossible orderings: no eCAR terminate-before-create issues, no Sysmon process/network-before-visible-create issues, and no Windows logoff-before-visible-logon issues for same identifiers.
- Source mix is plausible for an enterprise slice: DC Kerberos volume, workstation 5156/Sysmon noise, proxy access, ASA perimeter logs, Zeek core/DMZ split, Linux syslog, and bash histories all show role-appropriate activity.

## Detailed Analysis

**Orientation:** The dataset covers roughly `2024-03-18T12:00:00Z` to `18:00:00Z`, with endpoint tails after the primary window. It includes Windows endpoints/servers, Linux hosts, Zeek core and DMZ sensors, ASA, Snort, proxy access, web access, eCAR, and bash history.

**Operational lifecycle:** The most suspicious chain is not merely narratively complete; it is technically correlated. The `DB-PROD-01` dump and `scp` activity has process, file-read, SSH transport, receiving sshd, and Zeek support with matching IPs, ports, and timestamps. I did not find a transport/auth ordering contradiction.

**Network and perimeter:** `zeek-core/conn.json` has 7,445 rows and `zeek-dmz/conn.json` has 6,606 rows. DMZ has realistic external scan texture: high S0 volume, repeated external sources, and corresponding web/Snort evidence. Core traffic is mostly successful internal DNS/Kerberos/HTTP/SMB/LDAP, which fits an internal sensor.

**Endpoint telemetry:** Windows Security and Sysmon event IDs are plausible: DC has Kerberos events (`4768`, `4769`, `4771`, `4776`) plus `5156`, logon, process, and audit-clear events; workstations show Sysmon process, DNS, network, registry, image-load, and process-access events. eCAR object/action mixes also match host roles.

**Synthetic concerns:** The DC log-clear record numbering and collection-profile mail-artifact mismatch are the strongest synthetic indicators. The rest are softer texture issues: repeated admin commands and repeated Windows process command pools across hosts.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---:|---|
| `schema_or_format` | Windows Security | DC log-clear sequence | Medium: source-native ambiguity around `wevtutil cl Security` and continued high EventRecordIDs |
| `environment_or_collection_plausibility` | Collection profile | Dataset profile | Medium-low: advertised mail artifacts are absent |
| `distribution_texture` | Endpoint telemetry | Cross-host | Low: repeated command/process pools, but plausible enterprise standardization |
| `weak_signal` | Bash history | One user file | Low: timestamp ordering anomaly explainable by concurrent shells |

## Realism Score by Category

- **Field format accuracy:** 8 - Zeek, Windows XML, syslog, proxy, ASA, and Snort formats are broadly credible.
- **Temporal patterns:** 8 - Most lifecycle and sensor timings are coherent; no hard visible ordering failure found.
- **Cross-source correlation:** 9 - SSH/SCP, web scanning, proxy, and Windows activity correlate well.
- **Behavioral realism:** 8 - Admin work, user browsing, perimeter scans, Kerberos, and service traffic are believable.
- **Environmental consistency:** 7 - Host roles and source mix fit, but the collection profile has one notable inconsistency.

## Recommendations

If this were synthetic, I would improve realism by making the log-clear collection semantics explicit or rendering Security record numbering in a way that matches the chosen collection model. I would also align `COLLECTION_PROFILE.json` with actual delivered files, and add more host-specific variation to repeated Windows maintenance commands and Linux admin command histories.
