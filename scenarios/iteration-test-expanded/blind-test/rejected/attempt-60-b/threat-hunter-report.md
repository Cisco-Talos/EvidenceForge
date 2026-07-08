# Threat Hunter - Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 58
**Synthetic-Confidence Score:** 34

## Executive Summary

This dataset looks mostly production-like under cross-source pivots. I did not find hard contradictions, visible impossible ordering, generator identity leaks, or source-native field breakage; the main synthetic indicators are weak collection/profile and distribution texture concerns.

## Evidence For Synthetic

- `environment_or_collection_plausibility`: `COLLECTION_PROFILE.json` lists `mail_artifacts` formats (`email_artifacts`, `eml`), but no corresponding files are present in the directory. This is a profile/source-coverage mismatch, though not a telemetry contradiction.
- `distribution_texture`: Zeek NTP is extremely sparse: only 2 rows, both in `zeek-dmz/ntp.json`, despite a six-hour enterprise window and NTP being declared in the network sensor formats.
- `distribution_texture`: DHCP is cleanly modeled as repeated `REQUEST`/`ACK` pairs with stable lease-renew cadence and no messy edge cases. Plausible, but slightly polished.

## Evidence For Real

- PsExec/DC sequence is coherent: Zeek SMB from `10.10.1.35` to `10.10.2.10` at `16:00:09-16:00:11`, DC Security `4624` Type 3 for `aisha.johnson` at `16:00:09.782`, `PSEXESVC` file/service evidence at `16:00:11`, and process execution/termination through `16:00:38`.
- DB exfiltration chain is credible: root shell history on `DB-PROD-01`, eCAR `mysqldump`, file create, `gzip`, `scp`, Zeek SSH `10.10.4.10:46080 -> 10.10.2.30:22`, and receiver-side file creation on `APP-INT-01`.
- Zeek protocol rows passed UID consistency checks: DNS/HTTP/SSL/SMTP/DHCP/files rows had parent `conn` rows and stayed within connection intervals.
- Perimeter logs have sane lifecycle behavior: ASA built/teardown pairs had no teardown-before-build cases; unpaired sessions were boundary/long-lived cases.
- Windows and Linux source formats are generally source-native: Windows XML shapes, Sysmon process lifecycles, RFC5424 syslog, and kernel uptime deltas look plausible.

## Detailed Analysis

Available sources span Windows Security/Sysmon, Linux syslog/bash history, eCAR, Zeek core/DMZ, proxy, ASA, Snort, and web access. The collection window is `2024-03-18T12:00:00Z` to `18:00:00Z`, with endpoint tail rows allowed after the primary window.

I found a major attack-looking chain around `16:00`: `WS-AJOHNSON-01` initiated SMB/DCE-RPC activity to `DC-01`; `DC-01` logged `aisha.johnson` Type 3 logon, `PSEXESVC` service creation, `C:\Windows\PSEXESVC.exe`, and child `cmd.exe /c whoami && hostname`. Ordering across Zeek, Security, Sysmon, and eCAR is plausible.

The later DB dump path also holds together: `DB-PROD-01` root history shows `mysqldump`, `gzip`, and `scp`; eCAR records the same commands and file operations; Zeek records SSH transfer to `APP-INT-01`; `APP-INT-01` records `/tmp/.cache/rpt_0318.sql.gz` creation. I did not find a visible dependent event before its visible initiating event for the same identifier.

## Synthetic Indicator Summary

| Category | Affected Source Family | Scope | Score Impact |
|---|---|---:|---:|
| environment_or_collection_plausibility | collection profile | missing declared mail artifact files | +4 |
| distribution_texture | Zeek NTP | only 2 NTP rows | +3 |
| distribution_texture | DHCP | clean renew-only texture | +3 |
| weak_signal | baseline volume | very consistent multi-source coverage | +2 |

## Realism Score by Category

- **Field format accuracy:** 87 - Windows, Zeek, syslog, proxy, and ASA formats are mostly source-native.
- **Temporal patterns:** 78 - attack and baseline timing are plausible, with minor smoothness.
- **Cross-source correlation:** 90 - pivots across Zeek, eCAR, Security/Sysmon, syslog, and ASA hold up.
- **Behavioral realism:** 82 - tradecraft and admin noise are operationally credible.
- **Environmental consistency:** 76 - host roles and services mostly fit; collection profile/source mismatch weakens it.

## Recommendations

- Either include the declared `email_artifacts`/`eml` files or remove that source family from `COLLECTION_PROFILE.json`.
- Add more realistic NTP coverage or document why only DMZ NTP is visible.
- Add occasional DHCP edge texture such as discover/offer, missed renewals, or variable lease behavior where appropriate.
