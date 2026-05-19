# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 62

## Executive Summary

The dataset is highly realistic and contains many source-native relationships that hold up under scrutiny: Windows logon/process lifecycles, Sysmon ProcessGuid behavior, Zeek UID ordering, Linux syslog SSH/session formatting, and endpoint/network timing are mostly coherent. I assess it as synthetic with moderate confidence because a few endpoint artifacts look generated rather than collected, especially Windows SearchProtocolHost SID values, repeated ultra-short EDR process lifetimes, and missing PE metadata for common signed updaters.

## Evidence For Synthetic

- `WS-DRAMIREZ-01.meridianhcs.local/windows_event_sysmon.xml:668` records `SearchProtocolHost.exe ... S-1-5-21-237987055-511746570-747675673-3051`; similar generated-looking SIDs appear in `WS-AJOHNSON-01`, `WS-MCHEN-01`, and `WS-PPATEL-01`. These SIDs do not align with the observed domain SID base `S-1-5-21-1524654518-2022274387-1755902678-*`.
- `DB-PROD-01.meridianhcs.local/ecar.json:413-414` records `cat /etc/mysql/my.cnf` create and terminate 1 ms apart. Similar exact 1-4 ms lifetimes appear for `ls -lh` in `PROXY-01` and `cat /etc/resolv.conf` in `APP-INT-01`.
- Sysmon Event ID 1 often has all PE metadata fields set to `-` for common signed third-party binaries, including `AdobeARMservice.exe`, `ZoomUpdate.exe`, `DropboxUpdate.exe`, `GoogleUpdater.exe`, and `dcu-cli.exe`; 181 process-create events had all five metadata fields blank.
- Several workstation/user behaviors have an exercise-like regularity: many bash histories have median command gaps around 70-95 seconds for hours, with broad but tidy administrative command coverage across hosts.

## Evidence For Real

- No visible logoff-before-logon, terminate-before-create, or Zeek dependent-log-before-connection ordering contradictions were found inside the collection window.
- The DC compromise chain is internally plausible: `wevtutil cl Security` appears in DC Security logs, followed by Event ID `1102` at `2024-03-18T17:41:42.8093377Z`.
- Windows Sysmon ProcessGuid timing/structure is coherent, and process/network/registry relationships are generally source-native.
- Linux syslog formatting is strong: RFC5424-style records, correct-looking authpriv priorities, SSH accepted/open/closed pairs, sudo `COMMAND=` fields, cron/anacron, systemd, NetworkManager, and journald noise.
- Zeek logs look structurally credible: `conn`, `dns`, `ssl`, `x509`, `files`, `http`, and `ocsp` fields use plausible UID/FUID relationships and no obvious impossible byte/duration values.

## Detailed Analysis

The Windows telemetry is the strongest part of the corpus. Security and Sysmon event IDs, versions, providers, process IDs, logon IDs, and the DC log-clear sequence mostly behave like real Windows telemetry. The Event ID `1102` is correctly represented under `UserData`, not simple `EventData`, which is a good source-native detail.

The main Windows concern is SID realism. SearchProtocolHost command lines contain `S-1-5-21-*` values that appear syntactically valid but environmentally disconnected from the domain SID base used everywhere else. Local profile SIDs can exist, so this is not a hard contradiction, but the values look randomly generated and appear only in the SearchProtocolHost pipe context.

The Linux endpoint layer is also mostly convincing. SSH sessions, sudo lines, bash histories, and EDR process records line up in realistic ways. The weakest area is EDR timing: multiple short-lived commands terminate within 1-4 ms. Some simple commands can be that fast, but the repeated exactness across hosts reads more like deterministic rendering than sensor-captured process lifetime.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, syslog, Zeek, ASA, and web/proxy formats are mostly source-native, with SID and PE metadata concerns.
- **Temporal patterns:** 7 — No impossible visible ordering found, but repeated ultra-short process lifetimes and tidy user cadence reduce confidence.
- **Cross-source correlation:** 9 — Endpoint, Zeek, proxy, firewall, and web relationships are coherent without obvious contradictions.
- **Behavioral realism:** 7 — Admin, user, service, and attack behaviors are plausible but somewhat staged and evenly distributed.
- **Environmental consistency:** 8 — Host roles, IPs, SIDs, names, and services mostly agree; SearchProtocolHost SIDs are the main inconsistency.

## Recommendations

If synthetic, improve profile SID modeling for Windows Search/Indexing artifacts, populate PE metadata for common signed third-party binaries, and add more natural variance to EDR process lifetime timing. Preserve the strong source-native ordering and Windows/Linux/network correlation, because those are already convincing.
