# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

This is a high-quality dataset with a coherent intrusion storyline, realistic background noise, and strong source-native formatting across host, network, proxy, firewall, and web logs. My synthetic verdict rests mainly on duplicated Zeek sensor metrics and a few overly curated narrative patterns that feel generated rather than independently observed in a messy enterprise.

## Evidence For Synthetic

- `zeek-core/conn.json` and `zeek-dmz/conn.json` show many overlapping flows with different Zeek UIDs but exactly identical durations, byte counts, packet counts, states, and histories. Example: at `2024-03-18T17:25:26Z`, core UID `CGRyBGplf7ZyjH5hus` and DMZ UID `CFxsbEsHoNi6yJAbOj` both record `10.10.1.35:52188 -> 10.10.3.20:8080`, `duration=10.062652`, `orig_bytes=314783568`, `resp_bytes=2121`, `history=ShADadfFa`.
- This duplication is not isolated: 1,343 of 1,479 overlapping core/DMZ flows I matched had exactly identical connection metrics. Real independent sensors can align closely, but exact equality at this scale and precision suggests one canonical flow rendered twice.
- The attack path is unusually instructional: `net user /domain` and `net group "Domain Admins" /domain` on `WS-AJOHNSON-01` at `15:20`, PsExec to `DC-01` at `16:00`, domain admin creation at `16:14-16:15`, persistence at `16:20`, staged file compression at `17:01`, exfil at `17:25`, encoded PowerShell at `17:41`, and cleanup at `17:49`.
- `DC-01.meridianhcs.local/windows_event_security.xml` retains pre-clear Security events, then shows `wevtutil cl Security` at `17:41:41.921Z` and Event ID `1102` at `17:41:42.809Z` with `EventRecordID=3`. This is plausible for SIEM-retained telemetry, but suspicious if interpreted as a single local channel export.
- Some human-behavior details feel deliberately seeded: typos like `taiil` and `uilmit`, repeated admin commands across users and hosts, and very cleanly named artifacts such as `svc_mhsync`, `DeviceSyncSvc`, and `/upload/telemetry/7f3a2b19`.

## Evidence For Real

- The environment scope is internally consistent: workstations in `10.10.1.0/24`, core services in `10.10.2.0/24`, DMZ services in `10.10.3.0/24`, and DB in `10.10.4.0/24`.
- The source mix is realistic: Windows Security/Sysmon, eCAR, Linux syslog, bash history, Zeek core/DMZ, Cisco ASA, Snort, proxy access logs, and web access logs.
- The intrusion chain has plausible pivots and data flow. At `17:24:32Z`, `10.10.1.35` pulls `314272438` bytes from `FILE-SRV-01` over SMB; at `17:25:26Z`, the proxy logs a POST from `10.10.1.35` to `api.westbridge-services.net/upload/telemetry/7f3a2b19` with `314782795` client bytes.
- Windows artifacts are convincing: `4697` service install for `PSEXESVC`, Sysmon file creation for `C:\Windows\PSEXESVC.exe`, `4720` account creation for `svc_mhsync`, `4728` Domain Admins membership, and `4688` process creation entries all line up.
- Background noise is strong: DHCP renewals, Windows Update, Ubuntu apt traffic, public web scans, UFW blocks, Snort alerts, proxy failures, OCSP/X.509, syslog session churn, and web crawler/scanner traffic.

## Detailed Analysis

The dataset covers mainly `2024-03-18T12:00:00Z` through `18:00:00Z`, with some Linux/eCAR session teardown extending later. I identified about 15 hosts, including `DC-01` (`10.10.2.10`), `FILE-SRV-01` (`10.10.2.20`), `APP-INT-01` (`10.10.2.30`), `WEB-EXT-01` (`10.10.3.10`), `PROXY-01` (`10.10.3.20`), `DB-PROD-01` (`10.10.4.10`), and multiple user workstations.

The attack narrative centers on `aisha.johnson` / `WS-AJOHNSON-01` (`10.10.1.35`). At `15:20:33Z` and `15:20:35Z`, `WS-AJOHNSON-01` runs `net user /domain` and `net group "Domain Admins" /domain`. At `16:00:11Z`, `DC-01` records a type 3 logon for `aisha.johnson` from `10.10.1.35`; at `16:00:12Z`, `PSEXESVC` is installed, and at `16:00:15Z`, `cmd.exe /c whoami && hostname` runs under `C:\Windows\PSEXESVC.exe`.

Privilege escalation and persistence are cleanly represented. `DC-01` shows `net user svc_mhsync MhsSvc!2024 /add /domain` at `16:14:57Z`, Event ID `4720` for `svc_mhsync` at `16:14:58Z`, `net group "Domain Admins" svc_mhsync /add /domain` at `16:15:00Z`, and Event ID `4728` at `16:15:03Z`. At `16:20`, `sc.exe` creates `DeviceSyncSvc`, and `schtasks.exe` creates `\Microsoft\Windows\Maintenance\DeviceSync`.

The exfiltration path is especially coherent. `FILE-SRV-01` records `svc_mhsync` running PowerShell `Compress-Archive` over `\\FILE-SRV-01\Finance\Q1\*` and `\\FILE-SRV-01\Patients\Exports\*` to `C:\ProgramData\Microsoft\cache_7f3a.zip` at `17:01:21Z`. Zeek then shows a large SMB transfer from `FILE-SRV-01` to `10.10.1.35` at `17:24:32Z`, followed by proxy upload to `api.westbridge-services.net` at `17:25:26Z`.

There is also a Linux/DB staging thread: `DB-PROD-01` root bash history shows `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql` at `17:14:42Z`, `gzip` at `17:15:05Z`, and `scp` to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz` at `17:20:35Z`. eCAR and Zeek SSH records support this sequence.

The strongest authenticity weakness is not the completeness of these correlations, but the exact duplicated Zeek observations across sensors. Independent `zeek-core` and `zeek-dmz` UIDs with identical timing, bytes, packets, and history for hundreds of overlapping flows look more like deterministic rendering than two independent packet-observation points.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Zeek, ASA, proxy, syslog, and web fields are mostly source-native and detailed.
- **Temporal patterns:** 8 — Activity has plausible jitter and density, though the windowing and duplicated Zeek timings are clean.
- **Cross-source correlation:** 8 — Correlations are excellent, but exact duplicate sensor metrics reduce authenticity.
- **Behavioral realism:** 7 — The kill chain is plausible, but a bit too narratively complete and tidy.
- **Environmental consistency:** 8 — Host/IP/user topology is stable with convincing operational background noise.

## Recommendations

- Add independent observation variance between `zeek-core` and `zeek-dmz`: timestamps, durations, packet counts, byte counts, missed bytes, and histories should diverge slightly where two sensors see the same flow.
- Make attack execution messier: failed commands, delayed retries, partial staging, unrelated admin activity during the incident, and less semantically obvious artifact names.
- Clarify or model Security log clearing behavior: if output represents SIEM collection, keep the pre-clear/post-clear merge; if it represents local export, avoid retaining pre-clear events in the same channel file.
- Vary proxy identity and authentication behavior if the environment uses an authenticated secure web gateway; all `cs-username=-` is plausible for transparent mode but thin for enterprise proxy telemetry.
- Keep the strong causal chain, but introduce more long-tail operational entropy around it so the dataset feels less like a perfectly recoverable exercise trail.
