# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 48

## Executive Summary

The six-hour corpus is operationally coherent and unusually strong at supporting real threat-hunting pivots; I found no impossible visible ordering in the principal attack chain. Its main synthetic signals are environmental rather than causal: overlapping duplicate RDP sessions, high and narrowly concentrated interactive SSH volume, and generic health-check jobs aimed at semantically unrelated destinations.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` Two `mstsc.exe /v:WS-AJOHNSON-01` processes start from `WS-DRAMIREZ-01` as `aisha.johnson` only 34.2 seconds apart, using distinct source ports. Their Zeek sessions overlap for roughly 26 minutes, while the target creates separate `winlogon.exe`/`userinit.exe`/`explorer.exe` chains. This is possible under some server configurations but unusual for a workstation target and resembles session stacking rather than reconnect behavior (`WS-DRAMIREZ-01.../ecar.json:462,467,472,477`; `zeek-core/conn.json`, UIDs `CUr8D7YqtkIthrfIjh` and `CAOmeQrhy87LXzQpxML`).
- `[distribution_texture]` The corpus contains 136 successful SSH authentications across six Linux servers in six hours. Of these, 127 belong to only three people—`marcus.chen` 50, `aisha.johnson` 45, and `lina.nguyen` 32—and endpoint telemetry contains 122 SSH client process creations. The volume is possible during an operations event, but unusually interactive and concentrated for this small environment.
- `[environment_or_collection_plausibility]` A root-owned `/opt/meridian/bin/proxy_healthcheck.py` runs 43 times on exactly two servers—28 on `APP-INT-01` and 15 on `MAIL-CLIN-01`—against a broad pool including `registry.npmjs.org`, `px.ads.linkedin.com`, `tracking.pollfish.io`, and assorted analytics/widget domains. Nine checks target `registry.npmjs.org`; the combination of generic process identity, unrelated destinations, and cross-role deployment looks pool-driven (`MAIL-CLIN-01.../ecar.json:17,45,124,187`; corresponding `APP-INT-01.../ecar.json` records).
- `[weak_signal]` Several Linux histories share a compact administrative vocabulary—`journalctl`, `tail`, `ss`, `systemctl`, `grep`, `ls`—across different people and hosts. Commands are varied and timestamped, so this is only supportive texture, not an independent authenticity defect.

## Evidence For Real

- The corpus has credible scale and source mix: 18 endpoint directories spanning nine Windows and nine Linux-like hosts, 24,868 eCAR records, 17,872 Windows Security/Sysmon events, 11,472 Zeek connections, 2,800 DNS records, 4,550 syslog lines, 11,799 firewall messages, and 186 IDS alerts.
- The malicious lifecycle is technically coherent. Credential access on `WS-AJOHNSON-01` creates PID 7128 at 15:45:19Z, opens LSASS at 15:45:31Z, creates a remote thread, and terminates afterward (`WS-AJOHNSON-01.../ecar.json:1010,1019,1021-1023`).
- The 16:00Z PsExec pivot is ordered correctly: Zeek observes SMB from `10.10.1.35:55765` at 16:00:02.542Z; the DC records the dropped service binary and service creation at 16:00:04Z, `PSEXESVC.exe` at 16:00:07Z, and its child command at 16:00:08Z (`DC-01.../ecar.json:3808-3820`).
- Persistence and privilege changes are source-native and coherent: creation of `svc_mhsync`, addition to Domain Admins, `DeviceSyncSvc`, an hourly scheduled task, service execution, and later account deletion all retain plausible parent/process ownership (`DC-01.../ecar.json:3976-4305,5928-5935`).
- Data staging has strong causal evidence. A 313,527,225-byte SMB ZIP is transferred from `FILE-SRV-01` to `WS-AJOHNSON-01`, with 32,721 missing observed bytes rather than perfect extraction (`zeek-core/files.json:312`). Chrome reads the resulting file immediately before a 314,782,951-byte proxy POST at 17:25:07Z (`WS-AJOHNSON-01.../ecar.json`; `PROXY-01.../proxy_access.log:1599-1600`).
- The database branch is similarly convincing: `mysqldump` creates `/tmp/rpt_0318.sql`, `gzip` creates the compressed object, and `scp` reads that same object before connecting from `10.10.4.10:34696` to `10.10.2.30:22` (`DB-PROD-01.../ecar.json:594-639`).
- Network noise has a believable mixture of successful, unanswered, rejected, and reset traffic: 9,823 `SF`, 1,244 `S0`, 174 `RSTO`, 102 `RSTR`, 59 `REJ`, and smaller `S1`/`S2`/`S3`/`OTH` populations.
- A 247-query TXT tunnel from `10.10.2.30` lasts 899.2 seconds with jitter, intermittent gaps, and mixed `NOERROR`, `NXDOMAIN`, `REFUSED`, and `SERVFAIL` outcomes, rather than an exact fixed-rate loop (`zeek-core/dns.json:1372 onward`).

## Detailed Analysis

### Scope and orientation

The visible interval is approximately 2024-03-18 12:00:01Z through 17:59:58Z across four internal segments (`10.10.1.0/24` through `10.10.4.0/24`). Sources include Windows Security, Sysmon, Linux syslog and bash history, eCAR endpoint telemetry, Zeek at core and DMZ sensors, proxy and web access logs, Cisco ASA, and two Snort sensors.

Volume varies credibly by role. `DC-01` contributes 7,559 Security events and 6,099 eCAR rows, while ordinary endpoints are substantially quieter. The public web host receives both high-volume recurring clients and a long tail of one-off Internet sources; internal DNS, Kerberos, SMB, proxy, SSH, DHCP, NTP, and application traffic coexist with the attack.

### Hunt reconstruction and pivot feasibility

The strongest chain begins with the RDP activity from `WS-DRAMIREZ-01` to `WS-AJOHNSON-01`, followed by credential dumping from a PowerShell-owned masquerading executable. The LSASS access and remote-thread records share PID 7128 and a stable process UUID.

Roughly fifteen minutes later, the same workstation address opens SMB to `DC-01`. Transport evidence precedes logon, service installation, `PSEXESVC.exe`, and its child command. Subsequent WMI-owned commands create `svc_mhsync`, elevate it, install `DeviceSyncSvc`, and create scheduled persistence.

The service begins executing at 16:31:41Z. `APP-INT-01` then produces a 247-query TXT tunnel between 16:44:42Z and 16:59:41Z. At 17:01Z, `svc_mhsync` on `FILE-SRV-01` enumerates shares and creates `cache_7f3a.zip`; the archive is copied to `WS-AJOHNSON-01`, read by Chrome, and uploaded through the explicit proxy. Separately, a root SSH session on `DB-PROD-01` dumps selected healthcare tables and stages the compressed result to `APP-INT-01`.

Cleanup is also ordered: an encoded PowerShell request appears on the DC at 17:41:59Z, `wevtutil cl Security` runs at 17:42:12Z, and `svc_mhsync` is deleted at 17:49:38Z. I found no dependent event whose same-identity initiator appears later in the visible window.

### Signal-to-noise and behavioral texture

The malicious events remain a minority within tens of thousands of endpoint and network records. Scheduled jobs, software updates, mail traffic, proxy use, service checks, Internet scanning, failed authentication, DHCP, NTP, DNS, and ordinary user applications make pivots necessary.

The main weakness is that human remote administration is disproportionately common: 136 successful SSH authentications across six servers, with 93% assigned to three users. Likewise, the duplicate concurrent RDP sessions create two full target-side interactive process trees. Neither is strictly impossible, but both make the environment feel assembled from repeated activity templates.

The health-check process is the clearest role-distribution concern. A production application or mail monitor should normally test a stable, service-owned allowlist. Repeatedly selecting unrelated ad-tech, package, analytics, and widget destinations under the same root-owned executable looks less like an operational monitoring policy.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `environment_or_collection_plausibility` | eCAR, Zeek RDP | Two overlapping sessions | Same user/client/target creates two long-lived connections and two target interactive trees within 34 seconds. |
| `distribution_texture` | Syslog, bash history, eCAR | Dataset-wide Linux administration | 136 accepted SSH sessions; 127 concentrated in three users, with 122 matching client launches. |
| `environment_or_collection_plausibility` | Linux eCAR, proxy/network | 43 executions on two hosts | Generic health-check code probes a semantically broad destination pool unrelated to host role. |
| `weak_signal` | Bash history | Repeated across several hosts/users | Administrative command vocabulary has some shared template texture, although timing and parameters vary. |

## Realism Score by Category

- **Field format accuracy:** 8 — The reviewed endpoint, authentication, process, file, proxy, and Zeek fields are usable and internally plausible.
- **Temporal patterns:** 8 — Attack prerequisites and effects are correctly ordered; regularity concerns are distributional rather than impossible.
- **Cross-source correlation:** 9 — Authentication, process, file, flow, proxy, and network pivots preserve identities and timing well.
- **Behavioral realism:** 6 — The attack works technically, but SSH concentration and duplicate RDP sessions reduce organic texture.
- **Environmental consistency:** 6 — Host roles are broadly credible, while generic health-check destination selection is difficult to justify operationally.

## Recommendations

- If this were synthetic, make RDP behavior session-aware. A reconnect to the same workstation and user should normally reuse or replace the existing session; create a second `winlogon`/`userinit`/`explorer` tree only when the target role and session policy explicitly permit parallel sessions.
- Bind health-check definitions to host role and deployed service. Use stable purpose-specific target sets and cadences instead of sampling unrelated analytics, advertising, package-registry, and widget destinations under one generic root-owned script.
- Reduce the proportion of routine Linux administration performed through fresh human SSH sessions. Reuse sessions where appropriate and shift recurring operations toward named automation accounts, bastions, configuration-management tooling, and role-specific administrator populations.
- Preserve the existing causal strengths: transport-before-auth ordering, process/file ownership, imperfect file observation, lifecycle termination, and proxy/Zeek/firewall agreement materially improve huntability and realism.
