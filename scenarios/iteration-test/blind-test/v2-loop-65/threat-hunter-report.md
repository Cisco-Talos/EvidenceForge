# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 93
**Synthetic-Confidence Score:** 86

## Executive Summary

The corpus is unusually strong in source-native formatting, baseline volume, role-consistent activity, and cross-source pivots. Nevertheless, two high-specificity defects—a Windows process using an RDP Logon ID before that Logon ID is created, and an Nmap packet pattern that cannot be produced by the recorded command under the observed discovery results—outweigh the otherwise production-like texture; a separate PsExec transport/authentication gap and capped shell-command reuse reinforce a synthetic verdict.

## Evidence For Synthetic

- `[hard_contradiction]` On `WS-AJOHNSON-01`, Security Event 4688 records `powershell.exe` at `2024-03-18T15:20:24.3753616Z` and `whoami.exe /all` at `15:20:24.3774950Z`, both under `SubjectLogonId=0x27015bf`. Security Event 4624 does not create that same Logon ID as a Type 10 RDP session until `15:20:25.3832180Z` (record IDs 130782, 130783, then 130784). Sysmon independently places the processes at `UtcTime` `15:20:24.167` and `15:20:24.186`, while eCAR places their creates at `15:20:24.285` and `15:20:24.305` and the session login at `15:20:25.365`. This is a cross-source causal inversion, not a timestamp-format artifact.
- `[hard_contradiction]` `WEB-EXT-01` launches `nmap -sn 10.10.2.0/24` at `13:40:13.573Z`; Zeek core sees 253 ICMP targets, with only 9 `SF` responses and 244 `S0` non-responses. At `13:40:28.696Z`, the next visible command is `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`, without `-Pn`, yet `zeek-core/conn.json` contains exactly 1,270 TCP attempts: all 254 usable addresses multiplied by all five ports. Of those, 1,244 are `S0`, only 7 are `SF`, 16 are `REJ`, 2 are `RSTR`, and 1 is `RSTO`. Default Nmap host discovery would not proceed to a complete five-port connect scan of the hundreds of hosts that did not answer discovery; the trace looks like a generator expanding a CIDR/port Cartesian product rather than executing the recorded command.
- `[contract_gap]` The PsExec sequence on `DC-01` creates a Type 3 logon for `aisha.johnson` at `15:59:31.6916786Z`, with `IpAddress=10.10.1.35`, `IpPort=55861`, and `TargetLogonId=0x5552da6`. No endpoint or Zeek flow uses source port 55861. The first visible related transports arrive much later: SMB `10.10.1.35:60482 -> 10.10.2.10:445` at approximately `15:59:39.996Z` and RPC `:60483 -> :135` at `15:59:40.596Z`; target Sysmon records them at `15:59:40.132Z` and `15:59:40.731Z`. Event 4697 then installs `PSEXESVC` under Logon ID `0x5552da6` at `15:59:41.3189819Z`. A dropped preliminary connection is possible, but the visible authentication predates the only correlated transport by more than eight seconds and names a tuple absent from every network view.
- `[distribution_texture]` Across 346 Bash-history commands, there are 245 distinct command strings with an exact occurrence histogram of 159 singletons, 71 doubles, and 15 triples—no command appears four or more times. Fourteen commands occur in exactly three separate histories, including the long literal `journalctl -u systemd-resolved --since today --no-pager | tail -20` and `udevadm info --query=property --name=/dev/null | head`. A hard ceiling of three across repeated administrators and hosts is more consistent with capped sampling from a command pool than an organic shell-history frequency tail.
- `[weak_signal]` `WEB-EXT-01/syslog.log` contains 821 UFW blocks but only 12 external source IPs; 769 records (93.7%) come from five addresses, and every major source has one invariant packet length and TTL. Repeated scanners can legitimately retain stable fingerprints, so this did not drive the verdict, but the very small address pool adds to the templated baseline texture.

## Evidence For Real

- The dataset has substantial and role-appropriate volume: 125,690 logical records over approximately six hours, including 34,649 Zeek records, 33,682 eCAR records, 19,763 ASA messages, 18,270 Windows Security events, 11,546 Sysmon events, 3,777 Linux syslog records, and smaller proxy, web, Snort, and shell-history sources across 21 hosts.
- Zeek connection behavior has a credible long tail rather than a single clean pattern: 14,967 `SF`, 4,668 `S0`, 271 `RSTO`, 177 `RSTR`, 51 `REJ`, 48 `OTH`, and smaller `S1`/`S2`/`S3` populations. Durations range from sub-second traffic to 13,342 seconds, 78 history strings occur, and nonzero `missed_bytes` appears in a varied minority of records. I found no `S0` row with response payload, no TCP `SF` row missing duration, and no payload-byte count exceeding IP-byte count.
- Independent Zeek vantage points behave like separate sensors: 4,328 core/DMZ five-tuple overlaps use different UIDs and have a stable mean clock offset of about 114 ms with roughly 3 ms standard deviation; 454 overlaps have differing packet/byte observations. Core/DB overlaps show a different offset (about -62 ms) and some observation divergence. This looks more like distinct clocks and capture loss than duplicated files.
- Lifecycle quality is strong outside the cited RDP defect. Among visible eCAR data, 1,762 process identities have both create and terminate events and 499 sessions have both login and logout events; no paired termination/logoff precedes its visible start. Sysmon process creation, parentage, and termination checks likewise found no terminate-before-create or parent-created-after-child cases, while unpaired boundary events occur naturally at both ends of the six-hour slice.
- Host behavior generally matches infrastructure roles: domain controllers dominate Kerberos, LDAP, and Security auditing; file servers carry SMB; the proxy separates client CONNECT requests from proxy-to-origin TLS; mail hosts show Postfix/SMTP relays; `DB-PROD-01` carries MySQL; and the public web host receives UFW/ASA scan noise. DHCP REQUEST/ACK renewals use several lease lengths with jitter around renewal points rather than one fixed cadence.
- Several attack pivots are technically coherent. At `17:14:53.900Z`, `APP-INT-01` starts `ssh -A root@DB-PROD-01`; the TCP/22 flow, target SSH login, shell, `mysqldump`, `/tmp/rpt_0318.sql`, gzip, reverse SCP, and subsequent SMB write to `FILE-LNX-01` preserve host, account, file, and timing relationships. Likewise, the credential-dump process on `WS-AJOHNSON-01` is accompanied by Sysmon process-access/remote-thread evidence against LSASS.
- `DC-01` Security log clearing is represented credibly: `wevtutil cl Security` is followed by Event 1102 at `17:42:20.7762494Z`, after which `EventRecordID` restarts at 1. That is the kind of source-local state transition often omitted from simplistic log fabrication.

## Detailed Analysis

### Scope and collection profile

The visible interval is approximately `2024-03-18 12:00:01Z` through `17:59:54Z`. The 21 named endpoints occupy workstation (`10.10.1.0/24`), server (`10.10.2.0/24`), DMZ (`10.10.3.0/24`), and database (`10.10.4.0/24`) segments. Available sources include endpoint eCAR on all hosts; Windows Security and Sysmon on ten Windows systems; RFC 5424-style syslog and Bash histories on Linux systems; three Zeek vantage points; Cisco ASA, proxy, web, Snort, SMTP, SMB, DHCP, TLS/X.509, and file metadata.

The mix is not suspicious merely because it is broad. Volumes vary substantially by role: eCAR ranges from 258 records on `LT-MRIVERA-02` to 5,444 on `DC-01`, 4,666 on `PROXY-01`, and 3,974 on `WEB-EXT-01`. Per-minute volumes are bursty: the Nmap interval drives a pronounced `13:40` spike, proxy/web/Snort have many empty minutes, and Windows audit streams remain steadier. This is preferable to flat per-host generation.

### Threat-hunting pivots and tradecraft

The principal Windows chain begins with RDP from `LT-MRIVERA-02` (`10.10.1.99:58332`) to `WS-AJOHNSON-01` (`10.10.1.35:3389`). Zeek observes the flow at about `15:20:19.759Z`, the target eCAR flow follows near `15:20:19.944Z`, and the Type 10 logon is recorded around `15:20:25.365Z`. The transport-before-authentication ordering is sound. The defect is inside the endpoint session: PowerShell PID 6772 and child `whoami.exe` PID 6776 already claim the future Logon ID and execute before the 4624, before `userinit.exe`, and before `explorer.exe`. Because the Security channel itself assigns sequential record IDs in that inverted order, normal sensor clock skew is not a satisfactory explanation.

At `15:44:29.833Z`, `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` starts under `aisha.johnson`. Sysmon/eCAR then record high-access opens of LSASS and a remote thread at roughly `15:44:33Z`, followed by process termination. Those events have credible process IDs, parentage, and account context.

The next pivot reaches `DC-01`: Type 3 logon `0x5552da6`, SMB/RPC, a dropped `PSEXESVC.exe`, Event 4697, service execution, and `cmd.exe /c whoami && hostname`. Most of that chain is coherent, but the logon/transport tuple and timing gap described above prevents a clean network-to-auth pivot. Later actions create `svc_dirsync` (`16:15:16Z` onward), add it to Domain Admins, install `DeviceSyncSvc`, register an hourly scheduled task, and start the service. Proxy records then show jittered CONNECT activity to `api.westbridge-services.net`; the intervals are variable rather than mechanically fixed. At `17:42`, encoded PowerShell reaches the same infrastructure, `wevtutil` clears Security, and the account is deleted at `17:50:13Z`.

Data staging on `WS-AJOHNSON-01` is visible as `Compress-Archive` at `17:01:11.933Z`, creation of `C:\ProgramData\Microsoft\cache_7f3a.zip` at `17:01:15.603Z`, and a Curl upload through `10.10.3.20:8080` beginning at `17:25:04.909Z`; the file read occurs at `17:25:08.018Z` and the proxy flow at `17:25:09.497Z`. Separately, `APP-INT-01` emits 276 TXT queries to subdomains of `ns1.westbridge-services.cloud` from `16:45:12.987Z` through `16:59:45.494Z`. Query gaps are not uniform (median about 2.016 seconds, maximum about 52.5 seconds), and response codes include `NOERROR`, `NXDOMAIN`, `REFUSED`, and `SERVFAIL`, which is behaviorally credible for a noisy DNS channel.

The Linux/DB chain also works operationally. `APP-INT-01` initiates SSH to `DB-PROD-01`; the database host creates `/tmp/rpt_0318.sql` from `mysqldump --single-transaction ehr patients insurance_claims` at `17:15:27.035Z`, creates the gzip at `17:15:50.516Z`, and starts SCP back to `APP-INT-01` at `17:16:08.022Z`. The receiver creates `/tmp/.cache/rpt_0318.sql.gz` at `17:16:35.704Z`; `smbclient` then reads it and `FILE-LNX-01` writes the same filename to `ClinicalResearch/Integration/DB-Staging` at `17:18:38.766Z`. These are useful, technically feasible pivots rather than isolated indicators.

### Network and protocol realism

Across 20,259 Zeek connections, TCP, UDP, and ICMP populations are substantial, and service identification includes DNS, HTTP, TLS, Kerberos, LDAP, MySQL, SMB, syslog, SSH, DHCP, SMTP, RDP, and DCE/RPC. Protocol child records resolve to a same-sensor parent UID and fall within the parent connection interval in the DNS, HTTP, TLS, SMTP, and SMB samples checked. ASA connection IDs pair 7,502 teardowns with builds, with two visible builds left open at the boundary; duration calculations agree with timestamps within the format's one-second precision.

The Nmap sequence is the exception. A real full `254 x 5` attempt matrix is possible when discovery is disabled, but the logged command does not contain `-Pn`. Nor can “all hosts were up” explain it: the immediately preceding discovery and the resulting TCP states show that the overwhelming majority supplied no response. This is the strongest generator-like expansion pattern in the corpus.

### Endpoint, authentication, and lifecycle realism

Windows audit fields are generally source-appropriate: hexadecimal process and logon IDs, Type 2/3/10 sessions, domain/user SIDs, Kerberos ticket activity on the DCs, 4688/4689 pairing, service and task events, and IPv4-mapped remote addresses. Sysmon `UtcTime` normally precedes XML `TimeCreated` by small, variable collection delays. eCAR uses durable object and actor identifiers consistently; checks of dependent events found no actor created after its dependent event and no PID/image metadata conflicts.

The RDP inversion is therefore conspicuous precisely because the surrounding lifecycle work is good. A delayed 4624 write is the closest real-world alternative explanation, but the same ordering is encoded in eCAR's event times, and the first anomalous PowerShell is parented to `services.exe` rather than the later `userinit.exe`/Explorer tree. The PsExec gap is less absolute—a preliminary connection could have been dropped—so I weighted it as a contract gap instead of another hard contradiction.

Linux syslog includes failed sudo attempts, PAM open/close pairs, systemd-logind sessions, unattended upgrades, snapd, IRQ balancing, log rotation, cron, and UFW scanning. Source PIDs and session identifiers usually remain coherent. Bash history uses valid epoch-marker formatting, and explicit history clearing on `APP-INT-01` at `17:41:27.615Z` explains the empty root history there. The concern is the fleet-wide exact-command frequency ceiling, not the presence or absence of any one command.

### Assessment balance

If only the volume, schemas, host roles, and most cross-source relationships were considered, I would place the corpus in the “mostly realistic” range. The RDP Logon ID inversion and Nmap command/packet contradiction are different defect classes on different platforms, however, and both are anchored in source-visible timestamps and fields. Their independence makes an accidental production explanation unlikely enough to support a high-confidence synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `hard_contradiction` | Windows Security, Sysmon, eCAR | One successful RDP session on `WS-AJOHNSON-01` | Two processes use Logon ID `0x27015bf` before the Type 10 4624 creates it; the inversion is preserved across three views. |
| `hard_contradiction` | eCAR, Zeek core/DMZ | One `/24` Nmap scan from `WEB-EXT-01` | The command omits `-Pn`, but traffic is an exact 254-host by five-port matrix despite discovery showing only nine responsive hosts. |
| `contract_gap` | Windows Security, Sysmon, eCAR, Zeek | PsExec movement from `WS-AJOHNSON-01` to `DC-01` | The Type 3 logon predates visible SMB/RPC transport by more than eight seconds; its source port never appears in any network source. |
| `distribution_texture` | Bash histories | 346 commands across Linux hosts/users | Exact command reuse has a hard observed maximum of three, with multiple long literals repeated exactly three times and no heavier frequency tail. |
| `weak_signal` | Linux UFW / perimeter traffic | 821 blocked probes on `WEB-EXT-01` | Only 12 sources appear and five generate 93.7% of rows; plausible for recurring scanners, but low-diversity for the volume. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Zeek JSON, ASA, proxy, web, and RFC 5424-like syslog fields are largely source-native and internally well-typed.
- **Temporal patterns:** 6 — Most background and attack timing is varied and lifecycle-aware, but the RDP authentication inversion is a high-impact causal failure.
- **Cross-source correlation:** 8 — Network, endpoint, auth, file, proxy, and protocol pivots usually line up; the PsExec transport/auth gap is the main exception.
- **Behavioral realism:** 7 — Most tradecraft and baseline actions are technically plausible, while the Nmap command cannot explain its full-grid traffic.
- **Environmental consistency:** 8 — Source volumes and services generally match host roles and network zones, with only modest command-pool and perimeter-noise texture concerns.

## Recommendations

- If this were synthetic, enforce a session-creation invariant: no process, module, file, registry, or network event may reference a non-system Logon ID before the corresponding successful login. For RDP, emit transport, 4624/session login, `userinit.exe`, Explorer, and user activity in causal order, and regression-test that ordering in Security, Sysmon, and eCAR views.
- If this were synthetic, make network expansion obey tool semantics. A full Nmap host/port product should require `-Pn`; otherwise, model discovery first and port-scan only responsive hosts. Preserve response-dependent timing and state rather than expanding every CIDR address uniformly.
- If this were synthetic, bind Windows remote-administration authentication to the actual transport tuple. The source-port and TCP/RPC timing used by 4624, endpoint FLOW, Zeek, 4648/caller context, and service installation should describe one feasible session, with observation drops applied coherently if a source is intentionally missing.
- If this were synthetic, replace capped shell-command sampling with per-user, heavy-tailed repetition. Administrators should sometimes repeat ordinary commands more than three times, while long runbook commands should cluster by operator, host role, and troubleshooting episode rather than landing at a fleet-wide frequency ceiling.
- If this were synthetic, broaden perimeter-noise source diversity or explicitly model a few persistent scanners plus a larger singleton long tail. Keep the credible source-specific TTL/packet fingerprints, but avoid concentrating more than 800 probes into a 12-address vocabulary unless the logs show a reason for that concentration.
