# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 86  
**Synthetic-Confidence Score:** 76

## Executive Summary

The corpus has unusually strong temporal and cross-source coherence, including credible RDP, PsExec, SMB staging, proxy exfiltration, persistence, and Security-log clearing lifecycles. However, dataset-wide endpoint telemetry repeatedly assigns sensitive file operations and process-child relationships to implausible processes—most notably `winlogon.exe` and `lsass.exe` creating Defender history artifacts, and 61 of 65 Windows SSH clients launching directly from Explorer or Firefox—which is a strong generator-like fingerprint rather than ordinary production messiness.

## Evidence For Synthetic

- `[hard_contradiction]` Sysmon Event 11 on `FILE-SRV-01` records `C:\Windows\System32\winlogon.exe` creating `C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\36630` at `2024-03-18 16:02:14.632`, and later records `lsass.exe` creating `...\DetectionHistory\80122` at `17:16:27.420`. Neither process normally owns creation of Defender DetectionHistory records.
- `[distribution_texture]` This is not isolated noise: eCAR contains 71 Defender-history file operations and 68 `SoftwareDistribution\Download\...\update.cab` operations across all nine Windows hosts. The actors are repeatedly drawn from unrelated system processes such as `winlogon.exe`, `lsass.exe`, `csrss.exe`, `dwm.exe`, `smss.exe`, `userinit.exe`, `dns.exe`, `SearchIndexer.exe`, and `WmiPrvSE.exe`. Examples include `wininit.exe` reading an update CAB on `DC-01` at `14:08:13.620`, `dns.exe` reading one at `16:50:34.262`, and `lsass.exe` creating one at `17:47:28.910`. The repeated reuse of two path pools with broadly incompatible actors looks like randomized process/path pairing.
- `[distribution_texture]` Windows SSH parentage is strongly templated. Across eCAR, 65 `ssh.exe` process starts appear on four workstations: 58 have `explorer.exe` as direct parent, five have Firefox, and only two have `cmd.exe`. A concrete Sysmon event on `WS-AJOHNSON-01` at `12:04:21.709` shows Firefox browsing `http://WEB-EXT-01/` directly spawning `ssh.exe aisha.johnson@MAIL-CLIN-01.meridianhcs.local`. `WS-MCHEN-01` has 33 of 33 SSH clients parented directly by Explorer. Occasional shell-less launches are possible, but this cross-user distribution is not a believable dominant enterprise pattern.
- `[contract_gap]` The `16:00` PsExec-like action has excellent target-side evidence but no visible source client process on `WS-AJOHNSON-01`, despite detailed Security, Sysmon, and eCAR process coverage on that host. Zeek sees `10.10.1.35:61249 -> 10.10.2.10:445` carrying 118,966 origin bytes at `16:00:01.210`; `DC-01` then creates `PSEXESVC`, launches it, and runs `cmd.exe /c whoami && hostname`. No `PsExec`/equivalent source invocation appears in any of the three endpoint sources. Sensor loss or a renamed client is possible, so this is lower weight than the process/path defects.
- `[weak_signal]` The sole visible RDP transport from `10.10.1.99` to `WS-AJOHNSON-01` ends about `15:43:18`, while the same Type 10 session continues to originate new activity, including the credential-access process at `15:45:09` and subsequent remote administration. A disconnected RDP session can remain logged on and autonomous processes can continue, so this is not an impossible ordering, but the absence of a reconnect or alternate control channel makes the later interactive-looking activity less convincing.

## Evidence For Real

- The visible window is a bounded six-hour slice, approximately `2024-03-18 12:00:01–17:59:59 UTC`, spanning 18 endpoint/server directories. The source mix is substantial rather than attack-only: 25,792 eCAR records, 13,555 Security events, 4,610 Sysmon events, 4,195 syslog lines, 11,776 Zeek connections, 12,665 firewall records, 2,056 proxy rows, 866 web rows, DHCP, SMTP, TLS/X.509, OCSP, file, DNS, HTTP, and IDS data.
- Network texture is varied. `zeek-core/conn.json` contains 6,152 connections across DNS, HTTP, Kerberos, SMB, LDAP, SSH, DHCP, SMTP, TLS, and RDP, with `SF`, resets, rejects, partial states, and 12 `S0` sessions. The DMZ sensor has 1,161 `S0` connections among 5,624 records, consistent with exposed-host scanning rather than an unrealistically clean network.
- RDP initiation is well ordered. Zeek records `10.10.1.99:53772 -> 10.10.1.35:3389` at `15:19:46.813`; endpoint eCAR records the inbound flow at `15:19:47.720`, successful Type 10 login at `15:19:48.384`, `cmd.exe` at `15:19:48.750`, and `whoami /all` at `15:19:49.435`.
- The PsExec target lifecycle is convincing: separate SMB authentication and binary-transfer connections, a Type 3 logon, `C:\Windows\PSEXESVC.exe` file creation, `PSEXESVC` service creation, service process start, child command, and both child/service termination occur in source-native order.
- Collection and exfiltration have credible byte-level pivots. `FILE-SRV-01` creates `C:\ProgramData\Microsoft\cache_7f3a.zip`; Zeek files records an SMB transfer of exactly 313,880,769 bytes to `10.10.1.35`; Sysmon shows destination creation on the workstation; Chrome reads the destination; and the proxy plus both Zeek sensors observe a roughly 315 MB HTTPS upload to `api.westbridge-services.net`.
- The event-log clearing sequence is especially production-like: `wevtutil cl Security` runs on `DC-01` at `17:42:28.565/17:42:28.713`; Security Event 1102 follows at `17:42:29.678`; and its `EventRecordID` resets to `1`.
- Process lifecycle validation found no visible dependent eCAR event preceding the matching visible actor-process creation and no process termination preceding its visible creation. I did not count bounded-window processes lacking pre-window starts as defects.
- C2-like proxy check-ins from `10.10.2.10` use varied intervals—roughly 346–733 seconds—not a fixed clock cadence, and the source-native proxy, core HTTP, DMZ TLS, and endpoint flow records align.

## Detailed Analysis

### Scope and source-family mix

The corpus covers nine Windows systems and nine Linux-like endpoints/servers over about six hours. Windows hosts provide Security XML, Sysmon XML, and eCAR; Linux hosts provide syslog, eCAR, and selected shell histories. Network visibility includes core and DMZ Zeek, a perimeter ASA, core and perimeter Snort, an explicit proxy, and an external web server.

The source volumes are plausible for the visible environment. Windows Security is dominated by 5156 filtering-platform events plus logon/process/account-management records, while the DC has the expected heavier authentication and directory load. Core Zeek is dominated by DNS, HTTP/proxy, Kerberos, SMB, and LDAP. DMZ data has a realistic mixture of successful application traffic and incomplete inbound scans. Sparse families such as OCSP and DHCP are present at believable low volume rather than omitted wholesale.

### Operational lifecycle and pivot feasibility

The principal suspicious workstation activity begins with a properly ordered RDP transport and Type 10 session on `WS-AJOHNSON-01`. Within seconds, `whoami /all`, `net user /domain`, `net group "Domain Admins" /domain`, and `net view /domain` appear under the same logon ID `0x27000ab` and parent `cmd.exe`.

At `15:45:09.487`, `C:\Windows\System32\ms-index-service.exe` runs with `"privilege::debug" "sekurlsa::logonpasswords" exit`. It opens `lsass.exe` twice and creates a remote thread at `15:45:12.603`. The process identity, target PID, UUIDs, and session metadata remain coherent.

At `16:00`, the source workstation opens SMB and RPC toward `DC-01`. Zeek distinguishes a 15.9-second authenticated SMB session, a short 118,966-byte SMB transfer, and DCE/RPC. Target eCAR/Sysmon/Security then show the `PSEXESVC` file, service, service process, and child command. This is excellent target-side tradecraft rendering, although the missing source client process is a notable coverage gap.

At `16:14:56–16:15:04`, `DC-01` creates `svc_mhsync`, sets the account, and adds it to Domain Admins. At `16:20`, `DeviceSyncSvc` and an hourly scheduled task are created, and the service starts at `16:31:42`. Proxy check-ins to `/api/v2/checkin` begin at `16:32:26` with variable timing.

On `FILE-SRV-01`, `svc_mhsync` runs `Compress-Archive` at `17:01:04`, targeting Finance and patient-export shares. On `WS-AJOHNSON-01`, PowerShell starts at `17:16:50` to copy the archive from the administrative share. Zeek files sees 313,880,769 bytes traverse SMB from `10.10.2.20` to `10.10.1.35` beginning `17:22:04`; Sysmon records local creation at `17:22:14`; Chrome reads it at `17:22:15`; and the proxy records the 314,782,961-byte POST at `17:24:57`. These are technically useful pivots, not merely complete correlations.

The later `wevtutil cl Security` and account deletion are also source-native and properly ordered. I did not treat the overall lifecycle’s completeness as evidence of synthesis; only the concrete process/path and ownership defects affected the score.

### Behavioral and environmental realism

Normal network and authentication noise is reasonably dense. There are failed LDAP/authentication flows, short Type 3 sessions, legitimate SSH/RDP, browser/proxy use, software-update traffic, scheduled tasks, DHCP renewals, mail flows, public scanning, NTP-like infrastructure activity, and endpoint process/module noise.

The main environmental failure is that a significant portion of Windows file activity does not respect process ownership. Defender DetectionHistory and SoftwareDistribution paths recur on every Windows host, but their actors look selected from a general system-process pool. A real collection can contain surprising access due to AV inspection, kernel attribution, indexing, or injected code, but it would not produce repeated Sysmon file-creation records assigning Defender history artifacts to `winlogon.exe` and `lsass.exe` across servers while also assigning update CAB operations to `dwm.exe`, `csrss.exe`, `dns.exe`, and similar unrelated processes.

The SSH process trees have the same problem at a higher behavioral level. Direct `explorer.exe -> ssh.exe` execution can occur through a shortcut or Run dialog, and Firefox can invoke a registered external handler, but 61 of 65 SSH launches using Explorer or Firefox across unrelated users and workstations—with just two shell-parented launches—has generator-like distribution texture.

### Bounded-window and correlation checks

I did not penalize sessions, processes, or flows solely because their initiators were outside the visible window. I also treated high-fidelity cross-source matching as positive or neutral. The eCAR lifecycle check found zero dependent events before a matching visible actor creation and zero visible process terminations before matching creations.

The RDP transport/session-duration mismatch is retained only as a weak signal. Windows can preserve disconnected sessions, and processes can continue without a live RDP TCP stream; without evidence that every later command required fresh interactive input, this is not a hard causality finding.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `hard_contradiction` | Sysmon/eCAR Windows file telemetry | Repeated on multiple Windows hosts | `winlogon.exe` and `lsass.exe` are recorded creating Defender DetectionHistory artifacts, contradicting normal ownership semantics. |
| `distribution_texture` | eCAR/Sysmon Windows file telemetry | Dataset-wide: 139 records across all nine Windows hosts | Two sensitive path pools are repeatedly paired with a broad set of unrelated system processes, resembling randomized generation. |
| `distribution_texture` | eCAR/Sysmon process trees | 65 SSH starts across four workstations | 58 direct Explorer parents and five Firefox parents, versus only two command-shell parents, form an implausible cross-user distribution. |
| `contract_gap` | Windows endpoint plus SMB/RPC/PsExec | One high-value remote-admin action | Target evidence is detailed, but the source PsExec/equivalent process is absent despite broad source process telemetry. |
| `weak_signal` | Zeek RDP plus endpoint session/process telemetry | One RDP session | The visible RDP transport ends before much later activity in the same session; disconnected-session semantics prevent treating this as impossible. |

## Realism Score by Category

- **Field format accuracy:** 8 — Most source-native fields, identifiers, XML structures, Zeek states, proxy fields, and byte counts are convincing, but some file-event semantics are not.
- **Temporal patterns:** 9 — Transport-before-auth ordering, process lifecycles, variable C2 intervals, transfers, and event-log reset timing are strong.
- **Cross-source correlation:** 8 — RDP, PsExec target activity, SMB staging, proxy exfiltration, and log clearing pivot well; the missing source PsExec client is the main gap.
- **Behavioral realism:** 5 — Attack operations are feasible, but the repeated Explorer/Firefox-to-SSH topology and arbitrary system-process file ownership materially reduce realism.
- **Environmental consistency:** 5 — Source volume and service mix fit the environment, while dataset-wide Defender/Windows Update path ownership does not.

## Recommendations

- If this were synthetic, constrain Windows file events by process-owned behavior. Defender DetectionHistory creation should be attributed to Defender components or explicitly modeled kernel/service paths; Windows Update CAB creation and writing should use Windows Update servicing processes. Do not sample arbitrary system processes for these path families.
- Model Windows SSH initiation through realistic interactive parents such as `WindowsTerminal.exe`, `cmd.exe`, `powershell.exe`, or approved terminal applications. Keep Explorer direct launches rare and require an explicit shortcut/Run-dialog context; Firefox should spawn SSH only when a visible registered-protocol or helper transition explains it.
- For PsExec-like activity, emit or deliberately suppress the source client process as one coherent source-observation decision. When visible, connect its PID and principal to the SMB/RPC tuple; when dropped, ensure the surrounding source telemetry exhibits comparable observation gaps.
- Align RDP control activity with a live transport or add a source-native disconnect/reconnect lifecycle. If post-disconnect actions are autonomous, expose the local scheduler, malware process, or other execution mechanism that continues them.
- Preserve the current strengths: variable network timing, realistic state diversity, byte-level SMB/proxy correlation, transport-before-auth ordering, lifecycle termination, and Security-log record-ID reset behavior.
