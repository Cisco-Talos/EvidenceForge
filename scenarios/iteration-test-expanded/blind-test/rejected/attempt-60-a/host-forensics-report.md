# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 32

## Executive Summary

The endpoint and host telemetry is mostly production-like: Windows Security/Sysmon, eCAR, Linux syslog, bash history, and Zeek records show coherent field values, lifecycles, and cross-source ordering. I did not find hard contradictions such as child processes after parent termination, authentication after session close, impossible Windows event sequencing, or broken SSH/network/session relationships. The remaining synthetic evidence is weak and explainable, so I would not call this confidently real or synthetic.

## Evidence For Synthetic

- **[weak_signal] Bash history timestamp backstep on one workstation:** `WS-LNGUYEN-01/bash_history/lina.nguyen.bash_history` moves from `#1710779524` to `#1710777916`, then back to `#1710779574`. This can happen with multiple interactive shells appending history, so it is only a low-impact artifact.
- **[distribution_texture] Filtered Windows Security exports show large EventRecordID gaps:** for example, `DC-01/windows_event_security.xml` spans EventRecordID `28245269` to `29188363` but contains 8,797 parsed events from selected event IDs. That looks like a filtered collection profile rather than raw channel export, which is realistic for SIEM-style collection but limits confidence.

## Evidence For Real

- DC log-clearing evidence has correct Windows-native companion events. `DC-01/windows_event_security.xml` shows `cmd.exe /c wevtutil cl Security` at `2024-03-18T17:41:50.6635450Z`, `wevtutil.exe` at `17:41:51.3685459Z`, then Event ID `1102` at `17:41:51.6978749Z` with `SubjectUserName=SYSTEM`, `SubjectDomainName=NT AUTHORITY`, `SubjectLogonId=0x3e7`. Sysmon and eCAR also show the matching process create/terminate lifecycle.
- SSH session ordering is source-native and coherent. `APP-INT-01/syslog.log` shows `10.10.4.10:46080 -> 10.10.2.30:22`, accepted publickey at `2024-03-18T17:30:47.880103Z`, PAM open at `17:30:48.021270Z`, and close at `17:31:10.521097Z`. `APP-INT-01/ecar.json` has FLOW before USER_SESSION LOGIN, and `zeek-core/conn.json` has the same tuple with `conn_state=SF` and a duration covering the session.
- Windows process/hash consistency is strong. Same image paths with the same `FileVersion` retain the same hash across hosts, while different OS build versions differ as expected, such as `taskhostw.exe` and `gpupdate.exe` across Server 2022, Windows 10, and Windows 11 hosts.
- Endpoint lifecycle checks did not reveal impossible relationships. eCAR process creates did not occur after a visible terminated parent, Sysmon parent process GUIDs did not create children after termination, and host files were timestamp-ordered.
- Windows Security field semantics look plausible. For example, DC inbound LDAP 5156 records use `lsass.exe`, inbound direction, and `10.10.2.20 -> 10.10.2.10:389`, while the FILE-SRV peer record shows the corresponding outbound perspective.
- Linux host telemetry includes routine operational texture: cron/sysstat, sudo PAM open/close, DHCP renewals, NetworkManager state changes, rsyslog queue messages, systemd-logind session opens/closes, and bash commands that fall inside visible SSH/admin sessions on server hosts.

## Detailed Analysis

Windows host telemetry is internally consistent. The DC Security log contains expected Kerberos, logon, firewall platform, process, explicit credential, and log-clear records without obvious schema defects. The `wevtutil cl Security` sequence is especially useful because Security, Sysmon, and eCAR all agree on timing and lifecycle: process creation precedes Event ID `1102`, and termination follows.

Endpoint process modeling also holds together. Across eCAR files, process object IDs were not reused in conflicting ways, and no visible child process creation depended on a parent that had already visibly terminated. Sysmon Event ID 1 and Event ID 5 relationships also avoided parent-after-termination contradictions.

Linux SSH evidence is realistic. The APP-INT session from `10.10.4.10:46080` shows network transport first, then SSH auth, then PAM/session open, then later close. Zeek's connection interval spans the endpoint login/logout evidence instead of being a tiny placeholder flow. Bash histories on server hosts align with visible SSH or sudo session windows.

The weakest concern is workstation shell history ordering on `WS-LNGUYEN-01`, where one timestamp sequence moves backward. That is not impossible because bash history from multiple shells can be interleaved when appended, but in isolation it slightly reduces confidence.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Score Impact |
|---|---|---:|---|
| weak_signal | Bash history | One workstation user history has a timestamp backstep | Low |
| distribution_texture | Windows Security | Filtered exports with large EventRecordID gaps | Low |
| hard_contradiction | Endpoint/host lifecycle | None observed | None |
| contract_gap | SSH, process, Windows log clear | None observed in checked relationships | None |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows XML, Sysmon fields, eCAR objects, syslog, and Zeek JSON look source-native.
- **Temporal patterns:** 8/10 — session and process ordering is coherent; one bash history backstep is weakly suspicious.
- **Cross-source correlation:** 9/10 — SSH, Zeek, eCAR, Security, and Sysmon relationships line up without impossible ordering.
- **Behavioral realism:** 8/10 — endpoint, service, cron, sudo, DHCP, failed logon, and admin activity contain credible background texture.
- **Environmental consistency:** 8/10 — host roles and OS/build differences are consistent; filtered exports limit certainty.

## Recommendations

- Preserve shell session identifiers or terminal open/close context with workstation bash histories to disambiguate multi-shell timestamp interleaving.
- Include collection filter metadata for Windows Security exports so large EventRecordID gaps are explicitly attributable to SIEM/event-ID selection.
- Keep the existing cross-source lifecycle consistency; the SSH transport/auth/session and Windows log-clear process chains are strong realism anchors.
