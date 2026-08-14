---
description: "Windows Security and Sysmon evidence reference"
---

# Windows Evidence

Read this reference for Windows Security or Sysmon paths, supported event IDs, lifecycle joins, and
target-specific rendering.

## Windows Security

- Default: `<host>/windows_event_security.xml`, one rooted `<Events>` document.
- SOF-ELK®: `<host>/<year>/windows_event_security_snare.log`, Snare fields in RFC3164 syslog.
- Splunk: `<host>/windows_event_security.xml`, one complete `<Event>` per physical line.
- Provider: `Microsoft-Windows-Security-Auditing`, except Event 1102.
- Channel: `Security`.

| ID | Meaning | Important behavior |
| --- | --- | --- |
| 1102 | Security log cleared | `Microsoft-Windows-Eventlog`; uses `UserData`; starts a new channel epoch at record 1. |
| 4624 | Successful logon | Version 2; types 2, 3, 5, 7, 10, and 11; IPv4 is rendered as IPv4-mapped IPv6. |
| 4625 | Failed logon | Audit Failure with Status/SubStatus; remote attempts have established/reset-after-payload transport rather than SYN-only probes. |
| 4634 | Logoff | Joins 4624 by TargetLogonId; short type-3 lifecycle or end-of-day interactive/RDP lifecycle. |
| 4648 | Explicit credentials | Source-host evidence for RunAs, PsExec, WMIC, and alternate-credential scheduled tasks. |
| 4672 | Special privileges | Accompanies eligible elevated target-host 4624 rows. |
| 4688 / 4689 | Process create / exit | Command line, parent and elevation data; paired lifecycle. |
| 4697 | Service installed | Service binary/command and account. |
| 4698–4701 | Scheduled task create/delete/enable/disable | Task XML is HTML escaped where present. |
| 4720 / 4726 | Account create / delete | Storyline-triggered account management. |
| 4723 / 4724 | Password change / reset | May carry failure status where appropriate. |
| 4728 / 4729 | Global group add / remove | Storyline-triggered membership changes. |
| 4732 / 4733 | Local group add / remove | Storyline-triggered membership changes. |
| 4738 | Account changed | Full account properties, including the source-native leading Dummy field. |
| 4756 / 4757 | Universal group add / remove | Storyline-triggered membership changes. |
| 4768 | Kerberos TGT request | Success/failure details; data-driven pre-auth, options, encryption, and PKINIT certificate fields. |
| 4769 | Kerberos service ticket | TargetUserName includes the realm suffix. |
| 4770 | TGT renewal | Successful renewal evidence. |
| 4771 | Kerberos pre-auth failure | Audit Failure and password-spray signal. |
| 4776 | NTLM validation | Uses TargetUserName and Workstation field names. |
| 5156 | WFP permitted connection | Device-form application path and source-native direction codes. |

EventRecordIDs are assigned chronologically per host/channel. Gaps represent omitted same-channel
records in this selected projection and are bounded by conservative background rates. Security log
clear begins a new record epoch.

Auth/session bundles coordinate logon, failure, logoff, lock/unlock, service, machine-account,
anonymous, NTLM, Linux/eCAR, and companion network lifecycles. Kerberos/DC bundles coordinate
ticket timing, source tuple, TGT cache, SPN identity, and KDC network evidence. Windows audit
bundles align subject LogonID/session ownership, target account/group identity, task XML, and
process/thread context.

Domain controllers receive admin-oriented baseline activity, not ordinary desktop browsing or
Office activity. RSAT activity correlates workstation `mmc.exe` and DLL evidence with LDAP/RPC
transport and a DC-side type-3 logon.

## Windows Sysmon

- Default: `<host>/windows_event_sysmon.xml`, one rooted `<Events>` document.
- SOF-ELK: `<host>/<year>/windows_event_sysmon_snare.log`, Snare/RFC3164.
- Splunk: `<host>/windows_event_sysmon.xml`, one complete `<Event>` per physical line.
- Provider/channel: `Microsoft-Windows-Sysmon` / `Microsoft-Windows-Sysmon/Operational`.

| ID | Meaning | Important behavior |
| --- | --- | --- |
| 1 | ProcessCreate | Version 5; deterministic fake hashes; rich file metadata; real parent command from process state. |
| 3 | NetworkConnect | Canonical connection tuple and owning process when endpoint attribution exists. |
| 5 | ProcessTerminate | Paired with Security 4689 and eCAR PROCESS/TERMINATE. |
| 7 | ImageLoad | Process-aware DLL/module evidence. |
| 8 | CreateRemoteThread | Shared source/target process identity and thread context with eCAR. |
| 10 | ProcessAccess | Credential-access context such as LSASS access; correlated with eCAR PROCESS/OPEN. |
| 11 | FileCreate | Process-owned local file evidence; remote UNC objects do not fabricate client-local creates. |
| 12 / 13 | Registry create/delete / value set | Shared process and registry context. |
| 22 | DNS query | Host resolver evidence coordinated with the canonical DNS lookup. |

`ProcessGuid` is deterministic from hostname, PID, and process creation time, so the implemented
event families agree for one known process. Its morphology is Sysmon-like rather than an RFC UUID
version guarantee. Hashes are synthetic but stable for the same binary and host. Process lifecycle,
file/module/registry/network side effects, Security 4688/4689, and eCAR are coordinated through the
same execution state rather than independently derived by each emitter.
