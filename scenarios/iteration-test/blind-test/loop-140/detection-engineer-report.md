# Detection Engineer - Authenticity Assessment

## Verdict

**Assessment:** Real
**Confidence:** 64

## Executive Summary

This looks more like a sanitized, filtered production slice than a fully synthetic dataset. I found strong source-native consistency across Windows Security, Sysmon, eCAR, Zeek, TLS/X.509, and shell history, and I did not find a hard field contradiction or impossible visible ordering.

## Evidence For Synthetic

- Zeek `conn.json` files are strictly sorted by connection start `ts`, even for long-duration sessions such as `zeek-core/conn.json` `2024-03-18T12:00:05.327066Z` with `duration:3378.62303`; raw Zeek often emits conn records closer to teardown, so this feels post-processed.
- `WS-AJOHNSON-01.../windows_event_security.xml` has an unlocked event at `2024-03-18T17:34:45.3201889Z` for `SessionId=2`, `TargetLogonId=0x28072ce` without a visible same-ID lock. This is not impossible in a bounded slice, but it is a small session-lifecycle oddity.
- Several Linux bash histories repeat similar admin diagnostic patterns across users and hosts, such as `systemctl`, `journalctl`, `nmcli`, `lsusb`, and `cat`, giving a slightly curated exercise feel.

## Evidence For Real

- DC audit-clear sequence is source-native: `DC-01.../windows_event_security.xml` shows `wevtutil cl Security` at `2024-03-18T17:41:47.6859248Z`, followed by Event ID `1102` at `17:41:49.3383006Z` with `UserData/LogFileCleared` subject `NT AUTHORITY\SYSTEM`, then EventRecordID reset.
- RDP activity correlates correctly: `WS-AJOHNSON-01` Sysmon Event 1 creates `mstsc.exe /v:FILE-SRV-01` at `12:00:05.8374095Z`; Security 5156 and Sysmon 3 show `10.10.1.35:61521 -> 10.10.2.20:3389`; Zeek core has the same tuple at `12:00:09.221953Z`.
- Kerberos and Windows auth fields are plausible: 4768/4769 on `DC-01`, 4624/4634 on member hosts, `::ffff:` IPv4-mapped addresses, LogonIDs, SIDs, and privileged 4672 events are coherent.
- Zeek TLS evidence is internally consistent: `ssl.cert_chain_fuids` link to `files.json`, `x509.json` fingerprints match file SHA1s, and OCSP serials line up with certificate records.
- Shell history includes human-like typos and exploratory behavior, e.g. `atil`, `ddf`, `reslvectl`, mixed with normal admin commands.

## Detailed Analysis

Windows schema and event semantics are strong. Across 8 Security logs I counted 8,070 events, mainly 5156, 4688, 4624, 4634, 4768, and 4769. Sysmon has 4,064 events using expected fields for process create, network connection, DNS query, registry set, process access, module load, file create, and remote thread activity. Process IDs, parent process IDs, command lines, and hashes line up between Security 4688 and Sysmon 1 without visible contradictions.

The DC attack-administration chain is believable. Around `17:41:45Z`, `DC-01` shows `powershell.exe -NoProfile -EncodedCommand ...` under `C:\Windows\PSEXESVC.exe`, outbound proxy flow to `10.10.3.20:8080`, then `wevtutil cl Security`. Sysmon, Security, and eCAR agree on PIDs `6156` and `6188`, command lines, and timing within sub-second to millisecond differences.

Network telemetry looks source-native. `zeek-core` and `zeek-dmz` include 20,352 records with realistic mixes of `SF`, `S0`, `RSTO`, `RSTR`, DNS `NOERROR/NXDOMAIN/SERVFAIL/REFUSED`, HTTP CONNECT, TLS 1.2/1.3, x509 chains, OCSP responses, and DHCP renewals. I found no UID references in HTTP/SSL/DNS/files that were missing from conn logs.

Endpoint eCAR records are consistent with host perspective. Flow direction matches host IP ownership, process object IDs are created before dependent actor references when visible, and process termination never precedes a visible create for the same object ID.

## Realism Score by Category

- **Field format accuracy:** 8 - Windows, Sysmon, Zeek, x509, and eCAR fields are mostly source-native and parser-friendly.
- **Temporal patterns:** 8 - Bursts, logon/logoff sequencing, and attack timing are plausible; a few session lifecycle edges are mildly odd.
- **Cross-source correlation:** 9 - Correlations are concrete and source-correct without visible impossible ordering.
- **Behavioral realism:** 8 - Admin activity, typos, failed auth, lateral movement, and cleanup behavior are believable.
- **Environmental consistency:** 8 - Hostnames, IP ranges, SIDs, Kerberos realm, proxy paths, and mixed Windows/Linux assets hold together.

## Recommendations

- **P2:** Preserve or document native Zeek acquisition ordering if these are meant to be raw sensor files; strict start-time sorting can feel export-like.
- **P3:** Add more benign source-local irregularities: partial sessions, harmless unmatched records, and noisy operational events that do not need cross-source linkage.
- **P3:** Tighten workstation lock/unlock lifecycle modeling so visible 4800/4801 pairs more often share `SessionId` and `TargetLogonId`.
- **P4:** Diversify shell-history habits further so repeated diagnostic command families vary more by persona and host role.
