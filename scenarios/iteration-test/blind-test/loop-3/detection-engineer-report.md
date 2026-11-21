# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 71
**Synthetic-Confidence Score:** 18

## Executive Summary

The supplied records behave like a technically coherent, deliberately selected production collection when parsed and joined by source-native identifiers. I did not establish a source-native contradiction or impossible visible lifecycle; particularly strong details include Windows channel-reset semantics, process identity agreement, macOS fork/exec identity changes, and TLS-version-sensitive Zeek visibility. This is a moderate-confidence authenticity judgment, because a sophisticated synthetic implementation could reproduce those properties and the supplied files cannot establish provenance.

## Evidence For Synthetic

- No defensible high-impact synthetic indicator was established. I did not substitute source completeness, attack narrative shape, filesystem timestamps, sanitized domains, or absent Sysmon types for a concrete defect.
- Two `zeek-core/smb_mapping.json` rows have UIDs absent from the supplied `zeek-core/conn.json`: line 31, `CHMpRoLkoSbA0QcG4G1`, at `ts=1793626538.502434`; and line 134, `CXmGGDqkbkc7C70mn`, at `ts=1793640924.869766`. These are investigation caveats, not scored synthetic indicators: selective connection-record loss or export filtering can explain them, and the data do not establish mandatory complete connection collection.

## Evidence For Real

- `DC-01.meridianhcs.local/windows_event_security.xml` handles the visible Security-log clear correctly: event 5156 has record ID `28260865` at `18:42:19.1498012Z`, event 1102 resets to record ID `1` at `18:42:21.2975513Z`, and the following visible event 4689 has record ID `6` at `18:42:28.6926147Z`. Event 1102 also uses the Eventlog provider and `UserData/LogFileCleared`, rather than incorrectly imitating a Security-Auditing `EventData` event.
- Of 939 Security event 4688 records, 935 have a same-host, same-PID Sysmon event 1 within two seconds. Every such match agrees on executable, parent PID, command line and effective logon ID. The four outside that join are not treated as defects.
- No checked Sysmon GUID reference preceded its visible creation or followed its visible termination by more than 10 ms. The corresponding eCAR identity checks found no before-create or after-terminate reference beyond 50 ms. These are positive integrity results, not claims that all pre-window origins or post-window closures must be present.
- All matched Zeek protocol records agree with their connection's four-tuple. None had a timestamp more than 1 ms before its connection start or more than 200 ms after its modeled connection end. TLS 1.3 rows correctly lack visible certificate-chain FUIDs, while full TLS 1.2 handshakes can reference certificates and resumed TLS 1.2 sessions omit them.
- macOS native ES records distinguish the pre-exec actor from the exec target, preserve PID across exec while changing PID version, and use inherited process images for fork children. The supplied Unified Log rows remain structurally distinct from normalized eCAR and ES notifications.
- Linux SSH samples exhibit transport indication, authentication success, PAM session opening and later closure, including realistic public-key fingerprint representation and per-session sshd PIDs.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and briefing. I parsed all 28,973 Windows XML events, the JSON/NDJSON sources used for the checks below, and representative text records from syslog, histories, proxy, ASA and IDS logs. The three Zeek connection files contain 12,351, 10,267 and 470 records respectively; the macOS ES files contain 150 and 176 records. I did not consult scenarios, repository code, ground truth, other assessments or external provenance.

The review combined whole-file identity and reference checks with manual inspection of more than twenty distinct source/event shapes. Whole-file checks were bounded by the supplied slice: a missing initiating event was not treated as evidence that the underlying object never existed. The windows used in automated timestamp joins allow ordinary observation latency and timestamp resolution; positive findings do not imply independently verified packet capture truth.

### Windows schema and detection-field checks

The XML uses the Windows Event namespace and gives System metadata separately from event payload fields. Sample Security success events use level `0`, opcode `0`, and audit-success keywords `0x8020000000000000`; the sampled failed logon uses audit-failure keywords `0x8010000000000000`. Sysmon samples use the Sysmon provider, Operational channel, level `4`, and event-specific task values. IDs, hexadecimal logon/PID representations, decimal Sysmon PIDs, SID text, brace-delimited GUIDs, and native `%%` resource identifiers are internally usable by a SIEM parser.

Representative records checked:

| Source and time (2026-11-02, UTC) | Event/type | Fields and relationships inspected |
|---|---|---|
| DC-01 Security `13:00:58.3547985` | 4624 v2 | `LogonType=3`, NTLM/NtLmSsp, `LmPackageName=NTLM V2`, `KeyLength=128`, source `::ffff:10.10.2.11:57822`, target `marcus.chen`, logon ID `0x5375b2c`; v2 extended fields present. |
| DC-01 Security `13:00:58.4071092` | 5140 | Same user, logon ID, source address and port; `ShareName=\\\\*\\NETLOGON`, local SYSVOL scripts path. |
| DC-01 Security `13:01:07.1366447` | 4634 | Same target user and `TargetLogonId=0x5375b2c`, with `LogonType=3`, after the visible login. |
| DC-01 Security `13:01:35.5384171` | 4688 v2 | New PID `0xf68` / 3944, parent `0x924` / 2340, WmiPrvSE image, parent svchost image, token elevation and mandatory label. |
| DC-01 Sysmon `13:01:35.4446031` | 1 v5 | PID 3944, parent 2340, identical WmiPrvSE command, SYSTEM identity, logon ID `0x3e7`, hashes and process GUID. Cross-provider observation timestamps differ plausibly. |
| DC-01 Security `13:05:56.5801985` | 4769 | Machine-account target, service SID, `TicketEncryptionType=0x12`, ticket options, client IPv4-mapped IPv6 address and port. |
| DC-01 Security `13:17:42.8820947` | 4768 | `krbtgt`, RID-502 service SID, machine-account SID, pre-auth type 2, success status, and empty certificate fields consistent with password/key pre-auth. |
| DC-01 Security `13:23:21.4595010` | 4776 | Native package string `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation and account fields; no invented IP field required. |
| DC-02 Security `16:08:28.3472780` | 4625 | Status `0xc000006d`, disabled-account substatus `0xc0000072`, type 3, NTLM identity and source fields. |
| FILE-SRV-01 Security `13:00:05.9658107` | 5145 | Share `ClinicalExports`, relative target `Servers\\archive-final.bak`, share-local path and access mask. |
| FILE-SRV-01 Security `13:00:05.9723039` | 4656 | Handle `0xe1509168`, full object path corresponding to that share-relative target, process ID `0x4`, and access mask `0x12019f`. |
| FILE-SRV-01 Security `13:00:06.1459007` | 4663 | Same handle and object; write-data access `0x2` / `%%4417`. |
| FILE-SRV-01 Security `13:00:09.7044242` | 4658 | Same handle closed after the visible request/access events. |
| DC-01 Sysmon `13:01:00.3856303` | 10 v3 | Source/target process GUIDs, decimal PIDs, granted access `0x1010`, thread ID and pipe-separated module-offset call trace. |
| DC-01 Sysmon `13:01:00.5166620` | 8 v2 | Same source/target identities, new thread ID, hexadecimal start address, ntdll module and `RtlUserThreadStart`. |
| DC-01 Sysmon `15:21:27.1631127` | 11 v2 | Process identity, Defender file path, event time and creation time kept as separate fields. |
| FILE-SRV-01 Sysmon `13:32:40.4835781` | 13 v2 | `EventType=SetValue`, target registry path, textual Details, process identity and NETWORK SERVICE user. |
| DC-01 Sysmon `13:00:15.9942906` | 22 v5 | Query name, numeric query status, semicolon-terminated answer, lsass image/PID/GUID, and native millisecond UtcTime. |
| WS-AJOHNSON-01 Security `17:12:21.5185637` / `17:24:53.9110202` | 4800 / 4801 | Matching user, session ID `2`, and logon ID `0x24e0ec7` across lock/unlock. |
| DC-01 Security `17:19:50.5492298` | 4698 | Escaped TaskContent is a task XML document, with SYSTEM principal, time trigger and executable action. |
| DC-01 Security `18:42:21.2975513` | 1102 | Provider, UserData namespace, subject identity, keywords and channel-record reset. |

I also checked event 4697 service fields and events 4720/4724/4738/4728/4726 for their distinct account/group operation shapes. The user creation/change sequence retains the same account SID ending `2229`; group membership uses member DN/SID separately from the target group's RID-512 SID. I did not infer authenticity from whether that activity constitutes a neatly observable intrusion.

Across the Security files, a non-null SID did not map to conflicting usernames in the checked subject/target fields. Reused target logon IDs did not map to different successful-login usernames on the same host. EventRecordIDs increase in each supplied channel except for the explicit, coherent DC-01 Security clear.

### Network source semantics and correlation

The first `zeek-core/conn.json` row has UID `CjYcTnKtfeDlACbjaz`, tuple `10.10.1.41:61726 -> 10.10.3.20:8080`, `proto=tcp`, and `service=http`. The matching HTTP row uses the same tuple and a CONNECT method. The proxy text provides the control-message byte scope separately from tunneled bytes, preventing the common mistake of treating CONNECT control bytes as the entire TLS transfer.

DNS UID `CxYreueoXHnECgd8tG` has `ts=1793624401.617690`, the same tuple in conn and dns, query `registry.npmjs.org`, type A, NOERROR, two answers, and two corresponding TTLs. Numeric/boolean/array field types are appropriate for JSON ingestion.

For all three sensors, I checked connection accounting for payload larger than total IP bytes, implausibly short minimum headers, gap histories with zero missed bytes, missed bytes without a gap history, and successful-finish states containing reset histories. Those checks found no violations. This does not replace packet-level reconstruction, but avoids scoring superficially elaborate fields as correct without checking their relationships.

Certificate references resolve through SSL -> x509/files. All referenced certificate validity intervals cover the observed TLS time in these checks. For example, core TLS UID `CeJoHHJ9wEPFOKQRxC` references `FDUuU6or3lfMDksUSG`, and x509 provides a consistent internal LOG-MON certificate. Full TLS 1.2 handshakes, resumed handshakes, and TLS 1.3 do not share an indiscriminate certificate-output template: the TLS 1.3 sample `CYK3fTwwkLgtPMAKg42` has `TLS_AES_128_GCM_SHA256`, history `Cs`, and no certificate-chain FUID.

Visible PE file analysis is attached to plaintext HTTP transfers, rather than inventing PE dissection of an opaque CONNECT tunnel. The file with SHA1 `e05c855cf0ba6e0a8bc0775bf8f07ff44971fbdb` retains size `115241792` through upstream/downstream proxy views with distinct sensor-local FUIDs and connections. I did not require different sensors to share UIDs.

The two orphan SMB mapping UIDs noted above limit the completeness claim. They are not sufficient to distinguish selected production data from synthetic observation loss.

### Linux and macOS ingestion

Linux text records use a consistent RFC5424-style envelope with PRI, timestamp, host, application, PID and NILVALUE fields. On APP-INT-01, sshd PID `2943340` records the connection at `14:12:27.571014Z`, password acceptance at `14:12:34.794974Z`, PAM session opening at `14:12:34.851758Z`, and closure at `15:00:33.581098Z`. The visible session does not open before authentication. Key-authenticated sessions use an algorithm name and a plausible unpadded SHA256 fingerprint. Bash and zsh histories use different native timestamp conventions.

The MAC-MROSS-01 ES sequence begins with launchd forking PID `42154` at `13:07:32.811343000Z`: the child initially inherits `/sbin/launchd`, root credentials and PID version 12. At `13:07:32.820534000Z`, the exec target is `/usr/libexec/xpcproxy`, retaining PID 42154 and incrementing PID version to 13; the message actor remains the pre-exec image. Later command notifications and exits preserve audit-token/process relationships. Per-event sequence numbers increase independently; global sequence numbers increase across event types. Within each Mac, repeated executable device/inode pairs did not acquire contradictory path, size or cdhash values in my check.

I treated `version=11` ES notifications as that declared source shape and did not impose normalized EDR FLOW fields on them. The Unified Log sample from loginwindow has its own process/sender images, subsystem, category, format string and rendered eventMessage. The kernel AppleSystemPolicy message at `15:42:09.009673+0000` says security policy “would not allow” MeetingAssist; that wording alone does not prove denied execution. I therefore did not manufacture a policy-denial/child-execution contradiction.

### Distribution and limits of inference

The connection-state distributions include established, SYN-only, reset, partial and other connections; timestamps and volumes vary by sensor and host. Repeated service executable commands and scheduled CRON records are expected without further evidence of an impossible count or timing pattern. The observed six-hour slice and selected source scope do not justify demanding whole-day process churn, every audit family, or full boot-to-shutdown closure.

These checks support good detection-stack usability and production-like semantics. They cannot authenticate the origin of the bytes, and they leave uncertainty about untested native-version edge cases and collection configuration.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| No established scored indicator | Windows Security/Sysmon, eCAR, Zeek, Linux, macOS | Inspected schema samples and whole-file checks described above | No demonstrated contradiction warrants moving into the mixed or likely-synthetic bands. |
| Unscored collection caveat | Zeek SMB mapping / conn | Two core mapping UIDs absent from the supplied conn file | None; selective collection/export loss remains a sufficient explanation. |

The score of 18 reflects strongly production-like technical behavior, with residual uncertainty about authenticity rather than an invented list of defects. It is distinct from the 71% confidence in the Real verdict.

## Realism Score by Category

- **Field format accuracy:** 9 — Source-native XML/JSON/text shapes and the inspected event-specific fields are credible and ingestible.
- **Temporal patterns:** 9 — Checked visible lifecycle order, provider latency and protocol-within-transport relationships are coherent.
- **Cross-source correlation:** 9 — Process identity joins, logon/session examples and protocol tuples agree; two unpaired SMB mapping UIDs limit completeness.
- **Behavioral realism:** 8 — Host/process/service activity and connection outcome diversity are plausible within the supplied slice; underlying behavior cannot be independently verified.
- **Environmental consistency:** 9 — OS-specific paths, source semantics, certificates, proxy transfer views and SSH identities remain coherent in the inspected records.

## Recommendations

- No defect-specific realism change is justified by the checks performed. If this were synthetic, preserve the source-specific behavior demonstrated here: especially channel resets, pre-/post-exec identity, TLS-version visibility, distinct proxy byte scopes and lifecycle-compatible timing.
- For the two unpaired SMB mapping UIDs, inspect whether the intended collection/export policy permits conn records to be omitted while SMB records survive. If it does, retain that collection explanation; if it requires both records, repair those specific paired observations. The current data alone do not establish which case applies, so this is a targeted validation recommendation and does not increase the synthetic-confidence score.
