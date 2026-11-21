# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 63

## Executive Summary

Most of this dataset would ingest successfully into a detection stack, and its process identities, protocol references, and lifecycle relationships are substantially credible. I lean synthetic because three command clusters across two Macs retain an identical microsecond timestamp phase for separate process forks, together with a smaller Windows event-schema discrepancy. I did not establish an impossible lifecycle or an identity leak, so this is a qualified verdict rather than an assertion that the whole dataset is obviously artificial.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41 and 44 record shell forks at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z` and `13:50:02.198588000Z` on November 2. The children subsequently execute curl, bash, ls and id. Four separate kernel process-creation observations retain precisely the same microsecond phase, with gaps of exactly 27, 35 and 19 seconds. This is a timestamp-distribution issue, not a criticism of the activity sequence.
- [distribution_texture] The pattern recurs in the same file at lines 53, 56 and 59: bash, cat `/etc/resolv.conf`, and cat `/etc/hosts` begin with fork times `14:37:50.487145000Z`, `14:38:28.487145000Z` and `14:38:57.487145000Z`. It also appears on the other Mac: `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`, lines 83, 86 and 89, has forks at `15:30:55.965208000Z`, `15:31:17.965208000Z` and `15:31:58.965208000Z` for dscl, find and du. Independent system calls can be scheduled at approximate offsets, but exact microsecond agreement across these separate launches and repeated clusters is a credible construction fingerprint. These two bullets describe one underlying indicator and are not scored independently.
- [schema_or_format] The 47 Security Event 4658 records include a named `ProcessName` element in their version-0 `EventData`. For example, `FILE-SRV-01.meridianhcs.local/windows_event_security.xml`, EventRecordID `271778`, `2026-11-02T13:00:09.7044242Z`, includes `ProcessId=0x4` and `ProcessName=System`. Standard 4658 version 0 carries the process ID but does not have this `ProcessName` payload field. An enriched collector could add it, so this is a small raw-export fidelity concern, not proof of impossible Windows behavior.

## Evidence For Real

- All supplied XML documents and nonempty JSON/NDJSON records parsed successfully. Windows provider/channel metadata, hex versus decimal process identifiers, source-specific timestamp representations, and typed JSON values are generally credible.
- Across all ten Windows Sysmon files, a GUID-based scan found no non-create/non-exit process observations more than 0.5 seconds before a matching visible Event 1 or after a matching visible Event 5. The same GUID did not change its PID or image. Pre-window processes were allowed and were not counted as missing evidence.
- The eCAR actor-ID checks similarly found no dependent observations more than 0.5 seconds outside matching visible process lifetimes, and no visible child creation more than 0.5 seconds after its matched parent's termination.
- Zeek DNS, HTTP, SSL, SMB and SMTP records have matching tuples and reasonable timestamps relative to their matched `conn.json` rows. No matched protocol row was more than 10 milliseconds before connection open or more than one second after the recorded connection interval.
- Repeated certificates retain their content identity. Across 339 distinct SHA256 values in `files.json`, repeated fully observed objects did not change total size; repeated X.509 fingerprints did not change the compared certificate metadata. All checked MD5, SHA1, SHA256, fingerprint and macOS cdhash strings have the appropriate lengths.
- Native macOS evidence distinguishes fork, exec and exit. It retains the PID through exec while advancing PID version and replacing the executable, rather than treating every exec as a newly forked process. The native ES notifications and normalized eCAR process-modification records preserve this distinction.
- Linux sudo activity shows invoking-user processes and root children with coherent PAM session opens/closes. The records also include routine service, resolver, scheduler and queue-health messages rather than only authentication success lines.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. It contains 115 files, including 17,782 Security XML events, 11,577 Sysmon XML events, 37,903 eCAR records, 23,194 Zeek connection rows, 4,352 DNS rows, 5,625 HTTP rows, 3,756 SSL rows, 317 Endpoint Security notifications, five Unified Log records, and 4,030 Linux syslog lines. I parsed the structured records, inspected event-specific payloads, and ran identifier, timing, and content-consistency checks. All times cited below are November 2, 2026, UTC.

I did not score domain routability, copied-file timestamps, the existence of suspicious activity, completeness of source matching, or the absence of uncollected Sysmon event types. The native macOS source is treated as ES notifications and Unified Log exports; its normalized eCAR records are a separate source representation.

### Representative event-schema review

The following samples cover more than the requested 10–20 event types. A passing inspection means the displayed field shape and semantics were credible; it does not certify every operating-system implementation detail.

| Source / event | Specific inspected record | Result |
|---|---|---|
| Security 4624 v2 | DC-02, `13:00:33.6186239`, Type 5, LOCAL SERVICE, `0x3e5` | Service logon uses Advapi/Negotiate and local address placeholders; plausible. |
| Security 4672 | DC-02, `13:00:33.6371669`, LOCAL SERVICE, `0x3e5` | Principal and LUID agree with the preceding service logon. |
| Security 4625 | DC-02, `15:13:47.8535750`, jennifer.walsh | Type 3 NTLM, `Status=0xc000006d`, disabled-account substatus `0xc0000072`, audit-failure keywords; plausible. |
| Security 4634 | DC-02, `13:04:48.2650250`, diego.ramirez, `0xcb5c02d` | Expected target identity and logon-type fields. |
| Security 4688 v2 | DC-02, `13:05:36.8946664`, taskhostw.exe | Hex `NewProcessId=0x1c58`, parent PID `0x1408`, system integrity SID and version-2 target fields; plausible. |
| Security 4689 | DC-02, `13:01:20.1204409`, spoolsv.exe | Hex process ID and exit status have expected forms; creation may predate the slice. |
| Security 4768 | DC-02, `13:11:25.3188390`, MAC-MROSS-02$ | krbtgt service, domain SID, IPv4-mapped IPv6 client, AES encryption identifier and empty certificate fields are plausible. |
| Security 4769 | DC-02, `13:01:20.9893879`, DC-01$ to DC-02$ | Service-account name, service SID, ticket options and encryption fields are credible. |
| Security 4771 | DC-02, `16:00:33.0305527`, diego.ramirez | Preauthentication type 2 and failure `0x18`, with audit-failure keywords; plausible. |
| Security 4776 | DC-02, `13:13:10.4730895`, diego.ramirez | Native authentication-package and workstation fields; plausible. |
| Security 5145 | FILE-SRV-01, `13:00:05.9658107` | Share, relative path, access mask, client and LUID are internally coherent. |
| Security 4656 / 4663 / 4658 | FILE-SRV-01, `13:00:05.9844267` / `06.1459007` / `09.7044242` | Same handle `0xec6f2c02`, user, LUID and PID; open/use/close ordering is sound. The extra 4658 ProcessName is the noted schema concern. |
| Security 5156 v1 | DC-02, `13:00:48.6655519` | Decimal `ProcessID=5136`, device path, outbound token, numeric UDP protocol 17 and address/port fields; plausible. |
| Sysmon 1 | DC-02, `13:05:36.7983456`, PID 7256 | PID equals Security `0x1c58`; image and parent PID agree. Event-specific time is millisecond precision, envelope time is finer. |
| Sysmon 3 | DC-02, `13:00:48.9165633` | PID 5136, UDP, source port 57480 to DNS port 53; agrees with the WFP tuple. |
| Sysmon 5 | DC-02, `13:01:20.0120336`, PID 5904 | GUID and image retained for termination; matches the Security exit PID `0x1710`. |
| Sysmon 7 | DC-02, `13:31:01.6992915` | explorer.exe loads FileSyncShell64.dll; signature, module hashes and file metadata have plausible source shape. |
| Sysmon 8 | DC-02, `15:52:12.5542600` | Source/target process identities, remote thread ID and start address/module/function are present in the appropriate shape. |
| Sysmon 10 | DC-02, `13:00:30.0553589` | SourceProcessGUID/TargetProcessGUID capitalization, thread ID, access mask and pipe-separated call trace are credible. |
| Sysmon 11 / 13 / 22 | DC-02, `14:30:40.2064964` / `13:50:13.3638550` / `13:00:48.6988320` | File-create time/path, SetValue registry payload and DNS query/result fields respectively have appropriate source-specific forms. |

The sample Security 4656/4663/4658 chain uses the same `marcus.chen` SID and LUID `0xf62b74b`. Security 5145 describes `Servers\archive-final.bak` under the ClinicalExports share, and the file-audit object path ends in that same relative name. This would support useful access-correlation rules.

Well-known logon IDs such as `0x3e7` can already exist before a visible service-logon record, and Type 7 unlocks can refer to an existing user session. I excluded those cases from causal-failure findings.

### Network detection and content identity

The three Zeek sensor directories have conventional flattened `id.orig_h`, `id.orig_p`, `id.resp_h` and `id.resp_p` fields. Numeric timestamps, ports and counters remain numeric, and booleans remain booleans. The packet-accounting scan found no payload greater than the recorded IP bytes and no positive payload paired with zero packets; this is a basic bound check, not packet-capture reconstruction.

For example, `zeek-db/conn.json` begins with UID `Co6NB2pGpBGSqeVuRm`, APP `10.10.3.10:37756` to DB `10.10.4.10:3306`, TCP/mysql, `SF`, duration 4.322315 seconds and nonzero traffic in both directions. The file also contains rejected and reset traffic, which preserves useful state distinctions for detections.

There is one unmatched SMB mapping UID, `CDvU7F7ECk5HefE3QX`, at `zeek-core/smb_mapping.json` line 94. An unmatched companion can result from collection loss or a sliced connection; it is not sufficient here to score a synthetic defect. All matched protocol tuples passed the tested tuple and timing bounds.

Certificate objects provide a stronger positive test than merely having references present. UID `C1nZUCFwxDSH9BVjF2a` references certificate FUID `FN4B18fAh0UccOJ5Ofe` in `zeek-db/ssl.json`; `files.json` and `x509.json` agree on SHA1/fingerprint `61c2ffe5557cb932e97317235c4f81b5f9b89508`. Repeated appearances retain that certificate's metadata and byte size.

### macOS semantics and the timing indicator

The ES stream declares message version 11 and has separate event numbers 11/fork, 9/exec and 15/exit. On MAC-MROSS-02, the first fork creates PID 88252 with pidversion 12 and inherited launchd image; the following exec retains PID 88252, advances pidversion to 13 and names xpcproxy as target. Per-event sequence counters advance independently, while the global counter advances across types. These checks pass; first occurrences of each event type legitimately have sequence zero.

Executable inode/device metadata did not change inconsistently between repeated observations on a host. Notification `action_type=1` was not interpreted as an independent policy denial. The MAC-MROSS-01 Unified Log message saying policy “would not allow” MeetingAssist was not used to assert that execution actually failed or that later activity was impossible.

The negative finding is narrow: 61 shell-origin fork notifications across the two Macs contain three clusters of repeated microsecond fractions, involving ten launches altogether. The remaining shell forks have distinct fractions. Scripted command scheduling is a possible alternative explanation, but repeatedly retaining the exact microsecond phase while allowing different command and elapsed-time values looks more like intended timestamps being directly rendered than kernel timing being observed. This drives most of the synthetic-confidence score; it is not an impossible-ordering claim.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS ES fork notifications | Three clusters, ten of 61 shell-origin forks, across both Macs | Main indicator: exact microsecond phases survive independent launches at whole-second offsets. Strong enough to favor synthetic, with a scripted-scheduling caveat. |
| schema_or_format | Windows Security 4658 v0 XML | 47 records | Small additional weight: extra ProcessName field differs from the native version-0 payload; collector enrichment remains possible. |

No demonstrated hard contradiction was necessary for this verdict. The two findings do not justify a score in the 81–100 band.

## Realism Score by Category

- **Field format accuracy:** 9 — Broadly credible XML/JSON and event-specific payloads; 4658 contains an extra native-payload field.
- **Temporal patterns:** 6 — Most lifecycles and protocol timing pass, but three ES command clusters have conspicuously identical microsecond phases.
- **Cross-source correlation:** 9 — Strong PID/GUID, handle, tuple and certificate identity consistency in the tested relationships.
- **Behavioral realism:** 8 — Mixed routine and suspicious behavior with credible process ownership and service activity; no penalty for intrusion narrative shape.
- **Environmental consistency:** 9 — Platform-appropriate endpoint representations and service/network relationships; no demonstrated impossible host placement.

## Recommendations

- If this were synthetic, separate command intent times from observed fork timestamps and include realistic scheduler/system-call timing variation. The three ES clusters should not preserve identical microsecond fractions through independent launches; retain causal relationships while varying actual observation timing.
- If this were synthetic and intended to reproduce raw Windows XML, remove ProcessName from the 4658 version-0 EventData payload. If it is deliberate enrichment, preserve that value in a clearly separate enrichment representation so source-schema validation remains meaningful.
- Preserve the existing process, handle, certificate and tuple identity relationships when making those changes. The checked lifecycles and correlated content are already credible and should remain coherent.
