# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 65
**Synthetic-Confidence Score:** 18

## Executive Summary

The examined records are production-like from a detection engineering perspective: their native field shapes, numeric conventions, process identities, and independently joined network and authentication evidence are coherent. I did not establish a source-native contradiction or a score-bearing synthetic distribution artifact in this bounded review; the modest verdict confidence reflects that good synthetic telemetry could satisfy these same checks.

## Evidence For Synthetic

- No concrete, score-bearing synthetic indicator was established. I tested exact process GUID lifecycle relationships, host-local logon identities, hash encodings, transport tuples, and several native event shapes; the checks below did not expose an impossible value or causal inversion.
- Potential concerns about pre-window process/session initiators, thin macOS Unified Log coverage, and complete Zeek UID joins were excluded. These do not demonstrate synthetic origin under the stated collection assumptions.

## Evidence For Real

- Windows records use event-specific native representations instead of one generic shape. For example, Security 4688 uses hexadecimal `NewProcessId`, Sysmon 1 uses decimal `ProcessId`, WFP 5156 uses decimal `ProcessID` and a device path, and 1102 uses the eventlog `UserData/LogFileCleared` namespace rather than a fabricated generic EventData layout.
- All 1,017 observed SHA1, MD5, and SHA256 values in Sysmon `Hashes` have their expected 40-, 32-, and 64-character widths; all 1,006 IMPHASH values have 32 characters. This eliminates a common parser/value-format failure, although it does not prove the underlying bytes exist.
- Across 12,867 inspected Sysmon process-GUID references, no dependent event was visibly before its matching in-window process creation or after its matching termination, with a 10 ms tolerance on source timestamps. Exact GUID identity was used, rather than PID alone.
- All 13,662 examined Zeek DNS/HTTP/TLS rows across the three sensors join to their local `conn.json` UID with identical originator/responder IP addresses and ports. Cross-sensor UIDs are appropriately independent; the shared SSH tuple below has different UIDs and slightly different observation times at core and DMZ sensors.
- A concrete RDP session has transport-before-authentication ordering, a close aligned with disconnection, and a later logoff that correctly allows the disconnected Windows session to outlive its TCP connection.
- Linux SSH records preserve the same user, client port, sshd PID, PAM session and normalized session identity; macOS ES records distinguish fork, exec and exit, including pre/post-exec identities rather than treating every execution as a new PID.

## Detailed Analysis

### Scope and method

Only the assigned data directory and briefing were read. XML was parsed using its Windows Event XML namespace and JSON/NDJSON was decoded as actual records. The visible examples are from November 2, 2026. Aggregate checks covered 19,224 Security records, the supplied Sysmon XML files and 24,092 Zeek connection records; these aggregate checks are narrower than exhaustive schema validation.

Representative field review covered Security 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, 5156 and 1102; Sysmon process, access, network, image-load, DNS and registry examples; and Zeek DNS, HTTP, TLS, file, SMB, DHCP and certificate examples. Linux syslog, normalized eCAR, macOS Unified Log and ES records were also inspected. I did not run a vendor collector or claim exhaustive validation of unfamiliar version-specific Apple fields.

### Windows schema and value checks

In `DC-02.meridianhcs.local/windows_event_security.xml`, the 13:04:34.4786190Z Event 4688 is version 2. It has `NewProcessId=0x1cf8`, `NewProcessName=C:\Windows\System32\taskhostw.exe`, creator `ProcessId=0x1408`, `ParentProcessName=C:\Windows\System32\svchost.exe`, `TokenElevationType=%%1936`, and System integrity SID `S-1-16-16384`. The corresponding Sysmon 1 at 13:04:34.1647649Z has `ProcessId=7416`, parent PID 5128, the same image and parent image, and `LogonId=0x3e7`. The hexadecimal/decimal conversions agree exactly. The differing source timestamps are not treated as two different processes.

The same host's 13:05:08.5265115Z Event 4624 has service logon type 5, `NETWORK SERVICE`, SID `S-1-5-20`, LUID `0x3e4`, process `services.exe`, and no fabricated remote endpoint (`IpAddress=-`, `IpPort=-`). Its 4672 at 13:05:08.5319132Z carries the same service identity and a plausible limited privilege set. Conversely, the workstation failure at `WS-PPATEL-01.meridianhcs.local/windows_event_security.xml`, 15:36:19.7737669Z, is type 2 with `User32`, `winlogon.exe`, `Status=0xc000006d`, `SubStatus=0xc000006a` and failure keyword `0x8010000000000000`. These distinguish local interactive failure from remote logon behavior.

DC-02's 13:00:00.7564960Z WFP 5156 uses `ProcessID=5272`, `Application=\device\harddiskvolume3\windows\system32\dns.exe`, numeric protocol 17 and inbound direction token `%%14592`. The corresponding Sysmon network event uses `ProcessId=5272`, `Image=C:\Windows\System32\dns.exe`, `Protocol=udp`, `Initiated=false`, and tuple `10.10.2.20:58104 -> 10.10.2.11:53`. A SIEM must preserve the different case-sensitive native field names and direction encodings, but the records themselves are compatible.

The DC-01 1102 at 18:42:12.4201069Z uses the Microsoft-Windows-Eventlog provider and namespaced `LogFileCleared` userdata, with `EventRecordID=1`. A record-number reset around a visible audit-log clear is not evidence of an impossible decreasing sequence.

### Exact session and process lifecycle checks

There are 406 Event 4634 rows. Of these, 403 have a matching in-window 4624 on the same host and `TargetLogonId`; I found no mismatched target identity or impossible logoff-before-logon relationship in those joins. The remaining three cannot be rejected merely because their initiators are outside the supplied slice. A type-7 unlock can reuse a previously established interactive LUID: on WS-SMARTINEZ-01, LUID `0xc162b95` later has a type-2 final logoff. Selecting only the latest 4624 would incorrectly call this a type mismatch.

For process lifecycles I compared lowercased complete GUIDs in `ProcessGuid`, `SourceProcessGUID`/`SourceProcessGuid` and `TargetProcessGUID`/`TargetProcessGuid` to matching creation and termination rows on the same host. No contradiction was found among 12,867 references. This does not assert that every referenced process begins inside the window, and it does not penalize those that do not.

### Cross-source RDP join

In `zeek-core/conn.json`, UID `C9CW7SDpuCGUO32sSu` is the successful TCP RDP connection `10.10.1.35:59768 -> 10.10.2.10:3389`:

- Start: 13:54:21.666689Z, `conn_state=SF`, duration 168.116311 seconds.
- Transport close implied by start plus duration: 13:57:09.783000Z.
- In `DC-01.meridianhcs.local/windows_event_security.xml`, Event 4624 at 13:54:28.6047546Z records `aisha.johnson`, type 10, source `::ffff:10.10.1.35`, port 59768, LUID `0x53e0a9b`.
- Event 4779 at 13:57:09.9995844Z records the same LUID, user and client IP, session `RDP-Tcp#6`.
- Event 4634 at 14:07:06.7227332Z records final type-10 logoff for that LUID.

Transport opens before authentication, disconnection is about 217 ms after network close, and final logoff is later. The last interval is compatible with a disconnected session and must not be mislabeled as authentication surviving an impossible transport lifetime.

### Cross-source Linux SSH join

`WEB-EXT-01.meridianhcs.local/syslog.log` records `sshd[2696510]` accepting a public key for `aisha.johnson` from `10.10.1.35` port 61284 at 13:25:18.805366Z, followed by PAM session-open at 13:25:18.852945Z and logind session 213 at 13:25:19.561727Z. In its `ecar.json`, successful SSH LOGIN uses the same user, client IP/port, `session_id=213` and LUID `0x135d10e2`, with a source timestamp of 13:25:18.362Z.

`zeek-core/conn.json` UID `CUpUIpd4aCFfBOFJHys` opens that exact tuple to WEB-EXT-01 (`10.10.3.10:22`) at 13:25:09.606046Z. `zeek-dmz/conn.json` sees the same tuple at 13:25:09.489822Z with its own UID `CTpk0uHaVyHdmzOFgPH`. Both report successful SSH and approximately 3,191.21 seconds duration. The source timestamp offsets are subsecond, and neither endpoint authentication view predates transport open. LOGOUT in eCAR retains the same session object and identity.

### Zeek parser and counter checks

DNS/HTTP/TLS join denominators are respectively 39/15/22 at zeek-db, 3,360/2,566/401 at zeek-core, and 1,232/2,828/3,199 at zeek-dmz. None has a missing sensor-local conn UID or mismatched 4-tuple. This supports usefulness to correlation rules; complete joins are not themselves an authenticity indicator.

Connection counters were also checked across 462 DB, 12,961 core and 10,669 DMZ connections. No direction has positive byte counters with zero packets, and none reports IP bytes less than payload bytes plus 20 bytes per observed packet. This is a basic necessary consistency check, not a complete packet-level reconstruction.

At 13:00:00.006178Z, DNS UID `ClnAf4xMznbwm13HlN` has the same UDP tuple and duration/RTT 0.000469 in DNS and conn, an A query with numeric/name pairs `qtype=1/A` and `rcode=0/NOERROR`, string answer array and floating TTL array. The DNS query for DC-01 is answered by DC-02; that is normal DNS service behavior, not a hostname/IP contradiction. CONNECT records to the proxy use HTTP method CONNECT, authority-form URI and `200 Connection Established` with zero entity body; that does not imply the tunneled HTTPS response was zero length.

### macOS interpretation

MAC-MROSS-01 ES records declare message `version=11`. PID 41136 is first observed as a launchd fork child at 13:00:06.950823000Z, then an exec target `/usr/libexec/xpcproxy` with incremented pidversion at 13:00:06.953308000Z, then a Chrome exec target at 13:00:06.958279000Z, and exits at 13:00:29.844683000Z. The actor/target executable distinction and pidversion transitions are preserved. The supplied ES streams contain fork/exec/exit notifications; I do not demand absent native filesystem or network notifications from a collector that may have selected those types.

Unified Log retains writer/sender paths, message types, boot UUID and Mach timestamps separately from ES. The AppleSystemPolicy message at 15:41:38.735570Z says it “would not allow” MeetingAssist PID 62451. That text alone is not a demonstrated enforcement decision, and I did not infer a denial/child-execution contradiction from it. Normalized eCAR FLOW records are not native ES network events.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| No demonstrated score-bearing indicator | Windows, Zeek, Linux, sampled macOS | Bounded representative field review and stated aggregate checks | No upward adjustment for a verified defect |
| Excluded candidate: missing out-of-window initiators | Windows process/session lifecycles | References without visible starts | Not scored; a bounded window can contain existing state |
| Excluded candidate: complete UID joins / selective native sources | Zeek and macOS | Supplied source selection | Not scored; collection completeness or selection alone is invalid evidence |

## Realism Score by Category

- **Field format accuracy:** 9 — Representative native Windows and network event shapes, encodings and hash widths are credible; Apple version-specific conformance was not exhaustively certified.
- **Temporal patterns:** 9 — The examined exact identities have sensible process and transport/authentication ordering and source-specific subsecond offsets.
- **Cross-source correlation:** 10 — Exact sampled SSH/RDP chains and the enumerated Zeek tuple joins are consistent; no same-GUID lifecycle inversion was demonstrated.
- **Behavioral realism:** 9 — Service, interactive, failed-authentication, remote-session and disconnected-session distinctions are preserved in the observed examples.
- **Environmental consistency:** 9 — Mixed platform telemetry uses platform-appropriate paths and source semantics; no demonstrated host-role or collection-profile contradiction emerged.

## Recommendations

- No corrective recommendation is supported by a demonstrated defect in this review. If this were synthetic, preserve the observed event-specific native field types, exact identity ownership, transport-before-authentication ordering and disconnected-session semantics; changing those would reduce its usefulness to detection rules.
- For further validation, extend the same exact-identity checks to additional source-native event versions and packet/protocol detail. This is a bounded-review limitation, not a finding that the supplied records lack those sources or behaviors.
