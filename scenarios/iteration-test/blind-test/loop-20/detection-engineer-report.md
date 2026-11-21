# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 63

## Executive Summary

The dataset is largely usable by a detection stack: structured records parse successfully, Windows identities are coherent, and the network and endpoint lifecycle checks generally hold. I favor synthetic because three separate macOS command bursts preserve an identical microsecond phase across commands tens of seconds apart, including matching whole-second increments in the independent-looking Mach clock fields; this is a strong timing distribution artifact, rather than an impossible lifecycle. My score reflects that bounded artifact and a weaker Linux message-value concern, not the completeness or narrative shape of the observed activity.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41, and 44 record `/bin/zsh` forks at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z`, and `13:50:02.198588000Z` on November 2. The children subsequently execute curl, bash, ls, and id. Their spacings are exactly 27, 35, and 19 seconds, preserving all six meaningful fractional digits. Their `mach_time` increments are exactly `648000000`, `840000000`, and `456000000`, consistent with precisely those intervals at 24 million ticks per second. This is not merely whole-second shell-history precision: it appears in the purported native fork observations, while nearby exec observations have individual millisecond offsets.
- [distribution_texture] The same phenomenon recurs in two other bursts: MAC-MROSS-01 lines 53/56/59 at `14:37:50.487145000Z`, `14:38:28.487145000Z`, and `14:38:57.487145000Z`; MAC-MROSS-02 lines 86/89/92 at `15:30:55.965208000Z`, `15:31:17.965208000Z`, and `15:31:58.965208000Z`. These are ten fork rows in three bursts among 103 fork rows on the two Macs. Repeated phase preservation in wall time and Mach time looks like scheduled event construction. An exporter reconstructing timestamps or deliberately scheduled activity could explain it, so I do not label it a hard contradiction.
- [weak_signal] Ten `cups-browsed` messages across three Linux clients put bare six-digit integers after a printer's location-like `at` clause. Examples are `WS-LNGUYEN-01.meridianhcs.local/syslog.log:6`, `13:11:38.454177Z`, `Browse remote printer FRONTDESK-MFP at 266642`; the same file line 245 uses `FINANCE-MFP at 997463`; `LT-MRIVERA-02.meridianhcs.local/syslog.log:51` uses `FRONTDESK-MFP at 142314`. These values provide no recognizable hostname, address, or URI for address-oriented parsing and resemble substituted template parameters. Because the message text is free form and collection transformations are unspecified, this receives little weight and is not asserted to violate a verified cups-browsed version's schema.

## Evidence For Real

- All 79,406 JSON/NDJSON records and all 29,236 Windows XML events parsed successfully. The sources retain useful distinctions: Windows hexadecimal PIDs/LUIDs, Sysmon decimal PIDs and braced GUIDs, numeric Zeek ports and booleans, and millisecond eCAR timestamps.
- FILE-SRV-01 shows a credible SMB audit chain for `marcus.chen`, LUID `0xf62b74b`: 4624 Type 3 at `13:00:05.2935079Z`, share/file access, handle closure, and 4634 at `13:00:12.5133334Z`. The client IP/port remain `10.10.1.31:54494`, and the share path resolves to a corresponding local file path.
- Across all ten Windows hosts, the Sysmon checks found no visible process event before its matching creation or after its matching termination, no visible parent creation after its child, and no image/PID/user drift for the same created ProcessGuid. Security 4688 image paths agreed with corresponding Sysmon process-create identities in the comparison performed.
- Zeek's 23,125 connection rows include successful, rejected, reset, incomplete, and unanswered traffic. Protocol rows joined to matching connection tuples, and checked protocol timestamps fell within connection intervals; HTTP body totals and file byte totals did not exceed their associated directional connection payload totals.
- The Macs distinguish ES exec/fork/exit notifications from Unified Log messages and normalized eCAR network/session observations. For example, MAC-MROSS-01's Terminal startup contains launchd, xpcproxy, Terminal, login, and zsh transitions, rather than treating each command as a child of an invented generic process.
- Collection-boundary effects are present and plausible. Several Linux logs open with an SSH/PAM session closing. I did not count missing pre-window session starts as defects.

## Detailed Analysis

### Scope and parsing

I examined only the supplied data directory. I parsed all structured records and ran dataset-wide joins on selected lifecycle and network contracts; this was not a complete formal validation against every product release's manifest or SDK. The structured inventory is 41,106 Zeek records, 37,971 eCAR records, 324 Endpoint Security notifications, five Unified Log records, and 29,236 Windows events, supplemented by Linux syslog, shell histories, proxy/web access, ASA, and IDS text logs.

The visible examples are from November 2, 2026, principally 13:00–19:00 UTC. I treated this as a time slice. I did not infer an absent product, audit facility, or event type from sparse coverage, and did not treat domains as authenticity evidence.

### Windows schemas and authentication semantics

The spot-check below covers substantially more than twenty distinct event/source shapes. Windows success/failure Keywords are differentiated; Security success events use Level 0, while Sysmon uses informational Level 4. The Windows XML namespace and provider/channel separation parse correctly. I found no SID associated with conflicting account names in the Security subject/target identity fields checked.

| Record checked | Specific observed values and detection-stack assessment |
| --- | --- |
| DC-01 Security 4624, `13:06:31.1470318Z` | Version 2, Type 5, LOCAL SERVICE, SID `S-1-5-19`, LUID `0x3e5`, `Advapi`/`Negotiate`, no remote IP; service logon semantics are coherent. |
| DC-01 Security 4672, `13:06:31.1596701Z` | Same LOCAL SERVICE identity and LUID, with token privileges including `SeImpersonatePrivilege`; preserves the logon relationship. |
| FILE-SRV-01 Security 4624, `13:00:05.2935079Z` | Type 3, NTLM/NTLM V2, client `::ffff:10.10.1.31:54494`, user marcus.chen; suitable network-logon fields. |
| FILE-SRV-01 Security 4634, `13:00:12.5133334Z` | Same user, Type 3, and `0xf62b74b`; closes after the visible access chain. |
| DC-01 Security 4625, `16:20:48.9577326Z` | Failure Keywords `0x8010000000000000`, status `0xc000006d`, substatus `0xc0000072`, Type 3; consistent with a disabled-account failure. |
| DC-01 Security 4648, `13:26:35.3357959Z` | Explicit `svc_backup` credentials, source process PID `0xf44`, target server DB-PROD-01; distinct subject and target credential fields are retained. |
| DC-01 Security 4688, `13:02:01.1422860Z` | Version 2, new PID `0xee8`, parent `0x930`, taskhostw image, token elevation resource value, mandatory label `S-1-16-16384`; parseable create semantics. |
| DC-01 Security 4689, `13:00:05.3779607Z` | PID `0xb64`, winlogon, status `0x0`; a terminate near the boundary is not intrinsically invalid. |
| FILE-SRV-01 Security 4656, `13:00:06.0000868Z` | Handle `0xc5b31bd7`, `ProcessId=0x4`, file `C:\Mounts\Archive\Clinical\Exports\Servers\archive-final.bak`, mask `0x12019f`. |
| FILE-SRV-01 Security 4663, `13:00:06.1459007Z` | Same handle/file/session, write mask `0x2` and `%%4417`; coherent object access. |
| FILE-SRV-01 Security 4658, `13:00:09.7044242Z` | Same handle and subject LUID; closure follows the file access. |
| FILE-SRV-01 Security 5145, `13:00:05.9658107Z` | Share `\\*\ClinicalExports`, local path `\??\C:\Mounts\Archive\Clinical\Exports`, relative file `Servers\archive-final.bak`; joins the local path above. |
| DC-02 Security 5156, `13:00:02.5627328Z` | Decimal PID 5272, device image path for dns.exe, UDP protocol 17, inbound resource value, client `10.10.1.31:57565` to port 53; expected WFP-oriented field conventions. |
| DC-02 Security 4768, `13:36:25.3804590Z` | krbtgt service, AES encryption `0x12`, preauthentication type 2, mapped IPv4 client; internally coherent ticket fields. |
| DC-02 Security 4769, `13:03:13.7575377Z` | Service `DC-02$`, client FILE-LNX-01$, success `0x0`; machine and service identities remain distinct. |
| DC-02 Security 4771, `18:45:08.2594541Z` | Failure Keywords, status `0x18`, preauthentication type 2; credential failure is represented distinctly from successful ticket issuance. |
| DC-02 Security 4776, `13:04:43.9915830Z` | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, account diego.ramirez, workstation WS-DRAMIREZ-01, success status. |
| DC-01 Security 4697, `17:00:12.0607909Z` | Service PSEXESVC, type `0x10`, demand-start value `3`, LocalSystem; useful service-install fields. |
| DC-01 Security 4698, `17:19:56.5732157Z` | Version 0 with escaped task XML, named SYSTEM principal and executable action; embedded task content is structured rather than an opaque command fragment. |
| DC-01 Security 4720/4724/4738 | `svc_dirsync`, SID ending 7841, creation at `17:15:07.3475948Z`, password reset at `17:15:08.9516065Z`, account change at `17:15:09.9400573Z`; identity continuity holds. |
| DC-01 Security 1102, `18:42:21.4159803Z` | Eventlog provider, `UserData/LogFileCleared` with its own namespace, record ID 1; distinct shape from ordinary Security EventData. |
| DC-02 Sysmon 1/5 | Process creation carries image, command line, parent identities, hashes and LogonId; termination uses the same kind of process identity, without inventing another PID namespace. |
| DC-02 Sysmon 3, `13:00:02.6083531Z` | UDP, `Initiated=false`, dns.exe PID 5272, same DNS transport tuple as WFP; field types and direction are plausible. |
| DC-02 Sysmon 10, `13:02:43.8573010Z` | Separate source/target GUIDs, PIDs and users, mask `0x1400`, call trace; preserves actor/target roles. |
| WS-PPATEL-01 Sysmon 7, `14:01:52.7507626Z` | OUTLOOK.EXE loads OLMAPI32.DLL, with separate image/hash/signature fields. |
| DC-02 Sysmon 8/13/22 | Remote-thread source/target fields, registry SetValue with DWORD details, and DNS QueryStatus/QueryResults have distinct shapes. |

A naive LUID check initially marks earlier workstation processes as preceding a later 4624. Examining the actual event resolves this: WS-DRAMIREZ-01's `17:12:27.2345185Z` 4624 is Type 7 (unlock), adjacent to 4801, using an already active LUID `0x96cfaea`. Likewise WS-MCHEN-01 has Type 7 unlocks for `0x6c29844`. These are not late creations of the original user sessions and were excluded from synthetic findings.

### Zeek and normalized endpoint correlation

All three sensors' protocol tuples matched the referenced conn rows where a connection was present. I checked protocol occurrence timestamps against connection start plus duration, payload versus IP byte totals, positive payload with zero packets, HTTP request/response body sums, directional file-byte sums, and overlapping TCP intervals for an identical oriented four-tuple. Those checks produced no concrete contradiction.

There is one unmatched reference: `zeek-core/smb_mapping.json:100` at epoch `1793640924.870101` references `CJqVWaauzqBwjEIOtb` for `10.10.1.22:56998 -> 10.10.2.20:445`, share ClinicalExports. The UID is absent from the supplied core conn file. A connection beginning before the slice can explain a mapping row without its conn row; I therefore give this no synthetic score and do not require an unseen connection's initiation to fall inside the window.

In eCAR PROCESS/OPEN records, the top-level PID describes the actor while `objectID` and `target_pid` describe the accessed process. Different actor PIDs opening the same object do not demonstrate process identity drift. Lifecycle checks distinguished these roles; the checks of created and terminated processes and dependent actor references found no visible inversion.

I also compared Linux UFW BLOCK tuples to the supplied Zeek connections: no blocked TCP tuple matched a successful/in-progress TCP connection state in this comparison. This supports plausible firewall/sensor behavior without requiring all dropped packets to be observed everywhere.

### macOS semantics and the principal timing artifact

The ES records declare message version 11 and separate fork child, exec target, and exit actor structures. For MAC-MROSS-01, lines 1–3 show launchd PID 1 forking PID 25527, exec to xpcproxy, then exec to Terminal. Audit-token PID versions change across exec while the PID and process start time persist. The sampled notification actors and targets retain signing identity and file metadata. I did not find a visible use of an already-exited identical `(pid, pidversion)` actor.

The kernel Unified Log message at `15:42:09.009673+0000` says security policy would not allow MeetingAssist PID 42008. That wording alone does not prove successful execution or establish that later unrelated process activity belongs to that executable. I found no basis for turning that policy observation into an authorization-versus-execution contradiction. Native ES rows were not required to contain normalized EDR FLOW semantics.

The timing concern is narrower and measurable. For example, MAC-MROSS-01's four repeated-phase forks retain `.198588000` but their following exec observations occur at `.201976000`, `.207155000`, `.205524000`, and `.207561000`. This is not a general timestamp precision reduction applied uniformly to the stream. It looks as though one exact burst anchor was reused for the command starts and separate delays were applied to exec. The two additional bursts strengthen that inference. I count all three bursts as one related timing mechanism, not three independent implementation defects.

### Linux field-value texture and limitations

Linux records otherwise have credible RFC 5424 envelopes and host-appropriate process names, including sshd/PAM, systemd-logind, sudo, CRON, dhclient, resolved, rsyslogd, and desktop services. Sudo command and PAM records preserve the invoking user and root target distinction. The repeated printer message shape is the one retained value-quality concern; it is not enough by itself to distinguish a synthetic template from a local collector transformation.

No score was added for absent selected Sysmon event types, thin Unified Log coverage, complete cross-source joins, a compact suspicious sequence, lack of visible attacker mistakes, or filesystem copy timestamps.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
| --- | --- | --- | --- |
| distribution_texture | macOS Endpoint Security | Ten fork rows in three command bursts across two Macs; 103 fork rows total | Main reason for favoring synthetic: independent command starts preserve exact microsecond and whole-second Mach-clock phase despite individually variable exec delays. Strong artifact, not impossible causality. |
| weak_signal | Linux cups-browsed syslog | Ten messages on WS-LNGUYEN-01, WS-OHADDAD-01, LT-MRIVERA-02 | Small contribution: location-like fields contain bare six-digit numbers across printer names; transformation/version uncertainty limits its weight. |

## Realism Score by Category

- **Field format accuracy:** 9 — All structured records parse, sampled Windows event shapes and identifier conventions are convincing; Linux printer message values remain questionable.
- **Temporal patterns:** 6 — Most ordering and source timing is sound, but three native macOS fork bursts preserve an implausibly exact fractional phase.
- **Cross-source correlation:** 9 — Checked process identities, transport tuples, byte accounting, and session/file relationships hold; the single unmatched SMB reference is slice-compatible.
- **Behavioral realism:** 8 — User, service, desktop, network-failure and maintenance behavior is varied; timestamp scheduling texture weakens the shell-command observations.
- **Environmental consistency:** 9 — Windows, Linux and macOS source semantics generally remain distinct, and no demonstrated host-role/platform contradiction emerged.

## Recommendations

- If this were synthetic, timestamp each macOS command fork from a realistic execution-time model rather than preserving an exact fractional burst anchor over integer-second offsets. Keep wall and Mach clocks mutually consistent, and preserve the already plausible fork-to-exec relationships.
- If this were synthetic, replace the bare six-digit printer-location parameters with values supported by the intended cups-browsed message/version or explicitly preserve/document the collector's transformation. Use actual endpoint identifiers where the message purports to identify an endpoint.
- Retain the coherent process/session identities, source-specific actor/target semantics, byte accounting, and collection-window behavior. Do not add arbitrary missing events or break valid correlations merely to make the data appear messier.
