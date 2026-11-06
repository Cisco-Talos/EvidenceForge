# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 64

## Executive Summary

The data is highly usable for SIEM ingestion and preserves many difficult process, session, and network relationships. My synthetic verdict rests principally on browser executable versions disagreeing with User-Agent versions on precisely correlated connections, supported by an unusually degenerate process-exit-status distribution; I did not establish an impossible process lifecycle or malformed native event family.

## Evidence For Synthetic

- [contract_gap] Browser version truth diverges between endpoint and network evidence. In `WS-PPATEL-01.meridianhcs.local/windows_event_sysmon.xml:4316`, Event 1 identifies PID 6220, GUID `{398565f9-adbe-6ae8-ed00-0000fd852777}`, as Chrome `120.0.6099.225`. Its Event 3 at line 4753 uses `10.10.1.32:55457 → 10.10.3.20:8080`; the exact tuple in `zeek-core/http.json:675` advertises `Chrome/119.0.0.0`. The loaded `chrome_elf.dll` at Sysmon line 4361 also has version `120.0.6099.225`, supporting the endpoint version rather than the HTTP version.
- [contract_gap] This is not one anomalous request. Joining `zeek-core/http.json` to Windows Sysmon Event 3 tuples and then to Event 1 ProcessGuids produced 286 browser-associated HTTP rows: 47 Chrome-120 rows advertise Chrome 119, 46 advertise Chrome 121, and 102 Firefox-121 rows advertise Firefox 120. Thus 195/286 disagree at the major-version level. These are request counts, not independent machines or incidents. UA overrides, compatibility policies, or HTTP rewriting could explain individual cases, so this is a consistency defect rather than proof of impossibility.
- [distribution_texture] All 769 Windows Security Event 4689 records across the ten Windows hosts have `Status=0x0`, spanning 62 executable basenames, including shells, SSH, installers, service binaries, and administrative tools. For example, `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml:3` ends `ssh.exe` at `2026-11-02T13:00:34.3684724Z` with zero status. Separately, all 43 ES exit notifications on each Mac have `event.exit.stat=0` (86 total), including `MAC-MROSS-01.../macos_endpoint_security.ndjson:142–152` and `MAC-MROSS-02.../macos_endpoint_security.ndjson:140–151`. Successful exits are ordinary, but the joint distribution has no nonzero or signal-termination tail. This is a moderate statistical concern, not an impossible field value.
- [weak_signal] Linux administrative commands sometimes substitute protocol or package vocabulary for likely service-unit names: `WS-LNGUYEN-01.../syslog.log:105` runs `systemctl status smbclient --no-pager`; `MAIL-EDGE-01.../syslog.log:110` runs `systemctl status smtp --no-pager`. These can be legitimate diagnostics that return “unit not found,” and custom aliases remain possible. I give this little weight; the supplied logs do not demonstrate the commands' results.

## Evidence For Real

- The Windows XML parses with proper event namespaces, provider identities, source-specific channels, hex Security PIDs versus decimal Sysmon PIDs, SID-shaped principals, and event-version-dependent field sets. I found no broad parser-breaking schema defect.
- Across every supplied Sysmon file, checks using visible ProcessGuid identities found no dependent event preceding its visible creation and no dependent/parent reference after its visible termination. Pre-window processes and post-window survivors were treated neutrally.
- All 20,741 Zeek connection rows across core, DMZ, and DB sensors passed basic nonnegative-duration and IP-byte-versus-payload checks. Protocol rows with matching connection UIDs showed no tuple mismatch and no timestamp outside the connection interval by more than the 50 ms tolerance used in this check.
- `DC-02.../windows_event_security.xml:4507` logs a Type 3 Kerberos login for `WS-MCHEN-01$`, LUID `0xcb676af`, at `13:10:34.7411311Z`; line 5135 logs the corresponding Type 3 logoff at `13:10:59.4737923Z` with the same SID and LUID.
- The macOS data preserves fork versus exec distinctions, pre-exec actor versus post-exec target identities, and PID-version changes. No visible `(pid,pidversion)` actor occurrence preceded its observed fork/exec identity or followed its observed exit in my checks.
- Linux SSH records have distinct connection, authentication, PAM-session, and logind stages. For example, `DB-PROD-01.../syslog.log:8–11` progresses from connection at `13:08:29.587455Z`, to public-key acceptance at `13:08:31.088422Z`, to PAM open and logind session 276589, rather than collapsing the lifecycle into one line.

## Detailed Analysis

### Scope and method

I examined only files in the supplied data directory. I parsed all Windows XML events, all macOS ES records, Zeek connection/protocol JSON for the stated integrity checks, and eCAR records for actor lifecycle checks; I also inspected Linux, proxy, firewall, shell-history, and Unified Log examples. References use one-based physical file lines; for XML, the cited line is the opening `<Event>` line. I did not require omitted Sysmon types or additional endpoint products, and did not use domain resolution, copied-file timestamps, or completeness of attack coverage as authenticity indicators.

### Native schemas and ingestion behavior

The following samples were explicitly inspected rather than inferred from filenames:

| Source and line | Event or record | Checks and result |
|---|---|---|
| DC-02 Security:4507 | 4624 v2 | Type 3, Kerberos, mapped IPv4 source, target SID/LUID and v2 token fields are coherent. |
| DC-02 Security:5135 | 4634 | Target SID/LUID and LogonType match the preceding login. |
| DC-02 Security:113789 | 4625 | Audit-failure keywords, NTLM package, status `0xc000006d` with disabled-account substatus `0xc0000072`; reasonable combination. |
| WS-PPATEL Security:13718 | 4648 | Subject/caller fields, target credentials/server, hex caller PID, and source address are structurally appropriate. |
| FILE-SRV-01 Security:9711 | 4656 v1 | File handle `0xc989ded5`, access list and mask, object path and subject are present. |
| FILE-SRV-01 Security:9760 | 4663 v1 | Same handle/path/subject, read access `0x1`, between handle request and close. |
| FILE-SRV-01 Security:9801 | 4658 | Same handle and PID `0x4`, later close; no visible handle inversion. |
| DC-02 Security:4658 | 4672 | LOCAL SERVICE SID `S-1-5-19`, LUID `0x3e5`, privilege-list representation are plausible. |
| DC-02 Security:526 | 4688 v2 | Hex new/parent PIDs, parent image, command line, target-subject fields, mandatory label are consistent with the declared version. |
| WS-MCHEN Security:3 | 4689 | Proper termination fields; zero status contributes to the aggregate distribution concern. |
| DC-02 Security:171932 | 4697 | Service name, executable, type `0x10`, demand start `3`, LocalSystem account are intelligible. |
| DC-02 Security:809 | 4768 | krbtgt service, encryption `0x12`, PreAuthType 2, certificate fields and mapped client address are parseable. |
| DC-02 Security:120 | 4769 | Computer service principal, ticket options, encryption and client tuple have the expected shapes. |
| DC-02 Security:55584 | 4771 | Failure status `0x12`, preauthentication metadata and client tuple form a plausible failure event. |
| DC-02 Security:5415 | 4776 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation, account and status have source-native field names. |
| WS-PPATEL Sysmon:4316 | 1 | Process/parent GUIDs, decimal PIDs, hashes, token and image metadata parse correctly; version conflicts with joined HTTP UA. |
| WS-MCHEN Sysmon:38 | 5 | ProcessGuid, PID, image, user and UtcTime represent termination with no fabricated parent fields. |
| WS-MCHEN Sysmon:3 | 10 | Source/target GUIDs and PIDs, source thread, images, access mask and call trace are appropriately distinct. |
| DC-02 Sysmon:15640 | 8 | Source/target identities, new thread, address/module/function fields are present. |
| DC-02 Sysmon:3099 | 13 | SetValue, registry target and `DWORD (0x00000000)` are intelligible source-native data. |
| DC-02 Sysmon:659 | 22 | QueryName, QueryStatus, QueryResults and process identity are coherent. |
| zeek-core dns:1 | DNS | Numeric qtype/rcode, boolean flags, answer and TTL arrays, UDP tuple and transaction ID are appropriately typed. |
| zeek-core dhcp:1 | DHCP | `uids` array, REQUEST/ACK sequence, MAC, assigned address and numeric lease/duration are sensible. |
| MAC-MROSS-01 ES:1–2 | Fork and exec | Message version 11, action type 1, event types 11/9, child and target structures, pidversion 10→11 agree with distinct fork/exec observations. |

This is a field-level review from supplied records, not a certification against every platform release's complete event manifest. Unfamiliar optional macOS fields were not scored as errors.

### Browser identity consistency

Two further independently reproducible joins illustrate the principal concern:

- `WS-SMARTINEZ-01.../windows_event_sysmon.xml:2072`: Chrome PID 6684, FileVersion `120.0.6099.225`, created at `14:10:27.835`. Event 3 at line 2370 uses `10.10.1.36:55384 → 10.10.3.20:8080`. `zeek-core/http.json:208`, UID `C57FOFk1A0m06U9tya`, advertises Chrome `121.0.0.0` on that tuple.
- `WS-DRAMIREZ-01.../windows_event_sysmon.xml:3740`: Firefox PID 6672, FileVersion `121.0`, created at `14:40:45.592`. Event 3 at line 3899 uses `10.10.1.34:53117 → 10.10.3.20:8080`. `zeek-core/http.json:383`, UID `CjeWQrhH7aop08ggwK`, advertises both `rv:120.0` and `Firefox/120.0`.

UA minor/build reduction does not explain a change in major version. This would materially affect detection rules comparing endpoint software inventory to network client identity. The possibility of intentional UA configuration prevents me from labeling these hard contradictions; their repeated appearance across applications and hosts is what makes the pattern persuasive.

### Lifecycle and temporal counterchecks

The initial temptation to treat repeated 4624 LUIDs as new-session collisions was rejected after checking LogonType: workstation unlocks are Type 7 and reuse the existing interactive identity. For example, WS-PPATEL Security line 10239 creates Type 2 LUID `0xd9e997a` at `15:35:26.3365146Z`; lines 17493 and 19871 are later Type 7 observations, not proof that earlier processes preceded the session.

The Zeek checks compared protocol timestamps to connection start plus duration with a 50 ms allowance, and compared all four tuple members whenever present. They found no qualifying failure. The eCAR check likewise found no visible actorID reference before that actor's observed creation or after termination. These checks strongly limit the case for claiming a fundamental temporal/correlation defect.

The Unified Log policy message at `MAC-MROSS-01.../macos_unified_log.ndjson:2` says “Security policy would not allow process” for MeetingAssist. I did not interpret this alone as a confirmed execution denial or require a downstream child/effect record. ES notifications and normalized eCAR FLOW rows were assessed as different source types.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Sysmon process/network + Zeek HTTP | 195 of 286 browser-associated core HTTP rows disagree on browser major version | Principal indicator; exact process-to-tuple joins make the discrepancy reproducible. UA overrides remain a possible real-world explanation. |
| distribution_texture | Security 4689 + macOS ES exit | 769 Windows exits across 62 executable basenames; 86 Mac exits; all zero | Supporting distribution concern, with no claim that a particular zero is impossible. |
| weak_signal | Linux sudo/systemd diagnostics | Protocol/package-shaped unit names in concrete commands | Small contribution only; custom units or unsuccessful diagnostics could explain it. |

No demonstrated hard contradiction or dataset-wide parsing failure contributed to this score.

## Realism Score by Category

- **Field format accuracy:** 9 — Examined schemas and types are largely convincing and directly ingestible.
- **Temporal patterns:** 9 — Visible process and network lifecycle checks passed; timestamp precision is source-appropriate.
- **Cross-source correlation:** 7 — Strong identity/tuple integrity, reduced by systematic browser-version disagreement.
- **Behavioral realism:** 7 — Broad activity variation, but exit outcomes have a weak long tail and some administrative vocabulary is questionable.
- **Environmental consistency:** 8 — Host and OS roles generally fit their records; browser metadata/client identity needs explanation.

## Recommendations

- If this were synthetic, make process FileVersion, loaded browser-module versions, and per-connection HTTP User-Agent derive from the same browser installation identity. Preserve intentional spoofing only where it is explicitly part of the modeled behavior.
- If this were synthetic, represent process exit outcomes according to the command/application and shutdown circumstances rather than defaulting every Windows and Mac exit to zero. Add nonzero/signal outcomes only where the visible behavior supports them.
- If this were synthetic, use host-specific actual service-unit names for service-management commands, or include the resulting unsuccessful diagnostic behavior when operators query package/protocol labels such as `smbclient` or `smtp`.
