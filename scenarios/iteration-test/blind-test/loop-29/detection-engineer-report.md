# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 44

## Executive Summary

The data is largely compatible with a functioning detection stack: the XML and JSON parse, process identities remain stable, and the checked endpoint and network lifecycles agree. A repeated Windows native-schema anomaly, one unresolved SMB connection reference, and a small repeated-count pattern raise questions, but I found no demonstrated impossible lifecycle or field-value contradiction strong enough to establish synthetic origin.

## Evidence For Synthetic

- [schema_or_format] Every one of the 41 Security Event 4658 records in `FILE-SRV-01.meridianhcs.local/windows_event_security.xml` declares Version 0 but includes `EventData/ProcessName`. The standard Version 0 handle-close payload ends with `ProcessId`; `ProcessName` is not part of that native payload. For example, record 271780 at `2026-11-02T13:00:09.7044244Z` contains `ProcessId=0x4` and `ProcessName=System`. This is evidence of an enriched or reconstructed event representation, potentially a synthetic template. Exporter augmentation is an alternative explanation, so I do not classify it as an impossible operating-system event.
- [contract_gap] `zeek-core/smb_mapping.json:93` records UID `C4bqaKVpaYQLPkuTrz` at `2026-11-02T17:35:24.871449Z`, tuple `10.10.1.22:59392 -> 10.10.2.20:445`, share `\\FILE-SRV-01\ClinicalExports`. That UID occurs nowhere else in the supplied data and has no `conn.json` record. This is an isolated referential gap in an otherwise highly joinable source family. Selective collection or an ongoing connection whose conn record falls outside the window can explain it; it receives little weight.
- [weak_signal] Four hosts have exactly 76 Security 4688 records: `MAIL-FIN-01`, `WS-PPATEL-01`, `WS-SMARTINEZ-01`, and `WS-EBROOKS-01`. Their different roles and process mixes make identical totals mildly suggestive of an event budget. Other hosts vary from 46 to 152, and managed scheduling or sampling could also create coincident totals. This observation receives only minimal weight.

## Evidence For Real

- All examined line-delimited JSON records and all 20 Windows XML files parsed successfully. The Windows files contain 17,780 Security and 11,606 Sysmon events. Differences in timestamp representation are appropriate to the source: seven fractional digits in Windows `SystemTime`, millisecond Sysmon `UtcTime`, fractional Unix seconds in Zeek, and RFC 5424 text syslog.
- The 927 visible Sysmon process creations have 740 matching visible termination GUIDs. Across the checked GUID-bearing dependent records, I found no dependent timestamp preceding a visible creation or following a visible termination. Visible parent GUIDs also resolve to the matching parent image and precede their children.
- Across 37,414 eCAR rows, checked process `actorID` relationships and process-object references do not precede their visible CREATE or follow their visible TERMINATE records. Processes whose creation is outside the slice were not penalized.
- Of 14,032 Zeek protocol rows checked across DNS, HTTP, SSL, SMTP and SMB, 14,031 have local sensor conn references; their endpoint tuples agree and timestamps fall inside the corresponding connection interval, allowing 10 ms before and 100 ms after for precision/timing tolerance. The single exception is the SMB mapping listed above.
- FILE-SRV-01 shows a coherent handle lifecycle: 5145 record 271777 at `13:00:05.9658109Z`, 4656 record 271778 at `13:00:05.9709815Z`, 4663 record 271779 at `13:00:06.1459007Z`, then 4658 record 271780 at `13:00:09.7044244Z`. The handle is `0xb013d0ff`, user is `marcus.chen`, LogonID is `0xf62b74b`, and the write access is `AccessMask=0x2` / `%%4417`.
- DC-01 Security Event 1102 at `18:42:20.0702537Z` uses the Eventlog provider and namespaced `UserData/LogFileCleared`, rather than pretending to be a normal Security-Auditing `EventData` event. Its record ID resets to 1; subsequent record numbering remains ordered.
- The two Mac hosts contain 307 ES messages with distinct fork, exec and exit shapes. Sampled exec messages distinguish the pre-exec process from the post-exec target, keep the PID, advance pidversion and preserve start time. They do not confuse exec with spawning a new PID.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed records, counted event families, inspected more than 20 event types, and ran bounded semantic checks over the visible identities and timestamps. No repository, scenario, ground truth, evaluation or other reviewer material was consulted. The assessment concerns the supplied representation, not authenticated provenance; a sufficiently capable synthetic source can satisfy these checks.

### Windows schema and event-specific spot checks

The following are representative checks, not a claim to have validated every field against every possible installed provider manifest. Times are UTC on 2026-11-02. Short host names identify their corresponding `.meridianhcs.local` directories.

| Host/source | Event / record | Time | Checked evidence |
|---|---|---|---|
| DC-01 Security | 4776 / 28245269 | 13:00:05.5841888 | `PackageName=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, workstation and status use the expected credential-validation field names. |
| DC-01 Security | 4769 / 28245281 | 13:00:18.3707849 | Service ticket fields include service SID, ticket options, encryption type and IPv4-mapped client address. A zero LogonGuid is not itself a defect. |
| DC-01 Security | 4688 / 28245320 | 13:01:37.2023469 | Version 2 supplies creator and target security contexts, hexadecimal PIDs, parent image and mandatory label. |
| DC-01 Security | 4768 / 28245388 | 13:03:23.7991453 | `ServiceName=krbtgt`, service SID RID 502, `PreAuthType=2`, encryption `0x12`; empty certificate fields are compatible with this authentication mechanism. |
| DC-01 Security | 4624 | 13:10:16.4138675 | Type 5 NETWORK SERVICE uses SID `S-1-5-20`, LUID `0x3e4`, Advapi and no network address. |
| DC-01 Security | 4672 | 13:10:16.4406977 | Same NETWORK SERVICE SID/LUID; privileges are represented as privilege names, not a fabricated numeric mask. |
| DC-01 Security | 4634 | 13:10:49.8084721 | Type 3 machine-account logoff identifies a target session rather than a process. |
| DC-01 Security | 4697 | 17:00:12.2938629 | PSEXESVC installation has service image, service type `0x10`, start type 3 and LocalSystem account. |
| DC-01 Security | 4698 / 28257046 | 17:19:47.7438924 | Escaped task XML is carried in `TaskContent`; task name and URI agree. I did not certify the embedded task against a scheduler XSD. |
| DC-01 Security | 1102 / 1 | 18:42:20.0702537 | Eventlog provider, Level 4 and namespaced `UserData` distinguish log clearing from ordinary audit events. |
| FILE-SRV-01 Security | 5145 / 271777 | 13:00:05.9658109 | Share root, local NT-style share path and relative target form a coherent file target. |
| FILE-SRV-01 Security | 4656 / 271778 | 13:00:05.9709815 | Handle request includes process ID, object name and requested access. |
| FILE-SRV-01 Security | 4663 / 271779 | 13:00:06.1459007 | WriteData access agrees with `0x2` and the opened handle. |
| FILE-SRV-01 Security | 4658 / 271780 | 13:00:09.7044244 | Correct handle closure relationship; non-native extra `ProcessName` field is the schema concern. |
| WS-AJOHNSON-01 Security | 4625 / 130176 | 14:10:39.7393633 | Local Type 2 failure uses `Status=0xc000006d`, bad-password substatus `0xc000006a`, User32 and no remote IP. |
| DC-01 Sysmon | 1 / 3288923 | 13:01:36.8896748 | Process and parent GUIDs, numeric PID, user, hashes, session and integrity are separated correctly. |
| DC-01 Sysmon | 3 / 3288908 | 13:00:18.3883432 | Inbound UDP/88 identifies local lsass PID 2336 and `Initiated=false`. |
| DC-01 Sysmon | 5 / 3288907 | 13:00:05.1350891 | Termination has process identity; no matching pre-window creation is required. |
| DC-01 Sysmon | 10 / 3288925 | 13:01:54.3493599 | Source/target process identities, hexadecimal access and call trace are distinct fields. |
| DC-01 Sysmon | 8 / 3289088 | 13:13:02.9121340 | Remote-thread event provides source, target, thread, start address and module/function fields. |
| DC-01 Sysmon | 11 / 3292099 | 17:00:11.9872959 | File creation associates System PID 4 with `C:\Windows\PSEXESVC.exe`. |
| DC-01 Sysmon | 7 / 3292196 | 17:07:56.4439364 | Module image is distinct from process image; signature and hash fields are structured. This check does not authenticate the claimed signature. |
| DC-02 Sysmon | 13 / 1372205 | 17:31:25.3046597 | `EventType=SetValue`, registry target and value details are separated. |
| DC-01 Sysmon | 22 / 3288910 | 13:00:25.2419288 | DNS query has query status, result and querying process identity. |

An initially apparent “process before logon” pattern was not a contradiction: WS-AJOHNSON-01 LUID `0x254febf`, for example, has an in-window 4624 at `16:20:40.9385034Z` with **LogonType 7**, followed by 4801 at `16:20:41.0769554Z`. That is an unlock of an existing session, not proof its original logon occurred after earlier processes. The same distinction applies to the checked WS-MCHEN-01 and WS-DRAMIREZ-01 unlock sequences.

### Network source contracts

There are 23,141 Zeek conn rows across the three sensors. The checked protocol join counts are 88 for zeek-db, 6,582 for zeek-core and 7,362 for zeek-dmz. All matched protocol rows agree with conn endpoint tuples; therefore, reference integrity is positive interoperability evidence, not a synthetic indicator.

File-analysis hashes are stable with respect to reported total size: I found no repeated MD5/SHA1/SHA256 associated with contradictory total sizes. Non-TLS file observations do not individually exceed the matching connection's payload in the indicated transfer direction. No conn duration is negative, and IP-byte counts are not below payload-byte counts. All conn histories containing `g` or `G` also have nonzero `missed_bytes`: 41 rows at zeek-db, 550 at zeek-core and 699 at zeek-dmz. These checks avoid mistaking ordinary capture gaps for fabricated packet accounting.

The proxy also separates CONNECT control-message size from tunnel byte totals. For example, `PROXY-01.../proxy_access.log` at `13:00:37` has a 200 CONNECT for `spoprod-a.akamaihd.net:443`, with control-message and tunnel counters explicitly labeled. Zeek's corresponding CONNECT observation has zero HTTP response body, which is compatible with the tunnel carrying subsequent TLS traffic.

### Linux, eCAR and macOS interpretation

Linux RFC 5424 syslog supplies application names, PIDs and PAM/logind messages rather than Windows event fields. At APP-INT-01 `13:07:43.261481Z`, a sudo command is followed by PAM open at `13:07:43.387298Z` and close at `13:07:46.442735Z` with PID 3376214. This is a usable command/session relationship.

On MAC-MROSS-01, ES fork at `13:07:32.811343000Z` creates child PID 25527 with launchd's pre-exec image. At `13:07:32.820534000Z`, NOTIFY_EXEC has actor pidversion 2482477 and target pidversion 2482478, changing the target image to `/usr/libexec/xpcproxy`. The corresponding eCAR representation uses CREATE for fork and MODIFY for exec, keeping its process object ID. Across both hosts I found no actor activity after an exit of the same PID/pidversion and no contradictory executable size/path for a checked device/inode identity.

The ES rows declare message version 11. I did not establish every version-specific optional-field contract from an external SDK, and unfamiliar optional fields were not scored as defects. Unified Log rows were assessed as separate source observations, not required companions to all ES or normalized EDR activity. Sparse Unified Log coverage and missing Sysmon event families were not penalized.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | Windows Security 4658 | 41 Version 0 records on FILE-SRV-01 | Main concern: native-looking XML includes a non-native payload field; exporter enrichment remains possible. |
| contract_gap | Zeek SMB mapping/conn | One of 14,032 checked protocol records | Small effect: unresolved UID, explainable by collection boundaries or filtering. |
| weak_signal | Windows process-audit volume | Four of ten Windows hosts have 76 creations | Minimal effect: possible event-budget texture, with substantial competing explanation and variation elsewhere. |

No hard contradiction or generator identity leak was established. The score stays near the inconclusive range because these limited concerns coexist with strong source-semantic and lifecycle consistency.

## Realism Score by Category

- **Field format accuracy:** 8 — Clean parsing and credible event-specific structure; repeated 4658 native-payload augmentation prevents a higher rating.
- **Temporal patterns:** 9 — Checked process and network relationships are compatible with visible causality; unlocks and collection boundaries explain apparent exceptions.
- **Cross-source correlation:** 9 — Matched tuples, identifiers and file accounting are coherent; one unresolved SMB UID remains.
- **Behavioral realism:** 8 — Varied commands, authentication outcomes and process families; identical process-audit totals on four hosts are a small unresolved concern.
- **Environmental consistency:** 9 — Platform-specific source shapes and identities are maintained; no demonstrated OS/path or host-identity contradiction was found.

## Recommendations

- If this were synthetic, emit only the native Version 0 fields for Event 4658. Keep enriched process names in an explicitly separate normalization layer, or document an exporter that adds them.
- If this were synthetic, review the lifecycle and collection-boundary treatment of SMB UID `C4bqaKVpaYQLPkuTrz`. Retain the corresponding conn record when it belongs in the slice, or preserve enough collection metadata to explain why it is absent.
- If this were synthetic, check whether the repeated 76-event creation totals come from fixed per-host budgets. If so, derive volumes from host activity and collection policy; do not add arbitrary noise solely to make counts unequal.
