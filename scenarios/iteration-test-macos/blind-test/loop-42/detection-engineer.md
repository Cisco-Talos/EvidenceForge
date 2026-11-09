# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 53

## Executive Summary

The supplied telemetry is substantially production-like: Windows schemas, visible process/session lifecycles, network tuples, and protocol relationships withstand broad automated checks. I lean synthetic because five proxy records expose a repeated HTTP request-target error—browser fragment identifiers appear in purported network requests—but the demonstrated defect is localized, so the synthetic-confidence score remains in the mixed range.

## Evidence For Synthetic

- [hard_contradiction] `PROXY-01.meridianhcs.local/proxy_access.log:839` records `GET https://teams.microsoft.com/v2/#/conversations HTTP/1.1` at `02/Nov/2026:15:09:56 +0000`, from `10.10.1.35`, with a normal Firefox user agent and `proxy_action=ssl-inspect`. A browser does not transmit its URL fragment in the HTTP request target; TLS inspection cannot recover a client-side fragment. The same request-target mistake recurs at lines **854, 1114, 1141, and 2769**, across `aisha.johnson` and `priya.patel` and Firefox/Chrome. This is five instances of one defect, rather than five independent indicators. A transformed export could theoretically insert a page URL into a request field, but the supplied record presents it as the quoted HTTP request, without such a distinction.

## Evidence For Real

- All **18,611 Security events**, **11,657 Sysmon events**, and examined JSON-line sources parsed successfully. The Windows records distinguish Security-Auditing from the Eventlog provider and use source-appropriate payload structures.
- Across **884 matched Sysmon 1 / Security 4688 process creations**, process IDs, image paths, and parent PIDs agreed. No visible Sysmon process reference preceded its matching creation or followed its matching termination in the same process-GUID identity checks.
- Nonreserved Windows session IDs supported coherent visible process creation timing. Reserved system logon IDs were excluded from ordinary session-start assumptions; repeated `0x3e7` service logons are not independent creations of the SYSTEM identity.
- Across the three Zeek sensors, protocol records carrying connection UIDs had matching connection tuples and timestamps inside the corresponding visible intervals, allowing 10 ms before open / 100 ms after close for the check. No HTTP request or response body exceeded its corresponding directional connection byte count; HEAD and 204/304 records did not claim response bodies.
- Certificate fingerprints had consistent certificate metadata across repeated observations and sensors. The `zeek-db` certificate/file/SSL/OCSP examples retain useful distinctions between certificate identities, file IDs, connection UIDs, and OCSP response objects.
- The data contains realistic format differences: seven fractional digits in Windows `SystemTime`, millisecond Sysmon `UtcTime`, fractional epoch Zeek times, RFC 5424-style Linux records, native-shaped macOS ES messages, and separate Unified Log exports. Their precision is not artificially identical.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. Broad checks parsed every Windows event, the eCAR records, and the three Zeek sensor directories; source-native spot checks additionally covered Linux syslog, proxy/web access, ASA, Snort, macOS ES, and macOS Unified Log records. The network corpus contains **20,822 connection records**, **4,220 HTTP records**, **3,965 DNS records**, and **2,751 SSL records**. There are **34,454 eCAR records**.

I did not use domain resolvability, file modification timestamps, the completeness of the incident narrative, missing selected Sysmon types, or thin macOS collection as authenticity evidence. Matching records from separate sensors were assessed within their own UID namespaces; a different UID at a second sensor is not an error.

### Source-native spot checks

Paths below are relative to the supplied data directory. XML line numbers identify the beginning of the event element; record IDs provide stable secondary locators.

| # | Record location | Fields or semantics checked | Result |
|---|---|---|---|
| 1 | `DC-02.meridianhcs.local/windows_event_security.xml:454`, RID 25377484, 4624 v2 | Type 3, Kerberos, mapped IPv4 source, TargetLogonId, impersonation and elevated-token resource values | Plausible network logon schema; local LSASS process identity is distinct from remote client address. |
| 2 | Same file:244075, RID 25387399, 4625 | `Status=0xc000006d`, `SubStatus=0xc0000072`, failure keywords, Type 3, target account | Coherent disabled-account logon failure. |
| 3 | Same file:6336, RID 25377712, 4634 | Target account/SID, TargetLogonId, Type 3 | Appropriate compact logoff payload. All visible matching session pairs were additionally checked for account/type consistency. |
| 4 | `WS-PPATEL-01.meridianhcs.local/windows_event_security.xml:21753`, RID 359311, 4648 | Subject `priya.patel`, target `priya.patel-admin`, caller PID/path, `MAIL-FIN-01`, zero logon GUIDs | Explicit credential use retains separate subject, supplied credential identity, caller, and target. |
| 5 | `DC-02.meridianhcs.local/windows_event_security.xml:1575`, RID 25377537, 4688 v2 | Hex new/parent PID, Subject versus Target fields, mandatory label, token elevation | `0x1c30` is 7216; image and parent agree with Sysmon 1 RID 1368566. |
| 6 | Same file:1618, RID 25377541, 4689 | Process `0x1c30`, image, `Status=0x0` | Correct matching process termination; occurs after creation. |
| 7 | Same file:1785, RID 25377548, 4768 | Machine principal, `krbtgt`, domain SID ending 502, preauth type 2, AES `0x12`, mapped address | Coherent successful TGT request. |
| 8 | Same file:1495, RID 25377525, 4769 | Service account `DC-02$`, service SID, AES `0x12`, ticket options, client address | Service-ticket payload is distinct from the TGT payload; earlier tickets need not await a later visible TGT renewal. |
| 9 | Same file:169679, RID 25384585, 4697 | Service path, `ServiceType=0x10`, demand start `3`, `LocalSystem` | Plausible service-install audit representation. |
| 10 | `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:138`, RID 271776, 5145 | `ClinicalExports` share, local path, relative target `Weekly\incremental.bak`, source port, access mask | Share-local and relative target paths compose consistently. |
| 11 | Same file:187, RID 271777, 4656 v1 | Full object path, handle `0xb1db79f3`, PID 4, requested mask | Handle request has coherent subject and file identity. |
| 12 | Same file:240, RID 271778, 4663 v1 | Same handle/path, `AccessMask=0x2`, `AccessList=%%4417` | Actual write access is a sensible subset of requested access. |
| 13 | Same file:538, RID 271795, 4658 | Same handle, subject and PID | Handle close follows request/access rather than preceding them. |
| 14 | `DC-01.meridianhcs.local/windows_event_security.xml:183016`, RID 28256973, 4698 | Embedded task XML, author/principal, TimeTrigger, hourly repetition, executable | Structured task content is present and internally readable. |
| 15 | Same file:259234, RID 1, 1102 | Eventlog provider GUID, Level 4, Task 104, UserData `LogFileCleared` namespace | Uses the source-specific UserData structure rather than falsely treating 1102 as a normal Security-Auditing EventData payload. Record numbering resets at the clear. |
| 16 | `DC-02.meridianhcs.local/windows_event_sysmon.xml:854`, RID 1368566, Sysmon 1 | ProcessGuid, PID 7216, hash lengths, parent PID 5128, system account | Matches Security creation; encoded GUID timestamp matches creation second. All 884 visible creation GUIDs passed this timestamp check. |
| 17 | Same file:899, RID 1368567, Sysmon 5 | Matching ProcessGuid, PID, image, UtcTime | Logical termination follows creation; event emission times differ from embedded UtcTime in a plausible direction. |
| 18 | Same file:3, RID 1368530, Sysmon 10 | `SourceProcessGUID`/`TargetProcessGUID`, thread, granted access `0x0400`, call trace | Correct actor/target separation; the equivalent eCAR PROCESS/OPEN row uses source PID 5088 and target PID 5096 without confusing the target object with the calling process. |
| 19 | `zeek-db/conn.json:2` and `zeek-db/dns.json:1` | UID `CMfRZBB1UrKjIjJFwK`, UDP tuple, transaction ID, A answer, TTL array, RTT | Connection/DNS tuple and duration/RTT agree; response fields have appropriate scalar/list types. |
| 20 | `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:1-3` | Message version 11, fork/exec target, audit tokens, PID versions, parent/responsible tokens | Visible launchd → xpcproxy → iTerm transition retains PID 18976 while distinguishing exec identities; no demonstrated native-schema defect. |

### HTTP fragment defect and its limits

The five affected proxy rows do not merely mention a fragment in an arbitrary message. The fragment is inside the quoted `METHOD request-target HTTP/version` field. For example, line 1141 claims:

`GET https://teams.microsoft.com/v2/#/conversations HTTP/1.1`

The source is `10.10.1.32`, the user is `MERIDIANHCS\priya.patel`, and the timestamp is `15:34:05 +0000`. A browser can display that URL, but the corresponding request target excludes `#/conversations`. Even an inspecting proxy observes `/v2/`, not the browser's fragment-navigation state. This resembles using a browser-navigation URL directly as an HTTP logging field.

The associated network path is otherwise credible. For the earlier line 839 example, `zeek-core/http.json:574` and `zeek-dmz/http.json:655` show a CONNECT to `teams.microsoft.com:443` from source port 63492. Those CONNECT observations do not reveal the later encrypted origin-form request and do not independently contradict the proxy. I therefore count the fragment problem once, and do not penalize the lack of a matching plaintext GET in Zeek.

A custom export might decorate a request field with browser-side context. No such browser-context provenance is visible here, which is why I favor synthetic over real, but that possibility limits certainty. This one local issue does not justify calling the full dataset confidently synthetic.

### Lifecycle and collection interpretation

The visible Windows process trees and session relationships performed well. Cross-source equality itself was not scored as suspicious. Reserved SYSTEM sessions and pre-window parents were treated appropriately, and processes surviving the last captured record were not called incomplete.

Linux records include SSH accepted/session-open/session-close material, sudo commands and PAM session records, logind session changes, service logs, and maintenance. Their RFC 5424 envelopes parse as forwarded/structured syslog, rather than requiring a local journal export. The differing daemon names and host roles do not produce a demonstrated contradiction.

The macOS ES files contain 124 and 164 records respectively, with notify exec/fork/exit event families. Unified Log is separately represented and sparse; that is a collection choice, not a defect. I did not require ES network FLOW events, additional event families, authorization decisions, or launch-item effects that the visible source does not establish. Version-sensitive macOS fields were not declared invalid merely because they are unfamiliar.

### Distribution assessment

Process durations are varied and role-sensitive rather than fixed: visible `taskhostw.exe` lifetimes span roughly 3–900 seconds; `WmiPrvSE.exe` lifetimes span roughly 30–7,647 seconds; shell, browser, and remote-client processes have wider lifetimes. Zeek states include SF, S0, RSTO, RSTR, REJ, OTH, and partial connections, with several history variants. Repeated updater/system command lines are expected in managed fleets; I found no distribution artifact strong enough to add to the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| hard_contradiction | Inspecting proxy access log | Five GET records, two users, ordinary Firefox/Chrome agents; lines 839, 854, 1114, 1141, 2769 | A network proxy cannot observe a browser's client-side URL fragment as part of an actual HTTP request target. Strong local semantic issue; limited affected volume and possible export transformation keep the overall score at 53. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows and network structures are credible and parse cleanly; proxy request-target semantics have one repeated defect.
- **Temporal patterns:** 9 — Visible lifecycle ordering, heterogeneous precision, protocol intervals, and variable process durations hold up to checks.
- **Cross-source correlation:** 9 — Process identities/parents and Zeek connection/protocol tuples agree; no demonstrated lifecycle contradiction.
- **Behavioral realism:** 8 — Plausible administration, maintenance, browser, and service activity; the proxy fragment handling is behaviorally incorrect for normal browsers.
- **Environmental consistency:** 9 — Host roles and Windows/Linux/macOS source distinctions are coherent in the inspected evidence; sparse sources alone were not penalized.

## Recommendations

- If this were synthetic, separate the browser navigation URL from the network request target. Preserve the full URL only in explicitly browser-derived telemetry; remove the fragment before rendering proxy HTTP requests. Specifically, render the five affected Teams requests with `/v2/` and retain `#/conversations` only if a separately identified client-side source observes it.
- If this were a transformed production export, identify any field replacement that populates a quoted HTTP request from a page URL. Label that transformation explicitly so detections consuming request targets do not learn or match client-only URL state.
