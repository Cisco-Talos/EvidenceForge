# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 88  
**Synthetic-Confidence Score:** 78

## Executive Summary

The dataset is unusually strong at source-native field shape, identifier morphology, and cross-source correlation, and most individual records would parse cleanly in a SIEM. I nevertheless assess it as synthetic because the DC audit stream repeatedly creates fresh successful machine-account TGT activity at a rate incompatible with ordinary Kerberos ticket caching, and because one visible workstation lock/unlock lifecycle is physically implausible and lacks the expected type-7 logon companion.

## Evidence For Synthetic

- [distribution_texture] The two DC Security logs contain 800 Event 4768 records, of which 788 target machine accounts, plus 2,094 Event 4769 records, of which 2,074 target machine accounts. This is not merely high Kerberos coverage: individual machines repeatedly obtain successful TGTs every few minutes throughout the six-hour window. `MAIL-FIN-01$` has 121 successful 4768s from 12:07:09.1718822Z through 17:53:59.8423497Z (median interval 147.1 seconds), `FILE-SRV-01$` has 116 (median 168.7 seconds), `WS-PPATEL-01$` has 87 (median 140.3 seconds), and `WS-AJOHNSON-01$` has 93 (median 194.8 seconds). Normal LSA ticket caching should not require each computer account to reacquire dozens of successful TGTs per hour.
- [distribution_texture] The repeated AS-to-TGS construction has bundle-like timing. Of 2,094 Event 4769s, 1,279 (61.1%) have a same-account, same-source-IP Event 4768 within the preceding 60 seconds; 579 are within two seconds. Concrete examples in `DC-02.../windows_event_security.xml` include `FILE-SRV-01$` Event 4768 at 12:05:21.5504770Z followed by Event 4769 for `DC-02$` at 12:05:21.6512457Z, both using client port 64646, and another fresh `FILE-SRV-01$` pair at 12:11:21.9236723Z/12:11:21.9339712Z on port 59257. Fresh AS exchanges are plausible at boot, cache expiry, credential change, or renewal boundaries; repeating them continuously for the same machines is not.
- [hard_contradiction] On `WS-AJOHNSON-01`, Security Event 4800 locks session 2/logon ID `0x263743b` at 17:48:17.3933800Z and Event 4801 unlocks the same session at 17:48:17.3940149Z—only 0.6349 milliseconds later. A human workstation lock and credential-mediated unlock cannot complete in that interval.
- [contract_gap] The same 17:48:17.3940149Z Event 4801 has no nearby Security Event 4624 with LogonType 7. This is a concrete gap because this host demonstrably collects type-7 logons: it contains a type-7 4624 for the same logon ID at 17:35:04.7369526Z. By contrast, `WS-MCHEN-01` shows coherent companions: Event 4800 at 14:54:54.9118305Z, type-7 Event 4624 at 15:00:46.6008045Z, and Event 4801 at 15:00:47.0586562Z.
- [distribution_texture] Linux process identifiers drift at a strikingly similar sustained rate across unrelated systems. Based on visible eCAR PROCESS/CREATE records, fitted PID slopes cluster from about 1.96 to 2.62 PIDs/second: `DB-PROD-01` advances from PID 837940 at 12:02:50.481Z to 886591 at 17:30:25.719Z (2.62/s fitted), `FILE-LNX-01` from 1898683 at 12:01:01.576Z to 1949055 at 17:58:27.691Z (2.41/s), `MAIL-EDGE-01` from 188140 at 12:04:28.553Z to 234200 at 17:36:00.442Z (2.12/s), and `WS-LNGUYEN-01` from 1464541 at 12:01:16.905Z to 1507536 at 17:39:56.194Z (1.96/s). Similar PID churn on a database server, file server, mail edge, proxy, web server, and workstation suggests a shared process-rate model more than independent production workloads.
- [weak_signal] Several unrelated workstations contain byte-for-byte identical Sysmon Event 13 writes exactly one millisecond apart. `WS-AJOHNSON-01` writes `...Office\16.0\Common\General\ShownFirstRunOptin = DWORD (0x00000001)` three times at 15:20:41.2189408Z, .2199390Z, and .2209398Z, then repeats another triplet at 16:49:01.0449852Z/.0459852Z/.0469858Z. `WS-PPATEL-01` has the same duplicated value at 14:25:03.7310267Z/.7320266Z, and `WS-SMARTINEZ-01` at 13:35:34.5258577Z/.5268574Z. Applications can repeat writes, but the exact one-millisecond spacing and recurrence across hosts has generated-batch texture.
- [environment_or_collection_plausibility] `FILE-SRV-01` records all 76 visible type-3 logons as `NtLmSsp`/`NTLM`, even for domain users accessing hostname-based shares. At 12:01:43.5384061Z, for example, `diego.ramirez` logs on from `WS-DRAMIREZ-01`/10.10.1.34:59181 using NTLM V2, immediately followed by 5140/5145 access to `\\*\Finance`; Zeek identifies the client request as `\\FILE-SRV-01\Finance`. A domain member using the server hostname would ordinarily prefer a cached CIFS Kerberos ticket. Universal NTLM on this server is possible through SPN or policy problems, so I weight it below the repeated machine-TGT finding, but it is an odd authentication profile.

## Evidence For Real

- The Windows XML schemas are highly accurate across the sampled event families. Security events use plausible versions and metadata: 4624 v2, 4656 v1, 4663 v1, 4688 v2, 5156 v1, and 4768/4769 v0; Sysmon uses plausible versions including Event 1 v5, Event 3 v5, Event 5 v3, Event 7 v3, Event 8 v2, Event 10 v3, Event 11 v2, Event 13 v2, and Event 22 v5. Field sets, provider GUIDs, channels, tasks, keywords, and value encodings are consistent with those events.
- Across all parsed Windows records, SID strings, brace-delimited GUIDs, IP ports, process IDs, access masks, and hash strings have valid morphology. User-to-SID mappings are stable: no observed user maps to multiple SIDs and no non-null SID maps to multiple users.
- Process telemetry correlates cleanly without visible ordering impossibilities. The 930 Security 4688 records and 926 Sysmon Event 1 records yield 926 same-host/same-PID pairs within two seconds, with no mismatches in image, command line, parent image, or logon ID. No matched Sysmon Event 5 precedes its Event 1, and no visible child starts after the matched parent ProcessGuid has terminated.
- A representative process is internally convincing. On `WS-AJOHNSON-01`, Sysmon Event 1 records PID 5192/ProcessGuid `{fd907e59-2e02-65f8-6200-00007a24ed73}` at 12:05:22.1911805Z for `SearchProtocolHost.exe`, parent PID 4636 `SearchIndexer.exe`, SYSTEM logon `0x3e7`; Security 4688 records PID `0x1448`, the same image, command line, parent, and logon at 12:05:22.3372169Z; eCAR PROCESS/CREATE records PID 5192 and the same parent at 12:05:22.434Z. The corresponding Sysmon 5, eCAR termination, and Security 4689 occur around 12:44:17 with matching identity.
- The Security-log-clear event is source-native rather than superficially rendered. `DC-01` Event 1102 at 17:41:59.2606262Z uses provider `Microsoft-Windows-Eventlog`, task 104, `LogFileCleared` UserData, SYSTEM SID/logon `0x3e7`, and EventRecordID 1; later records restart at low IDs (for example, Event 4726 at record 443), while pre-clear records use the prior high sequence. That reset behavior is operationally coherent.
- SMB audit lifecycles are precise. The `FILE-SRV-01` access beginning at 12:01:43.5384061Z carries logon ID `0xf62df98` and source 10.10.1.34:59181 through 4624, 5140, and 5145; handle `0x9814e8d` then progresses through 4656 at 12:01:43.9981926Z, 4663 at 12:01:44.0768915Z, and 4658 at 12:01:44.2418555Z. Across that file, 55 handles have 4656→4663→4658 and six have 4656→4658, with no reversed visible ordering.
- Zeek records have credible typing and protocol relationships. All 3,891 DNS, 3,220 HTTP, and 2,371 SSL UIDs resolve to a conn record on the same sensor; file connection UIDs and TLS certificate FUIDs also resolve. TLS version/cipher combinations are valid, and resumed TLS sessions correctly omit certificate chains while non-resumed sessions may carry them.
- Network outcomes are not cosmetically forced to success. The 19,241 Zeek connections include 14,032 `SF`, 4,582 `S0`, 262 `RSTO`, 198 `RSTR`, plus `REJ`, `OTH`, `S1`, `S2`, and `S3`. For example, 10.10.1.35:49326→10.10.2.10:389 is `RSTO` with history `ShAR`, zero payload bytes, and a 0.909701-second duration, consistent with the eCAR failure outcome on both endpoints.
- Timing precision is source-appropriate. Windows `SystemTime` carries seven fractional digits, Sysmon `UtcTime` carries millisecond precision, Zeek uses floating-point epoch seconds, and eCAR uses integer epoch milliseconds. Sysmon event-write delay relative to embedded `UtcTime` is positive and variable rather than a fixed offset; sampled medians are approximately one to three milliseconds with occasional tens-of-milliseconds tails.

## Detailed Analysis

The visible data spans approximately 12:00Z–18:00Z on 18 March 2024. I parsed 48 newline-delimited JSON files, 20 Windows XML files, and 22 bash-history artifacts. The Windows set covers ten hosts with both Security and Sysmon channels; eCAR spans 21 hosts; and Zeek data is separated into core, DMZ, and database sensor views. I treated the six-hour boundary as a slice, so unmatched pre-window processes or sessions and end-of-window survivors were not counted as defects.

**Windows schema and Event ID fidelity.**

The XML is structurally parseable and the major event schemas are convincing. Security 4624 has all expected v2 fields through `ElevatedToken`; 4688 includes `TargetUser*`, `ParentProcessName`, and `MandatoryLabel`; 5156 carries process/application, tuple, direction, protocol, filter, and layer fields; and 4768/4769 use source-native hexadecimal ticket options and encryption types. Event 5156 direction/layer combinations are internally consistent: inbound `%%14592` records use layer `%%14610`/RTID 44, while outbound `%%14593` records use `%%14611`/RTID 48. Sysmon event schemas likewise use the expected specialized names, including `SourceProcessGUID`/`TargetProcessGUID` for Event 10 and `SourceProcessGuid`/`TargetProcessGuid` for Event 8.

Value morphology also survives mechanical checks. I found no ports outside 0–65535, malformed SIDs, or malformed Windows GUIDs. Security decimal and hexadecimal PID representations translate correctly to Sysmon decimal PIDs. EventRecordIDs are unique within each file and rise with expected gaps from uncollected events; the only major decrease is the correctly modeled DC-01 Security-log clear.

The chief Windows defect is not schema but lifecycle timing. The AJOHNSON lock/unlock records share the exact host, account SID, logon ID, and SessionId, so they cannot represent unrelated sessions. The 0.6349-ms interval is therefore a visible contradiction, not a missing-pre-window inference. The absence of a nearby type-7 4624 strengthens the conclusion because another type-7 event is collected on the same host and because the MCHEN lock/unlock sequences show the expected 4624→4801 relationship.

**Kerberos and logon semantics.**

The event-level Kerberos values look plausible in isolation: all successful 4768/4769 records use status `0x0`; encryption types include AES256 `0x12`, AES128 `0x11`, and RC4 `0x17`; IPv4 sources are represented as IPv4-mapped IPv6; and the source ports are valid ephemeral values. The aggregate behavior is not plausible, however. Eight busy machine accounts each request between 69 and 121 new TGTs within six hours, with median inter-request times of roughly 2.3–4.4 minutes. Those successful AS exchanges are then frequently followed by a TGS exchange for the same machine and IP within seconds.

This differs materially from ordinary ticket reuse. A workstation or server does not normally reacquire a successful computer-account TGT before each LDAP, CIFS, or host-service request; LSA caches the TGT and obtains service tickets from it until renewal or expiry. The pattern appears to instantiate prerequisites repeatedly rather than preserve ticket state. Its scale across both DCs and multiple machine roles makes it the highest-weight synthetic indicator.

Logon field combinations outside that family are generally good. Type 5 uses `Advapi`/`Negotiate` with local addresses represented by `-`; type 2 and type 7 use `User32`; type 9 uses `seclogo`; type 10 uses a remote source; and type 3 distinguishes Kerberos from `NtLmSsp`/NTLM. Event 4672 follows privileged logons using the same logon ID, and no visible 4634 precedes a matching 4624. The FILE-SRV universal-NTLM profile remains an environmental oddity rather than a strict schema error.

**Process, registry, and eCAR behavior.**

Windows process correlation is excellent. For matched 4688/Event 1 pairs, the Sysmon event generally precedes the Security event by about 35–650 ms, which is plausible for different provider pipelines, and field identity remains stable. Termination ordering is also sound. Sysmon ProcessGuid prefixes remain host-specific, while individual GUIDs persist across process-dependent events.

Registry records use credible paths, principals, types, and UserAssist ROT13 names. For example, `HRZR_EHACNGU:P:\Cebtenz Svyrf\Tbbtyr\Puebzr\Nccyvpngvba\puebzr.rkr` correctly has the morphology of a UserAssist value, and SYSTEM/service writes target plausible HKLM policy locations. The repeated same-value, exact-one-millisecond Outlook writes are therefore notable precisely because the surrounding registry morphology is otherwise convincing. I treat them as a lower-confidence generator texture, not an impossible application behavior.

The eCAR files are valid JSON and use stable UUID-shaped event/object/process references. PROCESS/CREATE and PROCESS/TERMINATE do not reverse visible lifecycle order, and actor/target detail is rich enough for SIEM pivots. The Linux PID-rate similarity is visible through these records even though many intermediate processes are not collected. Missing processes alone are not the concern; the concern is that independent hosts with different roles exhibit nearly the same inferred background PID consumption for the entire window.

**Zeek and cross-source checks.**

The Zeek field shapes are credible for `conn`, `dns`, `http`, `ssl`, `x509`, `ocsp`, `files`, `smb_files`, `smb_mapping`, `smtp`, `dhcp`, and `pe` records. Optional JSON fields are omitted rather than filled with arbitrary nulls. DNS query types include A, AAAA, PTR, SRV, TXT, NS, MX, and SOA. TLS 1.3 is paired only with TLS 1.3 cipher names, while TLS 1.2 uses appropriate ECDHE suites. All visible certificates are valid at observation time, and resumed sessions do not incorrectly emit new certificate chains.

Cross-source alignment is used only as evidence against contradictions, not as a synthetic tell. The SMB example above maintains tuple, username, logon ID, path, handle, and timing across Zeek and Windows audit records. Failed flows similarly preserve tuple and state semantics instead of claiming a successful Zeek session. I found no DNS-after-dependent-connection impossibility, no invalid Zeek UID reuse, and no process termination before a visible matching creation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on assessment |
|---|---|---|---|
| distribution_texture | Windows Security 4768/4769 | Dataset-wide across both DCs and many machine accounts | High: repeated successful machine TGT acquisition every few minutes conflicts with normal Kerberos cache behavior and exposes a prerequisite-per-activity pattern. |
| hard_contradiction | Windows Security 4800/4801 | One session on WS-AJOHNSON-01 | High: a 0.6349-ms physical lock/unlock lifecycle is not credible. |
| contract_gap | Windows Security 4624/4801 | One WS-AJOHNSON-01 unlock | Medium: the unlock lacks the type-7 logon companion that the same host collects elsewhere. |
| distribution_texture | Linux eCAR PROCESS/CREATE PIDs | Repeated across eleven Linux hosts | Medium: independent host roles share a narrow, sustained PID-consumption band. |
| distribution_texture | Sysmon Event 13 | Repeated on three workstations | Low-to-medium: identical same-value writes recur at exact one-millisecond spacing. |
| environment_or_collection_plausibility | FILE-SRV-01 4624/5140/5145 and Zeek SMB | Dataset-wide on one server | Low: all visible network logons use NTLM despite hostname-based domain SMB access. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows, Sysmon, Zeek, and eCAR records are parseable and use highly credible field names, versions, encodings, and identifier formats.
- **Temporal patterns:** 6/10 — Most source delays and process/network ordering are natural, but the sub-millisecond lock/unlock and exact one-millisecond duplicate writes are conspicuous.
- **Cross-source correlation:** 9/10 — Process, SMB, network, DNS, TLS, and file pivots agree without observed impossible ordering; the unlock companion is the main gap.
- **Behavioral realism:** 6/10 — Individual actions look operationally credible, but repeated TGT acquisition and common Linux PID churn do not reflect normal state reuse and role-specific workload variance.
- **Environmental consistency:** 7/10 — Host roles, paths, accounts, and protocols mostly cohere; the universal FILE-SRV NTLM profile and homogeneous background rates remain odd.

## Recommendations

- If this were synthetic, maintain Kerberos cache state per account/host. Issue one TGT at boot, initial domain use, cache purge, credential change, or realistic renewal/expiry; reuse it for multiple TGS requests, cache service tickets by SPN, and avoid generating a fresh 4768 as a prerequisite for ordinary service activity.
- Model workstation locking as a human-scale lifecycle. Require a meaningful locked duration, emit the type-7 4624 before 4801 when that audit policy is visible, and preserve the same session/logon identifiers across the sequence.
- Make Linux background PID consumption host-role- and workload-specific. Derive PID advancement from actual modeled process creation plus separately parameterized unobserved churn, allowing busy mail/proxy/database systems and lightly used workstations to diverge materially.
- Remove exact one-millisecond duplicate registry batches unless the modeled application explicitly performs repeated calls. When duplicates are justified, vary count and inter-call timing and retain them only where the source process behavior supports them.
- Review why FILE-SRV-01 always authenticates network users with NTLM. If intentional, add log-visible evidence of the SPN/policy condition; otherwise let hostname-based domain SMB sessions use cached CIFS Kerberos tickets with NTLM as a bounded fallback.
- Preserve the current source-native schemas, ProcessGuid/LogonID consistency, Security-log reset behavior, Zeek protocol typing, and SMB handle lifecycle; these are the strongest production-like aspects of the dataset.
