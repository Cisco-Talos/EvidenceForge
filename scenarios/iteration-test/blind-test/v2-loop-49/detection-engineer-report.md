# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 66

## Executive Summary

Most of the dataset is unusually strong at the schema and correlation layers, but a repeatable defect in every visible RDP/Type-10 logon path is difficult to reconcile with native Windows telemetry: identity and parent-process fields become empty, and `userinit.exe` remains alive for 49 minutes to 2.57 hours instead of exiting after shell initialization. Because the defect is systematic across four independently visible remote-interactive sessions and crosses Security, Sysmon, and process lifecycle semantics, I assess the dataset as synthetic, though not with extreme confidence because the rest of the corpus is highly production-like.

## Evidence For Synthetic

- `[schema_or_format]` All four visible Security 4624 Type-10 records have empty `TargetUserSid` and `LogonGuid` values despite naming a known domain user and carrying a valid `TargetLogonId`. Examples include DC-01 at `2024-03-18T17:09:56.8851662Z` (`marcus.chen`, logon `0x55df795`) and FILE-SRV-01 at `2024-03-18T17:06:19.5077017Z` (`aisha.johnson`, logon `0xf88fcda`). The two Type-10 records on WS-AJOHNSON-01 at `15:00:29.5947752Z` and `15:20:34.8148036Z` have the same omissions. These are empty XML elements, not normal sentinel values such as `S-1-0-0`, `-`, or the zero GUID.
- `[contract_gap]` The process-start records attached to those same four remote-interactive sessions lose parent identity. Twelve Security 4688 records—the `winlogon.exe` → `userinit.exe` → `explorer.exe` triplet for each RDP logon—have an empty `ParentProcessName`, even though `ProcessId` links the chain. Their matching Sysmon Event 1 records use `ParentImage=-`. Equivalent ordinary interactive chains elsewhere correctly show `smss.exe`, `winlogon.exe`, and `userinit.exe`, demonstrating a path-specific projection failure rather than an environment-wide collection choice.
- `[schema_or_format]` Each affected RDP `winlogon.exe` 4688 also has empty `SubjectUserSid`, `SubjectUserName`, and `SubjectLogonId` while retaining `SubjectDomainName=NT AUTHORITY`. Concrete examples are DC-01 at `17:09:56.8704904Z`, FILE-SRV-01 at `17:06:19.9159045Z`, and WS-AJOHNSON-01 at `15:00:29.6086509Z` and `15:20:34.9533726Z`. Native fields are selectively blank rather than populated with the SYSTEM identity shown on corresponding normal `winlogon.exe` starts.
- `[contract_gap]` All four affected RDP `userinit.exe` instances persist until close to session teardown: 2,985.99 seconds on DC-01, 2,948.43 seconds on FILE-SRV-01, and 8,045.38 and 9,263.18 seconds on WS-AJOHNSON-01. By contrast, the other ten visible `userinit.exe` lifetimes are 2.95–5.05 seconds, which fits normal shell initialization. The split is exact by execution path and is corroborated by termination records near RDP disconnect/logoff—for example DC-01 Event 4779 at `17:59:42.8386948Z`, `userinit.exe` Event 4689 at `17:59:43.0578384Z`, and Event 4634 at `17:59:47.6443615Z` for logon `0x55df795`.
- `[weak_signal]` Every one of 899 present Sysmon Event 3 records has `Initiated=true`, while Security 5156 contains 6,617 inbound and 4,962 outbound permitted connections on the Windows estate. A deliberate Sysmon rule filtering inbound events could explain this, so it is not a contradiction and receives little weight, but the all-or-nothing value distribution is operationally relevant to detection content expecting server-side Sysmon network telemetry.

## Evidence For Real

- All ten Security XML files and all ten Sysmon XML files parse successfully. I examined the field sets and system metadata across 18,473 Security events and 4,816 Sysmon events, spanning 27 Security Event IDs and nine Sysmon Event IDs. Provider names, channels, task/opcode/level values, event versions, SID/GUID morphology, hexadecimal process IDs, and source-specific timestamp precision are generally coherent.
- Security-to-Sysmon process correlation is excellent without impossible ordering. Of 930 Security 4688 records, 926 match a Sysmon Event 1 on host, PID, and image within five seconds; observed matching delays have host medians around 0.12–0.17 seconds and maxima below 0.65 seconds. The four Security-only creations are sparse enough to be plausible collection loss rather than a synthetic tell.
- Visible process references are causally sound. Across Sysmon Events 3, 5, 7, 8, 10, 11, 13, and 22, no record references a ProcessGuid whose visible Event 1 creation occurs later. Likewise, no eCAR `actorID` or `source_process_uuid` points to a later visible PROCESS/CREATE event.
- Logon lifecycle ordering is strong. Among 447 Security 4634 events, every logoff with a matching visible 4624 occurs after that logon; the small number without a visible initiator is consistent with the bounded collection window. I found no visible reverse-ordered logon/logoff pair.
- Object-access sequences are source-native and internally consistent. FILE-SRV-01 contains 61 Security 4656 handle requests, all followed by either `4656 → 4663 → 4658` or `4656 → 4658` using the same handle ID, process ID, logon ID, and object context.
- The Security log clear on DC-01 is convincingly represented. EventRecordID advances into the 28-million range, then Event 1102 at `2024-03-18T17:41:59.2606262Z` uses the `Microsoft-Windows-Eventlog` provider, correct `UserData/LogFileCleared` structure, SYSTEM subject, and EventRecordID 1; subsequent records continue from the reset sequence. This explains the sole non-monotonic record-ID transition rather than leaving an impossible reset.
- Zeek JSON is structurally clean and highly usable. All `dns.json`, `http.json`, `ssl.json`, `smtp.json`, `smb_mapping.json`, and `smb_files.json` UID references resolve to sensor-local `conn.json` entries with exact 4-tuples, and all checked protocol timestamps lie inside their connection intervals. All 1,071 SSL certificate-chain references resolve to X.509 records. Three of 912 protocol-level FUID references lack a corresponding `files.json` row, a sparse imperfection compatible with independent file-log filtering or loss.
- Text sources parse consistently: 4,975 RFC 5424 syslog records, 2,262 proxy records, 706 web-access records, 18,175 ASA records, and 174 Snort alerts match their expected source formats. ASA connection IDs have ordered build/teardown pairs, and all bash-history files use monotonic epoch markers paired with commands.
- The data contains believable source-specific entropy rather than one global timestamp or identifier pattern: Security uses seven fractional digits, Sysmon event payload time uses milliseconds, Zeek uses floating-point epoch timestamps, Snort uses microseconds, proxy/web/ASA use native text precision, EventRecordID gaps vary, and IDs are host/sensor scoped.

## Detailed Analysis

### Scope and sampling

I restricted the examination to generated evidence beneath `scenarios/iteration-test/data`. I did not use scenario material, ground truth, manifests, source code, prior assessment reports, repository history, or other reviewers' work. I parsed all available Security and Sysmon XML, eCAR JSONL, Zeek JSONL, RFC 5424 syslog, proxy/web combined logs, ASA messages, Snort alerts, and bash-history evidence, then manually inspected representative records from common and rare event types.

The visible collection window is approximately `2024-03-18T12:00:00Z` through `18:00:00Z`. I treated pre-window process/session initiators and post-window continuations as potentially legitimate and only counted visible ordering defects or source-native inconsistencies.

### Windows Event Log schema and Event ID fidelity

The Security inventory includes Events 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156. The dominant event counts—11,579 for 5156, 2,094 for 4769, 930 for 4688, 872 for 4624, and 800 for 4768—are plausible for a monitored Windows estate over six hours. Field sets are stable by Event ID and generally align with the declared versions.

Representative details are convincing. Event 5156 uses decimal PIDs, device-form application paths, numeric protocol values, `%%14592/%%14593` directions, and corresponding `%%14610/%%14611` layers. Events 4768/4769 use IPv4-mapped addresses, hexadecimal ticket options and encryption types, and coherent account/service naming. Events 5140/5145 use `\\*\share` names, `\??\` local paths, relative target names, and access-mask/message-token combinations. The rare 4728 record at `16:14:40.7744370Z` contains a concrete member DN and matching SID rather than a placeholder.

The decisive exception is Type-10 logon rendering. Each of the four successful RDP 4624 records has an empty target SID and logon GUID even though downstream records identify the same account SID and logon ID. Empty values are materially different from legitimate sentinels and will produce null/empty normalized fields in a SIEM, breaking rules and enrichment keyed on `TargetUserSid` or `LogonGuid`.

The same path loses Security 4688 creator and parent data. On DC-01, the RDP startup sequence is:

- `17:09:56.8704904Z`: 4688 creates PID `0x1614`, `winlogon.exe`, with blank subject SID/name/logon ID and blank parent image.
- `17:09:56.8851662Z`: 4624 Type 10 establishes `marcus.chen`, logon `0x55df795`, but leaves `TargetUserSid` and `LogonGuid` empty.
- `17:09:57.0693779Z`: 4688 creates PID `0x1618`, `userinit.exe`, parent PID `0x1614`, but parent image is empty.
- `17:09:57.3026889Z`: 4688 creates PID `0x161c`, `explorer.exe`, parent PID `0x1618`, again with an empty parent image.

The equivalent FILE-SRV-01 sequence has the same omissions, as do both RDP sessions on WS-AJOHNSON-01. This deterministic partition by session type is much more indicative than an isolated malformed record.

### Sysmon schema, values, and process correlation

The Sysmon files contain Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 with consistent field shapes. Process-create hashes use complete SHA1, MD5, SHA256, and IMPHASH tokens of correct lengths. ProcessGuids are braced and well formed; a host/PID pair does not acquire multiple ProcessGuids in the visible window. Event 10 correctly uses the source/target ProcessGUID field spelling associated with that schema, and Event 8 uses its own SourceProcessGuid/TargetProcessGuid spelling.

Security 4688 and Sysmon Event 1 agree on PID, image, command line, and parent PID for the matched population. The four RDP triplets reproduce the blank parent image in Sysmon as `-`, making the issue cross-source rather than XML serialization alone. No Sysmon dependent event precedes the visible creation of the same ProcessGuid.

The Event 3 population is syntactically valid—`Protocol` values are `tcp` or `udp`, IPv6 flags agree with IPv4 addresses, and destination service names are reasonable—but all 899 rows say `Initiated=true`. Because inbound Security 5156 events are abundant, this looks like a strict source filter or a one-sided generator path. It is not independently sufficient to identify synthetic data, but an ingest/detection validation corpus should make that collection assumption explicit or include some server-side Event 3 observations.

### Process and session lifecycle behavior

Security process termination is mostly credible. Normal interactive `userinit.exe` instances terminate shortly after launching the shell: ten observed lifetimes range from 2.946 to 5.051 seconds. The four Type-10 instances instead live for 49.14 minutes, 49.77 minutes, 2.24 hours, and 2.57 hours. Their terminations occur at or near RDP disconnect/logoff, showing that the process lifetime is being inherited from session lifetime rather than executable behavior.

This is not a bounded-window artifact: both creation and termination are visible for each affected process. It also is not merely an unusually long interactive program; `userinit.exe` is a bootstrap process expected to exit after starting the configured shell. A detection query measuring process lifetime or a graph builder reconstructing ancestry would see a distinctly artificial RDP-only lifecycle.

Apart from this family, lifecycle checks were strong. No matched 4634 precedes its 4624. No eCAR process actor refers to a later visible process creation. Process, module, file, registry, and thread records use stable object/process references, and paired eCAR SSH sessions retain source IP and source port across login/logout.

### Zeek and cross-source detection usability

The three Zeek sensors contain 19,241 connection records with a believable state vocabulary (`SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S1`, `S2`, `S3`) and protocol/source-specific schemas. Every UID in the examined DNS, HTTP, SSL, SMTP, SMB mapping, and SMB file logs resolves to a local connection with the same origin/responder tuple. Every `files.json` connection reference resolves and falls within its connection interval. SSL-to-X.509 chains are complete where referenced.

The three unresolved protocol FUID references are narrowly scoped: one HTTP response FUID and two SMB file FUIDs in `zeek-core`. Their rarity makes independent logging/filter loss plausible, and the briefing explicitly disallows treating incomplete coverage alone as synthetic. I therefore treat these as evidence of realistic collection imperfection, not as a scored contradiction.

### Text-source and signature fidelity

The RFC 5424 syslog records use valid priority/version/timestamp/host/app/procid/msgid/structured-data positions and preserve source-specific messages for sshd, sudo/PAM, systemd-logind, cron, Samba, Postfix, NetworkManager, DHCP, and other services. Proxy and web records parse as combined-style access logs with plausible methods, status codes, body-size conventions, referrers, user agents, and proxy extension fields. ASA priorities, message severities, message IDs, NAT/build/teardown relationships, connection numbers, durations, and byte counts are structurally coherent.

Snort alerts parse in standard fast-alert form. GID/SID/revision tuples, classifications, priorities, protocols, and endpoint formats are internally consistent for DNS-TLD, scan, ICMP, P2P, JA3, policy, and STUN signatures. I found no malformed signature row or endpoint syntax that would prevent conventional ingestion. Without external rule metadata, I did not score whether every SID/revision exactly matches a particular ruleset release.

### Detection usefulness

The corpus would ingest well into a real SIEM and supports high-quality pivots by host, PID, ProcessGuid, logon ID, Zeek UID, FUID, certificate ID, connection tuple, and timestamp. The RDP defects are consequential precisely because the rest is so usable: rules for remote interactive logons lose `TargetUserSid`/`LogonGuid`, process-tree rules receive missing parents, and lifecycle analytics see `userinit.exe` as a long-running session process. These are repeatable rule-engineering failures, not aesthetic objections to a tidy narrative.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `schema_or_format` | Windows Security 4624 | All 4 visible Type-10/RDP logons | Empty `TargetUserSid` and `LogonGuid` values are source-native defects and break common identity pivots. High impact. |
| `contract_gap` | Security 4688 and Sysmon 1 | 12 process starts across all 4 visible RDP startup triplets | Parent PID is present but parent image is empty/`-`; the equivalent normal interactive path is populated. High impact. |
| `schema_or_format` | Windows Security 4688 | All 4 RDP `winlogon.exe` starts | Creator SID, username, and logon ID are empty while the domain remains `NT AUTHORITY`. Medium-high impact. |
| `contract_gap` | Security 4688/4689 and session lifecycle | All 4 visible RDP `userinit.exe` instances | Lifetimes of 2,948–9,263 seconds partition exactly by RDP path, versus 2.95–5.05 seconds for 10 normal instances. High impact. |
| `weak_signal` | Sysmon Event 3 versus Security 5156 | Dataset-wide on Windows hosts | All 899 Event 3 records are initiated outbound despite 6,617 inbound permitted 5156 records; explainable by filtering, so low impact. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Nearly all schemas and value formats are strong, but empty RDP identity/creator fields are material native-event defects.
- **Temporal patterns:** 7/10 — Source precision and most ordering are convincing; RDP `userinit.exe` lifetimes are a repeatable executable-lifecycle fingerprint.
- **Cross-source correlation:** 9/10 — Security, Sysmon, eCAR, and Zeek references correlate extremely well with no observed later-visible initiators; the RDP parent gap is the main exception.
- **Behavioral realism:** 7/10 — Most process, authentication, network, and text-source behavior is plausible, but session-length `userinit.exe` execution is not.
- **Environmental consistency:** 8/10 — Host/source volumes and source-native diversity are convincing; the all-outbound Sysmon Event 3 population is a minor unexplained collection asymmetry.

## Recommendations

If this were synthetic, the highest-value improvement would be to repair the remote-interactive/RDP event family at its shared lifecycle owner rather than patching individual renderers:

- Populate successful Type-10 Security 4624 `TargetUserSid` from the authenticated target identity and emit a valid `LogonGuid` value (a coherent GUID or the native zero-GUID sentinel), never an empty element. Add a test that normalizes the rendered XML and rejects empty required identity fields for successful domain logons.
- Build the complete RDP startup process ancestry before projection: SYSTEM-owned `smss.exe`/appropriate session manager → `winlogon.exe`, then user-owned `userinit.exe` → `explorer.exe`. Render the same parent image and creator identity in Security 4688, Sysmon Event 1, and eCAR, and verify that a parent PID accompanied by a known modeled parent never produces an empty parent image.
- Give `userinit.exe` executable-aware lifetime semantics independent of session lifetime. It should normally terminate a few seconds after shell launch for both local and RDP sessions; session teardown should terminate the shell and remaining session-owned applications, not defer `userinit.exe` until disconnect.
- Add a family regression test covering at least local interactive, RDP to a workstation, and RDP to a server/DC. Assert nonempty 4624 identity fields, complete process ancestry, cross-source PID/ProcessGuid agreement, and a short `userinit.exe` lifetime in every branch.
- Decide whether Sysmon Event 3 is intentionally outbound-only. If so, encode and document that as a collection/filter profile so detection consumers understand the coverage; otherwise emit a limited, realistic set of `Initiated=false` server-side events that correlate with inbound Security 5156 evidence.

