# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 72

## Executive Summary

This six-hour collection is highly realistic at the individual-record and cross-source levels, but
three exact, same-DC Kerberos joins place a service-ticket event (4769) before the ticket-granting
ticket event (4768), and a broader same-host machine-authentication pattern places 4624 before its
nearest 4769 in 119 of 204 tightly matched sequences. Those causal defects outweigh otherwise
excellent Windows, eCAR, Zeek, firewall, IDS, syslog, proxy, and web-log fidelity and make the
corpus more likely synthetic than real.

## Evidence For Synthetic

- `[hard_contradiction]` Three exact KDC-local joins using the same DC, account, client IP, and
  ephemeral port record 4769 before 4768. On DC-01, `WS-MCHEN-01$` at
  `2024-03-18T17:39:46.7752720Z` (4769, record 28261323, port 53991) precedes its 4768 at
  `17:39:46.7868895Z` (record 28261324) by 11.617 ms. `MAIL-FIN-01$` at
  `17:46:49.3378360Z` (4769, record 227, port 54653) precedes 4768 at
  `17:46:49.3687861Z` (record 229) by 30.950 ms. `FILE-SRV-01$` at
  `17:53:18.3714710Z` (4769, record 532, port 56197) precedes 4768 at
  `17:53:18.3794206Z` (record 533) by 7.949 ms. A fresh TGS exchange cannot consume a TGT that the
  same KDC has not issued yet; identical client ports and adjacent record IDs make unrelated
  exchanges implausible.

- `[contract_gap]` KDC-local target-logon timing is systematically inverted. For 204 machine-account
  sequences matched on DC, requester, target service (`DC-01$` or `DC-02$`), and client IP, every
  nearest 4769 fell within 0.812 seconds of the 4624. In 119 cases (58.3%), 4624 came first by
  55.6–811.5 ms, and the 4769 also had a later EventRecordID (usually +2). Because both records are
  in the same DC Security log, host clock skew cannot explain the pattern. The join lacks a unique
  shared identifier, so this is classified as a contract gap rather than counted as 119 independent
  hard contradictions, but the dataset-wide directionality is a strong synthetic timing signature.

- `[contract_gap]` Kerberos GUID correlation is systematically unavailable where it would be most
  useful. All 2,072 Event 4769 records have an all-zero `LogonGuid`, while 148 Event 4624 records
  carry distinct non-zero `LogonGuid` values; none can be joined to a 4769 by that source-native
  identifier. Zero Kerberos GUIDs can occur in production, but the all-or-nothing split across this
  volume weakens SIEM correlation and amplifies the timing ambiguity above.

- `[contract_gap]` Two Zeek HTTP records reference response FUIDs that do not exist in the
  corresponding `files.json`: `zeek-core/http.json` line 952 references
  `FLEcSIMuqYpc4eduGR`, and `zeek-dmz/http.json` line 1807 references
  `FzA0m4BcX0G6KgEYDq3`. One is near the end of the window and could be boundary loss, but the core
  event occurs at `2024-03-18T15:47:09.666369Z`, well inside the window.

- `[distribution_texture]` For the eight Sysmon Event 13 records whose `ProcessGuid` creation is
  visible in-window, the registry event occurs only 3.996–4.109 seconds after process creation.
  This narrow four-second band is small-sample evidence, not a verdict driver by itself, but it
  looks more like a fixed scheduling rule than organic registry-write latency.

## Evidence For Real

- All JSONL and XML files parsed successfully. The Apache-style web/proxy records, RFC 5424-style
  syslog, Snort fast alerts, and tested ASA message families also passed source-specific parsing.
  Windows Event IDs, provider/channel metadata, localized tokens, SID/GUID/IP syntax, and Sysmon
  per-event field sets were internally consistent.

- Windows process joins are exceptionally usable. Of 976 Security 4688 events, 969 joined to
  Sysmon Event 1 within two seconds and the same 969 joined to eCAR `PROCESS/CREATE`; every matched
  triple agreed on image, command line, LogonId, PID, parent PID/image, and principal. Seven
  unmatched records are consistent with selective observation rather than fabricated perfection.

- Logon/token handling is strong. All 419 Event 4672 records resolve to a prior 4624 with the same
  host, LUID, SID, account, and domain; no visible 4634 precedes a later same-LUID 4624; and all 16
  Event 4648 records resolve to a previously visible caller process with matching subject identity
  and LogonId.

- Process and session lifecycles have realistic boundaries. Security contains 770 visible
  4688→4689 pairs with no termination-before-create case; Sysmon has 781 visible Event 1→5 pairs
  with no GUID or identity mismatch; eCAR has 1,689 process create/terminate pairs sharing the same
  object ID with no ordering or identity mismatch. Unmatched starts and ends occur in both
  directions, as expected in a bounded window.

- Network correlation is source-native and deep. All 3,895 Zeek DNS, 3,424 HTTP, 2,538 SSL, 46
  SMTP, 137 SMB mapping, and 234 SMB file records have a parent `conn.json` UID with the same tuple;
  none precede connection start or exceed the visible connection interval. All certificate-chain
  references resolve to X.509 rows and all inspected certificates are valid at observation time.

- Endpoint/network/firewall joins are strong without being literally complete. Of 7,435 Sysmon
  Event 3 records, 7,421 join to Security 5156, 7,402 to Zeek, and 7,361 to eCAR within narrow source
  latency windows. Every matched eCAR flow agrees on PID, image, and principal. The small unmatched
  sets are concentrated in DNS, Kerberos, LDAP, and a handful of other services and look like
  plausible collection loss.

- Firewall and IDS behavior is convincing. All 6,415 parsed ASA TCP teardowns have a prior build,
  matching tuple, non-negative order, and a reported whole-second duration within normal rounding
  of the timestamp delta. All 185 Snort alerts join to an exact Zeek connection tuple; alert
  latency ranges from 107 to 325 ms and rule/message/classification combinations are varied.

- The Security-log clear sequence is particularly source-authentic. DC-01 records `cmd.exe /c
  wevtutil cl Security` and child `wevtutil.exe` in Security 4688, Sysmon Event 1, and eCAR with
  matching PIDs 6032/6056 and parentage. Event 1102 then appears with the correct
  `Microsoft-Windows-Eventlog` provider and `UserData/LogFileCleared` identity, EventRecordID resets
  to 1, and subsequent events continue at 2, 7, 8, 9, and 14 with realistic gaps.

- Activity is not uniformly distributed. Across 360 one-minute buckets, Zeek DNS has a Fano factor
  of 4.66, eCAR process creation 2.08, and connection/flow families show much larger bursts. Process
  durations are also high-entropy: 1,629 distinct millisecond durations among 1,689 paired eCAR
  processes. Periodic Linux jobs use per-host phase offsets and include occasional missing runs.

## Detailed Analysis

### Scope and ingestion

The bounded directory contains 105 files spanning 21 host directories plus network sensors. Major
record counts are 32,991 eCAR, 19,833 Zeek connections, 19,376 ASA, 18,232 Windows Security,
11,542 Sysmon, 3,895 Zeek DNS, 3,869 syslog, 3,424 Zeek HTTP, 2,538 Zeek SSL, 2,524 proxy access,
1,928 Zeek files, 1,074 X.509, 710 web access, 424 bash-history lines, and 185 Snort alerts. The
machine-readable sources cover approximately `2024-03-18T12:00:01Z` through
`2024-03-18T17:59:56Z`, consistent with the stated six-hour boundary.

Every JSON line decoded, every Windows XML document parsed, and all tested text records matched
their expected framing. Windows timestamps consistently use seven fractional digits, Sysmon's
embedded `UtcTime` uses milliseconds, eCAR uses integer epoch milliseconds, and Zeek uses numeric
epoch seconds with microsecond precision. Sysmon envelope timestamps trail embedded `UtcTime` by
roughly 0.1–83 ms, with event-dependent variation rather than one constant offset.

### Windows schema and event semantics

The Security corpus includes common authentication and process events (4624, 4625, 4634, 4648,
4672, 4688, 4689), KDC events (4768, 4769, 4771, 4776), object/share events (4656, 4658, 4663,
5140, 5145), WFP 5156, session lock/unlock/disconnect events, and sparse account/service/task/audit
events. For each Event ID, the observed EventData field order and the System tuple
`Version/Level/Task/Opcode/Keywords/Channel` were stable and appropriate to that event family.
Failure events use failure keywords, while success events use success keywords. SIDs, GUIDs, IPv4
and IPv4-mapped IPv6 addresses, hexadecimal LUIDs/PIDs, and access masks are syntactically valid.

Event 4624 values are credible: types 2, 3, 5, 7, 9, and 10 appear; NTLM uses `NtLmSsp`, `NTLM V2`,
and 128-bit keys; service logons use `Advapi`; Kerberos and Negotiate combinations fit their event
contexts. Event 4625 status/substatus pairs distinguish bad-password and disabled-account cases.
Event 5156 direction tokens are consistent with host placement: all 6,566 inbound-token records
place the host IP at the destination, while all 5,039 outbound-token records place it at the source
(self-directed DC cases naturally satisfy both).

The primary Windows defect is causal, not lexical: the three exact 4769-before-4768 sequences. Of
306 exact KDC joins on DC/account/client-IP/client-port, 303 have the correct 4768→4769 order and
three invert it. The inverted rows occur in one source-local EventRecordID stream, so cross-host
clock skew and collector arrival order are not viable explanations.

### Logon, token, and session consistency

There are 802 successful logons and 383 logoffs. Using host plus `TargetLogonId`, 375 logoff keys
have a visible prior logon and eight are credible pre-window sessions; no logoff has only a later
same-LUID logon. User/SID/domain identity is stable across all matched pairs. Network-logon
durations are varied (1.70 seconds to 13,743 seconds), while RDP/type-10 durations range from 1,151
to 10,713 seconds. The one apparent type-7→type-2 mismatch is explainable: an unlock 4624 reuses
the existing interactive LUID, and the eventual 4634 reports the underlying interactive type.

All 419 special-privilege assignments follow a matching 4624 by 0.9–84.2 ms and preserve identity.
All 16 explicit-credential events reference an already visible process and preserve the caller's
SID, account, domain, and LogonId. Sysmon and eCAR process records carry the same token identity as
Security 4688 on all 969 matched creations. These are exactly the joins a SIEM detection stack
needs for token/session-aware process detections.

Kerberos `LogonGuid` behavior is weaker. All 2,072 4769s are zero-GUID even though 148 4624s have
distinct non-zero values. Composite joins remain possible, but exact GUID pivots do not. More
concerning, the zero-GUID machine-account set produces 204 same-DC requester/service/IP matches
within 0.812 seconds, with 119 target logons before ticket issuance. This broad inversion has lower
proof strength than the three shared-port contradictions but is too systematic to dismiss as
occasional unrelated traffic.

### Process, eCAR, and rule-oriented correlation

Security 4688→Sysmon Event 1 joins have a plausible source delay: Sysmon leads Security by 35–636
ms (median 133 ms). Security 4688→eCAR creation ranges from eCAR leading by 594 ms to lagging by
781 ms (median eCAR lag 18 ms). Command line, image, process ID, parent ID/image, user, and LogonId
are exact across the 969 matched triples. Security 4689 and Sysmon Event 5 preserve the creation
identity whenever the creation is visible.

Sysmon dependent-event semantics are also strong. No Event 3, 7, 11, 13, or 22 references a
`ProcessGuid` whose creation appears only later in the visible window. Event 8 and Event 10 source
and target PIDs/images agree with any visible Event 1 record, and every one of the seven remote
thread events has a prior Event 10 for the same source/target GUID pair. The many dependencies on
processes without visible starts are consistent with a bounded slice and mostly involve long-lived
system processes.

eCAR has unique event IDs and consistent host placement. Its 1,689 paired process lifecycles reuse
the process object ID and preserve PID, image, and principal; its 467 paired session lifecycles
reuse the session object ID. All 2,597 flows whose actor process creation is visible occur after
that creation. There are 123 file records using a source-specific `file-00000000...` object-ID
grammar rather than UUIDs, but the field remains a string and the IDs are stable on reuse; without
an external schema contract this is not treated as a defect.

### Zeek, firewall, IDS, web, proxy, and Linux evidence

UID integrity is excellent across three Zeek sensors. Every DNS/HTTP/SSL/SMTP/SMB child row finds
one sensor-local connection with the same four-tuple and protocol, all child timestamps fit the
connection interval, UDP IP-byte arithmetic is exact, and no S0 history contains an impossible
handshake. Certificate references and validity windows are consistent. The two missing HTTP FUID
targets are the only direct Zeek relational gaps found.

The 7,421 Sysmon→5156, 7,402 Sysmon→Zeek, and 7,361 Sysmon→eCAR network joins demonstrate that
source ports, destinations, protocols, processes, and users are operationally pivotable. Zeek and
eCAR observation is not perfectly complete, which is realistic. Snort alerts cover DNS policy,
P2P, scans, ICMP, STUN, user-agent, CONNECT, basic-auth, JA3, and other rule families; all 185 have
an exact Zeek tuple. ASA build/teardown IDs and rounded durations behave correctly.

All 3,869 syslog rows pass RFC 5424-style framing with host/application/PID fields. Bash histories
have valid epoch-marker/command pairs; 126 of 212 commands exactly match an eCAR process on the
same host and user within 60 seconds, with eCAR offsets from -0.309 to +2.884 seconds. Many
unmatched commands are shell built-ins or pipelines, so the incomplete match rate is expected.
The proxy and web logs parse cleanly and include realistic status, method, byte-count, referrer,
authentication, and user-agent variation.

### Operational detection texture

The collection supports practical detections rather than only demonstration events: account
creation/reset/change/group membership, service installation, explicit credentials, WFP permits,
process access/remote thread, suspicious DNS and scan alerts, SMB object access, and an audit-log
clear all retain the fields normally used in Sigma or SIEM content. EventRecordID gaps vary by host
and source, and the audit-clear reset is modeled at the native record stream rather than merely as
an isolated 1102 row.

The baseline is bursty. Zeek connection minute bins have a mean of 55.1 but a standard deviation
of 160.9 because of concentrated network bursts; DNS and process creation are also overdispersed.
Process commands include periodic system activity, per-user administration, interactive tools,
and service behavior. The four-second Sysmon registry offset is the only narrow repeated
event-family latency found that rises above a weak distribution concern.

## Synthetic Indicator Summary

| Indicator | Classification | Affected family | Scope | Effect on assessment |
|---|---|---|---|---|
| 4769 precedes exact same-port 4768 | `hard_contradiction` | Windows Security / Kerberos | 3 of 306 exact AS↔TGS joins, all on DC-01 | High; impossible source-local causality and the main verdict anchor |
| 4624 precedes nearest same-DC 4769 | `contract_gap` | Windows Security / machine Kerberos logons | 119 of 204 tightly matched requester/service/IP sequences | High; systematic same-host timing inversion, though no unique shared ID |
| KDC 4769 GUIDs are universally zero | `contract_gap` | Windows Security / Kerberos SIEM joins | 2,072 of 2,072 4769s; 148 non-zero 4624 GUIDs cannot join | Medium; removes a native correlation path and weakens causal attribution |
| HTTP references absent files rows | `contract_gap` | Zeek HTTP/files | 2 records across core and DMZ; one well inside window | Low-medium; dangling source-native identifiers |
| Near-fixed process→registry delay | `distribution_texture` | Sysmon Event 1/13 | 8 visible pairs, 3.996–4.109 seconds | Low; small sample but unusually rigid |

No independent `schema_or_format` defect was established. The source schemas and field grammars
were a major realism strength; the decisive issues are causal and relational.

## Realism Score by Category

- **Field format accuracy: 9/10** — All structured sources parsed, Windows/Sysmon schemas and
  localized field values were credible, and no definite field-format violation was found.
- **Temporal patterns: 5/10** — Broad timing texture is realistic, but exact KDC inversions and the
  119/204 target-logon ordering pattern materially reduce authenticity.
- **Cross-source correlation: 8/10** — Process, flow, firewall, IDS, and Zeek joins are excellent;
  Kerberos GUID loss and two dangling FUIDs prevent a higher score.
- **Behavioral realism: 9/10** — Process/session lifecycles, service activity, shell use, network
  bursts, rule diversity, and audit clearing behave like an operational environment.
- **Environmental consistency: 9/10** — Host roles, addresses, directionality, source volumes, and
  source-family coverage are coherent throughout the six-hour slice.

## Recommendations

1. **P0 — Enforce source-local AS→TGS ordering.** If this were synthetic, generate or schedule
   4768 before every causally dependent 4769 for the same KDC/account/client tuple. Add an exact
   invariant keyed by DC, account, client IP, and client port, and test EventRecordID as well as
   timestamp order across log-clear boundaries.

2. **P1 — Make target authentication follow ticket issuance.** For machine authentications to a DC,
   require the KDC 4769 to precede the target 4624 in the same Security stream. Apply source-native
   latency after causal order is established; do not let independent per-event delays invert the
   sequence. Verify all machine, user, service, and DC-to-DC sibling paths.

3. **P1 — Preserve a usable Kerberos correlation contract.** Propagate a shared non-zero
   `LogonGuid` where the source-native events would expose one, or consistently model a platform
   path where the GUID is unavailable. Tests should prove that any non-zero 4624 GUID has the
   intended 4769 counterpart and that zero-GUID cases remain joinable on a documented composite.

4. **P2 — Make Zeek HTTP/file observation atomic.** When `http.resp_fuids` is retained, retain the
   corresponding `files` row under the same observation decision; otherwise omit the dangling
   reference. Include an end-of-window case and an ordinary mid-window response in regression
   tests.

5. **P3 — Broaden registry-event timing.** Replace the near-fixed four-second ProcessGuid-to-Event-13
   offset with source- and action-aware latency variation, while preserving process-before-registry
   causality.

6. **P4 — Protect the strong existing contracts.** Retain the current 4688/Sysmon/eCAR identity
   joins, eCAR lifecycle object reuse, Zeek UID/tuple integrity, ASA build/teardown behavior, Snort
   tuple fidelity, and Security-log-clear record-ID reset in any future changes.
