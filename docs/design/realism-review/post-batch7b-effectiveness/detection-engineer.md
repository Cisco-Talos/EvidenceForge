# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment: Synthetic**

**Verdict Confidence: 98**
**Synthetic-Confidence Score: 96**

## Executive Summary

The corpus is highly polished synthetic telemetry. Native envelopes, identifiers, paths, hashes, and most causal joins are unusually well constructed, but several log-visible defects are incompatible with genuine endpoint collection.

The decisive defect is systematic corruption of Windows Filtering Platform Event 5156 process ownership. Across 3,032 inbound records matched to endpoint flow telemetry, 2,529 name a local destination executable but carry the wrong local PID; 2,438 carry the exact PID of the remote client process. In 262 records, the application is literally `System` while `ProcessID` is not PID 4. One record even assigns a Linux `rsyncd` PID to the Windows `System` process.

Independent distribution defects reinforce the conclusion: Linux PIDs track wall-clock time at an essentially exact two PIDs per second across two different hosts for six hours, and Windows LogonIDs advance at nearly identical rates across seven independent machines. These are bounded generator formulas, not organic allocator behavior.

This conclusion does not rely on filesystem metadata, domain sanitization, optional-source coverage, completeness of cross-source matching, or narrative neatness.

## Evidence For Synthetic

- **[hard_contradiction] Windows inbound WFP events merge identities from opposite hosts.** Of 3,032 inbound Event 5156 records matched to local eCAR flow records, 2,529 (83.4%) disagree with the local endpoint PID. In 2,438 cases, the Security event PID equals the remote actor PID instead.

  - Tuple `10.44.10.25:50320 → 10.44.20.10:53/udp`:
    - WS-VHALE eCAR at `1715688050317`: outbound `svchost.exe`, PID `4952`.
    - DC eCAR at `1715688050301`: inbound `dns.exe`, PID `5656`.
    - DC Security record `15385692`, `2024-05-14T12:00:50.9956742Z`: `Application=\device\harddiskvolume1\windows\system32\dns.exe`, but `ProcessID=4952`.
    - Thus the destination record names the destination image but copies the source-host PID.

  - Tuple `10.44.30.10:62142 → 10.44.20.20:445/tcp`:
    - WEB eCAR: `/usr/sbin/rsyncd`, Linux PID `303504`.
    - FILE eCAR: inbound `System`, local PID `4`.
    - FILE Security record `2584920`, `2024-05-14T12:01:00.5406366Z`: `Application=System`, `ProcessID=303504`.
    - A Windows `System` process is PID 4, not the remote Linux PID. This is a direct source-contract contradiction.

- **[hard_contradiction] Invalid `System` PID morphology is systemic.** Among 1,275 Event 5156 rows with `Application=System`, 262 use a PID other than 4; every one has inbound direction `%%14592`. Examples include `303504` and `1237257`, values visibly copied from Linux processes.

- **[distribution_texture] Linux PID allocation is clock-derived.** Across 206 eCAR `PROCESS/CREATE` records:

  - PROXY: PID `1247787` at `1715688062.024`; final PID `1290005` at `1715709171.750`. A two-PIDs-per-second formula predicts `1290006`.
  - WEB: PID `316676` at `1715688180.723`; final PID `358732` at `1715709208.536`. The same formula predicts exactly `358732`.
  - All 206 observations remain within five PID values of `anchor_pid + round(2 × elapsed_seconds)` over nearly six hours; 200 are within two.
  - All 55 independently visible new-process syslog PIDs selected from CRON, sudo, su-open, and SSH connection records are also within two steps of the same formula. Two separate hosts cannot organically maintain a bounded, identical, exactly 2 Hz process-counter rate through bursty workloads.

- **[distribution_texture] Windows LogonIDs share a common clock-rate formula.** Across 796 non-unlock Event 4624 logons on seven hosts, LogonID versus UTC time has per-host \(R^2\) between `0.999996676` and `0.999999509`. All fitted slopes fall in the tiny range `136.457–136.579` LUID values per second, including domain controller, file server, and workstations. LUID counters should reflect independent host-specific allocation workloads, not a common near-perfect wall-clock slope.

- **[contract_gap] Some Zeek files exceed their containing connection payload.** In 22 of 196 SMB file records, `files.log seen_bytes` exceeds the sender-direction `conn.log resp_bytes`.

  - UID `CWBNWQnG474cH7g5bx`: `files.log seen_bytes=46904`, `missing_bytes=0`; corresponding `conn.log resp_bytes=46345`.
  - A fully observed 46,904-byte file cannot be extracted from only 46,345 response payload bytes. The 22 discrepancies range from 36 to 559 bytes.

## Evidence For Real

- **Native Windows morphology is otherwise strong.** The review parsed 10,325 Security and 3,609 Sysmon events. Every sampled EventID has the expected field family and types. Examples include:

  - Event 4624 version 2 with SIDs, hexadecimal LogonIDs, logon type, process, address, and token fields.
  - Event 4688 version 2 with hexadecimal process IDs, command line, parent image, integrity SID, and token-elevation code.
  - Sysmon Event 1 version 5 with `ProcessGuid`, hash quartet, parent identity, LogonID, terminal session, and integrity level.
  - Sysmon Event 10 correctly uses the native `SourceProcessGUID`/`TargetProcessGUID` capitalization, whereas Event 8 uses `SourceProcessGuid`/`TargetProcessGuid`.
  - EventRecordIDs are unique, ordered, and contain plausible gaps.

- **Process GUID and lifecycle behavior is credible.** All 714 Sysmon process-create GUIDs have host-stable machine prefixes, unique tails, and embedded creation seconds consistent with the event timestamp. Across 497 visible create/terminate pairs, there are zero negative lifetimes and zero PID/image mismatches. No dependent Sysmon event with a visible lifecycle falls before create or after termination.

- **Windows cross-provider process joins are accurate outside the WFP defect.** Of 718 Security Event 4688 rows, 713 match a Sysmon Event 1 on host, PID, image, and approximately two-second timing, with zero matched image disagreements. Hash lengths are valid, and all 59 executable path/version groups observed on multiple hosts use the same hash set.

- **Identity data is coherent.** Domain SIDs consistently use `S-1-5-21-1195943476-1993654859-1558797721-*`, with stable RIDs per user and computer. Built-in principals use correct SIDs such as `SYSTEM=S-1-5-18`, `LOCAL SERVICE=S-1-5-19`, and `ANONYMOUS LOGON=S-1-5-7`. Visible logon/logoff pairs do not run backward.

- **Zeek joins are exceptionally clean.**

  - All 6,547 `conn.log` UIDs are unique.
  - All 1,057 DNS, 784 HTTP, and 1,099 SSL rows resolve to a matching connection UID and exact four-tuple.
  - All 881 file rows resolve to a connection and have correct transfer direction.
  - All 640 X.509 FUIds are referenced by SSL chains; all 640 certificate fingerprints equal the corresponding file SHA-1.
  - All certificates are valid at observation time.
  - Parser timestamps remain within their associated connection intervals.

- **Text formats look source-native.** RFC 5424 Linux syslog PRI/version/header morphology, Apache-style access records, Cisco ASA message IDs `302013/302014/106023`, and Snort fast-alert records are syntactically plausible.

- **Some multi-sensor timing is convincing.** The external SYN from `156.32.3.55:3709` to `10.44.30.10:22` appears as a Zeek `S0`, a WEB UFW block, an ASA build, and an ASA teardown 30 seconds later with `SYN Timeout`, all with compatible tuple and timing.

## Detailed Analysis

### Corpus and schema coverage

The assessment parsed approximately 53,601 logical records or text lines:

- 11,043 Zeek JSON records.
- 17,028 eCAR records.
- 13,934 Windows XML events.
- 7,352 Cisco ASA messages.
- 2,247 Linux syslog messages.
- 1,240 proxy-access records.
- 601 web-access records.
- 50 Snort alerts.
- 106 bash-history lines.

All JSON lines parsed successfully, and all Windows XML documents parsed without malformed events. JSON fields remained type-stable within each source.

### Windows event contracts

Security events cover EventIDs 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4768, 4769, 4771, 4776, 4800, 4801, and 5156. Sysmon covers EventIDs 1, 3, 5, 7, 8, 10, 11, 13, and 22.

Most schemas and value morphologies are good: hexadecimal Windows PIDs where expected, decimal Sysmon PIDs, correct SID families, device-form WFP paths, plausible access masks, uppercase hashes of correct lengths, and structured Sysmon GUIDs.

The Event 5156 ownership problem is therefore not a cosmetic schema error. The record carries a valid-looking field set but violates what the fields mean. Outbound records almost universally retain the correct local PID. The failure concentrates on inbound events, where the destination application is selected correctly but the originator PID is carried across the host boundary. That directional concentration is strong evidence of deterministic construction logic.

### Process, session, and identifier correlation

Process lifecycles are well maintained in Sysmon and eCAR. Process identity, image, principal, parent, and termination data remain stable within visible lifetimes. Security 4688 and Sysmon Event 1 timestamps normally differ by only milliseconds.

LogonIDs are valid hexadecimal values and normally nondecreasing. Unlock Event 4624 type 7 correctly reuses the prior interactive LogonID. The synthetic indicator is not monotonicity itself; it is the nearly identical allocation slope and near-perfect linear relationship on every independent host.

### Network and protocol correlation

The tuple `10.44.10.25:50320 → 10.44.20.10:53/udp` illustrates both strengths and weaknesses:

- Zeek UID `CmDh05a1FCAWTH4WAf` has `service=dns`, `duration=0.063953`, `orig_bytes=53`, `resp_bytes=89`, and `conn_state=SF`.
- Its DNS record uses the same UID and tuple, asks `20.20.44.10.in-addr.arpa`, and returns `FILE-BO-01.northstar-branch.local`.
- Source eCAR identifies workstation `svchost.exe` PID 4952.
- Destination eCAR identifies `dns.exe` PID 5656.
- Destination Security 5156 incorrectly combines destination `dns.exe` with source PID 4952.

Thus the network truth is coordinated, but one renderer or source model violates endpoint ownership.

Connection-state/history combinations are generally plausible: TCP `S0/S`, `REJ/Sr`, successful `SF` histories, UDP `SF/Dd`, and bounded byte/packet accounting. The SMB file-size violations are localized but concrete.

### Temporal and distribution analysis

Causal ordering is mostly credible: transport precedes protocol records, SSH connections precede authentication/session-open records, process dependencies remain inside visible lifetimes, and logoff/termination events follow starts.

The allocator distributions are the major exception. A real PID counter advances when processes are created, so its residual from a constant wall-clock rate performs a workload-dependent random walk. Here the residual stays bounded within a handful of values for six hours. The same exact 2 Hz rule appears on both Linux systems. Windows LUID allocation displays a parallel, host-independent formula.

These bounded relationships are far stronger than merely “smooth” activity or a compressed narrative.

### Environmental consistency

Hostnames, IP roles, domain SIDs, user placement, Windows versus Linux paths, service images, and source-native principal styles are coherent. Internal addresses consistently map to workstations, domain services, file services, proxy, and web roles. Public-facing scanner traffic is also consistently represented at Zeek, ASA, UFW, web, and IDS layers.

No material authenticity conclusion was drawn from sanitized names, unresolved domains, absent optional logs, or uniform file timestamps.

## Synthetic Indicator Summary

| Indicator | Label | Quantified evidence | Weight |
|---|---|---:|---|
| Inbound Event 5156 names a local application but uses a remote-host PID | `hard_contradiction` | 2,529/3,032 inbound matches disagree with local PID; 2,438 exactly copy remote PID | Critical |
| `Application=System` paired with non-4 PID | `hard_contradiction` | 262/1,275 `System` WFP rows; all inbound | Critical |
| Linux process IDs follow a two-per-second wall-clock formula | `distribution_texture` | All 206 eCAR creates within ±5; both hosts share the rule | High |
| Windows LogonIDs have a shared linear clock rate | `distribution_texture` | 796 logons; seven slopes within 136.457–136.579/s; \(R^2>0.999996\) | High |
| SMB file bytes exceed containing TCP response payload | `contract_gap` | 22/196 SMB files; excess 36–559 bytes | Medium |

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 8/10 | Excellent native morphology, GUIDs, SIDs, hashes, and schemas; materially reduced by invalid WFP process ownership. |
| Temporal patterns | 4/10 | Causal ordering is strong, but PID and LUID allocator behavior is deterministically clock-derived. |
| Cross-source correlation | 7/10 | UIDs, tuples, processes, files, and certificates join very well; inbound PID attribution breaks a fundamental ownership invariant. |
| Behavioral realism | 7/10 | Diverse endpoint, service, user, scanner, and protocol activity; allocator distributions remain recognizably generated. |
| Environmental consistency | 8/10 | Roles, paths, principals, SIDs, and address topology are internally coherent. |

## Recommendations

1. Make endpoint process identity host-local. For inbound WFP Event 5156, populate both `ProcessID` and `Application` from the destination listener; never carry the originator PID across the host boundary.

2. Add an invariant that `Application=System` requires PID 4 on current Windows versions. Validate PID/image pairs against local process state before rendering.

3. Replace wall-clock PID and LogonID formulas with stateful allocators driven by actual generated creation/allocation events plus independent, host-specific background activity. Residuals should drift and respond to bursts.

4. Enforce network accounting rules before release: extracted `seen_bytes` must not exceed the corresponding directional connection payload, and connection/file missing-byte fields must agree.

5. Retain the strong existing features: Sysmon GUID morphology, lifecycle control, SID consistency, hash reuse by file version, Zeek UID joins, certificate-chain linkage, and ASA/UFW/Zeek tuple coordination.

6. Add automated authenticity gates that specifically test source semantics—not only field presence—including local/remote ownership, PID/image validity, lifecycle ordering, allocator distributions, and byte conservation.
