# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 86/100  
**Synthetic-Confidence Score:** 76/100

## Executive Summary

The dataset is highly realistic in source formatting, lifecycle construction, and cross-source correlation. Windows Security/Sysmon metadata, Zeek protocol records, Cisco ASA messages, RFC 5424 syslog, proxy logs, web access logs, and endpoint telemetry mostly agree at a level expected from a carefully constructed enterprise collection.

I nevertheless assess it as synthetic because several concrete, log-visible defects are difficult to reconcile with independently produced telemetry. The strongest are a foreign endpoint address attached to a local Windows 4648 `runas /netonly` chain, a Windows Server 2022-era host emitting the pre-1903 Event 4698 schema, and an exact millisecond-offset lattice across all 120 SMB tree-mapping records. A dataset-wide SSH authentication-delay floor and an unusually bounded one-way Security 4688-to-Sysmon 1 latency distribution add supporting weight. I did not use filesystem timestamps, sanitized domains, source completeness, or cross-source completeness as synthetic indicators.

## Evidence For Synthetic

- **[hard_contradiction] Foreign source address in a local explicit-credential chain.** On `WS-MCHEN-01`, Security record 949277 at `2024-03-18T14:49:49.1276573Z` creates `runas.exe /netonly /user:marcus.chen "cmd.exe /c dir \\DC-01\ADMIN$"` under subject logon ID `0x6c6a067`. Record 949278 at `14:49:52.2635083Z` creates the expected Type 9 logon, and record 949279 at `14:49:52.2704192Z` logs Event 4648 for `C:\Windows\System32\runas.exe`, target server `DC-01`, but gives `IpAddress=10.10.1.99`. Endpoint FLOW records establish `10.10.1.31` as the source address for all 475 outbound flows from `WS-MCHEN-01`; `10.10.1.99` is the source address for all 189 outbound flows from `LT-MRIVERA-02`. The 4648 address therefore belongs to a different endpoint and is neither the local caller nor the named target. Record 949281 closes the Type 9 session at `14:49:57.9679919Z`. This is a concrete actor/source ownership leak inside an otherwise tightly correlated event chain.

- **[schema_or_format / environment_or_collection_plausibility] Event 4698 uses an obsolete schema for the observed host build.** `DC-01/windows_event_sysmon.xml` record 3288912 at `2024-03-18T12:02:12.1079573Z` identifies a Microsoft binary with `FileVersion=10.0.20348.1`, consistent with Windows Server 2022. On the same host, Security record 28257003 at `2024-03-18T16:20:05.8737054Z` is Event 4698 Version `0` and contains only `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`, `TaskName`, and `TaskContent`. The Server 2022-era 4698 schema is Version 1 and adds client-process/RPC provenance fields. The event is internally valid as the older schema, but inconsistent with the platform evidenced by the same host.

- **[distribution_texture] Every SMB tree mapping preserves the connection's sub-millisecond residue.** All 120 records in `zeek-core/smb_mapping.json` occur an exact integer number of milliseconds after their matching `conn.json` start. Examples: UID `CmL72541muLut0VFcf` moves from `1710763446.149118` to `1710763446.202118` (+53.000 ms); `CVsFITYlL24ruppq9z` moves from `1710763452.246819` to `1710763452.391819` (+145.000 ms); and `CPqs74V5duw86dpfPt` moves from `1710763581.664833` to `1710763581.765833` (+101.000 ms). Independent SMB tree-connect packets should not preserve the TCP SYN's final three microsecond digits for 120 of 120 sessions. HTTP, SSL, and file records in the same Zeek collection do not show this 100% lattice, which argues against a collector-wide timestamp quantization effect.

- **[distribution_texture] SSH authentication has a hard multi-second floor across the population.** Forty-one matched `sshd` connection/accept pairs have delays from 5.306511 to 13.744034 seconds; none authenticate faster than 5.3 seconds, across both password and public-key modes. `WEB-EXT-01/syslog.log` lines 148–149 show public-key authentication from `12:42:04.322117Z` to `12:42:09.628628Z` (+5.306511 s). `DB-PROD-01/syslog.log` lines 220–221 show password authentication from `17:14:43.467071Z` to `17:14:48.876131Z` (+5.409060 s). `APP-INT-01/syslog.log` lines 111–114 show connection at `14:15:01.546432Z`, password acceptance at `14:15:15.290466Z` (+13.744034 s), PAM open at `14:15:15.438988Z`, and logind session creation at `14:15:15.988357Z`. Occasional delays of this size are plausible, but the population-wide lower bound is characteristic of a bounded timing model.

- **[weak_signal / distribution_texture] Windows process-source latency is strictly one-way and tightly bounded.** Across 971 paired Security 4688 and Sysmon Event 1 records on ten Windows hosts, every Security event follows Sysmon by 35.405–646.416 ms; there are zero negative deltas. The minimum pair is `DC-01` Security record 28247331 at `12:44:53.6498148Z` versus Sysmon record 3289494 at `12:44:53.6144091Z` for PID 3484, `dllhost.exe`. The maximum is `WS-EBROOKS-01` Security record 949300 at `12:42:52.4141643Z` versus Sysmon record 359639 at `12:42:51.7677484Z` for PID 4108, `firefox.exe`. Provider ordering can create a bias, so this is not a contradiction by itself; the absence of any inversion or longer queueing outlier across 971 pairs is the suspicious part.

## Evidence For Real

- **Windows source-native accuracy is generally excellent.** Security Event 4624 uses Version 2 and appropriate logon fields; 4688 uses Version 2 with hexadecimal process IDs; Sysmon Event 1 uses Version 5; and Sysmon Events 3, 5, 7, 8, 10, 11, 13, and 22 carry plausible version-specific fields. Process images, command lines, parent IDs, and logon IDs agree in all 971 directly paired Security 4688/Sysmon 1 records. No paired process had a parent or logon-ID mismatch, and no visible process termination preceded its creation.

- **Security-log lifecycle behavior is coherent.** `DC-01` Event 1102 at `2024-03-18T17:42:34.7208375Z` uses the `Microsoft-Windows-Eventlog` provider, the expected `LogFileCleared` UserData structure, SYSTEM subject identity, and record-ID reset behavior. The examined logon/logoff, handle open/access/close, process create/terminate, service install, account management, Kerberos, share access, and firewall events preserve expected ordering and field relationships.

- **Zeek DNS and HTTP records look source-native and correlate at the protocol level.** `zeek-core/conn.json` line 1 and `dns.json` line 1 share UID `CF30UwQtycUEYRxyqc`, timestamp `1710763222.752904`, tuple `10.10.1.31:64758 -> 10.10.2.11:53/udp`, and a plausible 655-microsecond request/response interval. The DNS record contains coherent A-query flags, `NOERROR`, answer `10.10.2.11`, and TTL 300. `http.json` line 2 reports a 25,468-byte `/blog` response with FUID `FORJH23kIG62BsDqL5`; `files.json` line 1 carries the same FUID and UID and reports `seen_bytes=total_bytes=25468`. The corresponding web access row records `GET /blog`, status 200, and 25,468 bytes at `18/Mar/2024:12:01:07 +0000`.

- **Network populations have realistic breadth.** Core Zeek connection states include `SF`, `S0`, `RSTO`, `RSTR`, `OTH`, `REJ`, `S2`, and `S3`, with nonzero missed-byte cases. Core DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries and `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED` responses. TLS records mix TLS 1.2/1.3, session reuse, several ciphers, and certificate chains whose observation times fall within their validity windows.

- **Firewall, proxy, and web values use plausible native semantics.** ASA records use `%ASA-6-302013` built-connection messages with stable connection IDs and NAT/interface notation. For the HTTP connection at `12:00:43`, Zeek UID `CLA3qE1S4ol5Wmx5X` reports `orig_ip_bytes=872` and `resp_ip_bytes=514`; the associated ASA accounting totals 1,386 bytes, exactly their sum. The proxy distinguishes a `407` authentication-control response from a successful `CONNECT` tunnel and keeps control-message bytes separate from tunnel bytes; all 642 inspected tunnel parent/child relationships satisfied their byte and duration bounds.

- **DHCP and endpoint timing show convincing stateful behavior.** `zeek-core/dhcp.json` lines 1–4 contain differentiated one-, two-, and four-hour leases, stable client/MAC assignments, and nonuniform REQUEST/ACK durations. Host syslog renewal messages recur near T1 with per-client jitter rather than at one global interval. Endpoint login/logout, process create/terminate, and network FLOW records showed no visible lifecycle inversions.

- **Linux logs are detailed and individualized.** RFC 5424 formatting, sshd/PAM/logind sequencing, package-manager activity, systemd timers, log rotation, and service messages are structurally plausible. Twenty-six shell-history files were monotonic, contained no malformed timestamp/command pairs, and did not reuse a broad common command script across hosts.

## Detailed Analysis

The assessment covered complete-file parsing and targeted record inspection across Windows Security XML, Sysmon XML, endpoint eCAR JSON, Zeek `conn`, `dns`, `http`, `ssl`, `files`, `x509`, `ocsp`, `smtp`, `dhcp`, `smb_mapping`, and `smb_files`, Cisco ASA, Snort, proxy, web access, RFC 5424 syslog, and shell histories. Well over 20 individual records were manually inspected, while population checks covered thousands of Windows events, all available Zeek protocol rows, 642 proxy tunnels, 971 paired Windows process events, 120 SMB mappings, and 41 SSH sessions.

Schema and event-ID accuracy strongly favor authenticity in most areas. Event IDs and versions match normal Windows contracts almost everywhere, including 4624/4625/4634, 4648, 4656/4658/4663, 4672, 4688/4689, 4697, account/group events, Kerberos events, share events, WFP 5156, and the observed Sysmon families. The Event 4698 version/build conflict is conspicuous precisely because the remainder is so accurate. Sysmon registry Event 13 entries also use correctly ROT13-encoded UserAssist paths such as `JVAJBEQ.RKR` and `sversbk.rkr`.

Correlation integrity is the dataset's strongest realism feature. Zeek protocol UIDs resolve to connection records and their timestamps remain within connection intervals. HTTP FUIDs, content sizes, web access rows, ASA tuples, endpoint FLOWs, and SSH tuple/session identities agree. These matches were treated as positive realism evidence, not as proof of synthesis. The WS-MCHEN 4648 anomaly differs qualitatively: it is not “too-perfect” matching but a specific foreign-host value placed in a local event contract.

Timestamp precision is mixed. Seven-digit Windows timestamps, six-digit syslog/Zeek timestamps, and millisecond endpoint timestamps are individually appropriate. Process termination offsets cross both sides of their paired source timestamps, which resembles independent collection. In contrast, the SMB mapping timestamps preserve connection microseconds exactly in every case, and SSH authentication delays occupy a conspicuously bounded range. Those population shapes are difficult to explain as ordinary source semantics or a single collection clock.

Behaviorally, the dataset contains credible background diversity: browser navigation and assets, OCSP, TLS resumption, SMTP, SMB shares/files, DHCP renewal, scheduled/service activity, stale/noisy authentication, scans and alerts, and user-specific commands. It does not rely on a single linear attack narrative. The synthetic conclusion therefore rests on the concrete defects and distributions above, not on narrative neatness, missing sources, lack of retries, or sanitized names.

## Synthetic Indicator Summary

| Category | Scope | Concrete indicator | Weight |
|---|---:|---|---|
| `hard_contradiction` | One credential-use chain | `WS-MCHEN-01` Event 4648 assigns LT-MRIVERA's `10.10.1.99` to a local `runas.exe` chain targeting `DC-01` | High |
| `schema_or_format` / `environment_or_collection_plausibility` | One scheduled-task event | Server 2022-era build evidence conflicts with Event 4698 Version 0 and its truncated pre-v1 field set | Medium-high |
| `distribution_texture` | 120/120 SMB mappings | Tree-connect timestamps are exact integer-millisecond offsets from connection starts and preserve SYN microsecond residues | High |
| `distribution_texture` | 41/41 SSH accepts | Every authentication takes at least 5.306511 seconds, across password and public-key methods | Medium |
| `weak_signal` / `distribution_texture` | 971 process pairs | Security 4688 always follows Sysmon 1 by 35.405–646.416 ms, with no inversion or long-tail outlier | Low-medium |

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 8/10 | Source-native structure is strong; Event 4698 is the major exception. |
| Temporal patterns | 6/10 | Broad timing is plausible, but SMB, SSH, and process-pair distributions expose bounded generation patterns. |
| Cross-source correlation | 9/10 | UID, tuple, byte, process, session, and lifecycle joins are unusually thorough and mostly correct. |
| Behavioral realism | 8/10 | Background activity is varied, stateful, and role-appropriate across hosts and protocols. |
| Environmental consistency | 7/10 | Host roles and addressing are coherent except for the 4648 endpoint leak and 4698 platform/schema mismatch. |

## Recommendations

1. Populate Windows 4648 network fields from the actual caller/event-source context. Add a multi-host invariant that a locally executed `runas /netonly` event cannot inherit an unrelated remote endpoint's address.
2. Select Windows Security event versions from the modeled OS build. For Server 2022-class hosts, emit Event 4698 Version 1 and its client process, parent process, RPC locality, and FQDN fields.
3. Timestamp SMB tree-connect observations from an independently sampled packet-stage delay with microsecond variability. Do not add an integer number of milliseconds to the connection timestamp.
4. Broaden SSH pre-auth timing by authentication mode and server conditions. Include common sub-second or low-single-second accepts, with longer tails reserved for explainable DNS, GSSAPI, MFA, load, or retry behavior.
5. Model Security and Sysmon provider/collector latency independently per host, including occasional overlap, inversion, queueing, and longer-tail delays while preserving causal process identity.
6. Preserve the existing strengths: native field contracts, lifecycle completion, protocol UID/FUID linkage, stateful DHCP, proxy tunnel accounting, and varied baseline behavior.
