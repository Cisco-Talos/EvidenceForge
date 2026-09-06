# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 61  
**Synthetic-Confidence Score:** 54

## Executive Summary

The dataset is unusually strong: schemas, field values, process lifecycles, network tuples, and cross-source identities are largely source-native and internally coherent. I nevertheless lean synthetic because Kerberos authentication timing shows a repeated generator-like texture—apparent companion ticket events frequently occur after the corresponding network logon—and one correlated remote authentication lacks the client address that the KDC should normally record.

## Evidence For Synthetic

- `[distribution_texture]` Across both domain controllers, 215 of 223 Kerberos Type 3 logons had a same-account, same-source-IP TGS event within five seconds. In 145 of those 215 cases, the TGS event occurred after the successful 4624 logon. Examples include `FILE-SRV-01$` on DC-01: 4624 at `2024-03-18T16:05:25.2876185Z`, followed by 4768 at `.6968904Z` and 4769 at `.8937647Z`. Cached tickets prevent any individual example from being conclusive, but the dataset-wide post-logon majority is an artificial-looking timing distribution.
- `[contract_gap]` Six tightly clustered Kerberos sequences place a 4769 TGS event before a 4768 TGT event for the same account, source address, and KDC source port. Examples:
  - DC-02, `FILE-SRV-01$`, `10.10.2.20:56639`: TGS at `12:12:06.5666034Z`, TGT at `12:12:06.5930629Z`.
  - DC-01, `WS-MCHEN-01$`, `10.10.1.31:51973`: TGS at `17:46:49.2190805Z`, TGT at `17:46:49.2484558Z`.
  Cached or renewed tickets make this possible, so I do not classify it as a hard contradiction; repeated sub-30 ms inversions nevertheless resemble independently jittered companion events.
- `[contract_gap]` DC-01 Event 4771 at `2024-03-18T14:58:41.7257606Z` records `aisha.johnson`, status `0x18`, but has `IpAddress=-` and `IpPort=-`. Within 154 ms, Event 4776 identifies workstation `LT-MRIVERA-02`, while that host’s syslog records the same user’s local authentication failure at `14:58:41.847073Z`. A network-delivered Kerberos request should ordinarily give the KDC a client address.
- `[distribution_texture]` Linux `debian-sa1 1 1` executions use an exceptionally stable 30-minute grid across the fleet, with host-specific offsets and only subsecond launch variation. APP-INT-01, for example, runs near `:00:01` and `:30:01` throughout the window; FILE-LNX-01 runs near `:01:02` and `:31:02`. This is explainable as centrally managed scheduling, but the fleet-wide offset ladder is generator-like.
- `[weak_signal]` Kerberos, Security, Sysmon, and eCAR observation delays are consistently clean and bounded across hosts. This is not synthetic evidence by itself, but in combination with the repeated authentication-order texture it suggests modeled timing rather than organically variable collection latency.

## Evidence For Real

- Windows event schemas are highly accurate. Event 4624 uses Version 2, Task 12544, correct success keywords, and the expected 27 fields; Event 4688 uses Version 2, Task 13312, and correct hexadecimal PID, elevation, parent, target, and integrity fields.
- Event 1102 on DC-01 at `17:42:10.9908924Z` correctly uses the `Microsoft-Windows-Eventlog` provider, Task 104, `UserData/LogFileCleared`, and resets `EventRecordID` to 1. Subsequent records continue from the reset rather than duplicating the old sequence.
- All 947 visible Sysmon Event 1 process creations match Security 4688 records by host, decimal/hexadecimal PID, image, and time. Security follows Sysmon by approximately 35–645 ms, a plausible source-processing relationship. Four additional 4688 records lack Sysmon counterparts, which is realistic collection imperfection.
- Sysmon lifecycle checks found no dependent Event 3, 7, 8, 10, 11, 13, or 22 before its visible process creation or after its visible Event 5 termination. Visible parent GUID/PID/image relationships also remained consistent.
- SID and GUID syntax is correct across the sampled Windows corpus. Logon IDs, PIDs, access masks, integrity SIDs, process GUIDs, and hashes use source-appropriate representations.
- The PsExec sequence on DC-01 is convincing: Type 3 logon for `aisha.johnson` at `15:59:48.2866279Z`, service installation Event 4697 at `15:59:50.5286979Z`, `PSEXESVC.exe` Event 4688 at `.7581382Z`, child `cmd.exe` at `15:59:56.0351350Z`, and corresponding process exits.
- Account-management records are structurally coherent: Event 4720 for `svc_dirsync` at `16:14:51.9267502Z`, 4724 at `.8805856Z`, 4738 at `16:14:54.0762873Z`, and Domain Admins membership Event 4728 at `16:14:58.0614372Z`.
- All 19,215 Zeek connection UIDs are unique within their sensors. Every checked DNS, HTTP, SSL, SMB, and SMTP UID resolves to a connection with the same four-tuple; no protocol event fell before its connection or materially beyond its connection interval.
- Zeek packet accounting is credible. UDP DNS examples correctly satisfy payload-plus-IP-header relationships, while S0, REJ, and successful UDP states have compatible packet counts, byte counts, histories, and responder behavior.
- TLS certificate reuse is realistic: repeated observations of the same internal or public certificate retain the same fingerprint, issuer, validity interval, and key properties rather than inventing a new certificate per connection.
- All 164 Snort alerts match a Zeek connection on protocol, source, destination, ports, and time. All DNS-oriented alerts additionally have matching Zeek DNS records.
- The ASA data contains 6,051 built and 6,051 teardown records with complete connection-ID pairing. Tuple semantics remain stable and displayed durations differ from timestamp subtraction by only zero or one second, as expected from second-resolution rendering.
- Linux RFC 5424 syslog uses plausible PRI values, program names, PIDs, PAM semantics, and process ordering. Bash history uses normal epoch-marker and command pairs and contains host- and role-specific command diversity.

## Detailed Analysis

Windows Security XML was parsed across ten hosts, covering 18,044 events and 27 Event IDs. Representative validation included 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156. Versions, tasks, levels, opcodes, keywords, field names, and common value encodings were appropriate.

Logon correlation is generally sound. No visible 4634 precedes a visible 4624 for the same LogonID. Type 3 sessions usually last seconds to tens of seconds, while interactive and remote-interactive sessions persist much longer. Closures without visible initiators were limited and consistent with the stated slice-of-time boundary.

The main concern is Kerberos timing. DC-01 contains 117 and DC-02 contains 106 Kerberos Type 3 logons. Nearly every one clusters with a same-principal, same-client-address 4769, but approximately two-thirds of the nearest TGS records occur after the 4624. Because the service and KDC connections use different client ports and the logon GUID is frequently zero, these cannot all be proven to be the exact ticket consumed by the logon. The recurrence and narrow timing still look like companion events that received independent timestamp jitter.

Sysmon comprises 4,979 records: 947 Event 1, 899 Event 3, 828 Event 5, 144 Event 7, 10 Event 8, 784 Event 10, 26 Event 11, 135 Event 13, and 1,206 Event 22. Event schemas and value formats are accurate. For example, DC-01 Event 1 at `12:04:11.381651Z` describes `WmiPrvSE.exe` PID 3648 with a valid process GUID, parent GUID, command line, four standard hashes, SYSTEM integrity, and parent `svchost.exe`. Its Security 4688 counterpart follows at `12:04:11.483545Z`.

ProcessAccess records use plausible access masks and contract-specific call traces rather than one universal template. DC-01 Event 10 at `12:09:36.175366Z`, for example, records Defender opening `svchost.exe` with `GrantedAccess=0x1410`; all visible process GUID, PID, and image references remain consistent.

Zeek schemas were valid across conn, DNS, HTTP, SSL, X.509, files, SMB, SMTP, DHCP, OCSP, and PE records. The opening DNS record at `1710763211.05108` shares UID `CsVG5T6KlU0VHmsVhP` and tuple `10.10.2.26:49264 → 10.10.2.11:53/udp` with its conn record, occurs approximately 2 ms after connection observation, and has internally consistent RTT, answer, TTL, and flag fields.

Protocol semantics are similarly credible. The HTTP CONNECT records point to the explicit proxy on port 8080, while inbound HTTPS web requests appear in web access logs without incorrectly exposing decrypted HTTP at the external Zeek sensor. TLS 1.3 records often lack certificate extraction, while TLS 1.2 records carry certificate-chain FUIDs that resolve to matching X.509 entries.

The Cisco ASA records use severity-appropriate PRI values, correct message IDs for TCP/UDP builds and teardowns, and coherent NAT/interface notation. Snort timestamps retain microsecond precision and map to corresponding network flows without impossible pre-connection alerts.

Behavioral texture is diverse overall. Windows hosts show vendor-specific updaters, monitoring agents, Exchange processes, user sessions, service activity, WMI, scheduled tasks, and process access. Linux hosts show sysstat, SSH, PAM, package maintenance, mail, database, SMB, monitoring, and varied interactive commands. The recurring 30-minute sysstat pattern is the clearest distributional regularity but remains operationally plausible.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | Windows Security/Kerberos | 145 of 215 tightly clustered logon–TGS associations | Repeated post-logon ticket timing creates the strongest generator-like pattern, although cached tickets prevent a hard contradiction. |
| `contract_gap` | Windows Security/Kerberos | Six same-account/IP/KDC-port micro-inversions | Apparent TGS-before-TGT ordering suggests independently jittered companion evidence. |
| `contract_gap` | Windows Security, Linux syslog, eCAR | One correlated authentication attempt | DC-01 Event 4771 omits the client address even though adjacent evidence identifies remote workstation LT-MRIVERA-02. |
| `distribution_texture` | Linux eCAR/syslog | Fleet-wide recurring activity | Thirty-minute sysstat runs use exceptionally stable, host-phased scheduling with minimal timing drift. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, ASA, Snort, syslog, and eCAR records use highly credible schemas and source-native value formats.
- **Temporal patterns:** 6 — Process and network lifecycles are excellent, but repeated Kerberos ordering texture materially reduces realism.
- **Cross-source correlation:** 9 — PID, GUID, LogonID, UID, tuple, connection-ID, certificate, and alert relationships are consistently usable.
- **Behavioral realism:** 8 — Host activity is diverse and role-sensitive, with only limited repeated scheduling texture.
- **Environmental consistency:** 8 — Host roles, services, network placement, source volumes, and collection behavior are broadly plausible.

## Recommendations

If this were synthetic, the following would improve it:

- Preserve causal ordering within an authentication transaction: issue the TGT, then TGS, then service transport/authentication and 4624. Apply observation delay coherently to the transaction rather than jittering each record independently.
- Where a TGS is intentionally based on a cached TGT, avoid placing an unrelated 4768 on the same client tuple within a few milliseconds; wider separation would make the independent lifecycle visible.
- Populate Event 4771 `IpAddress` and `IpPort` from the actual KDC request when endpoint evidence shows a domain-backed remote authentication. For the `LT-MRIVERA-02` attempt, the KDC record should normally expose that host’s address.
- Model fleet timer behavior from explicit cron or systemd semantics. If hosts use randomized timers, vary each activation according to that timer’s behavior rather than assigning every host a stable minute offset with only subsecond jitter.
- Add a validation check that groups Kerberos events by account, client address, KDC port, service, and short time window, then flags likely TGS-before-TGT or ticket-after-logon inversions before rendering.
