# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 18

## Executive Summary

This is parser-ready, internally coherent telemetry with source-native Windows, Sysmon, Zeek,
eCAR, RFC 5424 syslog, ASA, proxy, web, and IDS structures. The strongest evidence is not mere
coverage: sampled identifiers, lifecycles, record counters, field values, and observation delays
behave as they would in independent production sensors; only two weak distribution signals keep
the synthetic-confidence score above the indistinguishable floor.

## Evidence For Synthetic

- `[weak_signal]` All 1,768 Zeek SSL records (`zeek-core/ssl.json` and
  `zeek-dmz/ssl.json`) have `established:true`, and every referenced connection is `SF`. The wider
  connection population does contain 1,185 `S0`, 194 `RSTO`, 109 `RSTR`, and other incomplete
  states, so a small population of parsed-but-incomplete TLS handshakes would add texture. This is
  low-weight evidence because Zeek may not classify a flow as SSL until enough handshake material
  is visible.
- `[distribution_texture]` Each of the 2,945 DNS rows has a distinct UID (2,194/2,194 in core and
  751/751 in DMZ). One-query UDP flows are common and fully valid, but zero socket/tuple reuse over
  a mixed Windows/Linux resolver population is slightly smoother than some production captures.

## Evidence For Real

- Windows event envelopes and payloads are source-native. Across 13,589 Security events and 4,063
  Sysmon events, sampled Event IDs have the expected provider, channel, version, task, level,
  keyword, and per-event field sets. Examples include Security 4624 v2, 4688 v2, 5156 v1 and
  Sysmon 1 v5, 5 v3, 8 v2, 10 v3, and 22 v5.
- The DC audit-clear event is especially convincing: Event 1102 at
  `2024-03-18T17:42:15.6063384Z` uses provider `Microsoft-Windows-Eventlog`, carries its subject in
  the proper `UserData/LogFileCleared` namespace, and is followed by a reset from EventRecordID
  28,262,000 to 1, then 2. Other channels remain monotonic with realistic gaps.
- Process correlation survives exact field checks. All 834 Sysmon Event 1 records match a Security
  4688 on the same host by PID, image, and command line; 834/834 command lines agree. Pair deltas
  range from about -21 ms to +139 ms, while eCAR copies generally arrive later, with a broader
  agent-like delay. Five Security 4688 events lack Sysmon companions, so the sources are not
  unrealistically identical.
- Logon lifecycles are coherent. Of 714 Security 4634 records, 705 have an earlier visible 4624
  with the same host, LogonID, user, and type. The nine unmatched logoffs occur after the beginning
  of the six-hour window and are consistent with sessions opened before collection. The 1,059
  successful logons have a plausible mix: 703 type 3, 329 type 5, 12 type 10, eight type 2, and
  seven type 7.
- Zeek fan-out is structurally sound. All 2,945 DNS, 2,097 HTTP, 1,768 SSL, and 66 SMTP rows point
  to an existing conn UID with an identical four-tuple; all 899 files rows reference known
  connections. The 11,385 conn UIDs and 899 file UIDs are unique, durations are nonnegative, byte
  accounting is internally valid, and no `SF` connection has zero response packets.
- Independent network views retain their own semantics. For DMZ flow
  `10.10.3.20:50489 -> 3.235.70.7:443`, Zeek UID `Csurzp80LbO9rIQbx7` begins at
  `2024-03-18T12:01:09.839228Z`, lasts 5.087364 seconds, and totals 26,254 IP bytes. ASA connection
  1218248 records the same tuple at 12:01:09, teardown at 12:01:14, duration five seconds, and
  exactly 26,254 bytes while separately tracking the NAT translation. That is meaningful
  cross-sensor agreement, not just duplicated formatting.
- All 24,370 eCAR JSONL records parse; record IDs are unique valid UUIDs. Of 1,400 process
  terminations, 1,285 reference creates visible earlier in the window and none precede its matched
  create. Of 813 logouts, 794 reference a visible earlier login; the remainder align with the same
  left-window boundary seen in native host logs.

## Detailed Analysis

### Scope and sampling

The bounded review covered representative beginning, middle, and ending windows within
`2024-03-18T12:00Z–18:00Z`. The data represents 18 host eCAR streams, nine Windows Security/Sysmon
host pairs, nine Linux syslog streams, two Zeek sensors, a perimeter ASA, two Snort sensors, an
explicit proxy, and a web server. I parsed complete lightweight indexes for counts and identifier
checks, then inspected representative raw records rather than narrating every activity.

### Windows schema and event semantics

The Windows XML is well formed and uses the Windows Events namespace. Security events contain the
correct localized token forms (`%%14593`, `%%14611`, `%%1833`), hexadecimal IDs, SIDs, and GUID
bracing. Event 4624 v2 consistently contains the modern linked-logon, virtual-account, outbound
identity, and elevated-token fields. Type 3 Kerberos and NTLM records use IPv4-mapped IPv6 source
addresses, while interactive types use `-` where an address is not meaningful. Kerberos events
show AES-256 (`0x12`), AES-128 (`0x11`), and RC4 (`0x17`) rather than one invariant cipher.

The DC has 521 Event 4768 TGT records, 1,157 Event 4769 service-ticket records, two 4771 failures,
and 107 NTLM 4776 validations. Ticket options and encryption types vary. Account-management
records form source-correct shapes: 4720 creates `svc_mhsync`, 4724 resets its password, 4728 adds
it to Domain Admins, 4738 enables it, and 4726 later removes it. Event 4697 uses service-specific
fields rather than a generic process payload.

### Process identity and lifecycle contracts

One concrete triple on `WS-PPATEL-01` is representative. Security 4688 at
`12:07:12.6951051Z` creates PID `0x17e4` (6116),
`C:\Windows\System32\CompatTelRunner.exe`, parent PID `0x13c4`/`svchost.exe`, with command
`CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun`. Sysmon Event 1 at
`12:07:12.7093600Z` preserves PID 6116, parent PID 5060, image, command, SYSTEM identity, LogonID
`0x3e7`, ProcessGuid, and four correctly shaped hashes. eCAR observes the same create at
`12:07:13.828Z`, then terminates the identical eCAR object/PID at `12:11:20.353Z`.

Across all Windows hosts, all 834 Sysmon creates match Security, while Security has five additional
creates. Of 676 Sysmon Event 5 terminations, 591 have their Event 1 visible earlier; unmatched
terminations are expected at the left boundary. All 84 child creates whose parent ProcessGuid is
also visible point backward in time and agree on parent PID and image. No matched termination or
parent relationship runs backward.

### Authentication/session contracts

On `FILE-SRV-01`, Security 4624 at `12:00:51.5059121Z` creates NTLM type-3 LogonID `0xf62c280`
for `lina.nguyen` from `::ffff:10.10.1.21:34709`; 4634 closes the same user, type, and LogonID at
`12:01:10.8918472Z`. This pattern generalizes: 705/714 visible logoffs match an earlier logon.
Service, network, remote-interactive, interactive, and unlock sessions remain distinguishable by
their native fields rather than being collapsed into a generic login shape.

### Zeek and network-facing contracts

The two conn streams contain 11,385 unique UIDs with a mixed state population: 9,794 `SF`, 1,185
`S0`, 194 `RSTO`, 109 `RSTR`, plus `OTH`, `S1`, `S2`, `S3`, and `REJ`. All protocol fan-out UIDs
and tuples checked cleanly. DNS `rtt` never exceeds its conn duration; HTTP supports persistent
connections (2,097 rows over 1,949 UIDs); TLS log timestamps follow connection open; and X.509
fingerprints recur across sessions rather than being regenerated per flow (530 certificate rows,
146 unique fingerprints).

The ASA evidence uses proper build/teardown and dynamic-translation message IDs and maintains
connection/NAT identities across lifecycles. The exact Zeek/ASA example in the evidence section
also demonstrates realistic native timestamp precision: Zeek keeps microseconds, ASA seconds and
rounded duration, while bytes remain reconcilable.

### Other ingestion surfaces

All 4,109 syslog records match RFC 5424 framing with PRI, version, UTC timestamp, hostname,
app-name, procid, and nil structured-data/message-id. Program/facility usage is plausible:
`sshd` and PAM use authpriv priorities, daemon messages use daemon priorities, and kernel UFW
records use kernel facility. Proxy and web records use stable combined/custom access-log layouts;
proxy CONNECT control bytes are distinguished from tunneled client/server bytes, preventing a
detector from double-counting those fields as one byte scope.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `weak_signal` | Zeek SSL | 1,768/1,768 rows established and on `SF` conns | Small increase only; Zeek classification can explain the selection |
| `distribution_texture` | Zeek DNS | 2,945/2,945 rows use distinct UIDs | Small increase; valid per-query sockets, but unusually uniform across mixed clients |

No `hard_contradiction`, `contract_gap`, or `schema_or_format` indicator was found in the bounded
review.

## Realism Score by Category

- **Field format accuracy:** 10 — Sampled Windows, Sysmon, Zeek, eCAR, RFC 5424, ASA, proxy, web,
  and Snort fields are parser-appropriate and source-native.
- **Temporal patterns:** 9 — Causal ordering and native precision are strong; TLS completion-only
  texture is the sole minor reservation.
- **Cross-source correlation:** 10 — PIDs, commands, LogonIDs, UIDs, tuples, NAT identities, bytes,
  and lifecycles reconcile without impossible ordering.
- **Behavioral realism:** 8 — Event-state, logon-type, cipher, DNS-response, and process-lifecycle
  mixtures are convincing, with mild DNS socket-reuse smoothness.
- **Environmental consistency:** 9 — Host roles, collection volumes, source families, and
  source-specific delays remain mutually plausible across the six-hour window.

## Recommendations

- If this were synthetic, add a low-volume set of genuinely parsed but aborted TLS handshakes so
  `ssl.log` includes a few `established:false` rows linked to compatible non-`SF` connection
  lifecycles. Do this only where Zeek would have seen enough handshake bytes to identify TLS.
- If this were synthetic, let a small subset of resolver implementations reuse a UDP socket/source
  tuple for adjacent A/AAAA or companion questions, producing occasional multiple `dns.log`
  transactions on one UID while retaining correct transaction IDs and timing.
