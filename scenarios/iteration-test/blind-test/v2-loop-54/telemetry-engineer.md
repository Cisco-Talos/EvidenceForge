# Telemetry Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 94/100  
**Synthetic-Confidence Score:** 83/100  
**Realism Score:** 72/100 (higher means more production-like)

## Executive Summary

This is high-quality, internally coordinated telemetry, but it contains a decisive endpoint-
provenance leak: 116 destination-host eCAR file records carry the exact process UUID, PID, and
image owned by a different client host. One record on `DC-01`, for example, identifies a Linux
`/usr/bin/smbclient` process that exists only on `WS-LNGUYEN-01`; a native DC-side file sensor
could not produce that process identity, and the record does not label it as cross-host enrichment.

Most lower-level mechanics are convincing. Zeek child records agree with their parent flows,
loss-aware byte accounting closes, Windows/Sysmon/eCAR process ordering is coherent, firewall
build/teardown pairs balance, and independent sensors show plausible timestamp offsets. The hard
cross-host identity contradiction, reinforced by mixed generator-like file identifier morphology,
is nevertheless enough to classify the dataset as synthetic with high confidence.

## Scope and Method

I examined only files beneath `scenarios/iteration-test/data`. I did not inspect scenario inputs,
manifests, ground truth, source code, repository history, assessment artifacts, or external probes.
The visible period is approximately 2024-03-18 12:00–18:00 UTC. I treated pre-window state,
post-window continuation, deliberately selected source coverage, and complete cross-source
matching as neutral unless a visible contradiction was present.

The audit covered:

- 19,217 Zeek connection records across `zeek-core`, `zeek-dmz`, and `zeek-db`, plus DNS, HTTP,
  TLS, X.509, OCSP, SMTP, DHCP, SMB, file, and PE projections.
- 21 host eCAR streams, 10 Windows Security/Sysmon pairs, 11 Linux syslog streams, and 20 bash
  history files.
- Cisco ASA, two Snort sensors, proxy access, and web access telemetry.
- Schema shape, parseability, identifier morphology, timestamp ordering, lifecycle balance,
  byte/packet accounting, multisensor agreement, and cross-source identity provenance.

## Ranked Findings

### P0 — Destination eCAR file events leak exact process identity from another host

**Category:** `hard_contradiction` / `contract_gap`  
**Scope:** Repeated; 116 eCAR `FILE` records on `DC-01`, `DC-02`, and `FILE-SRV-01`  
**Score leverage:** High

The clearest example is
`DC-01.meridianhcs.local/ecar.json:44`, event
`214bbd67-1c47-4da1-a6f2-3c38e33e4c3a`. It is a `FILE/READ` record whose host is `DC-01`, but
its properties claim:

- `source_process_uuid=5ecac865-7a35-4668-b0a1-a3f4b53fd36f`
- `source_pid=1465012`
- `source_image_path=/usr/bin/smbclient`
- `source_principal=lina.nguyen`

That UUID is the `PROCESS/CREATE` object on a different endpoint,
`WS-LNGUYEN-01.meridianhcs.local/ecar.json:7`, event
`9c2d9192-3dcb-4a4f-a3bc-1d471d71bae0`. The matching client-side flow is at line 10 of that file.
The DC record therefore combines the DC's server-side file path and network-logon context with
the remote Linux client's private EDR process UUID/PID/image. It neither identifies a source host
nor marks these fields as correlation enrichment.

This is not merely unusually complete correlation. A DC-local file event cannot natively observe
the remote endpoint's EDR process UUID, and `/usr/bin/smbclient` cannot be a DC-local Windows
process path. The same pattern occurs 116 times: 106 records project remote `explorer.exe`
identity and 10 project remote `/usr/bin/smbclient` identity. Another concrete instance is
`DC-02.meridianhcs.local/ecar.json:234`, event
`33b72ab9-1c0a-4de2-8198-c1b09ef1e702`, whose `source_process_uuid` is owned only by
`WS-SMARTINEZ-01`.

**Why it matters:** This is a generator-level omniscience leak and an immediate authenticity
failure for anyone validating endpoint provenance.

**Recommended correction:** Keep client process identity only in the client-host event. On the
server, represent the locally observable server process (`System`/SMB server worker), authenticated
session, client address, share, and file operation. If a later analytics layer joins client and
server evidence, emit explicit fields such as `remote_host`, `remote_process_ref`, and
`enrichment_source`, and do not present the joined identity as source-native host telemetry.

### P1 — eCAR file object IDs expose a mixed synthetic identity scheme

**Category:** `distribution_texture` / `schema_or_format`  
**Scope:** Repeated across multiple host streams; 188 of 391 eCAR `FILE` records  
**Score leverage:** Medium-high

The eCAR corpus uses three visibly different file-object namespaces: 198 bare UUIDv4 values, five
`file-<uuid>` values, and 188 values matching `file-00000000xxxxxxxx`. The fixed eight-zero high
half is conspicuous and repeated. Examples include:

- `FILE-LNX-01.meridianhcs.local/ecar.json:21` — `file-0000000012a2dbc1`
- `FILE-LNX-01.meridianhcs.local/ecar.json:128` — `file-0000000066748c01`
- `DC-02.meridianhcs.local/ecar.json:234` — `file-000000004f540ddc`

Stable identity reuse for repeat access is good, but the abrupt coexistence of UUIDv4, prefixed
UUID, and zero-padded 64-bit-looking identifiers has no source-visible discriminator explaining
different ID authorities. It reads like multiple generation paths leaking their internal key
formats.

**Recommended correction:** Use one documented object-ID namespace per eCAR producer, or carry an
explicit `id_type`/`id_authority`. Avoid fixed high-order zero padding unless it is genuinely native
to the source product.

### P2 — Proxy CONNECT byte semantics conflict with combined-log conventions

**Category:** `schema_or_format`  
**Scope:** Dataset-wide for proxy CONNECT records; 1,438 of 1,438 CONNECT lines  
**Score leverage:** Medium

Every CONNECT record in `PROXY-01.meridianhcs.local/proxy_access.log` places a nonzero value in the
combined-log response-size column even though a successful CONNECT response has no HTTP entity
body. Line 1, for example, records status 200 and size `102`, then explains in a custom trailing
field that this is `byte_scope=connect-control-message`, while separately giving
`tunnel_cs_bytes=5618` and `tunnel_sc_bytes=19314`.

The accounting is transparent, but it repurposes the familiar combined-log byte column from body
bytes to control-message bytes. Generic Apache/Nginx combined-log parsers will ingest the line but
assign the wrong semantic meaning to that value. The final quoted key/value bundle is also a
custom extension rather than a standard combined-log field set.

**Recommended correction:** Keep the standard body-byte field as `0` or `-` for CONNECT and expose
control, client-to-server tunnel, server-to-client tunnel, and tunnel-duration metrics in named
fields under a clearly documented source-specific format.

### P3 — Windows EventRecordID gaps have a bounded, generator-like texture

**Category:** `distribution_texture`  
**Scope:** Dataset-wide weak signal; all 20 Security/Sysmon channel segments inspected  
**Score leverage:** Low

Record IDs are unique and monotonic within each channel segment, and the `DC-01` Security reset at
Event 1102 is internally coherent. The gap texture is nevertheless unusually compressed across
every host. Examples:

- `WS-MCHEN-01` Sysmon: 466 visible records occupy 511 record IDs (91.2%), maximum gap 3.
- `DC-01` Sysmon: 795 records occupy 1,407 IDs (56.5%), maximum gap 12.
- `DC-02` Security: 5,675 records occupy 9,790 IDs (58.0%), maximum gap 17.
- `MAIL-FIN-01` Security: 947 records occupy 4,436 IDs (21.3%), maximum gap 48.

Across sources with very different roles and volumes, hidden-event gaps stay small and sharply
bounded. This resembles a visible counter with randomized small skips more than counters sampled
from independently noisy native channels. Because audit policy and collection filters can produce
high occupancy, this is a weak signal rather than a contradiction.

**Recommended correction:** Model record counters from a host- and channel-specific hidden event
rate with bursty long tails, while retaining tight adjacency for genuinely coupled event pairs.

## Evidence For Synthetic

- `[hard_contradiction]` The 116 cross-host eCAR file-process projections expose remote private
  process identity as if it were local source-native telemetry. The DC/Linux example at
  `DC-01.../ecar.json:44` and `WS-LNGUYEN-01.../ecar.json:7` is decisive.
- `[distribution_texture]` 188 file object IDs share the unmistakable
  `file-00000000xxxxxxxx` morphology while sibling file events use two UUID formats.
- `[schema_or_format]` All 1,438 proxy CONNECT lines place control-message bytes in the conventional
  response-size position.
- `[distribution_texture]` Native Windows record-counter gaps remain narrowly bounded across all
  inspected host/channel segments.

## Evidence For Real

- All JSON-lines inputs parsed without error, all Windows XML files parsed, and all Linux syslog
  lines matched their RFC 5424 envelope.
- All Zeek DNS, HTTP, and TLS rows had a same-sensor parent `conn` row with an identical five-tuple;
  there were zero tuple mismatches and no child timestamps outside the parent interval plus a
  one-second allowance.
- Zeek packet and byte accounting was coherent: no `ip_bytes < payload_bytes`, no payload with zero
  packets, no `SF` flow with an empty side, and file loss was represented explicitly. For UID
  `CSBMReILR36ahgb6Kg`, for example, three HTTP bodies total 526,578 bytes while `conn.json:3741`
  records 521,723 responder bytes and 5,476 missed bytes; `files.json:437-439` accounts for the
  exact per-object loss rather than silently contradicting the access log.
- Cross-sensor behavior was plausible. There were 4,071 matching core/DMZ five-tuples within two
  seconds; connection state always agreed, sensor timestamps differed by a median 114 ms, and
  packet/history differences appeared only on a minority of paths, as expected from separate
  vantage points.
- Windows process correlation was strong without impossible visible ordering. Across the Windows
  hosts, 947 Sysmon Event 1 records aligned with Security 4688 by PID/image and expected subsecond
  offsets. No Sysmon Event 5 for a known ProcessGuid preceded its visible Event 1.
- eCAR streams contained no duplicate event IDs or timestamp reversals. For locally owned process
  identities, dependent records did not precede creation or follow visible termination.
- The ASA stream contained 7,008 build records and exactly 7,008 matching teardown records, with no
  missing or duplicate connection IDs.
- All 147 port-bearing Snort alerts matched a corresponding Zeek tuple within five seconds. The
  remaining 17 alerts were portless ICMP records, valid for the classic fast-alert format.
- TLS chains referenced existing X.509 FUIDs, all inspected certificates were valid at use time,
  and repeated server names generally retained stable leaf fingerprints.
- The `DC-01` Security-log clear is source-native: Event 1102, record ID 1, includes the expected
  `LogFileCleared` UserData with SYSTEM SID/name/domain/logon ID before subsequent records resume.

## Detailed Analysis

### Source-native schemas

The Windows System metadata was largely correct for the represented providers and event IDs.
Security 4624 and 4688 used versions 2; 5156 used version 1; Sysmon Event 1/3/22 used version 5;
and field sets were stable per event type. SIDs, hexadecimal logon IDs, GUID braces, IPv4-mapped
addresses, protocol numbers, and audit keyword values were syntactically consistent. The 1102
event correctly uses `UserData/LogFileCleared`, not `EventData`.

Zeek JSON used plausible optional-field omission rather than null-filling and preserved native UID,
FUID, tuple, service, state, history, packet, and file-analysis relationships. HTTP transaction
depths were contiguous per UID. SMTP STARTTLS rows correctly retained `service=smtp` on the parent
connection even when an SSL child record existed.

The primary schema concern is eCAR provenance, not JSON shape. A normalized schema may support
enrichment, but these per-host records do not distinguish local observation from cross-host joins.
That makes `source_process_uuid` semantically unsafe for analysts and rules.

### Field distributions

Connection-state distributions were varied rather than uniform. Core had 8,639 `SF`, 1,952 `S0`,
118 `RSTO`, 86 `RSTR`, and smaller `REJ`, `S1`, `S2`, `S3`, and `OTH` populations. DMZ similarly
mixed successful service traffic with incomplete scanner traffic. Durations ranged from
millisecond exchanges to multi-hour sessions, and history strings varied with packet behavior.

DNS included A, AAAA, PTR, SRV, TXT, MX, SOA, and NS queries and mixed NOERROR, NXDOMAIN, SERVFAIL,
and REFUSED outcomes. Some very-low-TTL, high-entropy names are conspicuous, but they form coherent
traffic and detection clusters; suspicious traffic is not itself an authenticity defect, so it
did not affect the score.

The eCAR file-ID namespace and Windows counter-gap texture were the only broad distribution
patterns I scored negatively.

### Timestamp and lifecycle accounting

Files were chronologically ordered. Logon/logoff and process create/terminate imbalance was
consistent with a bounded collection window: no matching visible initiator appeared after its
dependent termination. On Windows, Sysmon process creation usually preceded Security 4688 by
roughly 35–648 ms, and eCAR creation followed Sysmon by roughly 2–887 ms. The direction and scale
of these offsets were consistent per source family.

Endpoint FLOW-to-Zeek offsets were host-specific rather than globally identical. Some Linux hosts
showed approximately one-to-two-second positive offsets while several Windows hosts were slightly
negative, consistent with separate host clocks or source latency. I found no basis to score those
offsets as impossible.

### Multisensor and cross-source behavior

Separate Zeek sensors assigned independent UIDs to the same observed five-tuples, which is correct
for independent sensor instances. Shared connection state agreed while timestamps and some packet
histories differed modestly. Snort offsets against the corresponding Zeek flow were stable but not
bit-identical. Firewall lifecycle pairs were complete and internally balanced.

SMB correlation was detailed: mappings, operations, FUIDs, endpoint file records, and Samba audit
lines generally aligned. `FILE-LNX-01` reports the `Shared` share as NTFS in some Zeek mappings and
`ClinicalResearch` as XFS, despite both appearing under `/srv/samba`; a mounted NTFS volume is
possible, so I treated this as inconclusive rather than a scored finding.

The sole hard multisource failure is the endpoint identity leak described in P0. It crosses the
line from correlation into impossible source-native observation.

## Synthetic Indicator Summary

| Severity | Category | Affected source | Scope | Impact |
|---|---|---|---|---|
| P0 | hard contradiction / contract gap | eCAR file telemetry | 116 records on three Windows servers | Remote endpoint process UUID/PID/image is emitted as destination-host file-event provenance. |
| P1 | distribution texture / schema | eCAR file IDs | 188 of 391 FILE records | Mixed ID authorities and fixed zero prefixes expose internal generation paths. |
| P2 | schema or format | proxy access | All 1,438 CONNECT rows | Combined byte column is repurposed for CONNECT control bytes. |
| P3 | distribution texture | Windows Security/Sysmon | All inspected channel segments | Record-counter gaps are unusually small and bounded; weak signal only. |

## Realism Score by Category

- **Field format accuracy: 7/10** — Windows and Zeek shapes are strong; eCAR provenance semantics
  and proxy byte-column meaning reduce the score.
- **Temporal patterns: 9/10** — Source-specific offsets, ordering, durations, and bounded-window
  lifecycle behavior are convincing.
- **Cross-source correlation: 6/10** — Most joins are excellent, but the eCAR file join exposes
  knowledge that the destination source cannot natively possess.
- **Behavioral realism: 8/10** — Protocol, process, authentication, file, mail, and service activity
  show useful variety without obvious fixed-loop behavior.
- **Environmental consistency: 8/10** — Host roles and source volumes are broadly plausible; the
  Linux-share filesystem label remains possible but unproven.

## Recommendations

1. Separate source-native facts from correlation enrichment in eCAR. Never place a remote
   endpoint's process UUID/path/PID into a destination-host record without explicit remote-host and
   enrichment provenance.
2. Normalize eCAR object-ID authority and morphology, or declare the ID type in each record.
3. Restore conventional response-body semantics in the proxy combined-log byte column and keep
   tunnel/control metrics in named extension fields.
4. Add host- and channel-specific long-tail modeling to Windows EventRecordID gaps while preserving
   adjacency for genuinely coupled events.
5. Retain the current Zeek loss accounting, independent-sensor timestamp variation, Windows
   process timing, firewall lifecycle balance, and explicit bounded-window handling; these were the
   dataset's strongest realism features.
