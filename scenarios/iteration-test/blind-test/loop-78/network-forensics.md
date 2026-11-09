# Blind Network Forensics Report

## Scope and verdict

- **Scope:** Only `/private/tmp/log-study-loop78/dataset-pine/data`; Zeek `conn`, DNS, HTTP, SSL and SMB records, correlated against the co-located firewall, IDS, proxy and endpoint records. The bounded interval is 2026-11-02 13:00:00–19:00:00 UTC (21,600 seconds). No scenario, ground truth, evaluation, source code or prior reports were consulted.
- **Verdict:** **Inconclusive**, leaning production-like.
- **Verdict confidence:** **78/100** that this is the appropriate conclusion from the bounded evidence.
- **Synthetic confidence:** **22/100** (low; lower means more production-like).

The records show strong, specific tuple, timing and byte-accounting agreement across independent-looking network and endpoint sources. The sharpest volume anomaly is explained by endpoint-observed scan commands. I found no concrete contradiction or unexplained network-shape artifact that would support a Synthetic verdict. Coherent telemetry can also be deliberately generated, however, so this six-hour log slice cannot establish provenance as real production capture.

## Category-tagged findings

### `hard_contradiction`

**None found.** The reviewed DNS, HTTP, SSL and SMB companion records have matching Zeek connection UIDs and matching four-tuples. Firewall, IDS, proxy and endpoint examples agree with the corresponding network observations within plausible source timing differences.

### `contract_gap`

**None found in the reviewed network relationships.** In `zeek-core`, all 3,087 DNS rows, 2,189 HTTP rows, 389 SSL rows, 152 SMB mapping rows and 268 SMB file rows reference a connection with the same UID and exact source/destination IPs and ports. SMB mapping and file records resolve to connections classified as SMB. Repeated UIDs in HTTP and SMB files are compatible with multiple transactions or file actions on one connection; they are not orphan records.

### `distribution_texture`

- `zeek-core` contains 12,386 connections, `zeek-dmz` 9,094, and `zeek-db` 442 in the six-hour interval. Core has 9,935 `SF`, 1,700 `S0`, and 420 `OTH` connections; DMZ has 6,324 `SF`, 2,211 `S0`, and 312 `OTH`. These include both completed sessions and unsuccessful/partial connection attempts.
- Core's ordinary ten-minute volume is mostly 166–479 connections. A single 14:40 UTC bucket contains 1,853 core and 1,747 DMZ rows, initially a notable concentration. In the same minute, the `WEB-EXT-01` endpoint records `/usr/bin/nmap -sn 10.10.2.0/24`, followed by `/usr/bin/nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`, with process create/terminate times spanning the activity. Zeek records the matching host and port sweep: 254 destination addresses in `10.10.2.0/24`, 254 ICMP probes, and nearly complete repetitions of the five listed TCP destination ports. The core count is 1,523 sweep-shaped records (one fewer than a complete 254 × 6 set); the DMZ sensor independently sees the same burst. This is a distinct scan, not a global uniform-rate pattern, and the endpoint evidence accounts for it. The one missing port probe is not a defect by itself.
- Core DNS traffic (3,087 rows), HTTP (2,189), SSL (389), and SMB (467 connections, plus 152 mappings and 268 file events) appears distributed across expected protocol/port families. The DB sensor is narrower and dominated by MySQL: 262 of its 442 connections are classified as MySQL. DMZ carries much more TLS/HTTP activity than core, consistent with its external-facing traffic mix.

### `schema_or_format`

**No material issue found.** Reviewed Zeek records parse as JSON and expose the expected tuple, UID, timestamp, protocol/service and connection-state fields. DNS, HTTP, SSL and SMB records carry the tuple needed for correlation. In particular, the HTTP and SMB repeated-UID cases retain consistent tuples rather than conflicting with their parent connections.

### `environment_or_collection_plausibility`

- **Endpoint ↔ Zeek DNS:** At about 13:00:02 UTC, `10.10.1.31:50389 → 10.10.2.10:53/udp` appears as a `WS-MCHEN-01` outbound endpoint FLOW and a `DC-01` inbound endpoint FLOW. The Zeek core connection starts at 13:00:02.525 and its DNS row shares its UID and tuple. Endpoint FLOW timestamps are 13:00:01.958 and 13:00:02.706. This is a plausible source/receiver/sensor view of one DNS exchange.
- **Proxy ↔ Zeek HTTP and bytes:** At 13:02 UTC, Zeek records `10.10.1.22:48574 → 10.10.3.20:8080/tcp`, an HTTP `CONNECT media.licdn.com:443` with status 200, and an `SF` connection. The proxy access line has the same client, target host and timestamp. Its client byte accounting (`462` control-message bytes + `2,670` tunnel bytes = Zeek's `3,132` origin bytes) and server accounting (`215` wire/control bytes + `35,419` tunnel bytes = Zeek's `35,634` response bytes) reconcile exactly. This is unusually useful, concrete cross-source agreement.
- **IDS ↔ Zeek DNS:** The Snort alert for `10.10.3.20:55801 → 10.10.2.11:53/udp` at 13:00:19.894 flags a `.top` query. Zeek records the same tuple, transaction ID `15563`, query `cdn-check-vrkx2npi.top`, and NXDOMAIN response in both core and DMZ views. The sensor and IDS timestamps differ by fractions of a second, a plausible observation/processing difference.
- **Firewall ↔ Zeek perimeter attempt:** The ASA reports an inbound TCP connection from `185.220.88.13:1830` to the translated DMZ endpoint `10.10.3.10:3389` at 13:00:01 (public-side address shown as `203.14.220.10`). DMZ Zeek has the same source and private destination tuple at 13:00:01.171 with `S0`, one SYN and no response. NAT translation and a failed/unfinished inbound attempt plausibly explain these views.
- **Sensor overlap:** Core and DMZ contain some of the same internal tuples, including the HTTP proxy exchange and scan. Their UIDs differ and their timestamps are slightly offset; the observed packet counts, byte counts and connection duration are often very close. That is compatible with separate taps observing shared traffic and is not by itself evidence of copied records or synthetic construction.

### `weak_signal`

- The successful tuple/UID, DNS companion, proxy byte-accounting, IDS and firewall joins increase confidence that the records form a coherent operational network view. This is positive realism evidence, not proof of real-world provenance; a generator with shared canonical events could produce similar agreement.
- The `.top` DNS alert and inbound RDP attempt are security-relevant observations, but neither alone distinguishes synthetic from real data. The review does not assign intent to either.
- Sensor coverage and event volume vary by zone and protocol. That does not qualify as a defect without a concrete contradiction or a required-companion failure, neither of which was found here.

## Recommendations

1. Keep the scan bucket classified as explained activity in any follow-up: the endpoint process records give a direct command and timing match to the observed network fan-out.
2. For a stronger provenance verdict, compare another independently selected six-hour interval or original packet captures / collector exports. This bounded log view is internally consistent, but consistency alone cannot distinguish carefully generated telemetry from real collection.
3. Preserve the proxy byte arithmetic and the endpoint/Zeek DNS and IDS/Zeek alert joins as specific acceptance checks for cross-source network fidelity.
