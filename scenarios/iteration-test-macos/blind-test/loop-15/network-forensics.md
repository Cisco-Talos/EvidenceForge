# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 65  
**Synthetic-Confidence Score:** 30

## Executive Summary

The Zeek records show plausible connection states, protocol mix, and DNS-to-proxy-to-TLS pivots across the core, DMZ, and database sensors. I found no demonstrated Zeek UID, tuple, timestamp, or lifecycle contradiction. The observed traffic could be real or synthetic; the repeated traffic patterns are a weak signal, but are not enough to establish synthetic origin.

## Evidence For Synthetic

- [weak_signal] HTTP traffic repeatedly uses a small set of user agents across sensors. For example, `Wget/1.21.3` appears 128 times in `zeek-core/http.json` and 169 times in `zeek-dmz/http.json`; common browser strings also recur. This could reflect a small modeled fleet or shared traffic seen at different points, so it is not strong evidence by itself.
- [weak_signal] The core sensor is highly concentrated on DNS and Kerberos to the two domain controllers: destination port 53 has 3,044 connections and port 88 has 2,576 in `zeek-core/conn.json`. That concentration is compatible with directory infrastructure, but without more network context it cannot distinguish modeled traffic from a real environment.

## Evidence For Real

- Cross-sensor records support a coherent proxy and egress pivot. At `2026-11-02 13:01:30 UTC`, `zeek-core/http.json` records a `CONNECT` from `10.10.1.42:62846` to proxy `10.10.3.20:8080` for `20-205-195-86.microsoft.com`, with status `200`. `zeek-dmz/dns.json` records the proxy querying that name and receiving `23.72.51.162`; shortly after, `zeek-dmz/ssl.json` records `10.10.3.20` connecting to `23.72.51.162:443` with the same SNI. The DNS, proxy, and TLS timestamps and fields line up.
- Zeek UID references are intact in the inspected protocol logs: every DNS, HTTP, and SSL row in each sensor’s available files has a matching `conn.json` UID. Their endpoint tuples also match the corresponding connection records. Protocol records occur within the parent connection’s observed duration.
- Connection states and traffic types vary plausibly by sensor. In `zeek-dmz/conn.json`, successful connections (`SF`) coexist with failed or incomplete attempts (`S0`, `REJ`, resets); many `S0` records are inbound attempts to services such as ports 445 and 3389. `zeek-db/conn.json` is dominated by MySQL traffic to port 3306, consistent with a database-facing vantage.
- DNS responses include a mix of `NOERROR`, `NXDOMAIN`, and `SERVFAIL`, and queries include A, AAAA, PTR, SRV, and TXT types. TLS records show both TLS 1.2 and TLS 1.3, with multiple cipher suites. These are plausible variations rather than a single uniform protocol pattern.

## Detailed Analysis

### Scope and time window

The three Zeek sensors cover approximately six hours on 2026-11-02:

- `zeek-core/conn.json`: 12,956? **11,956** connections, from 13:00:31 to 18:59:58 UTC.
- `zeek-dmz/conn.json`: 8,943 connections, from 13:00:06 to 18:59:25 UTC.
- `zeek-db/conn.json`: 513 connections, from 13:00:32 to 18:59:22 UTC.

The core and DMZ sensors each show activity throughout the window, with hourly counts that vary rather than repeating at a constant rate. Core counts range from 1,485 to 3,095 per UTC hour; DMZ counts range from 1,127 to 2,547. Database traffic is more narrowly focused, with 80–90 connections per hour.

### Connection states and protocol behavior

`zeek-core/conn.json` contains 9,660 `SF` rows and 1,932 `S0` rows, with smaller numbers of reset, rejected, and partial states. `zeek-dmz/conn.json` contains 6,016 `SF` and 2,687 `S0` rows, plus resets and rejections. The elevated `S0` share at the DMZ sensor is accompanied by single SYN histories and zero response packets in sampled records, a plausible pattern for unanswered connection attempts.

The dominant core services are DNS, Kerberos, HTTP to port 8080, LDAP, and SMB. The DMZ view contains TLS, HTTP, DNS, and MySQL, alongside inbound connection attempts. The database sensor is predominantly MySQL: 320 of 513 connections target port 3306, mostly with service identified as `mysql`.

### DNS and application pivots

The proxy example above shows a DNS response preceding an outbound TLS session. Another example in `zeek-db/dns.json` records `10.10.4.10` querying `LOG-MON-01.meridianhcs.local` at `2026-11-02 13:11:28 UTC`, answered with `10.10.2.40`. The database sensor’s HTTP records also show proxy `CONNECT` requests from `10.10.4.10` to `10.10.3.20:8080`, including a request for `api.snapcraft.io` at `13:11:04 UTC`. These records are internally consistent, though the specific DNS query is not by itself proof that it preceded that particular HTTP transaction.

Across sensors, DNS UID references match connection tuples and times. The observed DNS response-code and query-type mixes include ordinary successful lookups as well as failures; I found no impossible answer/rcode combination in the reviewed examples.

### TLS and record integrity

TLS records in `zeek-dmz/ssl.json` include both `TLSv12` and `TLSv13`, with common AEAD suites such as `TLS_AES_128_GCM_SHA256` and ECDHE-RSA AES-GCM. The core sensor also records both versions. The available SSL records all map to matching connections; the TLS timestamps fall within the parent connection duration.

Across the inspected sensors, DNS and SSL records have unique UIDs. HTTP has repeated UIDs because a connection can carry multiple transactions; every HTTP UID still resolves to a connection, and the HTTP endpoint tuple matches it. This is consistent with Zeek’s per-connection UID model and per-transaction HTTP logging.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `weak_signal` | HTTP user agents | Core and DMZ sensors | Repeated user-agent strings occur frequently. Sensor overlap and a limited client population could explain this, so the signal only modestly raises the score. |
| `weak_signal` | DNS/Kerberos connections | Core sensor | Traffic concentrates on two apparent domain controllers. The distribution is plausible for directory infrastructure and does not establish a generator pattern. |

No `hard_contradiction`, `contract_gap`, or `schema_or_format` issue was demonstrated in the reviewed Zeek records.

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek connection and protocol fields use plausible types and values; checked UIDs and tuples resolve consistently.
- **Temporal patterns:** 8 — Traffic spans the six-hour window with variable hourly counts; sampled DNS, HTTP, and TLS timing is coherent.
- **Cross-source correlation:** 9 — DNS, HTTP proxy, TLS, and connection records support practical pivots with intact UID and tuple relationships.
- **Behavioral realism:** 7 — Protocols and failed connection attempts vary plausibly; repeated user agents are a weak concern.
- **Environmental consistency:** 7 — Core, DMZ, and database traffic differ in ways consistent with their apparent vantage points, though host-role context is limited in network records alone.

## Recommendations

No concrete network-visible defect requires remediation. If this were synthetic, retain the observed sensor-specific service mix and UID/tuple integrity, and ensure repeated user-agent patterns remain tied to plausible client populations and observation points.
