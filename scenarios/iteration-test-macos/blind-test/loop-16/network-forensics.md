# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 27

## Executive Summary

The Zeek records show plausible protocol variety and coherent flow-to-protocol pivots across `zeek-core`, `zeek-dmz`, and `zeek-db`. I found no concrete network-layer contradiction or strong distribution artifact that distinguishes synthetic data from a scoped production capture. The roughly six-hour window limits how much behavioral context is visible, but I did not score that alone as evidence of synthetic data.

## Evidence For Synthetic

- No concrete Zeek-visible synthetic indicator met the briefing’s criteria. The bounded capture window and the matching protocol records are not, by themselves, evidence of synthetic generation.

## Evidence For Real

- **Connection-state variety:** `zeek-core/conn.json` has 11,956 flows, including 9,660 `SF`, 1,932 `S0`, and smaller counts of `RSTO`, `RSTR`, `REJ`, `S1`–`S3`, and `OTH`. `zeek-dmz/conn.json` has 8,943 flows, including 6,016 `SF` and 2,687 `S0`. This mix includes completed sessions, unanswered attempts, resets, and refusals.
- **UID and tuple consistency:** Every HTTP and SSL record examined in each sensor group matched a `conn.json` record on UID and flow tuple: 2,059/2,059 HTTP and 306/306 SSL in core; 2,261/2,261 HTTP and 2,520/2,520 SSL in DMZ; and 26/26 HTTP and 14/14 SSL in DB. Protocol-record timestamps fell within the matching connection interval in all checked cases.
- **Client-to-proxy-to-external pivot:** In core, HTTP UID `CF1KgrccdqMukCmuhQk` records a `CONNECT aws.amazon.com:443` from `10.10.1.36:56661` to proxy `10.10.3.20:8080`, status 200. DMZ records the same client tuple, host, and request under its own UID `CFHCb3JwZR0y88PkFEX`. The DMZ SSL record then shows proxy `10.10.3.20` reaching `52.85.84.55:443` with SNI `aws.amazon.com`.
- **DNS-to-TLS pivot:** In DMZ, DNS UID `CX14UvJHrysomOUCS` resolves `aws.amazon.com` to `52.85.84.55` at `1793636307.899568`. About 0.09 seconds later, connection UID `C38Ie870iOFsevi9zn` from the proxy reaches that address on port 443; the SSL record with the same UID reports SNI `aws.amazon.com` and TLS 1.2.
- **Plausible protocol mix:** Core includes DNS, Kerberos, LDAP, SMB, HTTP, TLS, SMTP, DHCP, SSH, and RDP. HTTP includes CONNECT, GET, and POST, with successful responses as well as 403, 407, 5xx, and redirect responses. TLS includes both 1.2 and 1.3, with varied ciphers and server names.
- **Cross-sensor database visibility:** `zeek-db/conn.json` and `zeek-dmz/conn.json` both show the `10.10.3.10:51402` to `10.10.4.10:3306` session as `RSTO`, with matching byte and packet counts and nearly identical timing. This is consistent with two sensors observing the same exchange.

## Detailed Analysis

### Flow states, volume, and timing

The three Zeek connection datasets cover approximately six hours on November 2, 2026 UTC. Core has 11,956 flows, DMZ 8,943, and DB 513. Their different volumes fit their apparent observation scopes; the DB sensor has a substantial concentration of MySQL flows, while core and DMZ include broader traffic.

Completed `SF` sessions dominate core and DB. DMZ has a larger `S0` share, including inbound attempts such as `zeek-dmz/conn.json` UID `CGySGYZWsiAZsCi3DX`: an external source to `10.10.3.10:8080`, one SYN packet, no response, state `S0`. That is plausible perimeter traffic. I also found ordinary examples of refusals and resets, such as core UID `CUSA3FuGoG8Nkj8ra` (`REJ`) and DB UID `Cesg5evaF9ooCQvtdYL` (`RSTO`).

### DNS, HTTP, and TLS pivots

The AWS example shows a coherent proxy path. Core and DMZ HTTP records carry the same client tuple and CONNECT target, while DMZ records the proxy’s external TLS session separately. A later DNS answer in DMZ resolves AWS to an IP used by a subsequent TLS connection, and the SSL record’s SNI agrees with the queried hostname.

Not every connection needs a visible preceding DNS query: caches, preexisting state, and the capture boundary can account for that. I did not find a demonstrated ordering contradiction.

### TLS and certificate fields

TLS records include TLS 1.2 and TLS 1.3, and the TLS 1.2 example includes a cipher and certificate chain references. A corresponding X.509 record for `aws.amazon.com` reports an RSA-2048 certificate with matching SAN entries. Some TLS records lack selected fields such as a cipher or version; without a contradiction in the accompanying flow, those omissions are insufficient to establish a schema defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| None established | Zeek conn, DNS, HTTP, SSL | All three sensor groups | No concrete contradiction or generator-like distribution pattern was established. |

## Realism Score by Category

- **Field format accuracy:** 9 — Zeek-style flow and protocol fields are internally consistent in the examined records.
- **Temporal patterns:** 8 — Protocol records fall within matching connection intervals; DNS-to-flow timing is plausible.
- **Cross-source correlation:** 9 — UID pivots and the proxy, DNS, TLS, certificate, and database examples align.
- **Behavioral realism:** 7 — The protocol and state mix is plausible, though this network-only view does not establish detailed user behavior.
- **Environmental consistency:** 8 — The traffic mix and different sensor volumes fit the apparent core, DMZ, and database scopes.

## Recommendations

No concrete network-layer change is indicated by this evidence. If this were synthetic, preserve the separate client-to-proxy and proxy-to-destination flow legs, along with their DNS, TLS SNI, and certificate relationships.
