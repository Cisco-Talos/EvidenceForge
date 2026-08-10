# Threat Hunter — Blind Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict confidence: 90/100
- Synthetic-confidence score: 88/100

## Executive summary

The dataset has unusually strong field-level fidelity and cross-source correlation, but it contains
a decisive process/network lifecycle contradiction: individual `ssh.exe` processes own many
overlapping, independent SSH transports for hours. Repeated IDS-to-HTTP semantic mismatches and
near-uniform public-client distributions provide additional generator-like evidence.

## Evidence for synthetic

- **Hard contradiction — one OpenSSH client process owns overlapping SSH transports.**
  `WS-NKAPOOR-01.../ecar.json:184` creates PID 7008 at `13:06:41.958Z` with command
  `ssh.exe nina.kapoor@WEB-BO-01...`; it terminates at `17:04:41.515Z` on line 922. That same
  process UUID/PID owns 13 destination-port-22 connections. `ZEEK-BO-CORE/conn.json:1035` records
  `10.44.10.24:55542 -> 10.44.30.10:22` from `13:06:42.579Z` for `1720.901063s`, ending about
  `13:35:23.480Z`. Before it closes, line 1188 starts another successful SSH transport,
  `:62634 -> :22`, at `13:15:06.008Z` for `1471.014592s`. Endpoint FLOW records at lines 186 and
  230 assign both to PID 7008. A normal `ssh.exe user@host` invocation owns one transport;
  OpenSSH multiplexing carries channels over one TCP connection rather than creating multiple
  simultaneous transport tuples under that invocation.
- **Distribution texture — systematic SSH reuse.** The workstation produces 49 successful
  internal SSH connections in six hours, with as many as six concurrent. PID 7008 owns 13, PID
  6968 owns eight, PID 6640 owns five, and PID 8128 owns four. Median duration is approximately 876
  seconds while median gap between openings is approximately 280 seconds. This is not explained by
  brief address-family retries or failed reconnects.
- **Contract gap — IDS descriptions do not match joined HTTP transactions.**
  `IDS-BO-EDGE/snort_alert.log:26` reports `PHP Possible file upload attempt` at
  `14:10:04.706698Z` for `145.78.103.167:62098 -> 10.44.30.10:80`; the exact tuple in
  `ZEEK-BO-CORE/http.json:260` is `GET /dashboard`, `request_body_len:0`, status 200. The mismatch
  repeats at `17:59:27.425918Z`: Snort line 56 reports a PHP upload while Zeek line 662 shows
  `GET /api/v1/status`, zero body, status 200. SQL-injection labels similarly join to bland
  requests: `UNION SELECT` maps to `GET /dashboard`; `SELECT FROM` maps to
  `GET /assets/app.js`. Real IDS false positives occur, but repeated attachment of exploit labels
  to semantically unrelated, zero-body transactions looks independently sampled.
- **Distribution texture — external web clients resemble uniform categorical sampling.** Of 85
  external source IPs reaching the web server, 79 make exactly one request. Those 79 divide almost
  evenly among six fixed Windows user agents: Chrome 119/120/121 occur exactly 14 times each,
  Firefox 121 13 times, Firefox 120 12 times, and Edge 120 10 times. Paths also come from a small
  pool: `/` 23 times, `/index.html` ten, and five paths seven times each. This lacks the skew,
  repeat-client behavior, asset fan-out, version diversity, and session clustering expected from
  public traffic.
- **Environment/collection plausibility — secondary Windows session anomalies.**
  `WS-NKAPOOR-01.../windows_event_security.xml` records Nina Type 2 logons at `17:26:13.026Z` and
  `17:30:30.747Z` with different LogonIDs and no intervening logoff. Multiple Nina-owned
  `explorer.exe` instances are created with SYSTEM `services.exe` as parent, including
  `ecar.json:181` at `13:06:20.100Z`. These are supporting indicators because unusual
  service-token execution can produce comparable records.

## Evidence for real

- Network accounting is exceptionally coherent. `FW-BO-EDGE/cisco_asa.log:18-21` pairs ASA
  build/teardown and NAT records for `10.44.20.30:44577 -> 13.107.246.52:443`; its 1,028 teardown
  bytes equal Zeek's `916 + 112` IP bytes in `conn.json:13`.
- All 2,499 ASA connection IDs have matching build and teardown records; all 707 observed dynamic
  TCP translations are paired.
- Zeek protocol joins are strong: DNS, HTTP, SSL, DHCP, and file records resolve to connection UIDs
  within their connection intervals.
- All 577 certificate references resolve to 577 X.509 records, with coherent SSL-chain
  relationships and SNI/SAN values.
- RDP evidence is coordinated: `10.44.10.24:54160 -> 10.44.20.10:3389` appears as an `SF` Zeek
  interval, a source `mstsc.exe` FLOW, an inbound DC FLOW, and a target Type 10 user session with
  the same tuple.
- Windows Security and Sysmon XML use plausible event-specific schemas, monotonically increasing
  record IDs/timestamps, stable per-image hashes, and generally sound logon/process lifecycle
  correlations.
- Host roles are believable: the DC owns Kerberos/DNS behavior, the file server owns SMB, the proxy
  shows client and origin-side traffic, and the web host receives public HTTP and scanning activity.
- The visible intrusion narrative correlates naturally across IDS, web, Zeek, Linux authentication,
  shell activity, and later internal movement.

## Detailed analysis

The reviewer parsed JSON/XML and joined records using timestamps, five-tuples, Zeek UIDs, process
UUIDs/PIDs, LogonIDs, certificate FUIDs, and ASA connection/NAT identifiers. Filesystem timestamps,
sanitized names, unavailable domains, selected event coverage, and dataset completeness were not
treated as authenticity evidence.

The SSH lifecycle is the highest-weight discriminator. Endpoint telemetry makes PID 7008 a single
process object with one creation and one termination. Zeek independently establishes that its first
and second SSH connections overlap by roughly 20 minutes, while server-side SSH/PAM records
corroborate distinct authenticated tuples. The same ownership error repeats across several PIDs,
making telemetry loss or one bad record implausible.

The IDS problem was evaluated by exact source port, source address, destination, and time. The PHP
upload cases are especially damaging because both joined requests are simple GETs with zero request
bodies. Broader SQLi/CRLF examples could theoretically result from unlogged headers, but their
repetition on the same small benign path pool strengthens the independent-labeling interpretation.

The public HTTP distribution has a measurable categorical signature: three Chrome versions receive
identical counts, adjacent Firefox versions nearly identical counts, and almost every apparent
client disappears after one request. That pattern is consistent with independently sampling an IP,
user-agent, and path pool for each event.

The main counterweight is unusually good mechanical correlation. Network bytes, NAT lifecycles,
RDP tuples, TLS certificates, Windows identifiers, and role behavior agree across sources. This is
a sophisticated synthetic dataset; the verdict rests on semantic lifecycle defects that polished
field rendering does not conceal.

## Synthetic indicator summary

| Category | Source family | Scope | Impact |
| --- | --- | --- | --- |
| hard contradiction | Endpoint + Zeek + Linux SSH | Multiple client PIDs and 49 sessions | Decisive lifecycle impossibility |
| contract gap | Snort + Zeek HTTP + web access | Repeated exploit alerts | Alerts not derived from observable request semantics |
| distribution texture | Zeek HTTP | 79 one-hit external clients | Near-uniform fixed UA/path pools |
| distribution texture | Endpoint + Zeek SSH | Six-hour admin activity | Implausible session volume and reuse |
| environment/collection | Windows Security + eCAR | One workstation | Duplicate console sessions and abnormal shell ancestry |
| weak signal | Bash history + endpoint | Proxy command executions | Consistently delayed endpoint starts; insufficient alone |

## Realism scores

| Category | Score |
| --- | ---: |
| Field-format accuracy | 9/10 |
| Temporal patterns | 6/10 |
| Cross-source correlation | 8/10 |
| Behavioral realism | 4/10 |
| Environmental consistency | 8/10 |

## Reviewer recommendations

- Give every independent SSH transport its own `ssh.exe` process lifecycle. If modeling
  ControlMaster, retain one TCP transport and represent multiplexed channels separately.
- Add an invariant preventing a normal one-shot SSH client process from owning overlapping TCP/22
  transports.
- Derive IDS alerts from actual HTTP method, URI, headers, and body. A file-upload alert should
  have payload characteristics capable of triggering that signature.
- Model public browsing as client sessions with skewed browser prevalence, persistent identities,
  repeat requests, asset fan-out, and realistic longitudinal versions.
- Anchor interactive `explorer.exe` creation to `winlogon.exe`/`userinit.exe` or an existing shell,
  and prevent simultaneous same-user Type 2 console sessions unless explicitly justified.

## Isolation statement

The reviewer received only `/private/tmp/eforge-realism-review/branch-enterprise/data`; scenario,
ground truth, code, prior reports, and other reviewers' conclusions were withheld.
