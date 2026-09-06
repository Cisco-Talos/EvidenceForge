# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 77  
**Synthetic-Confidence Score:** 63

## Executive Summary

This is a highly realistic corpus whose strongest qualities are temporal ordering, process and
session continuity, and agreement among endpoint, authentication, network, proxy, firewall, IDS,
and application telemetry. The observed intrusion can be reconstructed through native hunting
pivots without relying on a single source: an external web request leads to a web-server child
process and outbound callback; internal SSH sessions retain their transport tuples and principals;
database staging and SCP activity appear on both endpoints and network sensors; and Windows remote
administration, account creation, persistence, and audit clearing have coherent process and event
chains. Background traffic is substantial and varied enough that the suspicious activity does not
exist in an empty environment.

I nevertheless assess the corpus as **Synthetic**. The decisive evidence is not the completeness or
clarity of the attack story. It is a pair of implementation-shaped artifacts. First, a successful
44 MB proxy upload becomes only an 18.8 MB proxy-to-origin stream despite zero missed bytes, with
the same disparity independently reflected by the firewall. Second, identifiers in unrelated
telemetry families repeatedly expose a zero-padded 32-bit construction. The implausible SYSVOL path
vocabulary provides additional environmental evidence. These indicators outweigh the otherwise
excellent operational realism, but not by enough to justify a high-80s synthetic score.

## Evidence For Synthetic

### P1 — Successful proxy upload violates payload conservation (`contract_gap`)

At `2024-03-18T17:24:55.822Z`,
`WS-AJOHNSON-01.meridianhcs.local/ecar.json:1189` records `curl.exe` uploading
`C:\ProgramData\Microsoft\cache_7f3a.zip` through `10.10.3.20:8080` to
`api.westbridge-services.net`. The same transaction is represented consistently on the client-facing
leg:

- `PROXY-01.meridianhcs.local/proxy_access.log:2010-2011` reports a successful CONNECT and POST,
  HTTP 200, with `tunnel_cs_bytes=44025410` and POST `cs_bytes=44025410`.
- `zeek/dmz/conn.log:7216` records 44,025,877 originator bytes on the client-to-proxy connection.
- `WS-AJOHNSON-01.meridianhcs.local/ecar.json:1197` and
  `PROXY-01.meridianhcs.local/ecar.json:3677` agree on tuple
  `10.10.1.35:50989 -> 10.10.3.20:8080`.

The origin-facing leg carries far less data:

- `zeek/dmz/conn.log:7217` records only 18,813,517 originator bytes from the proxy to
  `45.33.32.30:443`, with `missed_bytes=0`.
- `asa/asa.log:16655-16656` independently preserves the disparity: 46,251,737 bytes for the
  client-facing connection versus 19,621,436 bytes for the origin-facing connection.
- `PROXY-01.meridianhcs.local/ecar.json:3679` identifies that second leg as
  `10.10.3.20:54839 -> 45.33.32.30:443`.

Re-encryption can change framing overhead, but it does not plausibly shrink an already compressed
ZIP multipart upload by roughly 57%. There is no deny, truncation, retry, or capture loss explaining
the difference, and the proxy reports success. This looks like two independently parameterized flow
records rather than one forwarded payload.

### P1 — Dataset-wide identifiers expose a zero-padded construction (`schema_or_format`, `distribution_texture`)

Across sampled eCAR file records, object identifiers repeatedly have the form
`file-00000000########`, leaving the upper 32 bits visibly fixed at zero. Examples include
`file-00000000ad22afc9` in `DC-01.meridianhcs.local/ecar.json` for a SYSVOL file read and the same
construction across DC, workstation, and Linux file activity. A corpus-wide count found 190 such
zero-padded file IDs among 412 FILE records, while a small minority used a UUID-like form such as
`file-0e264da6-...` for the SCP artifact.

The same implementation fingerprint crosses into a nominally unrelated source family:
`PROXY-01.meridianhcs.local/proxy_access.log:2010-2011` uses tunnel identifier
`PT-00000000a93f2b92`. Repeated upper-half zeroes are not a normal consequence of observing files
or proxy tunnels. Their prevalence, mixed identifier schemes, and reuse across source families are
strong evidence of deterministic synthetic ID construction.

### P2 — SYSVOL paths use implausible combinatorial vocabulary (`environment_or_collection_plausibility`)

The eCAR corpus contains 65 sampled FILE records referencing SYSVOL, including paths such as:

- `C:\Windows\SYSVOL\Machine\2024\gpt.ini`
- `C:\Windows\SYSVOL\Policies\2027\groups-v2.pol`
- `C:\Windows\SYSVOL\Preferences\2025\groups.ps1`
- `C:\Windows\SYSVOL\Scripts\2024\groups-approved.xml`

The broader set repeatedly combines generic stems (`groups`, `policy`, `gpt`, `startup`,
`scheduledtasks`, `registry`), review suffixes (`draft`, `review`, `v2`, `approved`, `final`), years,
and interchangeable extensions. Real domain SYSVOL content normally reflects the standard domain
and GUID-based Group Policy hierarchy, with recognizable GPO substructure. This vocabulary resembles
a generated document-name matrix more than operational SYSVOL state.

### P2 — Service execution lacks visible binary staging (`contract_gap`)

`DC-01.meridianhcs.local/ecar.json` records creation of `DeviceSyncSvc`, an `sc create` command naming
`C:\Windows\System32\DeviceSyncSvc.exe`, and subsequent execution of that image. The sampled endpoint
telemetry is otherwise rich in FILE activity and records nearby persistence actions, but no FILE
CREATE or transfer event establishes that binary on the host. A pre-existing file is possible, so
this is not a hard contradiction; in the observed compromise sequence it is still a notable missing
lifecycle link.

### P3 — Interactive Linux administration reuses a compact command pool (`distribution_texture`, `weak_signal`)

Across multiple Linux systems and users, exact command strings recur, including
`sudo /usr/bin/systemctl list-units --state=failed --no-pager`, `iostat`, `free`, and package-query
commands. Shared runbooks can legitimately produce repetition, and role-specific variation is also
present, so this is only weak supporting evidence. The exact-string reuse is somewhat cleaner and
broader than expected from independent interactive administrators.

### P0 — No hard contradiction observed

I found no impossible chronology, impossible source-native value, duplicate identity collision, or
unrecoverable lifecycle inversion. The strongest defect is the P1 proxy payload mismatch, which is
a major correlation-contract failure but does not make the surrounding chronology impossible.

## Evidence For Real

The external web compromise is exceptionally coherent. `WEB-EXT-01.meridianhcs.local/web_access.log:448`
records a POST from `185.70.41.45` at `13:19:41Z`. At `13:19:42.527Z`,
`WEB-EXT-01.meridianhcs.local/ecar.json:825` records an Apache child launching a base64-decoding
shell command as `www-data`; `ecar.json:826` then records its outbound connection to
`45.33.32.30:8443`. `zeek/dmz/conn.log:1474-1475` and `asa/asa.log:3346-3394` preserve the inbound TLS
request and approximately 25-second callback with compatible tuples, states, durations, and byte
directionality.

SSH evidence also behaves like a correlated environment rather than disconnected rows. A long-lived
connection from `10.10.1.35:58495` to `10.10.3.10:22` precedes root authentication on the web server;
the web eCAR data, syslog authentication/PAM messages, and both relevant Zeek sensor views agree on
the session. Later, database collection and SCP transfer preserve command, file, and transport
semantics: `DB-PROD-01.meridianhcs.local/ecar.json:546` creates the database dump,
`ecar.json:581` creates its compressed form, and `ecar.json:601-603` records SCP, its outbound tuple,
and file read. `APP-INT-01.meridianhcs.local/ecar.json:751-754` records the receiving flow, SSH
session, and target-side file creation. `zeek/db/conn.log:421` and `zeek/core/conn.log:10245` observe
the same tuple and approximately 20.4-second duration from distinct sensors.

Windows activity has strong native detail. On DC-01, PSEXEC-related service and process activity is
followed by WMI-launched commands that create `svc_dirsync`, add it to Domain Admins, and establish
service and scheduled-task persistence. Corresponding Security events include 4720 and 4728 rather
than only generic process telemetry. At `17:41:55Z`, PowerShell activity is followed by
`wevtutil cl Security`; Security event 1102 appears at `17:41:59Z`, and subsequent EventRecordIDs
restart near the beginning. That reset behavior is a particularly convincing source-native detail.

The background environment is also persuasive. Zeek connection states include substantial SF and
S0 populations plus smaller RSTO, RSTR, REJ, OTH, S1, S2, and S3 tails. DNS includes A, AAAA, PTR,
and SOA behavior. Linux scheduled `debian-sa1` activity repeats on realistic half-hour cadences but
with host-specific phase offsets and occasional gaps. The corpus includes routine authentication,
process lifecycles, SMB/file use, mail, updates, service activity, failed logons, proxy traffic,
firewall records, and IDS alerts. These characteristics materially resist a simplistic “attack-only”
or uniformly timed synthetic appearance.

## Detailed Analysis

### Scope and sampling

I reviewed only the generated log corpus. Sampling covered all major hunting surfaces available in
the data: eCAR endpoint records, Windows Security and Sysmon, Linux syslog and shell histories, web
and proxy access logs, Zeek core/DMZ/database sensor views, ASA firewall records, and Snort alerts.
The corpus spans an approximately six-hour window beginning near `2024-03-18T12:00:01Z` and includes
18 instrumented hosts plus three Zeek observation points. I used timestamp, tuple, user/session,
process/PID, path, and byte-count pivots to test both suspicious and routine activity.

### Temporal and lifecycle analysis

The principal chains preserve expected ordering: network transport precedes SSH authentication;
authentication precedes shell processes; process creation precedes associated flows; file staging
precedes SCP reads; target-side file creation follows the receiving connection; and short-lived
processes generally terminate. Windows process trees retain plausible parent relationships for
PSEXEC and WMI activity. Network records have varied durations and connection states rather than a
single fixed pattern. I did not treat sessions that may begin before the observation window as
errors, nor did I penalize the corpus for unusually complete cross-source visibility.

The DeviceSyncSvc staging gap is the clearest endpoint lifecycle weakness, but it is not sufficient
alone to prove synthesis because the binary could predate the visible interval. Conversely, the
proxy mismatch is stronger because all relevant records occur inside one observed transaction and
explicitly claim a successful transfer.

### Cross-source correlation analysis

Most correlations are excellent. Source ports, destination endpoints, process identities, and close
times remain compatible across endpoint and network records. Distinct Zeek sensors use distinct UIDs
while preserving the same underlying tuple and duration, which is more realistic than globally
reusing one sensor-local identifier. The nmap activity from the web server produces a mixed pattern
of successful and unanswered connections rather than a uniform wall of identical results.

The proxy upload is the material exception. Four perspectives agree that the client supplied about
44 MB, while two origin-leg perspectives agree that only about 19 MB left the proxy. This is too
large for TLS/framing differences and has no source-native explanation. Its bilateral consistency
suggests the records are each internally coordinated but not constrained by a shared transfer-size
truth.

### Distribution and environmental analysis

Event volume and family mix are believable for a small, heavily instrumented enterprise during a
six-hour daytime period. Domain controllers naturally dominate Windows authentication and filtering
events, while user and server endpoints contribute lower-volume process and network activity.
Periodic system jobs are regular where regularity is expected, but they are not synchronized across
all hosts.

The most revealing distribution defect is identifier entropy, not event timing. The repeated
`00000000` upper half in file and proxy object IDs is visible at corpus scale and crosses telemetry
domains. The SYSVOL path set similarly reveals a combinatorial content generator. Those patterns
are difficult to reconcile with independent native producers or an ordinary collector pipeline.

## Synthetic Indicator Summary

| Severity | Indicator category | Finding | Scope | Weight |
|---|---|---|---|---|
| P0 | `hard_contradiction` | None observed | Corpus-wide review | None |
| P1 | `contract_gap` | Successful 44 MB proxy upload becomes an 18.8 MB origin stream with zero missed bytes | One high-value transaction, corroborated by proxy, Zeek, endpoint, and ASA | High |
| P1 | `schema_or_format`, `distribution_texture` | Zero-padded 32-bit-style IDs recur across eCAR file objects and proxy tunnels | Dataset-wide, multiple hosts and source families | High |
| P2 | `environment_or_collection_plausibility` | SYSVOL paths use non-native year/review-suffix matrices instead of normal GPO hierarchy | 65 sampled FILE records | Medium |
| P2 | `contract_gap` | DeviceSyncSvc executes without visible binary staging in otherwise rich telemetry | One persistence chain | Medium-low |
| P3 | `distribution_texture`, `weak_signal` | Exact interactive Linux admin commands recur across independent users and hosts | Multiple Linux hosts | Low |

## Realism Score by Category

- **Field format accuracy: 7/10.** Most source-native fields and records are credible; identifier
  construction is a conspicuous exception.
- **Temporal consistency: 9/10.** Cross-source ordering, session timing, process lifecycles, and
  connection durations are consistently strong.
- **Cross-source correlation: 8/10.** Tuples, principals, processes, and artifacts usually align;
  the proxy payload mismatch is a significant but localized defect.
- **Behavioral realism: 8/10.** Both malicious and benign activity form plausible operational
  chains with useful background density and variation.
- **Environmental realism: 6/10.** Fleet roles and activity mix are convincing, but SYSVOL and some
  file-name vocabularies reveal templated construction.

## Recommendations

1. **P1:** Make transfer byte accounting a shared transaction invariant. Derive client request-body
   size once, then propagate it through proxy access, client/proxy flows, proxy/origin flows, and
   firewall byte totals with only explicitly modeled protocol overhead or transformation. Add a
   validation check that successful forwarded uploads conserve payload within a defensible margin.
2. **P1:** Replace zero-padded counter/hash identifiers with source-appropriate, independently scoped
   identifier generation. Validate entropy and format distributions per source, and prevent one
   internal ID recipe from leaking into unrelated source families.
3. **P2:** Model Windows SYSVOL using native domain and `{GPO-GUID}` directory structures plus a
   constrained catalog of real Group Policy artifacts. Avoid generic document naming, review
   suffixes, and year folders in infrastructure paths unless a specific application creates them.
4. **P2:** Ensure service-install chains either emit binary creation/transfer evidence before first
   execution or explicitly establish that the image pre-existed the observation window.
5. **P3:** Increase administrator-specific command variation by conditioning commands on role,
   shell history, host state, tool availability, and prior command output while retaining shared
   runbook behavior where operationally justified.
