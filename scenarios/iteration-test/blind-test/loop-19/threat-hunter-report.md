# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 30

## Executive Summary

The supplied telemetry is mostly production-like from a threat-hunting perspective: process, authentication, transport, file-transfer, and proxy pivots support technically coherent investigations across Windows, Linux, and macOS. I found a mild fleet-wide concentration of privileged diagnostic activity near the beginning of collection, but no demonstrated impossible lifecycle or cross-source contradiction in the checks performed; the Real verdict is therefore a modest lean, not an assertion of provenance.

## Evidence For Synthetic

- [distribution_texture] Privileged diagnostic command activity is unusually front-loaded across several Linux servers. Native `sudo ... COMMAND=` records show all 13 accepted commands on WEB-EXT-01 between 13:01:37 and 13:40:23, all six on APP-INT-01 between 13:18:35 and 13:29:46, and all eight on LOG-MON-01 between 13:00:47 and 13:28:31. DB-PROD-01 has eight between 13:05:37 and 14:26:55, and PROXY-01 has 13 between 13:13:26 and 14:17:11, followed by none during the remainder of the approximately six-hour slice. Commands include `systemd-analyze blame`, `needrestart -b`, `apt list --upgradable`, and filesystem/resource checks. This is a concrete baseline distribution concern, but a coordinated morning maintenance or support period could explain it; it receives limited weight.
- [weak_signal] The diagnostic vocabulary overlaps across those hosts: WEB-EXT-01, DB-PROD-01, and APP-INT-01 each execute `needrestart -b`; WEB-EXT-01 and APP-INT-01 execute `systemd-analyze blame`; APP-INT-01 and LOG-MON-01 use closely spaced sequences of resource and service checks. These are ordinary administration commands, so repetition alone is weak evidence. This observation is related to the preceding concentration and is not counted as an independent strong defect.

## Evidence For Real

- The public-web compromise has a viable process and network pivot: WEB-EXT-01 `web_access.log` line 440 records a POST to `/ehr/admin/upload.php` at 14:20:17; endpoint telemetry records an Apache-child shell at 14:20:20.711, then `base64 -d` and `bash`; the latter owns the connection to `45.33.32.30:8443` at 14:20:24.072. `zeek-dmz/conn.json` line 1752 observes the matching tuple and a completed 11.697631-second TCP flow.
- Windows privilege evidence supports the credential-access activity instead of requiring an unexplained medium-integrity injection. WS-AJOHNSON-01 Sysmon Event 1 records PID 5864, `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, with High integrity at 16:45:04.671. Security 4688 supplies mandatory label `S-1-16-12288` and an elevated token type, followed by Sysmon process-access and remote-thread evidence, then process termination.
- The same workstation preserves the distinction between local and outbound credentials. At 18:00, `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` produces a Type 9 logon whose local target remains `aisha.johnson` while `TargetOutboundUserName` is `marcus.chen`. Subsequent local processes remaining attributed to Aisha are technically consistent.
- The Linux diagnostic upload is supported by an explicit multipart curl command, the correct proxy tuple, HTTP body sizes, file metadata, and proxy records. The archive payload is 1,572,864 bytes; the multipart HTTP body is 1,573,258 bytes; the corresponding connection carries 1,573,700 originator bytes. These different layers have appropriately different sizes.
- SSH ordering is coherent in a directly checked Mac-to-Mac session: source FLOW, destination FLOW, accepted public key, and destination user login occur in that order. The session ends near the corresponding transport close, rather than before authentication or substantially beyond a visibly closed channel.
- The Gatekeeper-related Unified Log message naming MeetingAssist is not accompanied by a visible MeetingAssist execution in the supplied Endpoint Security exports. I did not infer successful execution or downstream effects from a policy message alone.

## Detailed Analysis

### Scope and method

I restricted examination to the supplied data directory. The normalized endpoint view contains 37,971 records across 23 host directories, with observed times from 2026-11-02 13:00:00.848 through 18:59:58.786 UTC. Apparent address groupings include client systems in `10.10.1.0/24`, directory/file/application/mail infrastructure in `10.10.2.0/24`, a public web server and proxy in `10.10.3.0/24`, and a database server at `10.10.4.10`.

Sources include 17,663 actual Windows Security events, 11,573 actual Sysmon events, 4,496 Linux syslog lines, 324 macOS Endpoint Security records, five Unified Log records, shell histories, three Zeek sensor directories, firewall records, proxy/web access logs, and IDS alerts. XML line counts were not treated as event counts. These are selective collections; I did not penalize sparse Unified Log data or omitted event families merely for being sparse.

I parsed the XML and JSON sources, followed selected suspicious and administrative pivots, and checked all supplied normalized process actors/source-process references against visible creation and termination events. With a one-second tolerance for differing observation timestamps, that scan found no dependent event preceding its visible process creation or following its visible termination. This is a bounded consistency result, not proof that every unexamined semantic relationship is valid.

### Web entry and Linux movement

The upload-to-shell sequence on WEB-EXT-01 is supported by native web access and endpoint process evidence. The encoded shell command decodes to a Bash reverse connection to `45.33.32.30:8443`; the visible connection uses source port 46747 and is owned by the child Bash process. Both endpoint and Zeek observations place the transport after the shell processes exist.

Later root SSH sessions and commands provide separate investigative leads. At 14:39, WEB-EXT-01 records a root SSH session, shell readiness, interface and resolver inspection, and `nmap` commands. At 14:59–15:00 it records reads of web configuration and `/root/.ssh/id_rsa`. I regard those as observed behaviors; the supplied rows alone do not establish which credential or exploit originally produced root access.

The later APP-INT-01 to DB-PROD-01 path is internally usable. APP-INT-01 launches `ssh -l root DB-PROD-01.meridianhcs.local`; Zeek records `10.10.2.30:52259 -> 10.10.4.10:22` at 18:14:54.746343. DB-PROD-01 syslog records accepted root password authentication at 18:15:07.496703 and session 521 shortly afterward. The root shell subsequently runs `mysqldump`, `gzip`, and `scp`.

The SCP return path uses a distinct connection, `10.10.4.10:58224 -> 10.10.2.30:22`, at 18:15:45.022370. APP-INT-01 records that source tuple at 18:15:50.399645 and accepted public-key authentication at 18:15:51.021793. Distinct password and public-key authentication in opposite directions is plausible and is not an identity contradiction. The Zeek flow also has nonzero missed bytes and a gap marker, showing a collection imperfection rather than an exclusively idealized network view.

### Windows credentials, collection, and exfiltration

WS-AJOHNSON-01's credential-access process is elevated in both Sysmon and Security views. Its Event 10 access to LSASS occurs at 16:45:08.066 with `GrantedAccess=0x1FFFFF`; a remote-thread event follows at 16:45:08.159, and PID 5864 terminates at 16:45:12.582. These observations are temporally possible. The precise binary's behavior cannot be established solely from its renamed executable and command line.

The later `runas /netonly` session uses local logon ID `0x27c9905`, while the visible 4624 keeps local and outbound principals separate. This is a consequential hunting distinction: local file access and remote SMB authentication need not have the same displayed username.

The collection commands reference finance, clinical, and research shares, compress local staged content, and subsequently upload `cache_7f3a.zip` with curl. At 18:25:17.759 the curl process is created; its file read and proxy connection follow. The proxy access log line 3989 records a POST to `/upload/telemetry/7f3a2b19`, HTTP 200, client source port 61456, and `cs_bytes=18783258`. Zeek observes the client-to-proxy leg separately from the proxy's TLS origin connection. A proxy action and its origin leg should not be expected to share a socket tuple.

### Administrative upload and protocol accounting

WS-LNGUYEN-01 executes a multipart curl command referencing ticket `MHS-48217`, JSON metadata, and `/tmp/mhs-support-48217.tar.gz`. `zeek-core/http.json` line 1350 records HTTP POST UID `CHmkMLnrrA6SrR50Zkn` with body length 1,573,258. `zeek-core/files.json` line 392 gives the archive FUID `FwI6wlWrJbnXxPnEbV` and 1,572,864 seen bytes. `zeek-core/conn.json` line 7539 gives 1,573,700 originator bytes, matching the proxy's client-byte accounting at line 2324.

The DMZ sensor also observes an origin-facing POST to `52.44.186.73:80` with an origin-form path, while the client-facing proxy request uses an absolute URI. That distinction is appropriate for forwarding an HTTP request through an explicit proxy.

For HTTP and SSL records across all three Zeek directories, I checked matching-UID protocol timestamps against visible connection intervals, allowing a one-second tolerance. I also checked individual HTTP request/response body lengths against their corresponding connection byte totals. Those checks found no protocol event outside its connection interval and no individual HTTP body exceeding the relevant connection total. They do not test every possible multi-transaction aggregation issue.

### macOS session interpretation

For `10.10.1.42:63330 -> 10.10.1.41:22`, the core sensor starts the connection at 16:02:01.058420. MAC-MROSS-02's outbound endpoint FLOW is at 16:02:01.478, and MAC-MROSS-01's inbound FLOW is at 16:02:02.266. Unified Log records accepted public-key authentication at 16:02:06.829781, followed by normalized USER_SESSION LOGIN at 16:02:08.431. The transport lasts 958.195871 seconds, and the normalized logout is at 16:18:08.535, close to transport termination. This supports a practical tuple-to-authentication-to-session pivot.

The Endpoint Security files contain fork, exec, and exit observations. I did not interpret them as authorization responses or require native Mac endpoint semantics from unrelated network-sensor rows. The MeetingAssist policy line at 15:42:09.009673 does not, by itself, prove execution; no supplied ES row names that application.

### Baseline texture and limitations

The privileged diagnostic activity concentration is the main reservation. Several independently named Linux servers exhibit command bursts in the first part of collection and then no further accepted sudo-command records. Shared morning administration can produce this, but the phase concentration plus overlapping command vocabulary warrants modest skepticism.

Conversely, there is sufficient routine DNS, authentication, service, process, proxy, and monitoring activity that the malicious trail is found by process and tuple pivots, not merely by reading a handful of isolated suspicious lines. Collection scope remains uncertain. I did not use sanitized names, absent pre-window initiators, complete alignment, attack compactness, or the ability to narrate the incident as synthetic indicators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog and normalized endpoint processes | Five server hosts; 48 accepted sudo commands concentrated before 14:27 in a slice ending near 19:00 | Mild upward pressure; plausible shared maintenance window prevents a strong conclusion |
| weak_signal | Linux administration command vocabulary | Overlapping diagnostic tools across the same hosts | Limited supporting weight; overlaps with the first observation and is not independently decisive |

No hard contradiction or demonstrated contract gap was established in the checks performed.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native and normalized records have credible fields, identifiers, and protocol-layer distinctions in the inspected paths.
- **Temporal patterns:** 8 — Investigated execution/authentication/transport orderings work; privileged diagnostic activity is front-loaded.
- **Cross-source correlation:** 9 — Checked process, SSH, proxy, multipart file, and network pivots preserve ownership and layer-specific values.
- **Behavioral realism:** 8 — Credential access, netonly authentication, Linux movement, collection, and support uploads are technically plausible; administrative command texture is somewhat repetitive.
- **Environmental consistency:** 9 — Mixed-platform identities, service placement, internal segments, and proxy transport behavior broadly agree with the visible evidence.

## Recommendations

- If this were synthetic, examine the concentration of accepted sudo commands across WEB-EXT-01, APP-INT-01, LOG-MON-01, DB-PROD-01, and PROXY-01. If no shared maintenance window is intended, spread routine privileged diagnostics according to independent administrator/session activity rather than clustering every host's command work near collection start.
- If this were synthetic, diversify the overlapping diagnostic sequences only where actual host roles justify it. Preserve the existing coherent process ownership, outbound-versus-local credentials, proxy legs, multipart sizes, and SSH ordering; these checks did not establish defects requiring changes.
