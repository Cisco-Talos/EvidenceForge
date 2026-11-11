# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 28

## Executive Summary

The examined records are mostly production-like: exact-tuple SSH pivots, remote-credential semantics, and an outbound upload form technically workable investigations across independently rendered sources. A repeated browser-search referrer on domain-controller check-ins and an unusual runas parent are weak concerns, but neither establishes artificial origin or an impossible relationship. This is a bounded authenticity assessment, not an assertion that the visible suspicious activity is benign.

## Evidence For Synthetic

- [weak_signal] In `PROXY-01.meridianhcs.local/proxy_access.log`, all **10/10** GET requests to `https://api.westbridge-services.net/api/v2/checkin` carry exactly `https://www.google.com/search?q=api+westbridge-services+net` as referrer and the same Chrome/121 Windows user agent. The client is the domain controller `10.10.2.10`, from 17:29:32 through 18:59:32 UTC. Repeated search-navigation decoration on a check-in endpoint looks like browser vocabulary reused for automation. A real implant can deliberately send static camouflage headers, so this is not a contradiction and receives little weight.
- [weak_signal] In `WS-AJOHNSON-01.meridianhcs.local/ecar.json` at 18:00:42.835, process UUID `73975905-5dc5-47f8-9bea-62ef9c851128`, PID 6624, is `runas.exe /netonly /user:marcus.chen "cmd.exe /d /q"` with parent `winlogon.exe`, PID 5796, UUID `688266f9-9542-4d82-ad86-e63a81261cd0`. That is an unusual origin for this interactive credential utility. The other **4/5** runas creates in the eCAR collection have `explorer.exe` parents. This may reflect a launcher/parent attribution shortcut, but compromise, unusual launching, or parent manipulation are also possible. It is not scored as impossible.

## Evidence For Real

- SSH transport precedes authentication on the exact `10.10.2.30:44788 -> 10.10.4.10:22` tuple. `zeek-core/conn.json` UID `C2KRUZXDrYJrSvVA853` begins at Unix time 1793643303.799508; DB endpoint FLOW is 18:15:04.833, sshd reports the connection at 18:15:07.665097 and password acceptance at 18:15:14.021042, and the DB eCAR LOGIN follows at 18:15:14.223. Root's shell and database commands follow authentication.
- The return SCP transfer uses a separate direction and source port, `10.10.4.10:53915 -> 10.10.2.30:22`, rather than reusing the interactive SSH tuple. Its receiver has a public-key authentication, noninteractive sshd activity, a destination file creation, and a paired session close.
- The large HTTPS upload has coherent proxy and wire accounting. The client connection has 18,809,750 origin bytes; the matching proxy CONNECT records 227 control-message bytes plus 18,809,523 tunnel bytes, exactly the same total. The POST's 18,783,258 client bytes are distinguishable from encrypted transport bytes.
- NewCredentials semantics preserve local `aisha.johnson` while setting outbound `marcus.chen`. Security 4648 and 4624 Type 9, followed by the child command process's new logon ID, avoid incorrectly making the local process principal change to the remote account.
- Background evidence has practical variety: DHCP renewal/ack pairs, Linux service messages, unsuccessful SSH, Internet scanning, different connection outcomes, and varied hourly event density. These support a plausible collection without proving that it is real.

## Detailed Analysis

### Scope and method

I read only the assigned data directory and briefing. The collection exposes **23 endpoint eCAR host files** and network sources across apparent user (`10.10.1.0/24`), server (`10.10.2.0/24`), DMZ (`10.10.3.0/24`), and database (`10.10.4.0/24`) segments. Endpoint evidence supports Windows, Linux, and two macOS hosts. Network visibility alone was not treated as native endpoint coverage.

The eCAR window is 2026-11-02 **13:00:00.756–18:59:50.518 UTC**, containing **39,270** records: 29,023 FLOW, 6,046 PROCESS, 2,092 MODULE, 1,475 USER_SESSION, 392 FILE, 228 REGISTRY, 11 THREAD, and 3 SERVICE. Parsing the XML document elements yields **19,224 Security events** and **12,086 Sysmon events**, rather than the misleading much larger XML line counts. Network sources contain 24,092 connection rows across three sensors; these are sensor observations, not necessarily distinct conversations. There are also 4,351 proxy access rows and 4,242 syslog rows.

I sampled representative Windows XML, Linux syslog/history-related execution, macOS endpoint and Unified Log records, proxy, firewall, and Zeek data. Deeper pivots followed root SSH/database collection, its SCP return, credential switching on a Windows workstation, and the large outbound upload. I also checked all eCAR records for narrowly defined lifecycle inversions: visible process/session termination before the first matching visible create/login; actor references more than three seconds after that exact process UUID's termination; and actor references more than two seconds before the exact UUID's create. None of those checks returned a candidate. These are bounded checks with tolerances, not a proof that every relationship is correct.

### SSH and database collection pivot

On APP-INT-01, root executes `ssh root@DB-PROD-01.meridianhcs.local` at 18:14:54.656. Network tuple `10.10.2.30:44788 -> 10.10.4.10:22` is observed by core UID `C2KRUZXDrYJrSvVA853` at 18:15:03.799508 and database sensor UID `CMFQdqWQ8DcvLERtAYi` at 18:15:03.871479. Their small timestamp difference and different UIDs are compatible with separate sensors. Core reports `SF`, duration 685.470508 seconds, origin/response bytes 22,398/30,792.

DB-PROD-01 syslog ties PID **1088964** to that exact client address and source port, password acceptance at 18:15:14.021042, PAM session opening at 18:15:14.103669, and systemd session **362**. The normalized LOGIN identifies root, logon ID **0x1185f8fa**, session 362. Root shell PID 1089007 appears at 18:15:16.620; `mysqldump --single-transaction ehr patients insurance_claims` PID 1089021 starts at 18:15:20.445 and the associated `/tmp/rpt_0318.sql` creation is recorded at 18:15:21.792. Gzip creates `/tmp/rpt_0318.sql.gz` at 18:15:43.523.

SCP PID **1089125**, UUID `a52c0f68-e66f-45cf-8951-30c477b55e0c`, starts at 18:15:50.237. Its tuple is `10.10.4.10:53915 -> 10.10.2.30:22`; core UID `CQiIqTqIvg1YuoPHBTs` begins at 18:15:53.041863 and database UID `CRSd4K28pLyMH5y2B7I` at 18:15:53.113395. APP syslog PID **2983988** records this connection, public-key acceptance at 18:16:03.367554, PAM opening at 18:16:03.485598, and systemd session **551**. The destination file `/tmp/.cache/rpt_0318.sql.gz` is observed at 18:16:25.723, PAM closure at 18:16:27.037835, and the eCAR session logout at 18:16:40.991 for the same session UUID `62797591-35a1-4e4a-8558-59be0cd012d4`.

Source timestamps differ by seconds, and the file observation follows the core sensor's computed transport close by less than one second. Given source observation timing, this is not sufficient to allege a physical write after transport closure. The exact identity and surrounding lifecycle remain compatible. The dump command's argv omits shell redirection; that omission is not a demonstrated error because redirection need not be in the executable's argument vector.

### Windows remote credentials and persistence

WS-AJOHNSON-01 Security **4648** at 18:00:45.6092108 names caller aisha.johnson, target marcus.chen, and runas PID **0x19e0 = 6624**. Security **4624 Type 9** at 18:00:45.8811456 retains aisha as `TargetUserName`, assigns new logon ID **0x27c991a**, and sets `TargetOutboundUserName=marcus.chen`. Child cmd PID **6652** at 18:00:46.339 has aisha as local principal and the new logon ID. This is a meaningful distinction between local token ownership and outbound credentials, not an account mismatch.

On DC-01, the visible `net user svc_dirsync ... /add /domain` execution at 17:14:44.129 precedes Security **4720** at 17:14:48.3124968, SID ending **4007**. The Domain Admins membership event **4728** at 17:15:07.9986778 uses that same SID. Service and task creation likewise have source-native companion events: **4697** for DeviceSyncSvc at 17:20:23.3955822 and **4698** for `\Microsoft\Windows\Maintenance\DeviceSync` at 17:20:24.2987117. The task contains an hourly repetition and matching executable path. These are technically workable pivots; their narrative completeness carries no authenticity penalty.

### Upload pivot and accounting

On WS-AJOHNSON-01, curl PID **6784**, UUID `f9b5d3e1-67c8-4e9e-9bdf-c4fe2b3759f4`, starts at 18:25:22.222 with explicit proxy `10.10.3.20:8080`, archive `C:\ProgramData\Microsoft\cache_7f3a.zip`, and upload path `/upload/telemetry/7f3a2b19`.

Proxy entries at 18:25:26 identify aisha, client source port **57145**, and tunnel **PT-7babf24552bdc8c3**. The tunnel entry and decrypted POST distinguish byte scopes and log inspection explicitly. Core UID `CtaWOR1ev1OCkDywOu` and DMZ UID `C73hCLZH3eWg9NHBOj` show the same client tuple to the proxy. Both record 18,809,750 origin bytes and 7,141 response bytes. The arithmetic is coherent: **227 + 18,809,523 = 18,809,750**, and **167 + 6,974 = 7,141**. The DMZ upstream tuple `10.10.3.20:36021 -> 45.33.32.30:443`, UID `C4DjQdw8HBHLFbCNPpc`, begins at 18:25:27.395060 and has SSL SNI for the same destination. I did not require Zeek to expose the decrypted POST in an encrypted wire capture.

### Baseline and limitations

Hourly eCAR counts are **6,411, 8,113, 6,035, 5,882, 6,665, and 6,164** for hours 13–18 UTC, rather than an exact constant. Core conn states include 10,459 SF, 1,702 S0, 456 OTH, 170 RSTO, and smaller other states. This is plausibly varied and not an obviously smoothed source mix.

WS-LNGUYEN-01 syslog has **22 DHCP-tagged messages**, including request at 13:01:19.806888 and ACK at 13:01:20.253497. WEB-EXT-01 contains **950 UFW BLOCK messages out of 1,365 syslog rows**, appropriate to an exposed host receiving scans, rather than a collection with only incident actions. DB-PROD-01 includes a failed password for jennifer.walsh from `10.10.2.11:65258` at 18:27:36.584820. I have not inferred a missing source family from sparse macOS Unified Log coverage, demanded omitted Sysmon types, or penalized processes/sessions that cross the window boundary.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Proxy HTTP metadata | 10/10 DC check-in GETs reuse one search referrer and user agent | Small increase: looks templated but real client camouflage is a viable explanation |
| weak_signal | Windows normalized process lineage | One of five visible runas creates uses winlogon as parent | Small increase: unusual launcher attribution, no demonstrated impossible execution |
| No demonstrated hard contradiction | Endpoint/session/network joins | Exact-identity checks and selected investigations described above | Keeps score in the mostly realistic band; absence of a found defect does not establish provenance |

## Realism Score by Category

- **Field format accuracy:** 9 — Examined XML, JSON, syslog, and network shapes are usable; no demonstrated source-native schema defect.
- **Temporal patterns:** 9 — Selected transport/authentication/action ordering works, with plausible source timing differences and varied hourly volumes.
- **Cross-source correlation:** 9 — SSH tuples, sessions, remote credentials, and proxy-upload accounting support substantive pivots.
- **Behavioral realism:** 8 — Technical tradecraft works; static browser-navigation headers and one launcher lineage leave weak concerns.
- **Environmental consistency:** 8 — Mixed fleet and segmented collection are plausible; selected DC web metadata is unusual but explainable.

## Recommendations

- If this were synthetic, make client HTTP headers reflect the actual originating program: preserve an intentional static camouflage profile when modeled, and avoid indiscriminate search-referrer decoration of periodic API check-ins. The concrete target is the 10 identical DC check-in referrers.
- If this were synthetic, verify the owner of the runas launch at 18:00:42.835 on WS-AJOHNSON-01. Use winlogon parentage only when that mechanism is intended and supported; preserve actual process creation/token ownership rather than assigning an interactive session anchor as a launcher.
- Preserve the demonstrated exact-tuple SSH lifecycle, NewCredentials local/outbound distinction, and explicit proxy byte scopes. There is no evidence-based reason in this review to add arbitrary retries, additional log products, or artificial disorder.
