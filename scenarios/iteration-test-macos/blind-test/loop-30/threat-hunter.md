# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 96
**Synthetic-Confidence Score:** 82

## Executive Summary

This is a useful, largely coherent hunting dataset with credible enterprise background activity and practical pivots between endpoint, network, authentication and file evidence. The decisive defect is narrowly identifiable: ordinary TCP connect-scan connections produce SSH password-authentication failures on three receivers, despite the corresponding network records having insufficient client traffic to perform SSH authentication.

## Evidence For Synthetic

- [hard_contradiction] `WEB-EXT-01.meridianhcs.local/ecar.json:1293` starts PID 2705135 with `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`. Its exact TCP/22 tuples appear at lines 1306, 1560 and 2151, with source ports 47335, 42865 and 58416 respectively. Those same tuples produce `Invalid user unknown` and `Failed password for invalid user unknown` in `FILE-LNX-01.meridianhcs.local/syslog.log:179-180`, `LOG-MON-01.meridianhcs.local/syslog.log:119-120`, and `APP-INT-01.meridianhcs.local/syslog.log:105-106`. A plain `-sT` connect scan does not attempt SSH user/password authentication. This is an operation-to-effect contradiction, not an absent-source complaint.
- [hard_contradiction] The network evidence independently constrains the same defect: `zeek-core/conn.json:2799`, `:3084` and `:3655` report only 60, 100 and 24 originating payload bytes, four originating packets each, zero missed bytes, and durations 0.253550, 0.492865 and 0.430280 seconds. In particular, 24 client bytes cannot contain the SSH identification, key exchange and encrypted authentication exchange required to reach a password failure. The DMZ sensor independently records matching byte and packet totals at `zeek-dmz/conn.json:2221`, `:2505`, and `:3076`. These are corroborating aspects of one defect, not separate indicators counted multiple times.

## Evidence For Real

- The background is substantial and differentiated: 34,474 normalized endpoint records across 23 hosts, 18,300 Windows Security events, 11,459 Sysmon events, and 20,741 connection records across three Zeek sensors. Windows network authorization and Kerberos traffic dominate their appropriate families rather than every source consisting chiefly of suspicious commands.
- File movement has a useful chain of custody. The SQL dump is created before compression and SCP on DB-PROD; the receiving APP-INT file is then read by `smbclient`; FILE-LNX and Zeek observe the same destination name. Specific evidence is detailed below.
- The legitimate support upload is distinguishable from the database staging activity through command arguments, ticket identity, MIME types and separate proxy legs. `WS-LNGUYEN-01.meridianhcs.local/ecar.json:350-358` correlates with `zeek-core/http.json:1147` and `zeek-dmz/http.json:1274-1275`.
- Native Mac process observations distinguish fork, exec and exit rather than assuming every image change is a new PID. For example `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1-3` follows launchd through xpcproxy into Terminal; normalized rows retain execution identities and changes. The policy message about MeetingAssist is not evidence establishing successful execution.

## Detailed Analysis

### Orientation and hunting feasibility

The normalized endpoint timestamps span approximately 2026-11-02 13:00:01 to 18:59:55 UTC. There are ten hosts supplying Windows Security/Sysmon XML, eleven supplying Linux-style syslog, and two supplying macOS Endpoint Security and Unified Log records, plus normalized endpoint telemetry. The visible network spans workstation addresses in 10.10.1.0/24, infrastructure in 10.10.2.0/24, DMZ systems in 10.10.3.0/24 and the database at 10.10.4.10.

The environment supports actual hunting. The supplied Security files contain 791 ticket-granting-ticket requests and 2,019 service-ticket requests. The 11,931 Security 5156 records and 7,555 Sysmon network events provide considerable background volume. Counts alone do not establish authenticity, but they do not support a claim that this is merely a handful of attack records surrounded by negligible enterprise activity.

### The decisive scan/authentication contradiction

The source process at `WEB-EXT-01.meridianhcs.local/ecar.json:1293` has objectID `9e88071a-b405-40cf-8b0d-7d702b49ab0b`, PID 2705135, principal root and executable `/usr/bin/nmap`, created at 14:40:28.915 UTC. The following FLOW rows name that same actorID, PID and command, so the attribution is stronger than a shared source host.

| Exact TCP tuple | WEB-EXT eCAR line | Core conn line / UID | DMZ conn line / UID | Origin bytes / packets |
|---|---:|---|---|---:|
| 10.10.3.10:47335 → 10.10.2.21:22 | 1306 | 2799 / CAwEFbUzvp0kLOkbA | 2221 / Cm8JwsovGthryhOvQ | 60 / 4 |
| 10.10.3.10:42865 → 10.10.2.40:22 | 1560 | 3084 / CJFLEQN8lh3Uxr7Vzw | 2505 / Cyxm3pRKAn25eBMCT0 | 100 / 4 |
| 10.10.3.10:58416 → 10.10.2.30:22 | 2151 | 3655 / C1CP3mr7gFBs55bhsp | 3076 / CwAhSJZ2BgUsj5NrAJ | 24 / 4 |

The receiver evidence is independently reproducible:

- FILE-LNX syslog lines 178-181: sshd PID 2700893 records source port 47335, `Invalid user unknown` at 14:40:35.659329, and `Failed password` at 14:40:35.810329.
- LOG-MON syslog lines 118-121: sshd PID 705201 records source port 42865, `Invalid user unknown` at 14:40:37.032705, and `Failed password` at 14:40:37.187705.
- APP-INT syslog lines 104-107: sshd PID 2946353 records source port 58416, `Invalid user unknown` at 14:40:39.370878, and `Failed password` at 14:40:39.781878.

Receiver paths are the host FQDN directories listed in Evidence For Synthetic. All three connections report `conn_state=SF`, `missed_bytes=0`, and `history=ShADadfF` on both sensors. Core connection starts are 14:40:32.234792, 14:40:33.630402 and 14:40:35.884091 respectively.

Privacy sanitization could explain the word `unknown`; it cannot turn a TCP connect scan into a password attempt. Clock skew or delayed collection could explain some disagreement between source timestamps, so I do not separately score receiver timestamps being later than network close. Those explanations cannot supply the missing SSH protocol traffic. A wrapped or altered nmap binary is theoretically possible, but the supplied command, executable path, repeated behavior and tiny packet budgets provide no affirmative support for that explanation.

### Intrusion and data-movement pivots

The root SSH session on WEB-EXT starts in normalized telemetry at lines 1027-1030, followed by host discovery and the two nmap commands at lines 1042 and 1293. The source 10.10.1.35 is visible, but an IP alone does not establish which human controlled the root credentials.

Later, DB-PROD receives a root SSH session from APP-INT: `DB-PROD-01.meridianhcs.local/syslog.log:185-188` records 10.10.2.30:46218, accepted password, PAM opening and logind session creation. Its endpoint log records the database dump, output file, compression and SCP at lines 582-595. Root's bash history includes redirection to `/tmp/rpt_0318.sql`, while the process command omits that redirection, a reasonable distinction between shell syntax and program arguments.

APP-INT receives the transfer from 10.10.4.10:58931 (`syslog.log:207-212`) and creates `/tmp/.cache/rpt_0318.sql.gz` (`ecar.json:724`). It subsequently executes `smbclient` with directory account `svc_mhsync` and destination `Integration\DB-Staging\rpt_0318.sql.gz` (`ecar.json:728-730`). FILE-LNX confirms NTLMSSP authentication and a write (`syslog.log:461-465`); `zeek-core/smb_files.json:165-166` records the same path, tuple and a 125,799-byte write. Root invoking a tool with separate directory credentials is coherent.

Windows evidence provides another actionable pivot: `DC-01.meridianhcs.local/windows_event_sysmon.xml:117296` and `:117341` show WmiPrvSE → cmd → sc; Security XML at line 187182 records service installation, and Sysmon at line 121699 shows DeviceSyncSvc executing under services.exe. These are credible evidence relationships; suspicious behavior is not itself an authenticity indicator.

### Legitimate alternatives and platform interpretation

The support-ticket upload provides a competing explanation for archive creation and outbound transfer. The Linux workstation command specifies JSON metadata and a gzip diagnostic attachment. HTTP records retain those MIME components, the ticket path, 1,573,258 request-body bytes, and the transition from client-to-proxy absolute URI to proxy-to-server origin URI. This makes the trail investigable without labeling every archive transfer malicious.

On the Macs, `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` says security policy would not allow MeetingAssist. I did not infer successful launch, execution effects or persistence from that message alone. Shell history, normalized process events and ES notifications were treated as different observation types. Thin Unified Log coverage and absent selectable Sysmon families were not scored.

A GUID-based sweep of the normalized endpoint data found no actor use more than one second after its visible process termination, or more than one second before its visible creation. This is a bounded check, not proof every lifecycle is correct. Missing starts and closures outside this six-hour window were neutral.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affects the score |
|---|---|---|---|
| hard_contradiction | Source endpoint process/FLOW, receiver SSH syslog, core and DMZ Zeek | Three exact TCP/22 connections from one nmap connect scan to three hosts | Plain connect probes become password failures while independent packet budgets cannot support SSH authentication. This replicated contradiction drives the score into the 81-100 band. |

The score reflects a demonstrated contradiction in one behavior family. It does not claim every source is defective. Complete matching, compactness, absent mistakes and sanitized names were not used as indicators.

## Realism Score by Category

- **Field format accuracy:** 9 — Fields are generally parseable and useful; no broad native-format defect was demonstrated.
- **Temporal patterns:** 8 — Varied background and plausible lifecycle sequences; no separate timestamp-only contradiction is asserted.
- **Cross-source correlation:** 6 — Most pivots work, but three scan tuples have incompatible endpoint/authentication/network meanings.
- **Behavioral realism:** 7 — Data movement and support workflows are coherent; TCP scanning producing password failures is not.
- **Environmental consistency:** 9 — Host roles, local versus directory identities and mixed-platform collection are generally coherent.

## Recommendations

- If this were synthetic, distinguish an SSH-port TCP probe from an actual SSH authentication attempt. Plain `nmap -sT` should produce connection/close or pre-authentication transport noise as appropriate, without a username/password failure.
- If authentication attempts are intended, make the initiating command/process, receiver messages and bidirectional packet/byte budget describe the same activity. Retain tuple-level checks across every observing sensor.
- Preserve the useful distinction between legitimate diagnostic upload, local root activity, directory-authenticated SMB access, policy messages and successful execution. Additional source coverage is not required to address the demonstrated defect.
