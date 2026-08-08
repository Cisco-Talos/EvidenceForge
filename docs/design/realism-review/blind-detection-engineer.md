# Detection Engineer — Blind Authenticity Assessment

## Verdict

- Assessment: Synthetic
- Verdict confidence: 97/100
- Synthetic-confidence score: 96/100

## Executive summary

The dataset has unusually strong cross-source correlation, but contains two Windows lifecycle
contradictions that would not survive on real endpoints: processes continue producing telemetry
after their logon sessions are destroyed, and single OpenSSH client processes originate many
distinct interactive SSH transports. A native Windows XML schema defect and several apparently
uncoupled IDS alerts further indicate deterministic generation rather than organic collection.

## Evidence for synthetic

- **Hard contradiction — process active after logon-session destruction.** Security Event 4634
  ends Nina Kapoor's Type 2 session `0x83a3cf8` at `2024-05-14T13:08:09.5604461Z`. The same user,
  LogonID, PID `7008`, and ProcessGuid `{aab87a56-61e1-6643-7200-0010e104dde1}` subsequently
  produce Sysmon Event 3 connections through `16:34:42Z`; process termination is not logged until
  `17:04:39Z`. A destroyed LUID cannot own later activity.
- **Hard contradiction — independent recurrence.** Session `0x8399fb9` receives a Type 2 Event
  4634 at `16:35:34.3907759Z`, yet Chrome PID `7532`, ProcessGuid
  `{aab87a56-90e5-6643-7c02-001053e1179a}`, emits Sysmon network events under the same user and
  LogonID at `17:31:54Z`, `17:32:38Z`, and `17:32:51Z`.
- **Hard contradiction — impossible SSH process reuse.** One `ssh.exe` instance, PID `7008`, opens
  twelve separate TCP/22 transports to `WEB-BO-01` between `13:06Z` and `16:34Z`, each with a new
  source port. PID `6640` opens five and PID `6968` opens eight to `PROXY-BO-01`. Server syslog
  records separate authenticated sshd session lifecycles. A normal OpenSSH client owns one
  transport; ControlMaster would reuse one TCP tuple.
- **Schema/format defect — incorrect native 4648 XML fields.** All 27 Event 4648 records use
  `NetworkAddress` and `NetworkPort`; the Windows 4648 manifest uses `IpAddress` and `IpPort`. At
  `14:15:13.7488467Z`, target-like values `10.44.20.30:61030` also appear in those fields.
- **Contract gap — IDS semantics detached from HTTP evidence.** Exact Snort tuples labeled `PHP
  Possible file upload attempt` map to `GET /dashboard` and `GET /api/v1/status`, both with zero
  request-body length. SQL-injection alerts map to `/dashboard`, `/assets/app.js`, and
  `/api/v1/status`; a CRLF alert maps to another ordinary `/api/v1/status` request. Missing
  headers/bodies leave individual ambiguity, but the repeated pattern indicates independently
  selected signatures.
- **Contract gap — RDP endpoint ordering.** For
  `10.44.10.24:54160 -> 10.44.20.10:3389`, the target Type 10 logon occurs at
  `14:21:36.4823806Z`; target and source eCAR FLOW observations follow at `14:21:37.888Z` and
  `14:21:38.142Z`. Host clock skew could explain a single case, so this is supporting evidence.
- **Distribution texture — symmetric process-create jitter.** Of 565 matched Security 4688 and
  Sysmon 1 pairs, 222 Sysmon records precede Security and 343 follow it. Median absolute
  displacement is 279 ms and extremes approach ±1 second, resembling independent per-source
  jitter rather than stable provider-specific latency.
- **Environment plausibility — repeated timezone manipulation.** `PROXY-BO-01` changes to
  `America/Chicago` twice, while `WEB-BO-01` changes to Chicago and back to UTC within about 90
  seconds. Companion evidence is coherent, but the behavior is weakly artificial.

## Evidence for real

- All fourteen Windows XML streams parse, with monotonic timestamps and EventRecordIDs.
- Provider metadata, domain SIDs, account RIDs, and named-user SID mappings are stable.
- Apart from session-boundary failures, local process lifecycles are strong: no Sysmon Event 5
  precedes its Event 1; dependent events stay inside ProcessGuid intervals; eCAR termination does
  not precede creation.
- Image hashes and module metadata remain stable across repeated execution.
- Of 9,035 non-ICMP eCAR FLOW records, 8,947 match Zeek tuples with coherent states, histories,
  byte counts, and durations.
- DNS evidence correlates across Zeek and Windows Filtering Platform records.
- SSH server evidence has plausible connection, authentication, PAM, logind, and close ordering.
- DHCP renewals preserve identity and occur near half-lease intervals with jitter.
- Proxy CONNECT transactions align client-to-proxy, proxy access, and origin-side evidence; denied
  requests do not create origin connections.
- Zeek SSL, X.509, files, and PE records preserve UID/FUID relationships and coherent metadata.

## Realism scores

| Category | Score |
| --- | ---: |
| Field-format accuracy | 7/10 |
| Temporal patterns | 3/10 |
| Cross-source correlation | 7/10 |
| Behavioral realism | 3/10 |
| Environmental consistency | 6/10 |

## Reviewer recommendations

- Treat the interactive LogonID as a hard lifecycle boundary: terminate or reassign every user
  process before Event 4634 and reject later references to the destroyed session.
- Allocate one `ssh.exe` process per independent SSH transport; model ControlMaster only by
  retaining one TCP tuple and adding channels.
- Render Event 4648 from the native manifest using `IpAddress` and `IpPort`, with actual source
  semantics.
- Derive IDS alerts from the same HTTP request representation used by Zeek and access logs.
- Anchor RDP endpoint FLOW observations before authentication or model bounded, stable host-clock
  offsets across all records from the host.
- Replace symmetric per-event process jitter with stable source-specific collection latency around
  one canonical process time.
- Make timezone changes stateful and role-driven.

## Isolation statement

The reviewer received only `/private/tmp/eforge-realism-review/branch-enterprise/data`; scenario,
ground truth, code, prior reports, and other reviewers' conclusions were withheld.
