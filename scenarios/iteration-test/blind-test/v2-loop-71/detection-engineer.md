# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 95  
**Synthetic-Confidence Score:** 97

## Executive Summary

The telemetry is assessed as synthetic with high confidence. Most individual records are
well-formed and many difficult operational contracts are handled convincingly: Windows process
lineage and session lifecycles are coherent, firewall connections have valid build/teardown
semantics, Zeek records have protocol-appropriate state, and Postfix queue chains preserve their
identifiers and recipient counts.

Those strengths do not overcome several concrete endpoint contradictions. Records dated 18 March
2024 execute software from later release trains, including Microsoft Teams
`24124.2315.3009.6699`, Visual Studio Code `1.89.1`, and Microsoft Office build
`16.0.17628.20006`. The Teams records also combine the new-client `24xxx` version family with the
classic-client `Teams.exe` name and `AppData\Local\Microsoft\Teams\current` installation path.
Separately, two Windows 11-build workstations report core OS binaries from Windows 10, Windows 11,
and Server 2022 build families in the same image. The proxy log adds a lower-weight state-model
problem: identical anonymous client/authority/user-agent groups repeatedly alternate between HTTP
407 and successful 200 outcomes without an authenticated identity appearing in the successful
record.

I did not treat sanitized domains, source-family selection, sparse coverage, the compactness of the
intrusion, or the mere presence of cross-source matches as authenticity evidence.

## Evidence For Synthetic

- **[hard_contradiction] Software chronology conflicts with event time.** Sysmon process-create
  records are consistently dated 18 March 2024, yet four workstations execute Teams version
  `24124.2315.3009.6699`; the `24124` client train is a 2024 day-124 train, later than day 78
  represented by 18 March. Independent examples include `Code.exe` version `1.89.1` on
  WS-MCHEN-01 at `15:07:15.178` and Office version `16.0.17628.20006` across six workstations.
  Those are later 2024 release branches. Repetition across hosts and applications rules out a
  single mistyped process record.

- **[hard_contradiction] Teams product generation, executable, and install path do not agree.**
  The records pair the newer `24xxx` Teams version scheme with
  `C:\Users\<user>\AppData\Local\Microsoft\Teams\current\Teams.exe`, the classic-client layout and
  executable name. The newer client uses a different packaged application layout and executable.
  This incompatible combination occurs six times on WS-AJOHNSON-01, WS-DRAMIREZ-01,
  WS-EBROOKS-01, and WS-PPATEL-01, always with the same four hashes.

- **[environment_or_collection_plausibility] Core Windows metadata mixes incompatible OS build
  families.** WS-MCHEN-01 otherwise has Microsoft system images at `10.0.22621.1` and a
  `10.0.22621.3155` servicing path, but eight `mstsc.exe` launches and three `gpupdate.exe`
  launches report `10.0.19041.1`; `perfmon.exe` reports Server 2022-family `10.0.20348.1`.
  WS-PPATEL-01 likewise has a 22621 image while three `gpupdate.exe` events report
  `10.0.19041.1`. A manually copied binary could explain one occurrence, but repeated core-tool
  substitutions from two other OS families on two hosts are characteristic of metadata selected
  from a catalog rather than read from coherent host images.

- **[contract_gap] Proxy authentication outcomes lack a stable state transition.** In 13 exact
  groups keyed by source IP, anonymous-user marker, method, authority, and user agent, the log
  alternates between 407 `auth-required` and 200 success while the accepted row still records user
  `-`. For example, anonymous `Wget/1.21.3` from `10.10.2.40` to
  `api.snapcraft.io:443` receives interleaved 200 `tunnel`, 403 `deny`, and 407
  `auth-required` outcomes over 25 requests. The format demonstrably records named identities for
  other accepted clients, so neither the policy state nor an authenticated retry is visible here.
  Complex policy could explain some variation, making this supporting rather than decisive
  evidence.

## Evidence For Real

- Windows XML is structurally and semantically close to native output. Security 4624 version 2,
  4688 version 2, and 5156 version 1 carry appropriate field sets. Sysmon event versions and fields
  are appropriate for process, network, image-load, remote-thread, process-access, file-create,
  registry, and DNS events.

- The DC-01 Security log-clear sequence is particularly convincing. Event 1102 uses the
  `Microsoft-Windows-Eventlog` provider and `LogFileCleared` user-data structure, and subsequent
  `EventRecordID` values restart from 1 instead of continuing the prior sequence.

- Visible Windows lifecycle state is coherent. No sampled dependent Sysmon event precedes its
  visible process create, no visible activity occurs after the matching terminate, and matched
  process GUIDs preserve PID and image. All 260 visible parent-child links checked across ten
  Windows hosts preserve parent PID and image. File-audit handles follow valid
  4656→4663→4658 or 4656→4658 sequences, while RDP 4624/4779/4634 records preserve logon IDs and
  source tuples.

- Firewall state is strong. All 6,351 teardown records with a visible build have the same
  connection ID, interfaces, endpoint tuple, and direction as their build record; only four builds
  remain open at the right edge of the observation window. NAT build/teardown records and Zeek
  tuples also follow the expected routed view.

- Zeek protocol semantics show useful texture rather than one generic connection template. TCP
  states, histories, packet counts, and durations vary; UDP DNS uses appropriate UDP histories;
  DHCP uses client/server ports 68/67; TLS versions, ciphers, resumptions, certificate chains, and
  X.509 records are internally compatible. Sensor-local protocol UIDs resolve to connection
  records without contradictory tuples.

- Linux telemetry has role-specific behavior and sound lifecycle ordering. SSH records retain the
  same daemon PID through connection, acceptance, PAM open, and close. SMB activity on FILE-LNX-01
  progresses through child process creation, inbound flow, user-session login, file operations,
  and termination with a plausible root daemon/effective remote-user distinction.

- Postfix queue processing is unusually well executed. Queue IDs progress through
  `smtpd`/`cleanup`/`qmgr`, produce the declared number of local or SMTP deliveries, and are then
  removed. Cross-server handoffs retain message IDs while allocating the receiving server's new
  queue ID, and reported delay components approximately sum to total delivery delay.

- The web scan is not rendered as completely random noise. Repeated static-path/status groups have
  stable byte counts—for example eight `/robots.txt` 200 responses are all 4,497 bytes and eight
  `/.htpasswd` 403 responses are all 1,277 bytes—while the dynamic `/info.php` 200 responses vary.

## Detailed Analysis

### Scope and parsing

The review was limited to the contents under `review-data`. No parent-directory artifacts,
repository files, prior assessments, external manifests, or filesystem timestamps were used. The
corpus covers approximately six hours on 18 March 2024 and includes ten Windows endpoint/server
sets, eleven Linux host sets, three Zeek sensors, two Snort sensors, an ASA firewall, explicit-proxy
access logs, and web access logs. All examined XML and JSON records parsed successfully, and file
local event order was nondecreasing.

### Windows endpoint and identity telemetry

The native event construction is generally excellent. Security and Sysmon represent process IDs in
their native hexadecimal/decimal forms yet reconcile to the same process. Process-create and
terminate records retain GUID, image, and PID; parent references resolve without visible lineage
contradictions. Kerberos AS/TGS events use sensible service and source fields, and 5156 direction
codes agree with their filtering-platform layer identifiers. Object-access handles remain stable
from open through access and close.

The software inventory breaks that otherwise coherent host model. On WS-MCHEN-01, most Microsoft
system processes identify as build 22621, while `mstsc.exe`, `gpupdate.exe`, and `perfmon.exe`
introduce 19041 and 20348 metadata. WS-PPATEL-01 repeats the 22621/19041 combination. More
decisively, the March timestamps predate several recorded application builds, and Teams combines a
new-client version family with a classic-client path and filename. These are properties rendered in
the process records themselves, not conclusions drawn from absent event families or source
coverage.

### Network, IDS, firewall, proxy, and web telemetry

The network layer largely obeys native contracts. Snort alerts use valid fast-alert structure and
plausible classifications, priorities, protocols, and tuples. Duplicated observations across core
and perimeter sensors preserve signature and tuple while showing small path-consistent time
offsets. ASA build and teardown messages have valid interface/NAT views, monotonically allocated
connection IDs, coherent durations, and no visible tuple mismatch.

The proxy format distinguishes ordinary forwarding, tunnel control messages, inspected TLS child
requests, denials, authentication challenges, and gateway errors. Tunnel IDs and byte-scope labels
are used coherently. The weakness is policy state: exact anonymous client/authority/user-agent
groups can move among 407, 403, and 200 without a user identity or other log-visible state change.
This is not impossible in an elaborate time-varying policy, but the repeated pattern makes sampled
per-request outcomes more plausible than an observed production proxy policy.

The web server shows believable static-versus-dynamic response behavior and a plausible scanning
cadence. I did not use the compact scan narrative or the cleanliness of its network companions as
an authenticity indicator.

### Linux, mail, and service telemetry

RFC 5424 structure, host labels, application names, process IDs, and role-specific messages are
internally sound. High PIDs coexist with kernel uptime values consistent with long-running hosts.
SSH, Samba, package-management, service-management, database, proxy, web, and mail behavior differ
appropriately by server role. Postfix queue semantics and multi-server delivery are among the
strongest authenticity-supporting parts of the corpus.

Some daemon message families recur across many hosts, but a standardized Linux fleet can naturally
produce that result. It was therefore not scored as an adverse indicator.

### Intrusion and detection semantics

The malicious sequence has source-native depth: PsExec-style service-binary placement and service
installation precede service process execution; account creation, password setting, group
membership, service creation, and scheduled-task registration have appropriate Security event
types; and the later `wevtutil` action is followed by a correctly formed 1102 record and record-ID
reset. These details support realism. Their cross-source completeness and the linearity of the
sequence were intentionally given no authenticity weight.

The assessment changes because baseline endpoint records—not just the intrusion—contain impossible
or highly implausible software-version combinations. That makes the verdict less dependent on how
the attack narrative was authored.

## Synthetic Indicator Summary

| Category | Concrete log-visible indicator | Weight | Caveat |
|---|---|---:|---|
| `hard_contradiction` | March 18 events execute Teams `24124...`, VS Code `1.89.1`, and Office `17628...`, all from later 2024 release trains | Critical | Would weaken only if timestamps were deliberately shifted during sanitization; no such evidence exists in the permitted corpus |
| `hard_contradiction` | New-client Teams version scheme is attached to classic `Teams.exe` and classic per-user `...\Teams\current` path | Critical | Repeated on four hosts, so not a one-record typo |
| `environment_or_collection_plausibility` | 22621 workstation images mix 19041 core tools and, on one host, a 20348 `perfmon.exe` | High | Individually possible via manual file copying, collectively unlikely |
| `contract_gap` | Thirteen exact anonymous proxy client/authority/UA groups alternate 407 and 200 without a recorded authenticated identity | Medium | A hidden, context-sensitive policy could account for a subset |

No adverse score was assigned for sanitized names, source selection, missing event families,
bounded-window censoring, sparse sources, cross-source completeness, or narrative compactness.

## Realism Score by Category

| Category | Score | Basis |
|---|---:|---|
| Field format accuracy | 9/10 | Native XML, JSON, RFC 5424, Snort, ASA, proxy, and web structures are strong; the main defects concern metadata truth rather than syntax |
| Temporal patterns | 8/10 | Event-local ordering, durations, session lifecycles, and service cadence are convincing; application release chronology is not |
| Cross-source correlation | 9/10 | Correlated tuples, process identities, queue IDs, handles, sessions, and firewall state are semantically consistent, beyond mere record matching |
| Behavioral realism | 8/10 | Role-specific baseline and attack behavior are detailed; proxy outcome transitions are insufficiently grounded in visible policy state |
| Environmental consistency | 5/10 | Host/IP/role topology is coherent, but future software and mixed Windows build families materially break the endpoint image model |

## Recommendations

1. Validate every generated application version against the scenario date. Treat future-version
   execution as a generation-blocking error unless an explicit clock-shift model is present.
2. Model Teams generations as distinct products: keep classic `Teams.exe`/per-user Squirrel paths
   with classic versions, and use the packaged new-client executable, path, and version family
   together.
3. Build process metadata from a coherent per-host software inventory. Core Windows binaries should
   inherit one compatible OS servicing lineage unless a deliberate side-loading or copied-binary
   story is represented in file telemetry.
4. Give the proxy an explicit authentication and ACL state model. A 407 retry that succeeds should
   show the authenticated principal when this log format records identities, and deny/auth outcomes
   should follow policy inputs rather than vary independently per request.
5. Preserve the existing strengths: native event schemas, lifecycle closure, Postfix queue
   semantics, firewall state, protocol-specific Zeek behavior, and static-versus-dynamic web
   response consistency.
