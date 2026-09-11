# Threat Hunter — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Verdict Confidence:** 70
**Synthetic-Confidence Score:** 66
## Executive Summary
The reviewed telemetry is more likely synthetic than real, but it is a close and notably
high-quality case. The collection has strong field-level validity, realistic role-dependent
volume, useful background noise, coherent endpoint lifecycles, and unusually good multi-source
pivotability. Those strengths are not treated as evidence of synthesis. The assessment turns
instead on a small number of log-visible defects that recur in otherwise independent activity:
commands inspect or hash exact artifacts before their observed creation, SMB file naming has a
low-entropy combinatorial texture with an implausibly broad set of future operational years, two
novel Windows service executables appear and execute without any observed delivery despite active
file telemetry, and one fully visible SSH transfer has close-only syslog lifecycle evidence on the
receiver.

No unambiguous source-schema impossibility or globally broken lifecycle was found. In particular,
all parsed JSON records were valid, the Windows XML parsed successfully, process and session
ordering was internally coherent, and Zeek protocol records stayed inside their referenced
connection lifetimes. Plausible real-world explanations exist for each principal anomaly in
isolation—failed shell probes, stale files, pre-positioned binaries, selective collection, or
unusual document naming. Their recurrence and distribution are what move the combined result into
the lower portion of “likely synthetic,” rather than “inconclusive” or “confidently synthetic.”

## Evidence For Synthetic
- **`contract_gap` — repeated artifact-before-creation command order.** In
  `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history`, root runs
  `du -h /tmp/rpt_0318.sql` at epoch 1710782083, eleven seconds before the `mysqldump` command at
  1710782094. More importantly, root hashes `/tmp/rpt_0318.sql.gz` at 1710782100 and runs `du` on
  it at 1710782111, before `gzip -9 /tmp/rpt_0318.sql` at 1710782112. Endpoint records independently
  place the gzip process at 1710782112.935 and the `.gz` `FILE CREATE` at 1710782116.883, followed
  by a successful SCP read. Shell history records attempted commands rather than their exit status,
  so this is not an absolute impossibility; however, the sequence reads like post-creation
  validation steps inserted ahead of their prerequisite.

- **`distribution_texture` — the same sequencing motif appears in unrelated benign activity.**
  `WS-LNGUYEN-01.meridianhcs.local/bash_history/lina.nguyen.bash_history` runs `file` and `du` on
  `/tmp/mhs-support-48217.tar.gz` at 1710775920 and 1710775931, then creates that exact ticket-bound
  archive with `tar` at 1710779241. Endpoint telemetry records the archive `FILE CREATE` at
  1710779246.213 and its later curl read. A stale archive and a later overwrite are possible, but
  the recurrence of “inspect the exact future artifact, then create it” in a separate user workflow
  strengthens the synthetic-sequencing interpretation.

- **`environment_or_collection_plausibility` — future-year operational paths are too broadly
  distributed for the visible date.** The logs are dated 2024-03-18, yet 33 of 112 Zeek SMB file-open
  rows contain 2025, 2026, or 2027 in the path. The set includes ordinary planning documents, where
  future years are credible, but also active operational paths such as
  `\\DC-01\NETLOGON\Preferences\2026\policy.ps1`,
  `\\DC-02\NETLOGON\User\2027\startup-final.ps1`, and
  `\\DC-02\SYSVOL\Policies\2027\groups-v2.pol`. The mix across future years and operational
  locations looks more like randomized vocabulary assignment than an environment anchored to March
  2024.

- **`distribution_texture` — SMB filenames show repeated combinatorial construction.** Across 112
  SMB opens (98 unique names), suffixes such as `draft`, `review`, `final`, `approved`, and `v2`
  recur heavily across unrelated SYSVOL, NETLOGON, team, vendor, and document paths. Examples include
  `Work\draft-draft.txt`, `startup-final.xml`, `vendor-review-final.docx`,
  `team-roadmap-final.txt`, and `groups-v2.pol`. Any one name is plausible; the aggregate has lower
  lexical entropy and more systematic adjective/suffix reuse than expected from independently
  authored operational files.

- **`contract_gap` — novel service executables lack a visible delivery path.** DC-01 records service
  creation and execution of `C:\Windows\System32\DeviceSyncSvc.exe`; DC-02 does the same for
  `C:\Windows\System32\DirectoryCacheSvc.exe`. Neither host's endpoint records show a file-create
  event for the corresponding executable, although DC-01 captures a `PSEXESVC.exe` file creation
  shortly before its service installation. The binaries could have existed before the six-hour
  window, so this is not a hard contradiction, but two newly introduced, narratively important
  services without staging evidence form a meaningful gap in otherwise active file telemetry.

- **`contract_gap` — one receiver-side SSH lifecycle is source-locally asymmetric.** APP-INT-01
  endpoint records show the inbound TCP/22 flow from `10.10.4.10:45291`, successful root SSH login,
  `/tmp/.cache/rpt_0318.sql.gz` creation, and logout. APP-INT-01 syslog contains the matching
  `pam_unix(sshd:session): session closed for user root` and removal of session 378785 at 17:16:06,
  but no connection, accepted-authentication, or session-open lines for that same in-window session.
  Selective syslog loss is possible, but a close-only lifecycle for a transfer whose start is
  independently visible is a collection-coherence weakness.

- **`weak_signal` — some attack process semantics are over-composed.** On WS-AJOHNSON-01, the
  credential-access executable uses Mimikatz-style arguments (`privilege::debug` and
  `sekurlsa::logonpasswords`), opens both winlogon and LSASS, and then records a remote thread in
  LSASS with `StartFunction=LsaICLookupNamesWithCreds`. A bespoke tool could combine memory access
  and injection, so this is not contradictory, but the record combines several high-signal
  primitives more densely than ordinary Mimikatz credential dumping requires.

- **`schema_or_format` / `hard_contradiction` — none established.** No malformed JSON, unparseable
  XML, invalid Zeek UID reference, protocol event outside its connection lifetime, terminate-before-
  create process, dependent event outside a process lifetime, or logout-before-login session was
  found. The lack of a hard contradiction is reflected in the moderate confidence rather than being
  counted against authenticity.

## Evidence For Real
- **Role-shaped volume and background behavior are credible.** Domain controllers carry the highest
  authentication, Kerberos, LDAP, and endpoint-flow volume; proxy and web systems are flow-heavy;
  workstations have lower process and authentication volume; and Linux systems contain normal SSH,
  package-management, systemd, journald, logrotate, and administrative noise. The six-hour window is
  busy without making every host equally active.

- **Endpoint lifecycle coherence is strong.** Across the eCAR records, no process termination
  preceded its matching creation, no dependent process event fell before creation or after
  termination, and no session logout preceded login. Creation/termination and login/logout
  imbalances are explainable at the bounded window edges or by session type rather than forming a
  global contradiction.

- **Network protocol contracts are internally sound.** For `zeek-core`, `zeek-dmz`, and `zeek-db`,
  DNS, HTTP, SSL, SMB mapping, and SMB file records with UIDs all resolved to a connection on the
  same sensor. None occurred materially before connection open or more than two seconds after its
  recorded close. The protocol mix—DNS, Kerberos, LDAP, SMB, HTTP(S), SSH, MySQL, DHCP, and syslog—
  fits the visible infrastructure.

- **Host-to-sensor timing resembles independent clocks and collectors.** Thousands of endpoint flows
  match Zeek tuples with small, host-dependent offsets rather than one exact global timestamp. For
  example, DC-01 matches cluster around a small positive offset, while several workstations cluster
  below the sensor time. That stable skew plus event-level jitter is credible for separately timed
  endpoint and network sources.

- **The DC-01 remote-service sequence is operationally pivotable.** A successful Aisha Johnson
  network logon from `10.10.1.35` precedes inbound SMB and RPC, creation of
  `C:\Windows\PSEXESVC.exe`, service installation, execution, and child `cmd /c whoami && hostname`.
  Windows Security, Sysmon, endpoint, and network views agree on actor, host, path, transport, and
  ordering.

- **The DB-to-APP-to-file-server transfer is strongly correlated.** DB-PROD-01 records a root SSH
  session, `mysqldump`, gzip, and SCP. Zeek sees the `10.10.4.10` to `10.10.2.30:22` transfer with
  approximately 1.6 MB of client data; APP-INT-01 records receipt of the same named archive; then
  APP-INT-01 uses `smbclient` to write it to FILE-LNX-01, where Zeek SMB/file records and receiver
  endpoint evidence agree on the path and 1,600,522-byte payload. This provides excellent practical
  pivots across process, session, tuple, filename, hash, and byte-count fields.

- **The proxy-mediated upload has realistic multi-leg accounting.** WS-AJOHNSON-01 reads and uploads
  `cache_7f3a.zip` with curl through `10.10.3.20:8080`. Endpoint, core Zeek, DMZ Zeek, proxy, and ASA
  records represent the client-to-proxy and proxy-to-origin legs with consistent direction,
  duration, and roughly 18.8 MB transferred. The distinction between logical request and network
  legs is preserved.

- **Periodic traffic is not mechanically uniform.** DeviceSyncSvc check-ins to
  `api.westbridge-services.net` recur on an approximately ten-minute cadence but with substantial
  jitter, varying response sizes, TLS resumption differences, and an extra manifest transaction.
  The APP-INT-01 TXT-query burst likewise has varied inter-arrival times, labels, answers, and TTLs
  rather than a fixed metronome.

- **Windows log clearing uses convincing native behavior.** DC-01 shows the command and process for
  `wevtutil`, then Security event 1102, followed by reset event-record numbering. That is a concrete
  source-native consequence rather than merely a high-level attack annotation.

## Detailed Analysis
**Scope and parse coverage.** Analysis was limited to the supplied review-data directory. It contains
endpoint JSON for 21 hosts, Windows Security and Sysmon XML for 10 hosts, syslog for 11 hosts, 26
per-user shell histories, three Zeek sensor views, and firewall, proxy, web, and IDS sources. The
records cover approximately 12:00–18:00 UTC on 2024-03-18. JSON records parsed cleanly and all Windows
XML files were structurally parseable. Record counts and event distributions were inspected by host
and source; process/session lifecycle keys, network tuples, Zeek UIDs, protocol timing, filenames,
users, and selected byte counts were cross-referenced.

**Operational lifecycle coherence.** The collection is strongest where a real action should produce
multiple phases. The PsExec-like sequence includes remote authentication, SMB/RPC transport, binary
creation, service creation, service process, child command, and termination. SSH sessions generally
show transport before authentication, shell readiness before commands, and closure after file
transfer. RDP/remote-admin and ordinary process trees preserve parent-before-child ordering. The
principal lifecycle weaknesses are narrow: absent service-binary delivery and the receiver-side
close-only SSH syslog record. They do not imply a globally broken event model.

**Signal-to-noise and environmental behavior.** Background traffic substantially outweighs the
explicitly suspicious operations and differs by role. The DCs are dominated by Kerberos ticketing,
domain logons, LDAP, and DNS; the proxy and externally facing web host are network-heavy; database
traffic is concentrated around MySQL; and user systems show browser, update, development, support,
and administrative behavior. Failed connections, proxy authentication failures, stale-account-like
events, routine SSH, and ordinary file access provide hunting noise. This is materially more
realistic than a sparse attack-only dataset. The main environmental concern is not source thinness
but vocabulary: future-year SYSVOL/NETLOGON paths and formulaic SMB filenames occur at a frequency
that is difficult to reconcile with the visible date and otherwise coherent organization.

**Tradecraft realism and huntability.** Credential access, remote service execution, domain-account
creation and group membership change, service/task persistence, C2-like proxy check-ins, TXT-query
bursts, staged SMB collection, database access, and proxy exfiltration all offer workable pivots.
Actors, sessions, source addresses, PIDs, paths, ports, and timestamps usually survive those pivots.
The attack does not depend on a pristine linear story: routine traffic overlaps it, and the
assessment does not penalize the broad source coverage. The questionable point is that a few
command histories and artifact records appear arranged around intended storyline products rather
than around the order in which a shell can create and inspect those products.

**Assessment calibration.** The visible anomalies are more consistent with synthetic generation
defects than with one isolated human mistake, but none is independently conclusive. A real host can
probe a missing file, reuse a ticket archive name, retain pre-positioned service binaries, lose
selected syslog messages, and contain forward-looking filenames. Conversely, the recurrence of the
same artifact-order motif and the patterned future-year file vocabulary across unrelated activity
are difficult to dismiss together. The evidence therefore supports “Synthetic” at moderate
confidence and a Synthetic-Confidence Score of 66—likely synthetic, not confidently synthetic.

## Synthetic Indicator Summary
| Category | Log-visible indicator | Weight | Limitation |
|---|---|---:|---|
| `contract_gap` | DB root hashes/stats `.gz` before gzip and observed file creation | High | Commands may have failed; shell history lacks exit status |
| `distribution_texture` | Separate support workflow inspects exact ticket archive well before creating it | Medium | A stale archive and later overwrite are possible |
| `environment_or_collection_plausibility` | 33/112 SMB opens contain 2025–2027 paths in March 2024, including SYSVOL/NETLOGON | High | Some future planning documents are legitimate |
| `distribution_texture` | Repeated `draft`/`review`/`final`/`approved`/`v2` filename combinations across unrelated paths | Medium | Individual filenames are plausible |
| `contract_gap` | Two novel service binaries execute without an observed file-create/delivery event | Medium | Binaries may predate the review window |
| `contract_gap` | APP root SSH transfer has syslog close/removal but no matching open/auth lines | Low–medium | Selective source loss can occur in production |
| `weak_signal` | Mimikatz-style dump arguments combined with LSASS remote-thread telemetry | Low | A bespoke combined tool is feasible |
| `schema_or_format` | No material indicator found | None | Formats and references were internally valid |
| `hard_contradiction` | No unqualified hard contradiction found | None | Key causal anomaly still permits failed-command/stale-file explanations |

## Realism Score by Category
- **Field format accuracy — 9/10.** JSON and XML parse cleanly; Windows event fields, RFC 5424-style
  syslog, Zeek UIDs and protocol records, proxy/ASA fields, hashes, paths, logon IDs, and PIDs are
  source-appropriate. No decisive schema or format defect was found.

- **Temporal patterns — 7/10.** Host-dependent clock offsets, jittered periodic traffic, bursty user
  activity, and lifecycle ordering are strong. Repeated inspection of exact artifacts before their
  observed creation is the principal deduction.

- **Cross-source correlation — 9/10.** SMB, SSH/SCP, PsExec-like service execution, proxy tunneling,
  firewall legs, and file hashes/byte counts pivot exceptionally well. Protocol records remain
  inside connection lifetimes. The APP SSH syslog gap prevents a perfect score.

- **Behavioral realism — 8/10.** Tradecraft and benign operations are operationally credible, and
  suspicious activity is embedded in substantial role-appropriate noise. Missing staging for two
  service binaries and the over-composed credential-access event slightly weaken it.

- **Environmental consistency — 6/10.** Host roles, network placement, service use, and volume are
  coherent. The large share of future-year SMB paths—especially future SYSVOL/NETLOGON policy
  paths—and formulaic naming texture are difficult to reconcile with the March 2024 environment.

## Recommendations
- Preserve artifact causality in shell histories and endpoint telemetry: create or compress a file
  before successful `du`, `file`, or hash validation, and represent failed preflight commands only
  when their failure is intentional and visible.
- Anchor operational filename years to the event date and business context. Reserve future-year
  names for clearly forward-looking planning artifacts, not routine SYSVOL/NETLOGON policy paths.
- Increase lexical diversity in routine SMB paths and avoid repeatedly composing names from a small
  suffix set such as `draft`, `review`, `final`, `approved`, and `v2`.
- For newly installed services, include a plausible binary provenance path—download, SMB copy,
  administrative-share write, package deployment, or explicit evidence that the executable was
  already present before the window.
- Keep source-local SSH lifecycle collection coherent. If receiver syslog observes session close,
  retain the corresponding connection/authentication/session-open records when the session began
  inside the same capture window, or make the source gap broader and operationally explainable.
- Retain the current strengths: role-shaped noise, independent clock texture, source-native Windows
  consequences, multi-leg proxy/firewall accounting, stable identifiers, and cross-source file and
  byte-count pivots.
