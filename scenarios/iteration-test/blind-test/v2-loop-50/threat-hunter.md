# Threat Hunter — Authenticity Assessment

## Verdict
**Assessment:** Synthetic  
**Verdict Confidence:** 88  
**Synthetic-Confidence Score:** 74

## Executive Summary
This corpus is unusually strong at reconstructable, multi-source attack chains: endpoint, Zeek, SMB, file, authentication, and shell evidence generally agree on identities, tuples, timing, and lifecycles. I nevertheless assess it as synthetic because a high-value SCP/SSH sequence contains an in-window session-identity contradiction, while repeated endpoint-access bursts and several unexplained public-service responses add generator-like texture that would materially affect a hunter's trust in the evidence.

## Evidence For Synthetic

- **P0 — The staged-file SCP session closes under the wrong systemd-logind session ID** `[hard_contradiction]`. `APP-INT-01.meridianhcs.local/ecar.json:751-754` records the inbound SSH transport, `sshd` PID `1937270`, a successful root login with `session_id=378971`, and creation of `/tmp/.cache/rpt_0318.sql.gz`. The same PID closes the root session in `APP-INT-01.meridianhcs.local/syslog.log:240`, but the immediately adjacent logind record at line 241 removes session `376079`, not `378971`. No corresponding Accepted/PAM-open/New-session sequence for tuple `10.10.4.10:46790` and session `378971` appears in that host's syslog during the in-window activity. This is not a boundary truncation: the transport, login, file creation, process termination, session close, and removal are all present.
- **P1 — Endpoint process-access telemetry forms mechanically repeated millisecond bursts** `[distribution_texture]`. At `DC-02.meridianhcs.local/ecar.json:4564-4570`, `MsMpEng.exe` PID `5280` emits seven `PROCESS/OPEN` records in roughly four milliseconds, including three identical `0x1010` opens of the same `svchost.exe` target and repeated `0x1410` LSASS opens. Similar exact duplicate groups recur on other Windows hosts; for example, `WS-AJOHNSON-01.meridianhcs.local/ecar.json:660-662` repeats the same Outlook registry modification three times at one-millisecond spacing. Such bursts are possible, but their exact repetition and compression create a conspicuous simulation signature and distort process-access baselining.
- **P2 — The public web host appears to answer unmodeled UDP services without supporting protocol evidence** `[environment_or_collection_plausibility]`. `zeek-dmz/conn.json:628`, `:858`, and `:1161` show successful bidirectional UDP `SF` sessions from external addresses to `10.10.3.10:53`; `zeek-dmz/conn.json:4024` similarly shows a successful response from UDP/3478. These UIDs have no companion records in `zeek-dmz/dns.json`, the connection rows do not identify a service, and the surrounding host evidence otherwise presents `10.10.3.10` as a public web endpoint. A hidden DNS/STUN role is possible, so this is not a contradiction, but the unexplained responses weaken environment plausibility.
- **P2 — Credential-dumping behavior is over-projected into a questionable remote-thread event** `[weak_signal]`. `WS-AJOHNSON-01.meridianhcs.local/ecar.json:738-750` coherently shows a renamed executable running `privilege::debug` and `sekurlsa::logonpasswords`, loading modules, opening `winlogon.exe` and LSASS, and terminating. Line 749 additionally claims `THREAD/REMOTE_CREATE` into LSASS. That action is not inherent to the shown credential-reading command and looks like a generic injection artifact attached to an otherwise credible dump sequence; it would create an unrealistically strong extra detection signal unless the binary actually used injection.
- **P3 — Linux interactive history reuses exact command templates across unrelated users and hosts** `[distribution_texture]`. Exact examples include `last -20` in `FILE-LNX-01.../bash_history/aisha.johnson.bash_history:2`, `LOG-MON-01.../bash_history/marcus.chen.bash_history:16`, and `DB-PROD-01.../bash_history/aisha.johnson.bash_history:12`; `systemd-analyze blame | head` also appears on multiple unrelated hosts. Shared operational habits can explain some reuse, but the aggregate lexical repetition makes the background feel pool-generated rather than organically authored.

## Evidence For Real

- The primary data-staging and transfer chain is highly huntable. `DB-PROD-01.meridianhcs.local/ecar.json:580-604` shows gzip creation, archive creation, `scp`, the outbound flow, file read, and process termination. `zeek-core/conn.json:10245` and `zeek-db/conn.json:421` independently observe the same `10.10.4.10:46790 -> 10.10.2.30:22` flow with nearly identical duration and byte counts, while `APP-INT-01.../ecar.json:751-754` observes the inbound flow and target file creation.
- The subsequent SMB pivot is unusually coherent. `APP-INT-01.../ecar.json:755-756` shows the newly arrived archive being read as a connection opens to `10.10.2.21:445`; `zeek-core/smb_mapping.json:198` maps the session to `\\FILE-LNX-01\ClinicalResearch`; `zeek-core/smb_files.json:328-329` records the write to `Integration\DB-Staging\rpt_0318.sql.gz`; and `FILE-LNX-01.meridianhcs.local/ecar.json:1286-1291` supplies the server-side `smbd` process, inbound flow, login, POSIX file write, process termination, and logout.
- Long-lived SSH evidence demonstrates realistic sensor perspective. The workstation-to-database flow appears in `WS-AJOHNSON-01.../ecar.json:653-664`, `zeek-core/conn.json:6510`, and `zeek-db/conn.json:243`. The two Zeek sensors agree on tuple and duration, but the core sensor reports `1488` missed bytes and correspondingly fewer response bytes than the database-side sensor. The endpoint process terminates at `WS-AJOHNSON-01.../ecar.json:801`, within a fraction of a second of the network close.
- Protocol child records are temporally and referentially disciplined. Sampled DNS, HTTP, TLS, SMB, and SMTP rows resolve to an existing Zeek connection UID and remain inside the corresponding connection interval across the core, DMZ, and database sensors. This supports practical pivots from alerts to flow and application evidence.
- The public-facing web activity has credible progression and enough volume to support hunting. `WEB-EXT-01.meridianhcs.local/web_access.log:52-415` contains a sustained, varied Nikto-style enumeration sequence; lines 433-434 transition to SQL-injection probes and line 448 records an upload attempt. The activity is buried among ordinary requests rather than presented as an isolated showcase event.
- Baseline roles are differentiated rather than globally uniform: domain controllers carry dense Windows authentication telemetry, the Linux file server carries substantial `smbd` and audit evidence, the public web host carries web and firewall activity, and the mail systems show mail-service behavior. This makes host-level triage and peer-group comparison useful.

## Detailed Analysis

### Corpus orientation and hunting surface

The sampled corpus spans approximately six hours, from 12:00 through 18:00 UTC, across Windows workstations and servers, Linux infrastructure, three Zeek viewpoints, a perimeter firewall, IDS alerts, proxy records, web access, shell histories, Windows Security/Sysmon, and endpoint eCAR telemetry. The volume is credible for a compact enterprise exercise: Zeek connection logs contain roughly 19,000 observations across the core and DMZ views, and endpoint data contains thousands of process, flow, file, registry, and session records. High-signal events are therefore embedded in substantial routine activity.

### Reconstructable suspicious activity

A hunter can reconstruct a coherent sequence beginning with activity on `WS-AJOHNSON-01`, continuing through DB access, archive staging, SCP to `APP-INT-01`, and SMB movement to `FILE-LNX-01`. The evidence preserves source ports, destination services, users, process identifiers, filenames, Zeek UIDs, shares, and timing well enough to move between host and network views without relying on a privileged narrative.

The credential-dump segment is also directly detectable. The renamed executable and command line at `WS-AJOHNSON-01.../ecar.json:738`, LSASS access at line 748, and short process lifetime through line 750 provide several independent hunt anchors. The main realism reservation is not missing evidence but excessive certainty: the extra remote-thread event looks more like a synthetic detection aid than a necessary consequence of the command shown.

### Lifecycle and identity integrity

Most sampled process and network lifecycles are sound. Process-dependent records generally occur after creation, termination follows use, and network child records stay inside their parent flow interval. The SCP arrival on `APP-INT-01` is the material exception: the exact `sshd` PID is carried into syslog close evidence, yet the authoritative-looking session number changes from `378971` to `376079`. Because the mismatch lands directly in the central exfiltration chain, it has outsized impact on confidence and would break a session-ID-based investigation or validation rule.

The defect is especially visible because normal SSH sessions on the same host do correlate correctly. For example, the session around `APP-INT-01.meridianhcs.local/syslog.log:126-151` creates and later removes session `377082`. The mixture of correct routine sessions and a broken high-value transfer session suggests a lifecycle integration gap rather than ordinary collection loss.

### Baseline, noise, and distribution texture

The baseline has good breadth and source-role differentiation. Network scans, web enumeration, normal interactive activity, service traffic, authentication noise, and administrative commands all create plausible competing leads. However, exact eCAR duplicates compressed into one-to-four-millisecond windows would be visible in basic frequency analyses and could train hunters to discount process-access or registry evidence for the wrong reason. Linux history has a milder version of the same issue: the commands are individually credible, but cross-user repetition exposes the finite template pool.

### Environment and collection plausibility

Multiple Zeek viewpoints behave convincingly: timestamps differ slightly, UIDs are sensor-local, and missed bytes can alter one sensor's byte accounting while preserving the underlying flow. The unexplained UDP replies from the public web address are the principal topology concern. They may represent deliberately undisclosed services or unusual scanner exchanges, but the lack of protocol companions or host-side service support prevents a hunter from resolving the ambiguity from the corpus itself.

## Synthetic Indicator Summary

| Priority | Category | Affected source(s) | Scope | Investigative impact |
|---|---|---|---|---|
| P0 | Hard contradiction | APP-INT eCAR and syslog | One high-value SCP/SSH lifecycle, with similar missing-open patterns observed in additional transfer sessions | Breaks exact session correlation in the central staging chain and strongly drives the Synthetic verdict |
| P1 | Distribution texture | Windows eCAR | Repeated process-open and registry bursts across multiple hosts | Pollutes baselines and makes telemetry cadence look generated |
| P2 | Environment/collection plausibility | Zeek DMZ | Several successful external UDP exchanges to ports 53 and 3478 on the public web IP | Implies unexplained exposed services and creates unresolved attack-surface ambiguity |
| P2 | Weak signal / behavior semantics | WS-AJOHNSON eCAR | One credential-dump sequence | Adds an unusually convenient remote-thread signal not clearly supported by the command behavior |
| P3 | Distribution texture | Linux bash histories | Exact commands repeated across unrelated users and hosts | Low-severity lexical pool signature; limited direct effect on reconstruction |

## Realism Score by Category
- **Field/format fidelity:** 8/10 — Source-native structure is generally strong, with plausible Windows XML, Zeek JSON, RFC-style syslog, firewall, proxy, web, and eCAR fields.
- **Temporal coherence:** 6/10 — Most process and connection timing is excellent, but the SCP SSH lifecycle has an in-window close/removal identity defect and some endpoint bursts are implausibly compressed.
- **Cross-source correlation:** 7/10 — Network tuples, files, shares, processes, and users correlate impressively across sensors; the key SSH/logind mismatch prevents a higher score.
- **Behavioral realism:** 8/10 — The attack and benign activities are operationally recognizable and huntable, though credential dumping is slightly over-signaled.
- **Environmental realism:** 7/10 — Host roles and ordinary traffic are differentiated, but unexplained UDP services and reusable shell-command texture weaken the enterprise model.

## Recommendations

- Preserve one canonical SSH session identifier from authentication through eCAR login/logout, PAM close, and systemd-logind removal. Add an automated invariant that an in-window successful SSH login with a visible close must remove the exact same session ID; do not substitute a generic sidecar session during transfer finalization.
- Generate process-access bursts from operation-specific call sequences with realistic inter-event timing and deduplicate identical target/access/call-trace tuples inside a narrow window. Apply the same safeguard to repeated registry modifications.
- Either model DNS/STUN service ownership for `10.10.3.10` with matching host and protocol evidence, or render unsuccessful/ambiguous UDP scan outcomes instead of bidirectional `SF` responses with substantial payloads.
- Emit LSASS remote-thread creation only when the selected credential-access implementation actually injects. A read-oriented `sekurlsa::logonpasswords` path should normally rely on process access and module/call-trace evidence unless injection is explicitly represented.
- Expand shell-history vocabularies by host role and persona, and parameterize equivalent investigative commands so unrelated users do not repeatedly issue byte-identical templates.
