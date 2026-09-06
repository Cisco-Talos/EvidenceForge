# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 87  
**Synthetic-Confidence Score:** 68

## Executive Summary

The endpoint corpus is technically strong: Windows process trees, logon lifecycles, Sysmon
identity, Linux SSH sessions, and eCAR ownership usually remain internally and cross-source
coherent. I nevertheless assess it as synthetic because repeated, source-native Sysmon records are
cloned into zero-to-three-millisecond microbursts across unrelated hosts, accompanied by one
near-instantaneous Windows lock/unlock pair and a conspicuously small repeated firewall-scanner
population.

## Evidence For Synthetic

- **P1 — [distribution_texture] Cloned Sysmon Event 10/13 microbursts:** I found 47 adjacent
  duplicate Event 10 payloads and six adjacent duplicate Event 13 payloads at no more than 3 ms
  separation. The duplicates preserve the same process GUIDs, PIDs, source/target images, access
  mask, call trace, registry object, and details; only event time/record identity advances. This
  occurs across eight Windows hosts for Event 10 and three hosts for Event 13, making it a corpus
  pattern rather than one noisy application.
- **P1 — [distribution_texture] Repeated Outlook first-run writes:** Sysmon records Outlook setting
  `ShownFirstRunOptin=1` repeatedly, including exact doublets/triplets. On
  `WS-AJOHNSON-01`, EventRecordIDs 31092-31094 at `15:20:41.2189408Z` through
  `15:20:41.2209398Z` are a three-record sequence for one ProcessGuid/PID 6716; IDs 31408-31410 at
  `16:49:01.0449852Z` through `16:49:01.0469858Z` repeat the triplet for PID 6220. Equivalent
  adjacent duplicate writes occur on `WS-PPATEL-01` (IDs 739993-739994) and
  `WS-SMARTINEZ-01` (IDs 121358-121359). Reasserting a first-run opt-in can occur, but these
  perfectly spaced, identical multi-record bursts across users are a strong construction tell.
- **P2 — [contract_gap] Implausible lock/unlock lifecycle:** In
  `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, Event 4800 RecordID 131199 locks
  `aisha.johnson`, LogonId `0x263743b`, SessionId 2 at `17:48:17.3933800Z`; Event 4801 RecordID
  131200 unlocks the same session at `17:48:17.3940149Z`, only 0.634 ms later. Other lock intervals
  in the corpus last minutes, so this isolated pair looks like lifecycle jitter collapsing to zero,
  not a human unlock.
- **P2 — [distribution_texture] Narrow external firewall-noise population:** The exposed
  `WEB-EXT-01` syslog contains 841 UFW blocks over almost six hours, but 840 are produced by only
  eight source IPs. Each source has one invariant `(LEN, TTL)` fingerprint for every packet (for
  example, all 151 records from `145.78.103.167` are LEN 52/TTL 118, all 139 from
  `38.186.148.245` are LEN 60/TTL 118, and all 136 from `37.75.195.175` are LEN 48/TTL 110) while
  cycling through a compact 17-port destination pool. Stable fingerprints per scanner are
  plausible, but the low source diversity and sustained reuse create a visible finite-pool texture.
- **P3 — [weak_signal] Round-number process-duration anchors:** Ten otherwise unrelated processes
  end within one second of a 60-second lifetime across multiple Windows and Linux hosts. Separately,
  `MAIL-FIN-01.meridianhcs.local/ecar.json` records WmiPrvSE PID 4040 created at timestamp_ms
  1710768706428 (line 255) and terminated at 1710783106449 (line 869), a 14,400.021-second
  lifetime. These are plausible individually and had little score impact, but the clustering is
  consistent with bounded duration templates.
- **P0:** No P0 hard contradiction or generator identity leak was observed.

## Evidence For Real

- Process lifecycle integrity is strong. Across the eCAR host files I found no process termination
  before its matching creation, no child whose visible parent was created later, and no child
  launched after its matched visible parent had terminated. Pre-window processes correctly remain
  usable without invented in-window creation records.
- Security 4688 and Sysmon Event 1 correlate well. On every Windows host, nearly every Security
  process creation has a same-PID/same-image Sysmon creation, with Sysmon generally preceding the
  Security event by roughly 35-650 ms—a credible difference between telemetry pipelines. eCAR
  process creation times stay within approximately 0.8 seconds of the Windows records.
- Sysmon identity is disciplined. Event 1 ProcessGuids were unique per creation in the sampled
  files; repeated binaries retained stable SHA1/MD5/SHA256/IMPHASH sets within each host; Event 5
  and eCAR termination records reuse the correct process identity.
- Windows process trees are recognizably role- and context-aware: `SearchIndexer.exe` launches
  `SearchProtocolHost.exe`; `services.exe` owns service children; explorer-owned interactive tools
  run under the user session; and administrative chains include realistic intermediate processes
  such as `cmd.exe`, `powershell.exe`, `ssh.exe`, and `conhost.exe`.
- Logon types are varied rather than flattened. The corpus includes service (5), network (3), local
  interactive (2), remote interactive (10), new-credentials (9), and unlock (7) activity where
  appropriate. Matched visible LOGIN/LOGOUT pairs do not run backward, and incomplete pairs at the
  window edges are consistent with a bounded collection slice.
- Linux SSH evidence is particularly convincing. For example, APP-INT-01 records an accepted
  public key for `aisha.johnson` from `10.10.1.35:59260` at `14:29:27.937467Z`, PAM open at
  `14:29:28.051103Z`, and PAM close at `15:01:30.950967Z`; the account's RSA fingerprint remains
  stable on later sessions while ports, PIDs, and durations vary. Failed pre-auth attempts also
  use appropriate `Failed password` and `Connection closed ... [preauth]` forms.
- Linux hosts show role-specific background evidence: Samba/audit traffic dominates FILE-LNX-01,
  Postfix/Dovecot activity appears on mail hosts, desktop services appear on Linux workstations,
  and operational daemons such as irqbalance, snapd, rsyslogd, journald, NetworkManager, cron,
  and systemd-logind provide heterogeneous texture.
- User command behavior is differentiated. Developer-oriented activity includes git, tests,
  containers, kubectl, editors, and build tools; database work includes mysql/psql and storage
  inspection; operational sessions use systemctl, journalctl, authentication logs, and network
  diagnostics. Bash-history timestamps align with corresponding eCAR process records without
  collapsing all users into one command sequence.
- Windows EventRecordIDs include plausible hidden-volume gaps and host-specific ranges. DC-01's
  Security log also shows a semantically coherent reset around Event 1102 rather than unexplained
  arbitrary backward movement.

## Detailed Analysis

### Scope and sampling

I reviewed only files under the supplied data directory. The endpoint view spans approximately
`2024-03-18T12:00Z` to `18:00Z` and includes ten Windows Security/Sysmon pairs, eCAR telemetry for
Windows and Linux hosts, eleven Linux syslogs, and per-user bash-history files. I parsed event-type
counts and sampled process, session, registry, file, module, process-access, SSH, service, and host
firewall records; I then tested process/session ordering and same-host Security/Sysmon/eCAR
correlation.

### Process trees, identity, and source correlation

The process model is one of the corpus's strongest areas. A representative
`WS-AJOHNSON-01` sequence shows eCAR creating `SearchProtocolHost.exe` PID 5192 under
`SearchIndexer.exe` PID 4636 at timestamp_ms 1710763522434. Sysmon Event 1 records the same PID,
image, command line, parent PID/image, SYSTEM identity, LogonId `0x3e7`, and a structured
ProcessGuid at `12:05:22.1911805Z`; Security 4688 follows at `12:05:22.3372169Z` with NewProcessId
`0x1448` and parent `0x121c`. Similar matching held across the Windows hosts, including stable hash
sets for repeated images and no duplicate creation GUIDs.

eCAR actor ownership also survives lifecycle checks. File, registry, module, and process-access
events tied to visible process creates occur within the process lifetime; unresolved actors are
predominantly long-lived pre-window services such as lsass, svchost, Defender, journald, rsyslogd,
and systemd-resolved, which is appropriate for a slice-of-time collection. I found no evidence of a
dependent event occurring after a visible termination for the same actor UUID.

The weakness is not correlation but repeated event construction. In
`DC-01.meridianhcs.local/windows_event_sysmon.xml`, RecordIDs 3289046-3289047 at
`12:40:09.5005864Z`/`12:40:09.5011431Z` duplicate one SearchIndexer-to-SearchProtocolHost
ProcessAccess payload, including access `0x1000` and the entire call trace. RecordIDs
3289060-3289061 similarly duplicate a WmiPrvSE-to-svchost access at
`12:44:58.7381108Z`/`12:44:58.7391016Z`. Normalizing only the source-native `UtcTime` field exposed
47 such Event 10 adjacent duplicates across DC-01, DC-02, FILE-SRV-01, MAIL-FIN-01,
WS-AJOHNSON-01, WS-DRAMIREZ-01, WS-MCHEN-01, and WS-SMARTINEZ-01. Repeated OpenProcess calls are
normal; repeated full records can also occur. The cross-host recurrence, identical call traces, and
near-mechanical spacing are what make this synthetic-looking.

### Windows sessions and host artifacts

Service and network logons dominate servers; client systems show interactive sessions and a small
amount of lock/unlock/new-credentials activity. Visible eCAR session pairs do not invert, and
Windows 4624/4634 identifiers generally align. Built-in service identities consistently use the
expected `0x3e4`/`0x3e5`/`0x3e7` LUIDs rather than fabricated domain sessions.

The concrete lifecycle defect is the 0.634-ms lock/unlock pair on WS-AJOHNSON-01. A user cannot
meaningfully transition from locked to authenticated/unlocked at that interval, and the separate
Execution PIDs on the two records do not supply an alternative explanation. By contrast,
WS-MCHEN-01 has lock intervals of 352 seconds and 2,969 seconds, demonstrating that realistic
durations are otherwise modeled.

Host artifacts are usually owned by sensible processes: explorer writes UserAssist/RecentDocs,
Office applications update MRUs, Defender processes touch DetectionHistory, and process-access
events identify both source and target. The recurring `ShownFirstRunOptin` sequences are the
exception. On WS-AJOHNSON-01, the eCAR mirror at lines 660-662 records three identical registry
modifications at consecutive milliseconds by one Outlook process; lines 998-1000 repeat the same
three-record shape for another Outlook PID. Cross-host doublets show this is not isolated
application noise.

### Linux endpoint evidence

Linux syslog uses credible RFC 5424 structure, facilities/severities, process identities, and
daemon-specific messages. SSH sequences preserve endpoint tuple and account identity and put
acceptance before PAM session open and close. Sudo records include TTY, PWD, target user, command,
and PAM open/close, while eCAR renders the expected sudo-to-root child process relationship.

The bash histories are neither identical nor role-blind. For example, Lina Nguyen's workstation
history includes git/npm/docker/kubectl/editor activity and multiple SSH destinations; database
sessions use mysql, psql, mysqldump, and storage checks; operational sessions use journalctl,
systemctl, and auth-log pivots. Exact command repetition exists but is modest—the most repeated
single command in the collected histories appears only three times.

### Host firewall and environmental texture

WEB-EXT-01's UFW stream is source-native in shape and keeps per-source packet fingerprints stable,
which is realistic in isolation. The distribution is less persuasive: eight sources generate 840
of 841 blocked SYNs over nearly the entire window, repeatedly selecting from ports 22, 23, 25, 80,
110, 135, 139, 143, 443, 445, 465, 587, 2323, 3389, 5985, 8080, and 8443. The first sampled event
is line 1 at `12:00:12.200674Z` and the recurring pool remains active through line 1165 at
`17:55:18.555151Z`. It resembles a bounded scanner catalog more than the source churn normally
seen on an exposed host, though sanitization or a filtered feed could partly explain it.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Score impact |
|---|---|---|---|---|
| P1 | `distribution_texture` | Sysmon Event 10 | 47 adjacent clones across eight hosts | High; repeated source-native payload cloning is the strongest generator-like fingerprint |
| P1 | `distribution_texture` | Sysmon Event 13 / eCAR REGISTRY | Six adjacent clones across three hosts; repeated Outlook first-run behavior | High; identical multi-record shapes recur across unrelated users and endpoints |
| P2 | `contract_gap` | Windows Security 4800/4801 | One session on WS-AJOHNSON-01 | Medium; a 0.634-ms lock interval is behaviorally implausible but isolated |
| P2 | `distribution_texture` | Linux UFW syslog | 840/841 blocks from eight sources | Medium; finite-pool repetition is visible across the full window |
| P3 | `weak_signal` | eCAR process lifecycle | Ten near-60-second lifetimes and one near-exact four-hour lifetime | Low; individually plausible and not sufficient for the verdict |
| P0 | — | — | None observed | No impact |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Windows XML, Sysmon fields, eCAR JSON, RFC 5424 syslog, SIDs,
  GUIDs, hashes, paths, and native message vocabulary are generally convincing.
- **Temporal patterns:** 6/10 — Broad timing is varied and causal, but cloned millisecond
  microbursts and the sub-millisecond lock/unlock pair are conspicuous.
- **Cross-source correlation:** 9/10 — Security 4688, Sysmon 1, and eCAR process identity/timing
  align closely without visible impossible ordering; Linux SSH and process evidence also agree.
- **Behavioral realism:** 7/10 — Role-aware commands, service activity, process trees, and session
  durations are strong, offset by repetitive first-run writes and a few duration anchors.
- **Environmental consistency:** 7/10 — Host roles and daemon/application placement are coherent,
  but external UFW noise has limited source diversity.

## Recommendations

- If this were synthetic, deduplicate canonical process-access and registry-effect intents before
  source rendering. Multiple real calls may still be emitted, but repeated Event 10/13 rows should
  carry source-native variation or defensible distinct operations rather than cloned payloads at a
  fixed millisecond cadence.
- Model Office registry effects as state transitions. `ShownFirstRunOptin` should not be emitted on
  every Outlook launch, and one process should not set the same value two or three times in
  consecutive milliseconds unless a specific retry/notification mechanism owns those writes.
- Enforce a realistic minimum lock duration and keep lock/unlock timing independent of unrelated
  adjacent process creation. Very short intervals should be rare and measured in human-operable
  seconds, not sub-millisecond telemetry jitter.
- Expand the public scanner population and campaign behavior used for host-firewall noise. Preserve
  stable per-source TTL/SYN characteristics, but add source churn, campaign-specific port sets,
  varied activity spans, and a long tail of one-off sources.
- Review round-number process lifetime defaults. Keep service and console-host termination tied to
  actual parent/session/service outcomes, with broader duration distributions when no concrete
  lifecycle event determines the close.
