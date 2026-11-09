# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 40

## Executive Summary

The collection supports technically useful hunting across endpoint, authentication, network, file-server, and proxy evidence. I found a modest repeated timing/command texture in the two Mac shell histories, but the inspected intrusion pivots and process lifecycles hold together; that limited texture does not establish synthetic origin. The score reflects mostly realistic telemetry with an explainable behavioral artifact, rather than a demonstrated hard contradiction.

## Evidence For Synthetic

- [distribution_texture] The two Mac histories share several command-spacing patterns despite different commands and wall-clock start times. In `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history`, lines 1–3 have epochs `1793624867`, `1793624888`, `1793624936`: gaps of 21 and 48 seconds. In the corresponding MAC-MROSS-02 history, lines 1–3 have epochs `1793625110`, `1793625131`, `1793625179`: the same two gaps. Their later groups also share a 30-second spacing (MAC-01 lines 4–5, MAC-02 lines 4–5), a 37-second spacing (MAC-01 lines 8–9, MAC-02 lines 6–7), and a 44-second spacing (MAC-01 lines 12–13, MAC-02 lines 9–10). This is a concrete recurring timing texture, although a shared operator/checklist remains a reasonable explanation.
- [weak_signal] Both histories repeatedly return to a narrow set of host-information and Documents-directory probes: `id`, `sw_vers -productVersion`, `uname -a`, `df -h`, `ps aux`, and the identical `find ... -name '*.pdf'` invocation. MAC-01 lines 10 and 19 and MAC-02 lines 7 and 19 repeat that find command. This strengthens the timing observation slightly; the hosts share one named user, so I do not treat their vocabulary overlap as an independent strong indicator.

## Evidence For Real

- The initial suspicious web-host activity has a feasible endpoint/network pivot. `WEB-EXT-01.meridianhcs.local/ecar.json:811` records a `www-data` bash process at 14:20:06.215 UTC under Apache; line 812 associates it with `10.10.3.10:54918 -> 45.33.32.30:8443`. `zeek-dmz/conn.json:1743` records that exact tuple at epoch `1793629209.625084`, with an established, bidirectional 1.305672-second flow. The endpoint process terminates later at line 814, 14:20:21.163 UTC. These observations do not require a process to use the network before it exists.
- The database staging chain preserves process, file, transport, receiver, and subsequent SMB identities. It is possible to follow the same archive from database creation through SCP receipt and onward to the Linux share; details follow below.
- Authentication contains operational distinctions rather than treating every session alike. `WS-PPATEL-01.meridianhcs.local/ecar.json:581` describes a Type 9 local session for `priya.patel`, distinct outbound identity `priya.patel-admin`, and `cloned_from_logon_id=0xd8b39ef`. This agrees with the visible `/netonly` command at line 576. Its new session closes at line 597. Unlock Type 7 records on WS-MCHEN reuse an existing session, which is appropriate and should not be mistaken for newly created session identities.
- Network outcomes include established sessions, refused connections, timeouts, resets, and incomplete captures. For example, `zeek-db/conn.json` has 386 SF, 36 RSTO, 18 RSTR, 8 S3, 6 S0, 5 S2, 4 OTH, and 1 REJ observations. Routine administration, service processes, cron work, failures, and noisy scanning coexist with suspicious activity.
- A full scan of supplied eCAR records for actor UUIDs with visible PROCESS CREATE/TERMINATE counterparts found no actor usage before its observed creation or after its observed termination. This is bounded to those UUID relationships, not a claim that every lifecycle is complete.

## Detailed Analysis

### Scope and hunting conditions

The endpoint directories describe 23 hosts across Windows, Linux, and macOS, with activity approximately 13:00–19:00 UTC on November 2, 2026. Addresses indicate workstation, internal-service, DMZ, and database segments under `10.10.1/2/3/4`. Collection includes Security/Sysmon XML, eCAR, Linux syslog and shell histories, two Mac Endpoint Security streams and Unified Log exports, three Zeek sensor views, Cisco ASA, Snort, web access, and proxy access.

There are 35,814 eCAR records and 22,030 Zeek connection observations: 12,279 core, 9,287 DMZ, and 464 database-sensor records. These are observations, not necessarily distinct network connections, because sensors overlap. Windows Security contains 18,978 records, dominated by 12,351 filtering-platform permits, 2,094 service-ticket events, and 792 TGT events. I did not equate XML line count with event count. The volume and mix provide a substantial baseline for these 23 endpoints in a six-hour collection; there is no clear volume-based contradiction.

### Initial foothold and authentication boundaries

The Apache-parented shell at WEB-EXT-01 is suspicious on behavior and parentage, and its network connection is directly traceable. Its short connection does not prove a sustained interactive shell or subsequent privilege escalation. Later root sessions have their own successful SSH authentication observations; I did not assume that every root command is a child or effect of the initial `www-data` execution.

For example, `WEB-EXT-01.meridianhcs.local/syslog.log:270` records accepted public-key authentication for root from `10.10.1.42:50632` at 14:40:01.330169 UTC. The eCAR sequence at lines 903–905 has the SSH worker, session login, then root shell. A different session at 15:00 from `10.10.1.34:49446` appears at syslog line 317. These may be additional suspicious access or administration; their account boundaries and tuples should be retained instead of narratively merging them into one reverse-shell session.

### Database extraction and file staging

`DB-PROD-01.meridianhcs.local/ecar.json:493` records root SSH login from `10.10.2.30:46416` at 18:15:11.496 UTC. A shell follows at line 494, then `mysqldump --single-transaction ehr patients insurance_claims` at line 495. The dump-file create at line 496 is attributed to that live process. The process closes at line 497; `gzip -9 /tmp/rpt_0318.sql` starts at line 499 and creates `/tmp/rpt_0318.sql.gz` at line 500 before its termination at line 501.

The SCP client at line 502 starts at 18:15:57.555 UTC. Its eCAR FLOW at line 504 uses `10.10.4.10:53008 -> 10.10.2.30:22`. `zeek-db/conn.json:384` and `zeek-core/conn.json:11001` both observe this tuple, with distinct sensor UIDs and slightly different opening timestamps. Their 19.178-second durations and matching byte totals are compatible with two sensors observing one connection.

At the receiver, `APP-INT-01.meridianhcs.local/syslog.log:220` records accepted root public-key authentication from `10.10.4.10:53008` at 18:16:06.908871 UTC. eCAR line 756 records session login at 18:16:08.384, and line 761 attributes the received archive creation to the receiver process at 18:16:20.287. The client terminates at DB line 507 at 18:16:20.517. Receiver process termination follows at APP line 762, with session logout at line 764. The small cross-source offsets do not create an impossible transfer ordering.

The later `smbclient` invocation at APP eCAR line 774 uses local root and supplied directory credentials `svc_mhsync`; those are different identity domains and need not be the same account. Lines 775–776 tie its connection and archive read to a live process. The network tuple `10.10.2.30:36663 -> 10.10.2.21:445` appears in `zeek-core/conn.json:11117`, UID `C7tqoP3BAvirMFCyIA`. The mapping at `smb_mapping.json:109` selects `ClinicalResearch`; `smb_files.json:188` records a write of 10,464 bytes to `Integration\\DB-Staging\\rpt_0318.sql.gz`; `files.json:613` carries the same UID and total size. `FILE-LNX-01.meridianhcs.local/syslog.log:535–537` records successful open/write/close by `svc_mhsync` from `10.10.2.30`. Its eCAR line 1446 gives the corresponding local file path and directory-account attribution.

This is useful cross-source evidence, not proof of real origin. I also do not compare encrypted SSH payload totals directly with SMB file size: SSH negotiation, encryption and protocol traffic prevent such an equality requirement.

### Behavioral texture and limitations

The recurring Mac command-gap pattern is the clearest authenticity concern I could reproduce. Its significance is limited by the shared user and possibility of repeatable administration. I did not establish that those histories must represent unscripted human work.

Native Mac streams were treated as separate source types, not as interchangeable Unified Log/ES records or authorization decisions. Their low Unified Log count alone is neutral under an unspecified collection filter. I found no demonstrated Mac permission denial followed by an impossible effect, and I make no source-schema allegation based only on unfamiliar fields.

I checked Windows native records and normalized endpoint examples, but did not exhaustively validate every native field. Source selection, high coverage, an easy-to-follow suspicious sequence, and absent out-of-window closures did not contribute to the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS zsh history | Two hosts sharing one user; multiple repeated within-group gaps | Modest concern: repeated 21/48, 30, 37, and 44-second spacing across shifted command groups |
| weak_signal | macOS zsh history | Repeated small diagnostic command vocabulary | Small supporting weight; same operator is a plausible real-world explanation, so not counted as an independent strong defect |

No hard contradiction, generator identity leak, or demonstrated impossible cross-source lifecycle was established in the examined relationships.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native and normalized records were usable; no substantiated format contradiction was identified.
- **Temporal patterns:** 8 — Operational ordering is coherent; repeated Mac command-gap patterns reduce naturalness somewhat.
- **Cross-source correlation:** 9 — Web, SSH/SCP, SMB, and authentication pivots preserve the relevant tuples and identities.
- **Behavioral realism:** 8 — Commands and account boundaries are workable; the repeated Mac diagnostic vocabulary is a modest limitation.
- **Environmental consistency:** 9 — The observed source volumes and segmented endpoint/service relationships are broadly plausible for the visible collection.

## Recommendations

- If this were synthetic, vary the repeated Mac diagnostic-group timing and command selection unless a repeatable operator checklist is explicitly intended. Preserve real dependencies and process lifetimes while avoiding reuse of the same small sequence of second offsets across hosts.
- If the repeated probes represent an actual scripted/checklist workflow, retain source-visible evidence of that workflow where the collection genuinely captures it. Do not add unrelated telemetry merely to increase apparent messiness.
