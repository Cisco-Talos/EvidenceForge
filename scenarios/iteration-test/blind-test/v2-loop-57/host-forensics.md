# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 94
**Synthetic-Confidence Score:** 84

## Executive Summary

The data is highly polished and often source-native, but it contains a repeatable Windows session-lifecycle fingerprint that I would not expect from production telemetry: every observed RDP-launched `userinit.exe` survives for most of the remote session, while every local-interactive instance exits within seconds. A second RDP timing contradiction and systematic Sysmon metadata placeholders reinforce the synthetic verdict, despite excellent process, logon, SSH, hash, and eCAR correlations elsewhere.

## Evidence For Synthetic

- `[contract_gap]` Across all nine Windows hosts with a visible new interactive session, the lifetime of `userinit.exe` splits perfectly by logon type. All five local Type 2 instances exit in 3.010–4.635 seconds, which is normal; all 18 RDP Type 10 instances persist for 508.485–9,262.764 seconds. On `WS-AJOHNSON-01`, Sysmon Event 1 creates PID 6212 (`userinit.exe`, LogonId `0x2701aaf`) at `2024-03-18T15:20:35.5451227Z`, Explorer starts through it at `15:20:35.9370204Z`, yet Sysmon Event 5 does not terminate `userinit.exe` until `17:54:58.3095845Z`. `userinit.exe` normally launches the shell/logon scripts and exits; retaining it as a session-lifetime process in every RDP session is a strong generator-family fingerprint.
- `[contract_gap]` One fully searched RDP lifecycle on `WS-AJOHNSON-01` contradicts its network transport. LogonId `0x2701aaf`, source `10.10.1.99:51382`, logs on with Security 4624 Type 10 at `15:20:35.4470488Z`. The unique matching `zeek-core/conn.json` flow (`CVR5GjUUSfBvGu0C5`) is `SF` and ends at `15:23:23.629912Z`, but Security 4779 says that exact source port/session disconnects at `15:45:01.9263176Z`, 1,298.296 seconds later. I searched all three Zeek `conn.json` files plus both endpoint eCAR files for the tuple and found no continuation/reconnection that accounts for the gap.
- `[schema_or_format]` Sysmon process metadata has systematic catalog-like holes. All 23/23 `winlogon.exe` and 23/23 `userinit.exe` Event 1 records across nine hosts contain `FileVersion=-`, `Description=-`, `Product=-`, `Company=-`, and `OriginalFileName=-`, even though these are standard Microsoft PE files and hashes are present. The same all-or-nothing omission affects 13/13 GoogleUpdater, 11/11 Exchange IMAP4, 8/8 Exchange EdgeTransport, and 9/9 DropboxUpdate process records, while neighboring cataloged binaries such as Explorer, svchost, and PowerShell are fully populated. That selective texture resembles a finite enrichment catalog rather than Sysmon extracting PE version resources from each image.
- `[environment_or_collection_plausibility]` `WS-AJOHNSON-01` appears to be a Windows 10-class workstation (its Microsoft binaries report build `10.0.19041.1`) but hosts two concurrent Type 10 sessions for `aisha.johnson` from the same client `LT-MRIVERA-02`: LogonId `0x26d9093` begins at `15:00:15.9838915Z`, and LogonId `0x2701aaf` begins at `15:20:35.4470488Z`; both remain logged on until `17:54:59` or later. Multi-session client Windows is possible only in specialized configurations, so the hostname/build plus same-user overlap is improbable, though not impossible by itself.
- `[distribution_texture]` Across 35 successful public-key SSH sessions in eight Linux server logs, TCP connection-to-acceptance delay is unusually compressed: 5.230–9.260 seconds, median 5.976 seconds, standard deviation 0.725 seconds. A shared reverse-DNS or authentication delay could explain a common floor, but the consistency across users, keys, servers, and hours looks generated, especially beside the wider password-auth range of 5.568–14.971 seconds.
- `[weak_signal]` Ten Linux hosts execute the exact `debian-sa1 1 1` cron command on a rigid 30-minute per-host phase for essentially the full six-hour window, with only subsecond jitter. Centralized scheduling or a shared image could explain this, so I give it little weight, but the uniform deployment and cadence add to the templated background texture.

## Evidence For Real

- Windows process correlation is exceptionally coherent. I parsed all 1,026 Sysmon Event 1 records across ten hosts; 1,025 have a Security 4688 on the same host with the same PID and image within 0.035–0.648 seconds. Parent-child pairs are credible, including `services.exe` → `svchost.exe`, `SearchIndexer.exe` → `SearchProtocolHost.exe`, `csrss.exe` → `conhost.exe`, and `explorer.exe` → browsers/Office/admin tools.
- Process lifetimes are not globally mechanical. Among 795 Sysmon create/terminate pairs there are 794 distinct millisecond lifetimes, ranging from 0.055 seconds to 19,920.515 seconds. Browser children, WMI providers, task hosts, update agents, shells, and long-lived user applications have differentiated duration shapes.
- Hash identity is internally convincing. Microsoft binary hashes remain stable within each OS build cohort and differ coherently between Server 2019 (`10.0.17763.1`), Windows 10 (`10.0.19041.1`), Server 2022 (`10.0.20348.1`), and Windows 11 (`10.0.22621.1`). For example, `svchost.exe` has one stable SHA-256 per build rather than drifting by host or process instance.
- eCAR state is well formed across all 21 endpoint files. I found no process termination before its matching create, no known process reference before creation or after termination, and no image identity conflict for a reused process UUID. The same Windows process instances also preserve PID, image, principal, parent, and logon identity across eCAR, Security, and Sysmon.
- Linux SSH sessions have realistic source-native sequences. For example, `APP-INT-01/syslog.log` records connection `10.10.1.21:38142` at `12:35:23.658981Z`, password acceptance at `12:35:38.630104Z`, PAM open at `12:35:38.755236Z`, and close at `13:01:23.387175Z`; eCAR uses PID 1898437 and the same tuple, and Zeek UID `Cpo0RXSNnzm0OH2HPU` reports a compatible 1,561.461-second SSH flow. Lina Nguyen's five bash-history commands at 12:49–12:51 fall inside that session.
- Endpoint roles are visibly differentiated. `DB-PROD-01` shows MySQL/Redis administration, `FILE-LNX-01` has sustained `smbd` and Samba audit activity, `MAIL-CLIN-01`/`MAIL-EDGE-01` show Postfix and Dovecot, `WEB-EXT-01` has web-service and kernel activity, and user workstations show browsers, Office, Teams/Webex, developer tools, or administrative clients in plausible combinations.
- The six-hour window includes realistic boundary truncation rather than forced closure of everything: several SSH sessions open before 12:00 or remain open after 18:00, and workstation processes/logon sessions also cross the boundaries. I did not score these missing heads/tails as defects.

## Detailed Analysis

### Scope, inventory, and collection window

I inventoried all 107 files beneath the supplied data directory. For endpoint analysis I parsed all 10 Security XML files, all 10 Sysmon XML files, all 21 eCAR JSON files, all 11 Linux syslog files, and all 24 bash-history files. I used the three Zeek `conn.json` files only for bounded transport checks tied to endpoint session tuples; detailed examples were drawn from every Windows host family and from `APP-INT-01`, `DB-PROD-01`, `FILE-LNX-01`, `MAIL-CLIN-01`, `MAIL-EDGE-01`, `PROXY-01`, and `WEB-EXT-01` on Linux.

The records themselves establish a primary window of approximately `2024-03-18T12:00:00Z` through `18:00:00Z`. Endpoint minima/maxima vary slightly by source and host, as expected for a slice. Conclusions about overnight behavior, boot sequences, full-day login rates, and post-window lifecycle tails are therefore inapplicable and were not penalized.

### Windows process trees and lifecycle

The broad process model is strong. The ten Sysmon files contain 1,026 Event 1 process creates and 850 Event 5 terminations. Source families agree on routine examples: on `WS-AJOHNSON-01`, Sysmon creates `SearchProtocolHost.exe` PID 5324 at `12:03:44.8573011Z`, parent `SearchIndexer.exe` PID 4636; Security 4688 records the same child/parent at `12:03:44.9558712Z`, and eCAR creates the same PID/image at `12:03:45.103Z`. Common user trees also include Explorer launching Firefox, Outlook, Teams, PowerShell, MMC, and RDP; Chromium-family child processes use renderer/GPU/utility command lines rather than being flat process lists.

The decisive defect is the remote-session treatment of `userinit.exe`. All five local Type 2 cases behave correctly: `WS-DRAMIREZ-01` has two instances lasting 3.010 and 3.082 seconds, while `WS-EBROOKS-01`, `WS-PPATEL-01`, and `WS-SMARTINEZ-01` last 3.215, 3.039, and 4.635 seconds. In contrast, every one of 18 Type 10 cases on `DC-01`, `DC-02`, `FILE-SRV-01`, `MAIL-FIN-01`, and `WS-AJOHNSON-01` remains alive for 508–9,263 seconds. This exact behavior split by logon type is too systematic to attribute to occasional slow logon scripts.

The issue is visible in multiple independent renderings, not merely inferred from an absent event. For `WS-AJOHNSON-01` LogonId `0x2701aaf`, Sysmon Event 1 and Security 4688 create userinit PID 6212/`0x1844` at `15:20:35.545/15:20:35.601Z`; Explorer is visibly launched through it at `15:20:35.937Z`; Security 4689 and Sysmon Event 5 terminate the same process at `17:54:58.207/17:54:58.310Z`. eCAR also keeps the same object alive until `17:54:58.269Z`. The records agree with each other but agree on implausible lifecycle semantics.

### Windows logon sessions and RDP

The dataset includes a credible mix of local interactive (2), network (3), service (5), unlock (7), new-credentials (9), and remote interactive (10) logons. Workstation lock/unlock behavior is visible: `WS-AJOHNSON-01` logs Security 4800 at `13:26:44.7907594Z`, failed Type 2 attempts at 13:43, Type 7 unlock for LogonId `0x2544e5a` at `13:45:40.0234699Z`, and 4801 at `13:45:40.4249746Z`. Pre-window sessions referenced by those unlocks and early process terminations were treated as valid boundary state.

Most RDP contracts are impressively consistent. Across 18 Type 10 logons, the matching Zeek TCP flow begins 5.595–7.292 seconds before Security 4624; for 17 sessions with 4779, 16 network-flow ends are within about 0.83 seconds of the Windows disconnect. The outlier is therefore conspicuous rather than a general clock-offset issue: `WS-AJOHNSON-01` LogonId `0x2701aaf` uses `10.10.1.99:51382` in 4624, 4779, endpoint eCAR, and Zeek, but its clean `SF` TCP close occurs at `15:23:23.629912Z` and 4779 arrives only at `15:45:01.9263176Z`. The other concurrent session from port 41135 ends and disconnects within 0.826 seconds, ruling out a host-wide 22-minute collection delay.

The same workstation carries three simultaneous aisha.johnson interactive contexts for a substantial period: the pre-existing local session `0x2544e5a` plus RDP sessions `0x26d9093` and `0x2701aaf`. Specialized multi-session Windows client deployments can do this, so I do not call it impossible, but nothing else in the endpoint texture identifies this workstation as a session host.

### Sysmon field and hash behavior

Event envelopes, channel/provider identities, tasks, versions, timestamps, GUID shapes, and core data names are generally convincing. Sysmon `UtcTime` consistently precedes the XML SystemTime by a small positive collection delay, EventRecordIDs are monotonic in every Sysmon file, and process/network/file/registry/access events use plausible fields. Hashes are stable by image and OS cohort, an important real-data property.

PE version enrichment is the exception. The absence is not random or process-instance-specific: every observed `winlogon.exe` and `userinit.exe` process create has five metadata values rendered as `-`, and several entire third-party image families exhibit the same pattern. Because fully populated records for adjacent Windows images prove the collector is configured to provide these fields, the family-level gaps look like unsupported catalog entries rather than natural extraction failure. This is a source-native format/content defect, not a complaint about a missing Sysmon event type.

### Linux syslog, shell activity, and SSH

Linux evidence has substantial lived-in detail. Host roles produce different program distributions: `FILE-LNX-01` has 153 `smbd` and 135 `smbd_audit` lines, the mail hosts contain Postfix/Dovecot workflows, `WEB-EXT-01` contains extensive kernel activity, and the workstation/laptop systems show NetworkManager, DHCP, desktop indexing, CUPS, firmware, and package services. SSH PIDs are consistent through connection, authentication, PAM open/close, eCAR process/session objects, and network tuples. Public-key fingerprints are stable per user across hosts, which is what I would expect from roaming administrators.

Bash histories are timestamped, host-sensitive, and usually fall inside the matching SSH session. Commands are role-aware (`mysql`/`redis-cli` on the database host, Samba checks on the file host, PHP/web checks on the web host), though a generic diagnostic pool recurs: `find /tmp -maxdepth 1 -type f | head` appears in four different host/user histories and several commands appear in three. The repetition is noticeable but not enough by itself to establish synthesis.

The SSH authentication latency distribution is more diagnostic. Thirty-five public-key sessions across eight servers nearly all wait about six seconds between the syslog `Connection from` line and `Accepted publickey` (median 5.976 seconds, standard deviation 0.725). A shared environmental timeout remains a viable real-world explanation, so this is supporting distribution evidence rather than a contradiction.

### eCAR correlation and state integrity

I checked all 21 eCAR files for process-object ordering and identity reuse. No termination precedes its visible create; no record referencing a known process UUID occurs before creation or after termination; and referenced source image identities do not conflict with their process-create images. This includes Windows session processes, Linux sshd children and shells, endpoint network flows, file/registry/module actions, and termination records.

The data also models source-specific visibility rather than blindly duplicating every event. A small number of Sysmon process terminations lack Security 4689, particularly browser children, while creates are almost completely shared. That asymmetry is plausible collection behavior and was not treated as synthetic. The RDP port-51382 mismatch is different because the same exact tuple and session are present across all relevant sources but disagree on an observable close/disconnect time.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `contract_gap` | Windows Security, Sysmon, eCAR | All 18 visible RDP sessions on five targets | `userinit.exe` incorrectly persists 508–9,263 seconds in every Type 10 session while all five Type 2 cases exit in 3–5 seconds; this is a repeated family-level lifecycle fingerprint. |
| `contract_gap` | Windows Security + Zeek + endpoint eCAR | One `WS-AJOHNSON-01` RDP tuple | Clean TCP close for `10.10.1.99:51382` precedes the exact matching 4779 disconnect by 1,298.296 seconds, with no matching continuation in any relevant connection log. |
| `schema_or_format` | Sysmon Event 1 | Dataset-wide by image family | 46/46 standard `winlogon.exe`/`userinit.exe` records and several third-party families have complete PE metadata replaced by `-`, unlike neighboring enriched binaries. |
| `environment_or_collection_plausibility` | Windows Security/Sysmon/eCAR | One Windows 10-class workstation | Same user/source establishes two overlapping RDP sessions while a local session also remains active; possible only under an unusual multi-session configuration. |
| `distribution_texture` | Linux syslog/SSH | 35 public-key sessions across eight servers | Public-key authentication latency is tightly centered near six seconds across hosts/users/time, consistent with a narrow generation distribution unless a shared timeout explains it. |
| `weak_signal` | Linux eCAR/syslog | Ten hosts | Identical sysstat command and rigid 30-minute host phase throughout the slice; explainable by shared configuration, so low score impact. |

## Realism Score by Category

- **Field format accuracy:** 7/10 — XML/JSON/syslog structures and most source-native fields are strong, but image-family-wide Sysmon PE metadata placeholders are conspicuous.
- **Temporal patterns:** 5/10 — Most ordering and duration distributions are credible, but the RDP `userinit.exe` lifecycle split and one 21.6-minute transport/disconnect mismatch are high-impact defects.
- **Cross-source correlation:** 8/10 — Process, logon, SSH, tuple, PID, and hash identities correlate extremely well; the isolated RDP close contradiction prevents a higher score.
- **Behavioral realism:** 7/10 — Host roles and user tools are differentiated and command/session durations vary, with some repeated diagnostic pools and narrow SSH auth timing.
- **Environmental consistency:** 6/10 — OS-build/hash cohorts and server roles are coherent, but the concurrent same-user Windows-client RDP sessions and uniform Linux scheduling require unusual assumptions.

## Recommendations

- If this were synthetic, model `userinit.exe` as a short-lived logon initializer for every interactive logon type. Terminate it shortly after it starts Explorer and any logon scripts; do not retain it with the remote session lifecycle. Add a cross-source test proving Type 2 and Type 10 sessions both exhibit short, varied `userinit.exe` lifetimes.
- If this were synthetic, make RDP transport, 4779 disconnect, and eCAR session state share one authoritative close/disconnect transition. For each exact source tuple, an orderly `SF` close should produce the endpoint disconnect within a realistic short window unless a visible reconnection/alternate transport justifies continued attachment.
- If this were synthetic, enforce host capability and session-policy constraints. A Windows 10-class workstation should default to one active remote-interactive session per user/host; use a clearly session-host-like system/profile when concurrent RDP sessions are intentional.
- If this were synthetic, populate Sysmon Event 1 PE metadata from the same per-build image identity that owns hashes. Standard Microsoft session binaries and common signed third-party services should not systematically fall back to all `-` fields when other PE images are enriched.
- If this were synthetic, broaden SSH connection-to-authentication timing by authentication method and environmental condition. Public-key auth should often complete quickly, while DNS/GSSAPI delays or passphrase interaction should appear as less universal, explicitly coherent long tails.
- If this were synthetic, vary sysstat deployment and cadence by host class or preserve a clearly organization-managed schedule with realistic host exceptions; avoid giving nearly every heterogeneous Linux host the same command at a rigid 30-minute cadence.
