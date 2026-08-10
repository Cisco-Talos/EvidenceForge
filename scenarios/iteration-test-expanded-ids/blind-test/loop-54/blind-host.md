# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 55

## Executive Summary

The endpoint telemetry is structurally strong: process, session, logon, file-object, and SSH lifecycle identifiers remain coherent across a six-hour window, and the Windows and Linux source-native records contain substantial realistic detail. The main obstacle to a “Real” verdict is a dataset-wide Sysmon file-creation texture—112 of 129 Event ID 11 records are five-digit numeric files under `C:\Windows\Temp`, attributed indiscriminately to core processes on every Windows host—supplemented by repeated CreateRemoteThread motifs and a one-sided eCAR-to-Sysmon timing offset.

## Evidence For Synthetic

- `[distribution_texture]` Of 129 Sysmon Event ID 11 records across nine Windows hosts, 112 (86.8%) use exactly `C:\Windows\Temp\<five digits>.tmp`; all 112 names are unique, but they share the same narrow numeric template. Examples include `DC-01` `smss.exe` creating `C:\Windows\Temp\33651.tmp` at `2024-03-18T12:49:09.5501800Z`, `dns.exe` creating `C:\Windows\Temp\52458.tmp` at `13:48:33.5742681Z`, and `WS-PPATEL-01` `userinit.exe` creating `C:\Windows\Temp\71385.tmp` at `14:19:14.6521246Z`. The pattern occurs on all nine Windows hosts and across implausibly broad owners: `svchost.exe` (33), `csrss.exe` (9), `WmiPrvSE.exe` (8), `smss.exe` (7), `userinit.exe` (7), `lsass.exe` (6), `taskhostw.exe` (6), plus `System`, `dns.exe`, `wininit.exe`, and others.
- `[environment_or_collection_plausibility]` Sysmon Event ID 8 appears 15 times and on every Windows endpoint, with only 11 source/target/start-function motifs. Six records collapse into two three-occurrence motifs: `SearchIndexer.exe → SearchProtocolHost.exe / ntdll.dll!RtlUserThreadStart` and `WmiPrvSE.exe → svchost.exe / kernel32.dll!BaseThreadInitThunk`. Several others describe Defender `MsMpEng.exe` creating threads in `winlogon.exe`, `explorer.exe`, or `RuntimeBroker.exe` at `MpOav.dll!AmsiScanBuffer` or `MpClient.dll!MpCreateRemoteThread`; for example, `DC-01` at `2024-03-18T12:04:56.8982674Z`. One or two such records are plausible; near-universal host coverage from a small motif family looks curated.
- `[distribution_texture]` For 917 PID-and-image-matched Windows process creations, every eCAR `PROCESS/CREATE` timestamp precedes the corresponding Sysmon Event ID 1 timestamp. The offset ranges from 6.006 ms to 1,767.597 ms, with a median of 643.567 ms; there are zero matches in the opposite direction. A stable sensor-order bias is possible, but the absolute one-sidedness across nine hosts is more regular than expected from independently timestamped endpoint products.
- `[weak_signal]` All non-`System` Windows Filtering Platform 5156 `Application` paths use `\device\harddiskvolume1\...` across all nine Windows systems (6,720 records), despite the mix of servers and workstations. A common corporate image can explain this, so it is not decisive, but it adds a small templating signal.

## Evidence For Real

- The collection contains 25,321 eCAR records, 13,799 Windows Security events, 4,148 Sysmon events, 4,322 Linux syslog lines, and 256 timestamped shell-history commands across 18 endpoints. Source volume varies materially by role: `DC-01` has 7,718 Security and 6,358 eCAR records, while Linux workstation `LT-MRIVERA-02` has 242 eCAR records and 309 syslog lines.
- Windows process correlation is excellent without visible lifecycle impossibilities. All 929 Sysmon Event ID 1 records match a Security 4688 by host, PID, and image; command lines agree in all matches, and Security-to-Sysmon timestamp deltas are generally within roughly ±21 ms. Of 695 Sysmon termination events, 644 reference a process visibly created earlier; none reference a matching process whose visible creation occurs later.
- Security logon semantics are internally coherent. Across 1,102 Event 4624 logons, 773 Event 4634 logoffs, and 346 Event 4672 special-privilege assignments, quantitative checks found no logoff or privilege event preceding a later visible login for the same Logon ID and no user/domain/logon-type mismatch on matched pairs.
- eCAR preserves durable lifecycle identity: all 861 visible login/logout pairs with a shared Logon ID reuse the same `objectID`; all visible PID-matched process create/terminate pairs reuse the same process `objectID`; repeated accesses to the same file reuse the file `objectID`.
- The DC Security log clear is source-native and coherent. Event 1102 occurs at `2024-03-18T17:42:03.6637048Z`, includes `UserData/LogFileCleared` for `NT AUTHORITY\SYSTEM` Logon ID `0x3e7`, resets `EventRecordID` to 1, and later events progress from the reset sequence.
- Linux SSH sessions have convincing event order and stable per-session identity. On `APP-INT-01`, PID 949974 records connection at `12:40:50.808486Z`, accepted public key at `12:40:52.996676Z`, PAM open at `12:40:53.042886Z`, logind session 376432 at `12:40:53.482069Z`, PAM close at `12:59:50.814101Z`, and logind removal at `12:59:51.630903Z`. Pre-window session closes were not treated as defects.
- Linux identity data is consistent across hosts: repeated accounts retain stable UIDs (`admin=1001`, `aisha.johnson=2528`, `marcus.chen=4119`, `lina.nguyen=5302`, `priya.patel=3843`).
- Shell history has reasonable entropy: 199 unique commands among 256 total, with no exact command occurring more than three times. The `DB-PROD-01` root history is tightly corroborated by eCAR: `mysqldump` at epoch `1710782225` maps to process PID 158513 and creation of `/tmp/rpt_0318.sql` at `1710782227709`; `gzip` creates `/tmp/rpt_0318.sql.gz`; `scp` PID 161147 reads the same file object and opens the outbound SSH flow to `10.10.2.30:22`.

## Detailed Analysis

### Quantitative scope and parsing

All endpoint JSON, XML, syslog, and history files parsed successfully. The visible window is approximately `2024-03-18 12:00–18:00 UTC`. I treated starts before 12:00 and ends after 18:00 as valid bounded-window conditions and only tested impossible ordering when both initiator and dependent were visible.

### Windows process and lifecycle evidence

The strongest aspect is shared process truth. There are 929 Sysmon Event ID 1 records and 935 Security 4688 records. Every Sysmon creation matched a Security creation by host, PID, and image, and the command line was identical in every match. eCAR matched 917 of those 929 process creations by PID and image, again with no command-line mismatch.

Sysmon GUID testing found zero cases where Event IDs 3, 5, 7, 8, 10, 11, 13, or 22 referenced a ProcessGuid whose visible Event ID 1 creation occurred later. The 644 terminations whose creates fell inside the window all follow their creation. This is notably convincing because the unmatched terminations are explainable as pre-window state rather than being force-paired to invented in-window starts.

### Authentication and session evidence

Windows Security login/logout data is detailed and consistent across servers and workstations. The DC has realistic domain-specific families—4768, 4769, 4771, and 4776—alongside 4624/4634 and 4672. No matched login/logout pair changed user, domain, or logon type.

The account lifecycle on `DC-01` is source-native and ordered: account `svc_mhsync` is created in 4720 at `16:14:33.8777666Z`, receives a password reset in 4724 at `16:14:35.4297663Z`, an account-change 4738 at `16:14:35.8587663Z`, and Domain Admins membership in 4728 at `16:14:40.5441383Z`. Later deletion appears in 4726 at `17:50:38.5284859Z`, after the Security-log record-ID reset.

Linux SSH evidence similarly preserves connection PID, user, UID, port, PAM state, and logind session ID. Failed attempts have distinct pre-auth close semantics, while successful sessions show transport, authentication, PAM open, logind creation, PAM close, and logind removal in plausible order.

### Endpoint behavior and field realism

Sysmon metadata is generally strong: correct provider/channel structure, plausible Event ID versions, millisecond `UtcTime`, richer seven-digit `SystemTime`, process GUIDs that remain stable across dependent events, hash sets, signer information, parent command lines, and source/target process access fields.

The Event ID 11 population is the conspicuous exception. Real systems produce many temporary-name conventions—GUIDs, application prefixes, extensions other than `.tmp`, installer/component names, and reusable working files. Here 86.8% of observed file-create events converge on one five-digit template, even for `smss.exe`, `csrss.exe`, `lsass.exe`, `dns.exe`, and `System`. The ownership breadth and all-host replication are more problematic than any single path.

Event ID 8 is also over-distributed. Fifteen total events are not excessive, but seeing at least one on every Windows host and recurring generic WMI/SearchIndexer/Defender motifs suggests a host-by-host allocation rule rather than naturally sparse remote-thread activity.

### Cross-source timing

Security and Sysmon process events differ by small bidirectional jitter, which looks credible. In contrast, eCAR is earlier in all 917 matched process creations. The offset is neither fixed nor identical, which is a positive sign, but the absence of even one reverse-order observation remains a measurable synthetic texture. This is a moderate indicator, not a contradiction, because products can have systematically different timestamp semantics.

### Linux shell and host activity

The Linux evidence is the most production-like family. Service-specific syslog varies by role: mail hosts include Postfix/Dovecot activity, `WEB-EXT-01` contains Apache/kernel volume, workstations contain NetworkManager, dhclient, GNOME, packagekit, fwupd, cups, and avahi, and servers contain SSH, cron, rsyslog, multipath, resolved, and journald behavior. Shell histories are sparse, user-specific, and cross-correlate with eCAR processes to sub-second precision while retaining realistic quoting differences between shell input and `argv`.

## Synthetic Indicator Summary

| Priority | Category | Affected source family | Scope | Impact |
|---|---|---|---|---|
| P1 | `distribution_texture` | Sysmon Event ID 11 / eCAR file telemetry | Dataset-wide; 112/129 Event 11s, all 9 Windows hosts | Repeated five-digit `.tmp` naming and indiscriminate core-process ownership are the strongest generator-like fingerprint. |
| P2 | `environment_or_collection_plausibility` | Sysmon Event ID 8 / eCAR remote-thread telemetry | Repeated; 15 events on all 9 Windows hosts | Remote-thread activity is too evenly distributed and drawn from a small set of generic motifs. |
| P2 | `distribution_texture` | eCAR and Sysmon process creation | Dataset-wide; all 917 matched records | eCAR precedes Sysmon in 100% of matches, producing a measurable one-sided timing signature. |
| P4 | `weak_signal` | Security 5156 | Dataset-wide; 6,720 path-bearing records | Universal `HarddiskVolume1` may reflect a standard image but lacks host-level storage diversity. |

## Realism Score by Category

- **Field format accuracy:** 8 — Security, Sysmon, eCAR, RFC5424 syslog, PAM, and shell-history formats are detailed and parse cleanly; Event 11 content semantics are the main exception.
- **Temporal patterns:** 7 — Lifecycles and source-native ordering are strong, but eCAR-to-Sysmon process timing is universally one-sided.
- **Cross-source correlation:** 9 — Process, session, file, PID, Logon ID, GUID, command-line, and SSH correlations survive quantitative checks without visible impossible ordering.
- **Behavioral realism:** 6 — Linux and malicious process behavior are convincing, but numeric Windows temp files and evenly allocated remote-thread motifs are conspicuous.
- **Environmental consistency:** 8 — Host roles drive credible source-family differences; universal Windows storage-path and Event 8 patterns reduce the score slightly.

## Recommendations

- **Highest-value target — P1:** Replace the dataset-wide Event ID 11 `C:\Windows\Temp\<five digits>.tmp` rule with process- and application-native file behavior. Core operating-system images should emit only defensible file-create families, while installers, Office, browsers, Defender, WMI, and services should use their own realistic path/name distributions. Preserve file-object IDs across subsequent accesses.
- **P2:** Make CreateRemoteThread evidence occurrence-driven and sparse. Generate Event ID 8 only when a concrete activity supports it, and validate `StartModule`, `StartFunction`, source/target process, signer, and installed Defender version as one contract. Avoid ensuring that every Windows host receives one.
- **P2:** Introduce a realistic source-timestamp model for eCAR versus Sysmon rather than a universally negative offset. A calibrated host/product latency profile may still have a dominant direction, but it should include clock skew, occasional near-equality, and some reverse ordering while preserving lifecycle bounds.
- **P4:** If host storage layouts are modeled, vary NT device-volume mappings by system image/build or explicitly tie a shared `HarddiskVolume1` mapping to a common deployment profile. This is a low-value refinement compared with Event 11 and Event 8.
