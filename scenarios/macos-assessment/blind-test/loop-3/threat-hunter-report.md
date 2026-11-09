# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 64

## Executive Summary

This is a technically useful, mostly coherent mixed-platform collection, with believable SSH and SMB pivots and substantial ordinary activity around the more interesting commands. I lean synthetic because a concentrated Windows process-creation timestamp anomaly, a systematic gap between Windows remote authentication and transport observations, and repeated Mac process metadata collectively look more like modeling or normalization artifacts than ordinary enterprise telemetry. I found no conclusive impossible lifecycle relationship; the score therefore remains well below the hard-contradiction range.

## Evidence For Synthetic

- **[distribution_texture] Windows process creations collapse onto one millisecond across unrelated executables and parents.** In `NS-WIN-01.northstar.example/windows_event_sysmon.xml`, Event 1 records **606893–606906** describe 14 distinct processes: 13 have `UtcTime=2026-10-20 13:05:56.148`, and the remaining one has `.149`. The 13-process group spans eight image paths and five parent PIDs, including Sublime Text, VS Code, Postman, Notepad++, `sihost.exe`, `taskhostw.exe`, `conhost.exe`, and `RuntimeBroker.exe`. The corresponding normalized creations are also compressed: `NS-WIN-01.northstar.example/ecar.json` lines **81–92** all have `timestamp_ms=1792501556251`; lines **93–94** follow two milliseconds later. A batch launcher or resumed host is an alternative explanation, but this is an event-time cluster in native Sysmon `UtcTime`, not simply identical file modification or ingestion times. It affects 14 of 130 visible Windows process creations.
- **[contract_gap] All 17 visible Windows Type 3 successes lack an exact transport pivot in the supplied sensor and endpoint FLOW records.** These Security 4624 events carry remote addresses and source ports, yet none of those address/port pairs appears as a connection to `10.42.0.21` in `office-span/conn.json` or as a matching FLOW in the four endpoint files. Examples are record **244832**, `13:05:56.1560588Z`, `10.42.0.31:58761`, Logon ID `0x1037cc13`; record **245443**, `16:51:13.8501878Z`, `10.42.0.12:59889`, `0x1053f4c5`; and record **245475**, `16:53:44.1532085Z`, `10.42.0.11:54355`, `0x10544406`. The collection does observe inbound Windows traffic: Windows eCAR lines **783**, **784**, and **1252** match build-host connections to ports 8080 and 135. It also observes other east-west SSH/SMB traffic. The family-wide lack of transport for successful remote Windows authentication is therefore more concerning than an isolated missing source. Selective filtering or pre-window persistent connections could explain individual cases; without a collection specification, this is a qualified gap, not proof that authentication was impossible.
- **[environment_or_collection_plausibility] Mac process ownership and job-control fields repeatedly resemble defaults.** Of 36 Mac-01 and 32 Mac-02 process CREATE records, respectively **24** and **19** explicitly carry both `process_group_id="1"` and `posix_session_id="1"`. Examples include Mac-01 eCAR line **13** (`/usr/bin/id`, PID 6480), line **19** (Homebrew `curl`, PID 7728), and line **43** (`/bin/zsh -c 'id; groups'`, PID 11448). On Mac-02, lines **1050**, **1054**, **1111**, **1129**, **1140**, and **1194** attach command-line file operations or a shell directly to `/sbin/launchd` with those same group/session values. Launchd parentage alone is normal for many Mac applications and services; the concern is its repeated combination with explicit group/session 1 for diverse user commands. A normalizer that substitutes unknown values could explain this pattern. I assign it limited weight and do not allege a native Endpoint Security schema violation.

## Evidence For Real

- **The Windows-to-Mac SSH pivot is operationally credible.** Windows eCAR line **766** creates `ssh.exe owen.patel@NS-MAC-02.northstar.example` under PowerShell at `15:07:35.686Z`; line **775** observes `10.42.0.21:56542 -> 10.42.0.12:22` at `15:07:44.999Z`. `office-span/conn.json` line **843**, UID `CAEWpvYnexF8tUOe4Vp`, starts at `15:07:44.568779Z`, has `conn_state=SF`, and spans approximately 1,394.65 seconds. Mac-02 eCAR line **403** records Owen's successful SSH login at `15:07:50.586Z` on that source tuple. Later command and termination evidence uses the corresponding process/session relationships.
- **Mac SSH separates execution identity and privilege changes.** Mac-02 eCAR lines **400–413** distinguish the keygen wrapper, executable replacement, forked SSH roles, audit binding, UID/GID changes, shell job control, and shell execution. The three native Endpoint Security records independently retain parent/child audit tokens and process versions. I treated those notification records as observations, not authorization decisions.
- **SMB activity supports practical hunting pivots.** `office-span/conn.json` line **2**, UID `CpDmnkLMDmtmUXfsMxy`, connects Windows `10.42.0.21:52674` to the build host on 445. `smb_mapping.json` line **1** names `\\NS-BUILD-01\Engineering`; `smb_files.json` lines **1–2** identify `Reports\performance-summary-draft.pdf`; `files.json` line **1** associates its FUID, hashes, receiver and 878,226-byte size. Build `syslog.log` lines **5–9** show Kerberos authentication, share connection, audit open/close, and service disconnection for that user and file.
- **Visible process lifecycles withstand basic contradiction checks.** Across all four eCAR files, I found no visible child created before a visible parent with the corresponding process UUID, no PID/PPID mismatch for those joined parent UUIDs, and no activity attributed to an actor more than 100 ms after that actor's visible termination. The native Windows Sysmon process GUID checks likewise found no dependent records after termination or child creation before the joined parent's creation.
- **Network data contains actual variation and consistent accounting.** The 2,255 connections include successful flows, resets, partial states, rejections and unanswered attempts. TLS includes both 1.2 and 1.3, resumed and fresh sessions, and unsuccessful establishment. Protocol rows joined to their connection UIDs did not fall outside their connection intervals within the small tolerance used for the check; packet and IP-byte accounting passed basic minimum-header checks.
- **Stable identities remain stable across observations.** Repeated X.509 fingerprints consistently described the same certificate fields; repeated file MD5 values did not conflict with file sizes or SHA-256 values. Repeated Windows image/version combinations also retained consistent hashes. These are useful substantive consistency properties, not evidence against authenticity merely because matching is complete.

## Detailed Analysis

### Scope and collection interpretation

The evidence covers approximately **2026-10-20 13:00–19:00 UTC**, with the first eCAR event at `13:00:07.035Z` and the last at `18:59:39.808Z`. Four endpoint identities map through their network records to one visible internal subnet:

| Endpoint | Apparent platform and role | Address | eCAR rows |
|---|---|---|---:|
| NS-MAC-01 | Mac developer/user workstation | 10.42.0.11 | 893 |
| NS-MAC-02 | Mac developer/user workstation and SSH receiver | 10.42.0.12 | 1,204 |
| NS-WIN-01 | Windows workstation used by Nora Ellis | 10.42.0.21 | 1,422 |
| NS-BUILD-01 | Linux development/build host, SSH and Samba server | 10.42.0.31 | 664 |

The principal visible human identities are Maya Chen, Owen Patel and Nora Ellis, alongside service identities and Nora's administrative credential. The network set contains 5,128 rows across ten families: 2,255 connections, 1,056 DNS, 937 TLS, 381 file observations, 284 X.509, 89 SMB file, 49 SMB mapping, 38 HTTP, 27 OCSP and 12 NTP records. Windows contributes 582 Security and 458 Sysmon events; the build host contributes 474 syslog lines. Mac native logs are narrowly represented: four Unified Log rows in total and three Endpoint Security fork notifications on Mac-02.

The last fact does not establish an unrealistic collection: these may be selected exports. I did not require additional native Mac event families, omitted Sysmon types, full boot histories, or logoff/termination events outside the visible interval. Nor did I use sanitized host/domain names or filesystem timestamps as authenticity evidence.

### Following remote administration

The clearest cross-platform trail begins with Nora's Windows session and an SSH client using Owen's account on Mac-02. The initiating client process, successful transport and target authentication occur in the expected order. Mac-02 keeps a root SSH monitor and distinguishes its children from the eventual Owen shell; line **455** records `/usr/bin/uname -a` at `15:13:08.471Z` with PPID **45521**, the shell created by the SSH execution chain.

The native fork records place the underlying forks at `15:07:46.599827Z`, `15:07:49.920897Z` and `15:07:49.936834Z`, whereas normalized eCAR places several subsequent state observations around `15:07:50.587–.591Z`. This warrants distinguishing event timestamps from normalization or observation timestamps. I did not count those offsets as impossible ordering: there is no shown child effect that predates its native fork, and the ordering within each source is usable.

The transport's calculated end is `15:30:59.222570Z`; the Mac shell/SSH process terminations at approximately `15:31:00Z` and logout at `15:31:10.032Z` are compatible with asynchronous endpoint/session reporting. A logout several seconds after TCP close is not inherently contradictory.

Nora also runs management commands against the Linux build host: Windows eCAR lines **485** and **1029** show `Get-CimInstance Win32_OperatingSystem -ComputerName 'NS-BUILD-01' -Credential 'nora.ellis-admin'`. These are interesting hunting leads, but command invocation does not prove successful Windows management of a Linux target. I did not penalize a command that could simply fail. Similarly, Security 4648 identifies explicit credential use, not proof of successful target-side administration.

The 17 Windows Type 3 logons are less satisfying to investigate. Their remote tuple fields provide precise intended pivots, but those pivots are uniformly absent from the supplied FLOW/connection evidence. This contrasts with the successful SSH and Samba investigations, where endpoint and sensor observations describe the same transport. An omitted service class or capture filter remains a plausible explanation; it would need to explain both network-sensor and endpoint FLOW visibility. I do not infer a particular destination port that the 4624 records themselves do not supply.

### Process timing and behavioral texture

The Windows timestamp concentration is the strongest single authenticity concern. Event 1 records **606893–606906** are genuine-looking process-creation shapes, with different PIDs, images, command lines and parent processes, yet their `UtcTime` values occupy only two adjacent milliseconds. Their XML `TimeCreated` values span roughly `13:05:56.1489114Z–13:05:56.1524567Z`; the corresponding Security 4688 records are spread over roughly the following 0.6 seconds. Different provider reporting delays can explain the Security spread, but not by themselves why 13 distinct process starts share one Sysmon event-time millisecond.

A synchronized application restore or automated launch is possible. However, the cluster combines several independent editor/application launches with Windows infrastructure processes, occurs about five minutes after the visible interactive logon, and accounts for roughly 11% of the Windows CREATE population. It looks more like time compression or a shared timestamp floor than an ordinary human burst. This is a strong distribution observation, not a claim that simultaneous process creation is logically impossible.

A weaker repeated timing feature occurs in failed local logons. Mac-02 eCAR lines **1014–1019** occur at `17:11:29.002Z`, `:33.002`, `:36.002`, `:41.002`, `:43.002`, and `:54.002`; lines **1045–1049** form another integer-second-offset group. Windows lines **1412–1416** similarly share the `.003` fraction in a later cluster. Automated credential retries can naturally produce whole-second spacing, so I do not count these groups as an additional major defect or independently increase the score for them.

The Mac process metadata concern is about attribution quality. Parent PID 1 may be legitimate, but repeated explicit group/session 1 across shell commands, file utilities and GUI launches reduces the value of job-control pivots. In contrast, Mac-02's SSH branch has distinct and changing process group/session values, including shell PID/group/session **45521**. This difference suggests more detailed process semantics in one activity family than in ordinary user activity, although the source's normalization rules are unavailable.

### Signal, noise and limits of attribution

The set is not composed solely of suspicious commands. It includes browser/application traffic, development tools, background service processes, scheduled sysstat activity, Samba reads/writes, sudo sessions, package maintenance, DNS errors/variation and network failures. Connection volume differs materially by host: Mac-02 originates 1,093 flows, Mac-01 808, Windows 286 and the build host 68. Hourly connection counts vary from 241 to 543. I found no basis to penalize the total volume without knowing capture filters or fleet size beyond the four represented endpoints.

On Mac-01, eCAR line **481** shows creation of `/Library/LaunchDaemons/com.northstar.assetcheck.plist` at `16:03:25.212Z`; line **493** independently shows `northstar-assetcheck --once` running as root at `16:08:55.361Z`; line **543** shows plist deletion at `16:18:31.220Z`. Those are separate observable facts. The supplied rows do not establish how registration occurred or why the item ran, and deletion is not proof of unload. I did not invent a missing authorization failure or claim this sequence proves malicious persistence.

Likewise, encoded PowerShell, hidden windows, credential use, SSH and local maintenance are investigation leads rather than standalone authenticity indicators. My score does not depend on whether these activities form a compact narrative or omit attacker mistakes.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Sysmon, with eCAR and Security corroboration | 14/130 process creations in two adjacent Sysmon milliseconds; 13 in one millisecond across five parent PIDs | Strongest concern: substantial event-time compression across unrelated process types |
| contract_gap | Windows Security 4624 versus network and endpoint FLOW | All 17 Type 3 successes have no matching source-address/port connection to Windows in the supplied records | Moderate: systematically weakens required remote-authentication pivots despite demonstrated east-west and inbound visibility; filtering/pre-window connections remain alternatives |
| environment_or_collection_plausibility | Normalized Mac process telemetry | 43/68 CREATE rows explicitly use process group/session 1, with repeated direct launchd attribution for diverse user commands | Limited: likely fallback-like metadata; normalization and platform specifics prevent treating it as impossible |

No demonstrated hard contradiction, generator identity leak, or verified native Mac schema defect was found. The combined evidence supports the lower part of the “likely synthetic” band rather than an 81–100 score.

## Realism Score by Category

- **Field format accuracy:** 8 — Source shapes, identifiers, hashes and byte accounting are generally credible; normalized Mac job-control values deserve verification.
- **Temporal patterns:** 5 — Most lifecycles work, but the native Windows creation-time cluster is a substantial artifact.
- **Cross-source correlation:** 7 — SSH and SMB pivots are strong; the complete Windows Type 3 transport gap is significant but collection-dependent.
- **Behavioral realism:** 7 — Developer and administrative activity is plausible, with diverse background activity; some routine process attribution appears generic.
- **Environmental consistency:** 7 — Platforms and services mostly fit their hosts; repeated Mac fallback-like metadata and unexplained authentication visibility reduce confidence.

## Recommendations

- If this were synthetic, preserve distinct execution times for independent process launches. Reproduce the Windows `13:05:56.148Z` case and ensure unrelated activities are not moved onto one shared minimum timestamp. Provider reporting delay should not erase the underlying execution-time distribution.
- If this were synthetic, connect each modeled remote Windows logon to the transport or pre-existing connection that actually carries it. If filtering intentionally hides that class of transport, make the observation model consistent across sensor and endpoint FLOW sources and retain enough collection context to explain the gap.
- If this were synthetic, populate Mac parent, process-group and POSIX-session values from the specific spawning activity. Represent unavailable values as unavailable instead of assigning PID/group/session 1 as a generic substitute; retain legitimate launchd parentage where supported.
- Preserve the existing SSH privilege/execution chain, explicit transport tuple ownership, SMB authentication/file pivots, stable content identities and nonuniform network behavior. These parts materially improve hunting utility and do not need arbitrary incompleteness to appear real.
