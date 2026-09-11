# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 88  
**Synthetic-Confidence Score:** 74

## Executive Summary

The endpoint evidence is technically sophisticated: Windows process, session, network, and eCAR records correlate correctly, and I found no impossible visible lifecycle ordering. Nevertheless, several independent dataset-wide distributions—especially Linux firewall timestamps, SSH authentication latency, Windows exit statuses, and fleet-wide cron timing—look generated rather than naturally accumulated.

## Evidence For Synthetic

- `[distribution_texture]` The 679 UFW records in `WEB-EXT-01.meridianhcs.local/syslog.log` draw from only 12 source IPs and 18 destination ports. Four sources account for 591/679 records, while each major source rotates among exactly three TCP window values—1024, 14600, and 65535—in roughly even proportions despite otherwise fixed TTL and packet length.

- `[distribution_texture]` Every UFW kernel record implies a boot anchor between exactly `2024-02-20T12:00:00.000Z` and `.250Z`: subtracting the bracketed kernel uptime from the RFC5424 timestamp leaves an almost uniform 0–250 ms residual. An exact noon boot anchor combined with uniformly distributed logging delay across 679 records is a strong generator-like timing fingerprint.

- `[distribution_texture]` Across eight Linux SSH servers, all 35 successful public-key authentications occur 5.689–9.639 seconds after the connection message, with a 6.285-second median. Automated failed-password attempts complete in only 0.221–0.904 seconds, while all 45 successful authentications transition from `Accepted` to PAM session-open in an unusually tight 48–179 ms band.

- `[distribution_texture]` The same application-timing regularity appears in eCAR RDP telemetry: all 18 matched inbound RDP flows precede successful Type 10 logins by 4.521–6.309 seconds, with a 5.638-second median.

- `[distribution_texture]` All 849 Windows Security Event 4689 records across ten hosts have `Status=0x0`. A six-hour collection containing interactive tools, update processes, service processes, browsers, administrative commands, and short-lived utilities would ordinarily contain at least some nonzero process exit statuses.

- `[distribution_texture]` Ten Debian-like systems run the same `debian-sa1 1 1` cron command on exact 30-minute lattices. Each host has a fixed minute phase—such as `:00/:30`, `:01/:31`, or `:07/:37`—with sub-300 ms jitter; occasional omissions produce almost exactly 3,600-second gaps. The cross-fleet phase-plus-dropout texture looks modeled.

- `[environment_or_collection_plausibility]` Windows process-creation volume is thin: 1,027 Sysmon Event 1 records across ten hosts over six hours, with individual workstations producing only 52–111. Aggressive Sysmon filtering could explain this, so it is supporting evidence rather than a decisive indicator.

## Evidence For Real

- Security 4688, Sysmon Event 1, and eCAR PROCESS/CREATE records correlate extremely well. Of 1,029 Security process creations, 1,024 match Sysmon and 1,020 match eCAR within two seconds; matched child PID, image, parent PID/image, command line, user, and logon ID have no observed contradictions.

- Network endpoint correlation is equally coherent. I matched 7,770 of 7,851 Sysmon Event 3 records to eCAR FLOW records and 12,034 of 12,154 Security 5156 records to eCAR, with no tuple, PID, image, principal, or direction mismatches among matches.

- Sysmon lifecycle analysis found no process termination before creation, child creation after the identified parent’s termination, or dependent Event 3/7/8/10/11/13/22 record outside a visible process lifetime. The 802 fully visible process lifetimes range from 1.532 seconds to approximately 4.49 hours.

- Among 5,951 eCAR actor references whose process creation was visible, none occurred before actor creation or after its visible termination.

- Process trees are role-sensitive. `MAIL-FIN-01` runs Exchange `Microsoft.Exchange.Imap4.exe` and `EdgeTransport.exe`; `WS-MCHEN-01` uses VS Code, DBeaver, SQL clients, editors, MMC, SSH, and RDP; `DB-PROD-01` shows multipath activity; and `WEB-EXT-01` carries substantial kernel firewall telemetry.

- Binary identity is internally consistent. The same image and OS-version combination retains the same SHA1/MD5/SHA256/IMPHASH values across hosts, different Windows versions receive different hashes, and no complete hash tuple is reused across different image names.

- Logon and lock lifecycles are plausible. On `WS-AJOHNSON-01`, Event 4800 at `17:19:41.443360Z` and Event 4801 at `17:35:16.105902Z` share LUID `0x274a9d2` and session 2. Similar same-session lock/unlock pairs appear on other workstations.

- The DC-01 Security-log clearing sequence is source-native and correctly ordered: `wevtutil cl Security` is created at `17:42:22.307880Z`, Event 1102 follows at `17:42:26.185525Z` with record ID 1, and subsequent Security record IDs restart from the new log.

- Linux SSH records maintain PID-specific connection, authentication, PAM, and close order. For example, APP-INT-01 PID 1900971 connects at `12:43:57.269074Z`, authenticates at `12:44:03.118027Z`, opens PAM at `12:44:03.282992Z`, and closes at `13:00:57.572396Z`.

- Centralized Linux identities are stable: Aisha Johnson is UID 2528, Marcus Chen 4119, Lina Nguyen 5302, and Priya Patel 3843 across hosts. SSH key fingerprints also remain consistent per user.

## Detailed Analysis

### Windows process and Sysmon evidence

The Windows XML uses credible provider GUIDs, channels, event versions, tasks, keywords, and event-specific field layouts. Security 4688 uses version 2 with the expected creator, target, parent, command-line, elevation, and mandatory-label fields; Sysmon Event 1 uses version 5 and includes ProcessGUID, hashes, parent identity, logon identity, terminal session, and integrity level.

A representative example is `WS-MCHEN-01` at `12:05:21Z`: Security record 948734 reports PID `0x1c4c` for `svchost.exe`, parent PID `0x16f0`/`services.exe`, command line `svchost.exe -k netsvcs -p -s BITS`, SYSTEM LUID `0x3e7`. Sysmon record 525182 reports the same child as decimal PID 7244, parent PID 5872, identical command line and account, and a stable ProcessGUID. This consistency holds throughout the matched population.

Process trees include expected Windows structures such as `smss.exe → winlogon.exe → userinit.exe → explorer.exe`, `services.exe → svchost.exe`, `svchost.exe → WmiPrvSE.exe/taskhostw.exe/dllhost.exe`, and browser or collaboration subprocesses. Administrative activity uses plausible trees such as `explorer.exe → powershell.exe → ssh.exe` and `explorer.exe → mstsc.exe`.

The principal weakness is distributional: only 1,027 process creations are visible across all ten hosts, and all 849 Security process terminations report successful exit status. The latter is difficult to explain through ordinary event filtering because exit status is a field within an included event type.

### Logon and session lifecycle

The Windows logs contain Types 2, 3, 5, 7, 9, and 10, with Type 3 sessions generally short and Type 10 sessions lasting from roughly 10 minutes to three hours. Fixed LUIDs `0x3e4`, `0x3e5`, and `0x3e7` are appropriately associated with NETWORK SERVICE, LOCAL SERVICE, and SYSTEM.

Visible lock/unlock sequences preserve LUID and terminal-session identity. RDP transport also precedes Type 10 authentication in every matched eCAR case, so there is no causality inversion. However, the 4.521–6.309-second transport-to-login band across all 18 RDP sessions is narrower than I would expect across different source machines, targets, and authentication conditions.

Failures use sensible Windows status combinations: bad-password attempts primarily show `0xc000006d/0xc000006a`, while disabled-account failures use substatus `0xc0000072`. These are source-native and plausible.

### Linux syslog and SSH

The syslog records are valid RFC5424-shaped entries with plausible facilities and severities: SSH under authpriv, CRON under the cron facility, and service messages under daemon. Persistent daemons retain stable PIDs, while session and command processes receive increasing host-local PIDs.

SSH evidence is structurally strong. Connection, authentication, PAM open, process activity, PAM close, and eCAR session lifecycle remain correctly ordered. Per-user public-key fingerprints are stable across servers, which is realistic for centrally managed user keys.

The timing distributions are much less convincing. Public-key authentication should generally be faster and more variable than the observed 5.7–9.6-second band on a LAN. The fact that automated failures happen almost immediately rules out a shared connection-establishment or reverse-DNS delay as a complete explanation. The narrow 48–179 ms PAM-open delay following every successful authentication adds a second independent timing band.

Administrative command lines are reasonably realistic. Apparently argument-less processes such as `tail` and `head` commonly start within tens of milliseconds of a corresponding `grep`, consistent with shell pipelines rather than malformed standalone commands.

### System and service activity

The endpoint slice contains credible background activity: TiWorker and BITS servicing, Defender `MpCmdRun.exe` activity, Group Policy refreshes, Google/Dropbox/Adobe updaters, WMI providers, scheduled-task hosts, snapd, irqbalance, multipathd, postfix, Dovecot, Samba, DHCP, and workstation desktop services.

The DC-01 account, service, task, and log-clear records are especially detailed. Event 4720 creates `svc_dirsync`; Event 4738 updates its state; Event 4728 adds it to Domain Admins; Event 4697 installs `DeviceSyncSvc`; and Event 4698 contains a correctly escaped Task Scheduler XML definition. These records use coherent SIDs, subject identities, record ordering, and companion process evidence.

The strongest system-level synthetic fingerprint is the UFW stream. Its wall-clock and kernel-monotonic timestamps mathematically reduce to an exact noon boot anchor plus a uniformly bounded 0–250 ms delay. The tiny source/port pools and three-valued TCP window distribution reinforce that conclusion.

### eCAR correlation

eCAR PROCESS, FLOW, USER_SESSION, MODULE, REGISTRY, FILE, SERVICE, and THREAD records use stable UUIDs and consistent actor relationships. PROCESS/CREATE and TERMINATE reuse the same objectID, and dependent objects reference a live actor where the actor’s lifecycle is visible.

Endpoint flows render direction correctly: inbound DC DNS/Kerberos records retain the remote source/local destination tuple while attributing the event to the local `dns.exe` or `lsass.exe`; outbound workstation flows retain their initiating application and principal. I found no concrete eCAR-versus-Windows contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `distribution_texture` | Linux kernel/UFW syslog | 679 records on WEB-EXT-01 | Exact boot anchor, uniform 0–250 ms residual, small recycled source pool, and three-valued TCP windows form the strongest generator fingerprint. |
| `distribution_texture` | SSH syslog and eCAR | 35 public-key and 45 total successful sessions across eight servers | Authentication and PAM transitions collapse into narrow method-specific timing bands not shared by failures. |
| `distribution_texture` | Windows Security 4689 | 849 records across ten hosts | Every visible process exits with `0x0`, eliminating the expected nonzero long tail. |
| `distribution_texture` | Linux CRON/eCAR | Ten hosts | Identical sysstat commands follow host-phased 30-minute lattices with near-zero jitter and exact one-period omissions. |
| `distribution_texture` | Windows RDP/eCAR | 18 sessions | Every successful login follows transport by approximately 4.5–6.3 seconds. |
| `environment_or_collection_plausibility` | Windows Sysmon Event 1 | Ten hosts | Low process volume is possible under aggressive filtering but weakens the lived-in endpoint texture. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, RFC5424 syslog, hashes, SIDs, and eCAR shapes are highly credible.
- **Temporal patterns:** 5 — Lifecycle ordering is excellent, but several independent timing families collapse into generator-like bands.
- **Cross-source correlation:** 9 — Matched process, network, session, and actor records agree without observed field contradictions.
- **Behavioral realism:** 7 — Process trees and user roles are convincing, but exit-status and command-schedule distributions lack a natural long tail.
- **Environmental consistency:** 6 — Host roles and software placement are coherent, while UFW source diversity and fleet-wide cron texture are less plausible.

## Recommendations

- If this were synthetic, generate firewall background noise from a much larger heavy-tailed source and destination-port population. Keep TCP fingerprint characteristics stable for a given scanner/tool instead of independently choosing among three window sizes.

- If this were synthetic, derive kernel monotonic time from a persistent, non-round boot timestamp and model queue delay from a realistic skewed distribution. Avoid a uniform 0–250 ms residual applied independently to every record.

- If this were synthetic, make SSH timing authentication-method aware. Public-key authentication should usually be fast, password sessions should include variable human or automation delay, and backend/PAM latency should have occasional long-tail behavior.

- If this were synthetic, derive RDP transport-to-authentication delay from host load, protocol negotiation, authentication mechanism, and network conditions instead of a common five-to-six-second envelope.

- If this were synthetic, populate Security 4689 exit status from actual modeled command outcomes, including failed commands, updater return codes, service errors, and occasional abnormal termination.

- If this were synthetic, use actual distro/package scheduler definitions or a persistent organization-level cron policy. Collection loss should be modeled independently rather than appearing as exact one-period gaps in an otherwise perfect lattice.

- If this were synthetic, retain the existing ProcessGUID, PID, LUID, hash, tuple, and eCAR actor correlation logic; those portions are already highly realistic.
