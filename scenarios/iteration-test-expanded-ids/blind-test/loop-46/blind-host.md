# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 70

## Executive Summary

The host telemetry is technically strong: Windows process, session, Sysmon, Security, and eCAR identities remain coherent, and the Linux SSH and shell evidence has credible lifecycle detail. I nevertheless assess it as synthetic because several independent Linux hosts exhibit conspicuously fixed event-count templates, while WEB-EXT-01's large UFW population is generated from a tiny recurring source set with near-balanced rotation among exactly three TCP window values.

## Evidence For Synthetic

- `[distribution_texture]` All nine Linux syslog files contain exactly eight `dbus-daemon` records despite widely different host roles and total volumes: WEB-EXT-01 has 1,627 syslog records, APP-INT-01 has 281, and WS-OHADDAD-01 has 215, yet each has eight D-Bus records. The same fixed count across every Linux server and workstation is a fleet-wide generation-like floor rather than an organic consequence of the surrounding activity.
- `[distribution_texture]` WEB-EXT-01 has 904 `[UFW BLOCK]` messages in six hours but only nine source IPs. Eight sources recur 50–162 times each. For each recurring source, packet length and TTL are invariant, while `WINDOW` is rotated almost evenly among exactly `1024`, `14600`, and `65535`. For example, `145.78.103.167` appears 162 times with `LEN=52 TTL=118`, split 59/51/52 across window 1024/14600/65535; `37.75.195.175` appears 156 times with `LEN=48 TTL=110`, split 49/47/60. This repeated three-bin texture across unrelated scanner identities is much more consistent with a parameter pool than live Internet background radiation.
- `[distribution_texture]` Eight Linux hosts share the identical `(sysstat) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)` job at a host-specific minute on an exact 30-minute grid. The logs also contain isolated missing grid slots without a visible host outage: APP-INT-01 records 12:30 and 13:30 but no 13:00 job, while normal host messages continue; WEB-EXT-01 records 14:01 and 15:01 but no 14:31. A centrally deployed schedule is plausible, but fleet-wide exact cadence plus sparse, apparently randomized holes has generator-like temporal texture.
- `[weak_signal]` Several background families show unusually uniform per-host quotas beyond D-Bus: `anacron` is exactly five records on seven of the Linux hosts where it appears, while system-role-specific activity varies substantially. This is supportive but not decisive alone.

## Evidence For Real

- Windows process lifecycles are internally sound. Across all Windows hosts, no Sysmon ProcessGUID that has both Event 1 and Event 5 is terminated before creation, and PID/image identity remains stable for each GUID.
- Sysmon Event 1 and Security 4688 correlate cleanly by PID, image, and time. Examples include 77/77 matches on WS-PPATEL-01, 149/149 on DC-01, 57/57 on WS-DRAMIREZ-01, and 141/141 on WS-AJOHNSON-01; matched timestamps differ by at most about 0.14 seconds.
- File hashes remain stable for repeated executions of the same image on a given host. Cross-host variation is grouped rather than random per event, which is consistent with a few Windows build cohorts.
- Session behavior includes realistic unlock semantics. On WS-PPATEL-01, logon ID `0xd8d7b28` starts as Type 2 at `2024-03-18T12:18:24.4778789Z` and is reused for a Type 7 unlock at `2024-03-18T15:14:12.2350002Z`; WS-SMARTINEZ-01 similarly reuses `0xc1982c7` for Type 2 then Type 7.
- DC-01's Security EventRecordID reset is source-native and explained in-band: record `28262000` at `2024-03-18T17:42:15.5236289Z` is followed by Event 1102 at `2024-03-18T17:42:15.6063384Z` with record ID 1, representing an audit-log clear rather than an unexplained ordering defect.
- Linux shell histories are role-sensitive and varied. Lina Nguyen performs development and SSH work (`git`, `pytest`, Docker, Emacs), while DB-PROD-01 root executes MySQL inspection, `mysqldump`, compression, and `scp`; administrator histories include plausible diagnostic pivots rather than one repeated universal command sequence.

## Detailed Analysis

### Windows process and eCAR lifecycle

The Windows hosts contain credible process ancestry: `services.exe` parents `svchost.exe` and service programs, `svchost.exe` parents WMI/task-host activity, `SearchIndexer.exe` parents search filter/protocol hosts, and user applications generally descend from `explorer.exe`, PowerShell, or a shell. The attack-like chain on WS-AJOHNSON-01 is also internally consistent: Sysmon Event 1 creates PID 7008, GUID `{fd907e59-618e-65f8-c102-0000a5c21609}`, image `C:\Windows\System32\ms-index-service.exe`, at `2024-03-18 15:45:18.644`; Event 10 process access follows at 15:45:20.336 and 15:45:21.769, Event 8 remote-thread creation follows at 15:45:21.840, and Event 5 terminates the same GUID at 15:45:26.313.

No eCAR PROCESS object with both CREATE and TERMINATE is terminated before its same-object creation. Visible eCAR parent `actorID` references point to earlier, image-compatible process objects; I found no later-created parent for a visible child. Initial terminations whose creates are outside the six-hour window were treated as neutral.

### Windows Security and Sysmon correlation

Every Sysmon Event 1 had a Security 4688 partner with the same PID and image on all nine Windows hosts. Timing is credibly near-contemporaneous rather than bit-identical. Security-only 4688 records are sparse (two on FILE-SRV-01 and one each on WS-MCHEN-01, WS-SMARTINEZ-01, and WS-EBROOKS-01), a plausible observation difference rather than a self-contradiction.

Hashes are stable within hosts: no host reports more than one hash set for the same executable path among its Sysmon Event 1 records. Common Windows binaries form a few consistent cross-host hash cohorts, while OpenSSH `ssh.exe` has one hash across 74 observed executions. ProcessGUID create/terminate pairs preserve PID and image, and no same GUID is duplicated for multiple creates or terminations.

### Logon sessions

I found no Security 4634 preceding a later 4624 for the same visible logon ID. Repeated 4624 records for existing IDs are semantically credible Type 7 unlocks, including `0x24dcd22` for Aisha Johnson and `0x6c07e4a` for Marcus Chen. Short Type 3 sessions commonly have paired logoffs, while interactive and remote-interactive sessions can remain open at the window boundary. eCAR session objects that visibly include LOGIN and LOGOUT preserve identity and order.

### Linux host evidence

The Linux records have good local detail: SSH authentication, PAM session open/close, and systemd-logind removal sequences are present; sudo records include TTY, working directory, target user, command, and paired PAM session messages. Bash histories use epoch markers and show host-appropriate work. These are meaningful realism strengths.

The weakness is population texture rather than individual line syntax. Exactly eight D-Bus messages occur on every one of the nine Linux hosts, even though their overall syslog populations range from 215 to 1,627. WEB-EXT-01's UFW stream is especially revealing: 904 lines are dominated by eight repeatedly recycled external identities, and every dominant identity independently cycles through the same three TCP window values in close-to-equal shares. Real scanners can be persistent and stable TTL/length is plausible, but changing among those exact three windows with roughly equal frequency for each stable source identity is not convincing endpoint traffic texture.

The sysstat schedule adds a second fleet-wide fingerprint. APP-INT-01 runs at minute 00/30, WEB-EXT-01 at 01/31, LT-MRIVERA-02 at 02/32, WS-LNGUYEN-01 at 03/33, and MAIL-CLIN-01 at 04/34, with analogous offsets on the other hosts. Staggering itself is operationally reasonable; the combination of perfectly offset grids and isolated skipped ticks amid continued logging looks modeled.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `distribution_texture` | Linux syslog / D-Bus | All 9 Linux hosts | Exactly eight D-Bus records per host despite major role and volume differences is a conspicuous fixed quota. |
| `distribution_texture` | WEB-EXT-01 kernel/UFW | 904 records, 9 sources | Eight recycled identities each rotate near-evenly through the same three TCP window values while retaining fixed LEN/TTL. |
| `distribution_texture` | Linux CRON/sysstat | 8 Linux hosts | Host-offset exact 30-minute grids with isolated unexplained holes look modeled rather than organically collected. |
| `weak_signal` | Linux background daemons | 7 Linux hosts | Additional exact per-family quotas, notably five `anacron` records, reinforce the fixed-count pattern. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, RFC 5424 syslog, eCAR objects, hashes, and process identifiers are source-appropriate with no material format defect found.
- **Temporal patterns:** 6 — Lifecycle ordering is strong, but the Linux cron grids and pooled UFW field rotations expose modeled timing and distribution.
- **Cross-source correlation:** 9 — Security 4688, Sysmon Event 1, and eCAR process evidence agree without impossible ordering or identity drift.
- **Behavioral realism:** 8 — User process trees, unlocks, shell histories, SSH administration, and malicious process behavior are credible and role-aware.
- **Environmental consistency:** 7 — Host roles and software placement are plausible, but identical Linux background quotas across dissimilar systems weaken the lived-in fleet impression.

## Recommendations

- If this were synthetic, derive D-Bus, anacron, and other daemon counts from host role, uptime, initiating activity, and per-host collection behavior rather than assigning fixed family quotas.
- Model Internet UFW background with a much longer source tail and source-consistent TCP fingerprints. Avoid independently drawing the TCP window from a shared three-value pool on every packet for an otherwise stable source identity.
- If a recurring cron job is deliberately dropped, tie the omission to visible collection loss, service delay, host load, or scheduler state. Otherwise retain the configured cadence; random holes in a rigid grid are more conspicuous than either a complete schedule or a causally explained miss.
