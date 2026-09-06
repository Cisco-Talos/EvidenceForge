# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 74

## Executive Summary

The endpoint collection is unusually strong in its process-tree construction, lifecycle pairing, build-aware hashes, and Security/Sysmon/eCAR alignment. However, two repeated Windows identity defects—the malformed subset of network-logon records and near-universal zero Sysmon LogonGuids for ordinary user processes—look like systematic generation-path artifacts rather than production collection effects; a smaller eCAR lifecycle inversion reinforces that conclusion.

## Evidence For Synthetic

- [schema_or_format] A distinct family of 151 Security Event 4624 Type 3 records on DC-01, DC-02, and FILE-SRV-01 has four defects in lockstep: blank `SubjectUserSid`/`SubjectUserName`/`SubjectLogonId`, blank `LogonGuid`, blank `LogonProcessName`, and a `WorkstationName` equal to the receiving host rather than the remote source represented by `IpAddress`. For example, `FILE-SRV-01.../windows_event_security.xml` at `2024-03-18T12:01:43.5384061Z` identifies `diego.ramirez` arriving from `::ffff:10.10.1.34`, yet says `WorkstationName=FILE-SRV-01` and leaves all of those source/logon fields empty. The same exact field-shape occurs 76 times on FILE-SRV-01, 47 times on DC-01, and 28 times on DC-02.
- [contract_gap] Sysmon Event 1 gives `{00000000-0000-0000-0000-000000000000}` as `LogonGuid` for 231 of 235 non-`NT AUTHORITY` process creations, even though those records carry nonzero, stable `LogonId` values. At `2024-03-18T12:24:54.7293878Z`, WS-AJOHNSON-01 records Teams under `MERIDIANHCS\aisha.johnson`, `LogonId=0x25137ac`, but a zero LogonGuid; the same zero persists through `cmd.exe` and `ssh.exe`. By contrast, all four non-system process creates on DC-02 at 17:51 use the same nonzero `{13527211-20df-4b7f-847a-d629d2ca533c}` LogonGuid with `LogonId=0xcd65001`. That split between 231 ordinary-user records and four exceptional records is a strong path-dependent fingerprint.
- [contract_gap] One eCAR process lifecycle is visibly inverted within the same source. On WS-AJOHNSON-01, Teams utility PID 6212 is created at epoch-ms `1710778237468`, terminated at `1710778237492`, and then emits seven `MODULE/LOAD` rows from `1710778237497` through `1710778237575`. The final `rpcrt4.dll` load is timestamped 83 ms after termination. The corresponding Sysmon record places process creation at `2024-03-18 16:10:37.306` and termination at `16:10:37.467`, so Sysmon itself is coherent; the defect is localized to eCAR lifecycle timing.
- [distribution_texture] Linux baseline noise is dominated repeatedly by `irqbalance` and `snapd` chatter across unrelated hosts. In six hours, `irqbalance` contributes 35–115 records on each of APP-INT-01, DB-PROD-01, FILE-LNX-01, LOG-MON-01, MAIL-CLIN-01, MAIL-EDGE-01, and WEB-EXT-01, often logging IRQ classifications every few minutes; `snapd` contributes 34–89 records on most of the same servers. That broad, repeated daemon mix is more uniform and much noisier than I would expect from healthy servers without visible service restarts, hotplug activity, or debug-level context.
- [weak_signal] WEB-EXT-01 contains 841 UFW block messages but 840 of them come from only eight recurring external source addresses. Each source retains a perfectly fixed packet length and TTL across the full six hours (for example, all 151 packets from `145.78.103.167` are length 52/TTL 118, and all 139 from `38.186.148.245` are length 60/TTL 118) while TCP windows cycle among only 1024, 14600, and 65535. Scanner fingerprint stability is plausible, but this small closed vocabulary is noticeably model-like.

## Evidence For Real

- Windows process correlation is excellent without relying merely on coverage as an authenticity clue: 926 Sysmon Event 1 rows align with 930 Security 4688 rows by host, PID, image, and parent image. The four Security-only rows are plausible collection drops. For matched rows, Sysmon precedes Security by roughly 35–650 ms, a believable source-native ordering offset rather than bit-identical timestamps.
- Process trees contain convincing role- and OS-specific chains: `services.exe` launches service binaries; `SearchIndexer.exe` launches search protocol/filter hosts; user `explorer.exe` launches browsers, Office applications, Teams, shells, and admin tools; Linux `sshd -> bash` and `cron -> sh -> debian-sa1` chains are represented naturally.
- Sysmon hashes are stable for a binary build and vary coherently with Windows builds. For example, `svchost.exe` uses the same 10.0.20348.1 SHA1 on both domain controllers and MAIL-FIN-01, 10.0.17763.1 on FILE-SRV-01, 10.0.19041.1 on the corresponding workstation cohort, and 10.0.22621.1 on the newer workstation cohort.
- Apart from the one eCAR Teams anomaly, visible lifecycle ordering is strong: no eCAR process termination precedes its matching visible creation, no eCAR logout precedes its matching visible login, and no Sysmon network/image/file/registry/DNS event occurs after a visible Event 5 termination for the same ProcessGuid. Unpaired starts or ends are expected in a six-hour slice and were not penalized.
- Linux SSH sequences look source-native and operationally plausible. APP-INT-01, for example, shows `Accepted` authentication, PAM session open, systemd-logind session creation, later PAM close, and session removal with stable sshd PID and variable delays. Pre-window sessions that close during the slice were treated as valid boundary effects.
- User behavior is differentiated. Lina Nguyen shows development/operations tooling (`git`, `npm`, Docker, Kubernetes, SSH); Omar Haddad uses Python/pandas, CSV, and database clients; Aisha Johnson performs host/log review; server-local commands and paths are OS-appropriate. Bash-history timestamps and endpoint process evidence generally support these distinctions.
- The host collection has realistic source variation rather than one universal schema: Windows hosts expose Security, Sysmon, and eCAR; Linux systems expose RFC 5424-style syslog, bash history, and eCAR; role-specific services include SMB auditing, Postfix/Dovecot, proxy activity, and web-host firewall noise.

## Detailed Analysis

### Windows logon and session evidence

I parsed 433 Security 4624 Type 3 records. Most Kerberos and NTLM records have plausible source-native values, but 151 form a sharply different family: 76 on FILE-SRV-01, 47 on DC-01, and 28 on DC-02. Every member simultaneously blanks the subject triplet, LogonGuid, and LogonProcessName and writes the destination's short hostname into WorkstationName.

The IP/host contradiction is reproducible from the logs themselves. At `2024-03-18T12:06:14.2779266Z`, DC-01 records `aisha.johnson` from `10.10.2.27`; endpoint FLOW records identify that address with MAIL-FIN-01, yet the 4624 says `WorkstationName=DC-01`. At `12:09:09.0021837Z`, DC-01 receives `marcus.chen` from `10.10.2.11`, whose endpoint records identify DC-02, but again reports `WorkstationName=DC-01`. Equivalent target-name substitution repeats across workstation, server, and domain-controller sources. A real collector can omit WorkstationName, but systematically substituting the receiver while also blanking the other authentication fields is not a credible collection gap.

Outside that family, session mechanics are good. Service logons use the expected reserved identities (`0x3e7`, `0x3e5`, `0x3e4`), Type 7 unlocks reuse an existing interactive LogonId, and I found no same-identifier 4634 preceding a visible 4624. I did not penalize unmatched logins/logouts because the supplied window is only six hours.

### Sysmon and process trees

Security 4688 and Sysmon Event 1 are internally consistent at scale. Images and ordinary parent images match, process identifiers are reused coherently, ProcessGuids are stable across Event 1/3/5/7/11/13/22, and source-native timestamp offsets are small but nonidentical. Process metadata is also richer than a shallow template: versions, product descriptions, original file names, build-dependent hashes, parent command lines, integrity levels, and user principals vary plausibly.

The LogonGuid field is the exception. Across 926 Event 1 records, 235 run as non-`NT AUTHORITY` users. Of those, 231 have an all-zero LogonGuid. This affects six ordinary users on eight hosts and persists across interactive shells, browsers, Office applications, Teams children, and SSH clients while their LogonIds remain populated. The only four nonzero examples are a tight DC-02 process cluster (`cmd.exe`/`sc.exe`) at 17:51. In a lived-in Sysmon collection, user-session GUID availability would not normally divide this cleanly by one exceptional execution path.

Process lifetime distribution is varied: 1,685 eCAR creations have visible matching terminations, with a median lifetime of about 8.0 seconds and a long tail beyond one minute. Short command processes coexist with long-lived GUI/service processes. The sole hard lifecycle blemish is WS-AJOHNSON-01 PID 6212, whose eCAR termination sits between its first and remaining module loads. Because these are timestamps inside one eCAR source and share the exact process UUID, PID, principal, image, and LogonId, this is a concrete visible ordering defect rather than a missing-boundary complaint.

### Linux host evidence

SSH and sudo lifecycles are generally convincing. Authentication methods, key fingerprints, UIDs, TTYs, source ports, PAM open/close lines, and logind session IDs remain coherent. Command histories show different operational roles and include ordinary alias/pipeline/background-command behavior. eCAR process records preserve Linux paths and parentage instead of leaking Windows defaults.

The baseline daemon distribution is less convincing. `irqbalance` is among the highest-volume applications on almost every Linux server—59 records on APP-INT-01, 46 on DB-PROD-01, 67 on FILE-LNX-01, 78 on LOG-MON-01, 35 on MAIL-CLIN-01, 51 on MAIL-EDGE-01, and 115 on WEB-EXT-01. Similar `snapd` state-engine chatter recurs across the fleet. Individual messages are plausible, but this level and cross-host regularity make the systems feel populated from a common noise recipe rather than from each daemon's normal production logging rate.

### Cross-source endpoint consistency

The strongest realistic feature is shared process truth. PIDs, principals, paths, and parent relationships align between Security, Sysmon, and eCAR; Windows binary hashes remain build-coherent; Linux SSH and shell processes align with syslog and bash history. I did not treat that completeness as synthetic. The synthetic assessment instead rests on specific contradictions and field-shape discontinuities: target-as-workstation Type 3 records, zero-vs-nonzero LogonGuid path separation, and one same-source process lifecycle inversion.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `schema_or_format` | Windows Security 4624 | 151 repeated records on three hosts | High: four malformed/source-inconsistent fields recur as one exact event family. |
| `contract_gap` | Sysmon Event 1 / Windows logon identity | 231 of 235 non-system process creates | High: ordinary sessions lose LogonGuid while one exceptional execution path preserves it. |
| `contract_gap` | eCAR process/module lifecycle | One process, seven post-termination module rows | Medium-low: concrete visible inversion, but isolated and sub-100-ms. |
| `distribution_texture` | Linux syslog | Fleet-wide recurring daemon mix | Medium: unusually noisy, repeated `irqbalance`/`snapd` baseline across distinct roles. |
| `weak_signal` | WEB-EXT-01 UFW syslog | 840 of 841 blocks from eight closed-vocabulary scanners | Low: possible real scanner fingerprints, but distribution is unusually bounded. |

## Realism Score by Category

- **Field format accuracy:** 6 — Most schemas and values are strong, but the repeated malformed 4624 family and zero Sysmon LogonGuids are material source-native defects.
- **Temporal patterns:** 8 — Broad timing and lifecycles are realistic; one eCAR process terminates before seven of its module loads.
- **Cross-source correlation:** 8 — Security, Sysmon, eCAR, syslog, and shell evidence correlate very well, with the logon-identity exceptions above.
- **Behavioral realism:** 8 — Process trees, user roles, commands, services, and session behavior are varied and plausible.
- **Environmental consistency:** 7 — Host roles and build cohorts are coherent, but repeated Linux daemon-noise rates and bounded firewall-source vocabulary reduce realism.

## Recommendations

- If this were synthetic, make the network-logon producer render a complete source-native 4624: use the remote workstation represented by the source IP (or `-` when unavailable), populate the standard unknown subject placeholders rather than empty strings, and provide a plausible LogonProcessName/LogonGuid contract for the selected authentication package. Test the same invariant across DC and file-server receivers.
- If this were synthetic, derive Sysmon LogonGuid from the canonical logon session for every process created in that session. Preserve one GUID across all children sharing a LogonId and reserve the all-zero GUID for identities or source conditions where Sysmon would genuinely lack session correlation.
- If this were synthetic, apply source-local lifecycle timing coherently so process termination cannot precede module, network, file, registry, or other dependent events for the same ProcessGuid/process UUID. The WS-AJOHNSON-01 Teams utility process is a focused regression case.
- If this were synthetic, reduce and diversify fleet-wide `irqbalance` and `snapd` rates according to host role, daemon state, and logging level; unusually chatty periods should have visible service, hardware, update, or diagnostic context.
- If this were synthetic, widen long-window firewall scanner populations and per-source TCP fingerprints, while retaining stable fingerprints where a single scanner genuinely reuses one stack.
