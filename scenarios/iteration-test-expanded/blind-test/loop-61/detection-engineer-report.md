# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 32

## Executive Summary

I would not call this confidently synthetic. The data shows strong source-native coherence across Windows Security, Sysmon, eCAR, Zeek, proxy, ASA, web, and Linux syslog records, with no hard contradictions found in timestamps, IDs, tuples, or lifecycle ordering. The remaining synthetic signal is mostly weak: the export is highly normalized and unusually well-correlated, but that is explainable by the stated collection profile.

## Evidence For Synthetic

- **[weak_signal]** `COLLECTION_PROFILE.json` describes normalized JSON exports and source-timestamp-sorted host files. That makes the dataset cleaner than many raw SIEM exports, but it is an export/collection artifact rather than a source-native contradiction.
- **[distribution_texture]** Some low-level service texture is thin relative to the broader network volume, for example `zeek-dmz/ntp.json` contains only 2 NTP rows while other Zeek families are much denser. This is minor because the profile allows source-level gaps and it does not contradict visible activity.
- **[weak_signal]** Cross-source correlation is unusually complete: Zeek protocol UIDs/fuids resolve cleanly, SSH syslog tuples match Zeek, and Windows Security/Sysmon/eCAR process records line up tightly. I weighted this lightly because the matches are internally valid, not impossible.

## Evidence For Real

- Windows Security XML uses plausible Event IDs, field names, SIDs, LogonIDs, GUIDs, paths, and `%%` token values; I did not find malformed EventData/UserData structures.
- Zeek `conn`, `dns`, `http`, `ssl`, `files`, `x509`, and protocol fan-out are structurally consistent: child records reference existing UIDs/fuids and fall within parent connection windows.
- SSH sessions have realistic Linux syslog ordering: connection, accepted authentication, PAM open, systemd-logind session, command activity, and close records.
- Windows process lifecycle and logon lifecycle relationships are coherent: no termination-before-create or logoff-before-logon issues were found for visible same-window records.
- Perimeter/proxy evidence lines up plausibly with internal activity, including proxy access rows, ASA build/teardown records, Zeek HTTP/files rows, and web access noise.

## Detailed Analysis

Windows Security on `DC-01` has credible domain-controller activity: 4768/4769 Kerberos records, 4624/4634 logon lifecycle, 4688/4689 process lifecycle, 4697 service installation, 4698 scheduled task creation, and 1102 audit-log-clear evidence. Example: at `2024-03-18T12:05:58Z`, user `diego.ramirez` receives a TGT from `::ffff:10.10.1.34` with AES enctype `0x12`; nearby 4769 records show service ticket activity such as `cifs/DC-01` from `::ffff:10.10.2.20`.

The suspicious Windows chain is source-native coherent rather than merely narrative-complete. On `DC-01`, `aisha.johnson` has a Type 3 logon around `2024-03-18T16:00:09Z` from `10.10.1.35`, followed by 4697 service creation for `PSEXESVC`, 4688 process creation for `C:\Windows\PSEXESVC.exe`, and child commands such as `cmd.exe /c whoami && hostname`. Later, at `2024-03-18T16:15:27Z` through `16:15:32Z`, `net user svc_mhsync ... /add /domain` and `net group "Domain Admins" svc_mhsync /add /domain` are reflected in 4720, 4724, 4738, and 4728 records with consistent domain SIDs.

Process correlation also held up. Sysmon Event ID 1 process creates, Event ID 5 terminates, and Security 4688/4689 records did not show same-host termination-before-create defects. Hashes for Sysmon process images and loaded images were internally consistent per host; I did not find the same path receiving contradictory hashes in the visible records.

Zeek correlation is strong. Protocol logs reference existing `conn.log` UIDs, and timestamps sit within the associated connection interval. SSL certificate chains resolve through `files` and `x509`; HTTP response fuids resolve through `files`. One example is a large MSI download visible through proxy and network telemetry: proxy access records show `DuoWindowsLogon64.msi` at `2024-03-18T12:04:38Z`, with matching Zeek HTTP/files evidence and ASA build/teardown records carrying plausible byte counts.

Linux SSH evidence is also well ordered. For an SSH session to `WEB-EXT-01`, syslog shows connection and accepted publickey authentication, followed by PAM/session open and later close; eCAR records contain matching `USER_SESSION` and process activity. Bash history entries such as `last -20` and `journalctl -u sshd --since '2 hours ago'` align with eCAR process-create timing inside the active session.

The strongest synthetic tells are not hard contradictions. They are mainly that the collection is highly normalized, very cleanly sorted, and unusually complete across sources. In a real MSSP pipeline, this could still happen after ETL normalization or a curated case export, so I would not score it as confidently synthetic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected score |
|---|---|---:|---|
| weak_signal | Collection/export profile | Dataset-wide | Normalized, sorted exports are cleaner than many raw SIEM pulls, but explicitly documented by the profile. |
| distribution_texture | Zeek service logs | Narrow | NTP volume is very sparse compared with broader Zeek volume; minor because no visible contradiction is created. |
| weak_signal | Cross-source correlation | Dataset-wide | Correlation completeness is unusually strong, but field values and timing are source-native coherent. |

## Realism Score by Category

- **Field format accuracy:** 88 — Windows XML, Zeek JSON, syslog, proxy, ASA, and web formats are largely source-native and valid.
- **Temporal patterns:** 84 — Event ordering is credible, with endpoint tail behavior explained by the collection profile.
- **Cross-source correlation:** 92 — UIDs, fuids, tuples, PIDs, LogonIDs, sessions, and process chains line up well.
- **Behavioral realism:** 82 — Attack and background activity are plausible, with service, user, proxy, SSH, web, and perimeter texture.
- **Environmental consistency:** 80 — Host roles, IP ranges, SIDs, domains, and source visibility are consistent, though somewhat curated.

## Recommendations

If this were synthetic, I would add more low-level background texture for sparsely represented sources such as NTP and other routine infrastructure chatter. I would also preserve a bit more realistic export unevenness, such as partial source delays or less-perfectly sorted normalized files, while keeping the strong canonical correlations that already make the data behave well in a SIEM.
