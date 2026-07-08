# Host/EDR Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 46

## Executive Summary

The endpoint data is largely coherent and production-like: Windows Security/Sysmon lifecycles, process GUIDs, hashes, SSH session ordering, and bash history alignment mostly hold together. I did not find a hard contradiction, but repeated Linux `sudo` session formatting and one inconsistent `sshd` publickey success line are concrete enough to keep this out of the "indistinguishable from real" range.

## Evidence For Synthetic

- `schema_or_format` - Across seven Linux hosts, I found 47 `sudo` PAM sessions opening `admin(uid=1001)` as `by (uid=0)` with no matching `sudo ... COMMAND=` line for the same PID. Example: `APP-INT-01.meridianhcs.local/syslog.log` lines 16 and 146 show PID `837939` opening/closing an admin sudo session, but no command line, while normal sudo-to-root records in the same file include `COMMAND=...` at lines 2-3 and 28-30.
- `schema_or_format` - `APP-INT-01.meridianhcs.local/syslog.log` line 393 logs `Accepted publickey for root ... ssh2` without key type or SHA256 fingerprint, while 63 of 64 publickey successes include the normal `ssh2: <keytype> SHA256:...` suffix. The same host includes fingerprinted publickey successes at lines 128, 172, 215, 226, 267, and others.
- `distribution_texture` - Bash/admin command content is plausible but somewhat pool-like: 290 timestamped bash history commands with 218 unique commands, with repeated checks such as `journalctl -u systemd-resolved --since today --no-pager | tail -20`, `tail -200 /var/log/auth.log`, and `iostat -x 1 3` recurring across hosts. This is a weak signal only.

## Evidence For Real

- Windows Security and Sysmon files are internally ordered: EventRecordIDs are monotonic, timestamps do not regress, and I found no Sysmon ProcessGuid lifecycle contradiction.
- Sysmon hash behavior is realistic: repeated image/module paths have stable hashes within each host, and common Windows binaries did not show obvious same-version hash drift across checked hosts.
- SSH lifecycles look source-native in many places. Example: `APP-INT-01.meridianhcs.local/syslog.log` lines 80-83 show connection, accepted password, PAM open, and logind new-session ordering for `marcus.chen`; lines 124-125 later close/remove the same session.
- RDP/process sequencing is mostly coherent. For `WS-MCHEN-01` to `DC-01`, source process creation precedes network permit: Security 4688 at `12:21:34.916`, Sysmon process create at `12:21:35.589`, source Security 5156 at `12:21:37.363`, and target DC 4624 Type 10 at `12:21:37.661`.
- Bash history aligns with endpoint/server evidence. `DB-PROD-01` root history shows database dump and `scp` at `17:30:44`; `APP-INT-01` records the inbound root SSH and file creation at `/tmp/.cache/rpt_0318.sql.gz` shortly after.

## Detailed Analysis

Windows endpoint telemetry is the strongest realism area. Across Windows Security/Sysmon XML files, I found no EventRecordID decreases, no timestamp decreases, no duplicate EventRecordIDs, and no visible Sysmon process events occurring after termination or before a later visible create for the same ProcessGuid. Security/Sysmon pairing for process create, network, and terminate events generally follows provider-realistic timing.

Linux syslog has good texture: cron/anacron jobs are host-offset rather than synchronized globally, SSH sessions include normal connection/auth/PAM/logind/close sequences, and bash histories include small human artifacts such as `ca`, `clear`, and host-specific operational commands. The main weakness is the repeated `sudo`-opened admin shell pattern with no command audit line, which appears systematic rather than an isolated dropped line.

Cross-source correlation is mostly too coherent to dismiss as fake, but not in a way I am treating as synthetic by itself. The RDP case where Sysmon/eCAR source network rows sometimes land slightly after target logon is explainable by provider timestamping because source Security 5156 precedes target authentication in the checked sample.

## Synthetic Indicator Summary

| Category | Affected Source Family | Scope | Score Impact |
|---|---|---:|---|
| `schema_or_format` | Linux syslog | 47 sudo admin sessions across 7 hosts | Moderate |
| `schema_or_format` | Linux syslog/sshd | 1 publickey success on APP-INT-01 | Low |
| `distribution_texture` | Bash history/syslog commands | Repeated admin command pool | Low |

## Realism Score by Category

- **Field format accuracy:** 74 - Strong Windows/Sysmon format, weakened by Linux sudo/publickey quirks.
- **Temporal patterns:** 82 - Ordered lifecycles, realistic jitter, no hard visible causality failures found.
- **Cross-source correlation:** 84 - RDP, SSH, process, and file evidence mostly aligns.
- **Behavioral realism:** 70 - Lived-in admin activity, but command pools repeat somewhat.
- **Environmental consistency:** 76 - Host roles and endpoint activity are plausible, with some noisy but explainable privileged access.

## Recommendations

- For Linux `sudo` session modeling, emit the corresponding `sudo ... COMMAND=` audit line when opening an admin shell, or use a more source-native service name if the session is not actually created by sudo.
- Normalize `Accepted publickey` sshd messages so the same daemon/config consistently includes key type and fingerprint.
- Increase long-tail bash/admin command diversity and host-specific operator habits to reduce repeated command-pool texture.
