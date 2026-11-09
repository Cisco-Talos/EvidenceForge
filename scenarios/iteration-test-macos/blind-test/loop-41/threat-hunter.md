# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 81
**Synthetic-Confidence Score:** 64

## Executive Summary

The collection supports technically coherent hunting across Windows, Linux, macOS, and network sources, with credible account boundaries and usable lateral-movement pivots. My synthetic verdict rests on a specific repeated timing fingerprint in the two Macs' interactive command activity, rather than the completeness or readability of the suspicious activity. I found no demonstrated hard contradiction in the intrusion trails I followed, so the score remains near the lower end of “likely synthetic.”

## Evidence For Synthetic

- [distribution_texture] The same rank-dependent command delays recur across two separate Mac terminal histories despite different commands and widely separated execution times. `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history` lines 1–3 have gaps of 21 and 48 seconds; the corresponding lines 1–3 on MAC-MROSS-02 have exactly 21 and 48 seconds with the command sequence shifted one place. Later bursts independently share gaps of 30, 37, 44, and 51 seconds. This is a repeated numeric scheduling pattern, not merely repeated use of routine commands.
- [distribution_texture] The timing fingerprint survives examination of native Endpoint Security event timestamps, ruling out second-resolution history formatting as its sole cause. MAC-MROSS-01 ES lines 76 and 79 execute `ifconfig` and `dscl` at 15:22:49.113033 and 15:23:33.112340, a 43.999307-second gap; MAC-MROSS-02 ES lines 90 and 93 execute `dscl` and `sw_vers` at 15:31:15.664982 and 15:31:59.667179, a 44.002197-second gap. A differently positioned command pair receives essentially the same 44-second delay. These bullets describe one underlying indicator and are not counted as independent defects.

## Evidence For Real

- The Windows `/netonly` activity preserves the distinction between local process identity and outbound credentials. On WS-AJOHNSON-01, `ecar.json` line 1019 shows `runas.exe /netonly /user:marcus.chen`, line 1027 records a Type 9 session retaining local principal `aisha.johnson` and outbound principal `marcus.chen`, and FILE-SRV-01 Security records at 18:01:11.6059105 identify `marcus.chen` arriving from 10.10.1.35:55269. That is a meaningful, technically correct authentication pivot.
- The SQL staging trail has coherent prerequisites and ownership: DB-PROD-01 `ecar.json` lines 493–507 show SSH login, shell, dump, compression, then SCP; APP-INT-01 lines 753–764 show the matching inbound tuple, successful root SSH session, receiver-side file creation and closure. The transfer precedes the subsequent SMB upload.
- The apparent reverse-shell connection is rendered as ordinary TCP rather than automatically mislabeled TLS because it uses port 8443. WEB-EXT-01 `ecar.json` lines 811–814 and `zeek-dmz/conn.json` line 1743 agree on 10.10.3.10:54918 → 45.33.32.30:8443; the network row has no `service: ssl` field.
- Proxy inspection is explicit where decrypted HTTPS content is visible. `PROXY-01.meridianhcs.local/proxy_access.log` line 3388 identifies the archive POST with `proxy_action=ssl-inspect ssl_bump=bump`, avoiding an unexplained claim that an ordinary passive TLS sensor recovered an encrypted URI and body.
- A same-identity audit across all endpoint JSON files found no PROCESS action or actor-attributed FLOW occurring more than two seconds after the corresponding visible PROCESS TERMINATE, and no child CREATE more than two seconds before its visible parent CREATE. These bounded checks do not prove all lifecycle relationships correct, but they provide substantial counterevidence to a simplistic event assembly.

## Detailed Analysis

### Scope and hunting method

I inventoried only the supplied data. There are 23 endpoint directories containing normalized endpoint telemetry: ten with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two with macOS Endpoint Security and Unified Log exports. Supporting sources include three Zeek sensor directories, two Snort sources, a perimeter ASA log, proxy access logs, web access logs, and timestamped shell histories. The visible window is approximately 2026-11-02 13:00–19:00 UTC.

Parsed volumes include 35,813 endpoint JSON rows, 18,978 Windows Security events, 11,676 Sysmon events, 22,030 Zeek connection rows, 3,800 proxy rows, 3,796 syslog rows, and 836 web access rows. The Windows XML physical line counts are much larger than their event counts, so I did not mistake pretty-printed XML lines for event volume. Source volume alone did not establish an authenticity defect: the network sensors overlap, domain controllers have much more authentication/network activity than individual workstations, and collection may intentionally be selective.

I followed process/session identities, command lines, source tuples, share paths, and proxy destinations. Absent pre-window initiators, post-window closure, deliberately excluded Sysmon event types, and thin source coverage were treated as neutral.

### A repeated interactive timing fingerprint

The strongest evidence comes from comparing two terminal histories for `maya.ross`:

| MAC-MROSS-01 history lines and activity | MAC-MROSS-02 history lines and activity | Shared gap |
|---|---|---|
| 1–2: `id` → `sw_vers`, 13:07:47 → 13:08:08 | 1–2: `sw_vers` → `uname`, 13:11:50 → 13:12:11 | 21 s |
| 2–3: `sw_vers` → `uname`, 13:08:08 → 13:08:56 | 2–3: `uname` → `pwd`, 13:12:11 → 13:12:59 | 48 s |
| 4–5: `pwd` → `ls`, 13:48:35 → 13:49:05 | 4–5: `ls` → `du`, 14:12:26 → 14:12:56 | 30 s |
| 8–9: `df` → `ps`, 14:38:18 → 14:38:55 | 6–7: `ps` → `find`, 14:51:55 → 14:52:32 | 37 s |
| 12–13: `ifconfig` → `dscl`, 15:22:49 → 15:23:33 | 9–10: `dscl` → `sw_vers`, 15:31:15 → 15:31:59 | 44 s |
| 15–16: `sw_vers` → `id`, 16:34:22 → 16:35:13 | 13–14: `uname` → `id`, 16:45:31 → 16:46:22 | 51 s |

The later repeated delays form a 30, 37, 44, 51-second progression. MAC-MROSS-01 lines 18–19 add a 58-second gap, and MAC-MROSS-02 lines 19–20 add 65 seconds. The command types vary while the apparent slot delay advances by seven seconds. This combination of rotated vocabulary and arithmetic timing across separate work periods is substantially more suspicious than ordinary recurring administration commands.

Native ES corroborates that these are actual execution intervals rather than only shell-history rounding. In addition to the 44-second example, MAC-MROSS-02 ES lines 15 and 18 execute `uname` at 13:12:11.643314 and `pwd` at 13:12:59.641751, a 47.998437-second gap; MAC-MROSS-01 ES lines 12 and 15 execute `sw_vers` at 13:08:08.615159 and `uname` at 13:08:56.621262, a 48.006103-second gap.

Real automation could produce deterministic delays, and one user operating two hosts can repeat a workflow. The histories do not establish whether a human or a script entered every command. That alternative limits my confidence and keeps this out of `hard_contradiction`; nevertheless, this many matched command-independent intervals and their arithmetic progression strongly favor generated activity.

### SQL collection and Linux staging

DB-PROD-01 `ecar.json` line 493 places root authentication from APP-INT-01's 10.10.2.30 at 18:15:11.496. Line 494 creates the shell at 18:15:13.260; line 495 starts `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:17.553. Dump termination precedes gzip creation (lines 497 and 499), gzip termination precedes SCP creation (lines 501–502), and the SCP flow uses source port 53008 (line 504).

`zeek-core/conn.json` line 11001 and `zeek-db/conn.json` line 384 observe that same 10.10.4.10:53008 → 10.10.2.30:22 transfer. Both show successful SSH transport with approximately 19.18 seconds duration, 25,675 originator bytes and 28,876 responder bytes. APP-INT-01 syslog lines 219–224 independently show connection, accepted public key, PAM opening, logind session creation, and closure. Receiver file creation at 18:16:20.287 in APP-INT-01 endpoint line 761 occurs while the sender SCP process remains alive until 18:16:20.517.

APP-INT-01 endpoint line 774 then starts an SMB upload of the received path at 18:19:19.421. `zeek-core/smb_files.json` lines 187–188 and FILE-LNX-01 syslog lines 535–537 agree on `ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`, the source IP, and successful write. The visible SMB write is 10,464 bytes, so I found no basis for claiming the earlier SSH byte count could not carry the staged file. The small database export is not itself impossible.

### Windows collection and outbound transfer

The Type 9 session's local/outbound identity split is handled correctly. WS-AJOHNSON-01 endpoint lines 1049–1119 show share discovery/copy commands followed by `Compress-Archive` and creation of `C:\ProgramData\Microsoft\cache_7f3a.zip`. FILE-SRV-01 Security records at 18:01:06 carry `marcus.chen`, a shared target logon ID `0xf885880`, and Finance paths; its 18:01:11.6059105 network logon and subsequent ClinicalExports accesses use `marcus.chen` from the same workstation.

WS-AJOHNSON-01 endpoint line 1199 starts `curl.exe` with an explicit 10.10.3.20:8080 proxy and the archive upload URL at 18:24:54.488. Proxy line 3388 records the POST at 18:24:58, with client source port 62702 and 18,783,090 client bytes. Zeek DMZ connection line 8487 records the separate proxy egress leg, 10.10.3.20:50391 → 45.33.32.30:443, with 18,809,754 originator bytes and a 7.818767-second successful connection. The larger TLS transport count is compatible with the application upload and does not require byte-for-byte equality.

The endpoint retains `aisha.johnson` for the local upload while the earlier share access uses outbound `marcus.chen`; I did not mistake that distinction for contradictory user attribution. I also did not score the ease of following this chain, its completeness, or the presence of multiple attack phases as synthetic evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS zsh history, corroborated by Endpoint Security execution events | Two hosts; repeated bursts from 13:07 through 18:25 | Matched command-independent 21/48-second gaps and a later 30/37/44/51-second progression strongly suggest a common scheduling template. This is the principal positive indicator. |

No independently demonstrated hard contradiction, schema defect, or required companion omission was used in the score. The finding is concentrated in one behavioral family; strong cross-source operational coherence constrains the assessment.

## Realism Score by Category

- **Field format accuracy:** 9 — Parseable native and normalized sources; no verified format contradiction in the examined trails.
- **Temporal patterns:** 5 — Correlated lifecycle order is credible, but the repeated Mac command delays expose a strong scheduling fingerprint.
- **Cross-source correlation:** 9 — Authentication, SSH/SCP, SMB, and explicit proxy pivots preserve useful identities and tuples.
- **Behavioral realism:** 7 — Suspicious actions technically connect; interactive Mac command timing is mechanically patterned.
- **Environmental consistency:** 9 — Mixed platform roles and relative source activity are plausible within a bounded, selective collection.

## Recommendations

- If this were synthetic, replace the shared rank-based terminal delays with per-session timing tied to command duration, user intent, and independent pauses. Validate that unrelated command pairs on different machines do not inherit the same arithmetic sequence of delays.
- If the repeated Mac commands represent real scripted checks, make their automation provenance observable where the collection supports it, such as the actual invoking script or controlling shell command. That would distinguish intentional scripted polling from purported interactive activity without inventing extra telemetry coverage.
- Preserve the existing local-versus-outbound credential distinction, SCP receiver lifecycle, SMB path agreement, and explicit proxy-inspection semantics when varying the baseline timing.
