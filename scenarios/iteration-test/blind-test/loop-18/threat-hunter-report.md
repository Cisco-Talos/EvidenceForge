# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 45

## Executive Summary

The dataset supports technically useful hunts through Windows credential use and SMB staging, Mac SSH sessions, and a Linux database dump and transfer. I found limited hints of templated background activity and one questionable normalized file-creation attribution, but did not establish an impossible native lifecycle or a decisive origin fingerprint; these findings do not justify a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] Linux irqbalance telemetry repeatedly samples a very small message vocabulary across different servers. For example, `WEB-EXT-01.meridianhcs.local/syslog.log` contains 155 irqbalance messages but only four distinct message bodies; `FILE-LNX-01` has 68/four, `LOG-MON-01` 70/four, `APP-INT-01` 67/four, and `DB-PROD-01` 52/four. On WEB-EXT-01, “IRQ 86 affinity hint keeps vector on CPU 2 (mlx5_comp1)” appears 47 times and “IRQ 86 classified for CPU 2 balancing on mlx5_comp1” 44 times. Recurrent daemon diagnostics are plausible, but the repeated four-message structure across unrelated server roles mildly suggests a bounded template pool.
- [contract_gap] `DB-PROD-01.meridianhcs.local/ecar.json`, record 445, attributes `FILE/CREATE /tmp/rpt_0318.sql` to mysqldump PID 1418111 at 18:15:15.680 UTC. The corresponding root shell history records `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql` at epoch 1793643314. A shell normally opens a redirected output file before executing the command; this record instead presents the utility as its creator after its visible process creation at 18:15:14.955. This is a narrow ownership/normalization concern, not proof of an impossible native syscall: the normalized CREATE action could conflate creation with first observed output.
- [weak_signal] The network exposes two substantial UDP/514 destinations: LOG-MON-01 (`10.10.2.40`) and FILE-LNX-01 (`10.10.2.21`). Of 342 core-sensor syslog-service connections, 114 target the file server, including 18 from the log monitor itself. Yet FILE-LNX-01 syslog record 7 explicitly describes `omfwd: target 10.10.2.40 using disk-assisted queue local-spool`. A file server can also act as a relay/archive collector; the records do not establish that this is wrong. It is an environmental ambiguity with very low evidential weight, rather than a contradiction.

## Evidence For Real

- Windows netonly credentials preserve the distinction between local execution identity and remote authentication identity. At approximately 18:00:45 on WS-AJOHNSON-01, Security 4648 names outbound `marcus.chen`, Security 4624 Type 9 retains local `aisha.johnson` and records `TargetOutboundUserName=marcus.chen`, and the resulting cmd.exe retains aisha's local identity with LogonId `0x27c9905`. Sysmon Event 1 agrees with that new session. This is materially better than simply changing every source to the outbound account.
- The DB dump/transfer hunt has workable process, file, transport, authentication, and receiver pivots. APP-INT-01 initiates root SSH to DB-PROD-01; DB authentication precedes its shell, dump, gzip and scp; APP-INT-01 then records receipt of the compressed file. The reverse SCP leg uses a different source port and authentication method from the initial interactive login.
- Independent network observations differ plausibly. For the SCP tuple `10.10.4.10:58224 -> 10.10.2.30:22`, the DB sensor records UID `COd5HRT39dG0PaqT4`, 79 originating packets and zero missed bytes; the core sensor records UID `CzxQgBBIjsRZwregi`, 78 originating packets, 1,203 missed bytes and history `ShADadfFG`. This supports sensor-specific observation rather than an erroneous demand that independent sensors share identifiers or capture identical packets.
- Mac process telemetry distinguishes forks from exec image transitions, carries audit-token identity and pidversion changes, and uses `/Users/...` and native macOS executable paths. Download and shell execution are separately visible for connector-check.sh. The MeetingAssist policy message is not accompanied by a claimed successful MeetingAssist execution in the reviewed endpoint records.
- The collection includes background failed/unfinished network states, privileged maintenance, DHCP renewal, cron, package-management and daemon chatter rather than only suspicious commands. Core connection states include 1,624 S0, 458 OTH, 168 RSTO, 119 RSTR and 42 REJ records alongside 9,925 SF records.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, parsing endpoint JSON, native Windows XML, Mac Endpoint Security and Unified Log JSON, shell histories, syslog and Zeek records. The endpoint records cover approximately 13:00–19:00 UTC on 2 November 2026. There are 23 endpoint directories and six additional sensor/firewall/IDS directories. Visible endpoints include ten Windows systems, eleven Linux systems and two Macs; the network spans at least 10.10.1.0/24 through 10.10.4.0/24. Scanned addresses are not equivalent to confirmed deployed hosts.

Record totals include 37,971 normalized eCAR records, 17,663 native Windows Security events, 11,573 Sysmon events, 23,125 Zeek connection records across three sensors, 4,496 syslog lines, 324 Mac Endpoint Security notifications and five Unified Log records. XML physical line counts would substantially overstate Windows event volume. I treated the small Unified Log export as filtered collection, not a full host log archive.

I checked process object identities and actor/source-process references against visible eCAR create/terminate events, allowing five seconds for minor collection timing differences. I also checked native Sysmon process GUID dependencies against visible Event 1/Event 5 lifecycles with a two-second tolerance. These checks did not produce a demonstrated substantial use-before-create or use-after-termination contradiction. They are bounded checks, not proof of universal correctness. System logon IDs and authentication daemon creation before user authentication are not valid lifecycle violations.

### Windows credentials and staging

WS-AJOHNSON-01 is a strong hunt pivot. At 18:00:41.985 Sysmon Event 1 records runas.exe PID 6176 using `/netonly /user:marcus.chen`; Security 4688 records the same PID as `0x1820`. Explicit-credential Event 4648 follows at 18:00:45.1659092, followed by Type 9 Event 4624 at 18:00:45.4385406. Its new local session is `0x27c9905`; the child cmd.exe PID 6192 appears at 18:00:45.562 in Sysmon. This order is technically coherent.

The ensuing PowerShell commands stage five Finance files, a clinical CSV and three research files into `C:\ProgramData\Microsoft\VaultCache\...`, then compress them into `C:\ProgramData\Microsoft\cache_7f3a.zip`. eCAR records 932–936 show the five Finance destinations at 18:01:14.401–18:01:15.206; records 965–967 show the Research destinations; record 977 records the resulting ZIP at 18:01:40.112. These are useful artifact pivots. Their compact timing is not an authenticity defect by itself.

DC-01 supplies later high-risk activity: encoded PowerShell under SYSTEM at 18:42:16, then cmd.exe and wevtutil.exe clearing Security around 18:42:17. Native process IDs and parent relationships are traceable. I did not infer success for arbitrary effects merely from the presence of a command line.

### Linux database theft candidate

APP-INT-01 eCAR record 800 records root's SSH client PID 3431393 at 18:14:40.547. Zeek-core record 10885 records the resulting `10.10.2.30:52259 -> 10.10.4.10:22` transport at epoch 1793643294.746343. DB-PROD-01 syslog records the connection at 18:14:58.650286 and accepted password at 18:15:07.496703, then PAM/session establishment. Its eCAR shell PID 1418103 starts at 18:15:09.522, followed by mysqldump PID 1418111 at 18:15:14.955.

After the dump terminates, gzip starts at 18:15:34.725 and produces `/tmp/rpt_0318.sql.gz` at 18:15:38.673. SCP starts at 18:15:42.334 and reads that existing archive at 18:15:51.768. Its separate reverse connection is `10.10.4.10:58224 -> 10.10.2.30:22`; APP-INT-01 accepts publickey authentication at 18:15:51.021793 and records the receiver file `/tmp/.cache/rpt_0318.sql.gz` at 18:16:11.937. The original interactive SSH session lasts until approximately 18:53, consistent with a long-running transport rather than an arbitrarily short placeholder.

The specific defect candidate is the output file CREATE attribution described above. The root history does contain the missing shell redirection, so the absence of `>` in mysqldump's executable command line is correct and is not itself a finding. The concern is ownership and timing of file creation, with normalization semantics limiting its strength.

### Mac activity and source interpretation

MAC-MROSS-01's native Endpoint Security record 36 shows curl exec at 13:48:41.201976 into `/opt/homebrew/opt/curl/bin/curl`, downloading `/Users/maya.ross/Downloads/connector-check.sh`. Record 39 separately shows `/bin/bash .../connector-check.sh --check-config` at 13:49:08.207155. Download is therefore distinguishable from execution.

The SSH client exec at 14:24:14.163644 is followed on MAC-MROSS-02 by launchd/xpcproxy/sshd transitions beginning 14:24:30 and a Unified Log acceptance message at 14:24:34.657611 for maya.ross from `10.10.1.41:59300`. MAC-MROSS-02 later initiates SSH in the reverse direction with `-tt`, and MAC-MROSS-01 records accepted publickey authentication from `10.10.1.42:63330` at 16:02:06.829781. Different authentication methods and distinct tuples provide practical hunt pivots without conflating the Macs' local account namespace with directory credentials.

The 15:42:09 AppleSystemPolicy message saying policy “would not allow” MeetingAssist is a policy observation. I found no basis here to claim either a successful malicious launch or a denial followed by impossible execution. Similarly, an endpoint-inventory plist CREATE/DELETE pair does not establish registration or activation of that launch item.

### Baseline and collection texture

Background distributions fit different roles reasonably: the DB sensor has 234 mysql-service connections among 364 total connections, while the DMZ sensor has 3,197 ssl and 2,842 http-service connections among 10,384. A source-family mix weighted toward network permits and network flows is plausible for this collection. All three sensors passed the specific checks for an established SSL session attached to an S0/REJ flow and HTTP response status attached to a connection with zero response bytes.

The Linux diagnostic vocabulary remains my main texture concern. The same four-way irqbalance message pattern recurs across many servers, although IRQ numbers, hardware labels, NUMA nodes and CPU assignments vary. A uniformly configured diagnostic collection could explain this; I therefore did not elevate it into a hard contradiction. Likewise, the 36 sysstat cron invocations on each of ten hosts over six hours are consistent with a ten-minute schedule and are not evidence against authenticity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux syslog / irqbalance | Multiple servers; e.g. WEB 155 messages/four bodies, FILE-LNX 68/four | Mild upward pressure from repeated bounded vocabulary across roles; diagnostic logging remains a plausible explanation. |
| contract_gap | Normalized Linux process/file evidence and shell history | One reviewed DB dump output file | Moderate local concern about shell-versus-utility creation ownership; normalization ambiguity prevents a hard-contradiction claim. |
| weak_signal | Network syslog routing and Linux forwarding messages | 114 of 342 core syslog-service connections target FILE-LNX-01 | Very small contribution; dual collection/relay roles could explain it. |

No demonstrated generator identity leak, impossible source-native field value or decisive visible lifecycle contradiction was established. The score remains in the mixed/inconclusive band rather than the likely-synthetic band.

## Realism Score by Category

- **Field format accuracy:** 9 — Native XML/JSON parses, and reviewed platform identities and process transitions are credible; the normalized file CREATE semantics remain uncertain.
- **Temporal patterns:** 8 — Reviewed SSH, dump, compression and staging phases have workable order; recurring diagnostic texture warrants caution.
- **Cross-source correlation:** 9 — Native credential semantics, distinct transports and sensor-specific capture differences support useful pivots.
- **Behavioral realism:** 8 — Commands and account boundaries largely work together; one redirected-file attribution is questionable.
- **Environmental consistency:** 8 — Service mix fits visible roles overall, with a plausible but unconfirmed secondary syslog destination.

## Recommendations

- If this were synthetic, represent shell redirection file creation with the shell's ownership and timing, and distinguish initial file creation from later writes by mysqldump in normalized telemetry.
- If this were synthetic, validate the repeated irqbalance message distributions against an actual diagnostic collection from comparable server roles, retaining genuine repetitions while avoiding a fixed small pool sampled independently of daemon state.
- If this were synthetic, make the FILE-LNX-01 secondary syslog collection/relay role agree with visible service and forwarding evidence when that role is intended. If it is not intended, route those UDP/514 streams to the actual collector.
