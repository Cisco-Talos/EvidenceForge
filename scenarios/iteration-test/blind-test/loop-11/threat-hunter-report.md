# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 40

## Executive Summary

This is predominantly production-like, usable hunting telemetry: the remote-access, account-management, file-staging and log-clearing pivots I examined generally preserve process identity, account boundaries and operational ordering. A few narrow behavioral and timing distributions suggest possible construction, but I did not establish a hard contradiction; those observations do not justify a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-02.meridianhcs.local/ecar.json`, seven process modifications execute `/bin/cat /Volumes/...` against PDF, DOCX or XLSX files: 13:37:11.492, 16:05:49.005, 17:10:44.236, 17:12:28.121, 18:37:47.244, 18:42:07.758 and 18:44:51.571 UTC. Repeatedly treating office documents as terminal-readable content is a weak behavioral texture concern, especially alongside visible Word and Outlook launches. It is technically possible, including for inspection or collection; it is not evidence that any execution failed.
- [weak_signal] In the 14 Windows Security 4624 Type 10 events I matched to `zeek-core/conn.json` by source IP and source port, transport-open-to-logon delays occupy a relatively narrow 7.50–9.65 second range across different users, targets and sessions. For example, DC-01 authentication at 13:49:11.671 follows transport open at 13:49:02.023; MAIL-FIN-01 authentication at 17:53:05.646 follows transport open at 17:52:56.227. This could reflect a shared access stack or collection timing; I assign it little weight rather than treating the valid ordering itself as suspicious.

## Evidence For Real

- The apparent fleet and source mix are coherent: 23 endpoint directories include Windows servers/workstations, Linux hosts and two Macs; three network sensors distinguish core, DMZ and database traffic. `zeek-db/conn.json` is dominated by MySQL, while core traffic has much more DNS, Kerberos and LDAP. These are role-appropriate differences, not a uniform source mixture.
- The SSH round trip between the two Macs is pivotable without conflating client execution, authentication and remote commands. The 14:24 connection from 10.10.1.41:55702 to 10.10.1.42:22 precedes the receiver's accepted authentication; the 16:02 reverse connection uses a different tuple and authentication method.
- The DB-to-application staging sequence has linked shell, process, file, SSH, syslog and network evidence. The archive exists before the visible SCP read, and the subsequently staged SMB artifact is accounted for by an actual SMB write rather than an unrelated connection.
- DC-01's Security log clear has the expected visible record-number discontinuity: EventRecordID 28260940 precedes Event 1102 with EventRecordID 1 at 18:42:21.7269251, then IDs 2, 3 and 4. This is a useful source-native detail rather than merely a narrative reference to clearing logs.
- Background telemetry contains meaningful operational variation: cron/sysstat execution, package and service maintenance, Samba workers, DNS/LDAP/Kerberos traffic, unsuccessful SSH credentials and proxy failures. For example, APP-INT-01 records a failed `svc_mgmt` password at 16:15:49.658659 followed by a pre-authentication close, without claiming a successful session.
- Broad identity checks found no native Sysmon event referring to a visible ProcessGuid before its creation or after its termination. The eCAR checks likewise found no source-process reference more than one second outside a visible process lifetime. This supports internal usability without making completeness itself an authenticity indicator.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The apparent collection interval is approximately 2026-11-02 13:00–19:00 UTC. There are 37,903 eCAR records across 23 endpoint directories, including 27,906 FLOW/CONNECT, 2,629 PROCESS/CREATE and 2,458 PROCESS/TERMINATE observations. Counts are observations, not an inventory of all enterprise activity or unique connections across sensors.

The network sensors contain 12,434 core, 10,347 DMZ and 413 database connection records. Other sources include Windows Security and Sysmon XML, Linux syslog and bash histories, macOS Endpoint Security notifications, Unified Log records and zsh histories, plus proxy, firewall, IDS, web, DNS, TLS, SMTP, DHCP and SMB evidence. The smaller database source contains 242 MySQL connections, 47 DNS and eight SSH connections; the core contains 2,137 Kerberos and 1,200 LDAP connections. The endpoint set and network-observed address space are not interchangeable: scans also account for numerous destination addresses without corresponding endpoint directories.

I parsed the endpoint records and performed whole-file identity checks, then followed selected suspicious and ordinary activities across native and normalized sources. I did not assume missing event families were required, treat pre-window lifetimes as errors, or require all products to expose the same timestamps.

### Remote access and identity boundaries

The Mac-to-Mac SSH connection in `zeek-core/conn.json` opens at 14:24:27.940965, UID `CGo2qddyIzWfTDX7EH`, from 10.10.1.41:55702 to 10.10.1.42:22. The receiver's Unified Log accepts `maya.ross` using keyboard-interactive/PAM at 14:24:35.064556. The receiver then exposes SSH process and shell activity; normalized eCAR records around 14:24:35.921–35.927 should not be interpreted as native fork timestamps because these are different observation sources.

The reverse connection opens at 16:02:00.587030, UID `CKbmYt3SGSOC3Knes`, from 10.10.1.42:55467 to 10.10.1.41:22. MAC-MROSS-01's Unified Log accepts public-key authentication at 16:02:06.488664. Native Endpoint Security records on both Macs have process start times no later than their containing notification timestamps in the records checked. I did not reinterpret Endpoint Security notifications as authorization decisions.

I matched all 14 visible Windows Type 10 Security logons to source-IP/source-port TCP/3389 connections. The sampled connections are substantial successful transports, not rejected probes being mislabeled as interactive logons. For example, WS-AJOHNSON-01's logon from LT-MRIVERA-02 at 16:01:26.972279 follows the 16:01:19.473951 connection, whose duration is 1086.841751 seconds and whose responder payload is 1,837,923 bytes. The delay range is a modest texture concern, not an ordering defect.

### File acquisition and staging

On DB-PROD-01, root's bash history records `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`, then gzip, then SCP. The eCAR dump process, PID 1418110, appears at 18:15:14.261, with creation of `/tmp/rpt_0318.sql` at 18:15:15.263. Its command line excludes shell redirection, which is consistent with the shell passing only executable arguments to the process. The dump terminates at 18:15:35.052, before gzip starts at 18:15:36.103.

The SCP process is PID 1418187, UUID `c9622b9c-e5dd-4de8-970d-4391dde72345`, created at 18:16:00.545. Its transport from 10.10.4.10:47846 to 10.10.2.30:22 opens at 18:16:03.536882 on the core sensor and 18:16:03.608526 on the DB sensor. APP-INT-01 syslog accepts root at 18:16:09.120201; the source's eCAR file read occurs at 18:16:10.091. Different sensor UIDs and small timestamp differences are plausible local observations.

APP-INT-01 later runs `smbclient` as root while supplying `svc_mhsync` as the remote SMB account. The different local process and remote share principals are valid account boundaries. Core UID `CbXT2PUpitp8uYgQ7` connects 10.10.2.30:54031 to 10.10.2.21:445 at 18:18:56.375771. `smb_files.json` opens `Integration\DB-Staging\rpt_0318.sql.gz` at 18:18:56.858839 and writes 15,100 bytes at 18:18:56.950488. `files.json` reports the same FUID `F7zc2B4aAkbUaou0aDg`, complete 15,100-byte accounting and SHA256 `965ff6b7f55b2cd2ac5d4d23ba1355be1b354f22c8ce0bd865ef85ee5eca4897`. FILE-LNX-01's eCAR write attributes the destination path to `svc_mhsync` through an NTLMSSP directory-account session. Endpoint observation latency alone does not make the later endpoint timestamp impossible.

### Directory changes and cleanup

DC-01's process evidence runs `net user svc_dirsync ... /add /domain` at approximately 17:15:02. Security Event 4720 creates the account at 17:15:06.0899101 using a consistent target SID ending in 9258; Event 4728 adds that SID to Domain Admins at 17:15:11.7495796. The later delete command at 18:50:26 is followed by Event 4726 at 18:50:30.2066969. The native effects support the commands; the conclusion does not depend on a storyline label.

The visible `wevtutil cl Security` process is followed by Event 1102 and a restart of Security record numbering. Retaining pre-clear exported records is compatible with forwarding or a collected slice, so I do not treat their continued presence in the export as a contradiction.

### Noise and negative checks

Scheduled sysstat work repeats 36 times on several Debian-like hosts during the six-hour slice. A ten-minute maintenance schedule explains this repetition; identical task counts are not automatically synthetic. Other source families have varied roles and outcomes rather than every record looking like attacker activity.

Across the three Zeek connection files, I found no case where recorded transport payload bytes exceeded that side's IP byte count. HTTP transactions with responses were not attached to S0/REJ connections, and failed CONNECT transactions did not have TLS companions on their same local UID. Per-host Sysmon process-create hashes were stable for each image/version combination; an initial mixed-event comparison was discarded because DLL-load hashes describe modules, not the owning executable. These checks reduce several common false-positive authenticity claims.

The seven Mac binary-document `cat` commands remain my clearest behavioral reservation. They could be deliberate inspection or collection, and I cannot establish from the records that they were intended as normal document viewing. The small Unified Log exports and absence of Endpoint Security file notifications are not scored as defects because filtering can explain their coverage.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | macOS eCAR process commands | Seven binary-document `cat` executions on MAC-MROSS-02 | Small upward contribution: repeated technically valid but unusual document-access behavior; no failed-action claim |
| weak_signal | Windows Security and core Zeek | Fourteen matched RDP logons with 7.50–9.65-second transport-to-authentication delays | Very small upward contribution: narrow timing spread may reflect construction, but shared access behavior or collection can explain it |
| No demonstrated hard contradiction | Native and normalized process, network and authentication records examined | Whole-file identity checks plus selected cross-source hunts | Keeps the score below the mixed/strong synthetic bands; this is a limit on findings, not proof of real origin |

## Realism Score by Category

- **Field format accuracy:** 9 — Native and normalized formats support practical parsing and pivots; no demonstrated impossible field value in the checks performed.
- **Temporal patterns:** 8 — Operational sequences are coherent, with a mildly narrow RDP authentication-delay distribution.
- **Cross-source correlation:** 9 — SSH, RDP, SMB and account-management pivots preserve identities and distinguish source-local timestamps.
- **Behavioral realism:** 7 — Strong tradecraft and background activity overall; repeated terminal reads of binary office documents are a limited concern.
- **Environmental consistency:** 9 — Platform, service role, account boundaries and sensor traffic mixes generally agree.

## Recommendations

- If this were synthetic, review why MAC-MROSS-02 repeatedly uses `cat` for PDF/DOCX/XLSX access. Preserve those commands where terminal inspection or collection is intended; use application-driven access where the intended behavior is reading documents normally.
- If this were synthetic, verify that the observed RDP transport-to-authentication delay range comes from the actual modeled handshake and authentication behavior. Add variability only where the underlying access methods or network conditions justify it; do not perturb already-correct ordering solely to create noise.
- Retain the concrete lifecycle and native-effect details already visible, especially Security record-number reset after Event 1102, distinct local and remote account identities, and transport-before-authentication relationships.
