# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 45

## Executive Summary

This is a technically coherent collection in which useful threat-hunting pivots survive checks across endpoint, authentication, network, proxy and file-service records. I found a small number of attribution and behavioral-texture questions, but no demonstrated hard contradiction strong enough to distinguish carefully synthesized telemetry from sanitized production data. The score reflects that uncertainty and leans slightly toward production-like appearance; the higher verdict confidence reflects confidence that the supplied evidence does not justify a categorical origin claim.

## Evidence For Synthetic

- [weak_signal] **Shell-redirection attribution deserves clarification.** `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history` records `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`. In that host's `ecar.json`, line 543 creates mysqldump PID 1418110 at 18:15:13.632 UTC and line 544 attributes `FILE/CREATE` for `/tmp/rpt_0318.sql` to mysqldump at 18:15:14.471. Ordinary shell redirection opens the output before executing mysqldump. This could reflect writer attribution or delayed normalization, so it is a semantic ambiguity rather than a proven impossible event.
- [distribution_texture] **Both Mac terminal histories draw heavily from the same narrow diagnostic vocabulary.** The 24 entries on `MAC-MROSS-01` and 23 on `MAC-MROSS-02` repeatedly use `id`, `sw_vers -productVersion`, `uname -a`, `ps aux`, `df -h`, `du -sh`, document-directory listings/finds and SSH. For example, Mac 01 has `sw_vers` at epoch 1793637213 followed by `id` at 1793637279; Mac 02 has `uname -a` at 1793637988 followed by `id` at 1793638030. The limited vocabulary is compatible with a command pool, but the same named user operates both machines and could reasonably repeat familiar commands. This receives little weight.

## Evidence For Real

- **Process ownership and lifetimes are internally coherent.** Across all supplied `ecar.json` files, matching visible process creation/termination records did not place an actor's dependent event before its creation or after termination. An independent check of Sysmon `ProcessGuid` relationships likewise found no such reversal among matching visible records. Pre-window processes were excluded from missing-creation judgments.
- **The SCP pivot has consistent endpoints, credentials and transport.** DB host PID 1418152 starts SCP at 18:15:40.207; its flow uses `10.10.4.10:39816 -> 10.10.2.30:22`. Core Zeek UID `CFqcpIZjj8rIp5WrNd8` starts at epoch 1793643342.812159 and lasts 34.665199 seconds. APP-INT syslog records the same source tuple, accepted public-key authentication for root and a PAM session.
- **SMB evidence preserves operational account boundaries.** A root process on APP-INT uses explicit `-U "svc_mhsync" --use-kerberos=off` credentials to write the staged database archive. FILE-LNX syslog identifies successful NTLMSSP authentication for `svc_mhsync`, the `ClinicalResearch` service and the matching destination path; Zeek observes the corresponding SMB write. Local root and directory service credentials are appropriately distinct.
- **A multipart upload has meaningful protocol detail.** The Linux workstation's curl command includes JSON metadata and a gzip attachment. Core Zeek UID `CMqguBmtRqdd7UGCoY` reports two originating file identifiers, JSON/gzip MIME types, a 1,573,258-byte request body and a named 1,572,864-byte gzip attachment. The proxy reports a matching POST and 96-byte response, while the DMZ sensor observes the separate forwarded leg.
- **Background activity is substantial and fits several host roles.** There are 17,454 Windows Security events, 11,378 Sysmon events, 36,902 normalized endpoint rows, 24,293 firewall lines and 22,567 Zeek connection records across sensors. HTTP, DNS, TLS, Kerberos, LDAP, MySQL, SMB, SSH, SMTP and DHCP all appear. These source totals overlap in what they observe and are not counts of independent user actions.
- **Benign-looking regularity has credible explanations.** Ten Linux hosts each show 36 `debian-sa1 1 1` processes in six hours, usually on a ten-minute schedule. That matches scheduled sysstat collection and should not be penalized as synthetic merely for being regular. Shell-history pipelines also explain apparently operand-free `head` and `tail` child process command lines.

## Detailed Analysis

### Collection scope and method

The supplied endpoint collection covers 23 named machines: ten Windows hosts with Security/Sysmon XML, 11 Linux hosts with syslog, and two Macs with Endpoint Security notifications and Unified Log records. Normalized endpoint records accompany these hosts. Network coverage includes core, DMZ and database Zeek sensors, a perimeter firewall, two Snort sources, a proxy and web access logs. Observed internal address families include `10.10.1.*`, `10.10.2.*`, `10.10.3.*` and `10.10.4.*`.

The principal collection window is approximately 2026-11-02 13:00–19:00 UTC. The normalized records contain 39 principal strings, including ten named human users, service identities, machine identities and local/system principals; these strings are not necessarily 39 distinct directory accounts.

I parsed the supplied JSON and Windows XML, counted event families, checked process identifier relationships, examined command histories and followed selected suspicious activity through multiple sources. I did not infer origin from directory names, filesystem modification times, sanitized domains, collection completeness or the ease of narrating the suspicious activity. This was not a field-by-field validation of every native schema.

### Web execution and subsequent investigation pivots

`WEB-EXT-01.meridianhcs.local/web_access.log`, line 449, records a successful POST to `/ehr/admin/upload.php` from `185.70.41.45` at 14:20:17. Endpoint records show Apache spawning a www-data shell at 14:20:29.870 with a base64-decoding pipeline. The encoded command directs an interactive bash connection to `45.33.32.30:8443`; DMZ Zeek UID `CvqTwwenIoCs2rwS82` observes `10.10.3.10:56043` reaching that address at epoch 1793629233.630931, approximately 14:20:33.631.

The visible request, process tree and outbound tuple therefore support a plausible code-execution hypothesis. They do not establish the uploaded object's contents, and the base64 shell alone does not prove later root access. Later root SSH sessions and credential-reading commands should remain separate findings unless additional evidence establishes their causal relationship. There is no authenticity penalty for a compact sequence here.

### Database access, staging and lateral file movement

APP-INT starts `ssh root@DB-PROD-01` at 18:14:40.900. DB endpoint records subsequently show a successful root session from `10.10.2.30:36513` at 18:15:06.806, followed by shell PID 1418102 and mysqldump PID 1418110. Mysqldump terminates at 18:15:27.238; gzip starts at 18:15:28.798, creates the `.gz` artifact at 18:15:32.745 and terminates at 18:15:38.327. SCP starts afterward at 18:15:40.207. That ordering is operationally plausible.

For the return SCP connection, APP-INT syslog lines 227–229 record connection establishment, public-key authentication and PAM session opening for `10.10.4.10:39816`; line 231 closes the PAM session at 18:16:17.723357. APP-INT endpoint records attribute creation of `/tmp/.cache/rpt_0318.sql.gz` to the receiver-side sshd. This supplies a practical route from source command to destination artifact.

APP-INT then starts smbclient PID 3431902 at 18:18:53.612. Core Zeek UID `CYoqsRNA7aV8jk8dG` observes `10.10.2.30:56819 -> 10.10.2.21:445`, and its SMB records name `Integration\\DB-Staging\\rpt_0318.sql.gz`. Zeek file UID `F9dI8pdgTIPYjEAy0A3` reports 108,865 bytes. FILE-LNX syslog lines 471–475 authenticate `svc_mhsync` and record successful open/write/close operations on `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`.

The normalized endpoint timestamps run later than the corresponding server-native and network observations in some places. Without a documented normalization timestamp contract, I have not treated small source offsets as impossible ordering. The specific stdout-file attribution question remains a weak concern because file creation, first-write attribution and collection time are different concepts.

### Proxy upload and download pivots

On `WS-LNGUYEN-01`, the archive-producing tar command begins at 16:44:46.557 and its output file is created at 16:44:50.501. The upload curl process begins at 16:44:56.835. The command explicitly specifies a proxy, JSON metadata and the archive filename. Core Zeek sees a proxy-facing absolute-form POST URI; the DMZ sees both that client-facing request and a separate origin-facing request to `52.44.186.73:80` using the relative resource path. Those are useful distinctions between the two HTTP legs.

The body is larger than the named gzip attachment by 394 bytes, leaving room for metadata and multipart framing. The metadata part has its own file-analysis identifier without requiring a filename. I found no mismatch here that would justify an authenticity penalty.

For the Mac download, proxy logs record the HTTPS `connector-check.sh` request under `maya.ross@meridianhcs.local` at 13:48:44. Core Zeek records CONNECT traffic to the proxy on client port 51002, and the Mac Endpoint Security stream records execution of the Homebrew curl path before the download. Later bash execution of the downloaded script is a separate visible fact; the download itself is not treated as execution.

### Windows and macOS interpretation

Windows Security events include process creation/termination, successful and failed logons, network filtering, Kerberos, privilege and share-access records. Domain controllers carry large Kerberos/LDAP-related volumes, while workstation volumes are smaller. Sysmon binary hashes were consistent across repeated Event 1 instances of the same image within a host in the supplied records; I found no per-execution hash churn.

The Mac stream distinguishes fork, exec and exit observations, and normalized records preserve same-PID exec transitions rather than treating every image change as a new process. Unified Log contains an AppleSystemPolicy message at 15:42:09.009673 stating that policy would not allow MeetingAssist. That message alone is insufficient to infer a definitive enforcement result or subsequent execution, and I did not use it to allege a contradictory child process. Likewise, the endpoint-inventory plist writes are file-placement evidence; they do not independently prove registration, activation or unload.

### Signal and noise

The suspicious operations are embedded in substantially larger background collections. Administrative pipelines, service traffic, authentication failures, package maintenance and scheduled system accounting supply usable alternative explanations for many individual alerts. Neither complete pivotability nor thin native Mac coverage establishes origin under this collection design.

The repeated Mac command vocabulary is the principal behavioral-texture reservation. Its weight is limited because the two histories belong to the same person and contain different timings, targets and some different commands. I did not find enough evidence of unrealistic source volume, impossible host-role behavior or lifecycle failure to move the score into the likely-synthetic range.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Linux shell history and normalized endpoint file telemetry | One mysqldump stdout-redirection operation on DB-PROD | Small concern: creation is attributed to the writer after exec, but normalization/observation semantics are unknown. Not a demonstrated hard contradiction. |
| distribution_texture | macOS shell histories | Two hosts, 47 history entries for the same named user | Small concern: narrow repeated diagnostic vocabulary is compatible with templating, but also with habitual administration. |

No confirmed `hard_contradiction` or independently established lifecycle `contract_gap` was found in the relationships checked. Neither weak concern supports a confident synthetic verdict on its own.

## Realism Score by Category

- **Field format accuracy:** 8 — Parseable and source-appropriate overall; native schema details were sampled rather than exhaustively verified.
- **Temporal patterns:** 8 — Visible process dependencies and selected transfer sequences are coherent; cross-source observation offsets limit stronger conclusions.
- **Cross-source correlation:** 9 — SSH, SCP, SMB, HTTP and proxy pivots preserve useful tuples, paths and account relationships.
- **Behavioral realism:** 8 — Plausible operational commands and background activity, with some repetitive diagnostic vocabulary on the Macs.
- **Environmental consistency:** 8 — Mixed operating systems, host roles and credential boundaries fit the visible activity; no required unsupported collection assumption was needed.

## Recommendations

- If this were synthetic, make stdout-redirection file ownership explicit: distinguish the shell's pre-exec file open/create from subsequent writes by mysqldump, or document the normalized record's writer-attribution and timestamp semantics. The DB-PROD example is currently ambiguous.
- If this were synthetic, review the two Mac histories' diagnostic command distributions against the intended user's role and repeated workflows. Preserve legitimate command reuse, while ensuring the narrow vocabulary is an intentional behavioral model rather than an incidental pool limitation.
- Preserve the observed separation of proxy legs, multipart metadata/file analysis, SSH transport/authentication/session evidence, SMB credential namespaces and same-PID macOS exec transitions; these features materially improve the plausibility and utility of the collection.
