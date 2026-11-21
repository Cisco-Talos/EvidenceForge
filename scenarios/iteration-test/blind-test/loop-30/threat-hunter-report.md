# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 27

## Executive Summary

The supplied six-hour slice is broadly production-like: suspicious activity can be investigated through technically coherent endpoint, authentication, network, file, and proxy pivots, while unrelated service traffic and administrative activity remain visible. I found no demonstrated impossible ordering or transport/file-accounting contradiction in the checks described below; a few shared background patterns leave modest reservations, so this is a qualified judgment rather than a claim of proven provenance.

## Evidence For Synthetic

- [weak_signal] Linux background telemetry shows a broad shared software footprint across unlike host roles. For example, `MAIL-EDGE-01.meridianhcs.local/syslog.log` contains `refresh candidates checked for microk8s` at `2026-11-02T13:23:31.236678Z`, and the same message occurs 18 times across six Linux hosts. `auto-refresh for lxd: no updates found` occurs 20 times across nine hosts. Shared images and centrally managed software could explain this; the messages do not establish an impossible installation or a collection contradiction, and receive little weight.
- [weak_signal] Some distinctive interactive commands recur across servers. Marcus Chen runs `udevadm info --query=property --name=/dev/null | head` in the bash histories of MAIL-EDGE-01, LOG-MON-01, and MAIL-CLIN-01, at epochs `1793624550`, `1793628866`, and `1793641133`. This could reflect a small command vocabulary, but the same administrator reusing a troubleshooting procedure is also a strong ordinary explanation. I do not count it as a hard behavioral defect.

## Evidence For Real

- Endpoint identities support useful lifecycle pivots. Across all 23 `ecar.json` files, the check of visible process CREATE and TERMINATE records against actorID-linked dependent records found no dependent action before its visible process creation or after its visible termination. Processes without visible starts or finishes were not penalized.
- Bidirectional Mac SSH activity preserves the actual transport tuples and distinguishes transport, authentication, shell activity, and close. The `10.10.1.42:54545 -> 10.10.1.41:22` connection is visible in `zeek-core/conn.json`, MAC-MROSS-02 outbound eCAR, MAC-MROSS-01 inbound eCAR, and MAC-MROSS-01 Unified Log public-key acceptance.
- The database export has technically ordered prerequisites and effects. DB-PROD-01 records dump creation, dump termination, gzip creation/termination, SCP execution, and the source-file read; APP-INT-01 records the matching incoming SSH session and destination-file creation.
- Network data contains failures and varied protocol behavior rather than only successful attack-related traffic. `zeek-core/dns.json` has A, AAAA, TXT, PTR, SRV, NS, MX, and SOA queries, including 206 NXDOMAIN, 12 SERVFAIL, and five REFUSED responses among 3,188 records. Connection logs contain successful, rejected, reset, unanswered, and partly observed states.
- The support upload has source-appropriate distinctions. The client's absolute proxy URI becomes an origin-relative URI upstream, multipart metadata and a gzip attachment receive separate file references, and the proxy records request bytes separately from its 96-byte response body. This makes the upload investigable without conflating its archive size with all request bytes.
- Windows hosts show varied operational evidence, including authentication failures, account management, lock/unlock, service creation, scheduled tasks, object access, and filtering-platform events. These coexist with the Linux and Mac evidence without requiring all hosts to use one native event schema.

## Detailed Analysis

### Scope and method

I examined only files under the supplied data directory. The visible window is approximately `2026-11-02 13:00–19:00 UTC`. There are 23 host directories with eCAR records: ten with Windows Security/Sysmon exports, eleven with Linux-style syslog, and two Macs with Endpoint Security and Unified Log exports. Apparent roles include two domain controllers, Windows and Linux file servers, a database server, an application/integration server, web and proxy infrastructure, mail servers, monitoring infrastructure, and user workstations.

The visible addressing spans `10.10.1.x`, `10.10.2.x`, `10.10.3.x`, and `10.10.4.x`. Collection also includes three Zeek vantage points, perimeter ASA logs, two Snort alert files, web access records, proxy records, and shell histories. Counts include 37,414 eCAR records, 17,780 Windows Security events, 11,606 Sysmon events, 4,089 Linux syslog lines, 23,141 Zeek connection observations, 4,379 proxy access lines, and 899 web access lines. Zeek totals include overlapping observations and should not be interpreted as distinct organization-wide connections.

I parsed the structured sources, followed selected suspicious and benign-looking activities, and tested visible identifier-linked lifecycles. I also checked every supplied Zeek HTTP record's request/response body length against its referenced connection's corresponding payload bytes, and every supplied file record's seen_bytes against its referenced connection's corresponding direction. These checks found no body/file payload exceeding its observed transport budget. They are bounded consistency checks, not a claim that every packet or native event field has been independently validated.

### Web execution and subsequent activity

`WEB-EXT-01.meridianhcs.local/ecar.json` lines 960–964 show Apache-owned execution of a base64-decoding shell pipeline at `14:20:27.968`, its `base64 -d` and `bash` children, and an outbound connection attributed to the bash child at `14:20:31.414`. The encoded command targets `45.33.32.30:8443`.

`zeek-dmz/conn.json` line 2170 independently records `10.10.3.10:48003 -> 45.33.32.30:8443`, UID `Ctm27uUQMZeRQHTLqj`, beginning at `14:20:31.482414`, with duration `22.413812`, SF state, and bidirectional payload. The bash child terminates at `14:20:59.920`, after the observed transport interval. This is a plausible short reverse-shell occurrence; the follow-on root SSH session is a separate observation and I do not infer an invisible privilege-escalation mechanism merely from temporal proximity.

The later root session on WEB-EXT-01 includes `nmap -sn 10.10.2.0/24`, a TCP connect scan of selected service ports, and reads of application configuration and root SSH material. These are useful hunt pivots, but their comprehensibility or coverage of an intrusion lifecycle does not contribute to the synthetic score.

### Database export and SCP

DB-PROD-01 eCAR shows root authentication from `10.10.2.30:39333` at `18:15:08.055`, followed by a shell and `mysqldump --single-transaction ehr patients insurance_claims` at `18:15:14.113`. `/tmp/rpt_0318.sql` is created at `18:15:15.413`; the dump ends at `18:15:27.952`. Gzip starts at `18:15:29.703`, creates `/tmp/rpt_0318.sql.gz`, and ends at `18:15:40.894`. SCP starts at `18:15:41.710` and reads that archive at `18:15:51.999`.

The SCP tuple is `10.10.4.10:49550 -> 10.10.2.30:22`. `zeek-core/conn.json` line 10909 and `zeek-db/conn.json` line 372 observe the tuple with separate sensor-local UIDs and roughly 23.4-second successful intervals. APP-INT-01 syslog lines 220–225 record connection, public-key acceptance, PAM session open, logind session 363, and close. APP-INT-01 eCAR line 796 records the received `/tmp/.cache/rpt_0318.sql.gz` at `18:16:08.581`.

Small differences between syslog, network, and eCAR timestamps are not intrinsically contradictions: these sources represent different observation points. I found no source-visible evidence here that the transfer required an uncreated source file, a failed authentication, or an already-terminated source SCP process.

### Mac activity and identity boundaries

For MAC-MROSS-02 to MAC-MROSS-01, `zeek-core/conn.json` line 6610 starts the SSH tuple at `16:02:02.087110`, with duration `956.893463`. MAC-MROSS-02 eCAR line 296 reports outbound FLOW at `16:02:02.587`; MAC-MROSS-01 line 323 reports inbound FLOW at `16:02:04.360`. MAC-MROSS-01 Unified Log then records public-key acceptance at `16:02:08.243284`, and eCAR LOGIN follows at `16:02:10.018`. The target logout at `16:18:11.839` occurs after the network interval's end, a plausible distinction between transport and session observation.

Mac Endpoint Security records distinguish fork from exec and carry audit-token credentials, parent identity, signing metadata, and execution-image transitions. I did not treat a fork's inherited image as the child's final command. I also did not require the Mac local UID 501 to equal the Linux directory UID for the same named user.

The `15:42:09.009673` Unified Log message concerning MeetingAssist says security policy would not allow the process. It does not by itself demonstrate successful execution, and I found no reason to attribute later effects to that application. Likewise, creation of an endpoint-inventory LaunchDaemon plist is a separate fact from the subsequent launchd/xpcproxy/sw_vers process observations; placement alone was not treated as activation.

### Proxy, files, and benign-looking ambiguity

The Linux support workflow includes downloading `/tmp/connector-check`, changing its mode, executing it, later creating `/tmp/mhs-support-48217.tar.gz`, and uploading diagnostics through the proxy. The same support domain appears in a Mac script-download workflow; a shared destination alone does not establish malicious execution or provenance.

At `16:32:04`, `zeek-core/http.json` line 1396 records a multipart request_body_len of 1,573,258 bytes. Its file record at `zeek-core/files.json` line 378 has 1,572,864 seen bytes for the gzip attachment. The difference is consistent with metadata and multipart framing. `PROXY-01.../proxy_access.log` line 2221 records `cs_bytes=1573700`, `wire_sc_bytes=253`, and a 96-byte response body. `zeek-dmz/http.json` lines 1578–1579 distinguish the absolute-form proxy request from the origin-form upstream request. I do not confuse these different accounting scopes.

### Background volume and reservations

Baseline activity is substantial enough to require pivoting: DNS, proxy sessions, mail, SMB, Kerberos, service communications, scanning, failures, and endpoint activity contribute different source-family volumes. The database sensor's 430 connection records versus 12,230 core and 10,481 DMZ observations fits distinct visibility and traffic roles; unequal counts are not evidence of collection failure by themselves.

10 Linux hosts have 36 visible `debian-sa1 1 1` executions and matching shell wrappers in the six-hour interval. A ten-minute sysstat schedule naturally explains this regularity, so I do not score the periodic count as a generator fingerprint. Similarly, the recurring troubleshooting commands belong to the same administrator, which substantially weakens the small-vocabulary concern. Broad snap-related chatter remains a low-weight environment question, not proof of synthetic records.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Linux syslog | Repeated snap refresh messages across multiple server and workstation roles | Small reservation about common software/background texture; shared Linux images are a plausible explanation. |
| weak_signal | Bash histories | A few distinctive commands reused by marcus.chen on several servers | Very small reservation about command-pool breadth; consistent operator habits are also plausible. |
| No material hard contradiction established | eCAR, Zeek, syslog, selected Mac/Windows pivots | Checks described above | Prevents a high synthetic score; does not prove production provenance. |

## Realism Score by Category

- **Field format accuracy:** 9 — Native and normalized sources remain distinguishable, with usable typed identifiers and payload/accounting fields in the examined records.
- **Temporal patterns:** 9 — The reviewed transport/authentication/process/file relationships are feasible; regular sysstat execution has an operational explanation.
- **Cross-source correlation:** 9 — SSH, SCP, reverse-shell, SMB, and proxy pivots preserve usable tuples and identities without the checked contradictions.
- **Behavioral realism:** 8 — Commands and effects are technically followable; a few repeated administrative habits leave modest uncertainty.
- **Environmental consistency:** 8 — Traffic mix fits differentiated roles, with only a weak reservation about the breadth of shared snap background activity.

## Recommendations

- If this were synthetic, make snap-related background messages conditional on each host's actual installed packages and service role. The broad lxd/microk8s/desktop-integration footprint is the clearest log-visible environment detail worth checking.
- If this were synthetic, ensure recurring interactive troubleshooting commands come from a consistent operator procedure or actual task context. The repeated `udevadm ... /dev/null` and old-log-counting commands should reflect that context; ordinary administrator reuse should be retained where appropriate.
- No lifecycle repair is justified by the consistency checks reported here. Preserve separate transport, authentication, process, and file observations and their source-specific timestamp meanings.
