# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 48

## Executive Summary

The six-hour window on November 2, 2026 contains several actionable sequences, including a root SSH session from the exposed WEB-EXT-01 host into APP-INT-01, a database dump copied from DB-PROD-01, and an external support-log upload from WS-LNGUYEN-01. Those sequences are supported by multiple source families and show realistic noise around them. I found no hard cross-source contradiction; the broad, repetitive background activity and generic shell-history texture leave some uncertainty about whether the dataset is synthetic.

## Evidence For Synthetic

- [weak_signal] Linux shell histories across APP-INT-01, DB-PROD-01, LOG-MON-01, MAIL-EDGE-01, and other hosts contain recurring generic diagnostics (`journalctl`, `systemctl`, `ss`, `df`, `uptime`, `hostname`). The commands fit those systems, but the repeated vocabulary and short, curated-looking history excerpts offer limited evidence of lived-in host variation. This is weak on its own and does not affect the verdict strongly.
- [weak_signal] The public-facing WEB-EXT-01 records repeated inbound probes from a small recurring set of external addresses across unrelated service ports. That may be ordinary internet scanning; the visible slice does not establish an implausible rate or pattern, so I treat it only as a weak texture signal.

## Evidence For Real

- Root SSH to APP-INT-01 from WEB-EXT-01 is independently visible in endpoint, host authentication, and network alert records. The tuple is `10.10.3.10:35039 → 10.10.2.30:22`; the target eCAR flow is at 15:15:19.430 UTC, the SSHD process appears at 15:15:23.724, and `root` login succeeds at 15:15:26.930. APP-INT-01 syslog records the same source and port, with password acceptance at 15:15:25.387 and session opening at 15:15:25.453. Snort flags the same SSH tuple at 15:15:17.995, consistent with observing the connection attempt before endpoint/session evidence.
- The APP-INT-01 root session is followed by `cat /etc/passwd` and `cat /etc/shadow` at 15:35:12.258 and 15:35:15.040, then a history-clearing command at 18:41:08.442 that writes `/root/.bash_history`. The same logon ID (`0x1525520c`) ties these events to the root session, which logs out at 18:57:12.766. These are strong hunt leads, not authenticity defects.
- A separate DB-PROD-01 root history sequence at 18:15 UTC runs `mysqldump` for `ehr`, `patients`, and `insurance_claims`, gzips the result, and uses `scp` to copy it to APP-INT-01 as `/tmp/.cache/rpt_0318.sql.gz`. APP-INT-01 records a root SSH session from `10.10.4.10` at 18:16:05.909 and a file create at 18:16:11.392 for that same path. The source history, target session, and target file event make the pivot feasible.
- WS-LNGUYEN-01 records Lina Nguyen creating `/tmp/mhs-support-48217.tar.gz` from EHR connector logs and POSTing it to `support.valeworks-health.net` at 16:40 UTC. Zeek core and DMZ HTTP logs, proxy access, DNS, firewall, endpoint process/file events, and the file-analysis record agree on the host, destination, URI, archive, and transfer size within normal protocol overhead. Verify the destination and ticket through the organization’s approved support process.
- Mac SSH evidence is similarly pivotable: MAC-MROSS-01’s outbound tuple to MAC-MROSS-02 uses source port `53075`; the receiving Mac records the matching SSH login from `10.10.1.41:53075`. Maya Ross’s later connection to APP-INT-01 also matches the target’s inbound flow and login tuple.
- Most reviewed process and session lifecycles are plausible within the visible window. The flows include both attributed and unattributed records, and I did not treat missing initiators or terminators outside that window as defects.

## Detailed Analysis

### Environment and collection

The data covers a mixed Windows, Linux, and macOS fleet, with eCAR on endpoints and servers, Windows Security/Sysmon on selected Windows hosts, macOS Endpoint Security and Unified Log exports on two Macs, Linux syslog and shell histories, and network telemetry from Zeek, proxy, firewall, and Snort sources. Most host eCAR files cover roughly 13:00–19:00 UTC. Several high-volume roles are visible: domain controllers, an application server, database and file servers, a proxy, and an internet-facing web server. I judged source coverage against this visible mix and did not penalize missing sources by themselves.

### Root SSH and host activity

At 14:40:43.790, APP-INT-01 syslog records an SSH connection from WEB-EXT-01; it is an invalid-user attempt and fails. At 15:15:19, the same source opens the successful root SSH connection described above. The exposed web server initiating privileged SSH into an application server is unusual and merits investigation. The successful root session’s `/etc/shadow` access and later history clearing strengthen the security concern. WEB-EXT-01’s matching eCAR FLOW lacks PID/principal attribution; however, many flows on that host are also unattributed, so this limits source-process attribution without demonstrating a collection contradiction.

The follow-on database transfer is distinct from that earlier session: APP-INT-01 records the later root SSH source as `10.10.4.10`, matching DB-PROD-01 and the copied file. Treating these as separate connections avoids conflating two roots and two source hosts.

### External upload and network pivots

At 16:39:34.571, WS-LNGUYEN-01 eCAR records `tar` creating the support archive from `connector.log` and `queue.log`. At 16:40:04.584, `curl` runs a multipart POST to `/api/v1/cases/MHS-48217/attachments`; the endpoint reads the archive at 16:40:20.741. Zeek core records the POST from `10.10.1.21:56692` to proxy `10.10.3.20:8080`, a 1,573,258-byte request, and the archive as a 1,572,864-byte file. The proxy logs the same POST, ticket, user, and archive at 16:40:20 with `cs_bytes=1573396`. Zeek DMZ records the proxy’s onward HTTP connection to `52.44.186.73:80`; the firewall builds and tears down that same proxy-side tuple. The small byte-count differences are compatible with multipart and transport overhead, not a concrete defect.

### Texture and authenticity limits

Baseline administrative commands and public-service probes provide context, but the excerpted histories are short and many entries use common diagnostic commands. This is a weak distribution signal only: host roles and operator work explain much of it, and I found no quantified implausible event volume or distribution. The suspicious sequences being easy to narrate or well-correlated does not count against authenticity. Complete cross-source matching is positive pivot evidence here, not a synthetic clue. I found no visible dependent event that demonstrably precedes its visible initiator, and no source-native field contradiction in the reviewed chains.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `weak_signal` | Linux bash histories | Multiple hosts and users | Repeated generic diagnostic vocabulary may indicate curated baseline texture, but remains plausible and contributes only modestly. |
| `weak_signal` | WEB-EXT-01 eCAR/network alerts | Public-facing host | Recurring scanners across service ports may be generated red herrings, but are plausible internet noise without a demonstrated rate defect. |

No `hard_contradiction` or confirmed `contract_gap` was identified in the reviewed evidence.

## Realism Score by Category

- **Field format accuracy:** 8 — The reviewed eCAR, syslog, Zeek, proxy, and firewall records use coherent source-native shapes; no material schema issue was established.
- **Temporal patterns:** 8 — The key login, process, transfer, and file events occur in plausible order with small sensor-specific timestamp offsets.
- **Cross-source correlation:** 9 — SSH tuples, identities, files, proxy activity, and network records provide workable pivots; this alignment is not scored as a synthetic clue.
- **Behavioral realism:** 7 — The mix of admin work, user activity, background services, and suspicious actions is plausible; shell-history variation is somewhat generic.
- **Environmental consistency:** 7 — Roles and paths mostly make sense, though root SSH from the exposed web server to the application host is a high-risk behavior requiring operational explanation.

## Recommendations

- If this were synthetic, vary benign Linux shell-history vocabulary and session context where multiple hosts currently show similar diagnostic command patterns. If the modeled collection profile includes source-process attribution for WEB-EXT-01 network flows, retain that attribution for the 15:15 SSH connection; the current FLOW is unattributed, limiting investigation of its initiator.
- For operational triage, verify whether the 15:15 root SSH from WEB-EXT-01 and the 18:15 database dump transfer to APP-INT-01 were authorized, and confirm whether the 16:40 EHR connector log upload was approved for ticket `MHS-48217`.
