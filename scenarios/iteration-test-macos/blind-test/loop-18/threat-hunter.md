# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 46

## Executive Summary

The logs show a broad, multi-platform environment with coherent pivots across endpoint, authentication, network, proxy, and file-transfer telemetry. Two events warrant immediate investigation: an external upload of an EHR connector diagnostic archive and a root-initiated dump of patient and insurance tables staged on an application host. The visible evidence supports concern about possible data handling or exfiltration, but authorization context is absent; I found no decisive log-visible authenticity defect that establishes whether the dataset is synthetic or real.

## Evidence For Synthetic

- [weak_signal] An EHR-related diagnostics archive is uploaded to an external host over plain HTTP: `WS-LNGUYEN-01.../bash_history/lina.nguyen.bash_history` lines 31–34 show creation of `mhs-support-48217.tar.gz` from connector and queue logs and a `curl` POST to `support.valeworks-health.net`; `zeek-dmz/http.json` line 1203 records the POST at 2026-11-02 16:32:33.941Z with a 1,573,258-byte body and HTTP 200. This is a materially risky workflow for a healthcare environment, but a real support process could use it, so it is only a weak authenticity signal.

No impossible event ordering, contradictory source-native fields, or generator identity leak stood out in the reviewed evidence. The tightly matching source records below are not counted as synthetic evidence by themselves.

## Evidence For Real

- The EHR diagnostic upload has a traceable, source-consistent sequence: archive creation on `WS-LNGUYEN-01` at 16:31:57Z and file creation at 16:32:01Z appear in `ecar.json` lines 447–448; the curl process is recorded at line 449; the proxy records the POST and HTTP 200 at `PROXY-01.../proxy_access.log` line 1653; Zeek records both the workstation-to-proxy and proxy-to-external HTTP requests in `zeek-core/http.json` line 1088 and `zeek-dmz/http.json` line 1203. Both Zeek file records name the archive and report 1,572,864 bytes transferred (`zeek-core/files.json` line 384; `zeek-dmz/files.json` lines 912–913). The command names ticket `MHS-48217` and component `ehr-connector`, which is consistent with a legitimate support submission, though it does not prove authorization.
- The database staging sequence is corroborated across endpoint and network records. `DB-PROD-01.../bash_history/root.bash_history` lines 1–6 show a root shell dumping `ehr` tables `patients` and `insurance_claims` at 18:15:01Z, compressing the dump, and copying it to `APP-INT-01` at 18:15:46Z. `DB-PROD-01.../ecar.json` lines 669–679 record the corresponding `mysqldump`, output creation, `gzip`, and `scp` read/flow; the flow is from `10.10.4.10:54865` to `10.10.2.30:22`. The application host records the file creation at `APP-INT-01.../ecar.json` line 740 (18:16:09Z) and the root SSH acceptance at `APP-INT-01.../syslog.log` lines 222–227. This is strong evidence of movement of sensitive data, but could be authorized, and does not establish the dataset's origin.
- A long-lived root SSH session from `APP-INT-01` to `DB-PROD-01` is temporally coherent: `zeek-db/conn.json` line 438 reports 2,673.446 seconds from 18:14:44.638Z; `DB-PROD-01.../ecar.json` line 770 records logout at 18:59:18.823Z, and `DB-PROD-01.../syslog.log` line 263 records session close at 18:59:18.564Z. The timing and account/source attribution align across sources.
- The data includes multiple independently useful source families: endpoint eCAR on 23 host directories, Windows Security and Sysmon on Windows systems, macOS Endpoint Security and Unified Log exports, Linux syslog and shell histories, three Zeek sensor groups, proxy, perimeter firewall, and Snort alerts. eCAR spans approximately 13:00–19:00Z on 2026-11-02, providing enough context to pivot rather than relying on an isolated alert.

## Detailed Analysis

### Environment and coverage

The directory contains 23 host directories plus network-sensor outputs. The apparent fleet spans Windows endpoints and domain controllers, Linux application/database/file/web/mail systems, and two macOS hosts associated with Maya Ross. eCAR contains 35,086 records between 2026-11-02 13:00:01Z and 18:59:59Z. Zeek coverage is split across core, database, and DMZ sensors; perimeter firewall, Snort, and proxy logs add network-level context. This review did not infer platform-specific missing companions beyond the visible collection.

### EHR diagnostic archive upload

On `WS-LNGUYEN-01`, Lina Nguyen's history at `bash_history/lina.nguyen.bash_history` lines 31–34 shows a tar archive made from `/var/log/ehr-connector/connector.log` and `/var/log/ehr-connector/queue.log`, then submitted with ticket/component metadata to `support.valeworks-health.net`. The eCAR records tar creation and file creation at 16:31:57.826Z and 16:32:01.754Z (lines 447–448), followed by a curl process at 16:32:09.126Z (line 449). Zeek records a 200 response and a 1,573,258-byte POST at 16:32:33.941Z (`zeek-dmz/http.json` line 1203); the proxy log records the same target, ticket URI, client, and 200 response (`PROXY-01.../proxy_access.log` line 1653). This makes the upload observable and successful. The destination and ticket framing are compatible with support activity, while the cleartext HTTP path and external transfer of EHR connector logs merit validation against approved support procedures and archive contents.

### Database dump and internal staging

At 18:14:48Z, `DB-PROD-01` logs an incoming SSH connection from `10.10.2.30` and accepts root authentication (`syslog.log` lines 242–245). The root history then records a dump of patient and insurance tables to `/tmp/rpt_0318.sql`, compression, and an SCP to `root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. eCAR corroborates the dump and resulting file, compression, and SCP flow (`DB-PROD-01.../ecar.json` lines 669–679). On `APP-INT-01`, the receiving SSH process creates `/tmp/.cache/rpt_0318.sql.gz` at 18:16:09Z (`ecar.json`, FILE CREATE record); its syslog records root SSH acceptance and session closure at 18:15:55Z and 18:16:08Z (lines 223–227). A later eCAR FILE READ of that path at 18:19:10Z (`APP-INT-01.../ecar.json` line 745) has no principal or process identity in the record. That read leaves the next actor and any onward movement unresolved; I found no basis here to claim an external transfer of this dump.

The underlying network is also visible in Zeek. `zeek-db/conn.json` line 441 records the SCP-direction SSH flow from `10.10.4.10:54865` to `10.10.2.30:22`, with 126,136 origin bytes and a successful `SF` close. The activity is technically coherent across shell history, endpoint, syslog, and network evidence. Whether root's access and data movement were approved remains the key investigative question.

### macOS and other pivots

Maya Ross's zsh histories on both Macs include system inspection, document browsing, and SSH sessions to internal Linux hosts. On `MAC-MROSS-02`, history records `cat /Volumes/Users/Documents/contacts-final.txt` at 16:15:16Z; eCAR records the matching process and file read at 16:15:36Z–16:15:41Z. Another visible read of a PDF under `/Volumes/ClinicalResearch/Archive/` is recorded at 16:53:54Z. The reviewed records do not show a downloaded executable, launch-item persistence, or a successful macOS execution chain tied to those reads, so I do not infer such effects.

Linux and Windows records show routine service and endpoint activity around the high-interest events, including DNS, Kerberos, SMB, process, and authentication telemetry. The selected source families permit viable pivots among host, user, time, IP, and port; the reported alignment is treated as a positive coherence observation, not a synthetic tell.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `weak_signal` | Workstation, proxy, Zeek DMZ | One EHR diagnostic archive upload | A 1.57 MB support archive leaves the organization over cleartext HTTP. This is a risky but possible real workflow; without authorization context it raises only a weak authenticity signal. |

## Realism Score by Category

- **Field format accuracy:** 8 — Reviewed eCAR, syslog, Zeek HTTP/connection, proxy, and shell-history fields are interpretable and internally consistent.
- **Temporal patterns:** 8 — The critical SSH, database-dump, transfer, and support-upload times are coherent across observed sources.
- **Cross-source correlation:** 9 — The key transfer paths can be followed through endpoint, syslog, proxy, and Zeek evidence.
- **Behavioral realism:** 7 — Both support-log export and root database staging are technically plausible; their authorization context is absent and the data movement is concerning.
- **Environmental consistency:** 7 — The mixed Windows/Linux/macOS fleet and segmented network sources are plausible; the external cleartext support upload deserves policy confirmation.

## Recommendations

- If this were synthetic, preserve the visible source correlation while adding realistic authorization context for the EHR support submission (such as the approved ticket or proxy policy outcome) so analysts can distinguish sanctioned diagnostics from unauthorized disclosure.
- If this were synthetic, retain process or user attribution for the 18:19:10Z read of `/tmp/.cache/rpt_0318.sql.gz` on `APP-INT-01`; the current eCAR FILE READ has neither principal nor PID and leaves downstream handling unresolved.
- Operationally, verify whether root was authorized to dump `patients` and `insurance_claims` and stage the archive on `APP-INT-01`; then determine whether the file was accessed or transferred after the observed read.
