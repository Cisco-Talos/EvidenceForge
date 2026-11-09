# Verdict (Assessment Synthetic/Real/Inconclusive, Verdict Confidence 0-100, Synthetic-Confidence Score 0-100)

**Assessment: Synthetic**  
**Verdict Confidence: 76/100**  
**Synthetic-Confidence Score: 64/100** (moderate; lower scores indicate more production-like data)

## Executive Summary

The slice supports a credible and huntable compromise narrative. A privileged Windows domain controller shows PsExec service installation, creation and Domain Admins membership for `svc_dirsync`, a new recurring SYSTEM task/service, and later event-log clearing. Separately, a Linux workstation packages diagnostic logs and sends a large ticket attachment through the proxy; later a root session from that workstation dumps production database tables and transfers the archive to the workstation. Endpoint, authentication, file, proxy, Zeek, firewall, and IDS evidence provide useful pivots and generally plausible source coverage.

I assess the dataset as synthetic mainly because Linux background process telemetry is unusually uniform across the estate: nine Linux hosts each have exactly 24 `debian-sa1`/shell process rows, paired at 12 half-hourly run times with nearly fixed per-host offsets. That resembles a shared generated cadence more than independent host collection. It is a moderate distribution-texture signal, not a contradiction. I found no decisive impossible ordering or broken cross-source event contract in the representative pivots examined.

## Evidence For Synthetic

### hard_contradiction

- None identified in the reviewed operational pivots. The sequences below have plausible ordering, and the six-hour boundaries do not establish missing pre-window or post-window events.

### contract_gap

- None established. The support upload and the database dump/SCP have endpoint process/file/network evidence and relevant network or proxy observation. Full source alignment is not treated as synthetic evidence by itself.

### distribution_texture

- On each of nine Linux hosts with eCAR process telemetry, the `debian-sa1` collection pattern appears as 24 rows: two process records per run, exactly 12 runs spaced about 30 minutes apart. Host offsets are consistent within each host and tightly clustered across hosts. This is plausible scheduled collection, but the same fixed count, cadence, and paired shape across all hosts is a moderate artificial-regularity signal.
- Baseline host and sensor volumes are highly structured around dense, repeated process/network activity. This is not independently decisive; the periodic Linux task pattern is the concrete distribution clue.

### schema_or_format

- No material malformed-record or source-format defect identified in this review. The reviewed eCAR, XML, Zeek JSON, syslog, and access-log records were parseable and source-appropriate.

### environment_or_collection_plausibility

- No decisive environment impossibility identified. The estate has a coherent mix of domain controllers, Windows workstations and file server, Linux application/database/mail/proxy/web/file hosts, macOS endpoints, and network sensors.

### weak_signal

- Some activity is conspicuously legible as an exercise pivot (for example, an explicit support-ticket archive upload and a labeled `DeviceSync` persistence task). These are weak signals only: named admin operations and readable filenames can occur in real environments, and narrative completeness is not used as a synthetic tell.

## Evidence For Real

- **Useful real-world noise and coverage:** the data includes routine scheduled process activity, successful and failed logons, ordinary SMB reads/writes, DNS and application traffic, external web probes, firewall denies, and IDS alerts. These coexist with the high-risk activity rather than leaving only attack events.
- **Operational chain with independent corroboration:** on WS-LNGUYEN-01, Lina Nguyen's shell history and eCAR show a tar archive of two EHR connector logs at 17:05:37Z, archive creation at 17:05:41Z, then a curl multipart upload at 17:05:54Z. The proxy records the corresponding POST to `support.valeworks-health.net` at 17:06:04Z with HTTP 200 and 1,573,700 client bytes. This supports a concrete data-transfer pivot; the sanitized vendor domain alone is not treated as suspicious.
- **Production database collection and staging:** DB-PROD-01 records root SSH access from 10.10.2.30 at 18:15:06Z. The same session runs `mysqldump` against `ehr`, `patients`, and `insurance_claims`, compresses `/tmp/rpt_0318.sql`, and SCPs the result to 10.10.2.30 at 18:15:49Z. eCAR process/file/flow evidence and the DB's SSH syslog support the sequence. FILE-LNX-01 later records `svc_mhsync` writing `rpt_0318.sql.gz` under the ClinicalResearch DB-Staging path at 18:19:27Z.
- **Domain persistence and privilege changes:** DC-01 records `PSEXESVC` installation under Aisha Johnson at 17:00:23Z; at 17:14:37Z a `svc_dirsync` account is created, reset, and added to Domain Admins; at 17:19:35Z a SYSTEM process creates a recurring `DeviceSync` task, followed by service/task records; Security event 1102 appears at 18:41:55Z. These are high-priority incident leads even if the dataset is synthetic.
- **Network context:** Zeek-core and Zeek-DMZ provide connection, DNS, HTTP, SMB, TLS, certificate, and file records; the perimeter ASA and Snort datasets capture repeated blocked/probe activity against the exposed web host. Proxy and web access logs supply application-layer context. The supporting noise provides reasonable analytic pivots.
- **Source breadth:** 23 named host directories are represented, plus three Zeek sensor families, two Snort families, and perimeter ASA logs. The host set includes Windows, Linux, and macOS sources.

## Detailed Analysis

### Scope and source mix

The slice covers approximately six hours on 2026-11-02. It contains 23 host directories with eCAR on all hosts; Windows Security/Sysmon on Windows systems; Linux syslog and selected shell histories; macOS endpoint-security/unified-log and zsh histories; Zeek core, DMZ, and DB sensor families; two Snort alert streams; perimeter Cisco ASA logs; and proxy/web access logs. The dataset has useful breadth for endpoint-to-network pivots, with thinner macOS unified-log coverage than its eCAR/endpoint-security coverage. That thinness alone is not a defect without a concrete required-companion contradiction.

### Primary incident pivots

1. **Potential diagnostic-data egress:** WS-LNGUYEN-01 process and file activity ties Lina's shell session to creation and reading of `/tmp/mhs-support-48217.tar.gz`. The endpoint flow goes to the internal proxy at 10.10.3.20:8080; the proxy records the external ticket attachment POST and a 200 response. The command names a ticket and component, which is a plausible support workflow, but the attachment volume and source logs warrant verifying the vendor, ticket, and approved transfer route.
2. **Database dump and internal staging:** a root SSH session reaches DB-PROD-01 from 10.10.2.30, runs a dump of patient/insurance-related databases, compresses it, and transfers the result to 10.10.2.30. FILE-LNX-01 then records a staging-path write under `ClinicalResearch/Integration/DB-Staging` by `svc_mhsync`. Investigate the originating account/session, the intended backup/export workflow, the archive contents, and subsequent access or egress.
3. **Domain persistence/privilege escalation:** DC-01's service install, account creation/reset, Domain Admins membership, scheduled task/service setup, and later log clear form the strongest Windows incident sequence. Correlate the initiating remote source and credentials with WS-AJOHNSON-01's `runas`/explicit-credential events, DC process trees, and any service-control network evidence. Confirm whether `DeviceSyncSvc.exe` exists and is authorized.
4. **Perimeter probes:** repeated SYN-only attempts from 185.220.88.13 and other external addresses target common ports on WEB-EXT-01. Zeek records mostly incomplete `S0` connections, with matching perimeter alerts and firewall activity. This is consistent with scanning and red herring traffic; it does not by itself establish successful access.

### Lifecycle, pivots, and limits

- Reviewed paired Windows process create/terminate and logon/logoff patterns were broadly plausible. Windows Security event logon types on DC-01/DC-02 included type 3 and type 5 activity; the observed 4634 counts were close to the count of distinct 4624 logon IDs, so the raw eCAR login/logout count ratio is not by itself evidence of missing lifecycle events.
- The inspected high-risk sequences have no obvious time inversion. I did not infer defects from session or process activity that may extend beyond the six-hour window.
- Network and endpoint records provide tuple, PID, principal, and application-layer pivots where reviewed. I did not use matching IDs/timestamps alone as proof of synthetic construction.
- The main authenticity concern is distribution regularity in periodic Linux system-stat collection. It is not enough to outweigh the broad and operationally useful mix of benign, failed, and high-risk evidence, but it supports a synthetic assessment with moderate confidence.

## Synthetic Indicator Summary

| Category | Finding | Weight |
|---|---|---|
| hard_contradiction | None found in reviewed pivots | None |
| contract_gap | None established | None |
| distribution_texture | Nine Linux hosts each show 24 `debian-sa1`/shell rows in 12 half-hourly, paired runs | Moderate |
| schema_or_format | No material format defect found | None |
| environment_or_collection_plausibility | Broad, coherent mixed estate and source mix; no decisive implausibility | Low |
| weak_signal | Especially legible ticket/persistence labels; not decisive | Low |

## Realism Score by Category

| Category | Realism (0-100) | Notes |
|---|---:|---|
| hard_contradiction | 94 | No impossible ordering or semantic conflict established in the reviewed pivots. |
| contract_gap | 88 | Important activity has plausible endpoint and network/proxy evidence; no required-companion break established. |
| distribution_texture | 59 | Repeated Linux system-stat process cadence is unusually regular across hosts. |
| schema_or_format | 93 | Reviewed source formats and representative records appear coherent. |
| environment_or_collection_plausibility | 82 | Host roles and source mix are plausible; macOS unified-log coverage is sparse but not contradicted. |
| weak_signal | 70 | Several highly readable exercise-like pivots, offset by ordinary operational noise and plausible admin actions. |
