# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 55

## Executive Summary

The records support credible operational activity and several meaningful threat-hunting pivots. Host, proxy, Zeek, firewall, IDS, and Windows/Linux/macOS artifacts agree on important actions, including a diagnostic archive upload and a database dump transfer. The timestamps and field values are generally plausible, and the data contains routine service, user, and network activity around the higher-risk events.

The strongest authenticity concern is the tightly bounded, nearly six-hour observation period with host and sensor streams starting near the same minute and ending near the same minute. That is a distribution/collection texture signal, not a contradiction: a deliberately selected collection window can explain it. I found no decisive impossible ordering, invalid role, or broken protocol lifecycle that establishes synthetic origin. The evidence supports a mixed assessment rather than a confident real or synthetic verdict.

## Evidence For Synthetic

- **Distribution texture — fixed observation boundaries:** Across eCAR and Windows security records, many unrelated hosts first appear just after 13:00Z and continue until shortly before 19:00Z on November 2. For example, DC-01 eCAR begins at 13:00:02Z, APP-INT-01 at 13:00:01Z, and DC-02 security events begin at 13:00:02Z; their streams also stop within the same final minute. A shared six-hour capture window is plausible, but the unusually synchronized boundaries fit a deliberately rendered dataset.
- **Distribution texture — many activity families fit one compact interval:** The same short window includes diverse routine admin command histories across Linux and macOS, extensive Windows endpoint/security events, public-service traffic, and perimeter alerts. This breadth is possible in a real enterprise, but the synchronized, pre-bounded sampling makes the records feel curated. This is weak evidence because it may simply reflect the collection scope.
- **Weak signal — highly regular background volume by source:** The endpoint streams contain many similar process create/terminate and connection records, while some Linux/macOS unified logs are sparse beside much denser eCAR/network records. That asymmetry can arise from product configuration and source selection; by itself it does not indicate synthetic data. I do not treat thin source coverage or absent selected event types as evidence.

## Evidence For Real

- **Cross-source correlation:** Lina Nguyen's WS-LNGUYEN-01 Bash history creates `/tmp/mhs-support-48217.tar.gz` from EHR connector logs, then uploads it with `curl` to `support.valeworks-health.net` using case `MHS-48217`. The host eCAR records the tar creation, file read, curl process, and proxy connection. PROXY-01 records the matching POST from `10.10.1.21` at 17:06:04Z, and Zeek DMZ HTTP records the same case URI, `curl/7.81.0`, 1,573,258-byte request, gzip filename, and HTTP 200 response. The sequence and identifiers agree across endpoint, proxy, and network evidence.
- **Plausible database workflow:** DB-PROD-01 root history runs `mysqldump`, compresses `rpt_0318.sql`, then sends it to `10.10.2.30` with `scp`. Zeek SMB records that host transferring `Integration\DB-Staging\rpt_0318.sql.gz` to the ClinicalResearch share on FILE-LNX-01, with a matching file record and byte count. This is a realistic operational pattern with an actionable sensitivity concern, not an impossible sequence.
- **Credible remote administration evidence:** DC-01 records a `PSEXESVC` file and service creation attributed to `aisha.johnson`, followed by a SYSTEM `PSEXESVC.exe` process and a child `cmd.exe /c whoami && hostname`; the service process then terminates. The order and parent/child relationship are plausible for PsExec-style administration. The activity deserves investigation, but the lifecycle itself is coherent.
- **Realistic background and red herrings:** The network data includes ordinary DNS, web, SMB, mail, and database activity alongside unsuccessful inbound probes, STUN traffic, and a BitTorrent alert. For example, perimeter alerts for STUN and a BitTorrent peer sync have corresponding Zeek/firewall traffic. This mixed signal is operationally plausible and gives analysts something to triage beyond one conspicuous storyline.
- **Format and timing are broadly credible:** The Windows Security XML uses familiar event IDs and fields; Zeek records have protocol-appropriate tuples, states, and byte counts; proxy logs carry user, method, status, and transfer metadata; Linux shell history timestamps align with the observed event period. The logs show plausible variation in users, systems, services, and destinations.

## Detailed Analysis

### Operational lifecycle coherence

Most visible lifecycles are internally sensible within the observed interval. The DC-01 PsExec service starts before its executable and child command, then the service process terminates. The support upload has a staged archive, a subsequent read by curl, a proxy-mediated request, and matching network-side HTTP records with a successful response. The database export is compressed before being transferred, and the file appears on a share through SMB. These are coherent process and transfer sequences.

Windows Security records also show ordinary network logons and service activity. Examples include machine-account logons on the domain controllers and expected service logons, with paired logoff events in the available window. User workstation records contain both successful and failed interactive logons. I did not infer a broken lifecycle from records that could continue beyond the capture window.

### Pivots and tradecraft

The highest-value pivot is Lina Nguyen's upload: start with the EHR connector paths and ticket identifier, then follow the tar file, curl process, proxy POST, and Zeek file metadata. It is a concrete potential data-loss event even though the destination may be an approved support provider. Confirm the recipient/domain authorization and whether the connector logs contain sensitive records.

The second priority is the SQL dump chain. Follow the dump artifact from DB-PROD-01 to the ClinicalResearch share, determine whether the operator and destination are approved, and inspect access to the share after the write. The archive's name, data source, privilege level, and transfer route justify review without assuming malicious intent.

The PsExec activity on DC-01 warrants validation against an authorized change or support session. The endpoint evidence is specific enough to pivot on user, service name, executable, parent process, and child command. The provided records do not establish the originating operator's intent.

### Signal-to-noise and collection

The collection is broad: Windows Security and Sysmon-like endpoint data, eCAR, Linux syslog and shell history, macOS endpoint/unified logs, proxy, Zeek, firewall, and Snort are present. The amount of ordinary host and network activity gives context for the rare high-risk actions. Coverage is uneven by host and source, but selected-source gaps are expected and do not count as evidence of fabrication.

The main limitation for authenticity is the common six-hour boundary across many sources. It is reasonable for a fixed hunt dataset, and I therefore score it as a weak texture concern. I do not find a clear timestamp inversion or impossible source/target role. Domains and names may be sanitized, and I have not treated them as authenticity clues.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---|
| `distribution_texture` | Many unrelated host and sensor streams share nearly identical six-hour start/stop boundaries. | Weak |
| `weak_signal` | Source volume is uneven and several host-local feeds are sparse relative to endpoint/network data. This is compatible with collection configuration and is not independently probative. | Very weak |
| `hard_contradiction` | None established. | None |
| `contract_gap` | None established. | None |
| `schema_or_format` | None established. | None |
| `environment_or_collection_plausibility` | Fixed, synchronized capture bounds are plausible as a selected exercise window, but contribute some synthetic suspicion. | Weak |

## Realism Score by Category

Scores use 10 for strongly production-like evidence and 1 for strongly synthetic-looking evidence.

| Category | Score |
|---|---:|
| Field format accuracy | 8/10 |
| Temporal patterns | 6/10 |
| Cross-source correlation | 9/10 |
| Behavioral realism | 7/10 |
| Environmental consistency | 7/10 |

## Recommendations

1. Validate the EHR support upload with the service owner: confirm the case, recipient, approved proxy route, and contents of the archive. Preserve the matching endpoint, proxy, and Zeek records.
2. Confirm the DB-PROD-01 dump and subsequent share write were authorized; inspect access and any later movement of `rpt_0318.sql.gz`.
3. Confirm whether Aisha Johnson's PsExec service creation on DC-01 was part of an approved administrative task. Pivot from the `PSEXESVC` service and child command to the originating workstation/session and related SMB/RPC activity.
4. For authenticity review, compare the exact observation-window boundaries with the collection schedule. If they are intentional, they explain the primary synthetic-texture signal; if not, examine how unrelated source streams acquired such closely aligned bounds.
5. Preserve the assessment as inconclusive unless independent provenance or additional records resolve whether the dataset was collected from live systems or rendered from a model.
