# Threat Hunter — Authenticity Assessment

## Verdict

Assessment: Inconclusive  
Verdict Confidence: 72  
Synthetic-Confidence Score: 52

## Executive Summary

The logs support two detailed and potentially concerning activity chains, and their host, identity, timing, file, and network evidence is coherent across multiple sources. I found no hard contradiction, impossible ordering, or clear source-format defect. The unusually complete cross-source joins do not, by themselves, indicate synthetic data.

Some endpoint coverage is sparse, and routine Linux shell histories lean heavily toward generic administration checks. These are weak signals without a concrete mismatch. Raw evidence alone does not resolve whether the dataset is real or synthetic.

## Evidence For Synthetic

- **[environment_or_collection_plausibility]** Each Mac has hundreds of eCAR records and 122 or 170 endpoint-security records, but only two or three unified-log records. That is a noticeable source-coverage imbalance, though selective collection could explain it.
- **[distribution_texture]** Several Linux histories are dominated by generic host checks—disk, process, service, and log inspection—across different systems. The variation and occasional command mistakes keep this from being a strong synthetic indicator.
- **[weak_signal]** The patient-data export and external support upload are unusually easy to follow across source logs. Their correlation is internally consistent, so this is not evidence of synthetic origin on its own.

## Evidence For Real

- **[hard_contradiction: none found]** I found no visible event where a dependent precedes an in-window initiator, and no impossible field or lifecycle ordering in the reviewed pivots.
- **[contract_gap: none established]** The key activity chains have corresponding endpoint, network, and server-side evidence; no required companion was demonstrably missing.
- **[environment_or_collection_plausibility]** Source volumes vary by apparent role: the domain controllers and proxy have much larger event streams than individual workstations, while Linux histories include both routine checks and errors.
- **[weak_signal]** The external upload includes plausible operational details: a ticket ID, component name, archive creation, a successful proxy request, and a matching outbound perimeter connection.
- **[weak_signal]** The patient-data staging chain has consistent names, timing, and destination across shell history, endpoint records, and file-server auditing.

## Detailed Analysis

### External support upload

At `WS-LNGUYEN-01`, Lina’s shell history shows a tar archive of EHR connector logs followed by a multipart curl upload to the support case endpoint (`bash_history/lina.nguyen.bash_history:29–32`). Endpoint records show the archive creation and subsequent read by curl (`ecar.json:367–375`). The proxy records the POST at 16:32:19 UTC with a 200 response (`PROXY-01.meridianhcs.local/proxy_access.log:2232`); Zeek records the request through the proxy and onward to `52.44.186.73` (`zeek-core/http.json:1421`, `zeek-dmz/http.json:1583–1584`); the perimeter firewall records the outbound connection and teardown (`fw-perimeter/cisco_asa.log:15306–15308`). This is a plausible, though security-sensitive, upload path.

### Patient-data staging

The DB host history shows root running `mysqldump` over the `ehr` database’s `patients` and `insurance_claims` tables, compressing the result, and copying it to `10.10.2.30` (`DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:1–6`). DB endpoint records include the dump, gzip, scp process, and destination flow (`ecar.json:527–536`). The receiving host creates the file, and `FILE-LNX-01` records `svc_mhsync` writing the matching archive into `ClinicalResearch/Integration/DB-Staging` (`APP-INT-01.meridianhcs.local/ecar.json:768`; `FILE-LNX-01.meridianhcs.local/syslog.log:464–468`; `zeek-core/smb_files.json:229–230`). The behavior warrants investigation, but the records do not contradict one another.

## Synthetic Indicator Summary

- Hard contradictions: none found.
- Contract gaps: none established.
- Distribution texture: weak generic-command concentration in Linux histories.
- Environment or collection plausibility: sparse Mac unified logs relative to other Mac telemetry.
- Cross-source completeness: notable, but treated as neutral without a log-visible defect.

## Realism Score by Category

- Field format: 8/10
- Temporal: 8/10
- Cross-source: 9/10
- Behavioral: 7/10
- Environmental: 7/10

## Recommendations

- Confirm whether the EHR export to the staging share and the support-case upload were authorized; both are high-value review pivots in the logs.
- If stronger authenticity discrimination is required, obtain more Mac unified-log coverage or evidence of the collection policy. The current gap alone does not establish a defect.
