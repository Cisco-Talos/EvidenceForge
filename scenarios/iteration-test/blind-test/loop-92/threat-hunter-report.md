# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 30

## Executive Summary

The reviewed telemetry is mostly operationally plausible, with useful exact pivots between endpoint activity, proxy transactions, network transfers, and server-side file writes. I did not establish a hard contradiction or a defensible high-impact synthetic indicator in this bounded review; the data could be real or a capable synthetic collection, and successful correlation alone cannot distinguish those possibilities.

## Evidence For Synthetic

- No substantiated important synthetic indicator emerged from the representative samples and two exact pivots. Consequently, there is no `hard_contradiction`, demonstrated `contract_gap`, or distribution defect supporting a confident synthetic verdict.
- [weak_signal] The selected SMB operation has endpoint timestamps later than network timestamps: source FILE/READ at 18:19:22.376Z and destination FILE/WRITE at 18:19:22.375Z, versus Zeek's connection ending about 18:19:21.393Z. This warrants checking timestamp provenance if the data were being validated operationally, but independent endpoint clock/collection latency can explain it. It is **not** established impossible ordering and receives no material synthetic-score penalty.

## Evidence For Real

- The support upload distinguishes a client-to-proxy connection from a proxy-to-origin connection, preserves the HTTP body across those legs, and allows HTTP header/wire-byte totals to differ. This is meaningful protocol structure, not simply repeated identical records.
- Linux root executing `smbclient` and remote Samba attributing the resulting write to directory identity `svc_mhsync` is a coherent separation of local process ownership and remote credentials.
- There is substantial non-attack activity: 23 endpoint directories, 39,151 normalized endpoint records, 23,644 Zeek connections, 4,463 syslog lines, 4,316 proxy transactions, and Security records spanning authentication, Kerberos, process lifecycle, network policy, access auditing, locking, and service activity.
- Exact-identity lifecycle summaries found 2,447 process objects with visible CREATE and TERMINATE, with zero reversed create/terminate orderings. Among 3,918 non-process records whose actor had a visible termination, none occurred more than one second after that termination. These are bounded aggregate checks on the supplied normalized endpoint files, not a claim that every lifecycle is complete.
- Repeated `debian-sa1 1 1` processes occur as scheduled maintenance, with 36 per host across ten Linux hosts in six hours. Ten-minute cron cadence is plausible for this command and is not counted as synthetic regularity.

## Detailed Analysis

### Scope, time window, and collection interpretation

I inspected only the supplied data directory and the assigned briefing. There are 118 files and 23 endpoint directories; additional directories represent Zeek sensors, IDS, and perimeter firewall collection. The normalized endpoint window runs from 2026-11-02T13:00:00.756Z to 18:59:50.485Z. Visible addresses include 10.10.1.*, 10.10.2.*, and 10.10.3.*; this establishes at least three address ranges, not independently verified subnet masks.

Windows Security contains 19,623 events, including 12,800 Event 5156, 2,087 Event 4769, 935 Event 4688, 863 Event 4624, 827 Event 4768, and 28 Event 4625. Sysmon contains 12,162 events. XML line counts are not event counts. The normalized collection includes 28,678 FLOW/CONNECT, 2,683 PROCESS/CREATE, 2,541 PROCESS/TERMINATE, 1,007 USER_SESSION/LOGIN, and 532 USER_SESSION/LOGOUT records. I did not treat unequal login/logout or process lifecycle totals as defects: this is a six-hour slice and state can cross either boundary.

Mac endpoint-security, Unified Log, normalized endpoint, and shell-history sources are distinct collection products. I did not impose native ES semantics on normalized eCAR or infer execution effects solely from history. No unfamiliar native Mac schema detail was used as a defect.

### Representative record inventory

The following 18 cited specimens anchor the bounded review; the two pivots below additionally resolve their linked companion records. Paths below are relative to the assigned data directory. Timestamps are UTC unless the source explicitly uses another representation.

| # | File and record locator | Visible evidence and interpretation |
|---|---|---|
| 1 | `zeek-core/conn.json:1` | 13:00:00.006178, UID `ClnAf4xMznbwm13HlN`, 10.10.2.20:58104 → 10.10.2.11:53, UDP DNS, 41/57 bytes: ordinary name-resolution traffic. |
| 2 | `WEB-EXT-01.meridianhcs.local/ecar.json:1` | 13:00:03.060, `-bash`, PID 2693877, parent sshd PID 2685619, principal lina.nguyen: plausible server-side remote shell. |
| 3 | `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1` | 13:00:06.950823, launchd fork child PID 41136; explicit audit tokens, executable metadata, and version 11. This is a fork observation, not evidence that a particular command completed. |
| 4 | `DC-01.meridianhcs.local/ecar.json:5576` | PID 5880, SYSTEM PowerShell with `-EncodedCommand`, parent svchost PID 2368; suspicious enough to investigate, but command obfuscation is not an authenticity indicator. |
| 5 | `MAIL-CLIN-01.meridianhcs.local/ecar.json:412` | marcus.chen runs `du -sh /tmp/*`, PID 496235: normal administrative command also useful during investigation. |
| 6 | `WS-LNGUYEN-01.meridianhcs.local/ecar.json:53` | PID 2945062 runs `python3 /tmp/pip-install-cache/setup.py install`; temporary-path execution is a hunt lead, not proof of maliciousness. |
| 7 | Same file, line 80 | PID 2946019, SSH using `~/.ssh/work_ed25519` to APP-INT-01 as lina.nguyen: explicit key and remote account. |
| 8 | Same file, line 133 | PID 2947619, `ssh -A lina.nguyen@APP-INT-01`: agent forwarding is distinct from the prior explicit-key command. |
| 9 | Same file, line 416 | PID 2970922, SSH with `/home/lina.nguyen/.ssh/id_rsa` to PROXY-01: another specific credential path. |
| 10 | Same file, line 458 | PID 2978182, curl requests internal wiki Architecture page with HTTP-status formatting. |
| 11 | Same file, line 498 | 16:42:20.108, tar PID 2980996 packages two ehr-connector logs into `/tmp/mhs-support-48217.tar.gz`. |
| 12 | Same file, line 500 | 16:42:24.689, curl PID 2981027 explicitly addresses PROXY-01:8080. |
| 13 | Same file, line 502 | 16:42:28.821, curl PID 2981051 sends multipart metadata and diagnostics for ticket MHS-48217 through the proxy. |
| 14 | `PROXY-01.meridianhcs.local/proxy_access.log:2641` | 16:42:45, same POST path and lina.nguyen identity, HTTP 200, 96-byte response, `cs_bytes=1573700 wire_sc_bytes=306`. |
| 15 | `zeek-core/http.json:1587` | UID `C09WEMTz1u8lKh5iYYK`, exact ticket endpoint and filename, 1,573,258-byte multipart body. |
| 16 | `zeek-dmz/http.json:1753` | UID `COzS6n47IrJvcnveji`, same body and destination host, origin-form URI on proxy egress. |
| 17 | `APP-INT-01.meridianhcs.local/ecar.json:921` | 18:19:16.494, root PID 2984601 executes smbclient using `svc_mhsync`, uploading rpt_0318.sql.gz to ClinicalResearch. |
| 18 | `FILE-LNX-01.meridianhcs.local/ecar.json:1402` | 18:19:22.375, smbd PID 2728834 writes the matching destination path as svc_mhsync; `auth_protocol=ntlmssp`, `account_scope=directory`. |

### Exact pivot 1: multipart diagnostics upload through an explicit proxy

Starting with specimen 13, the command identifies ticket `MHS-48217`, destination `/api/v1/cases/MHS-48217/attachments`, file `mhs-support-48217.tar.gz`, and curl as the client. The exact path and filename link specimens 14–16 without relying on similar timestamps alone.

The core HTTP record joins its connection and files by UID `C09WEMTz1u8lKh5iYYK`: `zeek-core/conn.json:8484` is 10.10.1.21:36016 → 10.10.3.20:8080, starting 16:42:45.162754 with duration 19.152601 seconds. `files.json:461–462` identify metadata FUID `FahrTTl6bPGJWZcl7c` with 50 observed bytes and gzip FUID `FLkgYeG1ChanKUqG8Z` with 1,572,864 bytes. Their sum is 1,572,914 bytes, below the 1,573,258-byte multipart body by 344 bytes, leaving plausible multipart framing. The request's 1,573,700 connection bytes leave another 442 bytes beyond the HTTP body, consistent with headers. The proxy access record independently reports exactly those client connection bytes and the 306 server bytes.

The egress UID `COzS6n47IrJvcnveji` joins `zeek-dmz/conn.json:7097` and `files.json:1046–1048`: 10.10.3.20:59455 → 52.44.186.73:80, a different transport tuple and FUID namespace, same metadata/gzip byte counts and 96-byte response. Egress orig_bytes 1,573,682 differs from ingress, as headers can change at a proxy.

DMZ HTTP time is about 48 ms earlier than the core HTTP record, and a response file appears before the entire observed upload finishes. These facts do not by themselves prove impossibility: sensors have separate timestamp provenance and HTTP can respond before a client finishes sending its request body. I do not claim a contradiction from those observations. The upload establishes that a ticket-labelled archive was transferred; it does not establish its benignness or prove the claimed archive contents.

### Exact pivot 2: SMB staging with separate local and remote principals

Specimen 17 identifies process UUID `fb5abf23-c4b1-4d7a-8d06-b757a969a0a5`, source `/tmp/.cache/rpt_0318.sql.gz`, destination share ClinicalResearch, and account svc_mhsync. The same process owns APP-INT-01 FLOW/CONNECT at line 922: 10.10.2.30:45432 → 10.10.2.21:445. This exact tuple joins Zeek UID `C3wJJb8OCKfbxQ9581x` in `zeek-core/conn.json:11775`.

The UID then joins `smb_mapping.json:143` to `\\FILE-LNX-01\ClinicalResearch`, `smb_files.json:248–249` to FILE_OPEN/FILE_WRITE on `Integration\DB-Staging\rpt_0318.sql.gz`, and `files.json:680` to FUID `FUfDcNt4TYUihA1HLHH`, 922,169 observed/total bytes. The file record supplies SHA256 `342d6e0118106a58162536ff2eeb99f915fb6b329c6f982a11a73533b55e6c7c`; it is a pivotable artifact identifier, not evidence that contents were validated here.

Endpoint destination specimen 18 maps the share-relative name onto `/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`. Local root and remote svc_mhsync need not match, because the command explicitly requests the latter account. Source endpoint FILE/READ at line 923 and destination FILE/WRITE at line 1402 are both approximately one second later than the sensor's transport close, so I retain a timestamp-provenance limitation rather than asserting physically impossible activity across independently collected sources.

### Signal-to-noise, huntability, and limits

The 935 Security process-creation and 934 Sysmon process-creation events, 12,800 policy connection records, thousands of background flows, and hundreds of successful logons provide a credible amount of activity for a six-hour, 23-host collection. I did not establish a source-volume defect. The selected SSH, temporary execution, encoded PowerShell, multipart upload, and SMB staging records offer useful hunt pivots; their compactness, completeness, or ease of narration does not affect the score.

I performed aggregate inventory, event-family counts, and two narrow normalized lifecycle consistency checks rather than an exhaustive audit. I did not validate every command, file hash, Windows account transition, service, Mac notification, DNS answer, or sensor clock. I did not access scenario definitions, repository code, ground truth, other assessments, or evaluation reports. The confidence of 82 concerns the conclusion that this review is inconclusive; the score of 30 describes the mostly realistic appearance of the reviewed evidence and is not an 82% or 30% probability calculation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| weak_signal | Normalized endpoint versus Zeek SMB | One exact transfer, UID C3wJJb8OCKfbxQ9581x | Endpoint file observations trail transport close by about one second. Timestamp provenance is unknown, so this is not an established contract gap and receives no material penalty. |
| No supported high-impact indicator | Reviewed endpoint, proxy, Zeek, Windows aggregate families | Representative samples and two exact pivots | No demonstrated impossible identity ordering, schema defect, or implausible distribution was found; score remains in the mostly realistic band. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled normalized, proxy, and Zeek fields are usable and internally consistent; native Mac schema was not independently audited.
- **Temporal patterns:** 8 — Visible exact-identity process lifecycles are ordered, and scheduled maintenance cadence is appropriate; cross-sensor timestamp provenance remains uncertain.
- **Cross-source correlation:** 9 — Exact proxy transaction/body and SMB tuple/UID/FUID/path pivots work with coherent credential ownership.
- **Behavioral realism:** 8 — Administrative SSH, cron maintenance, support upload, and Samba activity have workable command and identity relationships in the sampled evidence.
- **Environmental consistency:** 8 — Mixed endpoint roles and several network ranges have plausible source volume and ordinary background activity; a six-hour slice limits long-tail assessment.

## Recommendations

- If this were synthetic, retain the demonstrated separation of endpoint principal, remote credentials, proxy transport legs, and protocol/file identities.
- If this were synthetic, verify the SMB file-read/write timestamps against the canonical transport interval and document source clock/collection delay assumptions. Change timing only if the timestamps represent actual occurrence time on synchronized clocks; the supplied records alone do not establish that condition.
- No additional source family or extra intrusion steps are recommended merely to make the collection busier or the narrative less tidy. This review found no log-visible basis for those changes.
