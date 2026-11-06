# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 47

## Executive Summary

The collection supports practical hunting across a mixed enterprise fleet, with coherent remote sessions, credential boundaries, staging, and proxy transfers. A narrow, repeated pattern of shell-based document access on the Macs looks constructed, particularly the approximately 26-minute cadence on one machine, but the checked attack and process lifecycles did not expose a decisive contradiction. I would lean slightly toward synthetic on behavioral texture, while retaining substantial uncertainty.

## Evidence For Synthetic

- [distribution_texture] MAC-MROSS-01 repeatedly accesses different mounted-share documents at an unusually narrow cadence: native Endpoint Security exec observations at 14:17:25.899164, 14:43:40.166799, 15:10:50.428268, 15:37:58.199697, 16:03:31.126941, and 16:29:59.001267 UTC. The five gaps are approximately 1,574, 1,630, 1,628, 1,533, and 1,588 seconds. The operations alternate `/usr/bin/tee` and `/bin/cat` across unrelated share paths rather than repeatedly accessing one scheduled input. Evidence: `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 45, 59, 61, 73, 90, and 102. A polling script could explain this, so it is a distribution indicator rather than impossible behavior.
- [environment_or_collection_plausibility] The same document-access family repeatedly represents binary office/PDF work as bare shell utilities: `cat .../contacts.xlsx`, `cat .../action-items-review.pdf`, `cat .../risk-register-draft.pdf`, and `tee .../team-roadmap.pptx`/`team-roadmap.xlsx` on MAC-MROSS-01; MAC-MROSS-02 also has `cat .../status-update-review.pdf` at 16:53:53.579668 UTC. These are actual executable arguments in native ES rows, not merely a normalized label. The prevalence of this mechanism among the visible mounted-share operations is unusual for normal document use. Evidence: the preceding MAC-MROSS-01 rows and `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson:110`. This is possible shell activity and is not a schema error; it overlaps the cadence finding and was not counted as an independent severe defect.

## Evidence For Real

- The SCP pivot carries the same source tuple through endpoint, network, and target authentication evidence. `DB-PROD-01.meridianhcs.local/ecar.json:659` creates `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`; line 661 associates it with source port 52763. `zeek-core/conn.json:10147` observes `10.10.4.10:52763 -> 10.10.2.30:22`, SSH, `SF`, with a substantial upload. `APP-INT-01.meridianhcs.local/syslog.log:230-232` records the connection, accepted root public key, and PAM session opening in that order.
- The database sensor has a credible imperfect observation of that same transfer: `zeek-db/conn.json:448` reports 1,898,441 origin bytes and `missed_bytes=12522`, while the core sensor reports 1,910,963 origin bytes. Their difference is exactly 12,522. This is materially more plausible than unexplained disagreements between sensors.
- Windows outbound credential use distinguishes local process identity from remote credentials. WS-AJOHNSON-01 has a Type 9 logon with local target user `aisha.johnson`, outbound user `marcus.chen`, and new LUID `0x27c96b7` following explicit credential use at 18:00:38 UTC. The subsequent command shell and collection processes retain local principal `aisha.johnson` and that LUID (`WS-AJOHNSON-01.meridianhcs.local/ecar.json:939-1020`; corresponding Security 4648/4624 records). Different local and remote names here are technically appropriate.
- The suspicious archive upload is supported by a running curl process, a proxy tunnel, a large transport upload, and the proxy's inspected POST. `WS-AJOHNSON-01.meridianhcs.local/ecar.json:1087` creates the curl process at 18:24:35.400 UTC; `zeek-core/http.json:1613` observes the CONNECT; `zeek-core/conn.json:10389` has approximately 18.78 MB of origin application bytes; `PROXY-01.meridianhcs.local/proxy_access.log:2440` records the POST to `/upload/telemetry/7f3a2b19` with `cs_bytes=18783152`.
- A plausible support upload creates investigation ambiguity: lina.nguyen's tar/curl process activity (`WS-LNGUYEN-01.meridianhcs.local/ecar.json:452-456`) leads to the ticket-specific POST in `zeek-core/http.json:1067` and proxy line 1616. The HTTP record preserves two multipart origin files/MIME types, rather than treating the entire multipart envelope as a single opaque file.
- The Mac policy warning does not incorrectly establish successful application execution in the checked native exec stream. `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` names MeetingAssist at 15:42:29.972020 UTC; I did not find a matching successful MeetingAssist native exec. I therefore did not infer child activity or effects from that warning.

## Detailed Analysis

### Collection scope and huntability

I examined only the supplied data directory. It contains 23 endpoint eCAR streams: ten hosts with Windows Security/Sysmon exports, eleven with Linux-style syslog, and two Macs with native Endpoint Security and Unified Log exports. The visible collection is approximately 2026-11-02 13:00–19:00 UTC. The addressing separates workstations around `10.10.1.x`, infrastructure around `10.10.2.x`, proxy/web-facing services around `10.10.3.x`, and the database at `10.10.4.10`.

The directory contains 33,455 eCAR rows, 18,070 Windows Security events, 3,949 syslog rows, 20,363 Zeek connection rows across three sensors, 2,798 proxy rows, 19,657 firewall rows, and 142 IDS alert lines. Counts across sensors are observations and must not be interpreted as unique underlying flows. The much larger authentication/flow presence on DC-01 and DC-02 than on user workstations fits their visible roles. These source volumes do not make every malicious row self-evident, and I found no defensible volume-based reason to penalize the collection.

### Operational sequence and pivots

The root database sequence is technically usable: an inbound SSH session from APP-INT-01 is accepted before its shell starts; mysqldump creates `/tmp/rpt_0318.sql`; the dump process terminates before gzip starts; gzip creates the compressed artifact and terminates before SCP starts. Relevant eCAR lines are 645–663 in DB-PROD-01. On APP-INT-01, the reverse-direction SCP connection is accepted before the receiver file appears (`ecar.json:635-641`). Later, line 648 invokes smbclient to put that artifact on FILE-LNX-01's ClinicalResearch share using `svc_mhsync`. I did not require the root SSH and SMB service identities to match: these are separate authentication boundaries.

The Windows sequence is similarly traversable. Remote interactive access has an observable session, userinit/explorer processes, and later discovery commands. Type 9 credential use preserves the existing local identity while changing network credentials. File collection and compression lead to the curl upload described above. The presence of those steps is not an authenticity defect, nor is their narrative coherence.

I checked all eCAR streams for effects attributed to a process more than two seconds before its visible creation or after its termination; this found no such contradictions. A separate check of the supplied Sysmon rows found no visible same-GUID network/file/module/access event before process creation or after termination, and no child creation after its visible parent termination. These checks establish consistency within their fields and windows; they do not prove every action would succeed or establish production provenance.

### Mac execution and observation semantics

The native Mac records distinguish forks from subsequent exec image changes, preserve PID and audit-token information, and show a launchd/xpcproxy/application chain. The SSH path includes wrapper, sshd, sshd-session, sshd-auth, user privilege transition, and shell stages. I did not treat an unfamiliar native field or a policy message as a proven schema defect, and I did not require a broader Unified Log export than the one supplied.

The strongest residual concern is the document-access behavior. MAC-MROSS-01's six share operations are concentrated around a 26.5-minute repeat interval, despite changing share, directory, extension, and read/write operation. The associated eCAR process/image and file rows agree with the native exec arguments, so this is not an accidental translation of a GUI application into a generic file-read label. Examples include eCAR lines 112/115 for the spreadsheet cat/read, 165/169 and 228/231 for PDF cat/read, and 265/270 for tee/write of an XLSX file. It resembles a reusable file-operation exercise with jitter.

However, the logs do not show the content of shell input or a complete interactive transcript. A user could run a loop, pipe binary data through tee, or intentionally inspect files with cat. The same account owns both Macs, so shared habits are also possible. This limits the finding to moderate texture/plausibility evidence and prevents a high-confidence synthetic verdict.

### Network and protocol consistency

For each available Zeek HTTP, SSL, DNS, and SMB-files row, I checked its UID against the same sensor's connection file and compared the available origin/responder tuple fields. I found no missing same-sensor connection UID or tuple disagreement in those checked families. HTTP request/response body lengths also did not exceed their corresponding connection application-byte direction totals. These results support pivot feasibility; completeness itself was not treated as a synthetic indicator.

The proxy separates CONNECT setup from inspected HTTP requests and carries a shared tunnel identifier and client source port. That makes the archive-upload pivot plausible without requiring plaintext HTTP payload visibility from the Zeek sensor. Multi-sensor differences such as the SCP missed-byte example have a visible collection explanation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS native ES and normalized eCAR | Six changing share-document operations on MAC-MROSS-01, 14:17–16:30 UTC, with five gaps of 1,533–1,630 seconds | Principal reason for a modest synthetic lean; could still be a scheduled shell loop |
| environment_or_collection_plausibility | macOS native ES and eCAR file activity | Repeated bare cat of XLSX/PDF and tee of PPTX/XLSX on two Macs | Supports the same behavioral concern; possible shell behavior, not an impossibility, and not independently double-counted |

No demonstrated hard contradiction was used in the score. Strong checked lifecycle coherence and credible collection artifacts keep the score in the mixed/inconclusive band.

## Realism Score by Category

- **Field format accuracy:** 9 — Checked native Windows/Zeek fields and structured Mac observations were internally usable; no demonstrated native-schema defect.
- **Temporal patterns:** 7 — Session and process ordering holds, but one mounted-document workflow has a conspicuously narrow repeat interval.
- **Cross-source correlation:** 9 — SSH, credential, file, multipart HTTP, proxy, and network pivots work, including explained sensor loss.
- **Behavioral realism:** 7 — The suspicious transfers and identity boundaries make technical sense; repeated shell treatment of office/PDF documents is less convincing.
- **Environmental consistency:** 8 — Host/source roles and traffic volume are broadly credible; the Mac document-operation mechanism remains unusual.

## Recommendations

- If this were synthetic, make the mounted-document workload reflect the actual activity being represented: use document applications for normal document work, or make the shell/script input mechanism coherent when cat and tee are intentional.
- If those six operations represent independent user actions, diversify their timing beyond the observed 1,533–1,630-second interval. If they represent one scheduled job, preserve that explanation in the visible process ancestry/arguments rather than presenting a repeating mix of unrelated shell document operations.
- Preserve the checked credential boundaries, transport-before-auth ordering, process lifetimes, multipart structure, and explicit missed-byte accounting. Those features materially improve both authenticity and investigative usefulness.
