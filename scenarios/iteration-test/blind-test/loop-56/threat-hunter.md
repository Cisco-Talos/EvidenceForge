# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 48

## Executive Summary

The data supports practical investigations across a mixed enterprise fleet, with strong process/session ownership and generally coherent network pivots. I found a significant apparent timing inconsistency in a multipart upload and a weaker client-platform distribution anomaly, but neither establishes synthetic origin beyond reasonable collection or application explanations. Most of the examined operational chains work together, so this is a mixed assessment rather than a finding of broadly defective telemetry.

## Evidence For Synthetic

- [contract_gap] The same-sensor, two-leg support upload appears to finish at the upstream server before the proxy finishes observing the client file. In `zeek-dmz/http.json:1433-1434`, the client and proxy POSTs identify `support.valeworks-health.net`, case `MHS-48217`, and the same archive. In `zeek-dmz/files.json:974`, the client archive starts at `1793637185.837320` with duration `19.351756`, implying last activity at `1793637205.189076`. The upstream archive at line 976 starts at `1793637186.063863` with duration `13.511043`, implying last activity at `1793637199.574906`, **5.614170 seconds earlier**. Both show `seen_bytes=1572864`, `missing_bytes=0`, `overflow_bytes=0`, and `timedout=false`. Streaming alone cannot make the final forwarded bytes precede their arrival. This is an apparent transfer-timing defect, not an unconditional impossibility: file-analysis timing, reassembly, or proxy body substitution could complicate the interpretation, and these logs contain no payload hashes or packet capture to exclude those explanations.
- [weak_signal] The client identified by native Mac telemetry and eCAR as MAC-MROSS-01 / `10.10.1.41` makes 241 requests visible in `zeek-core/http.json`; **142 use an iPhone OS 17_2 mobile user agent**, versus 74 desktop Safari and 25 desktop Chrome requests. For example, line 104 is a CONNECT to `wd5.myworkday.com:443` from `10.10.1.41:55183` with an iPhone user agent. That majority-mobile browser identity merits an explanation on a visibly Mac endpoint. Browser emulation, an application-specific user agent, or client sharing can explain it, so I assign little weight and do not call it a platform contradiction.

## Evidence For Real

- SSH pivots preserve source tuples and put transport before successful authentication and shell activity. On DB-PROD-01, eCAR lines 590-593 show inbound `10.10.2.30:41315 -> 10.10.4.10:22` at 18:15:19.641, root session login at 18:15:30.192, shell creation at 18:15:32.235, and mysqldump at 18:15:36.100. Native syslog lines 201-204 supply matching connection, accepted-password, PAM, and logind evidence.
- The suspected export has plausible receiver-side evidence. DB-PROD-01 eCAR lines 600-603 show scp, its outbound tuple, a read of the archive, and process exit. APP-INT-01 eCAR lines 938-945 show the corresponding inbound tuple, root authentication, destination-file creation, process exit, and logout. The corresponding Zeek connection is successful and lasts long enough for the visible transfer.
- A deliberately difficult multipart pivot survives actual observation loss: `zeek-core/files.json:405` records the support archive with `seen_bytes=1559340` and `missing_bytes=13524`, while the complete DMZ client observation at line 974 has `1572864` bytes. The counts reconcile exactly. The core HTTP request body is correspondingly 13,524 bytes smaller. This is coherent collection imperfection, not arbitrary disagreement.
- Network source distributions vary with location: core has 12,382 connections, DMZ 9,629, and DB 498. Core is rich in DNS, Kerberos, LDAP, and SMB; DMZ is rich in TLS, HTTP, unsuccessful inbound probes, and web-to-DB traffic. The smaller DB view concentrates on MySQL. The mix fits the visible roles.
- Source-native and normalized process evidence distinguishes fork from exec on Macs; executable transitions do not simply appear as unrelated new processes. The visible MeetingAssist policy message is not followed by an ES process record for PID 62451, so I did not infer execution or effects from the message.
- HTTP outcomes and connection states include useful variation: 407/403/502/503/504 responses, redirects, conditional responses, reset/rejected connections, and incomplete TCP states occur alongside successful traffic. These provide practical ambiguity without preventing pivots.

## Detailed Analysis

### Input provenance and method

I read the supplied neutral briefing and only files under `/private/tmp/log-study-vn4mfwps/data`. Parsing used system `python3` with `/private/tmp` as the working directory. I did not read repository files, authored scenarios, prior reports, or other reviewers' output. Generic inherited project instructions were an environment limitation and were not evidence of the input's origin.

For interpretation of the file-duration concern, I consulted only official Zeek documentation and the upstream Zeek repository. The [Files framework documentation](https://docs.zeek.org/en/v9.0.1/scripts/base/frameworks/files/main.zeek.html) describes the first-seen timestamp and analysis duration; the [upstream implementation](https://raw.githubusercontent.com/zeek/zeek/v8.0.6/scripts/base/frameworks/files/main.zeek) computes duration using the file's last-active time minus its initial timestamp. This supports the arithmetic, but does not by itself prove how this collection exported or customized those fields. The supplied files use the older multi-connection array layout, so I make no claim that the collection ran that exact Zeek version.

### Orientation and source volume

There are 23 endpoint eCAR files containing 37,394 records. Native sources include Windows Security/Sysmon XML, Linux syslog and Bash histories, two Macs with Endpoint Security NDJSON and selected Unified Log messages, and zsh histories. Network sources include three Zeek sensor groups, ASA messages, two Snort alert streams, proxy access, and web access. The visible interval is approximately 2026-11-02 13:00-19:00 UTC.

The sources imply workstation, domain-controller, Linux application/database/file, mail, proxy, and external web roles across `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*` networks. Host labels alone were not used as proof of operating system; native paths, process metadata, and source families support those distinctions.

Core connection services include 3,194 DNS, 2,556 Kerberos, 2,166 HTTP, 1,124 LDAP, 466 SMB, and 62 SSH connections. DMZ has 2,805 TLS, 2,438 HTTP, 988 DNS, and 329 MySQL connections. DB has 329 MySQL connections out of 498. Some sensor overlap is expected; I did not count overlapping observations as independent activity or penalize completeness.

### Operational hunt and pivot feasibility

A root session on WEB-EXT-01 arrives from `10.10.1.22:54014` and authenticates by public key. Its native syslog lines 505, 508-510 show connection at 14:39:29.270856, accepted key at 14:39:31.612100, PAM session opening, and logind registration. eCAR lines 1135-1140 carry the matching transport, root session `0x136656d7`, and shell PID 2705036.

The shell launches host discovery and TCP connect scanning. eCAR line 1150 is `nmap -sn 10.10.2.0/24`; lines 1151 onward carry ICMP observations. Line 1407 is `nmap -Pn -sT -p 22,80,443,445,3306 10.10.2.0/24`. These are operationally compatible commands and network observations. I do not treat the ability to reconstruct this sequence as an authenticity indicator.

APP-INT-01 later has a root shell, sensitive-account file reads, a root SSH client toward the database, and the reverse scp transfer. On DB-PROD-01 the archive is created by mysqldump, gzip completes before scp begins, and the receiving host records its own file creation. The scp connection in `zeek-core/conn.json:11017` is `10.10.4.10:56155 -> 10.10.2.30:22`, `SF`, duration `25.280716`, with substantial originator payload. This is a usable pivot rather than a transport placeholder.

Windows evidence includes an RDP session on WS-AJOHNSON-01 from LT-MRIVERA-02 / `10.10.1.99`, a renamed executable with credential-dumping command arguments, subsequent remote service execution on DC-01, account/group changes, and archive staging. For example, WS-AJOHNSON-01 Sysmon EventRecordID 31206 records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at 16:45:05.060 with a high-integrity aisha.johnson process and a specific parent GUID. DC-01 Sysmon EventRecordID 3292160 records PSEXESVC as SYSTEM, and its Security source records service installation and later directory-account changes. These entries support suspicion; they do not establish that every intended action succeeded.

I performed a broad normalized process-identity check across all 23 eCAR files. Referenced actor/source process IDs were not observed more than 50 ms before their visible creation or after their visible termination. This check does not prove every lineage is correct, but it argues against widespread process-lifecycle breakage. Pre-window parents and post-window survivors were left neutral.

### Multipart upload and collection imperfections

The support upload is a useful realism test because it has two MIME parts, an explicit proxy, a client and upstream leg, and two network sensor views. WS-LNGUYEN-01's Bash history records tar creation and curl multipart submission. `PROXY-01.meridianhcs.local/proxy_access.log:1972` identifies lina.nguyen, the case-specific POST, status 200, `cs_bytes=1573700`, and `wire_sc_bytes=316`.

DMZ HTTP lines 1433 and 1434 show a request body of 1,573,258 bytes; their named gzip parts have 1,572,864 bytes, and the JSON metadata part has 50 bytes. The remainder is plausibly multipart framing. Core HTTP line 1275 has a smaller request body, but the corresponding file and connection records explicitly describe observation gaps. I compared 2,196 overlapping core/DMZ HTTP transactions; 26 had differences in the examined method/host/URI/body/status/user-agent fields, principally body counts. I did not promote those differences to contradictions without examining gap evidence.

The outstanding concern is the complete DMZ client/upstream file timing, whose arithmetic is given above. Four other matched POST file pairs of at least 1,000 bytes in the same DMZ view had upstream last activity later than client last activity, so this is a localized large-transfer concern rather than a proven universal pattern. It deserves packet-level or export-pipeline examination. I have deliberately categorized it as a contract gap instead of claiming an established physical impossibility.

### Mixed-platform interpretation

MAC-MROSS-01 and MAC-MROSS-02 provide native launchd/xpcproxy, terminal, fork/exec, and OpenSSH process transitions. In MAC-MROSS-01 Unified Log line 2, AppleSystemPolicy says it would not allow MeetingAssist PID 62451. I did not find that PID among the supplied ES records; the policy text alone was not used to infer child execution, persistence activation, or downstream effects.

The iPhone user-agent majority on the first Mac is a weak environment signal. It does not demonstrate that the machine is an iPhone, that a native Mac schema is invalid, or that the network source is Mac endpoint telemetry. Without an application inventory or proxy routing explanation, it remains an unresolved client-identity texture issue.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| contract_gap | Zeek HTTP/files, proxied multipart transfer | One large support upload; DMZ file lines 974 and 976 | Equal-size, gap-free file observations imply upstream completion 5.614170 seconds before client-side completion. Operationally concerning, but reassembly/export/application explanations remain unexcluded. |
| weak_signal | HTTP client identity versus native Mac endpoint scope | 142 of 241 core HTTP requests from 10.10.1.41 use an iPhone user agent | Unusual majority-mobile identity on a visibly Mac host; possible emulation/application/client-sharing explanation makes this low weight. |

I found no sufficiently established hard contradiction or generator identity leak. Neither high correlation nor thin selected native source coverage contributed negatively to the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Native-looking identifiers and structured records parse and support useful pivots; no demonstrated native schema defect.
- **Temporal patterns:** 7 — Broad session/process timing works, with an unresolved large-upload timing concern.
- **Cross-source correlation:** 8 — SSH, scp, proxy, and multipart gap accounting are strong; the two-leg upload ending remains questionable.
- **Behavioral realism:** 8 — Commands and effects are generally compatible with the observed hosts and account boundaries.
- **Environmental consistency:** 8 — Sensor service mixes fit the visible roles; the first Mac's predominant mobile user agent remains weakly anomalous.

## Recommendations

- If this were synthetic, derive both proxied upload legs' file-progress timestamps from one shared transfer timeline. Ensure the last upstream file byte cannot be observed before the corresponding client byte, while preserving legitimate streaming and separate sensor clock/observation effects.
- If file-analysis timing rather than transfer timing explains the upload, retain source-visible evidence of the relevant reassembly/export behavior so the timing can be interpreted accurately. Do not simply force all sensor timestamps to match.
- If this were synthetic, tie user-agent selection to the actual endpoint application or an explicitly modeled emulation/client-sharing arrangement. Review the 142 iPhone-agent requests from 10.10.1.41 without assuming every mobile user agent on a Mac is invalid.
- Preserve the existing coherent observation-loss accounting and process/session ownership. They make the dataset meaningfully huntable and should survive any timing repair.
