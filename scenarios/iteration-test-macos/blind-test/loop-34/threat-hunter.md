# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 67

## Executive Summary

The collection supports useful investigations across a mixed enterprise fleet, and the principal intrusion pivots generally have sensible host, account, transport and artifact relationships. My synthetic verdict is driven primarily by repeated exact fractional-second timing fingerprints in native macOS process records, supported by repeated baseline command texture and questionable direct process attribution for Linux transport activity; I did not establish an impossible intrusion timeline.

## Evidence For Synthetic

- [distribution_texture] Native macOS fork timestamps repeatedly preserve precisely the same fractional second across separate commands tens of seconds apart. On `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35 and 38 are `13:48:54.728144000Z`, `13:49:24.728144000Z` and `13:50:14.728144000Z`; lines 51, 54 and 57 repeat `.619862000` at 14:37:53, 14:38:30 and 14:39:22. On MAC-MROSS-02, lines 129, 132 and 135 are 17:33:03, 17:33:51 and 17:34:39, all ending `.014881000Z`. These are distinct shell fork observations, not duplicate ingestion of one event. Across the two files, 32 of 57 zsh fork records fall into 13 such repeated-fraction groups. Repeated exact microsecond preservation across human-style command bursts is a strong construction fingerprint.
- [contract_gap] Linux connection ownership appears flattened to a higher-level command. `WEB-EXT-01.meridianhcs.local/ecar.json:1025` creates PID 2702837 as the outer `bash -c 'echo … | base64 -d | bash'`; line 1026 attributes the TCP connection to that same PID/image/outer command. The decoded payload is another Bash invocation containing `bash -i` with a `/dev/tcp/45.33.32.30/8443` redirect. Ordinary Bash execution puts that socket operation in a pipeline/payload child, rather than the waiting outer pipeline shell. The file has no PROCESS CREATE with `ppid=2702837`. This is an ownership concern, not a claim that missing process types alone prove fabrication; a documented ancestry-rollup convention in the normalized collector would weaken it substantially.
- [contract_gap] The same direct-actor concern recurs in `DB-PROD-01.meridianhcs.local/ecar.json:499-500`: PID 1089111 has image `/usr/bin/scp`, and is presented as the actor opening TCP/22 to 10.10.2.30 using client source port 44357. Standard OpenSSH scp delegates the SSH transport to an ssh subprocess. There is no child process record with `ppid=1089111`, despite detailed shell and command lifecycle records around this transfer. The flow itself and successful receiver session are well supported; the concern is precise endpoint process ownership. I group this with the preceding concern rather than count it as an independent impossible network event.
- [distribution_texture] Routine Linux privileged-command noise is strongly front-loaded across unrelated server roles and drawn from closely overlapping maintenance vocabulary. The eight servers WEB-EXT-01, APP-INT-01, DB-PROD-01, LOG-MON-01, PROXY-01, FILE-LNX-01, MAIL-EDGE-01 and MAIL-CLIN-01 have respectively 12, 6, 8, 10, 14, 18, 14 and 15 PROCESS CREATE command lines beginning `sudo `; all 97 occur before 14:30 in a collection continuing until 19:00. Examples shared across hosts include `apt-cache policy openssl`, `find /var/log -type f -mtime -1`, `systemd-analyze blame`, `lsof -i -P -n` and service status/restart commands. A coordinated maintenance period could explain the timing, so this is supporting texture rather than a contradiction.
- [distribution_texture] The Mac share-access workload repeatedly uses `cat` for PDF/XLSX content and `tee` for office documents. MAC-MROSS-01 eCAR lines 176/180 associate `/bin/cat` with `/Volumes/Users/Documents/contacts.xlsx`; lines 215/218 and 298/301 do the same for PDF files. Lines 138/140 write a `.pptx` through `tee`, and 348/353 write an `.xlsx` through `tee`. MAC-MROSS-02 lines 338/341 and 432/435 likewise read a PDF and an XLSX through `cat`. These operations are possible, but their repeated mix resembles a generic file-operation recipe more than varied office-document use. This has modest weight because deliberate shell tests could produce it.

## Evidence For Real

- The environment is coherent at a useful investigative scale: 23 hosts with normalized endpoint records, Windows Security/Sysmon XML, Linux syslog and shell histories, two native macOS process streams, three network sensor locations, proxy, firewall, IDS and web access records. The endpoint window is approximately 2026-11-02 13:00:00.933 through 18:59:58.385 UTC. Role names and addresses indicate workstation, server, DMZ and database segments rather than one undifferentiated host pool.
- The web compromise pivot is technically credible. `WEB-EXT-01.../web_access.log:532` records a successful POST to `/ehr/admin/upload.php` from 185.70.41.45 at 14:20:12. eCAR line 1025 records an Apache-child Bash process at 14:20:13.774, followed by the outbound reverse-shell tuple at line 1026. `zeek-dmz/conn.json:1876` independently has 10.10.3.10:37451 to 45.33.32.30:8443, `SF`, 620/1840 application bytes and a 12.087564-second duration. It is not erroneously labeled as TLS merely because of port 8443.
- The database transfer has a believable sequence of session, dump, compression, transfer and receiver artifact. DB-PROD-01 eCAR lines 491-503 show root login, mysqldump, the SQL file, gzip, the compressed file, scp, a file read and process termination. APP-INT-01 syslog lines 210-214 identify the exact incoming source port 44357, successful public-key authentication and PAM open/close, while its eCAR line 725 identifies the receiving path. `zeek-db/conn.json:389` and `zeek-core/conn.json:10870` agree on the tuple and 427268/24768 bytes.
- The Windows collection distinguishes outbound credentials from local process identity. On WS-AJOHNSON-01, eCAR line 973 invokes `runas /netonly /user:marcus.chen`; line 985 starts a local Aisha-owned cmd.exe with a new LogonID, and subsequent collection processes remain Aisha-owned. This avoids incorrectly relabeling the local token as Marcus merely because Marcus credentials were supplied for network use.
- Archive staging and exfiltration can be followed through different sources. WS-AJOHNSON-01 eCAR lines 1023-1027 name individual staged Finance files; line 1066 creates `cache_7f3a.zip`, line 1117 launches curl and line 1126 reads the archive. `PROXY-01.../proxy_access.log:3124` records the authenticated Aisha POST with `cs_bytes=18783067`; `zeek-core/conn.json:11143` has the corresponding client port 56465 and 18783414 origin bytes. The proxy explicitly records SSL inspection, making visibility of the HTTPS POST plausible.
- Background activity includes failed sessions, public scanning, DHCP, DNS errors, scheduled sysstat/php/apt activity and varied connection outcomes. These supply alternate leads. They are positive operational detail, not proof of production origin.

## Detailed Analysis

### Scope and investigation approach

I inventoried all supplied source families, parsed the endpoint JSON and Windows event XML, inspected Linux and Mac shell histories, and cross-referenced selected suspicious endpoint actions against network, proxy, web and session records. Source counts include 12170 core, 9278 DMZ and 446 database connection rows, 3353 proxy records, 977 web requests, and 167 IDS alerts. Those volumes are compatible with a bounded, selected collection; I do not infer full production audit coverage from their presence.

The principal addresses are internally coherent: WEB-EXT-01 uses 10.10.3.10, PROXY-01 uses 10.10.3.20, APP-INT-01 uses 10.10.2.30, DB-PROD-01 uses 10.10.4.10, and the two Macs use 10.10.1.41/42. The root SSH activity is not automatically the same identity as a directory user with a similar source workstation. For example, WEB-EXT-01 syslog line 375 explicitly authenticates root from 10.10.1.31, while line 353 authenticates maya.ross from 10.10.1.42. The collection provides sufficient information to preserve that distinction.

### Attack pivots and operational coherence

The visible web-upload-to-Bash-to-egress pivot is actionable and has sane relative ordering. Later root activity on WEB-EXT-01 includes network enumeration and Nmap scans. eCAR line 1170 records `nmap -sn 10.10.2.0/24` at 14:40:05.446, followed by a five-port connect scan at line 1425, 14:40:35.683. The core sensor records a burst with many unanswered probes and a small set of responding targets; it does not unrealistically turn the whole address range into successful application sessions.

The DB-PROD-01 root session at 18:15 has a concrete remote source, 10.10.2.30:42289. Its syslog lines 228-230 show accepted password, PAM session open and logind session creation before the dump process. The scp receiver subsequently authenticates a separate root session with source port 44357. This is a useful distinction between the administrative channel into the database and the file-transfer channel back out.

The transfer's process tree is less convincing than its network/session relationships. The data assigns socket ownership to scp, and receiver file creation to the same sshd process identity originally presented as the privileged session handler. Different SSH implementations and normalized telemetry conventions can vary, so I treat the direct ownership issue as a contract concern requiring collection-semantics confirmation, rather than a hard source-native impossibility.

I checked visible eCAR process IDs by their durable object identifiers for references before their CREATE or after their TERMINATE. That check did not find a contradictory visible process lifecycle. Surviving parents or sessions at the collection boundaries were left neutral.

### Timing and baseline texture

The strongest authenticity evidence comes from the macOS native timing, not from how narratable the suspicious activity is. A single exact fractional-second pair could be a timer-driven script. Thirteen groups spanning two machines, multiple hours and numerous ordinary shell commands suggest construction by adding whole-second offsets to one group anchor. The native files retain high-resolution time, and other events vary below the second, so general timestamp rounding does not explain why these selected command groups preserve the entire fractional component.

The Linux sudo distribution reinforces the impression of a finite setup/noise block followed by a different sustained workload. On WEB-EXT-01 all 12 visible sudo process starts occur in the first 28 minutes; LOG-MON-01's ten occur in its first 31 minutes; DB-PROD-01's eight finish by 13:43:26. Meanwhile background service and network events continue for hours. This is possible during morning maintenance, and I have not labeled the absence of later sudo commands a missing-source defect. Its weight comes from the synchronized fleet-wide shape and overlapping command recipes.

The office-file shell operations are similarly a behavioral distribution concern. Reading a PDF through cat is legal and can be malicious or diagnostic. Repeatedly rendering otherwise different share activities as `cat`/`tee`, including binary office formats, limits the behavioral variety visible in the endpoint data. It is a secondary signal, not a claim that a GUI source must be present.

### Source interpretation and limitations

The native Mac files contain fork, exec and exit notifications, with version 11 and durable audit-token/PID-version information. I did not require file-event notifications absent from that selected stream. A Unified Log policy message on MAC-MROSS-01 at 15:42:04 says security policy “would not allow” MeetingAssist; I did not treat that wording as proof of a denied execution, successful execution or subsequent payload effects.

I did not score sanitized domain names, filesystem copy timestamps, selected Sysmon coverage, cross-source completeness, or the compactness of the intrusion. The suspicious behavior itself is operationally plausible. The 67 score reflects a strong native timing fingerprint and several bounded texture/ownership concerns, balanced against good lifecycle and network/session consistency; it does not reflect certainty that every apparent process-attribution concern is a defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security | 32/57 zsh fork rows in 13 exact fractional-second groups across two hosts | Highest weight: repeated precise whole-second-offset construction texture |
| contract_gap | Linux normalized process/flow records | Reverse-shell pipeline and scp transport | Moderate weight: higher-level command appears as direct socket actor; collector ancestry-rollup semantics could explain it |
| distribution_texture | Linux baseline endpoint records | 97 sudo starts across eight servers, all before 14:30 | Supporting weight: shared, front-loaded maintenance texture; coordinated maintenance remains an alternative |
| distribution_texture | Mac endpoint file/process records | Repeated cat/tee operations involving PDF/XLSX/PPTX share paths | Modest weight: repetitive generic file-workload behavior rather than an impossible operation |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed records are generally coherent and source-shaped; no verified native schema contradiction established.
- **Temporal patterns:** 5 — Coherent attack sequencing, but repeated exact native subsecond anchors are conspicuous.
- **Cross-source correlation:** 8 — Strong tuple/session/artifact pivots, with reservations about direct Linux process ownership.
- **Behavioral realism:** 6 — Plausible tradecraft and operational noise, weakened by repeated baseline command/file-operation recipes.
- **Environmental consistency:** 8 — Roles, platforms, subnets and SSL-inspection visibility generally fit the observed activity.

## Recommendations

- If this were synthetic, vary each native process occurrence at a realistic subsecond scale; do not preserve one exact fractional timestamp across a whole command group.
- If this were synthetic, represent the actual pipeline/payload process that opens the reverse-shell socket and the ssh child that owns scp transport. If the normalized collector intentionally attributes to an initiating ancestor, make that distinction explicit instead of presenting ancestry as a direct PID association.
- If this were synthetic, derive privileged maintenance activity from per-host/per-user schedules so unrelated roles do not all exhaust similar sudo command pools near collection start.
- If this were synthetic, diversify share-file handling according to the application and file type. Reserve cat/tee on office binaries for specific shell/testing behavior supported by its surrounding activity.
