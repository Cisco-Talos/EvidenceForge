# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 96/100  
**Synthetic-Confidence Score:** 92/100  
**Realism Score:** 62/100

The data supports a coherent and highly huntable compromise, but one physically implausible
cross-host file-transfer sequence and one orphaned source-local SSH lifecycle are strong evidence
of synthetic construction. The realism score remains materially higher than the synthetic verdict
might imply because most endpoint, network, firewall, authentication, HTTP, email, and SMB pivots
are internally useful and source-native.

## Executive Summary

I found a clear malicious sequence beginning with external web reconnaissance and exploitation,
followed by a web-server callback, long-lived root access, internal SSH movement, database access,
staging, and an SMB transfer to a file server. The core pivots are unusually complete: exact tuples,
PIDs, process UUIDs, session identifiers, Zeek UIDs, firewall connection IDs, SMB FUIDs, paths, and
hashes repeatedly connect the sources. A benefits-themed email and two endpoint downloads provide a
second viable hunt thread. Benign activity is broad enough to exercise routine DNS, TLS, HTTP, SMB,
email, authentication, and process pivots.

The decisive flaw occurs near the end of the database-staging chain. Zeek reports that the SCP/SSH
connection from DB-PROD-01 to APP-INT-01 carries only 30,675 client payload bytes and remains open
until approximately 17:35:21 UTC. Nevertheless, APP-INT-01 creates the named gzip file by
17:35:02.406, begins forwarding it over SMB at 17:35:02.069, and Zeek observes all 794,475 bytes of
that file by roughly 17:35:03. This is not a small timestamp-jitter issue: a pre-compressed 794 KB
file cannot be fully received and retransmitted after only 30 KB of upstream SSH application bytes,
18 seconds before that upstream connection closes. The receiving host also changes the file's eCAR
object identity between CREATE and READ.

A second significant gap affects a long-lived root SSH session on WEB-EXT-01. Zeek and eCAR show its
start, login, shell, and termination, while local syslog contains only the final `session closed`
record for the same sshd PID. Other SSH sessions in the same syslog have complete connection,
acceptance, PAM-open, and PAM-close sequences, making a source-wide collection limitation unlikely.

Malicious and benign behaviors are distinguishable—arguably too easily. The web attacker
`185.70.41.45` produces 351 of 748 web-access rows (46.9%), progresses from scanner traffic to a
literal SQL injection request and successful upload, and is followed within seconds by an
Apache-spawned base64 reverse shell. This makes the intended threat highly discoverable, but the
concentration and explicitness reduce the ambiguity expected in a difficult production hunt.

## Evidence For Synthetic

- **[hard_contradiction] [P0] The staged gzip file is forwarded before SCP can have delivered it.**
  DB-PROD-01 launches `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/...` at
  `DB-PROD-01.meridianhcs.local/ecar.json:527`, opens tuple
  `10.10.4.10:56481 -> 10.10.2.30:22` at line 529, and reads the source object at line 530.
  Zeek UID `Cep4Tk2vigAMACjdXO` records only 30,675 originator bytes over 27.609304 seconds
  (`zeek-core/conn.json:10295`), ending near 17:35:21.036. In conflict with that transport,
  APP-INT-01 creates the destination at 17:35:02.406 (`APP-INT-01.../ecar.json:836`), while SMB
  UID `CXsRY9o0y6Enensk4U` starts at 17:35:02.069 and carries 797,300 originator bytes in 1.607327
  seconds (`zeek-core/conn.json:10301`). `SMB::FILE_WRITE` reports 794,475 bytes and FUID
  `FABbVCpePpwSpHJOLNs` at `zeek-core/smb_files.json:331`; the file analyzer confirms all 794,475
  bytes with zero missing bytes and SHA-256
  `ecaa15a416671a544681e1b23d5675503d83f1db2c507265a16cfdf3a1aeffa0`
  (`zeek-core/files.json:626`). This is physically incompatible with the upstream SCP record.

- **[contract_gap] [P0, same transfer] File identity breaks at the APP-INT handoff.** The destination
  CREATE uses object ID `0c591283-7383-4f9b-9575-a5abc466dcd9`
  (`APP-INT-01.../ecar.json:836`), but the immediate READ of the identical path uses
  `file-ddf0c446-e61f-4e62-a9fd-888070df1603` (`APP-INT-01.../ecar.json:838`). That second ID is
  then used for the write on FILE-LNX-01 (`FILE-LNX-01.../ecar.json:1327`). The chain preserves the
  filename but silently swaps the canonical file identity at the intermediate host.

- **[contract_gap] [P1] WEB-EXT-01 syslog has an orphaned SSH close.** Zeek DMZ UID
  `C3SrG5kFGoy3k17r7` records `10.10.1.22:32825 -> 10.10.3.10:22` beginning at 13:40:16.621 and
  lasting 15,424.919064 seconds (`zeek-dmz/conn.json:1795`); the core sensor independently sees the
  same tuple and byte counts under UID `CsziPPxUaYDVKYOxo` (`zeek-core/conn.json:2390`). eCAR ties
  the connection to sshd PID `1485169`, a root login, session `351038`, and a shell. Yet the only
  matching local syslog record is `pam_unix(sshd:session): session closed for user root` at
  `WEB-EXT-01.meridianhcs.local/syslog.log:1015`. The opening occurs well inside the six-hour window,
  and the same file contains complete accepted/opened/closed sequences for other SSH sessions, so
  boundary truncation does not explain the orphan.

- **[distribution_texture] [P2] One hostile source dominates the web telemetry and advertises every
  major stage.** `185.70.41.45` accounts for 351/748 (46.9%) rows in
  `WEB-EXT-01.meridianhcs.local/web_access.log`. The same source emits a literal sqlmap request at
  line 442 and receives HTTP 200 for `/ehr/admin/upload.php` at line 466. At this concentration, a
  top-talker query plus user-agent or URI filtering isolates the principal threat with little need
  for behavioral discrimination. This is plausible for a low-volume exposed server, so it is a
  texture concern rather than a hard contradiction.

- **[weak_signal] [P3] The suspicious email branch has incomplete recipient and endpoint provenance.**
  The inbound SMTP transaction addresses Diego Ramirez, Evelyn Brooks, and Priya Patel
  (`zeek-core/smtp.json:3`), but the internal relay lists only Diego and Evelyn
  (`zeek-core/smtp.json:4`). The attachment hash is stable across the two SMTP hops
  (`zeek-core/files.json:30,32`), and files of the same name later appear on Diego's and Evelyn's
  endpoints (`WS-DRAMIREZ-01.../ecar.json:78`; `WS-EBROOKS-01.../ecar.json:119`), but the endpoint
  records carry no hash or FUID. This may reflect routing and sensor limits, so the finding is
  inconclusive and lightly weighted.

## Evidence For Real

- **HTTP-to-endpoint execution is temporally and causally strong.** The external upload succeeds at
  `WEB-EXT-01.meridianhcs.local/web_access.log:466`. The corresponding inbound endpoint flow from
  `185.70.41.45:57162` is at `WEB-EXT-01.../ecar.json:747`, followed by Apache PID 23958 spawning
  `/bin/bash` as `www-data` with a base64-decoded callback command at line 748. The resulting
  `10.10.3.10:60568 -> 45.33.32.30:8443` flow is line 749 and is rendered independently as Zeek UID
  `C59YGfH3YbODFZiVxo` (`zeek-dmz/conn.json:1491`).

- **Firewall accounting agrees with the callback.** ASA connection ID `1682914` is built for the
  exact tuple at `fw-perimeter/cisco_asa.log:3443`, torn down ten seconds later with 2,940 bytes at
  line 3451, and accompanied by its NAT translation. Zeek reports a 10.292391-second successful
  connection with 620/1,840 application bytes. Those are source-appropriate, mutually compatible
  views rather than copied identical fields.

- **Internal SSH movement is highly pivotable.** APP-INT-01 syslog records connection, accepted
  password, PAM open, and systemd session creation for root from `10.10.3.10:46259`, sshd PID
  `1916408`, session `377215` (`APP-INT-01.meridianhcs.local/syslog.log:123-126`), then coherent
  close/removal at lines 225-226. DB-PROD-01 similarly records accepted root access from
  `10.10.2.30:47571` and PAM open under PID `884604` (`DB-PROD-01.../syslog.log:218-219`), with a
  close at line 234. These records support endpoint-to-auth-to-network pivots.

- **Database staging has realistic host evidence before the flawed transfer.** The root shell creates
  `/tmp/rpt_0318.sql` through `mysqldump` (`DB-PROD-01.../ecar.json:492`), compresses it and creates
  `/tmp/rpt_0318.sql.gz` (`ecar.json:502-503`), inspects it (`ecar.json:506`), hashes it
  (`ecar.json:509`), and later starts SCP (`ecar.json:527`). The matching commands also appear in
  `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:10-22`.

- **SMB evidence is rich and internally correlated after the impossible handoff.** UID
  `CXsRY9o0y6Enensk4U` ties the connection (`zeek-core/conn.json:10301`) to the
  `\\FILE-LNX-01\ClinicalResearch` mapping (`zeek-core/smb_mapping.json:198`), file open/write
  (`zeek-core/smb_files.json:330-331`), FUID and cryptographic hashes
  (`zeek-core/files.json:626`), and target endpoint write by `smbd` as `svc_mhsync`
  (`FILE-LNX-01.../ecar.json:1327`). This is excellent SMB-to-file-server pivot structure.

- **Email provides a credible alternate lead.** SMTP preserves message ID
  `<notices-b9dac45a-8235363@benefits-serviceportal.com>` and attachment hashes between the edge and
  internal hops (`zeek-core/smtp.json:3-4`; `zeek-core/files.json:30,32`). Edge browser processes
  create `benefits-confirmation.txt` in two users' Downloads directories
  (`WS-DRAMIREZ-01.../ecar.json:78`; `WS-EBROOKS-01.../ecar.json:119`). Even without endpoint hashes,
  recipient, filename, process, host, and timing make the pivot operationally useful.

- **The surrounding environment is not empty camouflage.** Routine endpoint process lifecycles,
  authentication, DNS, TLS, HTTP, SMTP, proxy, SMB, firewall, IDS, Linux syslog, and Windows
  telemetry provide multiple benign comparison populations. Network flows use TCP, UDP, and ICMP,
  and failed inbound probes coexist with successful business traffic and internal service access.

## Detailed Analysis

### Ranked Findings (P0-P3)

| Priority | Finding | Impact on hunt realism | Disposition |
|---|---|---|---|
| P0 | 794,475-byte file is forwarded before a 30,675-byte SCP transport can deliver it | Breaks physical causality and decisively reveals synthetic orchestration | Must fix |
| P0 | APP-INT file object changes identity between CREATE and immediate READ | Breaks durable cross-host file provenance in the same action chain | Must fix with transfer lifecycle |
| P1 | WEB-EXT root SSH session closes in syslog without an observed in-window open | Creates a source-local orphan despite complete endpoint/network evidence | High priority |
| P2 | One hostile IP produces 46.9% of web rows and exposes scan, SQLi, upload, and shell stages | Makes malicious activity much easier to separate than normal | Tune distribution |
| P3 | Email relay loses one recipient and endpoint downloads lack attachment hashes | Weakens exact email-to-host attribution; may be a legitimate collection gap | Investigate |

### Broad Hunt Reconstruction

1. **Web lead:** rank HTTP sources and user agents. `185.70.41.45` dominates, reaches a SQLi-shaped
   request (`web_access.log:442`), then an upload endpoint with HTTP 200 (`web_access.log:466`).
2. **Endpoint pivot:** search the web host within seconds of the upload. Apache spawns base64-wrapped
   bash as `www-data` (`ecar.json:748`), preserving parent PID and process UUID.
3. **Network pivot:** the child opens `10.10.3.10:60568 -> 45.33.32.30:8443`
   (`ecar.json:749`), which resolves to Zeek UID `C59YGfH3YbODFZiVxo` and ASA connection `1682914`.
4. **Auth/lateral pivot:** a separate long-lived root SSH path is visible from `10.10.1.22` to the web
   host, then from WEB-EXT to APP-INT, and APP-INT to DB-PROD. APP and DB syslog authentication is
   convincing; WEB syslog is incomplete.
5. **Database/file pivot:** DB root runs discovery and dump/compress/hash/SCP actions, using stable
   session/process relationships. The transition from SCP reception to SMB forwarding is where
   causal timing and byte accounting fail.
6. **SMB pivot:** the SMB tuple, share, action, FUID, size, hashes, and file-server endpoint write all
   correlate well after the handoff.
7. **Email pivot:** message ID, SMTP recipients, filenames, and hashes lead to two browser-created
   endpoint files, but exact endpoint content identity cannot be proven from the available records.

### Distinguishability Assessment

The malicious chain is readily distinguishable from benign behavior. Strong discriminators include
the scanner/sqlmap user agents, successful admin upload, Apache-to-shell ancestry, base64 command,
rare port 8443 callback, root SSH hops, credential/config access, database dumping, staging under
`/tmp`, SCP, and an unusual service-account SMB write into `ClinicalResearch/Integration/DB-Staging`.
Benign process, service, DNS, TLS, and SMB populations exist, so the detections are not operating in
an empty dataset. However, the density of explicit malicious markers and the hostile web source's
46.9% share mean that basic sorting and string matching recover much of the chain. The data tests
pivot mechanics better than subtle threat discrimination.

### Boundary and Collection Considerations

I did not treat unmatched lifecycle events at the dataset edges as contradictions. The P1 SSH issue
is different: its transport and eCAR login start at 13:40, well inside the observed period, while
the matching local syslog contains only a close at 17:57. I also did not penalize differences in
Zeek UIDs across core and DMZ sensors; independent sensors normally assign independent UIDs. Nor did
I require firewall and Zeek byte counts to be identical, because source accounting layers differ.
The P0 file-transfer finding survives those allowances because both timing and minimum payload size
violate causality by a large margin.

## Synthetic Indicator Summary

| Category | Count | Strongest observation |
|---|---:|---|
| `hard_contradiction` | 1 | Full 794,475-byte gzip appears downstream before a 30,675-byte SCP flow finishes |
| `contract_gap` | 2 | File object identity swap; orphaned WEB-EXT SSH syslog close |
| `distribution_texture` | 1 | Single hostile source contributes 46.9% of web access rows |
| `schema_or_format` | 0 | No decisive source-format defect observed in the sampled hunt pivots |
| `environment_or_collection_plausibility` | 0 | Broad source mix and topology are generally plausible |
| `weak_signal` | 1 | Partial email recipient/provenance ambiguity |

The P0 is repeated across several artifacts but represents one causal defect, not multiple
independent findings. It is nevertheless sufficient to support the Synthetic verdict because it
links the exact filename, hosts, tuple, size, and immediate downstream use.

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field format accuracy | 8/10 | Zeek, ASA, syslog, HTTP, SMTP, SMB, eCAR, and hashes are generally source-appropriate |
| Temporal patterns | 5/10 | Most chains order well, but the staged-file transfer violates physical timing |
| Cross-source correlation | 6/10 | Excellent identifiers and tuples, reduced by file identity and SSH lifecycle gaps |
| Behavioral realism | 7/10 | Commands and service interactions are credible, though the threat is unusually explicit |
| Environmental consistency | 7/10 | Diverse benign activity and sensible service roles; hostile web traffic is over-concentrated |

**Weighted overall realism: 62/100.** The score gives substantial credit for hunt utility and
source-native correlation but caps the result because physical causality is a foundational
requirement, not a cosmetic defect.

## Recommendations

1. Make the SCP action own a single file identity and authoritative byte size from DB creation
   through APP reception. Do not allow dependent reads or forwarding until the transfer completion
   time, and ensure SSH originator payload is at least compatible with the transferred compressed
   object plus protocol overhead.
2. Preserve `f8e8a364-15e7-42c6-85c7-1c82c413f1d9` or a documented derived transfer identity across
   the remote CREATE, APP READ, SMB send, and FILE-LNX write. If host-local IDs must differ, add an
   explicit content hash or transfer/copy relationship that proves lineage.
3. Apply SSH syslog observation decisions to the whole source-local lifecycle group. Connection,
   accepted/failed authentication, PAM open, systemd session, PAM close, and removal should be kept
   or dropped coherently for a session/sshd PID.
4. Reduce the dominant attacker's web share or add comparable benign scanner, monitoring, API, and
   administrative traffic. Preserve the exploit chain, but require hunters to correlate behavior
   rather than identify one overwhelming top talker.
5. Carry attachment SHA-256 or a durable content/transfer identifier into endpoint file-create
   telemetry when the email-to-download relationship is intended to be provable. Clarify the Priya
   recipient branch with a delivery, rejection, routing, or mailbox record.
6. Add automated cross-source invariants for transfer families: downstream availability must follow
   upstream completion; observed payload must support object size; lifecycle records must be
   source-locally coherent; and copy operations must preserve an explicit provenance link.
