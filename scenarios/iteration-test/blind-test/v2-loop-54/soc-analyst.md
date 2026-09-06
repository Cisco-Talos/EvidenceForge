# Blind Realism Panel — SOC Analyst Report

## Scope and decision

I reviewed only the generated security data under `scenarios/iteration-test/data`. The corpus contains 104 files and 1,009,742 physical lines across Windows Security and Sysmon XML, Linux eCAR and syslog, shell histories, Zeek, Cisco ASA, Snort, proxy, and web access telemetry. I did not use scenario descriptions, manifests, ground truth, implementation material, repository history, prior assessments, or hard probes.

**Verdict: Real**  
**Verdict confidence: 83/100**  
**Realism score: 87/100**

Here, verdict confidence measures confidence in the Real/Synthetic classification. The realism score measures how closely the corpus resembles data collected from a real environment, where 100 is most realistic.

The corpus supports a credible investigation from perimeter activity through host execution, lateral movement, database collection, staging, and cleanup. Shared tuples, ports, process ancestry, users, session IDs, and timing survive cross-source pivots. I found no impossible lifecycle ordering, impossible network direction, contradictory shared identifier, exact duplicated JSON record, or generator/debug leakage. The strongest weaknesses are a small endpoint file-correlation gap and thin TLS enrichment; neither is a hard contradiction.

## Ranked SOC findings

### P0 — Confirmed public-web compromise and reverse shell

The evidence supports compromise of `WEB-EXT-01`, not merely scanning:

- The same external host first performs obvious SQL injection with sqlmap: `WEB-EXT-01.meridianhcs.local/web_access.log:442` records `185.70.41.45` submitting `UNION SELECT username,password FROM users` at 13:00:00.
- It later uploads to an administrative PHP path successfully: `WEB-EXT-01.meridianhcs.local/web_access.log:466`, `POST /ehr/admin/upload.php`, HTTP 200 at 13:20:29.
- The perimeter sees the corresponding inbound TLS connection with the exact source tuple: `fw-perimeter/cisco_asa.log:3426`, connection 1682908, `185.70.41.45:57162 -> 10.10.3.10:443`.
- Endpoint telemetry records that same inbound tuple at `WEB-EXT-01.meridianhcs.local/ecar.json:747`, record ID `42301197-cc86-4982-ba71-f87cc1978714`.
- Apache then spawns a `www-data` shell containing base64-encoded reverse-shell material: `WEB-EXT-01.meridianhcs.local/ecar.json:748`, record ID `8a269a07-1c35-4344-aacb-c33a59482730`, process object `d72f657d-d1d4-4b20-ba88-34c47e69d979`. The payload decodes to a bash reverse shell to `45.33.32.30:8443`.
- The child process opens that exact connection at `WEB-EXT-01.meridianhcs.local/ecar.json:749`, record ID `5593a37d-4e46-4d23-827d-52c78cce9b0d`.
- Independent network views agree: `zeek-dmz/conn.json:1491`, UID `C59YGfH3YbODFZiVxo`, records `10.10.3.10:60568 -> 45.33.32.30:8443`, `SF`, duration 10.292391 seconds. ASA connection 1682914 is built at `fw-perimeter/cisco_asa.log:3443` and torn down after 10 seconds with 2,940 bytes at line 3450.

This chain is highly huntable. Analysts can pivot from source IP, ASA connection IDs, web URI, eCAR process/object IDs, PID 1480967, destination `45.33.32.30:8443`, or Zeek UID.

### P1 — Root lateral movement, database collection, and staged transfer

The compromise progresses through two coherent SSH hops and reaches sensitive database material:

- On the web host, root launches `ssh -A root@APP-INT-01.meridianhcs.local`: `WEB-EXT-01.meridianhcs.local/ecar.json:2566`, record ID `b33637b4-dfd9-4449-9342-a94ac6d9421c`; its source FLOW at line 2568 is `10.10.3.10:46259 -> 10.10.2.30:22`.
- The application host records the receiving `sshd` process, exact inbound tuple, root login, and shell in order at `APP-INT-01.meridianhcs.local/ecar.json:276-279`. The durable pivots are session `377215`, logon ID `0x15254ec7`, login object `9d31e870-bb04-4fd7-987b-89533ef28575`, and shell object `d63b9b6f-060f-4aca-9620-69444731903c`.
- Native SSH logs independently confirm connection, password acceptance, PAM open, and logind session creation at `APP-INT-01.meridianhcs.local/syslog.log:123-126`. Snort observes the same tuple at `snort-core/snort_alert.log:18` and `snort-perimeter/snort_alert.log:37`.
- The APP root shell starts the second hop with `ssh -A root@DB-PROD-01.meridianhcs.local`: `APP-INT-01.meridianhcs.local/ecar.json:793`, record ID `423518ff-9b71-45e2-af84-c880d5e5ad6e`.
- Two independently plausible Zeek sensor views see `10.10.2.30:47571 -> 10.10.4.10:22`: `zeek-core/conn.json:9711`, UID `CEJJV2c2eKlBKmbmeZM`, and `zeek-db/conn.json:365`, UID `Cfm8Su0b784FST51FnD`. Their start times differ by 72 ms; the DB-side sensor reports 167 missed bytes while the core sensor reports none. Those small differences look like real sensor placement effects.
- DB endpoint telemetry records the receiving process, tuple, login, and shell at `DB-PROD-01.meridianhcs.local/ecar.json:479-482`, with session `279027` and logon ID `0x1185e00b`. Native syslog confirms the same source port and root authentication at `DB-PROD-01.meridianhcs.local/syslog.log:217-220`.
- Root shell history records database discovery, `mysqldump`, compression, hashing, and `scp` at `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:1-22`. The collection command is at line 10 and the staged transfer is at line 22.
- Endpoint records preserve process/file causality: `mysqldump` and `/tmp/rpt_0318.sql` creation at `DB-PROD-01.meridianhcs.local/ecar.json:491-492`; gzip and `/tmp/rpt_0318.sql.gz` creation at lines 502-503; and `scp`, its outbound flow, and file read at lines 527, 529, and 530.
- The transfer tuple `10.10.4.10:56481 -> 10.10.2.30:22` appears in `zeek-core/conn.json:10295` (UID `Cep4Tk2vigAMACjdXO`) and `zeek-db/conn.json:387` (UID `Cmla9EtDU40cUhovXV`) with essentially identical 27.6-second duration and byte accounting.
- APP endpoint telemetry receives `/tmp/.cache/rpt_0318.sql.gz` at `APP-INT-01.meridianhcs.local/ecar.json:836`, record ID `60b64035-5032-4dd3-a145-4e8143573ed8`.
- Cleanup is visible rather than silently omitted: APP clears root history at `APP-INT-01.meridianhcs.local/ecar.json:857-858`, and WEB shreds root history at `WEB-EXT-01.meridianhcs.local/ecar.json:3720`. Both resulting root history files are empty. APP session and process termination complete at `APP-INT-01.meridianhcs.local/ecar.json:865-867`.

The chain can be reconstructed without privileged knowledge of an intended narrative. Its endpoint/network/syslog relationships are unusually useful but remain temporally and semantically plausible.

### P1 — Probable DNS tunneling or application-layer C2 from APP-INT-01

`10.10.2.30` generates a sustained sequence of high-entropy TXT requests under `ns1.westbridge-services.cloud` with short TTLs and encoded-looking responses. Representative records include:

- `zeek-core/dns.json:2065`, UID `C7Arg1XlU1Iqr1NS0h`, query `e57c190f32526635579f4f6d.d80.r11.svc.ns1.westbridge-services.cloud`, TXT response, TTL 1.
- `zeek-core/dns.json:2066-2067`, additional variable-length labels and TXT responses through both internal resolvers.
- `zeek-core/dns.json:2171`, a SERVFAIL mixed into the stream, followed by successful requests at lines 2172-2176.

Snort independently flags samples from the sequence at `snort-core/snort_alert.log:50-51`, 53-54, and 58-59. The stream contains enough response-code, resolver, source-port, RTT, label-shape, and TTL variation to avoid looking like a fixed repeated template. It predates the later DB dump, so I do **not** infer that this channel carried `rpt_0318.sql.gz`; the data supports a suspicious channel, not that stronger causal claim.

### P2 — Internal discovery scan is visible and attributable

The web-host root shell launches `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` at `WEB-EXT-01.meridianhcs.local/ecar.json:1182`, process object `74d5732e-1dfb-4b83-844e-f2815d1a077f`. Subsequent eCAR FLOW records retain that object as actor and show randomized ephemeral ports, targets, ports, and success/failure outcomes; examples are lines 1183-1204. This is actionable process-attributed telemetry rather than only a generic network burst.

The volume is high and the endpoint capture is very complete, but a TCP connect scan against five ports on a /24 can legitimately create this pattern. I do not treat completeness alone as proof of synthesis.

## Realism and source-native assessment

### P0 realism defects

None found.

### P1 realism defects

None found.

### P2 — APP-side staged-file identity loses continuity

The inbound SCP receiver creates `/tmp/.cache/rpt_0318.sql.gz` with actor/process context at `APP-INT-01.meridianhcs.local/ecar.json:836`, but an immediate READ of the same path at line 838 has no actor, PID, principal, command, or session and uses unrelated object ID `file-ddf0c446-e61f-4e62-a9fd-888070df1603`. This is not impossible—collection products do produce partial events—but it breaks an otherwise strong canonical pivot and makes the endpoint side of the staged file less convincing than the DB-side sequence.

### P2 — TLS telemetry is structurally plausible but analytically thin

The Zeek SSL records have credible versions, ciphers, SNI, resumption state, establishment state, histories, and occasional certificate FUIDs; see `zeek-dmz/ssl.json:1-3`. Across the SSL files, however, I found no JA3/JA3S or negotiated ALPN/`next_protocol` fields. That can reflect deployed Zeek scripts and policy, so it is not a contradiction, but it limits client-family and application-protocol pivots in a corpus that is otherwise richly instrumented.

### P3 — IDS naming is noisier than the underlying evidence

Both Snort sensors label the single successful WEB-to-APP SSH connection as `ET SCAN Potential SSH Scan` (`snort-core/snort_alert.log:18`; `snort-perimeter/snort_alert.log:37`). The underlying tuple and timing are correct, and duplicate detection at two visibility points is realistic. The signature semantics are broad enough that a SOC would need endpoint and Zeek context before calling it scan activity. This reads as ordinary signature noise, not a synthetic contradiction.

## Concrete contradiction review

I did not identify a concrete hard contradiction in the reviewed data.

- The suspicious Windows Security `EventRecordID` reset on DC-01 is explained in-source: record 28260993 at `DC-01.meridianhcs.local/windows_event_security.xml:252742` is followed by Event ID 1102 at lines 252776-252783 with record ID 1, and normal auditing resumes with record ID 2. The 1102 payload attributes the clear to `NT AUTHORITY\\SYSTEM` with logon ID `0x3e7` at lines 252797-252800.
- eCAR process terminations reviewed occur after corresponding creates; root SSH sessions close after login and shell lifetime.
- ASA, Zeek, eCAR, syslog, web, and IDS views use compatible direction, address, port, duration, and timing semantics. Independent sensors are similar without being implausibly byte-for-byte identical.
- Missing fields and source gaps occur, but none require an impossible event ordering or fabricated network path.

## Huntability assessment

**Overall huntability: high.** Useful stable pivots include IP/port tuples, Zeek UIDs, ASA connection IDs, eCAR record/object/actor IDs, PIDs and parent PIDs, usernames, logon IDs, SSH session IDs, file paths, command lines, DNS names, and web URIs. Analysts can move in both directions—from an IDS/network alert to the initiating process, or from a suspicious endpoint command to network and receiver evidence.

Background traffic and source noise are substantial enough that the malicious records are not the only activity in the environment. The attack is still fairly legible because the observability is broad and the adversary behavior is loud. I treat that as strong training huntability, not by itself as evidence of synthetic generation.

## Final rationale

The deciding factor is not that the attack can be narrated cleanly; it is that the narrative survives source-native checks. The public TLS tuple, spawned process, reverse connection, two SSH transports, receiver authentication records, session/process ancestry, database file lifecycle, SCP transfer, multi-sensor byte/timing views, and cleanup all agree within realistic collection offsets. Small imperfections—especially the orphaned APP file READ, absent TLS fingerprint enrichment, and broad IDS labels—look more like telemetry limitations than generation artifacts. From the data alone, I would accept this as a real collected corpus with high confidence, while preserving modest uncertainty because its end-to-end observability is stronger than many production environments.
