# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 43

## Executive Summary

This is a highly huntable, operationally coherent six-hour enterprise dataset whose endpoint, authentication, network, firewall, proxy, web, and file evidence supports realistic pivots without impossible ordering. The strongest synthetic indicator is environmental rather than narrative: several unrelated Linux server roles exhibit conspicuously similar `snapd`, `microk8s`, and `snapd-desktop-integration` activity. Overall, the evidence looks more production-like than generated, but the cross-role baseline homogeneity prevents a confident Real verdict.

## Evidence For Synthetic

- **[Environmental consistency — moderate]** Unrelated Linux roles repeatedly share the same unusually specific software-maintenance vocabulary. `APP-INT-01`, `MAIL-EDGE-01`, `PROXY-01`, `LOG-MON-01`, and `WEB-EXT-01` all emit recurring `snapd` activity involving both `microk8s` and `snapd-desktop-integration` (for example, `PROXY-01.../syslog.log:26,28`, `MAIL-EDGE-01.../syslog.log:62,125`, `WEB-EXT-01.../syslog.log:35,120`, and `LOG-MON-01.../syslog.log:16,59`). A shared golden image can explain common packages, but desktop-integration and microk8s maintenance appearing across mail-edge, proxy, monitoring, application, and web roles is a recognizable cross-host template texture.
- **[Field/telemetry texture — weak]** Windows endpoint streams frequently place a compact, orderly module-load sequence immediately after process creation. The malicious `curl.exe` on `WS-AJOHNSON-01`, for example, is followed within milliseconds by a clean sequence of `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `ucrtbase.dll`, and `bcryptprimitives.dll` (`ecar.json:1238-1244`). The values and ordering are individually credible, but this degree of regularity across endpoint activity feels more curated than typical selectively collected module telemetry.
- **[Environmental consistency — weak]** Collection is exceptionally broad across nearly every modeled asset: eCAR exists throughout the fleet while Windows Security/Sysmon, Linux syslog, Zeek sensor views, firewall, IDS, proxy, web, SMTP, SMB, TLS, and file metadata fill most investigative gaps. Completeness is not itself evidence of synthesis and was not treated as a contradiction, but combined with the homogeneous host baselines it modestly raises synthetic likelihood.

## Evidence For Real

- **[Cross-source correlation — strong]** The initial web compromise is causally ordered across sources. A Nikto-originated web scan from `185.70.41.45` precedes the `13:20:01` POST to `/ehr/admin/upload.php` (`WEB-EXT-01.../web_access.log:424`); Apache then launches a `www-data` bash process containing a base64-decoded reverse shell, followed by the matching `10.10.3.10:49570 -> 45.33.32.30:8443` endpoint flow. Zeek and ASA observe the same tuple and an approximately eight-second session, with transport opening after process creation and closing before bash termination.
- **[Operational lifecycle — strong]** The long-lived SSH session from `WS-PPATEL-01` to `WEB-EXT-01` has credible source-process, transport, authentication, shell, and close semantics. The source `ssh.exe root@WEB-EXT-01.meridianhcs.local` precedes the TCP/22 connection; target syslog records connection, accepted password, PAM open, and logind session; the source process, Zeek flow, PAM session, and logind scope all close around `17:53:37-17:53:40` after more than four hours. This is lifecycle-compatible without suspicious timestamp identity.
- **[Behavioral realism — strong]** Post-compromise behavior is operationally plausible rather than a list of isolated indicators: host and resolver inspection, credential-file discovery, subnet and service scans, web configuration and SSH-key access, lateral SSH to `APP-INT-01`, onward access to `DB-PROD-01`, database discovery, `mysqldump`, compression, checksum, SCP staging, SMB placement, and later history destruction. Commands use role-appropriate tools, paths, users, and parent processes.
- **[Cross-source correlation — strong]** Database staging remains pivotable across hosts and protocols. `DB-PROD-01` creates and reads `/tmp/rpt_0318.sql.gz`, SCPs it to `APP-INT-01`, and the target records the SSH-side file creation. Zeek SMB activity then shows `APP-INT-01` opening and writing `rpt_0318.sql.gz` to `FILE-LNX-01`; target eCAR records the corresponding `smbd` write under `svc_mhsync`. Small source-local timestamp offsets are consistent with sensor and endpoint observation latency.
- **[Cross-source correlation — strong]** The `WS-AJOHNSON-01` exfiltration is particularly convincing. eCAR, Security 4688, and Sysmon agree on PID 7140, the `aisha.johnson` token, logon ID `0x27caf0d`, `services.exe` parentage, archive path, and explicit-proxy curl command. The endpoint flow, Zeek HTTP CONNECT, proxy CONNECT/POST pair, DMZ proxy-to-origin flow, and ASA sessions retain the client port/tunnel relationship and converge on roughly 18.78 MB transferred to `api.westbridge-services.net`.
- **[Signal-to-noise — strong]** The attack is embedded in substantial routine activity rather than surrounded by token filler. DNS includes A, AAAA, PTR, SRV, TXT, MX, NS, and SOA traffic with mixed response outcomes; Zeek connections include successful, rejected, reset, incomplete, and unknown-service sessions; endpoint streams include user, service, update, browser, authentication, and process lifecycle noise. Hourly volume varies naturally, with the pronounced 13:00 spike explainable by visible scanning.
- **[Pivot feasibility — strong]** A hunter can move in both directions using source-native identifiers: external IP to web request, web request to Apache child process, process to C2 tuple, source port to Zeek/ASA, SSH tuple to target auth session, process GUID/PID to files and flows, SMB path to source and destination hosts, and proxy tunnel/client port to origin egress. The key pivots do not depend on hidden metadata.

## Detailed Analysis

The dataset covers approximately `12:00:01-17:59:56 UTC` on 18 March 2024 and presents a mixed Windows/Linux healthcare-style environment spanning workstations, domain controllers, file servers, mail systems, application and database servers, a web edge, proxy, and monitoring host. The observed source mix is operationally sensible: Windows Security and Sysmon on Windows assets, syslog on Linux assets, endpoint-style eCAR throughout, multiple Zeek visibility zones, Cisco ASA, Snort, web and proxy access logs, and protocol-specific DNS, TLS, HTTP, SMTP, SMB, DHCP, and file records.

The first high-confidence investigative thread begins with external reconnaissance from `185.70.41.45`. The web log contains varied Nikto-style requests and outcomes before a successful-looking upload POST. Within about a second Apache creates a `www-data` bash child whose command decodes an interactive reverse shell to `45.33.32.30:8443`; endpoint, DMZ Zeek, and ASA observations preserve the same five-tuple and compatible open/close timing. This gives a realistic initial-access pivot rather than an unsupported alert-only claim.

The next phase uses credentials and interactive administration paths. On `WS-PPATEL-01`, a user-owned `ssh.exe` process initiates the connection to `WEB-EXT-01`; target sshd/PAM/logind events occur only after transport establishment. Root activity on the web server performs local discovery and scans internal ranges before an SSH hop to `APP-INT-01`. The application server later initiates its own root SSH session to `DB-PROD-01`, where the command and file sequence progresses from database enumeration to dump creation, compression, hashing, and SCP. Session creation and termination evidence is present where expected, and no visible child activity predates its parent process or authenticated session.

The data also supports parallel Windows-side activity rather than forcing the incident into one perfectly linear chain. Service creation and execution on `DC-02`, remote-management-style process ancestry, archive preparation on `WS-AJOHNSON-01`, a user-token curl process under `services.exe`, and later service cleanup are internally plausible. The `services.exe` parent plus user principal is not a contradiction: Security 4688, Sysmon, and eCAR all consistently describe the child token, while proxy authentication and the endpoint network event agree with that identity.

From a hunting standpoint, the strongest evidence is the preservation of source-native joins. The reverse shell can be joined by tuple and time; SSH sessions by source port, addresses, process, and auth lifecycle; SMB staging by host pair, share path, filename, operation, and byte count; and exfiltration by PID, archive path, client port, proxy tunnel ID, destination, method, and byte volume. Sensor timestamps differ slightly in plausible directions instead of being artificially identical. The traffic also includes failed and incomplete states, NXDOMAIN responses, routine machine and user activity, and unrelated large transfers, reducing the chance that every conspicuous event is malicious.

The principal reservation is fleet personality. Several functionally different Linux servers repeatedly emit the same narrow pair of distinctive snap packages and similar maintenance messages. A disciplined organization could deploy these from a common image, but a real environment would more often show stronger role-specific package and daemon divergence, especially between a proxy, mail edge, web server, and log monitor. This is a dataset-wide realism concern, not a causal flaw in the incident evidence.

## Synthetic Indicator Summary

- The most consequential indicator is repeated `microk8s` plus `snapd-desktop-integration` maintenance across unrelated, predominantly headless Linux server roles.
- Windows module-load observations have a polished, compact regularity that is credible at the record level but mildly generator-like in aggregate.
- Broad collection coverage increases the curated feel only weakly; it was not treated as standalone synthetic evidence.
- No impossible temporal ordering, broken process lineage, contradictory principal, unreconcilable tuple, or missing required lifecycle companion was found in the principal attack paths.

## Realism Score by Category

- **Field format accuracy:** 92/100 — Source-native structures, identifiers, users, paths, event semantics, connection states, and byte fields are credible. The main deduction is regular endpoint module-load texture.
- **Temporal patterns:** 94/100 — Processes, transport, authentication, dependent activity, and termination are causally ordered with plausible source-specific latency and non-identical clocks.
- **Cross-source correlation:** 96/100 — The key web, SSH, SMB, and proxy/exfiltration paths preserve usable identities and tuples across independent log families.
- **Behavioral realism:** 90/100 — Tradecraft progresses through believable discovery, lateral movement, collection, staging, exfiltration, and cleanup while coexisting with unrelated activity.
- **Environmental consistency:** 76/100 — Host naming, addressing, roles, and routing are coherent, but Linux maintenance/software profiles are too similar across disparate server roles.

## Recommendations

- Diversify Linux software inventories and maintenance events by server role. Avoid placing both `microk8s` and `snapd-desktop-integration` on most headless servers unless a visible fleet-management policy explains it.
- Give mail, proxy, monitoring, web, application, database, and file servers more role-specific daemon, package, timer, health, and failure behavior while retaining a smaller shared golden-image baseline.
- Vary endpoint module-load collection density and library subsets according to host policy, process type, and collector filtering so process starts do not repeatedly produce equally tidy sequences.
- Preserve the current canonical correlation quality. In particular, retain source ports, process identities, auth session IDs, proxy tunnel IDs, byte accounting, and source-local timestamp offsets; these make the dataset genuinely useful for threat hunting.
- Keep unrelated operational transfers and benign administrative sessions in the background, as they force analysts to validate context rather than treating every large transfer or remote logon as malicious.
