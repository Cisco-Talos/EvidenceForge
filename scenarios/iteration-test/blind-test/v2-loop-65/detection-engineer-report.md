# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 67

## Executive Summary

The dataset is exceptionally strong in schema fidelity, temporal ordering, lifecycle integrity, and cross-source correlation, and it contains several details that would behave correctly in a SIEM. I nevertheless assess it as synthetic because Sysmon repeatedly suppresses extractable PE version metadata for core signed binaries, recurring process activity draws from conspicuously shallow command-line pools across unrelated hosts, and one local Linux authentication failure is coupled to a source-less Windows KDC failure in a way that does not fit the visible authentication mechanism.

## Evidence For Synthetic

- `[schema_or_format]` Of 911 Sysmon Event ID 1 records, 659 (72.3%) set all five PE resource fields—`FileVersion`, `Description`, `Product`, `Company`, and `OriginalFileName`—to `-`. This is not limited to unknown or short-lived tools: it affects all observed instances of `taskhostw.exe` (141/141), `WmiPrvSE.exe` (103/103), `dllhost.exe` (92/92), `conhost.exe` (88/88), `SearchFilterHost.exe` (26/26), `svchost.exe` (26/26), `cmd.exe` (23/23), and `SearchProtocolHost.exe` (19/19), plus Exchange, Defender, Google, Adobe, and Veeam binaries. For example, `DC-01.../windows_event_sysmon.xml` at `2024-03-18 12:06:11.592` records `C:\Windows\System32\taskhostw.exe` with all five fields absent while still providing MD5, SHA-256, and IMPHASH values. Real Sysmon normally extracts version resources from these Microsoft binaries; this selective blanking looks like an incomplete metadata catalog.
- `[distribution_texture]` High-volume process families reuse very small exact command pools across ten unrelated Windows systems: 141 `taskhostw.exe` starts use only `taskhostw.exe` or `taskhostw.exe /Run`; 103 `WmiPrvSE.exe` starts use two forms; 92 `dllhost.exe` starts use only three CLSIDs; 88 `conhost.exe` starts use two forms; and 26 `SearchFilterHost.exe` starts use four numeric argument variants. Recurring Windows components naturally repeat, so this is not decisive alone, but the same compact pools appearing across servers and multiple workstation builds create generator-like texture.
- `[contract_gap]` `DC-01.../windows_event_security.xml` contains a Kerberos pre-authentication failure (4771) for `aisha.johnson` at `2024-03-18T14:58:45.8633854Z`, status `0x18`, but both `IpAddress` and `IpPort` are `-`. Sixty-four milliseconds later, `LT-MRIVERA-02.../ecar.json` labels the failure as a local `USER_SESSION/LOGIN` with `src_ip:"-"`; at `14:58:45.991701Z`, its syslog records `pam_unix(login:auth)` on local console `tty=/dev/tty1`. A local `pam_unix` attempt does not itself create a Kerberos AS request at a domain controller, and no contemporaneous port-88 flow is visible. The tight coupling therefore appears to mix two authentication contracts.
- `[contract_gap]` Logon GUID population is internally suspicious. Of 136 NTLM/NtLmSsp Type 3 logons, 107 have nonzero `LogonGuid` values; 43 Kerberos Type 3 logons also have nonzero GUIDs. Yet all 2,034 visible 4769 ticket-service events use the zero GUID, so none can correlate to those nonzero Kerberos logons through the field intended for that purpose. Because Windows may legitimately fail to capture a Logon GUID and collection can omit a matching ticket event, I treat this as supporting evidence rather than a hard contradiction.

## Evidence For Real

- Windows XML is structurally and semantically strong. Security events use the expected provider GUID, channel, versions, task values, keywords, and field sets for the audited IDs. Sysmon uses the expected provider, channel, versions, field names, and case-sensitive GUID-name variants for Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22.
- The DC-01 Security log-clear sequence is source-native: a Sysmon Event 1 records `wevtutil cl Security` at `17:42:13.026Z`; Security Event 1102 appears at `17:42:20.7762494Z` under the `Microsoft-Windows-Eventlog` provider with `EventRecordID` reset to 1; Sysmon Event 5 follows at `17:42:20.995Z`; and Security 4689 follows at `17:42:21.878Z`. Record IDs are monotonic before and after that single explainable reset.
- Sysmon `ProcessGuid` construction is highly authentic. For all 911 Event ID 1 records, the time-bearing GUID components decode to the process-start Unix second; 910 match exactly and one differs by one second. System `TimeCreated` follows `UtcTime` by small, variable millisecond delays rather than a fixed offset.
- Windows session and process lifecycles are coherent. No visible 4634 precedes its corresponding 4624, no 4689 precedes its 4688, and no Sysmon Event 5 precedes the corresponding Event 1. Every sampled 4672 follows a matching 4624 for the same user and Logon ID by roughly 1–85 ms.
- Cross-source endpoint/network semantics are consistent. Security 5156 and Sysmon Event 3 agree on tuples, process identity, and inbound/outbound direction; matched eCAR flows use the same host-relative direction. Security 4688 and Sysmon Event 1 agree on image, PID, command line, and Logon ID, with plausible source-specific delay.
- Zeek records exhibit excellent protocol behavior. Every audited DNS, HTTP, SSL, SMB, and SMTP UID resolves to a `conn.json` record with the same tuple and no application record preceding its connection. File `conn_uids` resolve, TLS certificate chains resolve into `x509.json`, certificate SHA-1 fingerprints agree with `files.json`, and certificate validity windows contain the handshake. Missing TLS 1.2 certificate chains were associated with nonzero `missed_bytes`, while resumed sessions and TLS 1.3 records omit fields in plausible ways.
- Network-device lifecycles are credible. All 7,502 completed ASA TCP/UDP connections have matching build/teardown IDs, protocols, ordering, and reported durations; only two builds remain open at the end of the capture. Twenty-four alerts visible at both Snort sensors appear at the perimeter 76–187 ms before the core sensor, a plausible topology-dependent delay.
- Host builds are reflected coherently in PE metadata that is present: Server 2022 systems share `userinit.exe` version `10.0.20348.1` and a hash, Server 2019 uses `10.0.17763.1`, Windows 10 hosts use `10.0.19041.1`, and Windows 11 hosts use `10.0.22621.1`.
- Linux telemetry has realistic internal relationships. On `WEB-EXT-01`, 821 kernel uptime prefixes imply one boot epoch within a 250 ms spread. RFC 5424 priorities match facilities/severities, DHCP REQUEST/ACK and renewal messages align, and shell history timestamps correlate with eCAR process/file events. On `DB-PROD-01`, root runs `du -h /tmp/rpt_0318.sql.gz` before `gzip -9 /tmp/rpt_0318.sql`; eCAR confirms the gzip output was created afterward, preserving a plausible failed human check rather than silently repairing the sequence.

## Detailed Analysis

### Scope and method

I restricted examination to the supplied `review-data` directory. The corpus is approximately 73 MB and 1.29 million lines, covering 21 endpoint directories, Windows Security and Sysmon XML, eCAR NDJSON, Linux syslog and shell history, three Zeek sensors, two Snort sensors, Cisco ASA, proxy, and web access telemetry over approximately `2024-03-18 12:00–18:00Z`. I parsed the structured records rather than relying on visual sampling, then manually inspected representative records and anomalies.

### Windows Security schema and event semantics

The XML parsed cleanly, timestamps were nondecreasing, and Event Record IDs were monotonic except for the explained DC-01 log clear. I audited Security IDs 1102, 4624, 4625, 4634, 4648, 4656, 4658, 4663, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4779, 4800, 4801, 5140, 5145, and 5156. Versions and source-native field shapes were correct in the reviewed records: 4624 and 4688 use version 2, 4656/4663/5156 use version 1, and the other listed event families use their expected version 0 forms.

Concrete sequences are strong. At `12:06:21.9819874Z`, DC-01 records a Type 3 NTLM 4624 for `lina.nguyen` from `::ffff:10.10.1.21:50851`, Logon ID `0x5380a5d`; 5140 at `12:06:22.0043767Z` carries that same Logon ID and source port; 4634 closes it at `12:06:26.6359042Z`. Administrative events also use credible schemas: DC-01 records 4697 for `PSEXESVC` at `15:59:41.3189819Z`; 4720, 4724, 4738, and 4728 build a consistent `svc_dirsync` account-change sequence from `16:15:20.5517813Z` through `16:15:24.9134151Z`; and 4698 at `16:19:56.9924989Z` contains syntactically valid embedded Task Scheduler XML.

SIDs, GUIDs, hex identifiers, and process paths were well formed. The domain SID prefix is stable, and I found no username-to-SID or SID-to-username conflicts. Logon types fit the visible mechanisms: Type 3 for network access, Type 5 for services, Type 10 for remote interactive sessions, and Type 7 for unlock. The Logon GUID distribution remains an authenticity concern because populated values do not connect to the ticket events provided, but this is a correlation-quality issue rather than malformed XML.

### Sysmon and eCAR fidelity

Sysmon field naming is precise, including `SourceProcessGUID`/`TargetProcessGUID` for Event 10 versus `SourceProcessGuid`/`TargetProcessGuid` for Event 8. Event 1 contains the expected ordered process fields, and its relationship to Security 4688 is realistic: Sysmon usually precedes Security auditing by tens to hundreds of milliseconds while retaining the same image, PID, command line, and session identity. Event 3 direction agrees with Security 5156's `%%14592`/`%%14593` semantics and with eCAR's host-relative direction. Event 7, 8, 10, 11, 13, and 22 records use plausible shapes and identifiers.

The main source-native defect is not field naming but field population. Hashing succeeds while version-resource extraction is represented as unavailable for large classes of signed, stable binaries. A genuine mixed estate can contain inaccessible or metadata-free executables, but it should not make every observed `taskhostw.exe`, `WmiPrvSE.exe`, `dllhost.exe`, `conhost.exe`, and `svchost.exe` look metadata-free while selectively populating neighboring Windows binaries such as `wevtutil.exe`, `powershell.exe`, `userinit.exe`, `winlogon.exe`, and `mmc.exe`.

All 33,682 eCAR lines were valid JSON; IDs were globally unique and timestamps were ordered within files. I found no process termination before the corresponding visible creation, no PID/image contradiction, no logout before login, no actor created after the event that referenced it, and no reuse of an object ID across incompatible object types. Many unresolved actor IDs plausibly refer to long-lived or pre-window processes rather than impossible future actors.

### Authentication and correlation integrity

The normal Windows cases correlate well. Privileged-logon 4672 records follow matching 4624 records on the same host, user, and Logon ID. SMB 5140/5145 activity retains the initiating session identifiers and source endpoints. Kerberos and NTLM fields have valid encodings, including IPv4-mapped IPv6 addresses and hexadecimal status codes.

The `14:58:45Z` failure is the notable exception. The Linux records explicitly describe a local console attempt handled by `pam_unix`, while the DC emits a 4771 with no client endpoint. A separate, later attempt at `14:59:48.567Z` on DC-02 is more credible: it identifies `aisha.johnson` from `::ffff:10.10.1.99:50847`, and LT-MRIVERA-02 has a corresponding TCP/88 flow. That contrast makes the earlier endpoint-less KDC record look like an over-expanded companion rather than ordinary field loss.

### Zeek, firewall, IDS, and application logs

The three Zeek sensors contain 20,259 connection records (11,337 core, 474 database, and 8,448 DMZ), with varied UIDs and source-appropriate JSON types. Protocol invariants held: TCP/UDP protocol labels matched `ip_proto`; `S0` flows lacked responder packets; `SF` flows had bidirectional packet counts; application timestamps did not precede connection timestamps. DNS fields, reverse lookups, HTTP fields, SMB mappings/files, SMTP records, DHCP messages, PE records, SSL sessions, OCSP responses, files, and X.509 objects all passed the sampled source-native checks.

DHCP behavior is particularly plausible: REQUEST/ACK renewals occur near half of the assigned lease duration with jitter, and clients with 3,600-, 7,200-, and 14,400-second leases renew at different cadences. TLS leaf certificates are reused by server name across the six-hour window; chains and fingerprints remain stable without every session being forced to include a certificate. These are difficult details to get right and materially lower the synthetic-confidence score.

ASA messages use plausible `%ASA-6-302013/302014/302015/302016`, translation, ICMP, and deny forms. Completed connection durations agree with timestamp differences, and an inbound SYN at `12:00:18` from `185.220.233.25` to `10.10.3.10:80` ends 30 seconds later with zero bytes and `SYN Timeout`, while the destination's UFW log records the blocked attempt at `12:00:18.183903Z`. Snort fast-alert records use plausible signatures, classifications, priorities, protocols, tuple syntax, and sensor-dependent delays; apparent parser exceptions were ICMP alerts without ports, which is correct for that protocol.

### Behavioral and environmental texture

Traffic placement fits system roles: domain controllers carry Kerberos, LDAP, and DNS; file servers carry SMB; the proxy has paired client and origin legs; the database receives SQL traffic; and the DMZ web host receives Internet scans and HTTP traffic. Windows version/hash cohorts fit separate server and workstation generations. Linux daemons, package maintenance, `systemd`, CRON, thermal, NetworkManager, UFW, SSH, and shell activity have credible facility usage and timing.

The environment is not uniformly smooth. Counts and intervals vary by host, source delays are neither zero nor constant, connections span different durations, and the database shell sequence includes a visible command that likely failed because its target did not yet exist. The narrower weakness is vocabulary depth in recurring Windows process launches: repeated system processes are expected, but the exact low-cardinality templates recur too consistently across the estate.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `schema_or_format` | Sysmon Event 1/7 | Dataset-wide; 659/911 Event 1 rows have five PE fields blank, including hundreds of core signed binaries | Highest-impact indicator; suggests an incomplete source-metadata model rather than genuine binary resources |
| `distribution_texture` | Sysmon process creation | Ten Windows hosts; dominant process families use only 2–4 exact command templates | Moderate indicator of finite generator pools, tempered by the naturally repetitive nature of Windows services |
| `contract_gap` | Windows 4771, Linux syslog, eCAR | One tightly timed local-login failure at `14:58:45Z` | Moderate one-off indicator: local `pam_unix` semantics do not explain an endpoint-less KDC pre-authentication request |
| `contract_gap` | Windows 4624/4769 | Broad across network logons and all 2,034 visible 4769 events | Supporting indicator: nonzero logon GUIDs are created but never usable for ticket/logon correlation |

No `hard_contradiction` reached the level of a dataset-wide impossible ordering, invalid identifier, or explicit generator identity leak. That is why the synthetic-confidence score remains in the middle of the "likely synthetic" band rather than the 81–100 range.

## Realism Score by Category

- **Field format accuracy:** 7/10 — Schemas, data types, IDs, provider metadata, GUIDs, SIDs, and protocol fields are excellent, but widespread impossible-to-explain PE metadata blanking is a material source-native value defect.
- **Temporal patterns:** 9/10 — Lifecycles, source delays, record-ID reset behavior, DHCP cadence, kernel uptime, and network-device durations are causally coherent and nonuniform.
- **Cross-source correlation:** 8/10 — Process, session, tuple, UID, certificate, and direction joins are strong; the local-login/KDC pairing and unusable Logon GUIDs prevent a higher score.
- **Behavioral realism:** 7/10 — Human, service, administrative, and network activity is diverse and role-aware, but several high-volume Windows process families expose shallow repeated templates.
- **Environmental consistency:** 9/10 — Host roles, OS-build cohorts, services, addressing, sensor placement, and collection timing form a coherent enterprise environment.

## Recommendations

- If this were synthetic, populate Sysmon PE fields from version resources keyed by exact image and OS build. A file that can be hashed should not systematically lose `Company`, `Product`, `Description`, `FileVersion`, and `OriginalFileName`, especially for Microsoft inbox binaries. Add validation that flags all-five-blank metadata for known signed system images.
- If this were synthetic, deepen recurring-process command distributions by OS build, host role, installed software, COM registration, and task identity. Preserve legitimate repetition, but avoid having an entire estate draw `taskhostw.exe`, `dllhost.exe`, `conhost.exe`, and Windows Search invocations from the same two-to-four exact templates.
- If this were synthetic, make the authentication mechanism own all companion evidence. A local `pam_unix` console failure should remain local unless an explicitly modeled PAM Kerberos module sends an AS request; a KDC 4771 should then carry the real client address/port and align with the transport observation.
- If this were synthetic, either leave `LogonGuid` zero when Windows would not provide a usable value or propagate one canonical GUID through the corresponding Kerberos ticket and logon events. Add a cross-source validation rule for nonzero 4624 GUIDs that claims only correlations actually represented by the selected collection profile.
- Retain the existing strengths: source-specific delay, Event Record ID reset behavior, ProcessGuid time encoding, protocol-aware Zeek omissions, ASA lifecycle accounting, OS-build cohorts, and Linux boot-time consistency are all materially production-like.
