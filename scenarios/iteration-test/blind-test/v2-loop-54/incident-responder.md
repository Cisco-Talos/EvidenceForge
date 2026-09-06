# Incident Responder — Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict Confidence:** 88/100
- **Synthetic-Confidence Score:** 79/100
- **Overall Realism Score:** 66/100

The data contains several unusually strong, response-grade incident chains. Network tuples,
timestamps, principals, sessions, process identifiers, file paths, and cleanup events often agree
across endpoint, network, firewall, proxy, and native operating-system sources. However, three
repeated or material continuity defects are more consistent with synthetic construction than with
a naturally collected estate: exact duplicate endpoint events across unrelated hosts, a file whose
identity and actor ownership change at a relay boundary, and Windows payload processes whose
parent/token lineage is fragmented across unrelated service and interactive contexts.

## Executive Summary

The observed six-hour window contains at least four incident threads:

1. An external HTTPS connection to `WEB-EXT-01` precedes an Apache-owned shell decoding a
   reverse-shell command and connecting to `45.33.32.30:8443`. Endpoint, Zeek, and ASA records
   agree on the relevant tuples and preserve connection-open, process, callback, teardown, and
   process-termination ordering.
2. A privileged SSH pivot from `APP-INT-01` to `DB-PROD-01` leads to database discovery, a
   `mysqldump`, gzip staging, SCP back to the application host, and an SMB relay to `FILE-LNX-01`.
   SSH/PAM, endpoint, Zeek, SMB, and Samba evidence mostly forms a coherent lifecycle.
3. On `WS-AISHA`, a type-9 credential context is followed by document staging, archive creation,
   and a proxied HTTPS upload. The proxy transaction and endpoint network tuple agree, but process
   ancestry and token/session ownership are not credible as a continuous execution chain.
4. Domain-controller activity includes PsExec/WMI-style execution, privileged account and group
   changes, service and scheduled-task persistence, execution of the installed service, Windows
   Security log clearing, and later partial account/service cleanup. Native Security and Sysmon
   records support much of the eCAR narrative, including a realistic EventRecordID reset after
   Event ID 1102.

The dataset is operationally useful: an analyst could identify affected hosts, reconstruct major
execution stages, and locate residual persistence and staged data. Its strongest synthetic tells
are localized rather than pervasive, but they affect exactly the identity and lifecycle contracts
an incident responder relies upon.

## Evidence For Synthetic

### P1 — Exact duplicate endpoint events recur across unrelated hosts

Multiple eCAR records are identical in timestamp, action, object, actor, PID, and properties while
differing only in their top-level event ID. Examples include:

- `data/APP-INT-01.edgecorporation.internal/ecar.json:348-349`: duplicate reads of
  `/etc/ssh/sshd_config` with the same actor, object ID, timestamp, and properties.
- `data/DC-01.edgecorporation.internal/ecar.json:450-451`: duplicate `PROCESS OPEN` observations
  from the same `svchost.exe` process to the same `lsass.exe` object at
  `2024-03-18T12:30:53.693Z`.
- `data/DC-01.edgecorporation.internal/ecar.json:3446-3447`: another duplicate process-open pair.
- `data/DC-02.edgecorporation.internal/ecar.json:1083-1085`: a three-record duplicate group for
  `msiexec.exe` opening `services.exe`.
- `data/FILE-SRV.edgecorporation.internal/ecar.json:284-285` and
  `data/MAIL-FIN.edgecorporation.internal/ecar.json:687-688`: additional duplicate pairs.

The duplication is not confined to the normalized source. For the first DC example, native Sysmon
contains two adjacent Event ID 10 records with different record numbers but the same event time,
source process GUID/PID/thread, target process GUID/PID, granted access, and call trace:
`data/DC-01.edgecorporation.internal/windows_event_sysmon.xml:1645-1713`. A later duplicate pair
appears at `data/DC-01.edgecorporation.internal/windows_event_sysmon.xml:18193-18261`.

Repeated low-level operations can occur on real systems, but byte-for-semantic duplicates with
identical high-resolution timestamps and identifiers, distributed across many unrelated hosts, are
a generator-shaped artifact. The native and normalized duplicates appear to descend from the same
duplicated occurrence rather than independent observations.

**Category:** distribution/texture and lifecycle duplication.  
**Impact:** inflates event counts, creates false corroboration, and can cause responders to infer
retries or repeated access that did not occur.

### P1 — File identity and actor continuity break during the database relay

The SCP receiver on `APP-INT-01` records creation of `/tmp/.cache/rpt_0318.sql.gz` with object ID
`0c591283-0b08-4c1f-8532-6bc0481444bc`:
`data/APP-INT-01.edgecorporation.internal/ecar.json:836`. One event later, a read of that same local
path uses object ID `file-ddf0d43d64aa0203` and has no actor ID or PID:
`data/APP-INT-01.edgecorporation.internal/ecar.json:838`.

That second identity is then associated with the destination-side file written on `FILE-LNX-01`,
`/srv/samba/ClinicalResearch/Integration/DB-Staging/rpt_0318.sql.gz`, rather than remaining the
identity of the source file. Destination write evidence is at
`data/FILE-LNX-01.edgecorporation.internal/ecar.json:1324-1329`; the SMB mapping and file operations
are at `data/zeek-core/smb_mapping.json:198` and `data/zeek-core/smb_files.json:330-331`; Samba also
records open/write/close at `data/FILE-LNX-01.edgecorporation.internal/syslog.log:658-660`.

The transfer itself is convincing, but the source-file identity should not silently become the
destination-file identity, especially while losing the source actor/process that performed the
read. This is a material evidence-provenance discontinuity at a critical exfiltration boundary.

**Category:** contract gap.  
**Impact:** prevents reliable chain-of-custody reasoning and weakens attribution of the SMB write
to the process that received and relayed the archive.

### P1 — Windows collection and upload lack a coherent parent/token lineage

`WS-AISHA` establishes a type-9 logon for `aisha.hassan`, with outbound credentials for
`marcus.chen`, at `data/WS-AISHA.edgecorporation.internal/ecar.json:1052`. Subsequent payload
activity does not form one credible process tree:

- The PowerShell process creating staging directories is parented by a `svchost.exe` running as
  `NETWORK SERVICE`: `data/WS-AISHA.edgecorporation.internal/ecar.json:1053`.
- Staged Finance, Clinical, and Research file creations are attributed to the interactive
  `explorer.exe` process under the older logon, not to the staging PowerShell/type-9 context:
  `data/WS-AISHA.edgecorporation.internal/ecar.json:1063-1076`.
- The compression PowerShell again appears under the service-host lineage:
  `data/WS-AISHA.edgecorporation.internal/ecar.json:1077`.
- The upload `curl.exe` process is instead parented directly by `services.exe` running as `SYSTEM`:
  `data/WS-AISHA.edgecorporation.internal/ecar.json:1164`.

Windows services can launch processes with alternate tokens, so no single row is categorically
impossible. What is missing is the bridge that would explain why one payload alternates between a
Network Service `svchost`, an interactive explorer session, and SYSTEM `services.exe` while being
presented as a continuous user-driven staging workflow. The upload network evidence is otherwise
strong: endpoint flow `10.10.1.35:55800 -> 10.10.3.20:8080` is at
`data/WS-AISHA.edgecorporation.internal/ecar.json:1172`, and the matching proxy POST with the same
client port and `18,783,109` request bytes is at
`data/PROXY-01.edgecorporation.internal/proxy_access.log:2095`.

**Category:** contract gap.  
**Impact:** undermines confidence in who executed the collection/upload and which logon session
owned the resulting file and network activity.

### P2 — A Linux cleanup command has no modeled privilege or outcome

An SSH session from `10.10.1.31:63325` to `FILE-LNX-01:22` is coherently represented by endpoint
flow/login events (`data/FILE-LNX-01.edgecorporation.internal/ecar.json:1344-1349`) and SSH/PAM
records (`data/FILE-LNX-01.edgecorporation.internal/syslog.log:676-679`). Within that session,
`marcus.chen` runs `systemctl restart syslog` without visible `sudo`, root transition, polkit
authorization, denial, or service restart evidence:
`data/FILE-LNX-01.edgecorporation.internal/ecar.json:1368` and
`data/FILE-LNX-01.edgecorporation.internal/bash_history.log:47-50`.

The command may simply have failed, which would be realistic, but neither success nor failure is
observable. For an incident responder, this leaves a cleanup/evasion action semantically
unfinished.

**Category:** contract gap.  
**Impact:** prevents determination of whether logging was actually interrupted.

## Evidence For Real

### External exploit and callback preserve causal ordering

The perimeter narrative is unusually coherent:

- Inbound HTTPS reaches `10.10.3.10:443` from `185.70.41.45:57162` at
  `data/WEB-EXT-01.edgecorporation.internal/ecar.json:747` and
  `data/zeek-dmz/conn.json:1485`.
- An Apache/`www-data` child launches PID `1480967` with a base64-decoded reverse-shell payload at
  `data/WEB-EXT-01.edgecorporation.internal/ecar.json:748`.
- The same PID opens `10.10.3.10:60568 -> 45.33.32.30:8443` at
  `data/WEB-EXT-01.edgecorporation.internal/ecar.json:749`; Zeek observes the same tuple at
  `data/zeek-dmz/conn.json:1491`.
- ASA build/teardown records bracket both flows at
  `data/fw-perimeter/cisco_asa.log:3426`, `:3443`, `:3450`, and `:3453`.
- The reverse-shell process terminates at
  `data/WEB-EXT-01.edgecorporation.internal/ecar.json:751`.

The order is physically plausible: transport arrival, execution, callback, network teardown, then
process termination. Source and destination semantics are consistent across all three source
families.

### SSH database theft has strong session and process continuity

`APP-INT-01` launches `ssh -A root@DB-PROD-01` from process object
`2fec4e85-0ffd-4898-b210-cc0cf591696c` at
`data/APP-INT-01.edgecorporation.internal/ecar.json:793`. Zeek records
`10.10.2.30:47571 -> 10.10.4.10:22` at `data/zeek-core/conn.json:9711`; the destination endpoint
observes the same tuple at `data/DB-PROD-01.edgecorporation.internal/ecar.json:480`, followed by
root login/session `351038`/`0x1185e00b` and shell creation at lines `481-482`. Native SSH/PAM
records preserve connection, accepted authentication, PAM open, and logind ordering at
`data/DB-PROD-01.edgecorporation.internal/syslog.log:217-220`.

The root shell performs database enumeration, dump, and compression at
`data/DB-PROD-01.edgecorporation.internal/ecar.json:485-503`, then starts SCP at line `527` and
reads the archive at line `530`. The root command history independently preserves that sequence at
`data/DB-PROD-01.edgecorporation.internal/bash_history.log:10-22`. The receiving SCP transport and
subsequent SMB relay use distinct, plausible tuples at `data/zeek-core/conn.json:10295` and
`:10301`. Finally, PAM/session-close evidence appears at
`data/DB-PROD-01.edgecorporation.internal/syslog.log:234-235` and the endpoint logout at
`data/DB-PROD-01.edgecorporation.internal/ecar.json:560`.

### Domain compromise and evasion have native corroboration

On `DC-01`, a network logon from `10.10.1.35` is followed by a PSEXESVC drop, service identity,
service process, and command shell at `data/DC-01.edgecorporation.internal/ecar.json:3456-3472`.
Later WMI/SYSTEM activity creates `svc_dirsync`, adds it to Domain Admins, installs
`DeviceSyncSvc`, creates a scheduled task, and executes the service. The eCAR chain appears at
lines `3643-3829` and `3955`; native Security support includes
`data/DC-01.edgecorporation.internal/windows_event_security.xml:177516`, `:177559`,
`:177746`, `:178119`, `:184911-184912`, `:185277`, and `:191501`; Sysmon support appears at
`data/DC-01.edgecorporation.internal/windows_event_sysmon.xml:19622`, `:19667`, `:19712`,
`:19757`, and `:20266-20284`.

Security-log clearing is especially persuasive. Encoded PowerShell and `wevtutil cl Security`
occur at `data/DC-01.edgecorporation.internal/ecar.json:5210-5230`. Native Event ID 1102 is at
`data/DC-01.edgecorporation.internal/windows_event_security.xml:252776`; the next records restart
at EventRecordID 1 and 2 at lines `252782-252815`. That is the correct kind of source-native side
effect, not merely a command-line claim.

### Broad lifecycle audit found no impossible actor ordering

Across the eCAR data, process-referencing actions did not visibly precede their actor's process
creation or continue after that actor's termination. Process termination did not precede creation
for the same object ID. Login/logout records likewise showed no same-session logout-before-login or
duplicate-login contradictions. Sessions open before the capture window and sessions still active
at the end of the window were treated as censored observations, not failures. This absence of broad
lifecycle breakage materially raises the realism assessment despite the localized defects above.

## Detailed Analysis

### Incident reconstruction

The earliest high-confidence intrusion thread is the external web connection and reverse callback
around 13:20 UTC. The available evidence supports exploitation of an Apache-served host and a
short-lived callback, but it does not by itself prove that every later privileged SSH action is a
direct continuation of that callback. A later root SSH session to the web host is observable from
`10.10.1.22:32825`, with login and shell evidence at
`data/WEB-EXT-01.edgecorporation.internal/ecar.json:867-869`. Commands then enumerate interfaces,
hosts, DNS settings, credentials, and adjacent systems at lines `871`, `873`, `888`, `910`, `915`,
and `1182`; later reads of application configuration and root SSH material occur at lines `2467`,
`2482`, and `2484`, followed by SSH toward `APP-INT-01` at line `2566`. This is consistent with
reconnaissance and pivot preparation, though the exact access transition remains inconclusive.

The database thread is the cleanest end-to-end chain. It starts with a modeled SSH client process,
has a transport interval before authentication, maintains a stable root session and shell on the
database host, produces staged files, closes the source session, and creates correlated receiver
and SMB-server evidence. The archive size and SMB operation are mutually plausible. The major
defect is not missing network evidence but the source/destination file identity swap described in
P1.

The Windows workstation thread supports credential-context creation, collection, compression, and
upload, but does not establish a trustworthy process genealogy. The network edge remains strong:
the endpoint and proxy agree on source port, proxy route, method, destination, path, success status,
and a large request body. The uncertainty lies in actor attribution, not whether an upload-like
transaction occurred.

The domain-controller thread shows both persistence and cleanup. `svc_dirsync` is later deleted at
`data/DC-01.edgecorporation.internal/ecar.json:5384-5390`. On `DC-02`,
`DirectoryCacheSvc` is stopped and deleted at
`data/DC-02.edgecorporation.internal/ecar.json:4516-4544`. By the end of the observed window,
`DeviceSyncSvc`, its scheduled task, database staging artifacts, and at least some relayed files do
not have visible removal evidence. These are useful residual indicators, but capture-window
censoring prevents concluding that later cleanup never occurred.

### Cross-source consistency

Cross-source agreement is strongest for TCP tuples and source-native lifecycle boundaries. The web
callback agrees across eCAR, Zeek, and ASA. The database SSH and SCP sessions agree across source
and destination endpoints, Zeek, PAM/syslog, and command history. The SMB relay agrees across Zeek
mapping/file records and Samba open/write/close. The workstation upload agrees across endpoint and
proxy telemetry. The DC log clear produces the expected native event and record-number reset.

The main consistency weakness is identity projection: the same real-world action is not always
rendered with stable file, actor, process, and logon ownership. This would force a responder to
trust temporal proximity over explicit identifiers in exactly the places where forensic joins
should be strongest.

## Synthetic Indicator Summary

| Rank | Severity | Finding | Indicator type | Confidence |
|---:|:---:|---|---|---:|
| 1 | P1 | Same-path relay file changes object identity and loses actor/PID | Contract gap | 96/100 |
| 2 | P1 | Windows staging/upload splits across unrelated service and interactive lineages | Contract gap | 91/100 |
| 3 | P1 | Exact duplicate eCAR/Sysmon occurrences recur across unrelated hosts | Distribution/texture | 94/100 |
| 4 | P2 | Unprivileged `systemctl restart syslog` has no success/failure or state evidence | Contract gap | 76/100 |

No P0 hard contradiction was found. No P3 item is separately reported: weaker observations such as
open sessions at the capture boundary or fixed Windows service-account LUIDs have plausible native
or window-censoring explanations and are not reliable synthetic indicators.

## Realism Score by Category

| Category | Score | Rationale |
|---|---:|---|
| Field and format fidelity | 8/10 | Rich source-native fields, credible paths and commands; duplicate events reduce trust. |
| Temporal behavior | 9/10 | Major chains preserve transport/auth/process/teardown order with plausible durations. |
| Cross-source consistency | 8/10 | Network tuples and native lifecycle effects correlate exceptionally well; identity projection fails locally. |
| Behavioral realism | 7/10 | Incidents are reconstructable and operationally coherent, but several action effects lack clean ownership. |
| Environmental texture | 7/10 | High-volume background activity provides useful concealment, though repeated exact duplicates expose generation structure. |

The category average is higher than the **66/100 overall realism score** because the overall score
weights incident-response-critical identity and provenance failures more heavily than ordinary
field plausibility.

## Recommendations

1. Preserve one canonical file identity per host/path/version and explicitly model transfer
   derivation. A destination object may receive a new identity, but the source read must retain the
   source object's ID and actor/process, with a transfer identifier linking both objects.
2. Build Windows payload execution around one explicit token/process lineage. If a service creates
   a process as another user, emit the service-to-token/process transition; attribute file effects
   to the process that actually performs them rather than to a nearby explorer process.
3. Deduplicate canonical occurrences before rendering. If two real operations are intended, vary
   their native time, thread/call context, or lifecycle identity so they are observably distinct.
4. Give state-changing administrative commands explicit outcomes. For failed Linux service
   control, emit denial/exit status; for success, model the privilege transition and service-state
   evidence.
5. Retain the current cross-source tuple, session-open/close, firewall teardown, proxy-byte, and
   Windows log-clear contracts. They are the strongest realism features in the dataset.
