# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 46

## Executive Summary

The supplied telemetry supports a workable investigation across a mixed fleet, including suspicious web-server shell execution, remote Windows administration, and database staging through SSH and SMB. Two process-to-network ownership details look simplified, but both occur in normalized endpoint records whose attribution policy was not supplied; I found no decisive native-source or visible same-identity lifecycle contradiction. This is a mixed assessment, with substantially stronger operational coherence than the suspicious attribution details alone would suggest.

## Evidence For Synthetic

- [contract_gap] **SCP transport is attributed to the copy process rather than its SSH child.** `DB-PROD-01.meridianhcs.local/ecar.json:536` creates `/usr/bin/scp`, PID `1089177`, at `18:16:05.208Z`; line 537 assigns that same PID and process UUID to TCP `10.10.4.10:58586 → 10.10.2.30:22` at `18:16:09.208Z`. Standard OpenSSH SCP forks and executes an SSH transport child. This is a probable attribution simplification if `FLOW.pid` denotes the socket-owning process. An ancestor-attribution convention could explain it, so I do not classify it as a hard contradiction.
- [contract_gap] **The encoded shell's connection is attributed to its outer pipeline shell.** `WEB-EXT-01.meridianhcs.local/ecar.json:839–840` creates PID `2702825` with `bash -c 'echo … | base64 -d | bash'` and assigns its UUID directly to the connection to `45.33.32.30:8443`. The encoded text contains another Bash invocation and the `/dev/tcp` redirection; the normal execution tree has additional shell processes. This raises the same direct-owner-versus-ancestor ambiguity as SCP. These are two examples of one issue family, not two independent strong indicators.

## Evidence For Real

- **The database staging path has useful, technically consistent pivots.** The DB host's gzip creation precedes SCP file read, the receiving application host authenticates the matching source tuple before the destination file appears, and SMB upload then uses a distinct directory service identity on the file server. The root account on the application host is not incorrectly equated with the SMB account `svc_mhsync`.
- **The raw reverse shell is not mislabeled as TLS just because it uses port 8443.** `zeek-dmz/conn.json:1625`, UID `CPKkQQWxJzRNpbk3z`, has a successful TCP flow and no `service:"ssl"` declaration. Its tuple matches the shell's endpoint observation.
- **Substantial background evidence competes with the suspicious activity.** There are 35,805 normalized endpoint rows across 23 hosts, 2,043 process creations, 22,148 connection rows across the three Zeek sensors, and 3,524 proxy access rows. Host activity includes administrative SSH, sudo/PAM sessions, developer command pipelines, mail, service noise, and unsuccessful connections. These volumes do not make the attack the only visible activity.
- **Visible process lifecycles are coherent.** A full normalized endpoint scan found no actor UUID used more than one second before its visible process creation or after its visible termination. A separate scan of supplied Sysmon records found no same-GUID source/process event outside a visible create/terminate interval.
- **Windows persistence records carry specific effects.** DC-01's Security log contains the service-install event, scheduled-task XML, and later service process launch. These are not merely suspicious command strings without corroborating state changes.

## Detailed Analysis

### Inputs, scope, and limitations

I read the complete neutral briefing `/private/tmp/log-study-mytn1lc8/threat-prompt.md` and inspected files only beneath `/private/tmp/log-study-mytn1lc8/data`. The inventory contained 117 files totaling 82,289,463 bytes. Analysis used read-only parsing of JSON/NDJSON, XML, histories, and text logs; logged commands and encoded content were treated as inert evidence and were not executed.

The supplied endpoint data covers approximately `2026-11-02 13:00–19:00 UTC`. It shows 23 endpoint host identities, including ten Windows hosts with Security/Sysmon XML, eleven Linux-like hosts, and two Macs with Endpoint Security, Unified Log, normalized endpoint, and zsh history records. The visible addressing separates workstation `10.10.1.x`, internal services `10.10.2.x`, DMZ `10.10.3.x`, and database `10.10.4.x` activity. Sources also include three Zeek sensors, two IDS files, a perimeter ASA file, web access, and proxy access.

My actual external inputs were GNU Bash documentation, OpenBSD SSH/SFTP documentation, and the upstream OpenSSH portable `scp.c` file. Searches used actual `gnu.org`, `openssh.com`, and `man.openbsd.org` domain filters; the source-code reference was opened directly from the upstream repository. I did not inspect project code, authored scenarios, project documentation, worklogs, prior assessments, other reviewers' reports, or neighboring directory inventories. Generic inherited operating/project metadata was present in the execution context; that limits complete procedural blinding but was not used as evidence about the data's origin.

This was not a comprehensive certification of every platform-specific field. In particular, the exact normalized endpoint attribution contract and installed OpenSSH builds were not supplied. Domains were treated as potentially sanitized. I did not score absent selected Sysmon families, filesystem timestamps, complete matching, thin coverage alone, narrative linearity, or missing initiators/closures outside the slice.

### Suspicious web activity and account boundaries

At `14:20:06.317Z`, `WEB-EXT-01/ecar.json:839` shows Apache (`www-data`, PID `23966`) creating Bash PID `2702825`. The command decodes text containing a Bash `/dev/tcp/45.33.32.30/8443` connection. Line 840 observes that destination at `14:20:09.662Z`; `zeek-dmz/conn.json:1625` observes the same source port `41647`, with start `1793629209.585467`, duration `29.415661`, and `conn_state:"SF"`. The port is handled as plain TCP, which fits the command.

The main concern is ownership, not the existence or timing of the connection. GNU documents that pipeline elements normally run in separate processes, with a `lastpipe` qualification. The observed outer-shell attribution therefore needs an explicit normalized ancestor policy to be considered faithful process ownership. I did not infer a guaranteed missing event merely because a child was not present. [GNU Bash pipelines](https://www.gnu.org/s/bash/manual/html_node/Pipelines.html).

Later, `WEB-EXT-01/ecar.json:914–927` records a separate root SSH login from `10.10.1.34:57673`, then host/network discovery and credential-path searches. Syslog lines 352–353 corroborate public-key acceptance and PAM session opening. I do not claim this root identity was obtained by the earlier `www-data` shell: the records show a different incoming session and source. The transition is a hunt pivot to investigate, not evidence of impossible privilege escalation or synthetic origin.

### Database collection, SCP, and SMB staging

`DB-PROD-01/ecar.json:528–539` shows root SSH from `10.10.2.30:44990`, a `mysqldump` process, gzip, then SCP back to the application host. The gzip process begins at `18:15:53.247Z`; its compressed artifact appears before the SCP process starts at `18:16:05.208Z`. SCP reads the same artifact object at `18:16:15.092Z`.

The corresponding Zeek tuple appears in `zeek-db/conn.json:385` and `zeek-core/conn.json:11098`: `10.10.4.10:58586 → 10.10.2.30:22`, successful SSH, about 34.18 seconds long. The application host records the inbound tuple at `ecar.json:775`, SSH acceptance/login at lines 776–777, and file creation `/tmp/.cache/rpt_0318.sql.gz` at line 778 (`18:16:42.816Z`). Small differences among endpoint, syslog, and sensor timestamps are compatible with observation timing and do not establish a causal inversion.

At `18:19:17.452Z`, `APP-INT-01/ecar.json:781` starts `smbclient` as local root using remote credentials `svc_mhsync`; lines 782–783 correlate the `54116 → 445` connection and source-file read. `FILE-LNX-01/ecar.json:1231–1236` shows a Samba worker, successful directory-scoped NTLMSSP session for `svc_mhsync`, the destination write under `/srv/samba/ClinicalResearch/Integration/DB-Staging/`, then logout and worker termination. `zeek-core/conn.json:11181` corroborates the successful SMB tuple. These credential and lifecycle boundaries make the pivot operationally credible.

The SCP client-side flow attribution remains questionable: the upstream implementation's `do_cmd` function forks and executes the SSH program, rather than having SCP itself own that TCP connection. This supports a probable normalized attribution gap, with moderate weight because the exporter may deliberately attach flows to initiating ancestors. [OpenSSH portable SCP source](https://raw.githubusercontent.com/openssh/openssh-portable/master/scp.c).

I specifically rejected a stronger claim that the destination file must have an external `sftp-server` process. OpenSSH supports an in-process `internal-sftp` subsystem, so absence of an external executable does not demonstrate a defect. [OpenBSD sshd_config](https://man.openbsd.org/sshd_config).

### Windows effects and lifecycle checks

The Windows trail includes DC-01 service installation at `17:00:21.9994534Z` (`ServiceName=PSEXESVC`), creation of `svc_dirsync` at `17:15:19.2242501Z`, and a later service/task persistence pair. `DC-01/windows_event_security.xml:200298` is Event 4698 with task name `\Microsoft\Windows\Maintenance\DeviceSync`, SYSTEM principal, `PT1H` repetition, and executable `C:\Windows\System32\DeviceSyncSvc.exe`. The later service launch at `17:29:17.6180943Z` uses `services.exe` as parent, rather than pretending the registration command itself proves execution.

The same Security export contains log-clearing Event 1102 (`:270296`) and later account deletion. Retained earlier events are compatible with an exported or forwarded collection and do not contradict clearing the source channel.

The normalized endpoint actor check covered every supplied `ecar.json`, and the Sysmon check used GUIDs rather than assuming a PID could never be reused. This provides positive lifecycle evidence within the slice. It does not prove that all hidden dependencies exist, and it does not penalize pre-window parents or post-window survival.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | Normalized Linux endpoint FLOW/process attribution | SCP PID `1089177` on DB-PROD-01 | Probable initiator/transport-owner conflation; moderate concern, reduced by undocumented exporter semantics |
| contract_gap | Normalized Linux endpoint FLOW/process attribution | Pipeline shell PID `2702825` on WEB-EXT-01 | Similar ancestor/direct-owner ambiguity; modest additional support for the same issue family |

No demonstrated hard contradiction was found. The two attribution observations justify a mixed score, not a confident synthetic verdict. The operationally coherent native and cross-source evidence prevents these ambiguous normalized details from dominating the assessment.

## Realism Score by Category

- **Field format accuracy:** 8 — Source formats parsed and the inspected native Windows effects were specific; this was not an exhaustive native schema audit.
- **Temporal patterns:** 9 — Inspected transport/auth/action order and same-identity process intervals were coherent within the visible slice.
- **Cross-source correlation:** 8 — SSH and SMB pivots work well; normalized flow process ownership needs clarification.
- **Behavioral realism:** 8 — Commands, local-versus-directory credentials, transfer staging, and persistence effects form technically plausible activities.
- **Environmental consistency:** 8 — Mixed platform and network-role behavior fits the visible sources, with no established collection-profile contradiction.

## Recommendations

- If this were synthetic, model the actual SSH child owning an SCP transport and preserve the SCP process as its initiating parent. If ancestor attribution is intentional, document or label that convention in the normalized export instead of presenting it as indistinguishable from socket ownership.
- If this were synthetic, preserve the shell pipeline's process tree and attach `/dev/tcp` transport to the shell that performs the redirection, while retaining the Apache/outer-shell ancestry for investigation.
- Preserve the existing distinction between local execution identity and remote SMB identity, and the observed transport-before-authentication and artifact-before-upload relationships; these are substantive strengths of the supplied data.
