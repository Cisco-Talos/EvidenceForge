# Threat Hunter Assessment — loop 21

## Assessment

**Verdict: Mixed, broadly production-like activity with one unresolved persistence concern.** The logs show coherent user and SSH lifecycles, host discovery, ordinary signed applications, and reads from mounted files. A root-owned `/bin/sh` creates and later deletes a LaunchDaemon plist, but the available evidence does not show that the item was registered, loaded, or executed. This warrants a focused hunt, not a confirmed-compromise conclusion.

**Verdict Confidence:** 82%  
**Synthetic-Confidence Score:** 32/100 (lower is more production-like)

## Executive summary

The Mac endpoint has a credible day-shaped event mix: a local Maya Ross session, standard macOS and signed desktop applications, inventory checks, DNS/Kerberos/SMB/proxy traffic, and SSH in both directions. The successful inbound SSH session from `10.10.1.41` is well-correlated across network, session, process, and Unified Log evidence; its login precedes the shell activity and its matching logout closes the session. The outbound SSH commands also agree with the user's shell history and process telemetry.

The main threat signal is a non-interactive root `/bin/sh` process (PID 19721) associated with creation and later deletion of `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist`. The file path and root ownership make this worth investigating. A file create/delete pair alone does not prove LaunchDaemon activation; no visible record ties this plist to a `launchctl` bootstrap or a process launched from that item. The name also matches an endpoint inventory service that is independently seen running periodic `sw_vers` checks. No downloaded executable or execution from a user-writable/download location is visible.

## Concrete evidence

### Production-like evidence

- A successful local login for `maya.ross` at 13:04:23 UTC has a corresponding session logout at 18:57:02 UTC (Mac `ecar.json`, lines 2 and 497). The iTerm2 startup tree reaches `login`, `ShellLauncher`, and `zsh` as UID 501 (Mac `macos_endpoint_security.ndjson`, lines 2–10). The shell exits before the matching local logout (endpoint line 143; eCAR lines 485–486, 497).
- Inbound SSH is consistently attributed to source `10.10.1.41:59129`: the Mac records an inbound TCP/22 flow at 14:24:48 and a successful SSH login at 14:24:54, then a logout with the same source and port at 14:35:08 (Mac `ecar.json`, lines 138, 146, 176). Unified Log line 2 independently records “Accepted keyboard-interactive/pam” for `maya.ross` from the same source and port at 14:24:53.650 UTC. The session's sshd/sshd-session process chain and subsequent `zsh`, `id`, `sw_vers`, and `find` activity appear in endpoint lines 52–74; the commands are bounded by process exits and the SSH session closes.
- Outbound SSH is also coherent. Shell history records SSH to `DB-PROD-01` and `APP-INT-01` (Mac `zsh_history/maya.ross.zsh_history`, lines 6 and 17); endpoint events show `/usr/bin/ssh` launched by Maya's shell (endpoint lines 48 and 124), and eCAR records matching process-attributed connections (Mac `ecar.json`, lines 130 and 398). These are meaningful lateral pivots, but are not by themselves evidence of misuse.
- Ordinary user and host activity is visible alongside the pivots: OS/version and platform checks, `pwd`, document enumeration, disk-usage queries, `ps`, and directory-service user listing (Mac `zsh_history/maya.ross.zsh_history`, lines 1–5, 7–10, 12–16, 18–20; endpoint events around 13:11–18:29). These commands are interpretable in the session timeline rather than appearing as unexplained standalone records.
- The five observed user-file reads are linked to `cat` processes owned by `maya.ross`, including files under `/Volumes/Users/...` and `/Volumes/ClinicalResearch/...` (Mac `ecar.json`, lines 135, 284, 320, 418, 483). The paths may merit access review, but `cat` reading a file is not execution of that file and no exfiltration is demonstrated by these rows.
- Across the 5h56m window, Mac eCAR contains 310 network flows, 176 process lifecycle rows, seven file actions, and paired local/SSH session records. Of the flows, 221 go to the internal proxy at `10.10.3.20:8080`; the remainder include DNS, Kerberos, LDAP, SMB, syslog, and SSH. This is a concentrated proxy share, but the service mix and endpoint context make it plausible without evidence that the proxy count itself is impossible.
- Chrome, iTerm2, Microsoft Word/Outlook, and Zoom run from their expected application locations with vendor signing identities/team IDs in endpoint telemetry (Mac `macos_endpoint_security.ndjson`, lines 3–10, 23–30, 35–40, 86–87, 112–113). The observed Mac file reads are data access, not a browser-download-to-executable chain.

### Synthetic-leaning or hunt-worthy evidence

- A root shell with no TTY is observed as parent PID 20519 and forks child PID 19721 at 13:19:48 UTC; the child executes `/bin/sh` as root (Mac `macos_endpoint_security.ndjson`, lines 20–21; Mac `ecar.json`, lines 30–31). The parent process start time predates this captured window, so its absent earlier launch is not treated as a defect. Its root, non-interactive context remains unusual enough to pivot on.
- That same child PID 19721 is attributed the creation of `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` at 13:22:34 and deletion of the same artifact at 18:42:05 (Mac `ecar.json`, lines 33 and 471; both rows share artifact ID `artifact-463bbaf3f83d57f6ecc7faf4c2c149e3` and process UUID `4d20edec-aa27-4104-aea4-d458c5067167`). The visible behavior establishes file staging and cleanup. It does **not** establish launch-item registration, activation, or execution: the plist contents/permissions and a corresponding bootstrap or service child are not present in these records.
- The plist label resembles the endpoint inventory job. Separately, launchd starts `com.meridianhcs.endpoint-inventory` and it runs `/usr/bin/sw_vers` at 13:43, 15:47, and 17:52 UTC (Mac `macos_endpoint_security.ndjson`, lines 31–34, 94–97, 125–128). This is compatible with benign inventory behavior, but the logs do not establish whether the staged plist is an update, an attempted persistence change, or unrelated cleanup.
- Remote sessions include discovery commands such as `id`, `sw_vers`, `find ... -name '*.pdf'`, `dscl . -list /Users`, and `ps aux` (Mac `zsh_history/maya.ross.zsh_history`, lines 7–10, 12–20; endpoint lines 67–74, 80–84, 89–93, 104–110, 121–124, 133–140). This forms a credible discovery pattern when viewed with the SSH pivots, but the evidence does not reveal the operator's authorization or intent.
- The four reads from mounted user/research paths may indicate document review or collection. No corresponding outbound file transfer, archive creation, or upload process is shown in this Mac slice, so the reads alone do not prove exfiltration.

## Detailed analysis

### Operational lifecycle and pivots

The clearest intact remote-session sequence is inbound SSH from `10.10.1.41:59129`: eCAR flow at 14:24:48 (line 138), successful login at 14:24:54 (line 146), matching Unified Log authentication at 14:24:53.650 (Unified Log line 2), and logout at 14:35:08 with the same source/port (eCAR line 176). Endpoint lines 52–74 show the sshd chain, Maya's shell and command execution after authentication. This alignment supports a real, closed SSH session rather than a same-ID ordering contradiction.

Two outbound SSH pivots are visible in both shell history and process/network records: Maya connects to `DB-PROD-01` and `APP-INT-01` (history lines 6 and 17; endpoint lines 48 and 124; eCAR lines 130 and 398). A separate history entry targets `MAC-MROSS-01` via `ssh -tt` (history line 11; eCAR line 270). These destinations and the inbound session merit authorization review as a group. Their activity is not inherently anomalous for an admin/developer workstation, and the available logs do not identify the operator's role.

Most short-lived commands have create/exec/exit coverage in Endpoint Security. The main incomplete lifecycle is the root shell/PID 19721: the slice shows its fork/exec and plist create/delete, but no termination row for that process. Since the slice ends after its delete and the process may continue beyond the observed events, this is not treated as a proven orphan or contradiction.

### Mac execution and launch-item distinctions

The endpoint data show no downloaded executable launch, browser child executing from Downloads, `xattr`/quarantine interaction, or `open` of a newly written application. The four user files read by `cat` are data-file accesses and should not be scored as file execution.

The LaunchDaemon sequence is a meaningful persistence lead, but the evidence only reaches **file create → file delete**. There is no plist content, destination binary path, code-signing context for a new payload, `launchctl bootstrap/load` evidence, or process lineage attributed to this item. The periodic `com.meridianhcs.endpoint-inventory` launchd job does run inventory checks, which is relevant context but does not prove the staged artifact was activated. Treat registration/activation as unknown, not as established persistence and not as disproven by the lack of a visible activation row.

### Source volume and collection plausibility

The Mac eCAR is flow-heavy and dominated by the internal proxy (`10.10.3.20:8080`, 221/310 flows). Process telemetry covers normal GUI launch trees, command-line work, and SSH sessions. Network evidence also includes internal DNS, Kerberos, LDAP, SMB, syslog, and a small number of inbound failures. This is a coherent source mix for a managed endpoint. The Unified Log file has two records, one loginwindow message and one SSH authentication message; because source coverage differs and the window is bounded, that small count is noted but is not treated as evidence of implausible collection by itself.

## Categorized indicator summary

| Category | Indicator | Assessment |
|---|---|---|
| `hard_contradiction` | None identified in the reviewed Mac records. | The SSH flow/auth/session ordering and source tuple agree. |
| `contract_gap` | No demonstrated event contract failure. | The missing root-shell termination is not decisive in a bounded slice. Launch-item activation is unknown, not contradicted. |
| `distribution_texture` | 221 of 310 flows go to the internal proxy on TCP/8080. | Concentrated, but plausible for proxy-mediated traffic; no independent evidence makes the volume impossible. |
| `schema_or_format` | None identified. | The sampled NDJSON/eCAR rows are parseable and their principal IDs, event times, and process fields are usable. |
| `environment_or_collection_plausibility` | Root `/bin/sh` creates/deletes an endpoint-inventory LaunchDaemon plist; inventory launchd job also runs periodic `sw_vers`. | Needs correlation against approved deployment/repair behavior and launchd state. A file operation is not proof of activation. |
| `weak_signal` | SSH pivots plus remote host/user discovery and reads from mounted user/research files. | Worth correlating with approvals and network transfer records; no malicious intent or exfiltration is established in this slice. |

## Realism scores

Scores use 1 = weak realism and 10 = strong realism.

| Dimension | Score | Basis |
|---|---:|---|
| Operational lifecycle | 7/10 | SSH login, shell, commands, and logout align; most short commands terminate cleanly. The root shell's full lifecycle is not visible. |
| Source volume and mix | 7/10 | Proxy-heavy but varied network services, with appropriate endpoint process and session activity. |
| Pivots and tradecraft | 7/10 | SSH and discovery activity form a coherent sequence, although authorization and intent are unknown. |
| Host/account/privilege boundaries | 6/10 | Maya's UID 501 activity is consistent; an unexplained non-interactive root shell and root-owned file operations need investigation. |
| macOS file execution and launch-item lifecycle | 6/10 | Ordinary application execution is plausible; the plist create/delete is concrete but lacks content and activation evidence. |

## Recommendations

1. For PID 19721 and parent PID 20519, correlate the process UUID, owning service/launch context, UID, and lifetime with the endpoint's authorized management tooling. Confirm whether a root shell is expected for the endpoint inventory job.
2. Recover the plist's content, owner/mode, hashes, and exact write/rename history. Check launchd's loaded job state and any bootstrap/activation records at the time of creation; distinguish a file staged on disk from a registered and running LaunchDaemon.
3. Correlate the SSH source `10.10.1.41:59129` and outbound destinations `10.10.4.10`, `10.10.2.30`, and `10.10.1.41` with the corresponding host owners, change tickets, and session records. Review the document reads against the user's expected access and look for separate transfer evidence before inferring collection or exfiltration.
4. If this pattern is synthetic in the generated dataset, correct it at the canonical process/file/action lifecycle layer: make plist write, launch-item registration/activation, service execution, unload, and delete separate events with explicit ownership and timing. Do not make a create/delete pair imply successful persistence.
