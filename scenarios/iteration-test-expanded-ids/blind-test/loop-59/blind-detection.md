# Blind Detection Engineering Review — Loop 59

## Verdict

- **Verdict:** Synthetic
- **Verdict confidence:** 80/100
- **Synthetic-confidence:** 69/100

The corpus is unusually strong as detection-development data: it contains enough background activity to exercise suppression logic and a coherent, multi-host intrusion with endpoint, identity, network, file, proxy, and IDS evidence. I would use it for analytic prototyping. I would not mistake it for an uncurated production collection, chiefly because several process/artifact relationships are source-native impossibilities and the attack is too completely signposted across a six-hour window.

## Category scores

| Category | Score | Assessment |
|---|---:|---|
| Malicious-signal observability | 92/100 | Excellent ATT&CK-shaped coverage from discovery through persistence, collection, exfiltration, and cleanup. |
| Cross-source correlation | 88/100 | Host, identity, tuple, file, and protocol evidence generally line up and permit reliable pivots. |
| Detection-rule usefulness | 87/100 | Rich fields, stable entity identifiers, full command lines, principals, PIDs, and network tuples support practical detections. |
| Baseline/noise discrimination | 72/100 | There is substantial benign volume, but some background process ownership is artificial enough to teach poor allowlists. |
| Source-native semantic fidelity | 66/100 | A few application/file and parent/child relationships are operationally implausible or impossible. |
| Temporal/lifecycle fidelity | 81/100 | The primary attack sequence is ordered well; some artifact provenance and execution prerequisites are absent. |
| **Overall detection-engineering value** | **81/100** | High-value training corpus with material realism defects. |

## Evidence supporting the verdict

### Strong, detection-ready intrusion chain

The corpus exposes a coherent sequence rather than disconnected indicators:

- At `1710776729463`, `ms-index-service.exe` on `WS-AJOHNSON-01` remotely creates a thread in `lsass.exe`, a high-value endpoint signal with source and target process identity.
- At `1710778508333`–`1710778512287`, SYSTEM-owned `cmd.exe`/`net.exe` processes on `DC-01` create `svc_mhsync`, expose the password in the command line, and add the account to Domain Admins.
- At `1710778802280`–`1710779366719`, the same host creates `DeviceSyncSvc`, installs an hourly scheduled task, and executes `DeviceSyncSvc.exe`.
- At `1710781259773`, `svc_mhsync` collects Finance and Patients data on `FILE-SRV-01` into `C:\ProgramData\Microsoft\cache_7f3a.zip`. The later SMB transfer is represented in Zeek `files.json` with the same path and realistic byte volume.
- At `1710782391910`–`1710783003699`, the Linux-side chain runs `mysqldump`, `gzip`, `sha256sum`, and `scp`, with matching file read/create telemetry at sender and receiver.
- The later `EncodedCommand`, `wevtutil cl Security`, account deletion, and shell-history clearing provide explicit defense-evasion/cleanup evidence.

This is excellent for building process-chain, privileged-account, archive-collection, service-persistence, DNS-tunneling, and exfiltration detections. Network dual-observation is particularly useful: for example, source and destination eCAR FLOW records for `10.10.1.35:57246 -> 10.10.2.10:135` differ by only 13 ms and correctly identify outbound versus inbound direction.

### Hard source-native contradiction: browsers own Outlook artifacts

Four FILE records assign Chrome or Edge as the actor for files underneath Outlook-only cache locations:

- Chrome creates `...\Microsoft\Windows\INetCache\Content.Outlook\11PCK49H\benefits-confirmation.txt` on `WS-DRAMIREZ-01`.
- Edge creates `...\Content.Outlook\10CRXDWP\reset-validation-steps.txt` on the same host.
- Chrome creates another `Content.Outlook` attachment (`operating-note-march.txt`).
- Edge creates `...\Content.Outlook\10CRXDWP\reset-validation-steps.txt` on `WS-EBROOKS-01`.

A browser using OWA may write its own browser cache or Downloads artifacts; it does not become `OUTLOOK.EXE` and populate the desktop Outlook `Content.Outlook` cache. These records are dangerous for detection engineering because they corrupt application baselines and process/file allowlists.

### Background parentage is too generator-like

Of 36 observed `wget`/`curl` process creates, 35 have PPID 1. The affected commands repeatedly fetch package repositories, analytics/CDN domains, and ordinary web properties as root. Some systemd jobs can produce an init-parented helper, but this near-universal pattern across many hosts and unrelated destinations suppresses the service or timer that should own the activity. It makes ancestry-based rules much less realistic and creates a conspicuous corpus-wide signature.

### Attack coverage is over-complete

Within one six-hour slice the analyst receives credential theft, account creation, Domain Admin membership, remote service execution, scheduled-task persistence, file collection, archive staging, database dumping, SCP transfer, DNS tunneling, browser upload, encoded PowerShell, Security-log clearing, account deletion, and history clearing. Production telemetry frequently has collection gaps, endpoint exclusions, delayed ingestion, or ambiguous ownership. Here, nearly every narrative transition has an explicit high-confidence artifact and highly descriptive names such as `cache_7f3a`, `rpt_0318`, and `DeviceSyncSvc`. That completeness makes the corpus useful but recognizable as an authored exercise.

### Missing prerequisite weakens one persistence chain

`DeviceSyncSvc` is installed with binary path `C:\Windows\System32\DeviceSyncSvc.exe` and later executes, but the reviewed endpoint FILE telemetry does not show the executable being created or written. This can occur under collection loss, but the otherwise dense visibility makes the isolated omission look constructed. Either model a plausible delivery/write/rename event and its owning process, or deliberately represent broader source-level coverage loss.

## Recommendations

1. **Fix application-native artifact ownership first.** Derive mail attachment/cache paths from the actual client. Desktop Outlook may own `Content.Outlook`; OWA in Chrome/Edge should own browser-cache or Downloads paths. Add a cross-product contract covering browser, Outlook, and Thunderbird clients.
2. **Preserve the true launcher for scheduled/background downloads.** Model the systemd timer/service, package manager, updater, or application process that launches `wget`/`curl`; avoid PPID 1 as the default for almost every fetch.
3. **Complete the service-binary provenance chain.** Add a realistic write/drop/rename of `DeviceSyncSvc.exe` before service creation and keep the writer, hash, and later process image correlated.
4. **Introduce coherent collection gaps.** Drop or delay related source groups at realistic rates instead of presenting every attack phase at maximum visibility. Keep enough evidence to hunt, but force at least some inference.
5. **Reduce authorial naming and one-of-everything staging.** Reuse ordinary operational names, let some behaviors blend with host baselines, and spread or omit selected steps so detections must rely on relationships rather than obvious tokens.

## Bottom line

This is a high-quality detection exercise and materially better than a bag of independent IOCs. Its best feature is the correlated multi-source chain. Its strongest synthetic tell is not formatting; it is semantic ownership—especially Chrome/Edge producing desktop Outlook artifacts—combined with near-perfect attack observability. Correcting those ownership rules would materially increase both realism and the safety of detections trained on the corpus.
