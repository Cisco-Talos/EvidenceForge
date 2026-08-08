## Blind verdict

**Synthetic**

- Verdict confidence: **86/100**
- Synthetic-origin confidence: **86/100**
- Posterior probability: **86% synthetic / 14% real**
- Assessment confidence: **high**
- The evidence is unusually sophisticated and well correlated, but repeated false process-to-registry causality is a decisive synthesis tell.

## Strongest evidence

### P1 — Corrupted process-to-registry causality

Unrelated user-shell and Office MRU registry activity is repeatedly assigned to newly launched processes at exactly `+1 ms`.

- `WS-LMORRIS` eCAR, `1715690887947`: PID 4060 launches hidden PowerShell to export Security events to `C:\Reports\security-review.csv`.
- At `1715690887948`, that same PID/process UUID writes:
  - `…\Search\SearchboxTaskbarMode`
  - `…\Explorer\ComDlg32\OpenSavePidlMRU\docx\24`
- `WS-NKAPOOR` eCAR, `1715709366673`: PID 8656 launches PowerShell `Compress-Archive` targeting `C:\Backups\audit-export.zip`.
- At `+1 ms`, that process writes Word Reading Locations, PowerPoint File MRU, and taskbar-search settings.
- Sysmon independently preserves the same attribution: EventRecordID `447593`, ProcessGuid `{aab87a56-a5b5-6643-c502-00003c9d9902}`, followed by registry EventRecordIDs `447594–447596`.

The pattern occurs eight times within ten milliseconds of process creation across two hosts. `SecurityHealthSystray` is also rewritten fourteen times by implausibly varied owners, including generic `svchost`, `dllhost`, `services.exe`, and EventLog `svchost`.

This materially poisons process/registry pivots and creates false persistence and user-activity conclusions.

### P2 — Command string without expected execution chain

On `WS-MPATEL` at `1715708518417`, PID 5436 is:

`cmd.exe /c net group "Domain Admins" /domain`

Security 4688, Sysmon EventID 1, and eCAR contain `cmd.exe`, but no child `net.exe`. The process terminates roughly 1.57 seconds later, and no corresponding domain-controller network activity is visible shortly afterward.

Collection loss could explain one missing source, but simultaneous absence across endpoint and network evidence suggests the command line was modeled without executing its native process/network consequences.

### P2 — Direct web and Zeek byte-count disagreement

Of 177 exact client/time/method/URI joins between the web access log and Zeek HTTP, 18 have different response-body byte counts, although statuses agree.

Examples:

- `12:57:02 GET /.git/HEAD`: Zeek `303`, web access `305`
- `12:55:12 GET /admin/`: Zeek `295`, web access `298`
- `12:21:34 GET /assets/img/content/42ae5430.jpg`: Zeek `355103`, web access `356886`

Zeek reports no missed bytes for these direct-origin observations. Compression or logging semantics could explain isolated differences, but the repeated drift weakens cross-source fidelity.

### P3 — Suspicious UserAssist binary morphology

Several Sysmon EventID 13 UserAssist values appear as arbitrary variable-length byte sequences rather than recognizable version-consistent structures. For example, `WS-NKAPOOR` EventRecordID `446984` reports a 40-byte Chrome UserAssist value, while nearby Word and Slack entries use different lengths.

This is suggestive, not conclusive, because registry rendering varies by Sysmon and Windows version.

## Realism strengths

- SSH evidence has excellent lifecycle ordering across source process creation, Zeek transport, target `sshd`, PAM authentication, session closure, and both endpoint process terminations.
- Explicit proxy traffic correctly separates client-to-proxy and proxy-to-origin connections while preserving hostname, CONNECT status, TLS SNI, certificate-chain FUIDs, and x509 identity.
- IDS alerts correlate cleanly with Zeek HTTP and origin access logs, including `.env`, `.git`, `server-status`, and crawler probes.
- Windows Security, Sysmon, and eCAR generally agree on PIDs, LogonIDs, images, process creation, and termination ordering.
- Zeek TLS/x509 morphology is strong: all referenced certificate-chain FUIDs resolve, SNI/SAN alignment is clean, and resumed sessions do not improperly carry new chains.
- The dataset contains useful false-positive texture: administrative SSH, hidden but potentially legitimate PowerShell, stale authentication noise, Internet scans, unusual DNS, and service activity.
- All inspected JSON records and Windows XML documents were structurally valid.

## Limitations

- This was a blind review of generated evidence only; scenario intent and ground truth were not inspected.
- The bounded six-hour window can legitimately omit earlier process creation or later termination.
- Collection policies, raw registry hives, PCAP, and application configuration were unavailable, so isolated telemetry gaps remain ambiguous.
- HTTP encoding or logging configuration might explain some body-length differences.
- Paths, filenames, metadata, branding, manifests, dataset volume, and ground-truth presence were excluded from the verdict.
