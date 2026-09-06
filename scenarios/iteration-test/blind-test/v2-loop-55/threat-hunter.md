# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 72  
**Synthetic-Confidence Score:** 65

## Executive Summary

The dataset is unusually strong synthetic telemetry: host roles, attack tradecraft, baseline volume, and most cross-source pivots are operationally convincing. My synthetic verdict rests on two concrete contract gaps concentrated around modeled attack actions—unmatched Windows network-logon source ports and omitted child processes required by visible shell commands—plus weaker repeated-command texture across Linux histories.

## Evidence For Synthetic

- `[contract_gap]` Several privileged remote-administration logons use source ports that do not exist in the accompanying network telemetry, despite ordinary network logons matching reliably. On `DC-01`, the 4624 Type 3 logon for `aisha.johnson` at `2024-03-18T15:59:48.2866279Z` reports `10.10.1.35:62031`, but the corresponding PsExec activity uses SMB `10.10.1.35:49576 → 10.10.2.10:445` and RPC `:49577 → :135`; no Zeek connection uses port `62031`. Similar mismatches occur at `15:06:23`, `15:44:29`, `16:59:27`, and `17:29:18` on `DC-01`, and in five comparable `DC-02` remote-admin logons.
- `[contract_gap]` Attack command lines requiring child processes are rendered only as a parent shell. `WEB-EXT-01.../ecar.json:748` records `bash -c 'echo ... | base64 -d | bash'` at `13:20:32.524Z`, but no `base64` or inner `bash` process follows. This contrasts with recurring sysstat commands, where `/bin/sh -c ...` and its `debian-sa1` child are both recorded.
- `[contract_gap]` The same omission recurs during cleanup: `APP-INT-01.../ecar.json:857` records `bash -c 'history -c && cat /dev/null > ~/.bash_history'` at `17:51:13.247Z`, followed by a file artifact but no required `/usr/bin/cat` child process.
- `[contract_gap]` `DC-01.../ecar.json:3472` records `cmd.exe /c whoami && hostname` at `15:59:56.121Z`, but neither `whoami.exe` nor `hostname.exe` appears as a child, even though the endpoint stream otherwise records short-lived process creation and termination extensively.
- `[distribution_texture]` Linux histories reuse a relatively compact administrative command vocabulary across unrelated user-host pairs: 315 commands yield only 239 unique strings, with 119 occurrences belonging to commands repeated across multiple histories. More distinctive strings such as `sysctl -a 2>/dev/null | grep net.ipv4.ip_forward`, `systemd-analyze blame | head`, and `journalctl -u sshd --since '1 hour ago'` recur verbatim across different accounts or systems.
- `[weak_signal]` The remote-admin transport gaps are disproportionately associated with high-value actions rather than ordinary logons. Of 172 network logons on `DC-01`, 165 had exact source-port matches; of 141 on `DC-02`, 135 matched. The exceptional cases cluster around SMB/RPC administrative activity, suggesting a separate modeled path rather than ordinary collection loss.

## Evidence For Real

- The six-hour window contains approximately 88,684 records: 32,524 eCAR, 18,044 Windows Security, 4,976 Sysmon, 32,825 Zeek, and 315 shell-history commands. This provides believable signal-to-noise for roughly twenty systems rather than presenting only attack records.
- The initial compromise is temporally plausible. Inbound TLS from `185.70.41.45` reaches `WEB-EXT-01` at `13:20:29.080548Z`; Apache spawns the encoded shell at `13:20:32.524Z`; the reverse connection begins at `13:20:43.245317Z` on `10.10.3.10:60568 → 45.33.32.30:8443`.
- The reverse connection agrees between endpoint and network telemetry. Zeek UID `C59YGfH3YbODFZiVxo` reports an `SF` connection lasting 10.292391 seconds with bidirectional bytes; eCAR records the same tuple 132 milliseconds after Zeek’s connection start and attributes it to PID `1480967`.
- PsExec behavior on `DC-01` is otherwise highly convincing: SMB transfer of `PSEXESVC.exe`, Event 4697 service installation by `aisha.johnson`, service process creation under `services.exe`, and child `cmd.exe /c whoami && hostname` occur in a credible order between `15:59:49Z` and `15:59:56Z`.
- Account persistence is source-native and coherent. At `16:14:42Z`, WMI-hosted `cmd.exe` launches `net user svc_dirsync MhsSvc!2024 /add /domain`; at `16:14:54Z`, the account is added to `Domain Admins`. Windows Security contains the corresponding account-management events.
- Data staging and exfiltration are well correlated. On `DB-PROD-01`, root runs `mysqldump` at `17:16:06Z`, compresses the dump at `17:18:35Z`, hashes it at `17:19:10Z`, and transfers it to `10.10.2.30` at `17:34:50Z`.
- The proxy exfiltration pivot is particularly credible. `WS-AJOHNSON-01` reads `cache_7f3a.zip`, connects to `10.10.3.20:8080` using source port `49173`, and Zeek records a 18,783,220-byte client upload. The proxy then opens `10.10.3.20:34101 → 45.33.32.30:443`, with matching TLS SNI `api.westbridge-services.net`.
- Cleanup has realistic source effects. `wevtutil cl Security` runs on `DC-01` at `17:42:07Z`; Security Event 1102 appears, and `EventRecordID` subsequently resets from the pre-clear sequence to low values rather than continuing monotonically.
- Zeek integrity is strong without visible contradictions: all 19,215 connection UIDs are unique per sensor, no companion record changes a UID’s tuple, and no DNS/HTTP/TLS/file companion precedes its connection start.
- The background contains varied connection outcomes (`SF`, `S0`, `RSTO`, `RSTR`, `REJ`, `S1`–`S3`, `OTH`), external scanning against multiple DMZ ports, DHCP, SMB, Kerberos, LDAP, SMTP, proxy traffic, certificate artifacts, scheduled maintenance, updater activity, failed authentication, and ordinary administrative mistakes such as `dff`.

## Detailed Analysis

### Scope and collection profile

The observable period is approximately `2024-03-18 12:00–18:00 UTC`. The environment contains workstation, domain-controller, file-server, mail, database, application, proxy, monitoring, and Internet-facing web roles across `10.10.1.0/24` through `10.10.4.0/24`.

The busiest sources are the domain controllers, with 6,487 Security events on `DC-01` and 5,675 on `DC-02`. Their mix is plausible for their role: Event IDs 5156, 4768, 4769, 4624, 4634, 4688, 4689, and 4672 dominate. Zeek core is correspondingly rich in DNS, Kerberos, LDAP, SMB, and HTTP, while the DMZ sensor is dominated by external scan failures and web/TLS traffic.

### Initial access and command execution

At `13:20:29.080548Z`, Zeek records a successful inbound TLS session from `185.70.41.45:57162` to `WEB-EXT-01` on port 443. The connection remains active for 26.84 seconds. At `13:20:32.524Z`, `/usr/sbin/apache2` spawns PID `1480967` as `www-data` with an encoded reverse-shell command. At `13:20:43.245317Z`, Zeek sees the resulting outbound port-8443 connection, and eCAR observes the identical tuple shortly afterward.

This chain is operationally viable. The defect is not the sequence but its process representation: decoding through external `base64` and invoking a second shell necessarily create processes that the eCAR stream does not show. That omission is conspicuous because routine shell wrappers elsewhere include their child executions.

### Lateral movement and privilege expansion

The Linux path proceeds from `WEB-EXT-01` to `APP-INT-01` via root SSH at approximately `14:15Z`. On the application server, root enumerates `/etc/passwd` and `/etc/shadow`, retains a long-running shell session, and later SSHes to `DB-PROD-01`. The database activity then stages and transfers a compressed export. The relevant SSH, process, file, and network evidence appears in workable order.

The Windows path uses `WS-AJOHNSON-01` as a source for PsExec against `DC-01`. Network telemetry records SMB and RPC immediately before service installation, and target telemetry captures `PSEXESVC.exe` creation and execution. The target’s Event 4624, however, claims a source port absent from all three Zeek sensors. Because 165 of 172 comparable `DC-01` network logons match exactly, collection scope alone is a weak explanation.

At `16:14Z`, remote WMI execution creates `svc_dirsync` and adds it to `Domain Admins`. At `16:20Z`, `DeviceSyncSvc` is installed on `DC-01`. These steps use appropriate binaries, parentage, privileges, and Windows event families.

### Collection and pivot feasibility

Most pivots work unusually well:

- Endpoint FLOW tuples align with Zeek.
- Zeek HTTP, TLS, certificate, and file records preserve UID and tuple identity.
- Process-dependent eCAR events do not precede visible process creation for the same `objectID`.
- Visible process terminations do not precede corresponding visible creation.
- SMB mapping and file records preserve the connection UID.
- Proxy client and origin legs are distinguishable and temporally ordered.
- Source-local timing differs by small, plausible collection delays rather than being bit-identical.

The dominant weakness is not excessive completeness but selective inconsistency: remote-admin logon ports and shell child processes follow weaker contracts than the ordinary activity around them.

### Signal-to-noise and behavioral texture

The attack is buried among tens of thousands of authentication, firewall, endpoint, web, proxy, DNS, directory, updater, scheduled-task, and scanning records. Zeek-core median connection inter-arrival is 0.782 seconds and Zeek-DMZ is 0.368 seconds, with long-tailed gaps rather than fixed uniform spacing.

Linux system activity has sensible periodicity: sysstat executes every thirty minutes with stable per-host phase offsets and subsecond scheduling variation. Human command timing is substantially less regular. The main distribution concern is vocabulary reuse, not event timing: several exact diagnostic strings appear across different admins and hosts often enough to resemble draws from a shared command pool.

### Cleanup

The attacker clears the `DC-01` Security log at `17:42Z`, deletes `svc_dirsync` at `17:49Z`, removes a service from `DC-02` around `17:51:56Z`, and clears root shell history on `APP-INT-01` at `17:51:13Z`.

The Windows log-clear behavior is a strong realism point because Event 1102 coincides with an actual `EventRecordID` discontinuity. The Linux cleanup command’s missing `cat` child is the countervailing synthetic tell.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Windows Security, eCAR, Zeek | Repeated across privileged DC remote-admin actions | High: 4624 source ports lack corresponding network tuples while ordinary logons match |
| `contract_gap` | Linux eCAR | Initial compromise and cleanup | High: visible shell commands require child processes that are absent despite detailed process collection |
| `contract_gap` | Windows eCAR | PsExec command execution | Medium: `cmd.exe /c whoami && hostname` has no required child executables |
| `distribution_texture` | Bash histories | Cross-host, cross-user | Medium-low: distinctive administrative commands recur verbatim from a relatively compact pool |
| `weak_signal` | Multi-source attack telemetry | Concentrated around modeled behavior | Low independently: realism defects cluster around attack-specific paths rather than baseline activity |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, eCAR fields, Zeek schemas, TLS values, registry artifacts, and command lines are generally source-appropriate.
- **Temporal patterns:** 8 — Baseline timing is varied and attack phases are mostly ordered plausibly; no same-identifier lifecycle inversion was found.
- **Cross-source correlation:** 7 — Most tuples and UIDs correlate extremely well, but privileged Windows logon source ports repeatedly diverge from visible transport.
- **Behavioral realism:** 7 — Tradecraft and host use are credible, weakened by missing shell subprocesses and repeated command vocabulary.
- **Environmental consistency:** 8 — Host roles, source volumes, protocol mix, failures, scanning, maintenance, and service activity fit the apparent environment.

## Recommendations

If this were synthetic, the following changes would improve it:

- Make each Windows network logon inherit the actual authentication or service-control transport source port. For PsExec and WMI paths, preserve the canonical SMB/RPC tuple through Event 4624, eCAR `USER_SESSION`, endpoint FLOW, and Zeek rendering.
- Ensure transport evidence visibly precedes the associated logon when both are retained. The PsExec example currently places the target logon before the matching SMB connection and assigns it an unrelated port.
- Expand shell-command modeling into required subprocesses. The encoded compromise should produce at least the outer shell, `base64`, inner `bash`, and their lifecycle events; the history cleanup should include `/usr/bin/cat`.
- Apply the same child-process contract to Windows command chains such as `cmd.exe /c whoami && hostname`, producing `whoami.exe` and `hostname.exe` with correct parent PID, principal, and termination.
- Increase role- and actor-specific command vocabulary so distinctive Linux diagnostics do not recur verbatim across unrelated histories as often. Preserve the existing timestamps, typos, pipelines, and host-specific commands, which already add useful production texture.
