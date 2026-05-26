# Detection Engineer - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The dataset is high quality and would mostly parse cleanly through a detection stack: Windows Security/Sysmon schemas, Zeek UID/FUID relationships, proxy/firewall byte counts, and attack-sequence correlations are generally coherent. My synthetic verdict rests mainly on repeated source-native Linux `sshd` PID allocation patterns that do not look like real process allocation, plus a somewhat curated attack narrative that lacks the messier edges I would expect in production.

## Evidence For Synthetic

- `sshd` child PIDs for visible new SSH connections move backward repeatedly on the same host without a plausible PID wrap. Examples:
  - `DB-PROD-01.meridianhcs.local/syslog.log`: line 11 has `sshd 693434` at `2024-03-18T12:03:08.890120Z`; line 21 has a later new connection using lower `sshd 693217` at `12:06:18.267252Z`.
  - `WEB-EXT-01.meridianhcs.local/syslog.log`: line 26 has `sshd 770917` at `12:02:49.661569Z`; line 60 has lower `sshd 770656` at `12:05:33.433062Z`.
  - `APP-INT-01.meridianhcs.local/syslog.log`: line 79 has `sshd 839040` at `12:24:58.989808Z`; line 120 has lower `sshd 838595` at `12:40:05.400286Z`.
- This is not just a one-off: I counted backward PID movement among visible `Connection from` SSH initiators on `WEB-EXT-01` 29 times out of 98, `DB-PROD-01` 19/52, `APP-INT-01` 12/36, and `PROXY-01` 5/23. Real Linux PIDs normally advance cyclically and would not repeatedly regress in narrow ranges over a six-hour slice unless the system wrapped PID space, which is not supported by the values shown.
- The malicious storyline is very neatly staged: `PSEXESVC` service creation at `2024-03-18T16:00:16Z`, `net user svc_mhsync ... /add /domain`, Domain Admins modification, scheduled task creation, encoded PowerShell, audit log clear `1102`, and cleanup all appear in a compact, highly readable sequence. That is not impossible, but it feels purpose-built for huntability.
- Some generated-looking regularity appears in companion events: many Windows 4624/4672 pairs occur within sub-millisecond offsets across all hosts. This is schema-valid, but the consistency feels more renderer-like than organically collected.

## Evidence For Real

- Windows Event XML is structurally strong: correct providers, channels, namespaces, task/version values, localized tokens such as `%%14593`, `%%14611`, `%%1936`, and realistic Security/Sysmon Event IDs.
- Zeek logs are internally coherent. `dns.json`, `http.json`, `ssl.json`, `files.json`, and `x509.json` UID/FUID relationships line up with `conn.json`; I found no sublog timestamps outside their connection windows.
- Cross-source network evidence is convincing. The large `api.westbridge-services.net` upload appears as proxy POST line 1023 with `cs-bytes 314782725`, Zeek DMZ connection line 5793 with `orig_bytes 315397859`, and ASA teardown line 14624 with `bytes 330380194`, which is plausible once headers and tunnel overhead are included.
- The Linux syslog format is credible RFC5424-style output with sensible PRI values, systemd, journald, cron, sudo, UFW, and SSH messages. Kernel uptime brackets on `WEB-EXT-01` advance consistently with wall-clock time.
- Web and proxy logs include normal operational texture: 304 responses with `-` byte counts, referrers, varied user agents, cache outcomes, SSL inspection entries, package-manager traffic, and denied proxy attempts.
- Zeek and firewall logs include realistic noise: scans, S0 connections, DNS resolver traffic, OCSP, certificate chains, and external web traffic mixed with internal activity.

## Detailed Analysis

**Windows Security and Sysmon schema**

The Windows records are largely source-faithful. Security logs use `Microsoft-Windows-Security-Auditing` with correct event families: 4624/4625/4634/4648, 4672, 4688/4689, 4768/4769/4771/4776, 5156, and account-change events. Sysmon uses `Microsoft-Windows-Sysmon/Operational` with Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. Field naming and capitalization are notably good: `SourceProcessGUID`, `TargetProcessGUID`, `QueryStatus`, `QueryResults`, `GrantedAccess`, and `CallTrace` all look parseable.

I spot-checked process-create correlation. Security 4688 and Sysmon 1 generally agree on PID/image pairs with realistic timing jitter. Sysmon hashes are correctly shaped for SHA1, MD5, SHA256, and IMPHASH. WFP 5156 fields use credible device paths, protocol numbers, layer IDs, and filter IDs.

The DC attack sequence is internally coherent: `PSEXESVC` appears as service creation, subsequent `net.exe` commands create `svc_mhsync`, add it to `Domain Admins`, later run encoded PowerShell, then delete the account. Event 1102 at `2024-03-18T17:42:33.7624841Z` uses the Eventlog provider and `UserData/LogFileCleared`, which is correct.

**Linux/syslog source-native checks**

The Linux log vocabulary is strong, but the `sshd` PID behavior is the main authenticity break. In OpenSSH, a new inbound connection is handled by a newly forked child, and the `Connection from ...` message is emitted by that child. Across a short window, those PIDs should generally advance unless PID space wraps. Instead, multiple hosts show later visible SSH initiators with lower PIDs in the same narrow range.

This is stronger than "missing opens/closes." I did not count close-only events as synthetic because the slice may begin after sessions started. The issue is visible initiating events for new SSH connections moving backward in PID space across the same host.

**Zeek and network telemetry**

Zeek JSON is one of the most convincing parts of the dataset. UIDs are consistently propagated, `local_orig`/`local_resp` align with internal/external IP direction, and sublogs stay within their parent connection windows. DNS fields such as `AA`, `RD`, `RA`, `qtype_name`, `rcode_name`, `TTLs`, and reverse lookups are plausible. SSL/X509/FUID relationships are particularly well modeled.

The 17:25 upload is a good example of high-quality source correlation: client-to-proxy CONNECT/POST, proxy-to-outside TLS, ASA build/teardown, and byte counts are close without being identical. That argues for careful construction or real SIEM-quality data.

**HTTP/proxy/firewall**

`PROXY-01.meridianhcs.local/proxy_access.log` has credible W3C-like fields and realistic tunnel versus SSL-inspected request distinctions. The large POST at `2024-03-18 17:25:06` is logged as `POST https://api.westbridge-services.net/upload/telemetry/7f3a2b19` with a very large client byte count, while CONNECT setup is separate. ASA records preserve connection IDs and teardown durations; I found no build/teardown ordering contradictions.

**Behavioral/narrative realism**

The background noise is better than most synthetic sets: package managers, OneDrive/Dropbox/Chrome/Windows Update, web browsing, internal SMB, Kerberos, LDAP, DNS, OCSP, inbound scanning, and Linux admin sessions all appear. The attack is detectable but not isolated from the baseline.

Still, the adversary sequence is almost too legible. It reads like a curated training dataset: recon commands, PsExec, domain user creation, privilege group modification, scheduled task persistence, exfil, encoded PowerShell, log clear, cleanup. Real intrusions can be that clean, but the combination with the Linux PID artifact pushes me to synthetic.

## Realism Score by Category

- **Field format accuracy:** 8 - Most Windows, Zeek, proxy, ASA, and syslog fields are schema-valid and parser-friendly.
- **Temporal patterns:** 6 - Broad timing is believable, but SSH PID ordering and some tight companion-event timing feel generated.
- **Cross-source correlation:** 9 - Zeek/proxy/firewall/EDR relationships are strong and byte/timestamp alignment is credible.
- **Behavioral realism:** 7 - Rich baseline and attack activity, though the intrusion storyline is unusually tidy.
- **Environmental consistency:** 8 - Host/IP roles, OS-specific logs, domain naming, timezone use, and service behavior mostly hold together.

## Recommendations

- **P1:** Fix Linux SSH PID allocation so visible new `sshd` connection child PIDs advance realistically per host, with PID reuse only after plausible wrap/reboot conditions.
- **P2:** Add more messy attacker/operator variance: failed commands, mistyped paths, partial output artifacts, privilege-context changes, and less linear cleanup.
- **P3:** Loosen repeated companion-event timing where possible, especially highly consistent sub-millisecond Windows logon/special-privilege pairs.
- **P3:** Add more benign event-log clutter around high-value attack actions so the timeline feels less staged while preserving detection pivots.
- **P4:** Continue adding source-native oddities such as occasional proxy cache quirks, TLS resumptions with mixed visibility, and host-specific logging idiosyncrasies.
