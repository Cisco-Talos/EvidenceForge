# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 64
**Synthetic-Confidence Score:** 31

## Executive Summary

The supplied slice is operationally credible: suspicious execution, remote authentication, file movement and proxy traffic support usable pivots without the clear lifecycle contradictions I specifically tested for. A few narrow coverage and command-texture questions remain, but the visible evidence does not justify a confident synthetic verdict; “Real” is a modest preference, not a claim that sophisticated generation has been excluded.

## Evidence For Synthetic

- [weak_signal] The two Macs have a conspicuously diagnostic command vocabulary. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` and the corresponding MAC-MROSS-02 file, each host has five EXEC notifications targeting `/usr/bin/sw_vers` during the six-hour slice. Their shell histories also repeatedly enumerate identity, OS version, documents, processes and disk usage. This is compatible with troubleshooting or an assessment, but provides a limited command-pool texture concern. I do not treat the presence or completeness of suspicious activity as evidence.
- [weak_signal] The DB export chain has an isolated observability discontinuity: `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history` records `gzip -9 /tmp/rpt_0318.sql` at epoch `1793643340` (18:15:40 UTC), between the visible dump and SCP commands, but the host's eCAR file contains neither a gzip process nor creation of the compressed output. This is a question about the apparent process capture, not proof that compression did not happen. Filtering, loss, or a failed command followed by use of an existing file remain possible; I give it little scoring weight.

## Evidence For Real

- The environment has distinguishable workstation, directory, file, application, database, mail, proxy and monitoring roles, with Windows, Linux and macOS source families appropriate to those hosts. I counted 23 hosts with eCAR records, not including network-sensor directories.
- The 2026-11-02 approximately 13:00–19:00 UTC slice contains substantial unrelated activity: 36,715 eCAR records, 22,408 Zeek connections across three sensor locations, 4,171 Linux syslog lines, 3,992 proxy records and 816 web-access lines. Windows Security contains 17,375 events. The suspicious actions are embedded among ordinary authentication, process, browsing, service and scanning activity.
- SSH pivots have concrete transport and account correspondence. DB-PROD's SCP uses `10.10.4.10:56898 -> 10.10.2.30:22`; APP-INT records that same source tuple, a root login, a destination file creation and a logout. Network sensors independently observe the transfer.
- A reverse-shell command on WEB-EXT refers to `45.33.32.30:8443`. The associated Zeek flow is raw TCP with no fabricated TLS service or TLS companions merely because port 8443 is used. Its connection ends before the endpoint shell terminates.
- Collection latency exists without breaking the selected pivots. For example, native Mac EXEC for the Homebrew curl is at 14:00:36.111832 UTC, while the corresponding eCAR process modification is at 14:00:37.327 UTC. Such source-specific observation differences are plausible.
- The Mac policy warning is not followed by a successful MeetingAssist EXEC notification in the inspected ES records. I found no basis for attributing execution or effects to the warning alone.
- Broad sanity checks found no eCAR actor action more than 100 ms before that actor's visible process creation, no actor action more than one second after its visible termination, and no checked process-owned flow extending over five seconds beyond the owner's termination. These checks used stable process object identifiers rather than PID-only joins.

## Detailed Analysis

### Orientation and collection scope

I examined only the supplied data directory. The 23 eCAR host directories cover 10 Windows hosts, 11 Linux hosts and two Macs, inferred from the supplied native source families and process paths. The address space includes `10.10.1.*` client systems, `10.10.2.*` internal services, `10.10.3.*` web/proxy systems and `10.10.4.10` DB-PROD. These are inferences from observed names and tuples, not an externally supplied inventory.

The earliest eCAR timestamp is 13:00:00.800 UTC and the latest is 18:59:55.807 UTC on November 2. I treated this as a collection slice. I did not penalize initial logouts, existing service processes or absent final terminations simply because their other lifecycle phase might fall outside the window.

The most active eCAR hosts are PROXY-01 (6,031 rows), DC-01 (5,525), DC-02 (4,744) and WEB-EXT-01 (4,113). Lower-volume endpoints differ meaningfully: the Macs have 594 and 549 rows, while APP-INT has 929. This is a credible role-dependent mix. Counts alone cannot establish whether the data is real.

### Web execution and reverse connection

`WEB-EXT-01.meridianhcs.local/web_access.log:467` shows `185.70.41.45` making a successful `POST /ehr/admin/upload.php` at 14:20:17 UTC. The endpoint's `ecar.json:929-934` shows an inbound HTTPS tuple from that address, an Apache child bash at 14:20:17.361, a `base64 -d` child and a second bash, followed by an outbound connection at 14:20:20.715.

The encoded command names `45.33.32.30:8443`. `zeek-dmz/conn.json:2003` provides UID `CdOiluYE8I5efAq6D`, tuple `10.10.3.10:52175 -> 45.33.32.30:8443`, start epoch `1793629220.568885`, duration `24.772326`, state `SF`, 620 originator bytes and 1,840 responder bytes. No `service: ssl` is assigned. This matters technically: a bash TCP reverse shell does not acquire TLS simply by choosing a commonly TLS-associated port.

The raw connection closes at approximately 14:20:45.341; the second bash terminates at 14:20:50.429 and its parent at 14:20:51.325 (`ecar.json:945-946`). Those observations are lifecycle-compatible. The logs show suspicious execution and a reverse connection; they do not themselves establish the vulnerability used by the HTTP request.

### Database collection and SCP transfer

DB-PROD records a root remote session from APP-INT, tuple `10.10.2.30:37538 -> 10.10.4.10:22`. At 18:15:10.697 the eCAR LOGIN is followed by a root shell at 18:15:13.241, `mysqldump --single-transaction ehr patients insurance_claims` at 18:15:15.997 and `/tmp/rpt_0318.sql` creation at 18:15:18.198 (`DB-PROD.../ecar.json:620-624`). The dump process terminates at 18:15:39.789.

SCP starts at 18:16:07.525, reads `/tmp/rpt_0318.sql.gz` at 18:16:16.946 and terminates at 18:16:41.570. Its network tuple is `10.10.4.10:56898 -> 10.10.2.30:22`.

`zeek-core/conn.json:10721` and `zeek-db/conn.json:433` observe that same tuple, with separate sensor-local UIDs. Core reports epoch `1793643370.476420`, duration `29.936438`, SSH service, successful close, 2,150,225 originator bytes and 31,932 responder bytes. DB's observation differs by roughly 70 ms and closely agrees on duration. The SCP process remains alive past transport close.

On the receiving host, `APP-INT.../ecar.json:853-858` contains the incoming tuple, a root sshd process, root LOGIN at 18:16:17.647, `/tmp/.cache/rpt_0318.sql.gz` creation at 18:16:41.209 and a subsequent logout. This is an actionable pivot between sender, network and receiver. I cannot infer file-content equality from a shared filename alone.

The gzip history/endpoint discontinuity described above is the principal uncertainty within this chain. Bash history is an attempted command record, not proof of successful compression. It therefore falls short of an impossible lifecycle finding.

### Windows collection and proxy upload

Windows Security records show expected differences between roles. DC-01 has 6,216 events including 980 TGS events (4769), 285 successful logons and 4,275 permitted-connection events (5156). DC-02 has 5,598 including 1,026 TGS events. FILE-SRV has 1,276 including share/object audit activity (5140, 5145, 4656, 4663 and 4658). These distributions are more meaningful than merely asking whether every possible Windows event family is present.

WS-AJOHNSON has PowerShell commands collecting files from FILE-SRV and FILE-LNX into `C:\ProgramData\Microsoft\VaultCache`, followed by archive creation. At 18:25:17.758 a visible curl process specifies an explicit proxy and a multipart upload to `https://api.westbridge-services.net/upload/telemetry/7f3a2b19`.

`PROXY-01.meridianhcs.local/proxy_access.log:3512` records that exact URL at 18:25:21, client `10.10.1.35`, authenticated account `MERIDIANHCS\aisha.johnson`, `curl/8.4.0`, HTTP 200, `cs_bytes=18783258` and client source port 51113. The row explicitly identifies `proxy_action=ssl-inspect ssl_bump=bump`. Logging the HTTPS path and multipart upload through this collection point is consequently plausible; the visible collection declares inspection rather than leaving HTTPS path visibility unexplained.

### Mac interpretation

The Mac native files are ES-style notifications and Unified Log-shaped exports, distinct from normalized eCAR. I did not assume Windows session identifiers or Linux PAM expectations applied to their native records.

MAC-MROSS-01's Homebrew curl EXEC at 14:00:36.111832 targets the downloaded `connector-check.sh`; a separate bash EXEC at 14:00:45.086420 invokes that script. Download and execution are distinguishable. The later MeetingAssist security-policy message at 15:42:09.009673 does not by itself prove a successful launch; no successful EXEC to that application was found in the inspected ES records.

Both Macs repeatedly execute OS and identity diagnostics. This is the only reasonably concrete command-texture concern I retained, and it is weak: the user's job, support workflow and reasons for maintaining two machines are unknown. I did not penalize sparse Unified Log coverage or expect every capability of macOS auditing to appear.

### Checks against false positives

I compared each Zeek HTTP UID's aggregate request/response body lengths with its connection's directional payload byte counts. None exceeded the associated transport payload. HTTP, DNS and SSL records did not occur more than one second after the associated visible connection close in the checked sensor-local data.

The 58 eCAR SSH logins have varied visible process counts, ranging from zero to 24. Such variation does not support a simple fixed-command session template. Similarly, a sample of 20 short Linux diagnostic commands with matched creation and termination had a median lifetime of 0.4465 seconds, a range of 0.134–5.948 seconds, and seven lifetimes over one second. I did not find enough evidence to call those durations a universal timing artifact.

These checks strengthen operational credibility. They do not turn complete correlation into an authenticity test, nor do they establish that every record is correct.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | macOS ES and shell histories | Both Macs; five sw_vers EXECs each in six hours, repeated diagnostic vocabulary | Modest concern about command texture; legitimate troubleshooting is an adequate alternative explanation. |
| weak_signal | Linux eCAR and bash history | One DB-PROD export/compression/transfer sequence | A narrow companion-record question, heavily discounted because capture completeness and command success are unproven. |

No hard contradiction was established. The score remains in the mostly realistic range; the weak observations above are insufficient to support a high synthetic-confidence score.

## Realism Score by Category

- **Field format accuracy:** 8 — Supplied JSON/XML and source-specific fields support coherent investigation; no decisive format violation was established.
- **Temporal patterns:** 9 — Selected transport, authentication, execution and termination relationships work, with plausible source latency and varied session activity.
- **Cross-source correlation:** 9 — Web, SSH/SCP and explicit-proxy pivots are usable and technically consistent; compression visibility remains an isolated uncertainty.
- **Behavioral realism:** 8 — Commands and transport usage support the observed actions, with a somewhat repetitive Mac diagnostic vocabulary.
- **Environmental consistency:** 8 — Host roles, segments and source-family volumes are credible for the visible slice; exact collection policy remains unknown.

## Recommendations

- If this were synthetic, diversify the two Macs' ordinary command activity around their actual users' workflows where appropriate, rather than repeatedly leaning on OS/version/identity diagnostics. Keep diagnostics when a concrete support task calls for them.
- If this were synthetic and DB-PROD's process stream is intended to include all commands in the root session, include the attempted gzip process and its actual success/failure and output-file lifecycle. If the omission represents filtering or loss, preserve a collection model that explains this class of omission consistently.
- Preserve the operational properties that already work: raw TCP for the bash reverse shell, source-specific observation latency, tuple/account correspondence for SSH, realistic sensor-local UID differences, and the explicit TLS-inspection explanation for HTTPS proxy visibility.
