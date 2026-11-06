# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 38

## Executive Summary

The collection is mostly production-like from a threat-hunting perspective: the suspicious Windows and Linux activity supports useful, technically coherent process, account, network and file pivots. I found limited timing texture worth investigating, but no demonstrated impossible lifecycle or decisive authenticity fingerprint; the supplied data does not justify a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] Six native macOS inventory executions have unusually tightly clustered lifetimes despite irregular launch times on two hosts. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, exec/exit line pairs 30/31, 62/63 and 109/110 yield 1.995341, 1.990099 and 1.992767 seconds for `/usr/bin/sw_vers` with no arguments. The corresponding pairs on MAC-MROSS-02 are 33/34, 103/104 and 134/135, yielding 1.992828, 1.993175 and 1.994222 seconds. All six fall within 5.3 ms of one another. These are launchd inventory jobs, so common management software or a timed execution policy could explain the clustering; its score contribution is small.
- [weak_signal] One simple native execution is a large runtime outlier: MAC-MROSS-01 ES lines 87–88 show PID 64577 executing `/usr/bin/id` at `16:04:15.614112Z` and exiting successfully at `16:05:40.605500Z`, a lifetime of 84.991388 seconds. Other visible `id` instances on these Macs finish in approximately 0.034–0.451 seconds. This merits examination as possible lifetime sampling divorced from command behavior, but directory-service delay, process suspension or output blocking remains possible. I do not treat it as an impossibility.

## Evidence For Real

- The fleet has differentiated activity and credible noise. Across 23 endpoint directories, eCAR contains 34,454 records, while the three network sensors contain 20,822 connection records. Linux syslog has 3,983 lines; proxy access has 3,046. DCs are visibly busier than most endpoints: DC-01 has 5,559 eCAR records, DC-02 4,789, and MAC-MROSS-01 473. These counts are compatible with a six-hour, selectively collected enterprise window and are not scored negatively for coverage.
- The database staging path is mechanically usable. DB-PROD-01 eCAR lines 518–525 show `mysqldump`, creation of `/tmp/rpt_0318.sql`, dump termination, `gzip`, gzip termination and then `scp`. The next host records the matching SSH tuple and file arrival before later SMB staging.
- Remote-session pivots preserve account boundaries. APP-INT-01's root process invokes SMB with `-U "svc_mhsync"` (eCAR line 844); FILE-LNX-01 records the destination write as `svc_mhsync`, with `auth_protocol=ntlmssp` and `account_scope=directory` (line 1260). Root on the Linux source and the SMB directory identity are correctly distinct.
- Windows collection provides a useful distinction between local identity and explicit network credentials. WS-AJOHNSON-01 eCAR line 1185 has `runas.exe /netonly /user:marcus.chen`, and its subsequent child and collection commands remain attributed locally to `aisha.johnson`. This is consistent with the local-token behavior of `/netonly`.
- The apparent HTTPS upload is represented with an explicit proxy hop. WS-AJOHNSON-01 eCAR lines 1343, 1350 and 1351 connect the curl command, archive read and connection to `10.10.3.20:8080`; `zeek-core/http.json` line 1829 exposes CONNECT, while proxy lines 2790–2791 expose the inspected POST. Seeing the internal URL at the inspecting proxy and CONNECT on the network sensor is coherent.
- Native macOS records distinguish a policy message from successful execution. MAC-MROSS-01 Unified Log line 2 reports that policy would not allow MeetingAssist at `15:42:00.697237+0000`; I found no matching successful MeetingAssist ES execution or attributed effects. This is not evidence of a successful compromise.

## Detailed Analysis

### Scope and hunting conditions

Endpoint records cover approximately `2026-11-02 13:00–19:00 UTC`. The environment has Windows workstations, two domain controllers, Windows file/mail systems, Linux workstations and servers, and two Macs. Addresses support at least the `10.10.1.*`, `10.10.2.*`, `10.10.3.*` and `10.10.4.*` internal groupings. Three Zeek sensor directories, two Snort collections, an ASA log, a web server log and a proxy log provide network perspectives.

The record mix is not dominated solely by suspicious commands. DNS, authentication, SMB, proxy browsing, application traffic, Linux scheduled jobs and administrator activity provide competing hypotheses. For example, APP-INT-01 eCAR line 1 is a sysstat CRON process, and its syslog line 1 independently identifies the CRON command. A scheduled job's regular recurrence is expected and was not scored as synthetic.

Counts above are physical records per supplied source, not deduplicated real-world events; sensors can legitimately observe the same transport. XML line counts were not used as event counts.

### Windows persistence and collection

DC-01 eCAR lines 3533 and 3551 show SYSTEM creating `svc_dirsync` and adding it to Domain Admins. Lines 3637/3644 create DeviceSyncSvc, lines 3667/3672 create the hourly DeviceSync scheduled task, and line 3858 starts `C:\Windows\System32\DeviceSyncSvc.exe` at `17:28:54.695Z`. These are sensible Windows persistence mechanisms. Their presence and their narrative continuity do not determine authenticity.

Later, DC-01 eCAR line 5243 executes encoded PowerShell and line 5253 invokes `wevtutil cl Security`. The Security XML contains a 1102 event as well as account-management, service-install and scheduled-task event families. The raw XML's inclusion of a log-clear record does not imply that centrally collected pre-clear events should disappear.

WS-AJOHNSON-01 eCAR lines 1206–1272 show staging directories, finance and clinical/research file collection and archive creation. The process owner remains aisha.johnson after the `/netonly` launch. At `18:25:23.860Z`, curl PID 6784 starts with an explicit proxy and `archive=@...cache_7f3a.zip` (line 1343). Its file read is at line 1350, its proxy connection at line 1351, and termination at line 1353. Proxy lines 2790–2791 share tunnel ID `PT-3517cb259556c7c2`, client source port 52302, and report 18,783,084 client bytes for the upload. The sensor's CONNECT row is not incorrectly treated as a plaintext POST observation.

### Linux data movement and identity ownership

DB-PROD-01 eCAR line 516 records successful root SSH from `10.10.2.30:35383`, followed by a bash process at line 517. The dump at `18:15:20.149Z` terminates at `18:15:48.941Z` (lines 518/521); gzip starts at `18:15:50.093Z` and terminates at `18:16:06.212Z` (522/524). SCP starts at `18:16:06.945Z` (525), connects from `10.10.4.10:53284` (527), reads the compressed file (531), and terminates at `18:16:23.540Z` (534).

The transport is visible in `zeek-core/conn.json` line 10384: UID `CR3LJyBOmPEm6swCqB`, source port 53284, destination `10.10.2.30:22`, SF state, 12.773637-second duration and 473,686 originator bytes. APP-INT-01 eCAR lines 836 and 838 record inbound transport and root login; line 839 records `/tmp/.cache/rpt_0318.sql.gz` created at `18:16:23.525Z`. The file timestamp is near the transport close and client exit; subsecond offsets among different sources are not themselves contradictory.

At `18:18:43.778Z`, APP-INT-01 runs smbclient under root while supplying `svc_mhsync` credentials (line 844). Its source file read is at line 846. `zeek-core/smb_files.json` lines 212–213 record open/write of `Integration\DB-Staging\rpt_0318.sql.gz` on `\\FILE-LNX-01\ClinicalResearch`; line 213 and `zeek-core/files.json` line 608 agree on 456,267 bytes and FUID `Ft2l8z2xOgq5DhnDkd`. FILE-LNX-01 eCAR line 1260 supplies the host-native destination path and the distinct authenticated identity. I found no account-namespace conflict in this sequence.

### macOS source interpretation

The macOS files are separately shaped native ES notifications, Unified Log messages and normalized eCAR. I did not apply a Windows process-create expectation to the native fork/exec sequence.

For the MAC-MROSS-02 → MAC-MROSS-01 SSH session, the network tuple is `10.10.1.42:49847 → 10.10.1.41:22` (`zeek-core/conn.json` line 6246). MAC-MROSS-01 eCAR line 226 observes inbound transport before login line 232. Native ES lines 71–85 show launchd, xpcproxy, sshd, sshd-session/auth and a user zsh; Unified Log line 3 records public-key acceptance. Native source times precede normalized eCAR process observations, which is compatible with a normalization/collection delay. The native sequence itself has authentication infrastructure preceding shell execution.

The six inventory runtimes and isolated `id` outlier discussed above are the principal authenticity reservations. Neither proves an execution impossibility. Repeated administrative commands on two machines used by the same visible user are insufficient by themselves to label the activity generated.

### Bounded consistency checks

I checked all supplied eCAR records against visible process creation/termination identities: no actor use more than one second after the visible corresponding process termination, and no actor use more than one second before its visible creation, was found. I separately checked native Sysmon ProcessGuid relationships, including visible parent references and process-access/remote-thread source and target references; no greater-than-100-ms visible lifetime violation was found in those checks.

Across the three Zeek connection collections, no TCP five-tuple was reused with more than one second of overlap inside the same sensor file. Basic packet/byte checks found no payload exceeding the 65,535-byte-per-packet upper bound, no IP-byte count below payload bytes, and no populated packet count with less than 20 IP bytes per packet. These bounded checks strengthen internal coherence; they cannot establish provenance or rule out more subtle defects.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS ES | Six launchd inventory executions across two Macs | Small increase: all six `/usr/bin/sw_vers` lifetimes fall in a 5.3-ms range around two seconds; a shared management policy remains an explanation. |
| weak_signal | Native macOS ES | One `id` execution on MAC-MROSS-01 | Small increase: 84.991-second successful lifetime is unlike the other visible `id` runs, but directory stalls/suspension are plausible. |

No hard contradiction was demonstrated. No penalty was applied for attack linearity, successful execution, completeness of pivots, source-selection omissions, sanitized domains or bounded-window lifecycle edges.

## Realism Score by Category

- **Field format accuracy:** 9 — Examined source families are readable and differentiated; no demonstrated native schema defect.
- **Temporal patterns:** 8 — Operational ordering holds in the examined pivots; inventory-runtime clustering and one simple-command outlier warrant inspection.
- **Cross-source correlation:** 9 — SSH/SCP, SMB staging and inspected-proxy upload pivots preserve tuples, paths and account ownership.
- **Behavioral realism:** 8 — Tools and privileges fit the observed actions; the small macOS runtime anomalies are the main reservation.
- **Environmental consistency:** 9 — Host roles, traffic volumes and identity boundaries form a plausible mixed enterprise collection.

## Recommendations

- If this were synthetic, calibrate native command lifetimes using the specific command and execution conditions. In particular, explain or vary the six two-second inventory runs; a shared timeout should have a visible operational reason where the collection supports one.
- If this were synthetic, model unusually slow simple commands as attributable conditions such as directory lookup delay or suspension, rather than applying a generic long process lifetime. The specific case is MAC-MROSS-01 ES PID 64577; do not indiscriminately shorten legitimate long-running processes.
