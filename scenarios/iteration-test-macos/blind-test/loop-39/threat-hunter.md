# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 44

## Executive Summary

The collection supports technically credible hunting across Windows, Linux, macOS, network sensors, SMB and an inspecting proxy. I found recurring execution-duration and background-file-access texture that raises suspicion, but did not establish a hard attack-lifecycle contradiction; the observed remote sessions, credential boundaries and transfer chains generally survive cross-source checking. The score reflects mixed evidence with limited synthetic tells, not certainty about the collection's origin.

## Evidence For Synthetic

- [distribution_texture] All six root inventory executions of `/usr/bin/sw_vers` on the two Macs have native Endpoint Security exec-to-exit intervals between **1.983774 and 1.994358 seconds**. These are `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` lines 30–31, 68–69 and 128–129, and the corresponding MAC-MROSS-02 file lines 33–34, 96–97 and 137–138. Interactive `sw_vers -productVersion` instances in those same files vary from 0.026973 to 0.256842 seconds. A common managed service can explain similar activity, but the narrowly repeated approximately two-second lifetime across six executions is a concrete timing tell. This is not an impossible execution or a claim that every similar automated task is synthetic.
- [distribution_texture] The visible Mac network-share file workflows repeatedly use shell inspection tools for business-document interaction: MAC-MROSS-01 `ecar.json` lines 108/110 uses `tee` to write `team-roadmap.pptx`, 149/153 uses `cat` to read `contacts.xlsx`, and 328/331 uses `tee` to write `team-roadmap.xlsx`; MAC-MROSS-02 lines 608/611 uses `cat` to read `schedule.xlsx`. Across the two Macs, the 11 visible `/Volumes/` file occurrences consist of eight `cat` reads, two `tee` writes and one `ls` read. Network SMB observations confirm these are real modeled file accesses rather than command strings alone. Scripted testing could produce this pattern, so it is a limited behavioral-pool signal, not proof of origin and not a penalty for missing GUI telemetry.
- [weak_signal] Several unrelated Windows users' business-document file operations are attributed to `RuntimeBroker.exe`: WS-AJOHNSON-01 `ecar.json:1217` writes `Documents\\meeting-notes.txt`; WS-DRAMIREZ-01 `ecar.json:653` creates `Documents\\report.docx`; WS-MCHEN-01 `ecar.json:1091` creates `Documents\\Q4-review.pdf`. Brokered application access is possible, and the selected source coverage does not prove the owning app is absent. The repetition nevertheless merits checking whether normalized actor assignment is reflecting actual broker behavior or a generic background-process choice; it contributes little to the score by itself.

## Evidence For Real

- The collection preserves the distinction between local and outbound identity for Windows new-credentials use. WS-AJOHNSON-01 Security XML line 23269 records 4648 with subject `aisha.johnson`, target `marcus.chen` and caller `runas.exe`; line 23311 records Type 9 with local target `aisha.johnson`, new LUID `0x27c9452` and `TargetOutboundUserName=marcus.chen`. FILE-SRV-01 Security XML lines 49131 and 49211 then show `marcus.chen` accessing Finance from the actual client `10.10.1.35:65423`. This is a meaningful privilege/account boundary rather than superficially matching usernames everywhere.
- The SSH/SCP staging chain has plausible authentication and transport order. DB-PROD-01 `ecar.json` lines 491–495 show the SSH daemon, inbound `10.10.2.30:46416` flow, successful root login and shell before `mysqldump`; native syslog lines 162–165 independently record connection, accepted password, PAM session and logind session. The subsequent SCP to APP-INT-01 has matching tuple `10.10.4.10:53008 -> 10.10.2.30:22` in both endpoints and `zeek-db/conn.json:384`.
- All **12** visible native Windows Security 4624 Type 10 logons map, after normalizing IPv4-mapped IPv6 addresses, to matching TCP/3389 Zeek connections with `conn_state=SF` and substantive traffic. Examples include `zeek-core/conn.json:6671` for `10.10.1.99 -> 10.10.1.35`, and lines 6115/10759 for Marcus's sessions to DC-01. None required treating a reset or tiny failed flow as successful RDP.
- The proxy distinguishes cleartext forwarding and inspected TLS. The diagnostic upload in `proxy_access.log:1992` is a cleartext POST with `proxy_action=forward`; `zeek-core/http.json:1264` and `zeek-dmz/http.json:1396–1397` preserve the client-facing absolute URI and upstream origin-form URI with the same 1,573,258-byte request body. The later ZIP upload is explicitly `ssl-inspect`/`ssl_bump=bump` in proxy line 3388, making its visible HTTPS POST compatible with inspection.
- macOS evidence does not equate a policy message with successful execution. MAC-MROSS-01 Unified Log line 2 describes a policy objection to `MeetingAssist`; I found no corresponding successful exec/child effects to support a claim that this binary ran. Endpoint Security separately preserves setuid login semantics: MAC-MROSS-01 ES line 5 transitions `login` from source EUID 501 to target EUID 0 with executable mode `0104555`.

## Detailed Analysis

### Scope and method

The supplied directory contains 23 endpoint host directories: ten with Windows Security/Sysmon XML, eleven with Linux syslog, and two Macs with native Endpoint Security plus Unified Log exports. All 23 also have normalized eCAR records. Other sources include three Zeek sensor views (`core`, `dmz`, `db`), perimeter firewall, two IDS views, proxy, web access and shell histories. Endpoint observations cover approximately **2026-11-02 13:00–19:00 UTC** and support workstation, directory, mail, web/application, file, monitoring, proxy and database roles on the 10.10.1/2/3/4 segments.

I parsed all 35,813 eCAR records, all Windows Security/Sysmon documents for event inventories and selected identity relationships, and the 22,030 Zeek connection rows. The Windows XML contains 18,978 Security events; XML line counts are not record counts. The network and endpoint families overlap and should not be summed as independent activities. Selected native Windows audits, Linux syslog, Mac ES records, SMB file observations, HTTP and proxy lines were then cross-referenced around the suspicious and administrative activity.

As an automated consistency check, I indexed visible eCAR process creations/terminations by process object identity, checked parent/actor PID and image agreement against visible process state, and looked for dependent events more than two seconds after a visible termination or before a visible creation. I found no such process-identity ordering violation, no overlapping visible different process objects using one PID, and no actor image/PID mismatch in that check. This is evidence against broad lifecycle corruption; it is not an assertion that every unseen initiating event must exist inside this bounded window.

### Hunting the Linux staging path

WEB-EXT-01 `ecar.json:811` at 14:20:06.215 contains a `www-data` bash command with an encoded reverse-shell payload. Later root sessions and discovery activity merit investigation, but I did not assume that a visible reverse-shell command alone proves all subsequent privileged activity came from that process.

The database path is more directly traceable. APP-INT-01 `ecar.json:747` launches `ssh root@DB-PROD-01.meridianhcs.local`; its outbound flow at line 750 and DB's inbound flow at line 492 share port 46416. DB's successful root login at line 493 precedes shell line 494 and the dump command at line 495. `zeek-db/conn.json:380` is the successful transport for this tuple with approximately 1,195.9 seconds of duration, so authentication and commands fit the connection interval.

DB lines 499–507 show compression, the archive creation/read, SCP and SCP termination. APP's inbound tuple at line 753 precedes accepted authentication in native syslog line 220, session opening at line 221, normalized login at line 756 and destination archive creation at line 761. APP syslog closes the session at 18:16:21.072588; eCAR termination appears at 18:16:22.122 and normalized logout at 18:16:30.887. These source offsets are not a visible same-source impossibility. I did not flag the receiver daemon's file attribution as automatically invalid: internal subsystems or normalization can produce daemon-owned file activity.

APP later runs `smbclient` at `ecar.json:774`, reads the received archive at line 776 and connects to FILE-LNX-01 on port 445 at line 775. `zeek-core/smb_files.json:187–188` shows `Integration\\DB-Staging\\rpt_0318.sql.gz` opening and writing on that matching tuple; `zeek-core/files.json:613` records the corresponding 10,464-byte transfer and FUID. These are usable pivots, with correctly separated SSH and SMB transport identities.

### Windows credential use, collection and exfiltration

The local Type 9/outbound-credential distinction described above remains consistent during the Finance/Clinical/Research collection. WS-AJOHNSON-01 `ecar.json:1062` shows a recursive Finance copy and subsequent destination files at lines 1073–1076; FILE-SRV-01 native 5145/4663 records at XML lines 49468–50246 expose the Finance files under the outbound `marcus.chen` identity and LUID `0xf885880`. Subsequent collection is followed by a `Compress-Archive` process at eCAR line 1110.

At 18:24:54.488, eCAR line 1199 launches the ZIP upload with an explicit proxy; line 1206 reads `cache_7f3a.zip`, and line 1208 attaches the process to client port 62702 on the proxy. Proxy line 3388 reports the same client port, URI, authenticated user and inspected TLS transaction, with `cs_bytes=18783090`. A processless additional proxy flow at eCAR line 1207 has a different client port; I did not label this duplicate evidence without a shared tuple or transaction identity.

DC-01's service/account operations are technically recognizable: Security XML line 182203 records `PSEXESVC` installation under the remote user, line 192319 creates `svc_dirsync`, and line 192703 adds its matching SID to the domain's `-512` group. Commands, privileged audit subjects and service-local SYSTEM execution are mutually plausible. Their completeness or narrative order is not scored as an authenticity tell.

### Mac behavioral texture versus technical correctness

Mac terminal, xpcproxy, fork/exec, credential changes and SSH lifecycle are substantially more detailed than a flat process list. In particular, setuid login state in native ES avoids the common mistake of treating every process in a user's terminal ancestry as continuously unprivileged. The native policy observation is also kept separate from an allowed execution.

The concern is narrower: business-document accesses repeatedly look like terminal-generated examples, and inventory process lifetimes converge to approximately two seconds across both hosts. For the six inventory `sw_vers` exec-to-exit intervals, the measured values are 1.993394, 1.991463, 1.983774, 1.992969, 1.994358 and 1.994176 seconds. The collection supports a common managed fleet, which weakens this as a standalone fingerprint; it does not erase the observed tight runtime distribution. The shell-document pattern likewise remains possible for testing or troubleshooting. Neither warrants an impossible-behavior finding.

### Signal, noise and limits

There is background DNS, DHCP, scheduled/service activity, administration, software traffic and failed authentication alongside the suspicious commands. The attacks are findable, but findability, compactness, absence of retries and detailed correlation do not establish synthetic generation. I found no defensible source-volume contradiction from the bounded window or selected audit scope. Several late SSH sessions have no completed Zeek row in the files; a connection logging on close outside the window or sensor coverage can explain this, so these are not scored as missing-companion defects.

The resulting judgment remains inconclusive: the timing/behavioral texture keeps the score above the mostly-realistic band, while the absence of established hard contradictions and the successful operational pivots keep it well below likely-synthetic confidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security | Six inventory `sw_vers` executions across two hosts | Strongest limited tell: 1.984–1.994 s runtimes, contrasted with variable interactive executions; common policy remains an alternative explanation. |
| distribution_texture | Normalized Mac endpoint + Zeek SMB | Eleven visible mounted-share file occurrences across two hosts | Repeated `cat`/`tee` business-document workflows suggest a small behavioral pool; not impossible and not a missing-GUI-source claim. |
| weak_signal | Normalized Windows endpoint | Three users/hosts with RuntimeBroker business-document operations | Actor ownership deserves validation; brokered access is plausible, so little independent scoring weight. |

No `hard_contradiction` or demonstrated `contract_gap` is asserted.

## Realism Score by Category

- **Field format accuracy:** 9 — Native and normalized fields support reliable parsing, tuple matching and account/privilege interpretation; no demonstrated native-schema error.
- **Temporal patterns:** 8 — Remote sessions and transfers are coherent; Mac inventory lifetimes show suspiciously narrow repetition.
- **Cross-source correlation:** 9 — RDP, SSH/SCP, SMB and proxy paths are practically usable and generally preserve identity and order.
- **Behavioral realism:** 7 — Threat tradecraft is technically plausible; repeated terminal-based Office-document activity and broker ownership reduce baseline naturalness.
- **Environmental consistency:** 8 — The mixed fleet and network roles fit the observations; the limited ownership concerns remain explainable.

## Recommendations

- If this were synthetic, derive inventory executable runtimes from representative measurements and workload variation rather than repeatedly retaining approximately two seconds of `sw_vers` lifetime. Preserve its actual fork/exec/exit relationships.
- If this were synthetic, give mounted-share file interactions a broader, role-appropriate operation mix tied to the actual invoking process. Retain shell `cat`/`tee` operations where there is a concrete scripted purpose, and preserve the current file/SMB name and tuple coherence.
- If this were synthetic, verify the three RuntimeBroker document operations against the intended broker/application behavior before using that process as the recorded file actor. Correct ownership only where the underlying operation supports it; the logs alone do not prove these instances impossible.
