# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 43

## Executive Summary

The sampled operational trails work technically: endpoint processes, SSH authentication, network tuples, transferred artifacts, and Windows persistence evidence permit useful pivots without a demonstrated impossible lifecycle. A narrow file-access vocabulary on the two Macs and questionable creation attribution for a redirected database export suggest constructed telemetry, but the evidence does not justify a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] All ten `/Volumes/` FILE operations in the two Mac `ecar.json` files use only `/bin/cat` for reads (8) and `/usr/bin/tee` for writes (2). This includes binary office documents: `MAC-MROSS-01.meridianhcs.local/ecar.json:80` writes `team-roadmap.pptx` using tee; line 122 reads `contacts.xlsx` using cat; `MAC-MROSS-02.meridianhcs.local/ecar.json:458` reads `schedule.xlsx` using cat. This concentrated choice of file utilities across two workstations is a modest behavioral texture concern, not proof that any single command is impossible.
- [contract_gap] `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:2` contains `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`. The corresponding eCAR process starts at 18:15:11.587 (`ecar.json:591`), while FILE/CREATE for that path at 18:15:13.012 is attributed to the mysqldump PID 1088989 (`ecar.json:592`). Shell redirection ordinarily opens/creates the output before executing the child. If FILE/CREATE denotes the actual filesystem creation, its actor/timing is wrong; if the normalization labels an output writer's first observation as creation, the discrepancy is explainable. I therefore assign this limited weight.

## Evidence For Real

- The web-host shell activity has a viable transport interval. `WEB-EXT-01.meridianhcs.local/ecar.json:923` creates a base64-decoding bash command at 14:19:57.838; its decoded command targets TCP/8443 at 45.33.32.30. `zeek-dmz/conn.json:1498` observes 10.10.3.10:37640 to that destination at 14:20:01.694975 for 14.957469 seconds, ending before the shell termination at 14:20:20.651 (`ecar.json:928`).
- The database export/compression/copy sequence has distinct processes and consistent artifact reuse. `DB-PROD-01.meridianhcs.local/ecar.json:596` creates `/tmp/rpt_0318.sql.gz`; line 603 reads that same artifact object ID for scp. Its receiver appears on APP-INT-01, and a later SMB upload of `Integration/DB-Staging/rpt_0318.sql.gz` is observable in `zeek-core/smb_files.json:165` with size 348477.
- A Mac SSH pivot respects transport-before-authentication. `zeek-core/conn.json:6281` opens 10.10.1.42:52550 → 10.10.1.41:22 at 16:02:16.571971. `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:3` records public-key acceptance at 16:02:23.591596; the normalized LOGIN at 16:02:25.401 preserves that tuple (`ecar.json:273`).
- Native Mac records distinguish fork and exec rather than pretending every executable image has a new PID. For example, `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1-3` follows PID 42169 through launchd → xpcproxy → Terminal, with changing pidversion and user/audit context. That is useful process identity modeling.
- Shared-file state persists across separate clients. `zeek-core/files.json:457` records a 1396-byte `Desktop/schedule.xlsx` write from 10.10.1.34; line 514 records a subsequent read by 10.10.1.42 with the same size and SHA256 `dda0545a7ff0c421dd86c5c262fc84a0616bf0721a39a17850f0929bd09a28d0`. This supports a coherent shared artifact, without treating completeness itself as authenticity evidence.

## Detailed Analysis

### Scope and bounded method

I inventoried only the supplied data directory. It contains 23 host eCAR files covering approximately 2026-11-02 13:00–19:00 UTC, Windows Security/Sysmon XML, Linux syslog and histories, two Mac Endpoint Security exports and Unified Log exports, three Zeek sensor directories, proxy/firewall records, web access, and Snort alerts. Across the directory there are 35313 eCAR rows and 21463 Zeek connection rows; these are observations, not counts of unique activities, because multiple sensors can see one connection.

I used a bounded representative investigation: web-host shell activity; application-to-database SSH and return scp; Mac-to-Mac SSH; Windows service/task creation; and Mac mounted-share file activity. I also checked the eCAR inventory for actor references more than two seconds before a visible matching process CREATE or after a visible matching TERMINATE. That check found no candidates. It does not prove native clocks, every context, every parent, or every process history are correct; pre-window processes and post-window survivors were neutral.

### Linux operational chain

APP-INT-01 PID 2983764 invokes `ssh root@DB-PROD-01.meridianhcs.local` at 18:14:35.165 (`ecar.json:665`). Zeek sees the connection at 18:14:52.064499, source port 41321 (`zeek-core/conn.json:10506`), followed by DB-PROD-01 sshd connection and password acceptance at 18:14:56.031847 and 18:15:03.248930 (`syslog.log:194-195`). A root shell and the database-export command follow (`ecar.json:590-591`). Root SSH password authentication is risky but possible and is not itself an authenticity defect.

The compressed file then moves in the opposite direction. DB-PROD-01's scp starts at 18:15:50.474 (`ecar.json:601`). Zeek opens 10.10.4.10:45342 → 10.10.2.30:22 at 18:15:53.101079 for 21.647156 seconds (`zeek-core/conn.json:10571`). APP-INT-01 accepts root public-key authentication at 18:15:59.228037 (`syslog.log:214`), observes the receiver artifact at 18:16:15.385 (`ecar.json:679`), and closes its PAM session at 18:16:16.700089 (`syslog.log:217`). The approximately subsecond-to-two-second differences between final network/endpoint/session observations do not establish impossible ordering across collectors.

The concern is specifically the output-file CREATE attribution before that transfer, not the feasibility of the transfer or the presence of a complete attack narrative. The shell history clarifies why mysqldump's process argv correctly omits `>`; that omission is not a bad command line. The issue is whether a normalized CREATE may legitimately use the writer's identity and later observation time.

### Mac activity and file-access texture

The Mac SSH interval closes at approximately 16:17:59.588 on the network sensor, with endpoint logout recorded later at 16:18:16.932 (`MAC-MROSS-01.../ecar.json:344`). Source collection and teardown semantics can explain a later normalized logout; I did not classify that difference as a hard contradiction.

The two Macs show a mix of Terminal/iTerm, browser helpers, Word, Outlook, Zoom, administrative queries, SSH, and an endpoint-inventory job. Their mounted-share accesses are much narrower: the entire observed set is eight cat reads and two tee writes. In particular, network evidence identifies the tee target as a 3773154-byte PPTX, not merely a misleading extension (`zeek-core/files.json:105`; `smb_files.json:25`). A utility can copy binary data, and a script can feed tee on stdin, so this is feasible. The concern is the repeated exclusive utility choice for all observed share operations, including office documents, despite the visible GUI application mix. The sample is small and collection may be selective; this remains a moderate distribution signal.

I did not equate the Unified Log security-policy message concerning MeetingAssist with a completed execution or child effects. Likewise, a launch-daemon plist file is not by itself proof of registration or activation.

### Windows pivot feasibility

DC-01's native Sysmon rows show WmiPrvSE spawning cmd/sc.exe and cmd/schtasks.exe around 17:20:22–23, with parent process GUIDs linking each child to its shell. Native Security Event 4697 follows at 17:20:26.1955967 for `DeviceSyncSvc`, and Event 4698 at 17:20:27.5042004 contains a task XML action targeting `C:\Windows\System32\DeviceSyncSvc.exe`, repetition `PT1H`, and SYSTEM principal. These are technically compatible persistence artifacts; creating a service and creating a task are separate observable actions. I found no concrete source-native contradiction in this sample.

### Signal and uncertainty

The visible web host has recurring blocked probes alongside application errors; the Windows sources include logon failures, ordinary processes, and filtering-platform connection records. This is enough background variation to support actual pivots. I did not infer authenticity from dataset-wide total volume alone, require additional products, penalize missing Sysmon types, or score attack linearity, completeness, or absence of operator mistakes.

The 43 score reflects mixed evidence with identifiable but limited concerns. No demonstrated hard contradiction or identity leak supports an 81–100 score, and the two concerns above are insufficient for a confident likely-synthetic verdict.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac eCAR with SMB/file corroboration | All ten observed mounted-share FILE operations on two Macs | Modest increase: exclusive cat/tee usage extends to binary office documents; individually feasible and possibly collection-selected. |
| contract_gap | Linux history and normalized eCAR | One redirected mysqldump output | Limited increase: FILE/CREATE actor/time disagrees with normal shell-open semantics, conditional on the normalizer's CREATE definition. |

## Realism Score by Category

- **Field format accuracy:** 8 — Parsed representative JSON/XML records and usable identifiers; native Mac version-specific details were not independently certified.
- **Temporal patterns:** 8 — Sampled transports precede authentication and effects; no clear impossible same-identity lifecycle found.
- **Cross-source correlation:** 8 — Linux, Mac SSH, Windows persistence, and shared-file pivots work; redirected-file creation attribution remains uncertain.
- **Behavioral realism:** 6 — Diverse process families coexist with a conspicuously narrow mounted-share utility pattern on both Macs.
- **Environmental consistency:** 8 — Distinct server/workstation roles, remote paths, authentication methods, and sensor vantage points are plausible in the sampled chains.

## Recommendations

- If this were synthetic, attribute redirected output creation to the shell's open operation before child execution, then represent child writes separately. If the source intentionally attributes the writer, document or encode that distinction rather than calling it an actual CREATE.
- If this were synthetic, diversify observed mounted-share activity around the applications and workflows visible on the Macs. Retain cat/tee where there is a concrete script or binary-copy reason; avoid making them the exclusive mechanism for XLSX/PPTX/PDF access.
- Preserve the existing tuple, artifact, process-image-transition, and native persistence relationships. Improvements should not add retries, dead ends, source families, or volume merely to make the incident harder to narrate.
