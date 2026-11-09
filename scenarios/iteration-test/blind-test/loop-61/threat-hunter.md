# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 68

## Executive Summary

The strongest synthetic evidence is repeated web-content texture across otherwise unrelated destinations: every successful full favicon response has exactly the same body length, and generic logos repeat the same path and length across many sites. Operational pivots through Linux SSH, database extraction, SMB staging, Windows collection, and proxy upload are substantially coherent; I found no demonstrated impossible same-process ordering in the checks performed. The verdict rests on measured baseline distributions, with weaker client-identity and command-vocabulary concerns, rather than the suspicious activity's completeness or narratability.

## Evidence For Synthetic

- [distribution_texture] In `PROXY-01.meridianhcs.local/proxy_access.log`, 267 GET requests to absolute-URL `/favicon.ico` span 52 destination hosts. All 203 status-200 responses have body length **890**, spanning 51 hosts; the remainder are 46 status-304 responses and 18 status-206 responses. Examples are lines 38 (`styles.pollfish.com`, 13:09:18), 62 (`auth.services.adobe.com`, 13:10:00), 127 (`stackoverflow.com`, 13:20:43), 158 (`en.wikipedia.org`, 13:24:42), and 179 (`wd5.myworkday.com`, 13:25:32). The problem is the identical payload-size distribution across destinations, not their names or actual Internet resolution.
- [distribution_texture] The same proxy file contains 23 successful GET responses of **13,861 bytes** for `/assets/img/logo.svg`, across 14 hosts. Lines 82, 241, 640, and 855 show that exact path and size at `styles.pollfish.com`, `mx.office365.com`, `github-releases.githubusercontent.com`, and `images.wellbridge.com`, respectively. A second reused asset, `/assets/fonts/inter-var.woff2`, has 16 successful responses of **99,900 bytes** across 12 hosts. Shared fonts alone are plausible; the joint recurrence of generic logo paths, logo sizes, favicon sizes, and generic resource trees is stronger evidence of a reused web template. These findings are related and are not counted as independent hard contradictions.
- [weak_signal] The proxy associates 483 of 569 rows for source `10.10.1.41` with an iPhone iOS 17.2 mobile User-Agent. That IP is MAC-MROSS-01 in endpoint FLOW records, and the supplied native endpoint records visibly launch desktop Chrome, including its renderer, GPU, and network-service helpers at 13:14:20–13:14:24 (`MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 18–25). For example, proxy line 179 still uses the mobile identity at 13:25:32. User-Agent override, a separate client, or forwarding can explain this; it is a modest environment-model concern, not an impossible platform value or proof that Chrome produced those particular requests.
- [distribution_texture] Of 49 visible `smbclient` PROCESS/CREATE command lines across eCAR files, 29 directly fetch from SYSVOL or NETLOGON. Three users share the same command grammar and interchangeable policy vocabulary (`startup`, `groups`, `registry`, `drives`; `-approved`, `-draft`, `-final`; several extensions and year subdirectories). Examples: `APP-INT-01.meridianhcs.local/ecar.json` lines 252 and 263, and `WS-OHADDAD-01.meridianhcs.local/ecar.json` lines 21, 33, 140, 153, 169, 181, 243, and 247. Central automation could explain repetition, so I give this less weight than the measured web-asset distribution. The concern is recurring vocabulary and source-family composition, not merely normal access to directory-policy shares.

## Evidence For Real

- Linux root database activity has a viable privilege and session context: `DB-PROD-01.meridianhcs.local/syslog.log` lines 190–191 record password acceptance from `10.10.2.30:44872` and PAM root-session opening at 18:15:22.848/22.978. The root shell and `mysqldump` process follow at 18:15:25.147 and 18:15:29.410 in eCAR lines 454–455.
- The database archive transfer preserves network and receiver identities. `DB-PROD-01.../ecar.json` lines 461–463 identify `scp`, source `10.10.4.10:54707`, and destination `10.10.2.30:22`; `zeek-db/conn.json` line 344 records that tuple as a successful SSH connection. `APP-INT-01.../syslog.log` lines 215–216 record matching public-key acceptance and PAM opening, and eCAR line 762 records the destination archive.
- The subsequent SMB staging is independently huntable: `APP-INT-01.../ecar.json` lines 769–771 show the root-owned `smbclient` process, a source-file read, and the `10.10.2.30:45726 → 10.10.2.21:445` flow. `FILE-LNX-01.../syslog.log` lines 470–474 show NTLMSSP authentication as `svc_mhsync`, service connection, and successful open/write/close of the expected path. `zeek-core/smb_files.json` lines 223–224 carry the same share, filename, tuple, and a 951,368-byte write.
- Proxy evidence distinguishes a legitimate support upload from a different archive upload. `WS-LNGUYEN-01.../ecar.json` lines 314–321 show tar creation and curl multipart upload for ticket MHS-48217; proxy line 2153 and Zeek HTTP rows record that support URL. `WS-AJOHNSON-01.../ecar.json` lines 1156/1163 and 1235/1242 instead link a staged archive to curl and an upload at proxy line 3263.
- Collection imperfections have actual supporting fields. For the support POST, core HTTP line 1330 has response body length 95 while DMZ HTTP line 1510 has 96. The matching core connection (`zeek-core/conn.json` line 7601) explicitly records `missed_bytes=3` and gap marker `g`; the DMZ connection (`zeek-dmz/conn.json` line 6423) has no missed bytes. I therefore do not label that difference contradictory.
- Exact-identity lifecycle checks found no actor event before its visible eCAR PROCESS/CREATE, no actor event after its visible PROCESS/TERMINATE, and no overlap between the fully bounded visible process lifetimes sharing a PID. Windows 4624/4634 checks found no matched LogonID with visible logoff earlier than visible logon. These bounded checks support operational coherence without assuming absent pre-window starts or post-window ends are defects.

## Detailed Analysis

### Scope, provenance, and method

Inputs were the supplied neutral `threat-prompt.md` briefing and files under `/private/tmp/log-study-rfg61n4z/data` only. I did not read project files, scenarios, TODO/worklogs, prior assessments, or other reviewers' output, and did not browse the web. Generic inherited operating instructions were treated as an environment limitation and supplied no authenticity evidence. Parsing used system `python3` with `/private/tmp` as the explicit working directory; no project tools or generator were invoked.

There are 23 endpoint directories containing eCAR, with Windows Security/Sysmon XML on 10 hosts, Linux-style syslog and bash histories on relevant hosts, and native Endpoint Security/Unified Log plus zsh histories on two Mac hosts. Network sources include core, DMZ, and database Zeek sensors, a perimeter ASA, core/perimeter Snort alerts, proxy access, and web access. The records cover approximately 2026-11-02 13:00–19:00 UTC. Visible internal addresses occupy client `10.10.1.x`, server `10.10.2.x`, DMZ/proxy `10.10.3.x`, and database `10.10.4.x` space; I do not infer exact subnet masks from those addresses alone.

Core, DMZ, and database `conn.json` contain 12,162, 9,382, and 392 records respectively; the ASA contains 22,517 lines and the proxy 3,462. Endpoint eCAR volume ranges from 253 rows on LT-MRIVERA-02 to 5,730 on DC-01. DC-01 and DC-02 have 1,005/995 TGS records and 402/391 TGT records, while broad Windows filtering-platform events contribute substantial background volume. This is a usable haystack, not simply a handful of attack records. I do not penalize source absence or selected Sysmon coverage.

### Operational hunt and pivot feasibility

A root session on WEB-EXT-01 is followed by interface, host, resolver and credential-file inspection and network discovery; APP-INT-01 later shows a root session and account-file reads. Those commands are suspicious but not themselves authenticity indicators. The most clearly attributable later transfer is the DB-PROD-01 → APP-INT-01 → FILE-LNX-01 archive path described above. It preserves local root execution separately from the `svc_mhsync` network credential, which is a meaningful boundary rather than a username mismatch.

For the database SCP tuple, the database sensor starts its observation at epoch `1793643366.350357`, duration `30.211086`, with `978623` origin bytes and `27830` response bytes. The core observer sees the same tuple and byte counts with its own UID and slightly different timestamp/duration (`zeek-core/conn.json`, line 10918). APP-INT-01 accepts the SSH key at 18:16:11.955723 and reports destination-file creation at 18:16:37.204. The receiver timestamp is slightly after the network close, which is compatible with endpoint collection delay or close/finalization observation; it is not an impossible causal inversion established by these records.

The Windows branch has explicit credential use (`runas /netonly`), a separate local process principal, SMB collection commands, archive creation, and a later proxy upload. The curl command's requested proxy, source host IP `10.10.1.35`, and source port `55554` agree with endpoint FLOW and proxy tunnel metadata. I do not infer success merely from a shell command when file or network evidence is absent; the cited archive and transfer pivots have those additional observations.

For the Mac hosts, I distinguished native ES notifications, Unified Log, normalized eCAR, shell history, and sensor traffic. ES sequences include fork/exec transitions through xpcproxy, terminal login/shell launch, and SSH service components. The `MeetingAssist` security-policy message in MAC-MROSS-01 Unified Log line 2 is not proof of successful execution. I found no basis in the examined records to claim that a denied action produced a child process or successful effect.

### Why web texture changes the verdict

Fixed content size for repeated retrieval of the same file is normal. The observed anomaly is that different destination hosts and client identities repeatedly converge on exactly the same favicon and generic-logo content lengths. The favicon result is exhaustive for the stated proxy filter, not an anecdotal pair: 203 out of 203 successful full responses are 890 bytes, across 51 hosts. The generic SVG result reinforces that with a second asset class and exact shared path. Common libraries can explain font reuse, and a rewriting proxy or specially normalized dataset could explain more, but the visible proxy annotations describe forwarding, tunneling, or SSL inspection rather than replacement of every site's icon/logo content.

That is strong distribution evidence, but no generator name, impossible field, or unambiguous causality contradiction was found. I therefore remain below the 81–100 rubric band. The weaker SMB vocabulary and mobile User-Agent observations support investigation and incremental score impact; they do not independently establish fabrication.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Proxy web responses | 203 full favicon responses / 51 hosts, all 890 bytes | Largest contribution: cross-destination payload-size collapse |
| distribution_texture | Proxy web resources | 23 generic SVG logos / 14 hosts, all 13,861 bytes; font reuse corroborates | Reinforces the same web-template finding; not double-counted as an independent contradiction |
| distribution_texture | Linux normalized process / SMB behavior | 29 of 49 smbclient creations target policy shares, recurring grammar across three users | Moderate concern about reusable vocabulary; automation remains a plausible alternative |
| weak_signal | Mac endpoint plus proxy identity | 483/569 proxy rows for 10.10.1.41 use mobile iPhone identity | Small contribution only; client spoofing/forwarding is possible |

## Realism Score by Category

- **Field format accuracy:** 9 — Supplied XML, JSON/NDJSON, syslog, histories, and proxy records are broadly usable; no demonstrated native-format contradiction found in this review.
- **Temporal patterns:** 9 — Bounded exact-identity lifecycle checks passed, and inspected session/transfer timing is viable.
- **Cross-source correlation:** 9 — Process, tuple, account, path, SMB, SSH, and proxy pivots work with plausible observation differences.
- **Behavioral realism:** 6 — Activity is technically plausible, but recurring policy-fetch grammar and highly reused web resources reduce organic texture.
- **Environmental consistency:** 7 — Host roles and privilege boundaries generally fit; dominant mobile browser identity on a Mac IP remains a qualified concern.

## Recommendations

- If this were synthetic, vary favicon and site-owned logo content identities and sizes by destination. Preserve sizes for repeated retrieval of the same resource, but avoid assigning all unrelated successful icon responses 890 bytes and all generic logos the same SVG size.
- If this were synthetic, tie generic resource paths to actual site/application families. Keep realistic shared font/library reuse, while giving unrelated services their own resource trees and payload characteristics.
- If this were synthetic, diversify or explicitly contextualize the repeated policy-share `smbclient` activity: the observed three-user grammar and interchangeable policy filenames should reflect actual scripts, tasks, or workflows rather than a broad vocabulary pool.
- If this were synthetic, align browser identity with the owning client or make the observed override/forwarding behavior coherent across endpoint and proxy evidence. Do not remove legitimate mobile User-Agents merely because a Mac is present.
