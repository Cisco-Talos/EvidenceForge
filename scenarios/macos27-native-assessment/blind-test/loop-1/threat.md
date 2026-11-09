# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 64

## Executive Summary

The dataset supports practical hunting across a small mixed fleet, and its SSH, process identity, and file-transfer pivots are substantially coherent. I lean synthetic because several independent application behaviors have an artificial texture: overlapping Chrome browser roots for the same user without visible profile separation, unusually long execution of simple macOS queries, and browser HTTP traffic attributed repeatedly to a Windows service host. These are plausibility and distribution findings, not a demonstrated impossible lifecycle; collection selection and unobserved configuration limit certainty.

## Evidence For Synthetic

- [environment_or_collection_plausibility] **Parallel Chrome roots lack visible instance separation.** In `NS-MAC-02.northstar.example/ecar.json`, line 81 starts PID 24495 at 13:27:28.449 UTC with `Google Chrome --new-window https://wiki.northstar.example/display/ENG/Architecture`; it remains visibly alive until line 458 at 15:15:03.992. The same executable and `owen.patel` account start PID 34165 at 14:00:23.915 (line 113) and PID 34564 at 14:04:01.807 (line 127), again using `--new-window`, without `--user-data-dir` or other visible separation. Each later root creates its own renderer child (lines 115 and 129), so these are more than short-lived command-forwarding launches. This is inconsistent with ordinary shared-profile Chrome behavior, though unseen custom configuration prevents calling it an unconditional contradiction.
- [distribution_texture] **Simple macOS commands repeatedly occupy seconds to tens of seconds.** `NS-MAC-01.northstar.example/ecar.json` lines 9–10 show `/usr/bin/id`, PID 6437, alive from 13:12:59.110 to 13:13:19.225: 20.115 seconds. On MAC-02, `node --version` lasts 36.433 seconds (lines 12 and 17), and two `gcc-16 --version` invocations last 12.980 and 15.789 seconds (lines 123/125 and 203/207). Native Endpoint Security independently shows `/usr/bin/id` executing at 15:15:41.080215 and exiting at 15:16:00.011283, 18.931 seconds later (`macos_endpoint_security.ndjson`, lines 7–8, PID 49369, pidversion 64). Scheduler pressure, startup checks, or output blocking can explain an individual long run; the repeated pattern across trivial queries and two hosts is the concern.
- [environment_or_collection_plausibility] **Four browser-shaped HTTP requests share an unlikely service owner.** `office-span/http.json` lines 1, 2, 3 and 22 have a Windows Chrome/119 user agent and ordinary page URLs, including `news.ycombinator.com/`, `dash.cloudflare.com/e61417f4/dns`, and `dbeaver.io/product/dbeaver-ultimate/`. Exact network tuples join to `NS-WIN-01.northstar.example/ecar.json` lines 30, 47, 53 and 934: PID 5620, `NETWORK SERVICE`, `C:\Windows\System32\svchost.exe`, command `svchost.exe -k netsvcs`. For example, the Cloudflare tuple is `10.42.0.21:60564 -> 104.18.33.7:80` at 13:09:35.780417 UTC. A service can set a browser user agent, but this repeated assignment across unrelated browsing destinations looks like a generic owner fallback. This finding is weaker than an impossible process identity and is scored accordingly.
- [distribution_texture] **One user's varied SMB work follows a narrow cadence.** MAC-02 makes 17 distinct TCP/445 connections to BUILD-01 over 13:03:28–18:39:24 (`office-span/conn.json`, lines 2, 78, 174, 223, 483, 596, 776, 850, 949, 993, 1019, 1141, 1242, 1366, 1484, 1537, 1673). The 16 intervals have mean 1,259.78 seconds, sample standard deviation 46.79 seconds, and range 1,154.06–1,331.18 seconds. They open assorted PDF, DOCX and XLSX files and alternate reads/writes (`smb_files.json`, e.g. lines 6–7, 19–20, 23–24, 53–54). Automation could produce this cadence; its association with varied user document work is a modest supporting signal, not proof.

## Evidence For Real

- **SSH has a usable transport-to-endpoint trail.** The Windows client PID 7624 starts at 15:07:18.391, connects from source port 51078, and survives through transport closure. Zeek UID `CW8qrKFikdyMQqDUFs4` joins the same Windows-to-Mac tuple, target inbound FLOW, successful target SSH session, and a differentiated sshd/fork/exec tree. Exact evidence and timings are developed below.
- **Visible process lifecycles pass substantive identity checks.** Across eCAR, 289 process identities have both create and terminate observations: 148 BUILD-01, 95 WIN-01, 38 MAC-02, and 8 MAC-01. None terminates before creation. Checks of visible parent creation/exit relationships and explicitly identified process actors found no later activity after that actor's recorded exit. Sysmon ProcessGuid references also keep a consistent PID/image pair.
- **Network companions retain source-native integrity.** Every supplied DNS, SSL, HTTP, SMB file and SMB mapping row has a matching Zeek connection UID. No companion timestamp falls more than one second outside its matching visible connection interval. Repeated X.509 fingerprints retain consistent certificate attributes. This is useful coherence, and completeness itself is not treated as a synthetic tell.
- **Background evidence has meaningful variety.** BUILD-01 syslog includes SMB, SSH, sudo, cron, snapd, irqbalance, resolver, D-Bus, anacron, journald and package-maintenance messages. The network data include DNS failures, reset/incomplete connections, OCSP, NTP and SMB; all traffic is not uniformly successful.
- **Distinct local and directory identity scopes are preserved.** MAC-02 SSH audit identity is UID 501/GID 20, while BUILD-01's directory-backed Owen identity uses UID/GID 6237. Those differences are plausible and should not be mistaken for a cross-platform account contradiction.

## Detailed Analysis

### Scope and hunting surface

The records cover approximately 2026-10-20 13:00–19:00 UTC. There are four endpoint directories: two Macs, a Windows workstation, and a Linux build/file server. Endpoint/network joins support these mappings: MAC-01 `10.42.0.11`, MAC-02 `10.42.0.12`, WIN-01 `10.42.0.21`, and BUILD-01 `10.42.0.31`. Maya Chen, Owen Patel, and Nora Ellis are the principal human users; additional service/admin accounts are visible. Other private destinations exist, but the supplied endpoint set cannot establish their complete roles.

There are 3,732 normalized eCAR records, 600 Windows Security events, 422 Sysmon events, and 473 Linux syslog lines. The office sensor contains 1,771 connections, 841 DNS records, 689 SSL records, 39 HTTP records, 386 file records, 286 X.509 records, 96 SMB file records, 53 SMB mappings, 31 OCSP records and 12 NTP records. Native Mac exports are selective: three Unified Log rows across the two Macs and fourteen Endpoint Security rows on MAC-02. I do not penalize their small count or demand unselected Mac or Sysmon event families.

The connection mix is dominated by DNS (877 connections) and TLS/443 (752), with SMB/445 (56), HTTP/80 (40) and SSH/22 (6) also present. That is a believable small-office surface. A count of 1,684 `SF` connections, 37 `RSTO`, 22 `RSTR`, and a smaller incomplete/other tail avoids a simplistic all-success pattern. Absolute volume alone does not establish authenticity given the bounded and selected collection.

### SSH pivot and operational lifecycle

A representative remote session begins with WIN-01 eCAR line 525: PID 7624, `ssh.exe owen.patel@NS-MAC-02.northstar.example`, under Nora's PowerShell process. The source account being Nora while the remote target account is Owen is technically possible; it does not imply shared credentials or an identity defect.

`office-span/conn.json` line 771 records UID `CW8qrKFikdyMQqDUFs4`, `10.42.0.21:51078 -> 10.42.0.12:22`, opening at 15:07:42.656634 UTC with duration 1,396.804534 seconds and state `SF`. MAC-02 eCAR line 427 observes inbound transport at 15:07:42.776. WIN-01 eCAR line 534 observes the source FLOW at 15:07:43.884 with PID 7624. Target successful SSH login follows at 15:07:46.608 (MAC-02 line 431, logon ID `0x7cad7bc`), after both endpoint transport observations.

The target then distinguishes the session supervisor, authentication child, credential transition, user child, and shell exec using stable object IDs and explicit execution IDs (MAC-02 eCAR lines 428–440). Endpoint Security fork rows retain parent/child audit-token relationships and increment pidversion on subsequent exec. I found no justification for treating inherited shell images at fork as wrong executable attribution: later MODIFY/exec observations supply the new image.

Zeek's transport closes at 15:30:59.461168. The Windows client terminates at 15:30:59.942 (line 702); target processes close around 15:31:00 (lines 497–499), and target session logout is at 15:31:09.172 (line 500). These are compatible observations of teardown with source delays. I do not demand bit-identical timestamps for TCP closure, process exit, and session cleanup.

BUILD-01 supplies a second useful SSH pivot: `conn.json` line 43, UID `CRmKEo4CDNaLvKgHYiR`, source `10.42.0.12:59781`, opens at 13:18:10.979390. BUILD-01 syslog lines 34–35 show accepted public-key authentication at 13:18:15.349029 and PAM session opening at 13:18:15.488513; BUILD eCAR line 43 observes login at 13:18:15.490. The source key fingerprint remains stable on Owen's later login. That relationship is production-like.

### File transfer, persistence leads, and effect attribution

The first SMB operation is traceable without guessing from names. `conn.json` line 1 provides UID `CFC20K6LLHisX5lUJlx` and `10.42.0.11:51244 -> 10.42.0.31:445`. SMB mapping line 1 identifies `\\NS-BUILD-01\Engineering`; SMB file lines 1–2 open/write `Procedures\2026\budget-review.pdf`; files line 1 gives 372,479 bytes. BUILD eCAR lines 3–4 attach Maya's SMB authentication/session reference and the server-side `/srv/samba/engineering/Procedures/2026/budget-review.pdf` write to the same activity. Direction and paths support the pivot.

MAC-01 offers persistence-oriented leads without proving malicious persistence. At 16:02:04.243, root process `northstar-maintenance` starts (eCAR line 483), writes `/Library/LaunchDaemons/com.northstar.assetcheck.plist` at 16:02:50.631 (line 484), and later deletes that file at 16:19:04.464 (line 492). An assetcheck process starts at 16:09:02.482 and exits at 16:10:46.217 (lines 485–486). The file placement and process observations are individually present; absent registration/activation records do not establish whether launchd loaded the item or what mechanism launched the executable.

MAC-01 Unified Log line 2 at 16:20:55.650827 says `ASP: Security policy would not allow process: 34349, /Applications/ReleaseAssistant.app/Contents/MacOS/ReleaseAssistant`. I treat that as a policy-related observation and investigation lead, not proof of a successful launch, a completed malware execution chain, or even a demonstrated final denial outcome. Likewise, the manifest download recorded in zsh history line 2 and eCAR lines 34/36 is a download; it does not establish execution of downloaded content.

### Where behavioral modeling looks weaker

The concurrent Chrome trees are the clearest application-specific concern. Chromium's own documentation describes separate data directories for parallel browser instances and the `--user-data-dir` mechanism ([Creating and Using Profiles](https://www.chromium.org/developers/creating-and-using-profiles/)). Here the same Mac user and same application path create three browser roots, with new renderer children owned by the later roots, while the first root is still running. No corresponding instance separation is visible. I classify this as application/environment plausibility because the records do not expose every possible setting or custom launch mechanism.

The short-command runtimes are corroborated in two forms. Native ES line 7 names `/usr/bin/id` in the exec target, with PID 49369 and pidversion 64; line 8 names the same executable/token at exit. That makes its approximately nineteen-second lifetime more than a normalized EDR delivery-lag artifact. ES lines 10–11 similarly put `sw_vers -productVersion` at roughly 5.909 seconds. Such commands can be delayed, but repeated inflated lifetimes across several simple query commands and two hosts suggest a generic duration distribution rather than command-specific behavior. I found no accompanying evidence sufficient to assert that the runtimes are impossible.

Windows browser HTTP ownership is also a caveated inference. A service can issue arbitrary HTTP requests with an arbitrary user agent. Nevertheless, the four exact tuple joins all land on the same `svchost.exe -k netsvcs` process, while the dataset elsewhere attributes a Chrome/121 OCSP request to an actual user Chrome process (`http.json` line 37; WIN-01 eCAR line 1371, PID 7748). This contrast makes the four service-owned browsing requests an ownership-model concern rather than a blanket assumption that user-agent text proves the process executable.

The 21-minute SMB cadence has less weight: a scheduled indexer or sync utility could access assorted documents. The report scores its narrow repeated intervals, not the fact that transfers correlate well or that the work is easy to describe.

### Limits and rejected indicators

No source-native impossible field value or unconditional same-identity temporal contradiction was established. Unmatched logouts or missing creates at the boundary can reflect pre-window sessions; missing closes can reflect post-window activity or selected collection. I found no reason to score those absences by themselves. I also did not score sanitized domains, perceived narrative neatness, the number of visible intrusion stages, absence of attacker mistakes, or complete cross-source matching.

There are Windows network logons for which this sensor excerpt does not supply an obvious matching transport, but independently selected source families and unknown routing/filtering prevent elevating that absence to a demonstrated defect. A collection specification could resolve it. Administrative commands targeting BUILD-01 do not by themselves prove successful Windows-specific management of a Linux host, so their presence is also not treated as an operational contradiction.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| environment_or_collection_plausibility | Mac eCAR application/process trees | Three Chrome browser roots for Owen; first remains visibly alive while later roots spawn renderers | Largest concern: default browser-instance semantics lack visible profile separation; hidden configuration remains a caveat |
| distribution_texture | Mac eCAR and native Endpoint Security | Several trivial query commands across both Macs; native ID exec-to-exit is 18.931 seconds | Moderate concern: repeated command-insensitive durations, not impossible execution |
| environment_or_collection_plausibility | Windows eCAR/Sysmon and Zeek HTTP | Four browser-shaped requests attributed to PID 5620, NETWORK SERVICE, svchost | Moderate concern: repeated unlikely owner; user-agent spoofing or an actual service remains possible |
| distribution_texture | Zeek SMB/connection records | Seventeen varied document sessions from MAC-02, roughly 21 minutes apart | Small supporting contribution; legitimate automation is a viable alternative |

## Realism Score by Category

- **Field format accuracy:** 9 — Structured records parse and retain plausible source-specific fields; no verified native schema defect was found.
- **Temporal patterns:** 6 — SSH ordering and closure work, but simple Mac command lifetimes and the SMB cadence have noticeable modeled texture.
- **Cross-source correlation:** 8 — Exact SSH, SMB, network UID, process and file pivots work; browser HTTP process ownership is less convincing.
- **Behavioral realism:** 6 — Operational actions generally work, with caveated concerns about browser-instance behavior and command durations.
- **Environmental consistency:** 7 — Mixed operating systems and account scopes are handled well; several application-to-process associations need explanation.

## Recommendations

If this were synthetic, the following changes would improve the specific weaknesses visible here:

1. Reuse the existing Chrome browser instance when opening new windows for one profile. If separate parallel instances are intended, show distinct user-data directories or another concrete, supported instance boundary and keep renderer ownership consistent with it.
2. Use command-sensitive process lifetimes for simple identity/version queries. Preserve genuine slow starts when their environment calls for them, but avoid repeatedly giving `id`, `uname`, and version-only commands generic multi-second runtimes. Keep native ES and normalized endpoint observations aligned to the same execution.
3. Resolve ordinary browser request ownership to the actual browser/network-service child rather than a generic Windows `svchost` fallback. If a real service is intended to fetch these pages with a Chrome user agent, provide consistent service-specific command/configuration context instead of inferring browser ownership from user-agent text.
4. Distinguish scheduled SMB automation from interactive document work. A genuine fixed-cadence indexer can remain periodic; user-driven reads and edits should follow that user's activity sessions and retain coherent application ownership.
