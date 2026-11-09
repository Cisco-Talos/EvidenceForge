# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 49

## Executive Summary

The dataset supports technically coherent investigations across endpoint, authentication, network, proxy and file-sharing evidence, and I did not establish an impossible same-identity lifecycle relationship. Its strongest synthetic-looking features are repeated diagnostic command groups and an unusual repeated use of terminal utilities for ordinary Office/PDF share access; these are concrete behavioral textures, but they also admit legitimate testing or administration explanations. They justify a mixed assessment rather than a confident synthetic verdict.

## Evidence For Synthetic

- [distribution_texture] The two Mac shell histories contain 39 commands, of which 35 are repetitions from just 11 diagnostic command strings, with the remaining four being SSH commands. Examples include five `ps aux`, four `sw_vers -productVersion`, four `id`, and four identical `find ... -maxdepth 2 -type f -name '*.pdf'` commands. The repeated short groups appear throughout the six-hour window on both hosts: `MAC-MROSS-01.meridianhcs.local/zsh_history/maya.ross.zsh_history`, lines 1–6, 8–11, 14–16 and 18–21; the corresponding MAC-MROSS-02 history, lines 1–9 and 11–18. This recurring activity palette is more suggestive of scripted activity sampling than varied interactive work, although a deliberate diagnostic routine could explain it.
- [environment_or_collection_plausibility] MAC-MROSS-02 repeatedly accesses binary productivity documents using `/bin/cat`, not just a one-off inspection. Its native Endpoint Security export records eight such executions, covering PDF, XLSX and DOCX files, at lines 32, 102, 112, 115, 151, 157, 163 and 166 of `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson`. For example, PID 21345 executes `cat /Volumes/ClinicalResearch/Team/2026/project-plan.pdf` at 13:37:04.757165Z and exits successfully at 13:37:32.052136Z; PID 45873 similarly cats `service-review.xlsx` at 16:05:43.435835Z. These are actual process arguments corroborated by SMB reads, not an inference from filenames alone. Repetition across eight productivity documents makes the behavior look like an artificial stand-in for document use. It remains possible that this is intentional file-access testing.
- [distribution_texture] One visible Mac terminal teardown has mechanically spaced dependent exits. MAC-MROSS-02 Endpoint Security lines 175–178 close `cat` PID 65767, zsh PID 19009, login PID 19008 and iTermServer PID 19007 at 18:56:59.150935Z, .150936Z, .150937Z and .150938Z respectively. The exact one-microsecond staircase across four processes is a small timing-texture concern. Child-before-parent order is coherent; I am not calling this an impossible lifecycle or treating the existence of logout closure as a defect.

## Evidence For Real

- The MAC-MROSS-01 → MAC-MROSS-02 SSH pivot preserves distinct transport, authentication and shell stages. `zeek-core/conn.json:2498` opens 10.10.1.41:60425 → 10.10.1.42:22 at 14:25:20.267877Z. MAC-MROSS-02 Unified Log line 2 records accepted keyboard-interactive/PAM authentication for `maya.ross` from that exact tuple at 14:25:27.911230Z. Native Endpoint Security lines 62–64 then show session child creation and shell execution at approximately 14:25:28Z.
- The database export has usable artifact and session continuity. DB-PROD-01 syslog lines 187–190 show the inbound root session from 10.10.2.30:37984; its root history lines 9–14 supplies the redirected dump, gzip and SCP commands. DB-PROD-01 eCAR lines 561–569 tie the resulting SQL and gzip artifacts to the processes that subsequently consume them. The transfer has a corresponding TCP/22 connection in `zeek-db/conn.json:420`, and the receiver records root public-key authentication in APP-INT-01 syslog lines 214–215.
- Proxy activity distinguishes client and server legs. The support attachment appears as an absolute-form client request in `zeek-dmz/http.json:1386` and an origin-form forwarded request from 10.10.3.20 in line 1387, with the same request-body length of 1,573,258 bytes. `PROXY-01.meridianhcs.local/proxy_access.log:1930` records the matching ticket URI and curl agent. This gives meaningful pivots, rather than merely repeating one endpoint tuple everywhere.
- The suspicious Windows upload also has endpoint and egress evidence: WS-AJOHNSON-01 eCAR lines 1179, 1324 and 1331 identify the ZIP creation, curl execution and subsequent ZIP read; proxy line 2974 records the matching upload URI and an inspected TLS tunnel; `zeek-dmz/conn.json:8434` shows approximately 18.8 MB outbound on the external leg.
- Network observation is not uniformly pristine. The same SCP transport has 76 missed bytes at the DB sensor and zero at the core sensor (`zeek-db/conn.json:420`, `zeek-core/conn.json:11083`), with differing response packet counts. Such sensor-specific differences are plausible and do not break the shared tuple or bulk-byte relationship.

## Detailed Analysis

### Input provenance and scope

I read only the supplied neutral briefing and files under `/private/tmp/log-study-yflye15q/data`. Parsing used system `python3` from `/private/tmp`; I did not read project code, authored scenarios, roadmap/worklogs, other assessments or origin metadata, and did not use web searches. Generic inherited operating instructions were not used as evidence of data origin.

The endpoint exports cover 23 host directories, including Windows workstations and servers, Linux workstations and servers, and two Macs. The visible hostname and address relationships support several segments: 10.10.1.x clients, 10.10.2.x internal services, 10.10.3.x web/proxy systems and a 10.10.4.10 database host. I counted 37,089 normalized eCAR records, 19,272 Windows Security events and 12,097 Sysmon events. There are 22,296 Zeek connection records across three sensor directories; those are sensor observations, not necessarily that many distinct enterprise connections. Endpoint timestamps span approximately 2026-11-02 13:00–19:00 UTC.

This is a bounded collection slice. I did not score missing pre-window parent processes, surviving sessions, an absent audit family, or differences in platform collection breadth. The five Unified Log records and selected native ES process notifications are not sufficient grounds to require a comprehensive Mac system log or file audit trail.

### Hunt paths and technical feasibility

The visible web-host shell is suspicious on its own merits: WEB-EXT-01 eCAR line 795 creates PID 2702851 as `www-data`, parented to apache2, with a base64-decoding Bash command. `zeek-dmz/conn.json:1733` records an outbound connection from 10.10.3.10 to 45.33.32.30:8443 a few seconds later. The short transport duration does not prove a persistent shell, and I do not infer persistence or additional effects from this one command.

The Windows domain-controller evidence supports a separate concrete sequence: DC-01 has PSEXESVC installation and execution, then account creation/group changes and service/task persistence activity. For reproducibility, its Security events identify service installation at 16:59:51.1315061Z, account creation 4720 at 17:14:50.6010373Z, Domain Admins addition 4728 at 17:14:55.0847394Z and task registration 4698 at 17:20:06.1140301Z. The `svc_dirsync` account SID ends in 2525 consistently through account creation, membership and deletion. Corresponding Sysmon process commands include `net user`, `net group`, `sc.exe` and `schtasks.exe`. I regard the ability to pivot through these records as a strength. Their narratability and the presence of multiple intrusion stages did not contribute to the synthetic score.

The DB export demonstrates why shell syntax and process arguments must be distinguished. The native process command line for `mysqldump` omits the `>` redirection, whereas the root Bash history includes it. This is compatible with shell handling of redirection, and I did not flag the absence of `>` from the child process as a tradecraft defect.

The normalized Windows `runas /netonly` activity also retains the local `aisha.johnson` process principal while naming alternate remote credentials. Different local and remote account identities are not inherently inconsistent. I did not count them as an ownership contradiction.

### Lifecycle and timing checks

I compared eCAR actor references against visible same-object process creation and termination timestamps on all hosts. With a one-second allowance for source timing/normalization, I found no actor event occurring before its visible creation or after its visible termination. I separately checked Sysmon process-associated events against visible same-GUID Event 1 and Event 5 boundaries and found no inversions exceeding that allowance. These checks do not prove every activity is correct, but they failed to produce the kind of hard contradiction needed for a high synthetic-confidence score.

I also matched Zeek DNS, HTTP, TLS, SMTP and SMB-file records to connection UIDs within their own sensors. No matched protocol timestamp fell more than 0.5 seconds before its connection start or more than one second beyond its duration. An initial packet-accounting screen found some TCP rows with fewer IP bytes than payload-plus-minimum-header arithmetic would suggest; all those cases were associated with missing-byte/gap evidence. I excluded them as authenticity defects because stream-size estimates and captured packet counts need not agree under packet loss.

The tiny Mac terminal-exit staircase remains a texture concern, not a causality failure. Conversely, the explicit SSH transport-before-auth and shell-after-auth sequence is meaningful positive evidence.

### Behavioral texture and alternative explanations

The diagnostic histories and repeated `cat` activity are the main reasons the score does not fall in the production-like 0–40 bands. They concern actual executable choices and repeated command distributions, rather than whether an intrusion is tidy. The strongest alternative explanation is that these particular endpoints were undergoing administrative checks or scripted file-access testing. The data contains enough role-appropriate activity elsewhere—mail, directory authentication, remote administration, proxy requests, periodic host tasks and SMB use—that the Mac behavior should not be extrapolated into a dataset-wide impossible environment.

The MeetingAssist entry at MAC-MROSS-01 Unified Log line 2 says the security policy “would not allow” a process. I did not promote that message into proof of successful execution, child activity, or a specific authorization result, and found no demonstrated contradiction requiring such an interpretation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac zsh histories, corroborated by process notifications | 35 diagnostic commands from 11 strings across two hosts | Moderate concern: repeated activity palette; administrative routine remains plausible |
| environment_or_collection_plausibility | Mac native ES, normalized endpoint and Zeek SMB | Eight binary document accesses using `cat` on MAC-MROSS-02 | Moderate concern: repeated utility substitution for productivity document work; file-access testing is a viable explanation |
| distribution_texture | Mac native ES exit timestamps | One four-process terminal chain | Small concern: exact one-microsecond steps; ordering itself is valid |

No established hard contradiction or generator identity leak contributed to the score. The behavioral indicators overlap somewhat and were not treated as three independent proofs.

## Realism Score by Category

- **Field format accuracy:** 9 — The examined records parse and support native/normalized distinctions; I established no source-native schema violation.
- **Temporal patterns:** 8 — Transport, authentication and process relationships work; a small terminal-exit staircase and repetitive command texture remain.
- **Cross-source correlation:** 9 — SSH, export, proxy and upload paths support concrete pivots with sensible source-specific observations.
- **Behavioral realism:** 6 — Repeated diagnostics and eight binary-document `cat` operations are conspicuous but possible.
- **Environmental consistency:** 8 — Host roles and network paths broadly fit; the Mac document-access workflow is the principal local concern.

## Recommendations

- If this were synthetic, broaden the interactive command distribution only where it represents actual user intent; the 35 diagnostic commands from 11 strings should have a defensible operational reason.
- If this were synthetic and the eight share reads represent ordinary document work, model the application or workflow that would actually perform those reads. Retain `cat` when the intent is an explicit shell-based validation or file-access test.
- If this were synthetic, derive terminal teardown timing from the actual process lifecycle rather than imposing exact one-microsecond increments across successive ancestors. Preserve the observed child-before-parent relationship.
- Preserve the existing distinctions among sensor-local loss, proxy legs, shell redirection, remote credentials and native process transitions; these were strengths in the reviewed evidence.
