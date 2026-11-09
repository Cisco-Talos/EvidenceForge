# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 43

## Executive Summary

The supplied telemetry supports practical hunting across a mixed fleet, with credible network/session ordering and useful file-transfer pivots. I found one qualified process-ownership concern and a small command-duration anomaly, but no demonstrated impossible same-identity ordering or decisive generator fingerprint; these observations do not establish synthetic origin.

## Evidence For Synthetic

- [contract_gap] **Qualified transport ownership concern:** `DB-PROD-01.meridianhcs.local/ecar.json:567–569` assigns both the source-file read and the TCP/22 FLOW to `/usr/bin/scp`, PID `1089082`, process object `41989080-c555-4c97-a76e-bd70bd3ea478`. The FLOW at `18:15:41.306Z` is `10.10.4.10:58907 → 10.10.2.30:22`. Standard OpenSSH scp delegates the SSH transport to a child SSH process, so the socket-owning process should ordinarily differ from the file-copy parent. This is a concern about the positive PID/image attribution, not merely the absence of a child record. A normalized product that attributes connections to an initiating ancestor, or a different scp implementation, could explain it; the dataset does not identify that attribution policy. Moderate, localized weight only.
- [weak_signal] **A short sampling-command lifetime:** `DB-PROD-01.meridianhcs.local/ecar.json:403–404` creates `vmstat 1 5` at `16:41:45.413Z` and terminates the same object `259f4fa3-a77a-4f6a-83e5-8834edfab9dd`, PID `1077168`, at `16:41:46.735Z`: only `1.322 s`. Five ordinary reports with one-second spacing normally require about four seconds. The same command on `MAIL-CLIN-01.meridianhcs.local/ecar.json:255–256` lasts `4.503 s`. An interrupted/erroring command remains a plausible real explanation because no exit status or captured output establishes normal completion. Small weight; not a hard contradiction.
- [distribution_texture] **A narrow macOS interactive-command vocabulary:** the two Maya Ross zsh histories contain 21 commands/14 exact strings on MAC-MROSS-01 and 18 commands/11 strings on MAC-MROSS-02. MAC-MROSS-01 history lines `4–6`, `8–10`, and `18–21`, and MAC-MROSS-02 lines `4–9` and `13–18`, repeatedly combine directory listings, disk usage, process lists, and PDF searches. The repeated `find ... -name '*.pdf'` is visible at MAC-MROSS-01 lines `10` and `19` and MAC-MROSS-02 lines `7` and `16`. This provides mild template-like texture, but the same user testing or administering two machines is a straightforward alternative. Very small weight; no claim that all interactive activity must be captured in shell history.

## Evidence For Real

- **Transport precedes authentication in an actionable SSH pivot.** `zeek-core/conn.json:3001` and `zeek-dmz/conn.json:2187` show `10.10.1.99:46575 → 10.10.3.10:22` beginning around `14:39:41Z`, lasting about `1953.59 s`. `WEB-EXT-01.meridianhcs.local/syslog.log:365–366` accepts root's public key at `14:39:50.765456Z` and opens PAM at `14:39:50.843464Z`; eCAR line `954` creates the root shell at `14:39:52.737Z`. These are coherent distinct phases, rather than authentication appearing before transport.
- **A transfer has several useful, mutually compatible pivots.** DB-PROD-01's dump, gzip, and scp processes appear at eCAR lines `561`, `564`, and `567`. The transfer tuple matches `zeek-db/conn.json:420` and `zeek-core/conn.json:11083`; APP-INT-01 records the matching source port in syslog lines `213–214` and eCAR lines `860` and `862`. APP-INT-01 later reads the received file with smbclient at eCAR `867–870`, while FILE-LNX-01 records `svc_mhsync` writing the corresponding share path at syslog `536–538` and eCAR `1403`. Root's local identity and the directory service credential are kept distinct.
- **The reverse-shell command and network view agree on plaintext transport.** `WEB-EXT-01.meridianhcs.local/ecar.json:795` contains a base64-encoded bash command whose inert decoded text targets `/dev/tcp/45.33.32.30/8443`; line `799` records that destination. `zeek-dmz/conn.json:1733`, UID `CZlJyhfTtC1KsxbXGx7`, has no SSL service classification, and no SSL companion for that UID was present. Port 8443 was not automatically treated as proof of TLS.
- **The network layer has useful observed variation.** Across the three sensors, 22,296 connection rows include successful, unresponded, reset, rejected, and partial states. Zeek-core has `9995 SF`, `1685 S0`, `156 RSTO`, `106 RSTR`, and `32 REJ`; Zeek-dmz has `6321 SF` and `2462 S0`. Example `zeek-dmz/conn.json:7790` includes `missed_bytes=50`, while the adjacent C2-related records include both resumed and full TLS handshakes. Such variation supports plausible collection rather than an exclusively idealized successful network view.
- **The macOS policy message does not invent successful execution.** MAC-MROSS-01 Unified Log line `2` says policy would not allow MeetingAssist PID `62445` at `15:41:34.381320Z`. Searching the supplied eCAR and Endpoint Security records did not find a successful MeetingAssist process execution. I did not infer either child execution or effects from the policy message.

## Detailed Analysis

### Scope and actual input provenance

All log citations are relative to `/private/tmp/log-study-pifdrjj7/data`; line numbers are physical one-based file lines. The neutral directory contains 119 files. There are 23 endpoint directories with eCAR, spanning 10 Windows hosts with Security/Sysmon XML, 11 Linux-like hosts with syslog, and two Macs with Endpoint Security, Unified Log, and zsh history. Three Zeek sensor directories, one ASA directory, and two Snort directories add network evidence. Visible endpoint activity spans approximately `2026-11-02 13:00–19:00 UTC`; this is a six-hour slice, not a complete machine lifetime. Names and addresses suggest workstation, directory, file, application, mail, proxy, database, and web roles on `10.10.1/24`, `10.10.2/24`, `10.10.3/24`, and `10.10.4/24` segments.

I read the complete neutral `threat-prompt.md`, inventoried only the supplied data directory, parsed every eCAR record, parsed all supplied Windows Security and Sysmon XML files, and parsed all three sensors' conn/DNS/HTTP/SSL records plus available SMB/SMTP companions for reference and timing checks. I sampled native syslog, shell history, macOS ES/Unified Log, and Snort records, with additional targeted searches for the investigated identities, commands, and tuples. The 23 eCAR files contain 37,089 rows: 27,430 FLOW, 5,172 PROCESS, 2,292 MODULE, 1,550 USER_SESSION, 384 FILE, 248 REGISTRY, 10 THREAD, and three SERVICE records. There are 39 distinct nonempty principal strings, including system/service and machine identities; that is not a count of human employees.

Read-only parsing used system `python3` with explicit working directory `/private/tmp/log-study-pifdrjj7`. Commands found inside logs were never executed. No repository files, authored scenario, TODO, worklog, prior assessment, other reviewer's report, or project web content were accessed. Generic inherited operating instructions were an environment limitation and were not used as origin evidence. External research was restricted to direct upstream OpenSSH/procps sources and a domain-filtered official Zeek documentation search. Output was written only to the requested neutral report path.

### Following the intrusion-relevant trail

The web host has an Apache-parented bash process under `www-data` at `14:20:23.150Z`, followed by the matching outbound connection to `45.33.32.30:8443`. This is a viable initial hunting pivot, but it does not by itself prove the later root session shares that origin. A different source, `10.10.1.99`, opens a root SSH session about 19 minutes later. I preserve that attribution boundary rather than filling it with an assumed privilege-escalation story.

Inside that root session, `WEB-EXT-01/ecar.json:964` creates `nmap -sn 10.10.2.0/24`; subsequent FLOW records such as `965–970` carry ICMP type 8/code 0. Line `1219` creates a separate TCP connect scan for ports `22,80,443,445,3306`; line `1470` is an example failed TCP/80 observation attached to that second process. The process/protocol distinction makes these pivots usable. The existence and compact timing of this sequence were not scored as evidence of synthetic origin.

At the database host, root history lines `10–14` and eCAR `561–569` support dumping selected EHR tables, compressing the result, and copying it to APP-INT-01. The dump terminates before gzip begins, and gzip terminates before scp begins. APP-INT-01's later SMB client uses `svc_mhsync` while its process remains locally root, matching the server's directory-account audit attribution. This is operationally plausible credential separation. The principal concern is the initiating scp process being positively attributed as the TCP socket process; successful file movement itself is supported.

The [upstream OpenSSH scp implementation](https://raw.githubusercontent.com/openssh/openssh-portable/master/scp.c) creates a communication socketpair, forks, and executes the SSH program in its transport path (`do_cmd`, source lines approximately 247–336). This establishes the standard implementation expectation, but does not identify the installed binary in the logs. For that reason I have not labeled the normalized FLOW attribution an impossible native Linux event or treated the missing child alone as a coverage defect.

### Lifecycle and timing checks

For eCAR processes with visible CREATE and TERMINATE records, I indexed object identities separately for each host. I found zero cases where a visible child CREATE preceded its visible parent's CREATE, zero visible children created after that parent's recorded termination, and zero dependent activities whose `actorID` referred to an already terminated visible process. This is a bounded identity/order check, not proof every process or session was captured.

For Zeek DNS, HTTP, SSL, available SMB-file, and SMTP records, every referenced connection UID existed in the same sensor's conn file. With a conservative tolerance, none of the checked protocol timestamps preceded its connection start by more than 0.5 seconds or extended more than one second past its reported close. Complete matching was treated as functional strength, not synthetic evidence.

The anomalous `vmstat 1 5` lifetime concerns one visible execution. The [upstream procps manual](https://gitlab.com/procps-ng/procps/-/raw/master/man/vmstat.8) defines a first report and later reports separated by the requested delay. A normally completed five-report call therefore differs from the 1.322-second observation. However, signal termination, invalid runtime conditions, or an unusual binary can explain it, and no logged completion status rules those alternatives out. Other observed calls last 4.503–7.836 seconds or about 5.7 seconds for the sudo child, which limits any claim of a dataset-wide duration defect.

### Source interpretation and exclusions

The collection mix is large enough to support substantial baseline traffic and several unrelated administration or support actions; thin source families alone were not penalized. Routine cron/sysstat repetition was not scored: a recurring scheduled task can legitimately repeat the same command. Source-specific sensor UIDs were not required to match across network sensors.

I also did not infer packet-accounting contradictions simply from a TCP application-byte count exceeding captured IP bytes minus a naive per-packet header budget when `missed_bytes` was nonzero. Likewise, an HTTP body larger than wire payload is not automatically impossible: the [official Zeek HTTP schema](https://docs.zeek.org/en/v8.0.11/scripts/base/protocols/http/main.zeek.html) describes body lengths in terms of uncompressed content. Neither observation contributed to the score.

On macOS I treated ES notifications, Unified Log, shell history, and normalized eCAR as separate views. I did not apply Linux or Windows-native requirements to the Macs, infer denial merely from a notification result field, or require absent event families without an established collection contract. The few Unified Log records alone cannot establish an unrealistic full-system logging volume because these files may be selected exports.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score and alternative |
|---|---|---|---|
| contract_gap, qualified | Linux normalized process/FLOW attribution | One scp transfer; DB-PROD-01 eCAR 567–569 | Main reason for exceeding the mostly-realistic band: scp parent is attributed as TCP owner. Ancestor-attribution normalization or a different implementation could explain it. |
| weak_signal | Linux process lifecycle and bash history | One vmstat invocation; DB eCAR 403–404, history 25–26 | Small increase for a shorter-than-normal sampling lifetime. Early termination/error remains possible. |
| distribution_texture | macOS zsh histories | Two hosts, same human identity, 39 commands total | Very small increase for repeated diagnostic command vocabulary. Repeated user workflow is a plausible alternative. |

No hard contradiction, confirmed source-native schema defect, or origin-identifying string was established. The score reflects limited mixed evidence, not confidence that generation occurred.

## Realism Score by Category

- **Field format accuracy:** 9 — Supplied JSON/XML parses and the sampled native records provide plausible source-specific fields; no verified native-format defect.
- **Temporal patterns:** 8 — Major transport/auth and process lifecycles align; one sampling-command duration merits qualification.
- **Cross-source correlation:** 8 — Transfers, tuples, identities, and file paths are investigable; scp transport-process attribution remains uncertain.
- **Behavioral realism:** 8 — Administrative and suspicious commands have workable pivots; some repeated Mac command vocabulary is narrow but explainable.
- **Environmental consistency:** 8 — Roles, network zones, local versus directory identities, and the observed source mix are broadly coherent for the visible slice.

## Recommendations

- If this were synthetic, represent the scp parent and its SSH transport child separately, associating TCP ownership with the child while retaining the parent as initiating activity. If ancestor attribution is intentional, make that distinction explicit in normalized fields rather than using a socket-owner PID ambiguously.
- If this were synthetic, derive `vmstat 1 5` normal-completion duration from its reporting cadence, and model early termination/error explicitly when a shorter lifetime is intended.
- If this were synthetic, expand the two Macs' interactive-history variety around the actual observed workflows and host differences, while retaining legitimate repeated commands. This is a minor texture improvement, not a demand to fabricate missing telemetry or mistakes.
