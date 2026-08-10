# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 64

## Executive Summary

This is high-quality, operationally useful telemetry with unusually strong source-native formatting and cross-source correlation. I nevertheless judge it synthetic because two dataset-wide patterns are difficult to reconcile with organic collection: selectively incomplete SSH process lifecycles despite visible session closure, and a systematic multi-second delay between Bash history timestamps and matching process creation telemetry.

## Evidence For Synthetic

- `[contract_gap]` SSH process lifecycles are selectively incomplete. Across Linux eCAR sources, I found 117 `sshd: <user> [priv]` process creates. One hundred had a same-PID `pam_unix(sshd:session): session closed` record in syslog, but only 63 had a matching eCAR `PROCESS/TERMINATE`; 37 closed sessions retained an unterminated process object. Example: `APP-INT-01.../ecar.json` creates PID 946591 at `2024-03-18T12:01:52.301Z`; `syslog.log` records its session opening at `12:01:55.388206Z` and closing at `13:00:55.418896Z`, but eCAR has no termination for that object.
- `[distribution_texture]` Bash history and process telemetry have a consistent artificial-looking lag. I exactly matched 154 history commands to same-host, same-user eCAR process creates. Every process timestamp followed the integer history timestamp by 0.403–6.757 seconds; median lag was 2.0815 seconds. `DB-PROD-01.../bash_history/root.bash_history` records `hostname -f` at epoch `1710782080` (`17:14:40Z`), while eCAR line 610 creates it at `17:14:46.757Z`. The final `scp` is recorded at `17:32:43Z`, while eCAR line 706 creates it at `17:32:45.091Z`. One-sided, multi-second delays across all 154 exact matches resemble generated observation jitter more than shell execution latency.
- `[contract_gap]` The SCP receiver lifecycle exposes the SSH defect particularly clearly. On `APP-INT-01`, PID 982025 is created at `17:32:46.982Z` as `sshd: root [priv]` and later owns the file creation `/tmp/.cache/rpt_0318.sql.gz` at `17:32:51.674Z` under process title `sshd: root@notty`. The session closes in syslog at `17:32:54.787006Z`, but PID 982025 never terminates in eCAR; only the sibling PID 982026 terminates at `17:32:56.448Z`.
- `[weak_signal]` The observation window is exceptionally bounded: nearly every source begins shortly after `12:00` and ends shortly before `18:00` on the same date. This is explainable as a six-hour export and did not materially drive the verdict, but it reinforces the two stronger distribution/lifecycle findings.

## Evidence For Real

- Windows process correlation is excellent and source-native. Of 935 Security 4688 records and corresponding Sysmon Event 1 records, 927 matched on host, PID, image, and command line within 100 ms. Their clock delta ranged from -20.9 to +18.2 ms, with median -1.57 ms and 95th-percentile absolute delta 16.3 ms.
- Sysmon lifecycle integrity is strong. Across the nine Windows hosts, no matching Event 5 termination preceded its Event 1 creation, no ProcessGuid was reused for two creates, and matched termination PID/image/user tuples agreed with creation.
- Executable identity is stable. Within every Windows host, repeated image paths retained one hash and one metadata tuple; across hosts, an image with the same FileVersion also retained the same hashes. This avoids a common synthetic defect where each process instance receives a new executable hash.
- The DC Security-log clear is modeled convincingly. `wevtutil cl Security` appears at `17:42:03.0812204Z` with EventRecordID 28262315; pre-clear records continue through 28262319; Event 1102 appears at `17:42:03.6637048Z` as record 1; subsequent events use records 2, 3, 4, and onward. The reset and filtered gaps are plausible for centralized retention.
- Network telemetry has substantial entropy. The core and DMZ sensors contain 6,230 and 5,554 connection rows. Among 1,934 tuple/time-matched observations visible to both sensors, sensor offsets had 1,810 distinct microsecond values with 6.67 ms standard deviation, and UIDs differed. HTTP, SMB, LDAP, Kerberos, and successful TLS byte/duration tuples generally showed near-record-level uniqueness rather than fixed templates.
- TLS/X.509 relationships are coherent. Every populated certificate FUID resolved, and no certificate was used outside its validity interval. TLS 1.3 sessions generally omit visible certificate chains while TLS 1.2 sessions usually include them, matching passive-observation semantics.
- The suspicious activity is detection-useful without relying on narrative cleanliness: DC records show PSEXESVC installation at `16:00:07.7739543Z`, domain account creation and Domain Admin membership at `16:14:33–16:14:40Z`, DeviceSync service/task persistence at `16:20:16–16:20:31Z`, execution at `16:29:10Z`, and audited clearing at `17:42:03Z`. Security, Sysmon, eCAR, network, syslog, and file evidence agree on identities and ordering.

## Detailed Analysis

### Dataset and quantitative probes

The set covers 18 host eCAR streams, Windows Security/Sysmon XML, Linux RFC 5424-style syslog and Bash history, two Zeek sensors, ASA, Snort, proxy, and web access telemetry. Zeek provides 11,784 connection rows, 2,994 DNS rows, 2,284 HTTP rows, 1,846 SSL rows, and 550 X.509 rows. Windows Security contains 13,799 events across nine hosts.

I tested:

- exact Windows Security 4688 ↔ Sysmon Event 1 matching by host, PID, image, command, and timestamp;
- Sysmon create/terminate ordering, ProcessGuid reuse, and lifecycle field equality;
- per-image hash/version stability;
- Zeek tuple overlap, sensor timestamp deltas, UIDs, byte distributions, IP/payload accounting, certificate references, and validity;
- Linux SSH transport, auth, session-open, session-close, file-transfer, and eCAR process lifecycle;
- exact Bash-history command ↔ eCAR create timing.

### Endpoint and identity telemetry

Windows is the strongest portion. The 927 exact 4688/Event 1 pairs are not merely “complete”; they preserve distinct source clock texture within a narrow plausible range. ProcessGuid reuse and termination-order probes found zero contradictions.

The DC clear sequence is especially credible. The record-ID transition from 28262319 to Event 1102 record 1, followed by normal records 2 onward, is source-native behavior rather than a generic “log cleared” annotation.

### SSH lifecycle defect

Transport and authentication ordering is generally good. For the suspicious SCP from `10.10.4.10:58989` to `10.10.2.30:22`, Zeek core begins the connection at `17:32:45.657394Z`; source eCAR creates `scp` at `17:32:45.091Z`; target eCAR observes the inbound flow at `17:32:47.018Z`; syslog records connection/auth/session-open at `17:32:47.822380Z`, `17:32:50.045590Z`, and `17:32:50.131808Z`; and the target file appears at `17:32:51.674Z`.

The defect is termination ownership. Thirty-seven SSH processes whose same PID visibly reaches syslog session closure never terminate in eCAR. This is too systematic and source-family-specific to dismiss as ordinary random loss, particularly because general Linux process create/terminate coverage is otherwise dense.

### Shell-history timing texture

All 154 exact history/process matches were positive; none were simultaneous or sub-400 ms. A median of 2.0815 seconds between a one-line Bash history entry and the corresponding exec is implausibly broad if both are event timestamps from the same host. Variable telemetry ingestion delay could explain isolated cases, but the universal one-sided lag and bounded range look like a timing planner.

### Network and protocol telemetry

Network volume, packet accounting, service diversity, and dual-sensor behavior are persuasive. For example, core successful SMB has 865 distinct byte pairs across 865 rows; LDAP and Kerberos likewise show high cardinality. Core/DMZ duplicates receive different UIDs and slightly different timestamps/durations. Certificate-chain visibility follows TLS-version constraints, and all FUID/validity probes passed.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `contract_gap` | Linux eCAR + syslog SSH | 37 of 100 visibly closed SSH processes lack termination | Highest-impact tell; selective lifecycle incompleteness despite otherwise dense process telemetry |
| `distribution_texture` | Bash history + Linux eCAR | 154/154 exact command matches lag by 0.403–6.757 s; median 2.0815 s | Strong dataset-wide one-sided timing fingerprint |
| `contract_gap` | SCP receiver eCAR | PID 982025 owns transferred file but remains alive after visible session close | Concrete instance of the broader SSH ownership problem |
| `weak_signal` | All sources | Common six-hour boundary | Explainable export artifact; low score impact |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Security, Sysmon, Zeek, syslog, ASA, proxy, and web fields are highly source-native.
- **Temporal patterns:** 6/10 — Cross-source Windows timing is excellent, but Bash/eCAR lag has a conspicuous global fingerprint.
- **Cross-source correlation:** 9/10 — Identities, tuples, process GUIDs, file transfers, and account/service actions correlate strongly.
- **Behavioral realism:** 8/10 — Baseline and suspicious behaviors are operationally plausible and huntable.
- **Environmental consistency:** 8/10 — Host roles, services, routes, and dual-sensor visibility are coherent; SSH lifecycle collection is the main exception.

## Recommendations

- Highest-value target: ensure every observed per-session `sshd` process receives a termination tied to the same process object after PAM/session closure, including privilege-separation and `@notty` receiver processes. If termination observation is intentionally dropped, drop the source-local lifecycle group coherently rather than leaving a selective create-only process.
- Highest-value target: derive Bash history timestamps and process-create timestamps from one command-execution anchor. Normal second-resolution truncation is reasonable, but eliminate universal 0.4–6.8 second post-history jitter; most one-line commands should execute within the same second.
- Add regression probes for `sshd` PID/object lifecycle: connection → auth → session open → optional file activity → session close → all session child/monitor terminations.
- Preserve the current Windows process, log-clear, dual-sensor, and TLS/X.509 contracts; they are the dataset’s strongest realism features.
