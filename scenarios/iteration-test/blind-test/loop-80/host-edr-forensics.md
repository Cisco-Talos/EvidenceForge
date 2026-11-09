# Loop 80 — Blind Host/EDR Forensics Assessment

## Verdict

**Verdict:** Inconclusive  
**Verdict confidence:** 65/100 (Moderate)  
**Synthetic-confidence score:** 48/100 (higher means more synthetic)

## Executive summary

The host evidence is internally coherent across the six-hour slice. Windows Sysmon process creation and termination records closely match eCAR process events by action, PID, and image; visible process and logon lifecycles have valid ordering. Linux syslog/eCAR host activity and macOS Endpoint Security/eCAR process trees show no verified impossible sequence. Cross-source alignment is strong, but is not treated as evidence of synthetic construction by itself.

The main realism limitation is collection coverage on the two macOS hosts: each has hundreds of eCAR events and 128/182 Endpoint Security records, but only two/three Unified Log records for the full window. This could reflect a deliberately narrow Unified Log query, so it is a weak collection-plausibility signal rather than a contradiction. The inspected data does not support a confident Real or Synthetic verdict.

## Categorized evidence

### hard_contradiction

- **None verified.** Paired process lifecycles were ordered correctly in eCAR and Windows Sysmon. Paired Windows 4624/4634 logon IDs also had no logoff-before-logon cases.
- An initial PID-only comparison appeared to show incorrect macOS parent images. Reviewing the complete process lifecycle resolves it: macOS records process creation at fork and then record `PROCESS MODIFY` events as the same PID execs a new image. Child `parent_image_path` values match the parent's current image by the time the child is created. This is not a contradiction.

### contract_gap

- macOS Unified Log is unusually sparse for a six-hour window: two lines on `MAC-MROSS-02` and three on `MAC-MROSS-01`, against 182 and 128 Endpoint Security records respectively. The files contain useful login/session messages, but little ongoing application or system activity. Without a stated collection contract, this remains an unverified coverage gap.
- No required-companion omission was established in the reviewed host/EDR records. In particular, process and logon terminations missing from the visible slice are not treated as defects when their corresponding starts can be outside the window or their ends outside the window.

### distribution_texture

- The Windows slice contains substantial but varied host activity. Across ten Windows hosts, Sysmon has 3,674–4,541 records on the domain controllers and 303–573 on the sampled servers/workstations. Network Event ID 3 is the largest class on most hosts; process create/terminate, DNS, image load, registry, and access events provide additional texture.
- Sysmon process lifecycle volume is coherent: exact action/PID/image overlap with eCAR ranges from 95.1% to 100% of Sysmon Event ID 1/5 records. The small residual differences (typically 1–5 events per host) are compatible with source observation gaps.
- Windows Security logs have expected role variation: domain controllers are Kerberos/authentication-heavy (for example, DC-01 has 918 Event 4769 and 383 Event 4768 records); user endpoints have fewer logons and more process/network filtering events.
- eCAR contains 37,709 rows across 23 host directories. Flow records dominate many hosts, particularly `PROXY-01` (5,896/6,188) and `WEB-EXT-01` (3,709/4,073). This is high volume, but the inspected data does not establish an impossible rate or a uniform per-host distribution.
- Linux and macOS eCAR process lifecycles are mostly paired. Where one side is absent, the records are consistent with a slice boundary or collection difference; no visible paired lifecycle was reversed.

### schema_or_format

- Windows event XML parsed as structured event records, with event IDs and `TimeCreated` values spanning the window. Syslog records use structured RFC 5424-like headers; eCAR and macOS telemetry parse as JSON/NDJSON.
- eCAR rows have unique row IDs and include the expected host, timestamp, object/action, and object ID fields. Flow rows in the inspected set carry source, destination, and protocol fields; process create/terminate records carry PID and image identity.
- No malformed or truncated host/EDR record was found in the inspected files.

### environment_or_collection_plausibility

- The two macOS hosts show plausible terminal ancestry once exec transitions are included. For example, the Terminal/iTerm process is first observed with a launcher image and then changes to its application image before its child is created; shell/login descendants and their exits follow in order.
- Both macOS Endpoint Security datasets contain the expected mixture of fork, exec, and exit event types (128 total on one host; 182 on the other). The sparse Unified Log files are plausible only under a narrow filter or selected-message collection, which is not documented in the data.
- Linux hosts expose varied service and session activity in syslog, alongside shell-history files for selected users. I found no host/EDR evidence that a visible shell/process event requires an absent initiator within this six-hour slice.
- Windows Security sessions have realistic window truncation: interactive and network logons commonly remain unmatched at one edge. On the domain controllers, 162/171 and 174/183 visible logon IDs pair in order; remaining boundary records are not counted as defects.

### weak_signal

- The macOS Unified Log line count is the clearest weak synthetic/collection signal. A very selective logging predicate could explain it, but the dataset provides no filter metadata to confirm that interpretation.
- eCAR row counts are large and flow-heavy, while workstation process lifecycles are considerably smaller. Host roles and source visibility plausibly explain this spread; the distribution alone is insufficient to call the data synthetic.
- The high cross-source agreement between eCAR and Sysmon strengthens consistency, not authenticity classification. It is not counted as a synthetic clue.

## Detailed analysis

### Scope and window

The host records cover approximately **2026-11-02 13:00–19:00 UTC**. This assessment treats the data as a six-hour slice: an initiator before 13:00 or a termination after 19:00 is not required to appear. The review covered Windows Security and Sysmon XML, Linux syslog and available shell histories, macOS Endpoint Security and Unified Log, eCAR, and process/session lifecycle relationships.

### Windows

- Ten Windows hosts have paired Sysmon Event ID 1/5 process lifecycles. No paired ProcessGuid sequence had termination before creation.
- eCAR PROCESS create/terminate rows were matched against Sysmon by action, PID, and image path. The overlap is high on every reviewed Windows host: 95.1–100% of Sysmon process lifecycle rows, with 97–100% of eCAR process lifecycle rows represented in Sysmon. This demonstrates coherent shared identity and ordering; it is not used as a synthetic indicator.
- Domain-controller Security logs show substantial Kerberos and logon activity, and paired Logon IDs have no reversed lifecycle. End-of-window and collection gaps explain the remaining unmatched logon/logoff records.
- Workstation records contain varied process, module, network, registry, and authentication events. Counts differ by host rather than repeating as a fixed template.

### Linux

- Linux eCAR volumes range from a few hundred to roughly 1,400 rows per host, with process creation/termination and user-session events alongside high network volume. Syslog files contain service, SSH/PAM, and host activity; the reviewed examples include session closures at ordinary times within the slice.
- Paired eCAR process events were ordered correctly on all reviewed Linux hosts. Unmatched create/terminate records are compatible with the slice boundaries or source coverage; they do not show an impossible lifecycle.
- Shell histories are present for a subset of users and hosts. Their partial availability does not prove that commands are absent from the host activity, and copied file modification times are excluded from this assessment.

### macOS and eCAR process trees

- `MAC-MROSS-01` has 128 Endpoint Security records (48 exec, 41 fork, 39 exit); `MAC-MROSS-02` has 182. eCAR has 566 and 887 rows respectively, including process modifications, create/terminate records, and flows.
- Process tree review used PID plus event chronology, not a static PID-to-image map. macOS exec transitions legitimately change a process image without changing its PID. After accounting for `PROCESS MODIFY`, sampled child parent images match the parent image active at child creation.
- Visible process exits occur after corresponding activity; no reviewed paired process was terminated before it was created. The two/three Unified Log rows remain a coverage concern, but their messages align with login/session activity and do not contradict Endpoint Security ordering.

## Realism scores

Scores use 1 (poor) to 5 (strong). Collection completeness is scored separately from event consistency.

| Dimension | Score | Rationale |
|---|---:|---|
| Schema and native format | 4.5/5 | Structured XML/JSON/syslog records parse cleanly; no malformed host records found. |
| Process/session lifecycle | 4.5/5 | Paired Windows, Linux, and macOS lifecycles are ordered; slice-edge omissions are plausible. |
| Cross-source host consistency | 4.5/5 | High Sysmon/eCAR process agreement with coherent event identities; alignment alone is not a synthetic clue. |
| Distribution and role texture | 3.5/5 | Host counts and event types vary by role; flow-heavy distributions merit monitoring but are not impossible here. |
| Collection plausibility/completeness | 2.5/5 | macOS Unified Log contains only 2–3 records over six hours, without filter or collection metadata. |
| Overall host/EDR realism | 3.8/5 | Strong internal coherence, tempered by unexplained Unified Log sparsity and uncertainty about collection scope. |

## Recommendations

1. Record the macOS Unified Log collection predicate, subsystem/category filters, and expected retention/volume. If these files are intentionally selective, make that scope explicit in the collection manifest.
2. Preserve PID/image transition events when exporting macOS process trees; interpreting fork-time image and post-exec image as one static identity creates false parent-image alarms.
3. Keep source-specific observation coverage metadata for eCAR, Sysmon, Security, Endpoint Security, and Unified Log so missing records can be distinguished from actual companion-event defects.
4. No lifecycle repair is recommended from the reviewed host/EDR evidence. The main follow-up is to clarify macOS Unified Log coverage before increasing the synthetic verdict confidence.
