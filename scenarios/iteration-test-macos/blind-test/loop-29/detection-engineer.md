# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 57

## Executive Summary

The records are largely convincing and should support ordinary SIEM parsing and correlation. My tentative synthetic verdict rests on a concentrated temporal fingerprint in the two Macs' utility executions: 18 of 20 qualifying consecutive execution intervals fall within 20 milliseconds of a whole number of seconds, despite ranging from approximately 22 to 65 seconds. I found no demonstrated hard contradiction in the bounded schema, identity, lifecycle, and network-reference checks; scripted real activity remains a credible alternative.

## Evidence For Synthetic

- [distribution_texture] Both `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` and the corresponding `MAC-MROSS-02` file contain utility-command bursts whose execution times preserve almost the same fractional second across long gaps. On MAC-MROSS-01, lines 33/36/39 execute `pwd`, `ls`, and `du` at `13:48:48.728362`, `13:49:18.729299`, and `13:50:08.724928` UTC: gaps of **30.000937** and **49.995629** seconds. On MAC-MROSS-02, lines 115/118/121 execute `du`, `df`, and `ps` at `17:33:09.354077`, `17:33:57.356931`, and `17:34:45.358394`: gaps of **48.002854** and **48.001463** seconds. The bounded measurement described below finds this texture in 18/20 eligible intervals, not just these examples. This suggests whole-second activity scheduling with a small rendering offset. Automation could produce it, so this is a distribution indicator rather than impossible behavior.

## Evidence For Real

- Windows source identities and event-specific shapes are convincing. In `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml`, record 948745 is a version-2 4688 with hexadecimal process IDs, `TokenElevationType`, target-subject fields, `ParentProcessName`, and `MandatoryLabel`; record 948849 is a version-2 4624 for NETWORK SERVICE, Type 5, with SID `S-1-5-20`, reserved LUID `0x3e4`, and local service semantics rather than a fabricated remote address.
- `DC-01.meridianhcs.local/windows_event_security.xml` uses the Eventlog provider and namespaced `UserData/LogFileCleared` for 1102 at `18:41:52.1514680Z`, with EventRecordID 1. Subsequent records include record 422 at `18:50:15.8464084Z`. This handles the observable log-clear record-number reset plausibly.
- The core Zeek records retain consistent UID and tuple relationships. All checked DNS, HTTP, SSL, SMTP, SMB file, and SMB mapping rows resolve to a `zeek-core/conn.json` UID with the same originating/responding addresses and ports. None of these companion timestamps was more than 0.1 second before connection start or 0.5 second after its reported end.
- SSH evidence has sensible transport-before-authentication ordering. `zeek-core/conn.json` line 1121 observes `10.10.1.42:61323 → 10.10.2.30:22`, UID `Cl5AqBVwAGJF0DHIM`, at `13:43:50.155411Z`. `APP-INT-01.meridianhcs.local/ecar.json` line 55 records its inbound FLOW at `13:43:51.558Z`; syslog lines 64–66 show connection, public-key acceptance, and PAM opening at `13:43:55.315519`, `.577767`, and `.631860`. eCAR line 58 then records the session login at `13:43:57.153Z` with the same source tuple.
- Native Mac credentials have meaningful detail. MAC-MROSS-01 ES line 5 shows `/usr/bin/login` executed by an actor with effective UID 501, becoming effective UID 0 while retaining real UID 501. Its recorded file mode is `0104555`, including the setuid bit, so the privilege transition is internally justified. MAC-MROSS-02 line 7 has the same coherent relationship through its iTerm helper.

## Detailed Analysis

### Scope and parsing

I inspected only the supplied data. The bounded sample emphasized WS-MCHEN-01, DC-01, WS-AJOHNSON-01, both Macs, representative APP-INT-01 and MAIL-EDGE-01 syslog records, and the core Zeek sensor. I parsed actual XML and JSON records; this is not an exhaustive audit of all hosts or a vendor conformance certification.

The Windows field review included first representatives of Security IDs 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4800, 4801, and 5156 on WS-MCHEN-01, plus Sysmon IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22. I also examined DC examples including 4768, 4769, 4771, 4697, 4698, 4779, and 1102. The observed source shapes, SID/GUID syntax, numeric versus hexadecimal field conventions, channel/provider selection, and timestamp representations did not establish a schema defect. The 4698 TaskContent at `17:20:27.5042004Z` also parses as nested XML after extraction from EventData.

### Process and session integrity

I checked the complete Sysmon files for the three sampled Windows hosts: 434 rows on WS-MCHEN-01, 4,350 on DC-01, and 479 on WS-AJOHNSON-01. For GUIDs with visible creation or termination records, I compared `UtcTime` on ordinary, source-process, and target-process references. There were no references preceding their visible creation or following their visible termination. A separate chronological pass over these hosts' Security records found no 4688 subject LUID used after a visible 4634 without an intervening new 4624 for that LUID. Pre-window identities and post-window closures were not counted as defects.

Both Mac ES files parse, containing 152 and 151 rows respectively. Checks of the actor and exec/fork target `(pid, pidversion)` pairs found no pair mapped to conflicting executable paths. No actor event timestamp preceded its recorded process start time. Native exec targets, audit identities, and normalized eCAR process modifications were treated as separate source views; I did not apply Windows process-creation semantics to Mac exec notifications.

The AppleSystemPolicy message on MAC-MROSS-01 at `15:41:46.250414Z` says policy “would not allow” MeetingAssist. That message alone does not prove a denied execution, and the ES notification result fields are not independent proof that an authorization request was granted or denied. I did not score these as contradictory evidence.

### Reproducible temporal measurement

For each Mac ES file, extract rows containing `event.exec`. Retain targets whose executable is one of:

`/usr/bin/id`, `/usr/bin/sw_vers`, `/usr/bin/uname`, `/bin/pwd`, `/bin/ls`, `/usr/bin/du`, `/bin/df`, `/bin/ps`, `/usr/bin/find`, `/sbin/ifconfig`, `/usr/bin/dscl`.

In file order, compare each retained row with the previous retained row. Include a pair only when both target PPIDs match and the timestamp gap is between 15 and 90 seconds inclusive. Measure `abs(gap - round(gap))` using the native ES `time` field.

- MAC-MROSS-01: **8/9** intervals are within 0.020 second of a whole second.
- MAC-MROSS-02: **10/11** meet that threshold.

Additional concrete pairs are MAC-MROSS-01 lines 50→53, **36.984507 s**, and 53→56, **52.002200 s**; MAC-MROSS-02 lines 89→92, **44.000066 s**, and 130→133, **64.996606 s**. This is considerably more concentrated than freely timed interactive commands would suggest. However, the user is the same on both devices, and automation, paced testing, or an operational checklist could explain a substantial part of it. I therefore give this finding moderate weight, not the weight of a native-field impossibility. Integer-second shell-history timestamps themselves were not used as evidence.

### Network source behavior and uncertainty

I parsed all 11,497 core connection rows and checked protocol UID/tuple links and the timestamp bounds stated above. The connection sample contains failed, rejected, reset, partial, and successful TCP states, plus UDP and ICMP activity; it does not consist solely of successful, identical-looking flows. File-transfer sizes individually fit within their corresponding directional connection payload counts in the checked core data.

Two HTTP connections have aggregate `files.seen_bytes` slightly above directional conn payload counts. I did not score that as a contradiction: application decoding, content compression, and the rows' nonzero missing-byte accounting prevent a reliable wire-byte equality claim without more evidence. Likewise, selected source coverage and missing out-of-window initiators were neutral. Successful reference checks support usability, but their completeness alone says nothing about provenance.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native Mac ES execution timestamps | Two hosts; 18/20 qualified utility intervals near whole seconds | Main reason for a tentative synthetic verdict and a score in the mixed 41–60 band; automation remains plausible |
| hard_contradiction / contract_gap / schema_or_format | Sampled Windows, Mac, Linux, and core Zeek | Bounded checks described above | No demonstrated issue; no penalty assigned |

## Realism Score by Category

- **Field format accuracy:** 9 — The parsed source-specific structures and sampled event fields are convincing; review was not exhaustive.
- **Temporal patterns:** 6 — Mac utility execution intervals show a repeated whole-second anchor with millisecond-scale variation.
- **Cross-source correlation:** 9 — Sampled lifecycle identities, network references, tuples, and SSH ordering hold together.
- **Behavioral realism:** 8 — Activity is plausible, although repeated paced utility groups admit a templated explanation.
- **Environmental consistency:** 9 — Sampled service identities, host-local process paths, credential transitions, and remote-source relationships are coherent.

## Recommendations

- If this were synthetic and the utility bursts are intended to depict human interaction, vary execution intervals continuously rather than preserving a common fractional-second anchor across 30–65-second gaps. Preserve the existing process lineage and source timestamp relationships.
- If those bursts intentionally model automation, retain their paced timing. The observed concentration would then be explainable operational behavior rather than something requiring randomization; the present logs alone do not establish which interpretation is intended.
