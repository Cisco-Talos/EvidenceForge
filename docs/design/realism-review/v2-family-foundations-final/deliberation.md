# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 82 | 66 | Synthetic | 94 | 85 |
| Detection Engineer | Synthetic | 98 | 94 | Synthetic | 99 | 95 |
| Network Forensics | Inconclusive | 82 | 47 | Synthetic | 88 | 78 |
| Host/EDR Forensics | Synthetic | 99 | 96 | Synthetic | 99 | 97 |

The Threat Hunter strengthened their existing Synthetic position after the Detection Engineer and
Host/EDR analyst independently established that the Windows temporal defects were widespread rather
than isolated. The Detection Engineer retained the verdict and raised verdict confidence slightly;
the Host/EDR findings corroborated the same Sysmon and eCAR lifecycle failures while adding
build-specific identity and RDP ancestry evidence. The Network Forensics analyst revised from
Inconclusive to Synthetic after cross-examination because the endpoint findings are source-native
impossibilities that DNS caching, collection filtering, or sensor placement cannot explain. That
revision still preserves the analyst's original judgment that the network telemetry, considered by
itself, sits much closer to the authenticity boundary than the endpoint telemetry.

## Key Agreements

- The panel agreed that the dataset is operationally useful and often highly convincing. All four
  reports described strong tuple, identity, or protocol correlation, and three highlighted
  especially credible RDP, SSH/SCP, proxy, Windows-account, service-installation, or log-clear
  sequences.
- The Threat Hunter, Detection Engineer, and Host/EDR analyst independently identified the same
  eCAR PowerShell PID `6496` contradiction: termination at `17:19:40.246Z` is followed by five
  module loads for the same process identity through `.293Z`. The panel treated this as a direct
  lifecycle impossibility, not an observation gap.
- The Detection Engineer and Host/EDR analyst independently measured the broken Sysmon time
  population across seven Windows hosts. Their counts and examples agree that at least 105 Event
  1/5 records claim an embedded occurrence time more than one second after the enclosing event was
  recorded, with some offsets lasting minutes or hours and unrelated processes converging on the
  same future millisecond anchors.
- The panel agreed that network construction is a relative strength. Zeek child ownership, sensor-
  specific UIDs and timing, TLS/certificate behavior, DHCP renewal jitter, connection-state
  histories, OS-specific ephemeral ports, firewall lifecycles, and proxy byte accounting were all
  described as realistic and internally useful.
- The panel agreed that the absence of UDP/123 traffic is conspicuous in a richly observed mixed-OS
  environment. It remains a plausibility concern rather than a hard contradiction because filtering,
  another time source, or polling outside the window could explain it.
- The panel agreed that strong correlation is not itself evidence of synthetic origin. The final
  verdict rests on concrete source-native contradictions and family-specific contract gaps, not on
  the dataset being unusually complete.

## Key Disagreements

- The largest initial disagreement was whether the convincing network evidence justified an
  Inconclusive verdict. The Network Forensics analyst found no tuple, duration, payload, certificate,
  or child-ownership contradiction and treated proxy DNS ordering as cache-ambiguous. The endpoint
  specialists, however, supplied repeated records whose own occurrence times lie after their
  headers, dependents that precede creation or follow termination, and children that precede visible
  parents. Because those alternatives cannot be explained by network collection boundaries, the
  Network Forensics analyst revised to Synthetic while keeping a lower synthetic-confidence score
  than the endpoint specialists.
- Human shell behavior remained mixed. The Threat Hunter considered one 34-command, 219-second
  administrative burst and exact command reuse across distinct users and hosts generator-like. The
  Host/EDR analyst found the broader Bash histories role-specific and human-textured, including an
  organic-looking typo. The panel reconciled these observations as compatible: the overall Linux
  population can be varied while a particular dense burst and several shared templates remain weak
  or moderate synthetic signals. They did not drive the consensus verdict.
- Proxy DNS causality remained disputed in strength. The Network Forensics analyst identified
  repeated upstream TCP/TLS opens before the only visible same-name A lookup, including a late-window
  `cache.rollbar.org` answer with a 30-second TTL. Other reports emphasized otherwise excellent proxy
  leg and byte correlation. The panel retained this as a significant contract gap but not a hard
  contradiction because an unseen or stale cache can explain at least some cases.
- Hash evidence required a scope clarification. The Detection Engineer found stable hash bundles
  for the same image/version and no collisions between unrelated binaries. The Host/EDR analyst's
  narrower finding was that `winlogon.exe` and `userinit.exe` reuse complete hash bundles across
  visibly different Windows builds while adjacent binaries vary by build. The general stability
  observation does not refute that specific cross-build incompatibility, so the panel retained the
  latter as a strong synthetic indicator.
- The Threat Hunter's missing reverse-shell pipeline children were not independently replicated by
  the other specialists. The alternative explanation is incomplete process collection, but the
  outer Bash PID also owns the socket and the same source reportedly represents other pipeline
  children. The panel therefore retained it as a strong localized contradiction below the
  independently corroborated Windows defects.

## Most Convincing Evidence

1. **Widespread impossible Sysmon occurrence times.** The Detection Engineer and Host/EDR analyst
   independently found at least 105 Event 1/5 records across seven hosts whose payload `UtcTime` is
   more than one second later than `System/TimeCreated`; some are minutes or hours later, and
   unrelated processes reuse nearly identical future anchors. This is broad, source-native, and
   independently corroborated.
2. **Dependent activity after process termination.** Three experts identified the same eCAR
   PowerShell PID `6496` sequence in which five foundational DLL loads occur 10–47 milliseconds
   after termination for the same process UUID. This has no ordinary collection-delay explanation.
3. **Windows family-specific lifecycle and identity failures.** Detection and Host/EDR evidence
   combines child-before-parent Security 4688 ordering, RDP bootstrap ancestry that uses PID 4
   instead of the otherwise observed `smss.exe` chain, missing parent/subject identity, blank
   successful-logon fields, and FILE-SRV-01 `WorkstationName` values that name the responder rather
   than the remote initiator.
4. **Build-incompatible bootstrap binary identity.** Complete `winlogon.exe` and `userinit.exe`
   hashes repeat across Windows builds 17763, 19041, 20348, and 22621 while `explorer.exe` and
   PowerShell vary appropriately. The selective exception is more indicative than generic same-file
   hash stability.
5. **Collapsed reverse-shell pipeline ownership.** The Threat Hunter found a Bash command that
   necessarily invokes decoder and downstream-shell children, yet no such process identities appear
   and the network socket is assigned directly to the outer Bash PID. This is localized, but it
   exposes a concrete execution-versus-effect ownership gap.

## Most Debated Points

- Whether excellent network realism should outweigh endpoint contradictions. The final view is that
  it should not: it demonstrates that some source families are highly convincing, while the
  endpoint impossibilities still determine the whole-dataset verdict.
- Whether proxy-origin connections before visible DNS are impossible or cache-driven. The
  late-window, short-TTL case weakens the cache explanation, but the reports do not establish cache
  state well enough to remove all ambiguity.
- Whether shell activity is templated or human. The panel distinguished a suspiciously dense,
  repetitive subset from the broader role-specific Linux histories rather than treating either
  description as universal.
- Whether missing NTP represents generation failure or collection policy. Its agreement across the
  Threat Hunter and Network Forensics reports makes it worth fixing or explicitly accounting for,
  but not decisive for authenticity.
- Whether hash consistency is supportive or suspicious. Consistency within one binary version is
  realistic; reuse across incompatible OS builds without matching version metadata is not.

## Improvement Recommendations (Consensus)

1. Establish one canonical occurrence time per Windows event and derive Sysmon payload `UtcTime`,
   `System/TimeCreated`, Security source timing, and dependent timestamps from that occurrence.
   Reject output when a record is published before its claimed occurrence, a child precedes its
   visible parent, a dependent precedes process creation, or any process-owned event follows
   termination.
2. Route RDP bootstrap through the same complete Windows interactive-session lifecycle used by
   ordinary sessions: `smss.exe -> winlogon.exe -> userinit.exe -> explorer.exe`. Preserve the
   parent PID/GUID/image and subject SID, user, logon ID, target SID, and LogonGuid across Security,
   Sysmon, and eCAR.
3. Validate successful Windows logons against source-native field requirements. Populate real
   values or native sentinels instead of empty strings, and derive remote Type 3
   `WorkstationName` from the initiating client rather than the responding file server.
4. Make Windows system-binary identity build-aware. Generate version metadata and hashes for
   `winlogon.exe`, `userinit.exe`, and related binaries from the same per-build identity source that
   already differentiates Explorer and PowerShell; reuse a full hash bundle only for genuinely
   identical binary content.
5. Model shell pipelines as explicit process trees and attach files and sockets to the descendant
   that performs the effect. Separately, diversify administrator behavior with user-specific
   command habits, runbooks, pauses, mistakes, and task-focused bursts instead of exact shared
   templates and compressed unrelated actions.
6. Give proxy DNS caching explicit causal state. Before an upstream origin connection, require a
   still-valid cached A/AAAA result or a completed lookup; represent expiry and any stale-while-
   revalidate policy so later queries are visibly refreshes rather than apparent prerequisites.
7. Add low-volume, role-appropriate, per-host-jittered NTP traffic when infrastructure flows are in
   collection scope. If NTP is intentionally filtered or replaced, make that boundary consistently
   visible rather than fabricating companion traffic.
8. Preserve the strengths that made the review difficult: sensor-specific network observations,
   protocol-child ownership, OS-aware source ports, varied TCP outcomes, TLS-version-dependent
   certificate visibility, DHCP jitter, cross-source tuple correlation, and realistic log-clear,
   SSH/SCP, proxy, and service-installation sequences.
