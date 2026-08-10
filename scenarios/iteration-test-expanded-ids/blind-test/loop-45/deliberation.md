# Deliberation Summary

## Deliberation Basis

The panel entered deliberation with a 50-point synthetic-confidence spread and three different
verdicts. The facilitator treated the four independent reports as expert positions, then checked
the disputed concrete claims against the blind data. Narrative neatness, attack completeness,
ease of reconstruction, missing false starts, and complete cross-source matching were explicitly
excluded as authenticity indicators. Thin source coverage and absent event families were also
excluded unless the visible records created a required-companion or collection-profile
contradiction.

## Round 1 — Initial Findings

### Threat Hunter

**Initial position:** Synthetic, verdict confidence 78, synthetic-confidence 66.

The hunter's strongest evidence was environmental and distributional: APP-INT-01 repeatedly ran
a root/systemd-owned `proxy_healthcheck.py` against a broad mix of ad-tech, analytics, package,
and CDN destinations; successful TTY-backed sudo activity reused six generic identities and a
small command pool across unrelated Linux roles; and the initial web compromise combined an
upload request, a SQL `UNION SELECT` diagnostic, and direct Apache-child command execution without
a visible semantic bridge. The hunter uniquely emphasized baseline actor/host-role ownership while
also finding the intrusion mechanics, process lifecycles, and session ordering technically sound.

### Detection Engineer

**Initial position:** Synthetic, verdict confidence 86, synthetic-confidence 78.

The detection engineer identified the panel's strongest exact correlation defects. Thirteen
DB-PROD-01 `wget` actors advertised `https://internal-service/` in their command line but their
exact source-port-matched proxy requests CONNECTed to unrelated public hosts. On MAIL-CLIN-01, one
long-lived Postfix `smtpd` process identity owned 21 Python-Requests proxy transactions and also
owned unrelated outbound LDAP and generic port-probe traffic. The repeated, exact-tuple nature of
these findings distinguished them from a vague role-plausibility concern. The engineer also found
strong source-native Windows schemas, correct process lifecycles, independent Zeek UIDs, and
coherent ASA accounting.

### Network Forensics Analyst

**Initial position:** Inconclusive, verdict confidence 74, synthetic-confidence 44.

The network analyst found highly credible protocol state, byte and packet accounting, TLS/cipher
semantics, certificate truncation behavior, DMZ scanning texture, DNS diversity, explicit-proxy
behavior, and child-record lifetimes. The main reservations were nearly fixed per-client DHCP
renewal intervals and a narrow, always-positive core-to-DMZ sensor offset across 1,930 matched
flows. Both were considered suspicious but plausibly explained by T1 timers and stable clock skew.
The analyst uniquely established that the network facts themselves were internally coherent.

### Host/EDR Forensics Analyst

**Initial position:** Real, verdict confidence 82, synthetic-confidence 28.

The host analyst found no same-identity process or session lifecycle inversions across extensive
eCAR, Security, and Sysmon checks. Windows lock/unlock semantics, ProcessGuid usage, parent-child
behavior, Linux SSH/PAM/logind phases, source-specific collection delays, and the Security-log
clear were all production-like. The principal reservations were an exact estate-wide total of
4,096 Sysmon records and unusually concentrated SSH administration by two users. The analyst
uniquely demonstrated the depth of source-native endpoint lifecycle correctness.

## Round 2 — Cross-Examination

### Process correctness versus process meaning

The central disagreement was not whether process identities and lifetimes were well formed; all
four reports supported that conclusion. It was whether a perfectly valid process identity could
still own semantically impossible or highly implausible activity. The detection findings answered
yes. Blind-data verification found 18 DB-PROD-01 `wget` creates with the same `internal-service`
command line. Thirteen had an actor-owned FLOW, exactly one FLOW per actor, and all 13 source ports
joined to proxy CONNECT records for other hosts, including `packages.microsoft.com`,
`changelogs.ubuntu.com`, `api.snapcraft.io`, `pypi.org`, `images.formstack.io`, and
`js.docusync.app`. No visible initiating request or redirect explains the destination transition.
This does not invalidate the host analyst's lifecycle work; it shows that lifecycle correctness and
semantic ownership are separate authenticity dimensions.

### Postfix actor attribution

The Postfix finding also survived exact-tuple verification. The cited `smtpd` object owned 106
visible FLOW records. Twenty-one were client-to-proxy transactions, and all 21 joined to Zeek HTTP
CONNECT records whose user agent was `python-requests/2.31.0`; their hosts spanned ad, analytics,
package, monitoring, and CDN properties. The same actor also owned 55 outbound LDAP/389 flows and
multiple outbound 80, 443, 8080, and 8443 attempts, in addition to plausible inbound SMTP traffic.
A long-lived listener can legitimately own many accepted SMTP sockets, but native Postfix `smtpd`
does not become the same OS process as a Python Requests client or a generic network scanner. A
content filter or helper would normally have its own process identity. A compromised process is an
alternative explanation in principle, but no visible evidence supports that explanation and the
uniform six-hour reuse across unrelated traffic families makes it weak.

### Baseline-role texture

The hunter's APP-INT-01 claim was reproduced: 54 root/systemd-owned healthcheck creates included 26
requests to `internal-service` and 28 requests spread across 25 public targets, including unrelated
analytics, advertising, package, monitoring, and CDN names. This is possible only under an unusually
broad synthetic-monitor policy, but no visible naming or process specialization supports such a
policy. It therefore remains a strong `environment_or_collection_plausibility` indicator, though
weaker than the exact process/proxy ownership gaps.

The sudo concern was also systematic. The blind syslogs contain 69 successful TTY-backed sudo
commands across nine Linux hosts using the same six recurring generic identities. Exact commands
such as `ss -s`, `systemctl list-timers --all --no-pager`, and `iptables -L -n -v` each appear on
four hosts. This is meaningful `distribution_texture`, but it is not a hard contradiction because
shared operations accounts and standardized runbooks are possible.

### Strong realism evidence challenged

The network and host findings remained persuasive after challenge. No expert found impossible
same-object ordering, source-native format failures, invalid transport accounting, or protocol
children outside connection lifetimes. Independent source delays, differentiated DMZ scanning,
capture-loss-dependent X.509 parsing, correct Windows event shapes, Linux SSH phase ordering, and
the Security EventRecordID reset are positive realism evidence, not suspicious completeness.

However, those strengths do not explain the two repeated semantic-ownership families. Exact tuple
correlation actually makes the conflict more specific: the network request is not merely nearby in
time; it is the request attributed to the incompatible endpoint actor.

### Weak or rejected indicators

- The narrow positive core-to-DMZ offset remains explainable by stable sensor skew and receives
  only low weight.
- Stable DHCP intervals remain explainable by client/server T1 behavior and receive low weight.
- The exact 4,096 Sysmon total was reproduced, but it is compatible with a central export cap and
  receives only weak collection-plausibility weight.
- Absent NTP is not scored: a six-hour slice can miss NTP, and absence alone is not a valid source
  coverage signal.
- Dense SSH/RDP activity is not scored without stronger role evidence.
- The upload/SQL/RCE combination remains a moderate semantic concern, not a decisive defect; one
  application request can traverse multiple vulnerable code paths.
- The intrusion's linearity, completeness, compactness, and ease of narration are excluded.

## Round 3 — Revised Positions

### Threat Hunter

**Final position:** Synthetic, verdict confidence 88, synthetic-confidence 74.

The hunter raises both values because the detection engineer's exact actor/tuple checks provide
stronger contract evidence than the hunter's original role-texture observations. The absence of
hard ordering or schema contradictions keeps the synthetic-confidence score below the top band.

### Detection Engineer

**Final position:** Synthetic, verdict confidence 91, synthetic-confidence 80.

The engineer's verdict is reinforced by reproduction of all 13 `wget` mismatches and all 21
Postfix/Python proxy joins. The score rises only slightly because the host and network experts
demonstrated substantial production-like detail, and the panel did not establish an impossible
timestamp, impossible field value, or explicit generator identity leak.

### Network Forensics Analyst

**Final position:** Synthetic, verdict confidence 79, synthetic-confidence 67.

The analyst changes from Inconclusive after accepting that exact network tuples expose repeated
endpoint ownership contradictions even though the network records themselves remain highly
realistic. The lower score relative to the hunter and detection engineer reflects the strength of
the network protocol, timing, and capture-loss texture.

### Host/EDR Forensics Analyst

**Final position:** Synthetic, verdict confidence 81, synthetic-confidence 69.

The analyst changes from Real because the two decisive defects are present in host eCAR actor
fields: valid lifecycles repeatedly attach network activity to processes whose command and function
do not support it. The score remains moderate rather than extreme because the previously verified
Windows, Sysmon, eCAR lifecycle, and Linux session behavior still stands.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 78 | 66 | Synthetic | 88 | 74 |
| Detection Engineer | Synthetic | 86 | 78 | Synthetic | 91 | 80 |
| Network Forensics | Inconclusive | 74 | 44 | Synthetic | 79 | 67 |
| Host/EDR Forensics | Real | 82 | 28 | Synthetic | 81 | 69 |

## Consensus Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 89  
**Synthetic-Confidence Score:** 74

The consensus is likely synthetic, not confidently synthetic in the rubric's highest band. Two
repeated, exact-tuple process-ownership contract gaps are difficult to reconcile with organic
endpoint behavior, and independent baseline-role texture supports them. At the same time, the
dataset has unusually strong source-native field formats, lifecycle ordering, protocol semantics,
capture-loss behavior, and timing variation. Those qualities materially limit the consensus score.

## Key Agreements

- Windows, Sysmon, Linux SSH, Zeek, ASA, proxy, TLS, and certificate records are structurally and
  temporally strong; no hard same-identity ordering contradiction was found.
- The DB-PROD-01 `wget` command/proxy-host mismatch and MAIL-CLIN-01 Postfix/Python ownership issue
  are concrete cross-source contract gaps rather than narrative-completeness signals.
- DHCP regularity, cross-sensor offset, the 4,096-record Sysmon total, and dense remote
  administration are at most supporting signals and cannot carry the verdict.
- Complete correlation is neutral by itself. Here it matters only because exact tuple joins reveal
  semantic disagreement between the process and the request.

## Key Disagreements

The remaining disagreement is primarily one of weight. The detection engineer views the repeated
actor attribution defects as near-top-band evidence because they affect every inspected member of
two behavior families. The network and host analysts give more weight to the absence of impossible
lifecycle or protocol behavior and therefore retain lower synthetic-confidence scores. The panel
does not claim that the network layer or Windows event families alone would support a Synthetic
verdict.

## Most Convincing Evidence

1. **DB `wget` process/request disagreement (`contract_gap`):** all 13 actor-owned flows from
   short-lived `wget ... https://internal-service/` processes exact-match proxy CONNECTs to other
   hosts, with no visible initiating request or redirect.
2. **Postfix/Python actor mismatch (`contract_gap`):** one `smtpd` identity exact-matches 21
   Python-Requests proxy transactions and additionally owns broad LDAP and probe traffic.
3. **APP healthcheck destination ownership (`environment_or_collection_plausibility`):** a
   root/systemd healthcheck rotates across 25 public targets from unrelated operational and
   consumer-web categories rather than a bounded application dependency set.
4. **Shared Linux sudo texture (`distribution_texture`):** the same small account and command pools
   recur through application, database, mail, proxy, DMZ, laptop, and workstation roles.
5. **Countervailing production realism:** source-native event shapes, valid lifecycles, protocol
   accounting, independent sensor texture, and coherent capture loss prevent a higher score.

## Most Debated Points

- Whether perfect lifecycle mechanics can outweigh incorrect semantic process ownership. The panel
  concluded they are independent dimensions, and repeated ownership gaps are more probative.
- Whether the Postfix identity could represent a helper, instrumentation artifact, or compromise.
  No visible process boundary or compromise evidence supports those alternatives.
- Whether broad healthcheck destinations and shared sudo accounts could reflect unusual but real
  operations. They can, so these remain supporting rather than decisive evidence.
- Whether fixed DHCP cadence and a stable cross-sensor offset are synthetic. Both have ordinary
  implementation explanations and receive little weight.

## Improvement Recommendations (Consensus)

- Bind every endpoint FLOW actor to the process that owns the socket. Validate exact endpoint/Zeek
  tuple joins against process-family invariants so listener daemons cannot absorb unrelated client
  traffic.
- For command-line clients such as `wget`, derive DNS, proxy CONNECT host, TLS SNI, and destination
  from the command URL. If redirects are modeled, emit the initiating request and redirect response
  before the new-host transaction.
- Separate Postfix listener, content-filter/helper, directory lookup, monitoring, and Python HTTP
  activity into source-native process identities and parent-child relationships.
- Bind service healthchecks to small, role-specific dependency inventories. Use separate named
  monitors for package repositories or third-party SaaS dependencies when those checks are
  intentional.
- Replace the estate-wide Linux sudo account/command pool with host-role and identity-specific
  operating models, reserving service identities for non-TTY execution unless an explicit
  interactive exception is modeled.
- Preserve the existing lifecycle, source-native schema, network accounting, sensor-delay,
  capture-loss, and boundary-handling quality while fixing ownership semantics.
