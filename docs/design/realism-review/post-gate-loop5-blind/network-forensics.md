# Network Forensics — Blind Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict confidence:** 96/100
- **Synthetic-confidence score:** 96/100

## Executive summary

The reviewer judged network structure and correlation unusually strong but identified three
source-semantic families: incorrect inbound ICMP static-NAT address projection, content-specific
IDS alerts attached to incompatible HTTP requests, and service labels on payload-free bad-checksum
Zeek connections. These are network/protocol/projection findings scheduled for Batch 3.

## Evidence supporting synthetic

- ASA inbound ICMP records render the public VIP as both `gaddr` and `laddr`. At ASA line 265,
  source `185.249.5.220` targets public `45.83.220.5`, while Zeek, IDS, and endpoint telemetry show
  the translated destination `10.44.30.10`; `laddr` nevertheless remains `45.83.220.5`. The emitter
  statically sets both fields from `net.dst_ip` and ignores the event's NAT context for ICMP.
- Three SID `2012647:6` “PHP Possible file upload” alerts join to zero-body GETs for `/`,
  `/dashboard`, and `/assets/main.css`. A fourth alert in the file carries the same signature. This
  recurs from the pre-gate IDS predicate family.
- Payload-free `OTH/Cc` rows carry services such as `ssl`, `krb`, `smb`, and `ldap`. The output
  evidence is accepted as a Batch 3 candidate, but native Zeek analyzer semantics still require a
  primary-source reference check before final source-fidelity disposition.

## Evidence supporting real

- All 1,023 DNS, 649 HTTP, 1,011 TLS, and 750 file rows joined to existing connection UIDs.
- DNS RTT, protocol timing, file timing, tuple identity, and byte accounting were generally
  coherent; 2,535 of 2,536 ASA TCP builds matched a Zeek tuple near the same second.
- All 554 certificate references resolved, certificate validity covered observation time, SAN/SNI
  relationships were credible, and resumed sessions omitted chains.
- The sampled web transaction joined across Zeek conn/HTTP, web access, ASA, eCAR, and IDS with
  exact accounting conservation.

## Scores

| Category | Score |
|---|---:|
| Field and native-format realism | 86 |
| Temporal realism | 84 |
| Cross-source correlation | 96 |
| Behavioral realism | 75 |
| Environmental realism | 77 |

## Disposition

ICMP NAT projection and IDS semantic prerequisites are accepted into Batch 3. Payload-free service
assignment remains accepted as a reproducible candidate pending the planned primary-source check.
None belongs to the completed post-Batch-2 gate family.
