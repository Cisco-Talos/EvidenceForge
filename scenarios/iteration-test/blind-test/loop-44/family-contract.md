# Loop44 family contract: ASA native endpoint and reset roles

Classification: `family_level` for shared security-side semantics and observation
reason planning; `source_native_single_schema` for ASA wire endpoint ordering;
`adapter_to_family_model` for direct-emitter compatibility and parser normalization.

Owner: canonical topology resolves interface/security facts; the network observation
planner owns the frozen teardown reason. A pure ASA semantic helper maps reset sender
to security side. The ASA emitter serializes the already-owned endpoints in native
foreign/local order and keeps each endpoint's real/mapped address pair together.
The eval parser interprets that native representation rather than demanding the
previous incorrect originator-first shape.

Invariant: changing transport initiator never changes the meaning of Reset-I/O.
RSTO is the originator's reset; RSTR/REJ are the responder's. I/O denotes relative
higher/lower interface security. Unknown/equal interface relationships and midstream
capture gaps alone must not fabricate a qualified reset side. Preserve transport
identity, close timing, packet accounting, connection IDs and NAT truth.

Entry paths: baseline/storyline/causal canonical connections, sensor observation
planning, exact ASA publications, direct-emitter compatibility and unmatched parser
rows. Consumers: TCP/UDP build/teardown and NAT output, authoritative eval/parsers,
correlation checks, focused tests and rendered family probes. Raw syslog remains an
explicit escape hatch.

Sibling coverage: inbound/outbound TCP and UDP; source PAT/destination NAT; custom
and conventional security levels; originator/responder resets; non-reset OTH;
same-interface/equal-level ambiguity. ICMP keeps its separate native faddr/gaddr/laddr
contract. Connection-order correction must not reverse native NAT translations or
Deny src/dst semantics. Parser teardown inference may use only a matching build;
standalone teardown rows retain explicit native endpoint roles without inventing
initiator identity. Remaining application/stream-capture accounting is deferred to
its owning family, not repaired here.

Verified before editing: loop43 probe finds4,528 outbound TCP builds and7 outbound
UDP builds in originator-first layout, with60 unambiguous reset-side inversions.
Cisco message definitions and its outbound PAT example were independently checked.

## Verification after fresh generation

The focused gate passes198 tests plus the explicitly selected slow teardown-timing
contract. Ruff check/format pass. Revision443 binds the complete behavior surface.
The fresh bundle has136,813 records /117 files and passes every hard criterion at
96.3093508229. All116 non-ASA data files match loop43 byte-for-byte.

Rendered probe:8,519 builds; zero qualified interface-order errors;179 qualified
reset comparisons and zero side mismatches. The27 equal-security builds remain
explicitly unqualified. Source PAT/destination NAT and custom interface names have
focused source-to-parser checks; unmatched/mismatched teardown rows do not invent
initiator identity. Mac native census remains89/89 forks,107/107 execs,87/87 expected
exits and zero aggregate births. Mounted helpers retain4/4 native exits. The prior
Mac fraction and inventory-duration repairs remain unchanged.

The independent blind panel is running; the completed loop report must retain its
initial scores and qualify any movement against this objective change scope.
