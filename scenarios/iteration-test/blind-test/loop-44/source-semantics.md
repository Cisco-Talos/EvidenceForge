# ASA source semantics

[Cisco's message definitions](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html)
identify reset I/O by inside/outside side. Their SCTP field description explicitly
relates outside/inside to lower/higher security levels. Applying that relationship
to TCP reset sides is the modeled security-level interpretation, not a claim that
all equal-security or hairpin cases are empirically calibrated. Such cases remain
unqualified and receive no invented I/O reset label.

[Cisco's outbound PAT example](https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/15243-19.html)
places the external endpoint first and the internal endpoint, with its translated
address, second. The repair preserves these real/mapped pairs for both initiation
directions and for TCP/UDP. NAT translation messages and explicit Deny src/dst
records retain their distinct semantics.

An unmatched teardown does not identify an initiator. Parser orig/resp fields now
require a matching build with the same hostname, connection ID, protocol and native
endpoint tuple. Native foreign/local fields remain available independently. The
build cache is bounded; evicted or mismatched closes remain unqualified.

The carried TCP accounting finding is checked against [Zeek's Conn::Info definitions](https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html).
TCP payload totals use sequence numbers; IP/packet volume and content-gap counts
have distinct meanings. This issue is unchanged by the ASA repair.
