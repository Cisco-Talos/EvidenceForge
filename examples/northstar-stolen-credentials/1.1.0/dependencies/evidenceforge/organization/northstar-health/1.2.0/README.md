# Northstar Health network

The organization model uses one stateful firewall for inter-zone traffic and the internet edge. Each zone has its own firewall interface. Only the SMTP relay in the mail DMZ has a public NAT mapping for inbound traffic. Staff connect to the internal mailbox server for submission and access. The mailbox server exchanges internet mail through the relay.

## Deployment controls

- Reserve the management workstation for privileged work. Use named administrative accounts separate from daily-use accounts. If remote administration is enabled, require phishing-resistant MFA on the access gateway and restrict it to managed administrative devices. The modeled network has no internet-facing management listener.
- Send ASA permit, deny, and NAT records, Zeek connection and protocol records, Active Directory authentication and DNS logs, Postfix and Dovecot logs, Windows file-share audit, and Samba audit to a central collector. Use authenticated, encrypted forwarding, synchronize source clocks, and restrict collector access. Alert on lost feeds, denied access to management, and administration from an unexpected source.
- Before production enforcement, verify the actual AD, DNS, file, and mail dependencies, including any Windows RPC requirements. Pilot the allowlist with both Windows and Linux clinical clients and exercise rollback. Plan redundant gateways and identity services if this topology is used as a production design.

EvidenceForge generates synthetic records for the modeled paths. MFA enrollment, log shipping and retention, and production availability are deployment controls.
