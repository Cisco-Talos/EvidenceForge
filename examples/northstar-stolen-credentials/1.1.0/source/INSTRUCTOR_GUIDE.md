# Northstar Health - Stolen Credentials: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence. The guide and scenario.yaml reveal the intended sequence.

## Learning questions

1. Which workstation originates the authentication failures, and which accounts are targeted?
2. Where do Daniel's credentials appear next, and what does the source workstation's credential-use event establish?
3. Which firewall decision applies to the RDP attempt? Is there a corresponding successful remote-interactive logon on the file server?
4. What scope does the evidence support?
5. How do Jordan's mounted-share access and the management workstation's WinRM traffic differ from the incident?

## Intended interpretation

The intruder begins with a foothold under Maya on NSH-CLIN-01 and already has Daniel's IT credentials. Initial entry and credential theft are outside scope. Authentication attempts against several domain accounts fail at NSH-DC-01. The clinical workstation then records explicit use of Daniel's credentials for NSH-FILE-01. The firewall denies the RDP connection before the file server can authenticate it. The modeled compromise stays on NSH-CLIN-01.

## Authored timeline

| Offset | Account context | System | Intended activity |
|---|---|---|---|
| +1h | maya.patel | NSH-CLIN-01 | The intruder enumerates domain users from the existing user session. |
| +1h5m | maya.patel | NSH-DC-01 | Several domain accounts record failed authentication attempts from NSH-CLIN-01. |
| +1h14m | maya.patel | NSH-CLIN-01 | The workstation records explicit use of Daniel's credentials for NSH-FILE-01. |
| +1h16m | maya.patel | NSH-CLIN-01 | The firewall denies the workstation's RDP connection to NSH-FILE-01. |

## Benign comparisons

- At +35m, Jordan uses his own account and assigned Linux workstation to access the clinical share.
- At +4h, Ethan uses his separate admin account for routine administration. The authored evidence models the permitted WinRM over HTTPS connection from NSH-ADMIN-01 to NSH-FILE-01.

## Evidence acceptance

Verify source-side Windows credential use, the Cisco ASA denial, and the permitted WinRM flow against run ground truth and the collection manifests. The WinRM event models network transport. Attribution to Ethan's admin account comes from the scenario context. Check file-server coverage at the time of the denied connection when assessing the absence of a matching successful logon.
