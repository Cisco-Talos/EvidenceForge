# Northstar Health - Stolen Credentials: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence; this guide and scenario.yaml reveal the intended sequence.

Distinguish valid-account abuse and unusual remote administration from ordinary clinical and IT activity.

## Learning questions

1. Which host originates the authentication campaign, and which account succeeds?
2. Where does that credential appear next, and why is the source placement unusual?
3. What evidence connects the source workstation to the staged service package and service installation?
4. Which clinical files are collected and where are they staged?
5. How do Jordan's mounted-share access and Ethan's RDP session differ from the attack sequence?

## Intended interpretation

The exercise assumes an existing foothold under Maya on NSH-CLIN-01; initial entry and credential recovery are outside scope. A bounded campaign from 10.42.10.21 succeeds as daniel.kim. Explicit credential use and RDP lead to NSH-FILE-01, followed by internal management-port probes. The staged DeviceHealth package is copied through the file server's administrative share and registered as DeviceHealthCache using remote service control. Clinical documents are copied back to the source workstation. Jordan's Linux CIFS access uses the assigned clinical endpoint and own account; Ethan's later RDP session originates on the IT endpoint. Session-establishment records supply context and should be interpreted with the subsequent behavior.

## Authored timeline

| Offset / time | Actor | System | Intended activity |
|---|---|---|---|
| +1h | maya.patel | NSH-CLIN-01 | An existing clinical-workstation foothold enumerates domain users; initial entry is outside scope. |
| +1h5m | daniel.kim | NSH-IT-01 | The clinical workstation tries several known accounts and eventually authenticates as an IT operator. |
| +1h14m | maya.patel | NSH-CLIN-01 | The source foothold supplies the stolen IT credentials for remote administration. |
| +1h16m | daniel.kim | NSH-FILE-01 | The stolen IT account opens an RDP session from the clinical workstation. |
| +1h20m | daniel.kim | NSH-FILE-01 | The remote session probes management and file-sharing ports on internal servers. |
| +1h28m | daniel.kim | NSH-CLIN-01 | The stolen operator credentials copy a service package to the file server's administrative share. |
| +1h31m | daniel.kim | NSH-FILE-01 | Remote service control installs the staged package under a maintenance-style name. |
| +1h42m | daniel.kim | NSH-CLIN-01 | The stolen account enumerates the clinical file share from the foothold workstation. |
| +1h46m | daniel.kim | NSH-CLIN-01 | Clinical documents are copied to a local staging directory using valid IT read permissions. |

## Benign comparisons

- approved-linux-access (+35m): Expected Linux-to-Windows clinical access, with the coordinator's assigned endpoint and own credential.
- approved-admin-rdp (+4h): Normal IT-to-server access; the earlier RDP source is a clinical workstation and follows a credential campaign.

## Capabilities demonstrated

Published healthcare organization composition; bounded credential spray with a success; explicit credential use; canonical RDP; internal port scanning; remote service-control transport; Windows and Linux SMB client/server evidence.

## Modeling and interpretation limits

The service binary is an invented staged artifact; service registration does not prove successful service execution, and no such execution is asserted. The Windows administrative-share and clinical-share operations use separate permissions and purposes. No data destruction or external exfiltration is modeled. The scenario intentionally overrides the pack's firewall default to permit the modeled routed traffic while retaining its host/user roster.

## Evidence acceptance

This guide describes authored intent, not a reviewed generated dataset. Input validation and publication do not prove that every intended observation appears. After generation, inspect the run-owned GROUND_TRUTH.md/JSON, collection/observation manifests, relevant artifacts and exact process/session/network relationships, then evaluate the bundle. Do not invent a missing source, relax an acceptance threshold or treat absent telemetry as proof of nonexecution.
