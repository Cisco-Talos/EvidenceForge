# Northstar Health - Stolen Credentials: design and research

Northstar Health and the incident details are fictional. The engine renders the authored event plan deterministically and owns the correlated evidence, run manifests, and ground truth.

## Technique basis

- The clinical workstation attempts RDP to the file server. The scenario models the denied attempt as a network event. [MITRE ATT&CK T1021.001 — Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

## Composition

- The scenario pins the published `project:evidenceforge:organization:northstar-health@1.2.0` release by exact path. Its pack digest is `c8916637be154fca2c99d8c486db2dac4141ce988c499c9e30eaa32dad0e7509`.
- The release brings its locked `evidenceforge:industry:healthcare@1.0.0` dependency with digest `91f369c55113c940a9a907282b53fcc5629c54d3b91b79a869814cbcb7b82220`.

## Exercise boundaries

The investigation covers failed domain authentication, explicit credential use, and an RDP attempt denied under the pack's firewall policy. Routine clinical SMB access and the permitted WinRM path illustrate legitimate inter-segment traffic under the same policy.
