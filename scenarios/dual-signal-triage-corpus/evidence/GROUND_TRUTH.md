# Ground Truth: dual-signal-triage-corpus-evidence

**Scenario:** Real, generated underlying evidence for the dual-signal SnortML + signature +
Splunk-notable triage corpus (corpus/labeled_events.json). Each corpus event
is grounded in an actual EvidenceForge-generated request or authentication
burst, not an assertion without supporting data.

SQLi cases use the built-in `adversarial_payload` (family: sql_injection)
mechanism: the canonical UNION SELECT form is signature-mapped to a real
Emerging Threats SID (2009714) and fires when observed in cleartext by an
IDS sensor; an evasion variant of the same family (comment-split UNION/**/
SELECT) is a documented detection blind spot and produces real HTTP request
evidence with no signature match -- exactly the "ML-only, no signature
corroboration" case this corpus is about. Which variant lands on which event
is decided by the scenario's generation seed, not hand-picked after the
fact; GROUND_TRUTH.json is the source of truth once generated.

Splunk-notable cases use `credential_spray` against the domain controller,
differing only in real attempt volume/pattern -- the actual signal a
risk-based-alerting rule would score.


**Generated:** 2026-08-01 13:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **marta.diaz** on **SEC-TEST-01**: SQL injection attempt against the web app (corpus case: sig-sqli-001 / corr-003 candidate)
2. **marta.diaz** on **SEC-TEST-01**: Second SQL injection attempt against the web app, different request (corpus case: sig-sqli-001 / corr-003 candidate)
3. **marta.diaz** on **SEC-TEST-01**: Third SQL injection attempt against the web app, different request (corpus case: ml-sqli-002 candidate)
4. **marta.diaz** on **SEC-TEST-01**: Fourth SQL injection attempt against the web app, different request (corpus case: ml-sqli-002 candidate)
5. **marta.diaz** on **SEC-TEST-01**: Ordinary product-catalog request against the web app (corpus case: ml-low-004)
6. **SYSTEM** on **DC-01**: High-volume credential spray against a domain account (corpus case: notable-1001, high-risk Splunk notable)
7. **SYSTEM** on **DC-01**: Low-volume, scattered failed logons (corpus case: notable-1002, low-risk Splunk notable)


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-08-01 13:19:52 UTC | marta.diaz | SEC-TEST-01 | Adversarial_Payload | Adversarial payload (sql_injection) to http_request_url [percent]: EFORGE_TEST&#x27; UNION SELECT username,password FROM users-- EFORGE_TEST p2lAzH (sha256:2177e260939f) [IDS 2009714: ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT] |
| 2026-08-01 13:34:45 UTC | marta.diaz | SEC-TEST-01 | Adversarial_Payload | Adversarial payload (sql_injection) to http_request_url [percent]: EFORGE_TEST&#x27; AND extractvalue(1,concat(0x7e,user()))-- EFORGE_TEST 9YjWbg (sha256:445e8c44d129) |
| 2026-08-01 13:49:42 UTC | marta.diaz | SEC-TEST-01 | Adversarial_Payload | Adversarial payload (sql_injection) to http_request_url [percent]: EFORGE_TEST&#x27; UNION SELECT username,password FROM users-- EFORGE_TEST HpIRhD (sha256:3dcd82ccc039) [IDS 2009714: ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT] |
| 2026-08-01 14:05:30 UTC | marta.diaz | SEC-TEST-01 | Adversarial_Payload | Adversarial payload (sql_injection) to http_request_url [percent]: EFORGE_TEST&#x27; AND extractvalue(1,concat(0x7e,user()))-- EFORGE_TEST PSXVMG (sha256:c27a72630682) |
| 2026-08-01 14:14:45 UTC | marta.diaz | SEC-TEST-01 | Connection | Connection to 10.20.30.10:80 (UID: CicEFG6uBSVyLf7xb1) |
| 2026-08-01 14:29:56 UTC | SYSTEM | DC-01 | Credential_Spray | Credential brute_force: 61 attempts against 1 accounts |
| 2026-08-01 14:45:28 UTC | SYSTEM | DC-01 | Credential_Spray | Credential spray: 2 attempts against 2 accounts |


## IDS Evaluation Summary

Observation totals: visible=2.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| IDS-EDGE | 1:2009714 | 2 | 2 | 0 | built_in=2 | `b949ba309e2b` |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.20.30.10:80 (Internal Server)
- Zeek UID: CicEFG6uBSVyLf7xb1

### User IOCs

- SYSTEM (compromised account)
- helen.ortiz (Spray Target) (compromised account)
- marta.diaz (compromised account)
- raj.subramaniam (Spray Target) (compromised account)
- svc-legacyapp (Spray Target) (compromised account)
