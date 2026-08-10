# Loop 45 Assessment Report

Loop 45 established a fresh baseline from committed `d7162d57` without using
prior-loop findings for target selection. Generation produced 83,707 records;
automated evaluation scored 96.0256 and failed only pivot linkability.

The initial blind panel was Synthetic/Synthetic/Inconclusive/Real at
66/78/44/28, average 54.0. Verdict disagreement and a 50-point spread triggered
deliberation. After evidence checking, the panel converged unanimously on
Synthetic at 74/80/67/69, average 72.5.

## Fresh Findings

- Detection verified 18 DB `wget` creates whose command named
  `internal-service`; 13 actor-owned single flows joined exactly to proxy
  requests for unrelated public hosts.
- The same MAIL-CLIN Postfix `smtpd` identity owned 106 flows, including 21
  exact Python-requests proxy joins and 55 LDAP flows.
- Threat Hunter found 54 APP healthchecks split between 26 internal targets and
  28 requests across 25 heterogeneous public targets, plus shared Linux sudo
  identities/commands.
- Network found strong protocol realism with residual DHCP cadence,
  cross-sensor clock-shape, and infrastructure-tail concerns.
- Host found no endpoint lifecycle contradiction and assessed the corpus Real
  before cross-specialty evidence was presented.

## Selected Improvement

**Family:** source-native canonical process ownership for HTTP and explicit
proxy clients. **Classification:** `family_level` sibling-defect repair.

The shared resolver now falls back to `HttpContext.host`, prioritizes
source-native Linux CLI/HTTP client families over generic server-role daemons,
allows target-bearing server helpers to own the socket, and rejects Postfix
mail daemons as arbitrary proxy client owners. This changes canonical
`ProcessContext` and initiating PID truth before eCAR, Zeek, proxy, or
firewall rendering.

## Verification

Nine focused ownership/lifecycle tests passed across explicit-proxy Linux
servers, CLI families, hostname fallback, daemon replacement, high-confidence
owners, and one-shot process timing. Loop 46 will provide the rendered-output
family probe and independent blind confirmation.

## Prioritized Remaining Findings

- **P1:** Bind service-health destinations to role-specific dependency
  inventories rather than broad public pools.
- **P1:** Replace shared Linux sudo actor/command pools with host- and
  identity-specific operating models.
- **P1:** Derive DHCP schedules from coherent T1/T2 state with realistic
  disturbance.
- **P2:** Model independent sensor clock drift and sparse role-aware
  infrastructure protocols.
