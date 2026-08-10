# Iteration Test Expanded IDS Assessment Loops 55-59

Scenario: `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded-ids/scenario.yaml`

This set begins at commit `90a997db`. Per user direction, Loop 55 uses the latest Loop 54
findings as its starting context and first validates the committed process-native Windows file
change. Each loop still regenerates the corpus, runs automated evaluation, and uses an isolated
data-only blind panel before selecting the following family fix.

## Starting Priorities From Loop 54

1. Verify generic numeric `C:\Windows\Temp` Event 11 creation is absent while installer/update
   and user-shell process-native temp artifacts remain.
2. Complete SSH and finite-command process lifecycles.
3. Remove universal one-direction source timestamp signatures.
4. Make SSH concurrency and DHCP renewal behavior stateful rather than host-periodic.

## Loop 55

- Generated 82,076 records from commit `90a997db`; automated evaluation scored 95.64
  (Parseability 100.00, Plausibility 97.24, Causality 88.84, Timing 95.60).
- The Loop 54 process-native file probe passed: 11 Sysmon Event 11 records and zero generic
  five-digit `C:\\Windows\\Temp` artifacts.
- Fresh initial synthetic-confidence scores were 48 (Threat Hunter), 68 (Detection), 32
  (Network), and 74 (Host/EDR), averaging 55.5. Verdict disagreement triggered deliberation;
  revised scores were 60/76/49/78, averaging 65.75.
- The panel ranked a bare, 43-minute `runas.exe` process that nevertheless produced successful
  Event 4648 evidence as the strongest hard contradiction.

### Explicit-Credential Family Contract

- **Owner:** `ExplicitCredentialUseActionBundle` owns the generated caller process, successful
  Event 4648 occurrence, and one-shot caller lifecycle.
- **Invariant:** a successful generated `runas.exe` caller exposes `/user:<target>` and a target
  command; Security, Sysmon, and eCAR share its PID/image; a bundle-created caller terminates
  within seconds. A caller supplied by another action retains that action's lifecycle ownership.
- **Entry paths:** baseline administrative activity, typed storyline `explicit_credentials`,
  command-derived explicit credential use, and direct activity-generator compatibility calls.
- **Consumers:** Security 4648/4688/4689, Sysmon 1/5, and eCAR process create/terminate and auth.
- **Sibling risk:** MMC, PowerShell, PsExec, WMIC, and scheduled-task credential callers must not
  gain misleading command semantics or have externally owned processes terminated by this bundle.
