# Post-Batch-2 Blind Realism Assessment

## Gate decision

**Failed pending sibling remediation.** The six contradictions targeted by the session and
authentication slice remain absent, but four independently verified lifecycle/source-sequence
families are severe enough to block progression into Batch 3:

1. Linux process creation uses non-monotonic host-local PID streams without plausible wrap.
2. SSH target syslog can precede the same PID's eCAR process creation.
3. Mandatory Windows startup modules can first load minutes or hours after process creation, and
   narrow third-party modules can be assigned to incompatible processes.
4. Windows Security and Sysmon record IDs can imply impossible hidden event rates.

These are sibling defects, not recurrences of the six original Batch-2 findings. The next
remediation slice will close these families, regenerate the integrated dataset, rerun invariant
probes, and repeat the isolated four-specialty panel before Batch 3 begins.

## Isolation and method

- Assessed output: `/private/tmp/eforge-session-auth-v3/branch-enterprise/data`
- Neutral reviewer copy: `/private/tmp/auth-study-postbatch2.fswAaE/data`
- Reviewer inputs: rendered logs only; no scenario, ground truth, code, previous output, previous
  reports, finding register, or implementation history
- Reviewers: fresh Threat Hunter, Detection Engineer, Network Forensics, and Host/EDR roles
- Deliberation: not triggered; verdicts were unanimous, average verdict confidence was 97.75, and
  the synthetic-score spread was 5
- Verification rule: no impression was accepted without direct rendered evidence and a code trace
  to an owning layer, or an explicit proof-gap disposition

## Scores

| Panel | Threat Hunter | Detection | Network | Host/EDR | Average |
|---|---:|---:|---:|---:|---:|
| Original pre-fix synthetic confidence | 88 | 96 | 86 | 97 | 91.75 |
| Post-Batch-2 synthetic confidence | 98 | 95 | 94 | 99 | 96.50 |

The panels were independent and the rendered output changed broadly, so the 4.75-point increase
must not be interpreted as a causal realism regression. It establishes only that the post-fix
dataset remains confidently distinguishable after the original defects were removed.

## Verified dispositions

| Priority | Disposition | Finding family | Evidence and owner | Planned slice |
|---|---|---|---|---|
| P1 | Accept | Linux PID chronology | PROXY creates 233855 then 232295; WEB creates 749498 then 749092 without wrap. `StateManager._allocate_linux_pid` owns allocation. | Gate repair |
| P1 | Accept | SSH process observation | PROXY PID 233723 logs at 12:10:03.573 before eCAR create at 12:10:06.016. SSH bundle and source timing own the relationship. | Gate repair |
| P1 | Accept | Windows module lifecycle | 52/56 visible `ntdll.dll` loads occur over ten minutes after create; hourly baseline module sampling owns placement. | Gate repair |
| P1 | Accept | Windows EventRecordID rate | NKAPOOR Security IDs jump 13,206 in 8.999 ms; similar Security/Sysmon cases recur. Channel sequence modeling owns gaps. | Gate repair |
| P1 | Accept | Kerberos transport causality/cache | 852/852 proximal KDC audits precede same-clock 5156; 629/1,484 lack exact Zeek transport; machine TGTs recur every few minutes. Baseline Kerberos orchestration bypasses cache-aware paths and emits audits before connections. | Batch 3 |
| P1 | Accept | HTTP `HEAD` response body | 10/10 HEAD rows carry 136–478 body bytes, including corresponding web-access bytes. Canonical HTTP response normalization owns method semantics. | Batch 3 |
| P2 | Accept | TCP state/history derivation | Zeek UID `CK1AnxAfXo2jJQtCB6` combines `S1` with `ShR`, 2/1 packets, and zero bytes. Network transaction outcome owns the state tuple. | Batch 3 |
| P1 | Accept | Sensor clock stability | Consecutive IDS/Zeek ICMP observations repeatedly flip relative offset sign. Observation/source timing owns durable sensor clocks. | Batch 3 |
| P2 | Accept | OCSP object stability | The same OCSP request/serial/validity is rendered at substantially different response sizes. Protocol payload identity owns bytes. | Batch 4 |
| P1 | Accept | Recursive DNS TTL state | Thirty internal PTR observations repeatedly return non-authoritative TTL 86400; 25/28 within-TTL repeats reset rather than decrement. Resolver cache state owns observed TTL. | Batch 4 |
| P2 | Accept | DHCP renewal state | Each renewal independently jitters T1 and transaction morphology rather than following one durable lease. DHCP bundle owns lease state. | Batch 4 |
| P2 | Accept | Linux daemon state | One long-lived rsyslog PID repeatedly reacquires its socket and reloads configuration dozens of times. Baseline daemon lifecycle owns these messages. | Batch 4 |
| P2 | Accept | Per-host hardware inventory | Both Linux hosts draw the same incompatible VMware/Mellanox/virtio/NVMe/AHCI vocabulary. World capability state owns inventory. | Batch 4 |
| P2 | Accept | Snort classification projection | Fast alerts render classtype keys instead of configured native descriptions. The Snort emitter owns source-local projection. | Batch 5 |
| — | Reject | TEST-NET RDP source | Documentation-range addresses can result from dataset sanitization; no contradictory companion evidence established synthesis. | None |
| — | Proof gap | Long-lived `kubectl` without flow | A missing flow can reflect collection scope; the report did not establish a required visible transport. | None |

The existing rendered-invariant probe still reports 32 later-slice findings: six Windows 4648
native-field errors, one Zeek AAAA distribution warning, 24 Zeek file-interval errors, and one
Zeek OCSP duration warning. These remain tracked independently of the panel.

## Reports and machine-readable evidence

- [Threat Hunter](threat-hunter.md)
- [Detection Engineer](detection-engineer.md)
- [Network Forensics](network-forensics.md)
- [Host/EDR](host-edr.md)
- [Scores](scores.json)
- [Verified findings](verified-findings.json)

Commands, baseline/final locations, deterministic repeat evidence, invariant-probe results, and
test results remain in the
[session/authentication worklog](../../../worklog/2026-08-05-session-auth-lifecycle.md).
