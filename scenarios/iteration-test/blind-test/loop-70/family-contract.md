# Loop 70 family contract: datagram firewall state expiry

## Evidence and scope

Loop 67's Network Forensics review identified one-way UDP Zeek `S0` rows with missing
`duration` alongside ASA build and teardown records that displayed the same second and
`duration 0:00:00`. The loop 69 generated sample independently reproduces it: 33 UDP/514 Zeek
DMZ observations, all without a `duration` field (8 multi-packet); 11 matching ASA UDP/514
build/teardown pairs, all with zero displayed seconds.

## Change

Firewall state expiry is a source-observation lifecycle, separate from transport close. The
`source.firewall.datagram_teardown` timing relationship now samples a right-skewed 1-second to
2-minute idle interval after the last observed datagram or start when no close is available.
This interval aligns with ASA's second-scale teardown rendering. Zeek's one-way UDP `S0` field
semantics and canonical transport close ownership are unchanged.

## Guardrails and uncertainty

The targeted observation test requires the ASA expiry to be at least one second after the
observed UDP close and within the configured two-minute bound. Existing TCP teardown timing
remains unchanged. The profile is a plausible baseline state timeout, not a capture-calibrated
claim for every firewall policy; native comparisons should qualify the interval before further
tuning.
