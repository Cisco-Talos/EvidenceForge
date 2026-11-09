# Loop 87 — DC-02 Installer Transfer Trace

## Question

Does the Citrix installer download establish endpoint execution or reveal impossible cross-source ordering/ownership?

## Result

Zeek DMZ records show a complete HTTP GET and a completed seven-second TCP flow from DC-02 to the proxy. The proxy fetched the same URI externally, and the two file observations share size, MIME type and SHA-1. This proves transfer to/from the proxy, not local installation or execution. The inspected DC-02 eCAR and Windows records have no exact tuple/process/file companion; absent endpoint evidence is not a defect absent a collection requirement, and scenario content makes no execution claim.

## Decision

No code or scenario change. Keep the installer as an investigative follow-up only. Probe details and exact UIDs/tuples are in `citrix-transfer-probe.json`.
