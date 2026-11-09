# Loop 78 family contract — DNS and IDS background alert texture

- **Owning abstractions:** `IdsAlertActionBundle` owns canonical IDS alert context attached to network activity; `activity/ids_signatures.yaml` and DNS configuration own enumerable signature and domain vocabulary; sensor visibility decides which sensors observe it.
- **Invariant:** an alert must be justified by an observed canonical activity/predicate and its source-native signature, tuple, protocol and sensor vantage; family frequency and vocabulary should reflect heterogeneous traffic rather than a compact repeated palette.
- **Entry paths:** authored scenario alerts and built-in baseline/red-herring IDS intents enter the IDS action bundle; canonical DNS/network events and visibility determine sibling observations.
- **Consumers:** Snort sensors render alerts; Zeek DNS/conn and endpoint network evidence provide corroborating activity; eval consumes IDS integrity links.
- **Sibling risks:** altering shared signature pools or alert cadence can affect threat-story assertions, red herrings, sensor visibility and distribution across unrelated source families.
- **Why this layer owns the truth:** the concern spans alert vocabulary, canonical trigger and sensor path, so any change must be made in the signature/config or bundle/intent owner, not in the text emitter alone.
- **Loop question:** quantify signature/domain-family recurrence and confirm alerts correspond to visible tuples across core/perimeter sensors. Make no change unless the probe shows a dataset-wide pattern that is not explained by valid signatures, authored assertions, or sensor overlap.
