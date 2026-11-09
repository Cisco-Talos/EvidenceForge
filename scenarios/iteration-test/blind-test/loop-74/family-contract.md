# Loop 74 family contract — process-owned browser request identity

- **Owning abstraction:** the data-driven `workstation.windows` User-Agent catalog, together with
  request-header provenance in `BrowserSessionRequest`/`HttpContext` and the
  `NetworkTransactionPlanner` browser-process binding, before network/proxy rendering.
- **Invariant:** When a generated HTTP request is owned by a known browser process, its browser
  family and major release agree with that process's canonical loaded executable. Explicitly
  authored scenario headers and finalized action-bundle headers retain precedence. The same header
  identity is used by Zeek, proxy, and source endpoint evidence.
- **Entry paths:** baseline persona browsing and web-visitor sessions (`engine/baseline.py` and
  `actions/browser_session.py`); generic activity and network requests bound to a process
  (`actions/network_transaction_planner.py`); explicit/storyline HTTP requests
  (`engine/storyline.py`, typed network handlers); proxy transactions
  (`actions/proxy_transaction.py`). The exact request provenance must be maintained from those
  authors through canonical `HttpContext` construction.
- **Consumers:** Zeek HTTP, explicit proxy access, HTTP transaction/body accounting, and endpoint
  process/network evidence used to attribute the originating PID and loaded executable version.
- **Layer rationale:** The internal Windows workstation pool offered Chrome 119/121 and Firefox
  120 while the modeled workstation binaries are Chrome 120, Edge 120, and Firefox 121. That
  catalog owns generated default versions; narrowing it removes unsupported defaults at selection
  time. `BrowserSessionRequest` and `HttpContext` also carry generated-default provenance, and the
  planner can bind generated requests to an owning process where the request path resolves one.
  Patching Zeek or proxy emitters would leave other consumers inconsistent.
- **Sibling risks:** preserve explicit scenario User-Agent values (including deliberate spoofing),
  tool/service User-Agents, known-absent headers, browser family tokens, OS-specific formats,
  process reuse, and header byte budgets. Cover a generic baseline browser path and a non-browser or
  authored-header sibling.
- **Evidence before fix:** In the loop73 bundle, Windows Sysmon Event3 source tuples match Zeek HTTP source
  tuples on three workstations. Across those tuple matches, 20 Chrome/119 requests map to a
  `chrome.exe` process with FileVersion `120.0.6099.225`; eight Firefox/120 requests map to
  `firefox.exe` FileVersion `121.0` (6 on WS-EBROOKS-01 and 2 on WS-AJOHNSON-01). This is a
  process/request identity `contract_gap`, not a judgment that old releases are intrinsically
  unrealistic. The modeled browser binaries are Chrome 120, Edge 120 and Firefox 121. The final
  loop74 bundle has 360 exact Sysmon Event3-to-Zeek HTTP tuple matches; 179 rows have a supported
  Windows browser family and matching process FileVersion, with zero major-version mismatches.

## Secondary contract — exhausted out-of-order logind ID ranges

- **Owning abstraction:** `StateManager._preview_linux_logind_session_id` and its per-host temporal
  allocation index.
- **Invariant:** Allocations never fail because an out-of-order event arrives between adjacent
  already-assigned IDs. The regular path preserves temporal order; when no integer remains in that
  interval, a unique host-wide ID is allocated from the next free range and the resulting bounded
  chronology inversion is measurable in the rendered output.
- **Entry paths / consumers:** the same SSH, local interactive logon, and baseline session paths and
  syslog/eCAR/session-context consumers listed above. The failure reproduced with eight randomly
  ordered timestamps on one host and also interrupted the loop74 fixed-seed full generation.
- **Layer rationale:** the allocator owns host-unique ID allocation and sees the temporal index;
  callers and emitters cannot safely invent a replacement without causing split-brain session IDs.
- **Sibling risks:** never duplicate an ID or perturb caller RNG state; preserve normal chronological
  order and checkpoint rollback. Probe both fallback count/order and matching New/Removed session
  identity across the full output.
