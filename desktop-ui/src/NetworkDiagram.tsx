import { useCallback, useEffect, useEffectEvent, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import {
  AppWindow, BrickWallFire, ChevronDown, CircleHelp, ClipboardCopy, Cloud, Download, Database, Expand, FileText, Folder, Globe, Info, KeyRound, Layers,
  Mail, Maximize, Minimize, Monitor, Network, Server, Sparkles, X, ZoomIn, ZoomOut,
} from "lucide-react";
import { Tooltip } from "radix-ui";
import { firewallRuleFilter, searchDiagram, type SearchResult } from "./networkSearch";
import { groupRows, indexCoverage, INTERNET, TIER_LABELS, TIER_ORDER, traceEntities, type CoverageIndex, type Direction } from "./networkCoverage";
import type { DownloadResult, NetworkChatContext, TopologyGraph } from "./api";
import { captureNetworkView, captureViewImage, copyViewImage } from "./captureNetworkView";
import { changesSinceLastShown, rememberShown, type DiagramChanges } from "./networkDiff";
import { Modal } from "./Modal";
import {
  buildDiagramModel, categoryLabel, hostCategory, layoutNetworkDiagram, MIN_READABLE_SCALE, shortOs, siteDeviceLine, textWidth,
  type DiagramDevice, type DiagramEntity, type DiagramHost, type DiagramLayers, type DiagramLinkKind, type DiagramScene,
  type Bounds, type Detail, type Equipment, type HostCategory, type PlacedChip, type PlacedHost, type PlacedZone, type Zone,
} from "./networkDiagramLayout";

const OS_LABELS: Record<string, string> = { windows: "Windows", linux: "Linux", macos: "macOS" };
const EXPOSURE_LABELS = { internal: "Internal clients", external: "External clients", both: "Internal and external clients" };
const KIND_LABELS = { firewall: "Firewall", router: "Router", switch: "Switch", network: "Network appliance" };
const SENSOR_LABELS: Record<DiagramDevice["kind"], string> = { network: "Network sensor", ids: "IDS sensor", firewall: "Firewall" };
const LAYER_LABELS = { sensors: "Sensors", hosts: "Hosts" };
const LAYER_HELP = {
  sensors: "Network sensors appear as chips on the subnets and links they observe. Zeek writes network logs and Snort raises IDS alerts. Hover over a chip to see its logs.",
  hosts: "Endpoints in each subnet. When hidden, subnets show only their address ranges, attached devices and sensors.",
  scopes: "Outlines subnets that share a firewall policy interface, such as every subnet behind inside. Firewall rules apply per interface.",
};
const LINK_LABELS: Record<DiagramLinkKind, string> = { network: "Network link", wan: "WAN link", vpn: "VPN link" };
const SCOPE_COLORS = ["--accent", "--info", "--ok", "--syntax-keyword", "--warn", "--diagram-scope-rose", "--diagram-scope-olive", "--err"];
const SCOPE_DASHES = ["3 4", "8 3", "7 2 1 2", "1 3"];
/** Names and addresses are not prose: keep system autocorrect and suggestions out of these fields. */
const PLAIN_INPUT = { autoComplete: "off", autoCorrect: "off", autoCapitalize: "off", spellCheck: false } as const;
const HOST_ROW = 44;
const HOST_TABLE_HEIGHT = 360;
/** Above this many rows, the details host list renders only the rows in view. */
const HOST_WINDOW_THRESHOLD = 60;
const INITIAL_SIZE = { width: 720, height: 320 };
const CATEGORY_ICONS: Record<HostCategory, typeof Monitor> = {
  domain_controller: KeyRound, database: Database, web_server: Globe, mail_server: Mail, file_server: Folder,
  app_server: AppWindow, log_server: FileText, server: Server, workstation: Monitor, other: CircleHelp,
};
type Camera = { x: number; y: number; scale: number };
type Drag = { pointer: number; x: number; y: number; camera: Camera };
type FirewallScope = { id: string; label: string; segments: Set<string>; color: string; dash: string };

function indexFirewallScopes(graph: TopologyGraph) {
  const groups = new Map<string, Omit<FirewallScope, "color" | "dash">>();
  for (const device of graph.devices) {
    if (device.kind !== "firewall") continue;
    for (const { segment_id, interface_name } of device.associations) {
      if (interface_name === null) continue;
      const id = JSON.stringify([device.id, interface_name]);
      const group = groups.get(id) ?? { id, label: `${device.hostname} · ${interface_name}`, segments: new Set<string>() };
      group.segments.add(segment_id);
      groups.set(id, group);
    }
  }
  const scopes = [...groups.values()]
    .sort((a, b) => a.label.localeCompare(b.label, "en") || a.id.localeCompare(b.id, "en"))
    .map((group, index) => ({
      ...group,
      color: `var(${SCOPE_COLORS[index % SCOPE_COLORS.length]})`,
      dash: SCOPE_DASHES[Math.floor(index / SCOPE_COLORS.length) % SCOPE_DASHES.length],
    }));
  const scopesBySegment = new Map<string, FirewallScope[]>();
  for (const scope of scopes) {
    for (const id of scope.segments) scopesBySegment.set(id, [...(scopesBySegment.get(id) ?? []), scope]);
  }
  return { scopes, scopesBySegment };
}

function entityLabel(entity: DiagramEntity): string {
  switch (entity.kind) {
    case "zone": return entity.zone.name;
    case "equipment": return entity.equipment.name;
    case "sensor": return entity.device.hostname;
    case "host": return entity.host.hostname;
    case "internet": return entity.internet.name;
    case "transit": return entity.transit.name;
  }
}

function zoneLabel(zone: Zone): string {
  return zone.unassigned ? "Unassigned hosts" : zone.cidr ? `Segment ${zone.name}, ${zone.cidr}` : `Segment ${zone.name}`;
}

function equipmentLabel(item: Equipment): string {
  return item.kind === "firewall" ? `Firewall ${item.name}` : `${item.name} ${KIND_LABELS[item.kind]}`;
}

function hostLabel(host: DiagramHost): string {
  return `${host.hostname} ${OS_LABELS[host.os_family] || "Other OS"}`;
}

/** What one sensor writes, for its hover text: each family with the logs it produces. */
function sensorLogs(device: DiagramDevice): string[] {
  const evidence = device.evidence ?? [];
  if (!evidence.length) return [`Logs: ${device.log_formats.join(", ")}`];
  return evidence.map(({ family, label, formats }) => family === "zeek"
    ? `Zeek logs: ${formats.map((name) => name.replace(/^zeek_/, "")).join(", ")}`
    : family === "ids" ? `${label} IDS alerts` : family === "asa" ? `${label} firewall logs` : `${label}: ${formats.join(", ")}`);
}

function sensorLabel(device: DiagramDevice): string {
  const evidence = (device.evidence ?? []).map(({ label }) => label).join(" and ") || device.log_formats.join(", ");
  return `Sensor ${device.hostname}, ${evidence}, ${device.placement.toUpperCase()}`;
}

function activateByKey(event: KeyboardEvent<SVGGElement>, action: () => void) {
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  action();
}

function FindingBadge({ x, y, messages }: { x: number; y: number; messages: string[] }) {
  return <g className="diagram-finding-badge" transform={`translate(${x} ${y})`} aria-hidden="true">
    <path d="M 0 -8 L 8 7 L -8 7 Z" />
    <text y={5} textAnchor="middle">!</text>
    <title>{messages.join("\n")}</title>
  </g>;
}

function RouterIcon({ x, y, size }: { x: number; y: number; size: number }) {
  return <svg width={size} height={size} x={x} y={y} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="1.55" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <ellipse cx="12" cy="8.5" rx="10.5" ry="5.25" />
    <path d="M1.5 8.5v7C1.5 18.4 6.2 21 12 21s10.5-2.6 10.5-5.5v-7M7 7h3L7 5.5M17 7h-3l3-1.5M7 10h3l-3 1.5m10-1.5h-3l3 1.5" />
  </svg>;
}

function EquipmentIcon({ kind, x, y, size }: { kind: Equipment["kind"]; x: number; y: number; size: number }) {
  if (kind === "firewall") return <BrickWallFire x={x} y={y} size={size} aria-hidden="true" />;
  if (kind === "switch") return <Network x={x} y={y} size={size} aria-hidden="true" />;
  return <RouterIcon x={x} y={y} size={size} />;
}

function HostFacts({ host }: { host: DiagramHost }) {
  return <dl className="diagram-facts">
    <dt>IP address</dt><dd><code>{host.ip}</code></dd>
    {host.public_address && <><dt>Public address</dt><dd><code>{host.public_address}</code>
      <small>{host.public_address_source === "static_nat" ? " static NAT" : " routable address"}</small></dd></>}
    <dt>Operating system</dt><dd>{host.os}</dd>
    {host.type && <><dt>Type</dt><dd>{host.type.replace(/_/g, " ")}</dd></>}
    {!!host.primary_users?.length && <>
      <dt>{host.primary_users.length === 1 ? "Primary user" : "Primary users"}</dt>
      <dd>{host.primary_users.join(", ")}</dd>
    </>}
    {!!host.roles?.length && <><dt>Roles</dt><dd>{host.roles.join(", ")}</dd></>}
  </dl>;
}

/** Every host in a subnet, filterable. Long lists render only the rows in view. */
function HostTable({ hosts, onSelect }: { hosts: DiagramHost[]; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const query = filter.trim().toLowerCase();
  const shown = query ? hosts.filter((host) => [host.hostname, host.ip, host.os, host.type ?? "", ...(host.roles ?? []), ...(host.primary_users ?? [])]
    .some((value) => value.toLowerCase().includes(query))) : hosts;
  const windowed = shown.length > HOST_WINDOW_THRESHOLD;
  const first = windowed ? Math.max(0, Math.floor(scrollTop / HOST_ROW) - 6) : 0;
  const last = windowed ? Math.min(shown.length, first + Math.ceil(HOST_TABLE_HEIGHT / HOST_ROW) + 12) : shown.length;
  return <div className="diagram-hosts">
    <h5>Hosts <span>{shown.length === hosts.length ? hosts.length : `${shown.length} of ${hosts.length}`}</span></h5>
    {hosts.length > 1 && <input type="search" className="diagram-host-filter" {...PLAIN_INPUT} placeholder={`Filter ${hosts.length} hosts`} title="Filter by name, address, operating system, role or user"
      aria-label="Filter hosts" value={filter} onChange={(event) => { setFilter(event.target.value); setScrollTop(0); }} />}
    <div className="diagram-host-scroll" style={windowed ? { maxHeight: HOST_TABLE_HEIGHT } : undefined}
      onScroll={windowed ? (event) => setScrollTop(event.currentTarget.scrollTop) : undefined}>
      <ul style={windowed ? { paddingTop: first * HOST_ROW, paddingBottom: (shown.length - last) * HOST_ROW } : undefined}>
        {shown.slice(first, last).map((host) => <li key={host.id}>
          <button type="button" className="diagram-host" aria-label={hostLabel(host)} title={`${host.hostname} · ${host.ip} · ${host.os}`}
            onClick={() => onSelect(host.id)}>
            <CategoryIcon host={host} size={16} />
            <span className="diagram-host-text"><strong>{host.hostname}</strong>
              <small><code>{host.ip}</code> · {host.public_address ? `public ${host.public_address} · ` : ""}{shortOs(host.os)}</small></span>
          </button>
        </li>)}
      </ul>
      {!shown.length && <p className="muted">No hosts match.</p>}
    </div>
  </div>;
}

function CategoryIcon({ host, category, size, x, y }: { host?: DiagramHost; category?: HostCategory; size: number; x?: number; y?: number }) {
  const Icon = CATEGORY_ICONS[category ?? hostCategory(host!)];
  return <Icon size={size} x={x} y={y} aria-hidden="true" />;
}

function EvidenceList({ device }: { device: DiagramDevice }) {
  const evidence = device.evidence ?? [];
  if (!evidence.length) return <><dt>Log formats</dt><dd>{device.log_formats.join(", ")}</dd></>;
  return <>{evidence.map((entry) => <span key={entry.family} className="diagram-evidence-row">
    <dt>{entry.label}</dt><dd>{entry.formats.join(", ")}</dd>
  </span>)}</>;
}

/** Which network evidence exists for traffic to or from one subnet, grouped by how much it shows. */
function CoverageSection({ zone, coverage, scene, onTrace, onSelect, hostNote }: {
  zone: Zone; coverage: CoverageIndex; scene: DiagramScene; hostNote?: string;
  onTrace: (entities: Set<string> | null) => void; onSelect: (id: string) => void;
}) {
  const [direction, setDirection] = useState<Direction>("to");
  const groups = groupRows(coverage.rows(zone.id, direction), zone.id);
  if (!groups.length) return null;
  const peerName = (peer: string) => peer === INTERNET ? "the Internet" : scene.model.zones.get(peer)?.name ?? peer;
  const sensorName = (id: string) => coverage.devices.get(id)?.hostname ?? id;
  return <section className="diagram-coverage" aria-label="Network evidence">
    <h5>Network evidence</h5>
    <div className="diagram-coverage-direction" role="group" aria-label="Traffic direction">
      <button type="button" aria-pressed={direction === "to"} onClick={() => setDirection("to")}>To this subnet</button>
      <button type="button" aria-pressed={direction === "from"} onClick={() => setDirection("from")}>From this subnet</button>
    </div>
    {hostNote && <p className="muted">{hostNote}</p>}
    {groups.map(({ tier, rows }) => <div key={tier} className="diagram-coverage-group" data-tier={tier}>
      <h6><span className="diagram-tier-mark" data-tier={tier} aria-hidden="true" />{TIER_LABELS[tier]}</h6>
      <ul>{rows.map(({ peer, path }) => <li key={peer}
        onMouseEnter={() => onTrace(traceEntities(path, scene.model))} onMouseLeave={() => onTrace(null)}>
        <button type="button" onFocus={() => onTrace(traceEntities(path, scene.model))} onBlur={() => onTrace(null)}
          onClick={() => peer !== zone.id && onSelect(peer === INTERNET ? [...scene.model.internets.keys()][0] ?? peer : peer)}>
          {peer === zone.id ? "Within this subnet" : `${direction === "to" ? "From" : "To"} ${peerName(peer)}`}
        </button>
        <span>{path.sensors.length ? path.sensors.map(sensorName).join(", ") : "No sensor"}</span>
        {path.delivered === false && <small>Not delivered{path.reason ? `: ${path.reason}` : ""}</small>}
      </li>)}</ul>
    </div>)}
    <p className="muted diagram-coverage-note">From the generation engine's routing and visibility rules for this revision. Hover over a row to trace its path.</p>
  </section>;
}

/** Short rule lists are read at a glance; longer ones get a filter. */
const RULE_FILTER_THRESHOLD = 6;

function FirewallRules({ device, segments }: { device: DiagramDevice; segments: TopologyGraph["segments"] }) {
  const [filter, setFilter] = useState("");
  const nat = device.nat_rules ?? [];
  const policy = device.policy ?? [];
  if (!nat.length && !policy.length && !device.default_action) return null;
  const matcher = firewallRuleFilter(filter, segments);
  // Keep each rule's position, because policy is evaluated in order.
  const shownNat = nat.map((rule, index) => ({ rule, index })).filter(({ rule }) => !matcher || matcher.nat(rule));
  const shownPolicy = policy.map((rule, index) => ({ rule, index })).filter(({ rule }) => !matcher || matcher.policy(rule));
  const count = (shown: number, total: number) => <span>{shown === total ? total : `${shown} of ${total}`}</span>;
  const total = nat.length + policy.length;
  return <>
    {total >= RULE_FILTER_THRESHOLD && <input type="search" className="diagram-host-filter diagram-rule-filter" {...PLAIN_INPUT}
      placeholder={`Filter ${total} rules`} aria-label="Filter firewall rules" value={filter} onChange={(event) => setFilter(event.target.value)}
      title="Filter by action, subnet, address or port. A full IP address finds the rules that apply to it." />}
    {matcher && !shownNat.length && !shownPolicy.length && !device.default_action && <p className="muted">No rules match.</p>}
    {shownNat.length > 0 && <><h5>Address translation {count(shownNat.length, nat.length)}</h5><ul className="diagram-associations">
      {shownNat.map(({ rule, index }) => <li key={index}>{rule.type === "static"
        ? <><code>{rule.real_ip}</code><span>↔</span><code>{rule.mapped_ip}</code><span>static NAT</span></>
        : <><span>{(rule.src ?? []).join(", ") || "any"}</span><span>→</span><code>{rule.mapped_ip}</code><span>dynamic PAT</span></>}
      </li>)}
    </ul></>}
    {(policy.length > 0 || device.default_action) && <><h5>Policy {policy.length > 0 && count(shownPolicy.length, policy.length)}</h5><ol className="diagram-policy">
      {shownPolicy.map(({ rule, index }) => <li key={index} value={index + 1} data-action={rule.action}>
        <strong>{rule.action}</strong> {rule.src} → {rule.dst}{rule.ports?.length ? ` · ports ${rule.ports.join(", ")}` : ""}
      </li>)}
      {device.default_action && <li value={policy.length + 1} data-action={device.default_action}><strong>{device.default_action}</strong> everything else</li>}
    </ol></>}
  </>;
}

function DiagramInspector({ entity, scene, graph, coverage, onTrace, onSelect, onFocus, onClose, askAction }: {
  entity: DiagramEntity; scene: DiagramScene; graph: TopologyGraph; coverage?: CoverageIndex;
  onTrace: (entities: Set<string> | null) => void;
  onSelect: (id: string) => void; onFocus: (id: string) => void; onClose: () => void; askAction?: ReactNode;
}) {
  const findings = graph.findings.filter((finding) => finding.entity_id === entity.id
    || (entity.kind === "equipment" && entity.equipment.device?.id === finding.entity_id));
  const { model } = scene;
  const link = (id: string, text: string) => scene.entities.has(id)
    ? <button type="button" onClick={() => onSelect(id)}>{text}</button> : <span>{text}</span>;
  const equipmentName = (id: string) => model.equipment.get(id)?.name ?? id;
  let body: ReactNode = null;
  if (entity.kind === "zone") {
    const { zone } = entity;
    const gateway = model.gateways.get(zone.id);
    body = <>

      {!zone.unassigned ? <dl className="diagram-facts">
        <dt>Address range</dt><dd><code>{zone.cidr}</code></dd>
        {zone.segment && <><dt>Web clients</dt><dd>{EXPOSURE_LABELS[zone.segment.exposure]}</dd></>}
        {gateway && <><dt>Gateway</dt><dd>{link(gateway, equipmentName(gateway))}</dd></>}
        {zone.parentId && <><dt>Within</dt><dd>{link(zone.parentId, model.zones.get(zone.parentId)?.name ?? zone.parentId)}</dd></>}
        {zone.link && <><dt>{LINK_LABELS[zone.link.link.kind ?? "network"]}</dt><dd>{zone.link.name}</dd></>}
      </dl> : <p>These hosts have no segment match in this environment.</p>}
      {zone.segment?.description && <p>{zone.segment.description}</p>}
      {zone.attachments.length > 0 && <><h5>Attached devices</h5><ul className="diagram-associations">
        {zone.attachments.map((attachment) => <li key={attachment.key}>{link(attachment.equipmentId, equipmentName(attachment.equipmentId))}
          {attachment.interfaceName !== null && <span>{attachment.interfaceName}{attachment.ip ? ` · ${attachment.ip}` : ""}</span>}
          {attachment.style === "inferred" && <span>Inferred from policy interface</span>}
          {attachment.style === "observes" && <span>Monitored by firewall</span>}
        </li>)}
      </ul></>}
      {zone.sensors.length > 0 && <><h5>Sensors</h5><ul className="diagram-associations">
        {zone.sensors.map(({ device, via, scope }) => <li key={device.id}>{link(device.id, device.hostname)}
          <span>{(device.evidence ?? []).map(({ label }) => label).join(" + ")}</span>
          <span>{device.placement.toUpperCase()}{via === "tap" ? ` on link${scope === "internet" ? " · Internet traffic" : ""}` : ""}</span>
        </li>)}
      </ul></>}
      {zone.children.length > 0 && <><h5>Contained segments</h5><ul className="diagram-associations">
        {zone.children.map((child) => <li key={child.id}>{link(child.id, child.name)}<span>{child.cidr}</span></li>)}
      </ul></>}
      {zone.link && <><h5>Interfaces</h5><ul className="diagram-associations">{Object.entries(zone.link.link.interfaces).map(([device, iface]) =>
        <li key={device}><strong>{device}</strong><span>{iface.name}</span><code>{iface.ip}</code></li>)}</ul></>}
      {coverage && !zone.unassigned && <CoverageSection key={"coverage:" + zone.id} zone={zone} coverage={coverage} scene={scene} onTrace={onTrace} onSelect={onSelect} />}
      {zone.hosts.length > 0 && <HostTable key={"hosts:" + zone.id} hosts={zone.hosts} onSelect={onSelect} />}
    </>;
  } else if (entity.kind === "host") {
    const zone = [...model.zones.values()].find(({ hosts }) => hosts.includes(entity.host));
    body = <><HostFacts host={entity.host} />{zone && <p>In {link(zone.id, zone.name)}</p>}
      {coverage && zone && !zone.unassigned && <CoverageSection key={"coverage:" + zone.id} zone={zone} coverage={coverage} scene={scene} onTrace={onTrace} onSelect={onSelect}
        hostNote={`For traffic between subnets, measured from a representative address in ${zone.name}.`} />}</>;
  } else if (entity.kind === "equipment") {
    const { equipment } = entity;
    const attachments = model.attachments.filter(({ equipmentId }) => equipmentId === equipment.id);
    const transits = [...model.transits.values()].filter(({ ends }) => ends.some(({ equipmentId }) => equipmentId === equipment.id));
    body = <>
      <p>{equipment.subtitle}</p>
      {equipment.device && <dl className="diagram-facts">
        {equipment.device.hostname !== equipment.device.name && <><dt>Name</dt><dd>{equipment.device.name}</dd></>}
        <dt>Monitoring placement</dt><dd>{equipment.device.placement.toUpperCase()}</dd>
        <dt>Direction</dt><dd>{equipment.device.direction}</dd>
        <EvidenceList device={equipment.device} />
        {equipment.device.default_interface !== null && <><dt>Default interface</dt><dd>{equipment.device.default_interface}</dd></>}
      </dl>}
      {equipment.device?.description && <p>{equipment.device.description}</p>}
      {equipment.device && <FirewallRules device={equipment.device} segments={graph.segments} />}
      {equipment.host && <HostFacts host={equipment.host} />}
      {(attachments.length > 0 || transits.length > 0) && <><h5>Interfaces</h5><ul className="diagram-associations">
        {attachments.map((attachment) => {
          const target = scene.entities.get(attachment.targetId);
          return <li key={attachment.key}>{link(attachment.targetId, target ? entityLabel(target) : attachment.targetId)}
            {attachment.interfaceName !== null && <span>{attachment.style === "interface" ? "Interface" : "Policy scope"} {attachment.interfaceName}</span>}
            {attachment.ip && <code>{attachment.ip}</code>}
            {attachment.style === "observes" && <span>Monitored</span>}
            {attachment.style === "membership" && <span>Address in subnet</span>}
          </li>;
        })}
        {transits.map((transit) => {
          const end = transit.ends.find(({ equipmentId }) => equipmentId === equipment.id)!;
          const others = transit.ends.filter(({ equipmentId }) => equipmentId !== equipment.id);
          return <li key={transit.id}>{link(transit.id, transit.name)}<span>{end.interfaceName}</span><code>{end.ip}</code>
            <span>to {others.map(({ equipmentId }) => equipmentName(equipmentId)).join(", ")}</span></li>;
        })}
      </ul></>}
    </>;
  } else if (entity.kind === "sensor") {
    const { device } = entity;
    const covered = scene.coverage.get(device.id) ?? [];
    const tap = graph.link_taps?.[device.id];
    body = <>
      <dl className="diagram-facts">
        <dt>Type</dt><dd>{SENSOR_LABELS[device.kind]}</dd>
        {device.hostname !== device.name && <><dt>Name</dt><dd>{device.name}</dd></>}
        <dt>Placement</dt><dd>{device.placement.toUpperCase()}</dd>
        <dt>Direction</dt><dd>{device.direction}</dd>
        {tap && <><dt>Link</dt><dd>{tap.link}</dd><dt>Traffic</dt><dd>{tap.scope === "internet" ? "Internet traffic" : "All traffic"}</dd></>}
        <EvidenceList device={device} />
      </dl>
      <p className="muted">{device.placement === "span" ? "SPAN sees traffic within each monitored subnet as well as traffic crossing it."
        : "TAP sees traffic crossing the tapped link or subnet boundary, not traffic between hosts inside a subnet."}</p>
      {device.description && <p>{device.description}</p>}
      {entity.host && <HostFacts host={entity.host} />}
      {covered.length > 0 && <><h5>Observes</h5><ul className="diagram-associations">
        {covered.map((id) => { const target = scene.entities.get(id); return <li key={id}>{link(id, target ? entityLabel(target) : id)}</li>; })}
      </ul></>}
    </>;
  } else if (entity.kind === "internet") {
    const { internet } = entity;
    const publicHosts = graph.hosts.filter(({ public_address }) => public_address);
    body = <>
      {internet.inferred && <p>No Internet boundary is declared. It is shown because {[
        (graph.public_cidrs ?? []).length ? `public ranges ${graph.public_cidrs!.join(", ")} are declared` : "",
        publicHosts.length ? `${publicHosts.length} ${publicHosts.length === 1 ? "host has" : "hosts have"} a public address` : "",
      ].filter(Boolean).join(" and ")}.</p>}
      {internet.attachments.length > 0 && <><h5>Uplinks</h5><ul className="diagram-associations">
        {internet.attachments.map((attachment) => <li key={attachment.key}>{link(attachment.equipmentId, equipmentName(attachment.equipmentId))}
          {attachment.interfaceName && <span>{attachment.interfaceName}</span>}{attachment.ip && <code>{attachment.ip}</code>}</li>)}
      </ul></>}
      {internet.sensors.length > 0 && <><h5>Sensors</h5><ul className="diagram-associations">
        {internet.sensors.map(({ device }) => <li key={device.id}>{link(device.id, device.hostname)}<span>{device.placement.toUpperCase()}</span></li>)}
      </ul></>}
      {publicHosts.length > 0 && <><h5>Hosts with public addresses</h5><ul className="diagram-associations">
        {publicHosts.map((host) => <li key={host.id}>{link(host.id, host.hostname)}<code>{host.public_address}</code></li>)}
      </ul></>}
    </>;
  } else if (entity.kind === "transit") {
    const { transit } = entity;
    body = <>
      <dl className="diagram-facts">
        <dt>Type</dt><dd>{LINK_LABELS[transit.kind]}</dd>
        {transit.segment && <><dt>Address range</dt><dd><code>{transit.segment.cidr}</code></dd></>}
      </dl>
      {transit.segment?.description && <p>{transit.segment.description}</p>}
      <h5>Interfaces</h5><ul className="diagram-associations">
        {transit.ends.map((end) => <li key={end.equipmentId}>{link(end.equipmentId, equipmentName(end.equipmentId))}<span>{end.interfaceName}</span><code>{end.ip}</code></li>)}
      </ul>
      {transit.sensors.length > 0 && <><h5>Sensors</h5><ul className="diagram-associations">
        {transit.sensors.map(({ device, scope }) => <li key={device.id}>{link(device.id, device.hostname)}<span>{scope === "internet" ? "Internet traffic" : "All traffic"}</span></li>)}
      </ul></>}
    </>;
  }
  const focusable = entity.kind === "zone" && entity.zone.hosts.length > 0;
  return <aside className="diagram-inspector" aria-label="Network diagram details">
    <header className="diagram-details-heading">
      <h4>{entityLabel(entity)}</h4>
      <button type="button" className="icon-button" aria-label="Close details" onClick={onClose}><X size={16} aria-hidden="true" /></button>
    </header>
    {(askAction || focusable) && <div className="diagram-detail-actions">
      {focusable && <button type="button" className="button-quiet" onClick={() => onFocus(entity.id)}>Focus subnet</button>}
      {askAction}
    </div>}
    {body}
    {findings.length > 0 && <ul className="diagram-findings">
      {findings.map((finding) => <li key={finding.message}>{finding.message}</li>)}
    </ul>}
  </aside>;
}

const RESULT_KINDS: Record<SearchResult["kind"], string> = {
  host: "Host", zone: "Subnet", sensor: "Sensor", equipment: "Device", containing: "Contains address",
};

/** Find a host, address, subnet, sensor or device. Press / to focus it from anywhere in Studio. */
function DiagramSearch({ search, onChoose }: { search: (query: string) => SearchResult[]; onChoose: (result: SearchResult) => void }) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useId();
  const results = useMemo(() => search(query), [search, query]);
  useEffect(() => {
    const shortcut = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
      if (target && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))) return;
      // Studio keeps inactive tabs mounted but hidden; only a visible diagram takes the shortcut.
      if (!input.current || input.current.closest("[hidden], [inert], [aria-hidden='true']")) return;
      event.preventDefault();
      input.current.focus();
      input.current.select();
    };
    document.addEventListener("keydown", shortcut);
    return () => document.removeEventListener("keydown", shortcut);
  }, []);
  const choose = (result: SearchResult | undefined) => {
    if (!result) return;
    onChoose(result);
    setOpen(false);
  };
  return <div className="diagram-search" onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setOpen(false); }}>
    <input ref={input} type="search" role="combobox" aria-label="Find in diagram" {...PLAIN_INPUT} aria-expanded={open && results.length > 0}
      aria-controls={list} aria-activedescendant={open && results[index] ? `${list}-${index}` : undefined}
      placeholder="Find host, IP or subnet" value={query}
      onChange={(event) => { setQuery(event.target.value); setIndex(0); setOpen(true); }}
      onFocus={() => setOpen(true)}
      onKeyDown={(event) => {
        if (event.key === "ArrowDown") { event.preventDefault(); setOpen(true); setIndex((value) => Math.min(results.length - 1, value + 1)); }
        else if (event.key === "ArrowUp") { event.preventDefault(); setIndex((value) => Math.max(0, value - 1)); }
        else if (event.key === "Enter") { event.preventDefault(); choose(results[index]); }
        else if (event.key === "Escape") { event.stopPropagation(); if (open && query) setOpen(false); else { setQuery(""); input.current?.blur(); } }
      }} />
    <kbd aria-hidden="true">/</kbd>
    {open && query.trim() && <ul id={list} role="listbox" aria-label="Diagram matches" className="diagram-search-results">
      {results.map((result, position) => <li key={result.kind + result.id} id={`${list}-${position}`} role="option" aria-selected={position === index}
        onMouseDown={(event) => event.preventDefault()} onMouseEnter={() => setIndex(position)} onClick={() => choose(result)}>
        <strong>{result.label}</strong><span>{result.detail}</span><small>{RESULT_KINDS[result.kind]}</small>
      </li>)}
      {!results.length && <li className="diagram-search-empty" role="presentation">No matches</li>}
    </ul>}
  </div>;
}

async function browserSave(image: Blob, filename: string): Promise<DownloadResult> {
  const objectUrl = URL.createObjectURL(image);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
  return { status: "browser" };
}

/** Saves the image on click; the menu beside it can copy it to the clipboard instead. */
function ExportMenu({ onSave, onCopy }: { onSave: () => void; onCopy: () => void }) {
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => { if (!menu.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  const choose = (action: () => void) => { setOpen(false); action(); };
  return <div className="diagram-export" ref={menu} onKeyDown={(event) => { if (event.key === "Escape" && open) { event.stopPropagation(); setOpen(false); } }}>
    <button type="button" className="button-quiet icon-only" aria-label="Save image of this view" title="Save an image of this view" onClick={onSave}>
      <Download size={16} aria-hidden="true" />
    </button>
    <button type="button" className="button-quiet diagram-export-more" aria-label="More export options" aria-haspopup="menu" aria-expanded={open}
      onClick={() => setOpen(!open)}><ChevronDown size={14} aria-hidden="true" /></button>
    {open && <div className="diagram-export-menu" role="menu" aria-label="Export">
      <button type="button" role="menuitem" onClick={() => choose(onSave)}><Download size={14} aria-hidden="true" />Save image as PNG…</button>
      <button type="button" role="menuitem" onClick={() => choose(onCopy)}><ClipboardCopy size={14} aria-hidden="true" />Copy image to clipboard</button>
    </div>}
  </div>;
}

function ChangesBanner({ changes, showing, onToggle, onDismiss }: {
  changes: DiagramChanges; showing: boolean; onToggle: () => void; onDismiss: () => void;
}) {
  const parts = [changes.added.size && `${changes.added.size} added`, changes.changed.size && `${changes.changed.size} changed`,
    changes.removed.length && `${changes.removed.length} removed`].filter(Boolean);
  return <div className="diagram-changes" role="status">
    <span><strong>Changed since the revision you last viewed:</strong> {parts.join(", ")}</span>
    {changes.removed.length > 0 && <details>
      <summary>Removed</summary>
      <ul>{changes.removed.map(({ id, label, kind }) => <li key={id}>{label} <small>{kind}</small></li>)}</ul>
    </details>}
    <button type="button" className="button-quiet" aria-pressed={showing} onClick={onToggle}>{showing ? "Hide changes" : "Show changes"}</button>
    <button type="button" className="icon-button" aria-label="Dismiss changes" onClick={onDismiss}><X size={14} aria-hidden="true" /></button>
  </div>;
}

function Minimap({ scene, view, size, onCenter }: {
  scene: DiagramScene; view: { x: number; y: number; scale: number }; size: { width: number; height: number };
  onCenter: (x: number, y: number) => void;
}) {
  const width = 180;
  const height = Math.max(60, Math.min(140, width * scene.height / scene.width));
  const scale = Math.min(width / scene.width, height / scene.height);
  const visible = { x: -view.x / view.scale, y: -view.y / view.scale, width: size.width / view.scale, height: size.height / view.scale };
  const zones = scene.zones.flatMap(function flatten(zone): PlacedZone[] { return [zone, ...zone.children.flatMap(flatten)]; });
  const dragging = useRef<number | null>(null);
  const move = (event: PointerEvent<SVGSVGElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    onCenter((event.clientX - box.left) / scale, (event.clientY - box.top) / scale);
  };
  const stop = (event: PointerEvent<SVGSVGElement>) => {
    if (dragging.current !== event.pointerId) return;
    dragging.current = null;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  };
  return <div className="diagram-minimap" aria-label="Overview map">
    <svg width={scene.width * scale} height={scene.height * scale} role="img" aria-label="Overview map, select or drag to move the view"
      onPointerDown={(event) => {
        event.stopPropagation();
        dragging.current = event.pointerId;
        event.currentTarget.setPointerCapture?.(event.pointerId);
        move(event);
      }}
      onPointerMove={(event) => { if (dragging.current === event.pointerId) move(event); }}
      onPointerUp={stop} onPointerCancel={stop}>
      <g transform={`scale(${scale})`}>
        {scene.sites.map((site) => <rect key={site.id} className="diagram-minimap-site" x={site.x} y={site.y} width={site.width} height={site.height} />)}
        {zones.map((zone) => <rect key={zone.zone.id} className="diagram-minimap-zone" x={zone.x} y={zone.y} width={zone.width} height={zone.height} />)}
        {scene.equipment.map(({ equipment, x, y }) => <circle key={equipment.id} className="diagram-minimap-device" cx={x} cy={y} r={14} />)}
        <rect className="diagram-minimap-view" x={visible.x} y={visible.y} width={visible.width} height={visible.height} />
      </g>
    </svg>
  </div>;
}

function Breadcrumb({ zoneId, siteId, scene, onOverview, onZone, onSite }: {
  zoneId: string | null; siteId: string | null; scene: DiagramScene;
  onOverview: () => void; onZone: (id: string) => void; onSite: (id: string) => void;
}) {
  const chain: Zone[] = [];
  for (let zone = zoneId ? scene.model.zones.get(zoneId) : undefined; zone; zone = zone.parentId ? scene.model.zones.get(zone.parentId) : undefined) chain.unshift(zone);
  const box = zoneId ? scene.bounds.get(zoneId) : undefined;
  const site = siteId ? scene.sites.find((entry) => entry.id === siteId)
    : box && scene.sites.find((entry) => box.x >= entry.x && box.x <= entry.x + entry.width && box.y >= entry.y && box.y <= entry.y + entry.height);
  const current = chain[chain.length - 1];
  return <nav className="diagram-breadcrumb" aria-label="Diagram location">
    <button type="button" onClick={onOverview}>Overview</button>
    {site && <span className="diagram-crumb"><span aria-hidden="true">›</span>
      {current ? <button type="button" onClick={() => onSite(site.id)}>Site {site.label}</button> : <strong aria-current="location">Site {site.label}</strong>}
    </span>}
    {chain.map((zone, index) => <span key={zone.id} className="diagram-crumb">
      <span aria-hidden="true">›</span>
      {index === chain.length - 1 ? <strong aria-current="location">{zone.name}</strong> : <button type="button" onClick={() => onZone(zone.id)}>{zone.name}</button>}
    </span>)}
    <small>{current ? `${current.hosts.length} hosts` : site?.summary ? `${site.summary.zones} subnets` : ""} · Esc to go back</small>
  </nav>;
}

function LayersMenu({ layers, available, showScopes, scopeCount, onLayer, onScopes }: {
  layers: DiagramLayers; available: DiagramLayers; showScopes: boolean; scopeCount: number;
  onLayer: (key: keyof DiagramLayers) => void; onScopes: () => void;
}) {
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => { if (!menu.current?.contains(event.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  const keys = Object.keys(LAYER_LABELS) as (keyof DiagramLayers)[];
  const shown = keys.filter((key) => available[key] && layers[key]).length;
  const total = keys.filter((key) => available[key]).length;
  return <div className="diagram-layers" ref={menu} onKeyDown={(event) => { if (event.key === "Escape" && open) { event.stopPropagation(); setOpen(false); } }}>
    <button type="button" className="button-quiet" aria-expanded={open} aria-haspopup="true" onClick={() => setOpen(!open)}>
      <Layers size={15} aria-hidden="true" /> Layers {shown < total && <span className="muted">{shown}/{total}</span>}<ChevronDown size={14} aria-hidden="true" />
    </button>
    {open && <div className="diagram-layers-panel" role="group" aria-label="Diagram layers">
      <Tooltip.Provider delayDuration={200}>
        {keys.map((key) => <div key={key} className="diagram-layer-row">
          <label title={available[key] ? undefined : `No ${LAYER_LABELS[key].toLowerCase()} in this environment`}>
            <input type="checkbox" checked={layers[key] && available[key]} disabled={!available[key]} onChange={() => onLayer(key)} />{LAYER_LABELS[key]}
          </label>
          <LayerHelp label={LAYER_LABELS[key]} text={LAYER_HELP[key]} />
        </div>)}
        {scopeCount > 0 && <div className="diagram-layer-row">
          <label><input type="checkbox" checked={showScopes} onChange={onScopes} />Firewall policy scopes</label>
          <LayerHelp label="Firewall policy scopes" text={LAYER_HELP.scopes} />
        </div>}
      </Tooltip.Provider>
    </div>}
  </div>;
}

function LayerHelp({ label, text }: { label: string; text: string }) {
  return <Tooltip.Root>
    <Tooltip.Trigger asChild>
      <span className="diagram-layer-help" tabIndex={0} role="img" aria-label={`About ${label}: ${text}`}><Info size={14} aria-hidden="true" /></span>
    </Tooltip.Trigger>
    <Tooltip.Portal><Tooltip.Content className="state-tooltip" side="right" sideOffset={6}>{text}<Tooltip.Arrow className="state-tooltip-arrow" /></Tooltip.Content></Tooltip.Portal>
  </Tooltip.Root>;
}

function DiagramKey({ scene, showScopes, scopes, segments }: { scene: DiagramScene; showScopes: boolean; scopes: FirewallScope[]; segments: TopologyGraph["segments"] }) {
  const { model } = scene;
  const kinds = new Set([...model.equipment.values()].map(({ kind }) => kind));
  const styles = new Set(scene.wires.map(({ style }) => style));
  const linkKinds = new Set(scene.wires.map(({ linkKind }) => linkKind));
  const placements = new Set(model.sensors.map(({ placement }) => placement));
  const families = new Set(model.sensors.flatMap(({ evidence }) => (evidence ?? []).map(({ family }) => family)));
  const names = new Map(segments.map(({ id, name }) => [id, name]));
  const entries: [string, ReactNode][] = [];
  const swatch = (className: string) => <svg width="30" height="10" aria-hidden="true"><path className={className} d="M 1 5 H 29" /></svg>;
  if (kinds.has("firewall")) entries.push(["Firewall", <span className="diagram-key-glyph" data-kind="firewall" />]);
  if (kinds.has("router") || kinds.has("network")) entries.push(["Router", <span className="diagram-key-glyph" />]);
  if (kinds.has("switch")) entries.push(["Switch", <span className="diagram-key-glyph" />]);
  if (linkKinds.has("network") && (styles.has("interface") || !styles.size)) entries.push(["Link", swatch("diagram-key-line")]);
  if (linkKinds.has("wan")) entries.push(["WAN link", swatch("diagram-key-line wan")]);
  if (linkKinds.has("vpn")) entries.push(["VPN link", swatch("diagram-key-line vpn")]);
  if (styles.has("inferred")) entries.push(["Inferred link", swatch("diagram-key-line inferred")]);
  if (styles.has("observes")) entries.push(["Monitored by firewall", swatch("diagram-key-line observes")]);
  if (styles.has("membership")) entries.push(["Address in subnet", swatch("diagram-key-line membership")]);
  if (placements.has("tap")) entries.push(["TAP", <span className="diagram-key-mark" data-placement="tap" />]);
  if (placements.has("span")) entries.push(["SPAN", <span className="diagram-key-mark" data-placement="span" />]);
  if (families.has("zeek")) entries.push(["Zeek network logs", <span className="diagram-key-chip" data-family="zeek">Zeek</span>]);
  if (families.has("ids")) entries.push(["Snort IDS alerts", <span className="diagram-key-chip" data-family="ids">Snort</span>]);
  if (scene.zones.some(function has(zone): boolean { return zone.zone.hosts.some(({ public_address }) => public_address) || zone.children.some(has); })) {
    entries.push(["Public address (per host)", <span className="diagram-key-chip" data-family="public">public</span>]);
  }
  if (!entries.length && !(showScopes && scopes.length)) return null;
  return <details className="diagram-key" open aria-label="Diagram key">
    <summary>Key</summary>
    <ul>{entries.map(([label, symbol]) => <li key={label}>{symbol}{label}</li>)}</ul>
    {showScopes && scopes.length > 0 && <ul aria-label="Firewall policy scopes">
      {scopes.map((scope) => <li key={scope.id} title={[...scope.segments].map((id) => names.get(id) ?? id).join(", ")}>
        <svg width="22" height="14" viewBox="0 0 22 14" style={{ color: scope.color }} aria-hidden="true">
          <rect className="diagram-scope-swatch" x={1} y={1} width={20} height={12} rx={3} strokeDasharray={scope.dash} />
        </svg>{scope.label}
      </li>)}
    </ul>}
  </details>;
}

export function NetworkDiagram({ graph, context, description, actions, revision, onAsk, historyKey, exportName, onSaveImage }: {
  graph: TopologyGraph; context?: string; description?: string; actions?: ReactNode;
  revision?: string; onAsk?: (context: NetworkChatContext) => Promise<void>;
  /** File name, without extension, suggested when saving the diagram image. */
  exportName?: string;
  /** Saves a rendered image; Studio passes its native save dialog. Defaults to a browser download. */
  onSaveImage?: (image: Blob, filename: string) => Promise<DownloadResult>;
  /** Identifies the item across revisions, so the diagram can show what changed since it was last shown. */
  historyKey?: string;
}) {
  const title = useId();
  const viewport = useRef<SVGSVGElement>(null);
  const canvas = useRef<HTMLDivElement>(null);
  const [surface, setSurface] = useState<HTMLDivElement | null>(null);
  const trackCanvas = useCallback((element: HTMLDivElement | null) => {
    canvas.current = element;
    setSurface(element);
  }, []);
  const expandButton = useRef<HTMLButtonElement>(null);
  const restoreButton = useRef<HTMLButtonElement>(null);
  const drag = useRef<Drag | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [asking, setAsking] = useState(false);
  const [askError, setAskError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [showScopes, setShowScopes] = useState(false);
  const [layers, setLayers] = useState<DiagramLayers>({ sensors: true, hosts: true });
  const [pendingReveal, setPendingReveal] = useState<{ id: string; tries: number; fit?: boolean } | null>(null);
  const [focusZone, setFocusZone] = useState<string | null>(null);
  const [focusSite, setFocusSite] = useState<string | null>(null);
  const [lens, setLens] = useState<"topology" | "coverage">("topology");
  const [trace, setTrace] = useState<Set<string> | null>(null);
  const [changes, setChanges] = useState<DiagramChanges | null>(() => historyKey && revision ? changesSinceLastShown(historyKey, revision, graph) : null);
  const [showChanges, setShowChanges] = useState(true);
  const [exportStatus, setExportStatus] = useState("");
  useEffect(() => { if (historyKey && revision) rememberShown(historyKey, revision, graph); }, [historyKey, revision, graph]);
  const changeOf = (id: string) => !changes || !showChanges ? undefined : changes.added.has(id) ? "added" : changes.changed.has(id) ? "changed" : undefined;
  const [size, setSize] = useState(INITIAL_SIZE);
  const [camera, setCamera] = useState<Camera | "fit" | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [focused, setFocused] = useState<string | null>(null);
  const [zoneDetail, setZoneDetail] = useState<Record<string, Detail>>({});
  const [siteChoices, setSiteChoices] = useState<Record<string, boolean>>({});
  const [layoutSize, setLayoutSize] = useState(INITIAL_SIZE);
  const scene = useMemo(() => layoutNetworkDiagram(graph, layers, { viewport: layoutSize, zoneDetail, siteChoices }),
    [graph, layers, layoutSize, zoneDetail, siteChoices]);
  const hasNodes = scene.zones.length > 0 || scene.equipment.length > 0 || scene.sites.length > 0;
  const scale = Math.min(1.05, size.width / scene.width, size.height / scene.height);
  const centered = (value: number): Camera => ({
    x: (size.width - scene.width * value) / 2,
    y: (size.height - scene.height * value) / 2,
    scale: value,
  });
  const fit = centered(scale);
  const readable = centered(Math.max(MIN_READABLE_SCALE, scale));
  const initialView = { ...readable, x: Math.max(0, readable.x), y: Math.max(0, readable.y) };
  const view = camera === "fit" ? fit : camera ?? initialView;
  const previewId = [hovered, focused].find((id) => id && scene.entities.has(id));
  const pinned = selected ? scene.entities.get(selected) : undefined;
  const preview = previewId ? scene.entities.get(previewId) : undefined;
  const active = preview?.id ?? pinned?.id;
  const covered = new Set(active ? scene.coverage.get(active) ?? [] : []);
  const { scopes, scopesBySegment } = useMemo(() => indexFirewallScopes(graph), [graph]);
  // Search and reveal use every entity, including those in hidden layers.
  const fullModel = useMemo(() => buildDiagramModel(graph, { sensors: true, hosts: true }), [graph]);
  const findings = useMemo(() => {
    const byEntity = new Map<string, string[]>();
    for (const { entity_id, message } of graph.findings) byEntity.set(entity_id, [...(byEntity.get(entity_id) ?? []), message]);
    return byEntity;
  }, [graph.findings]);
  const findingLabel = (id: string) => {
    const count = findings.get(id)?.length ?? 0;
    return count ? `, ${count} ${count === 1 ? "finding" : "findings"}` : "";
  };
  const layerAvailability: DiagramLayers = {
    sensors: graph.devices.some((device) => device.kind !== "firewall"),
    hosts: graph.hosts.length > 0,
  };
  const hasFirewalls = graph.devices.some((device) => device.kind === "firewall");
  // A selected device or subnet lights its links; a selected sensor lights what it observes instead.
  const highlighted = (entities: string[]) => !!active && entities.includes(active);

  useEffect(() => {
    if (!surface || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (!width || !height) return;
      setSize({ width, height });
      setLayoutSize((previous) => previous.width === width && previous.height === height ? previous : { width, height });
    });
    observer.observe(surface);
    return () => observer.disconnect();
  }, [surface]);

  const previousSize = useRef(size);
  useLayoutEffect(() => {
    const previous = previousSize.current;
    previousSize.current = size;
    if (previous === size) return;
    setCamera((current) => current && current !== "fit" ? {
      ...current, x: current.x + (size.width - previous.width) / 2, y: current.y + (size.height - previous.height) / 2,
    } : current);
  }, [size]);

  function resizeDiagram(value: boolean) {
    setHovered(null);
    setFocused(null);
    setCamera(null);
    setExpanded(value);
  }

  function zoom(factor: number, x = size.width / 2, y = size.height / 2) {
    setCamera((camera) => {
      const current = camera === "fit" ? fit : camera ?? initialView;
      const nextScale = Math.min(3, Math.max(Math.min(0.25, scale), current.scale * factor));
      if (nextScale === current.scale) return camera;
      const ratio = nextScale / current.scale;
      return { x: x + (current.x - x) * ratio, y: y + (current.y - y) * ratio, scale: nextScale };
    });
  }

  const wheelZoom = useEffectEvent((event: WheelEvent, target: HTMLDivElement) => {
    if (!target.contains(target.ownerDocument.activeElement) || !event.deltaY) return;
    event.preventDefault();
    const { left, top, height } = target.getBoundingClientRect();
    const units = event.deltaMode === WheelEvent.DOM_DELTA_LINE ? 16 :
      event.deltaMode === WheelEvent.DOM_DELTA_PAGE ? height : 1;
    const delta = Math.max(-360, Math.min(360, event.deltaY * units));
    zoom(Math.exp(-delta / 360), event.clientX - left, event.clientY - top);
  });
  useEffect(() => {
    if (!surface) return;
    const handleWheel = (event: WheelEvent) => wheelZoom(event, surface);
    surface.addEventListener("wheel", handleWheel, { capture: true, passive: false });
    return () => surface.removeEventListener("wheel", handleWheel, true);
  }, [surface]);

  function startDrag(event: PointerEvent<SVGSVGElement>) {
    if (event.button !== 0) return;
    event.preventDefault();
    canvas.current?.focus({ preventScroll: true });
    if ((event.target as Element).closest(".diagram-node")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = { pointer: event.pointerId, x: event.clientX, y: event.clientY, camera: view };
    setDragging(true);
  }

  function moveDrag(event: PointerEvent<SVGSVGElement>) {
    const start = drag.current;
    if (start?.pointer !== event.pointerId) return;
    setCamera({ x: start.camera.x + event.clientX - start.x, y: start.camera.y + event.clientY - start.y, scale: start.camera.scale });
  }

  function stopDrag(event: PointerEvent<SVGSVGElement>) {
    if (drag.current?.pointer !== event.pointerId) return;
    drag.current = null;
    setDragging(false);
  }

  function panByKeyboard(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Escape" && !expanded) {
      if (selected) setSelected(null);
      else if (focusZone || focusSite) showOverview();
      return;
    }
    if (event.currentTarget !== event.target) return;
    const offset = { ArrowLeft: [48, 0], ArrowRight: [-48, 0], ArrowUp: [0, 48], ArrowDown: [0, -48] }[event.key];
    if (!offset) return;
    event.preventDefault();
    setCamera({ ...view, x: view.x + offset[0], y: view.y + offset[1] });
  }

  // Keep revealed items clear of the floating key and the details panel.
  function clearArea() {
    const frame = canvas.current?.getBoundingClientRect();
    const key = canvas.current?.querySelector(".diagram-key")?.getBoundingClientRect();
    const panel = canvas.current?.parentElement?.querySelector(".diagram-inspector")?.getBoundingClientRect();
    const crumb = canvas.current?.querySelector(".diagram-breadcrumb")?.getBoundingClientRect();
    const bottom = frame && key?.height ? key.top - frame.top - 8 : size.height - 4;
    const right = frame && panel?.width ? panel.left - frame.left - 8 : size.width - 4;
    const top = frame && crumb?.height ? crumb.bottom - frame.top + 8 : 4;
    return { left: 4, top: top < size.height / 3 ? top : 4, right: right > size.width / 3 ? right : size.width - 4, bottom: bottom > size.height / 3 ? bottom : size.height - 4 };
  }

  // Sensors and links have no box of their own; reveal something they connect to.
  function revealBox(id: string): Bounds | undefined {
    const own = scene.bounds.get(id);
    if (own) return own;
    for (const target of scene.coverage.get(id) ?? []) {
      const box = scene.bounds.get(target);
      if (box) return box;
    }
    const transit = scene.model.transits.get(id);
    return transit?.ends.map(({ equipmentId }) => scene.bounds.get(equipmentId)).find(Boolean);
  }

  function fitTo(box: Bounds) {
    const area = clearArea();
    const pad = 28;
    const value = Math.min(2.2, (area.right - area.left - pad * 2) / box.width, (area.bottom - area.top - pad * 2) / box.height);
    setCamera({ scale: value, x: (area.left + area.right) / 2 - (box.x + box.width / 2) * value,
      y: (area.top + area.bottom) / 2 - (box.y + box.height / 2) * value });
  }

  function reveal(id: string) {
    const box = revealBox(id);
    if (!box) return;
    const area = clearArea();
    const left = box.x * view.scale + view.x;
    const top = box.y * view.scale + view.y;
    const right = left + box.width * view.scale;
    const bottom = top + box.height * view.scale;
    if (left >= area.left && right <= area.right && top >= area.top && bottom <= area.bottom) return;
    setCamera({ ...view, x: (area.left + area.right) / 2 - (box.x + box.width / 2) * view.scale,
      y: (area.top + area.bottom) / 2 - (box.y + box.height / 2) * view.scale });
  }

  const coverage = useMemo(() => indexCoverage(graph, (id) => id === INTERNET || fullModel.zones.has(id)), [graph, fullModel]);
  // A traced flow lights the links it crosses and the devices that forward it.
  const traced = (entities: string[]) => !!trace && (entities.some((id) => id.startsWith("link:") && trace.has(id))
    || (entities.some((id) => trace.has(id) && scene.model.equipment.has(id)) && entities.some((id) => trace.has(id) && scene.model.zones.has(id))));
  const search = useCallback((query: string) => searchDiagram(graph, fullModel, query), [graph, fullModel]);
  const hostZone = (id: string) => [...fullModel.zones.values()].find(({ hosts }) => hosts.some((member) => member.id === id));

  /**
   * Select an item and bring it into view. It may first need a hidden layer, a collapsed site or
   * a summarized subnet to be shown; each step changes the scene, so reveal continues afterward.
   */
  function selectFromDetails(id: string, options: { fit?: boolean } = {}) {
    const isHost = id.startsWith("host:") && !!hostZone(id);
    const isSensor = fullModel.sensors.some((device) => device.id === id);
    if (!scene.entities.has(id) && !isHost && !isSensor) return;
    setHovered(null);
    setFocused(null);
    setSelected(id);
    canvas.current?.focus({ preventScroll: true });
    if (isHost && !layers.hosts) setLayers((current) => ({ ...current, hosts: true }));
    if (isSensor && !layers.sensors) setLayers((current) => ({ ...current, sensors: true }));
    setPendingReveal({ id, tries: 0, fit: options.fit });
  }
  useEffect(() => {
    if (!pendingReveal) return;
    const { id, tries, fit: fitBox } = pendingReveal;
    const box = scene.bounds.get(id);
    if (box || (tries > 0 && revealBox(id))) {
      if (fitBox && box) fitTo(box); else reveal(id);
      setPendingReveal(null);
      return;
    }
    if (tries > 3) { setPendingReveal(null); return; }
    const site = scene.collapsedSite.get(id) ?? scene.collapsedSite.get(hostZone(id)?.id ?? "");
    if (site) setSiteChoices((current) => ({ ...current, [site]: true }));
    const zone = id.startsWith("host:") ? hostZone(id) : undefined;
    if (zone) setZoneDetail((current) => ({ ...current, [zone.id]: "hosts" }));
    setPendingReveal({ id, tries: tries + 1, fit: fitBox });
    // Each pass runs after the scene reflects the previous step.
  }, [scene, pendingReveal]);

  /** Zoom into one subnet at host detail; the breadcrumb leads back out. */
  function focusOn(id: string) {
    if (!fullModel.zones.has(id)) return;
    setZoneDetail((current) => ({ ...current, [id]: "hosts" }));
    setFocusZone(id);
    setFocusSite(null);
    selectFromDetails(id, { fit: true });
  }

  /** Zoom to one site, expanding it first when it is collapsed. */
  function focusOnSite(id: string) {
    setFocusZone(null);
    setFocusSite(id);
    setSelected(null);
    if (scene.sites.find((site) => site.id === id)?.collapsed) setSiteChoices((current) => ({ ...current, [id]: true }));
    setPendingReveal({ id: "site:" + id, tries: 0, fit: true });
  }

  function showOverview() {
    setFocusZone(null);
    setFocusSite(null);
    setCamera("fit");
  }

  function toggleSelection(id: string) {
    setSelected((current) => current === id ? null : id);
  }

  /** Save or copy exactly the map as shown: its zoom, pan, collapsed sites and layers. */
  async function exportImage(mode: "save" | "copy") {
    const displayedMap = viewport.current;
    if (!displayedMap) return;
    const done = (message: string) => { setExportStatus(message); window.setTimeout(() => setExportStatus(""), 4000); };
    try {
      if (mode === "copy") {
        setExportStatus("Copying…");
        await copyViewImage(() => captureViewImage(displayedMap));
        done("Image copied");
      } else {
        const image = await captureViewImage(displayedMap);
        const name = `${(exportName ?? "network-diagram").trim().replace(/[\\/:*?"<>|]+/g, "-") || "network-diagram"}.png`;
        const result = await (onSaveImage ?? browserSave)(image, name);
        done(result.status === "cancelled" ? "" : result.status === "saved" ? "Image saved" : "Image downloaded");
      }
    } catch (error) {
      done(error instanceof Error ? error.message : String(error));
    }
  }

  async function askAbout(entity?: DiagramEntity) {
    if (!onAsk || !revision || !viewport.current || asking) return;
    setAsking(true);
    setAskError("");
    try {
      const image = await captureNetworkView(viewport.current).catch(() => null);
      await onAsk({
        revision, topology: { ...graph, coverage: undefined }, image, firewall_scopes_visible: showScopes && scopes.length > 0,
        selected_id: entity?.id, selection_label: entity && entityLabel(entity),
        visible_layers: [
          ...(layers.sensors && layerAvailability.sensors ? ["sensors" as const] : []),
          ...(hasFirewalls ? ["firewalls" as const] : []),
          ...(layers.hosts && layerAvailability.hosts ? ["hosts" as const] : []),
        ],
        expanded_subnet_ids: scene.zones.flatMap(function hosts(zone): string[] {
          return [...(zone.detail === "hosts" ? [zone.zone.id] : []), ...zone.children.flatMap(hosts)];
        }),
        sensor_key: {},
      });
      setExpanded(false);
    } catch (error) {
      setAskError(String(error));
    } finally {
      setAsking(false);
    }
  }

  const interactive = (id: string, label: string, extra: Record<string, unknown> = {}) => ({
    role: "button", tabIndex: 0, "aria-label": label, "aria-pressed": selected === id, "data-active": active === id,
    onMouseEnter: () => setHovered(id), onMouseLeave: () => setHovered(null),
    onFocus: () => { setFocused(id); reveal(id); }, onBlur: () => setFocused(null),
    onClick: (event: { currentTarget: SVGGElement }) => { toggleSelection(id); event.currentTarget.focus({ preventScroll: true }); },
    onKeyDown: (event: KeyboardEvent<SVGGElement>) => activateByKey(event, () => toggleSelection(id)),
    ...extra,
  });

  const chip = (placed: PlacedChip, x: number, y: number) => {
    const family = placed.device.evidence?.[0]?.family ?? "other";
    const width = placed.width;
    return <g key={placed.key} className="diagram-node diagram-chip" transform={`translate(${x + placed.x} ${y + placed.y})`}
      data-family={family} data-placement={placed.device.placement} data-related={active === placed.device.id || !!trace?.has(placed.device.id)}
      data-finding={findings.has(placed.device.id) || undefined} data-change={changeOf(placed.device.id)}
      {...interactive(placed.device.id, sensorLabel(placed.device) + findingLabel(placed.device.id))}>
      <rect className="diagram-chip-box" width={width} height={18} rx={9} />
      {placed.device.placement === "tap" ? <circle className="diagram-chip-mark" cx={10} cy={9} r={3.4} />
        : <path className="diagram-chip-mark" d="M 10 5 l 4 4 -4 4 -4 -4 z" />}
      <text x={19} y={12.6} className="diagram-chip-label" aria-hidden="true">{placed.label}</text>
      <title>{[placed.device.hostname, ...sensorLogs(placed.device)].join("\n")}</title>
    </g>;
  };

  const hostNode = (zone: PlacedZone, card: PlacedHost, compact: boolean) => {
    const { host } = card;
    return <g key={zone.zone.id + host.id} className="diagram-node diagram-host-card" transform={`translate(${zone.x + card.x} ${zone.y + card.y})`}
      data-compact={compact || undefined} data-public={!!host.public_address || undefined} data-finding={findings.has(host.id) || undefined}
      data-change={changeOf(host.id)}
      {...interactive(host.id, hostLabel(host) + findingLabel(host.id))}>
      <rect className="diagram-host-box" width={card.width} height={card.height} rx={compact ? 6 : 8} />
      {compact ? <>
        <CategoryIcon category={card.category} size={13} x={6} y={3.5} />
        <text x={24} y={14} className="diagram-host-name" aria-hidden="true">{host.hostname}</text>
      </> : <>
        <CategoryIcon category={card.category} size={20} x={10} y={8} />
        <text x={8} y={42} className="diagram-os-badge" data-family={host.os_family} aria-hidden="true">{(OS_LABELS[host.os_family] ?? "Other").slice(0, 3).toUpperCase()}</text>
        <text x={40} y={18} className="diagram-host-name" aria-hidden="true">{host.hostname}</text>
        <text x={40} y={32} className="diagram-host-ip" aria-hidden="true">{host.ip}</text>
        <text x={40} y={44} className="diagram-host-os" aria-hidden="true">{host.public_address ? `public ${host.public_address}` : shortOs(host.os)}</text>
      </>}
      <title>{`${host.hostname} · ${host.ip} · ${host.os}${host.public_address ? ` · public ${host.public_address}` : ""}`}</title>
    </g>;
  };

  const zoneNodes = (zone: PlacedZone): ReactNode[] => {
    const { zone: model } = zone;
    const segmentScopes = showScopes ? scopesBySegment.get(model.id) : undefined;
    const detail = zone.detail;
    const nodes: ReactNode[] = [
      <g key={model.id} className="diagram-node diagram-zone" transform={`translate(${zone.x} ${zone.y})`}
        data-unassigned={model.unassigned || undefined} data-covered={covered.has(model.id) || undefined}
        data-finding={findings.has(model.id) || undefined} onDoubleClick={() => focusOn(model.id)}
        data-coverage={lens === "coverage" ? coverage?.weakest(model.id) : undefined} data-traced={trace?.has(model.id) || undefined}
        data-change={changeOf(model.id)}
        {...interactive(model.id, zoneLabel(model) + findingLabel(model.id)
          + (lens === "coverage" && coverage?.within(model.id) === "none" ? ", traffic within it is not observed" : ""))}>
        {segmentScopes?.map((scope, index) => <rect key={scope.id} className="diagram-scope-highlight" x={-4 - index * 4} y={-4 - index * 4}
          width={zone.width + 8 + index * 8} height={zone.height + 8 + index * 8} rx={12 + index * 2} style={{ color: scope.color }} strokeDasharray={scope.dash}>
          <title>{scope.label}</title></rect>)}
        <rect className="diagram-zone-box" width={zone.width} height={zone.height} />
        <text x={12} y={20} className="diagram-zone-name" aria-hidden="true">{model.name}</text>
        {findings.has(model.id) && <FindingBadge x={zone.width - 14} y={14} messages={findings.get(model.id)!} />}
        {lens === "coverage" && coverage?.within(model.id) === "none" && <text x={zone.width - (findings.has(model.id) ? 30 : 12)}
          y={12 + textWidth(model.name, 13.5) + 14 + textWidth("Unobserved within", 10.5) + (findings.has(model.id) ? 30 : 12) > zone.width ? 35 : 20} textAnchor="end"
          className="diagram-within-blind" aria-hidden="true">Unobserved within<title>No network sensor sees traffic between hosts in this subnet</title></text>}
        {model.cidr && <text x={12} y={35} className="diagram-zone-cidr" aria-hidden="true">{model.cidr}</text>}
        {zone.summary.length > 0 && <g aria-hidden="true" transform={`translate(12 ${zone.chips.length ? 70 : 46})`}>
          {(() => {
            let x = 0;
            return zone.summary.map(({ category, count }) => {
              const text = zone.summary.length <= 2 ? `${count} ${categoryLabel(category, count)}` : String(count);
              const node = <g key={category} transform={`translate(${x} 0)`}>
                <CategoryIcon category={category} size={15} x={0} y={0} /><text x={19} y={12} className="diagram-zone-count">{text}</text>
                <title>{`${count} ${categoryLabel(category, count)}`}</title>
              </g>;
              x += 19 + text.length * 7 + 14;
              return node;
            });
          })()}
          <text x={0} y={32} className="diagram-zone-os">{zone.osSummary}</text>
        </g>}
        {model.hosts.length === 0 && model.children.length === 0 && <text x={12} y={zone.chips.length ? 82 : 60} className="diagram-zone-empty" aria-hidden="true">No hosts</text>}
        {zone.hiddenHosts > 0 && <text x={12} y={zone.toggleY - 8} className="diagram-zone-os" aria-hidden="true">{zone.hiddenHosts} more in details</text>}
      </g>,
    ];
    zone.chips.forEach((placed) => nodes.push(chip(placed, zone.x, zone.y)));
    if (zone.overflow.length) {
      const last = zone.chips[zone.chips.length - 1];
      const x = last ? last.x + last.width + 6 : 12;
      nodes.push(<g key={model.id + ":more"} className="diagram-node diagram-chip" data-family="more" transform={`translate(${zone.x + x} ${zone.y + zone.chipY})`}
        {...interactive(model.id, `Show ${zone.overflow.length} more sensors on ${model.name}`)}>
        <rect className="diagram-chip-box" width={34} height={18} rx={9} /><text x={17} y={12.6} textAnchor="middle" className="diagram-chip-label">+{zone.overflow.length}</text>
      </g>);
    }
    zone.groupLabels.forEach((label) => nodes.push(<text key={model.id + label.text} x={zone.x + label.x} y={zone.y + label.y}
      className="diagram-group-label" aria-hidden="true">{label.text}</text>));
    zone.names.forEach((card) => nodes.push(hostNode(zone, card, true)));
    zone.hostCards.forEach((card) => nodes.push(hostNode(zone, card, false)));
    zone.publicHosts.forEach((host, index) => {
      const y = (zone.chips.length ? 70 : 46) + 40 + index * 24;
      nodes.push(<g key={model.id + host.id + ":public"} className="diagram-node diagram-public" transform={`translate(${zone.x + 12} ${zone.y + y})`}
        {...interactive(host.id, `${host.hostname} public address ${host.public_address}`)}>
        <rect className="diagram-public-box" width={zone.width - 24} height={20} rx={6} />
        <Globe size={13} x={6} y={3.5} aria-hidden="true" />
        <text x={24} y={14} className="diagram-public-label" aria-hidden="true">{`${host.hostname} → ${host.public_address}`}</text>
      </g>);
    });
    if (zone.morePublic) nodes.push(<text key={model.id + ":more-public"} x={zone.x + 12} y={zone.y + (zone.chips.length ? 70 : 46) + 40 + zone.publicHosts.length * 24 + 10}
      className="diagram-zone-os" aria-hidden="true">{zone.morePublic} more with public addresses</text>);
    if (model.hosts.length > 4 || detail === "hosts") {
      const next: Detail = detail === "hosts" ? "overview" : "hosts";
      const toggle = () => setZoneDetail((current) => ({ ...current, [model.id]: next }));
      const caption = detail === "hosts" ? "Collapse hosts" : `Show ${model.hosts.length} hosts`;
      nodes.push(<g key={model.id + ":toggle"} className="diagram-node diagram-zone-toggle" role="button" tabIndex={0}
        aria-label={`${detail === "hosts" ? "Collapse" : "Expand"} ${model.name} hosts`} aria-expanded={detail === "hosts"}
        transform={`translate(${zone.x + 12} ${zone.y + zone.toggleY})`} onClick={toggle} onKeyDown={(event) => activateByKey(event, toggle)}>
        <rect className="diagram-toggle-box" width={caption.length * 6.4 + 22} height={18} rx={5} />
        <text x={8} y={12.5} aria-hidden="true">{caption}{detail === "hosts" ? " ▴" : " ▾"}</text>
      </g>);
      if (!zone.summary.length && detail !== "hosts") nodes.push(<text key={model.id + ":count"} x={zone.x + zone.width - 12} y={zone.y + zone.toggleY + 13}
        textAnchor="end" className="diagram-zone-os" aria-hidden="true">{model.hosts.length} hosts</text>);
    }
    if (zone.summary.length) nodes.push(<text key={model.id + ":count"} x={zone.x + zone.width - 12} y={zone.y + zone.toggleY + 13}
      textAnchor="end" className="diagram-zone-os" aria-hidden="true">{model.hosts.length} hosts</text>);
    for (const child of zone.children) nodes.push(...zoneNodes(child));
    return nodes;
  };

  const diagram = <section className="network-diagram" aria-labelledby={title}>
    <h3 id={title} className="sr-only">Network diagram</h3>
    <div className="diagram-toolbar">
      <div className="diagram-controls">
        <LayersMenu layers={layers} available={layerAvailability} showScopes={showScopes} scopeCount={scopes.length}
          onLayer={(key) => { setLayers({ ...layers, [key]: !layers[key] }); setHovered(null); setFocused(null); setCamera(null); }}
          onScopes={() => setShowScopes(!showScopes)} />
        {hasNodes && <div className="diagram-lens" role="group" aria-label="Diagram view">
          <button type="button" aria-pressed={lens === "topology"} onClick={() => setLens("topology")}>Topology</button>
          <button type="button" aria-pressed={lens === "coverage"} disabled={!coverage} onClick={() => setLens("coverage")}
            title={coverage ? "Outline each subnet by the weakest network evidence for traffic reaching it from elsewhere"
              : "Visibility needs network sensors and a compiled environment"}>Visibility</button>
        </div>}
        {hasNodes && <DiagramSearch search={search} onChoose={({ id }) => selectFromDetails(id)} />}
        {(description || context) && <p className="muted diagram-context" title={description || context}>{description || context}</p>}
      </div>
      <div className="diagram-controls">
        {onAsk && revision && hasNodes && <button type="button" className="button-quiet diagram-ask" disabled={asking}
          aria-label="Ask about this diagram" title="Ask about this diagram" onClick={() => void askAbout()}>
          <Sparkles size={15} aria-hidden="true" />Ask</button>}
        {actions}
        {exportStatus && <span className="muted diagram-copy-status" role="status">{exportStatus}</span>}
        {hasNodes && <ExportMenu onSave={() => void exportImage("save")} onCopy={() => void exportImage("copy")} />}
        {expanded
          ? <button ref={restoreButton} type="button" className="button-quiet icon-only" aria-label="Exit expanded view" title="Exit expanded view" onClick={() => resizeDiagram(false)}><Minimize size={16} aria-hidden="true" /></button>
          : hasNodes && <button ref={expandButton} type="button" className="button-quiet icon-only" aria-label="Expand diagram" title="Expand diagram" onClick={() => resizeDiagram(true)}><Expand size={16} aria-hidden="true" /></button>}
      </div>
    </div>
    {hasNodes && scene.model.inferredLinks && <p className="diagram-notice" title="Add authored routing for exact links and paths.">
      <strong>Segment-based model:</strong> dashed links are inferred from firewall interfaces and monitored segments.
    </p>}
    {askError && <p role="alert">{askError}</p>}
    {changes && <ChangesBanner changes={changes} showing={showChanges} onToggle={() => setShowChanges(!showChanges)} onDismiss={() => setChanges(null)} />}
    {graph.segments.length === 0 && <p className="muted">No network segments are declared.</p>}
    {hasNodes ? <div className="diagram-body">
      <div ref={trackCanvas} className="diagram-canvas" role="group" tabIndex={0} data-focused={focusZone || focusSite ? true : undefined}
        aria-label="Network map, use arrow keys to pan and the wheel to zoom when focused" onKeyDown={panByKeyboard}>
        <svg ref={viewport} className="diagram-viewport" data-dragging={dragging}
          onPointerDown={startDrag} onPointerMove={moveDrag} onPointerUp={stopDrag}
          onPointerCancel={stopDrag} onLostPointerCapture={stopDrag}>
          <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
            {scene.sites.filter(({ collapsed }) => !collapsed).map((site) => {
              const collapse = () => setSiteChoices((current) => ({ ...current, [site.id]: false }));
              return <g key={site.id} className="diagram-site" transform={`translate(${site.x} ${site.y})`}>
                <rect className="diagram-site-frame" width={site.width} height={site.height} />
                <g className="diagram-node diagram-site-label" role="button" tabIndex={0} aria-label={`Collapse site ${site.label}`}
                  onClick={collapse} onDoubleClick={() => focusOnSite(site.id)} onKeyDown={(event) => activateByKey(event, collapse)}>
                  <text x={16} y={18}>{`SITE · ${site.label}`.toUpperCase()}</text>
                </g>
              </g>;
            })}
            <g aria-hidden="true" className="diagram-edges">{scene.wires.map((wire) =>
              <path key={wire.key} d={wire.path} data-style={wire.style} data-link-kind={wire.linkKind}
                data-highlighted={trace ? traced(wire.entities) : highlighted(wire.entities)} />)}
            </g>
            {/* Collapsed site cards sit above the links, which then end at the card's edge. */}
            {scene.sites.filter(({ collapsed }) => collapsed).map((site) => {
              const toggle = () => setSiteChoices((current) => ({ ...current, [site.id]: true }));
              return <g key={site.id} className="diagram-node diagram-site-card" role="button" tabIndex={0} aria-label={`Expand site ${site.label}`}
                transform={`translate(${site.x} ${site.y})`} onClick={toggle} onKeyDown={(event) => activateByKey(event, toggle)}>
                <rect className="diagram-site-box" width={site.width} height={site.height} />
                <text x={16} y={26} className="diagram-site-title">{site.label}</text>
                <text x={16} y={48} className="diagram-zone-os">{site.summary!.zones} subnets · {site.summary!.hosts} hosts</text>
                <text x={16} y={66} className="diagram-zone-os">{siteDeviceLine(site.summary!.devices)}</text>
                <text x={16} y={88} className="diagram-site-expand">Expand site ▾</text>
              </g>;
            })}
            {scene.zones.flatMap(zoneNodes)}
            {scene.internets.map(({ internet, x, y }) => <g key={internet.id} className="diagram-node diagram-internet" transform={`translate(${x} ${y})`}
              data-inferred={internet.inferred || undefined} {...interactive(internet.id, internet.inferred ? `${internet.name} (inferred)` : internet.name)}>
              <rect className="diagram-node-box" x={-32} y={-24} width={64} height={48} rx={10} />
              <Cloud x={-24} y={-22} size={48} aria-hidden="true" />
              <text x={34} y={-2} className="diagram-device-name" aria-hidden="true">{internet.name}</text>
              {internet.inferred && <text x={34} y={12} className="diagram-device-subtitle" aria-hidden="true">inferred from public addresses</text>}
            </g>)}
            {scene.equipment.map(({ equipment, x, y, labelSide }) => <g key={equipment.id} className="diagram-node diagram-device" transform={`translate(${x} ${y})`}
              data-kind={equipment.kind} data-finding={findings.has(equipment.id) || undefined} data-traced={trace?.has(equipment.id) || undefined}
              data-change={changeOf(equipment.id)}
              {...interactive(equipment.id, equipmentLabel(equipment) + findingLabel(equipment.id))}>
              <rect className="diagram-device-box" x={-24} y={-24} width={48} height={48} rx={11} />
              {findings.has(equipment.id) && <FindingBadge x={22} y={-22} messages={findings.get(equipment.id)!} />}
              <EquipmentIcon kind={equipment.kind} x={-15} y={-15} size={30} />
              <text x={labelSide === "above" ? 0 : -34} y={labelSide === "above" ? -46 : -2} textAnchor={labelSide === "above" ? "middle" : "end"}
                className="diagram-device-name" aria-hidden="true">{equipment.name}</text>
              <text x={labelSide === "above" ? 0 : -34} y={labelSide === "above" ? -32 : 12} textAnchor={labelSide === "above" ? "middle" : "end"}
                className="diagram-device-subtitle" aria-hidden="true">{equipment.subtitle}</text>
              <title>{`${equipment.name} · ${equipment.subtitle}`}</title>
            </g>)}
            {scene.taps.map((tap) => <g key={tap.key}>
              <path className="diagram-tap-stem" aria-hidden="true" d={tap.chip.y > tap.y + 4 ? `M ${tap.x} ${tap.y} V ${tap.chip.y}`
                : `M ${tap.x} ${tap.y} H ${tap.chip.x > tap.x ? tap.chip.x : tap.chip.x + tap.chip.width}`} />
              <circle className="diagram-tap" cx={tap.x} cy={tap.y} r={4.5} aria-hidden="true" data-highlighted={highlighted(tap.entities)} />
              {chip(tap.chip, 0, 0)}
            </g>)}
            <g aria-hidden="true" className="diagram-labels">
              {scene.labels.map((label) => <text key={label.key} x={label.x} y={label.y} textAnchor={label.anchor} data-kind={label.kind}>{label.text}</text>)}
            </g>
          </g>
        </svg>
        {preview && preview.id !== pinned?.id && <div className="diagram-preview">
          <strong>{entityLabel(preview)}</strong>
          {preview.kind === "zone" && preview.zone.cidr && <code>{preview.zone.cidr}</code>}
          {preview.kind === "sensor" && <>
            <span>{SENSOR_LABELS[preview.device.kind]} · {preview.device.placement.toUpperCase()}</span>
            {sensorLogs(preview.device).map((line) => <span key={line} className="diagram-preview-logs">{line}</span>)}
          </>}
          {preview.kind === "host" && <span>{preview.host.ip} · {preview.host.os}</span>}
          {preview.kind === "equipment" && <span>{preview.equipment.subtitle}</span>}
        </div>}
        {lens === "coverage" && coverage ? <details className="diagram-key" open aria-label="Diagram key">
          <summary>Weakest evidence for traffic into each subnet from elsewhere</summary>
          <ul>{TIER_ORDER.map((tier) => <li key={tier}><span className="diagram-tier-mark" data-tier={tier} aria-hidden="true" />{TIER_LABELS[tier]}</li>)}
            <li><span className="diagram-within-key" aria-hidden="true">Unobserved within</span>No sensor sees traffic between the subnet's own hosts</li></ul>
        </details> : <DiagramKey scene={scene} showScopes={showScopes} scopes={scopes} segments={graph.segments} />}
        <div className="diagram-zoom" role="group" aria-label="Diagram view">
          <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoom(1.25)}><ZoomIn size={16} aria-hidden="true" /></button>
          <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoom(0.8)}><ZoomOut size={16} aria-hidden="true" /></button>
          <button type="button" aria-label="Fit to view" title="Fit to view" onClick={showOverview}><Maximize size={16} aria-hidden="true" /></button>
        </div>
        {(focusZone || focusSite) && <Breadcrumb zoneId={focusZone} siteId={focusSite} scene={scene}
          onOverview={showOverview} onZone={focusOn} onSite={focusOnSite} />}
        {(focusZone || focusSite || view.scale > scale * 1.75) && <Minimap scene={scene} view={view} size={size}
          onCenter={(x, y) => setCamera({ ...view, x: size.width / 2 - x * view.scale, y: size.height / 2 - y * view.scale })} />}
      </div>
      {pinned && <DiagramInspector entity={pinned} scene={scene} graph={graph} coverage={coverage} onTrace={setTrace}
        askAction={onAsk && revision && <button type="button" className="button-quiet diagram-ask" disabled={asking}
          onClick={() => void askAbout(pinned)}><Sparkles size={15} aria-hidden="true" />Ask about this</button>}
        onSelect={(id) => selectFromDetails(id)} onFocus={focusOn} onClose={() => { setSelected(null); setTrace(null); canvas.current?.focus(); }} />}
    </div> : (graph.segments.length > 0 || graph.devices.length > 0 || graph.hosts.length > 0) && <p className="muted">No diagram items in the selected layers.</p>}
    {graph.findings.length > 0 && <details className="diagram-findings">
      <summary>{graph.findings.length} diagram {graph.findings.length === 1 ? "finding" : "findings"}</summary>
      <ul>{graph.findings.map(({ entity_id, message }) => <li key={JSON.stringify([entity_id, message])}>
        {scene.entities.has(entity_id) || fullModel.zones.has(entity_id)
          ? <button type="button" onClick={() => selectFromDetails(entity_id)}>{message}</button> : message}
      </li>)}</ul>
    </details>}
  </section>;
  return expanded ? <Modal title="Expanded network diagram" hideTitle size="full" className="network-diagram-dialog"
    onClose={() => resizeDiagram(false)}
    onOpenAutoFocus={(event) => { event.preventDefault(); (canvas.current ?? restoreButton.current)?.focus({ preventScroll: true }); }}
    onCloseAutoFocus={(event) => {
      event.preventDefault();
      requestAnimationFrame(() => {
        const button = expandButton.current;
        if (button && !button.closest("[hidden]")) button.focus();
      });
    }}>
    {diagram}
  </Modal> : diagram;
}

