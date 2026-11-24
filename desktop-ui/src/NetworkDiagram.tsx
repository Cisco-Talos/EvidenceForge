import { useCallback, useEffect, useEffectEvent, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import {
  AppWindow, BrickWallFire, ChevronDown, CircleHelp, Cloud, Database, Expand, FileText, Folder, Globe, Info, KeyRound, Layers,
  Mail, Maximize, Minimize, Monitor, Network, Server, X, ZoomIn, ZoomOut,
} from "lucide-react";
import { Tooltip } from "radix-ui";
import type { NetworkChatContext, TopologyGraph } from "./api";
import { captureNetworkView } from "./captureNetworkView";
import { Modal } from "./Modal";
import {
  categoryLabel, hostCategory, layoutNetworkDiagram, MIN_READABLE_SCALE, shortOs,
  type DiagramDevice, type DiagramEntity, type DiagramHost, type DiagramLayers, type DiagramLinkKind, type DiagramScene,
  type Detail, type Equipment, type HostCategory, type PlacedChip, type PlacedHost, type PlacedZone, type Zone,
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
const PAGE_SIZE = 12;
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

function HostGroup({ hosts, onSelect }: { hosts: DiagramHost[]; onSelect: (id: string) => void }) {
  const [page, setPage] = useState(0);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const start = page * PAGE_SIZE;
  const end = Math.min(hosts.length, start + PAGE_SIZE);
  function showPage(next: number) {
    setPage(next);
    setExpandedHost(null);
  }
  return <div className="diagram-hosts">
    <h5>Hosts <span>{hosts.length}</span></h5>
    {hosts.length > PAGE_SIZE && <div className="diagram-pagination">
      <button type="button" className="button-quiet" disabled={page === 0} onClick={() => showPage(page - 1)}>Previous hosts</button>
      <span role="status">{start + 1}–{end} of {hosts.length}</span>
      <button type="button" className="button-quiet" disabled={end === hosts.length} onClick={() => showPage(page + 1)}>Next hosts</button>
    </div>}
    <ul>{hosts.slice(start, end).map((host) => {
      const expanded = expandedHost === host.id;
      return <li key={host.id}>
        <button type="button" className="diagram-host" aria-expanded={expanded}
          aria-label={hostLabel(host)} title={`${host.ip} · ${host.os}`}
          onClick={() => setExpandedHost(expanded ? null : host.id)}>
          <CategoryIcon host={host} size={16} /><strong>{host.hostname}</strong><span>{host.public_address ? "Public · " : ""}{shortOs(host.os)}</span>
        </button>
        {expanded && <><HostFacts host={host} />
          <button type="button" className="button-quiet diagram-host-focus" onClick={() => onSelect(host.id)}>Show on map</button></>}
      </li>;
    })}</ul>
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

function DiagramInspector({ entity, scene, graph, onSelect, onClose, askAction }: {
  entity: DiagramEntity; scene: DiagramScene; graph: TopologyGraph;
  onSelect: (id: string) => void; onClose: () => void; askAction?: ReactNode;
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
      {zone.hosts.length > 0 && <HostGroup key={zone.id} hosts={zone.hosts} onSelect={onSelect} />}
    </>;
  } else if (entity.kind === "host") {
    const zone = [...model.zones.values()].find(({ hosts }) => hosts.includes(entity.host));
    body = <><HostFacts host={entity.host} />{zone && <p>In {link(zone.id, zone.name)}</p>}</>;
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
  return <aside className="diagram-inspector" aria-label="Network diagram details">
    <header className="diagram-details-heading">
      <h4>{entityLabel(entity)}</h4>
      {askAction}
      <button type="button" className="icon-button" aria-label="Close details" onClick={onClose}><X size={16} aria-hidden="true" /></button>
    </header>
    {body}
    {findings.length > 0 && <ul className="diagram-findings">
      {findings.map((finding) => <li key={finding.message}>{finding.message}</li>)}
    </ul>}
  </aside>;
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
      <Layers size={15} aria-hidden="true" /> Layers <span className="muted">{shown}/{total}</span><ChevronDown size={14} aria-hidden="true" />
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

export function NetworkDiagram({ graph, context, description, actions, revision, onAsk }: {
  graph: TopologyGraph; context?: string; description?: string; actions?: ReactNode;
  revision?: string; onAsk?: (context: NetworkChatContext) => Promise<void>;
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
  const [pendingReveal, setPendingReveal] = useState<string | null>(null);
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
      setSelected(null);
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
    const bottom = frame && key?.height ? key.top - frame.top - 8 : size.height - 4;
    const right = frame && panel?.width ? panel.left - frame.left - 8 : size.width - 4;
    return { left: 4, top: 4, right: right > size.width / 3 ? right : size.width - 4, bottom: bottom > size.height / 3 ? bottom : size.height - 4 };
  }

  function reveal(id: string) {
    const box = scene.bounds.get(id);
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

  // A host can be hidden in a summarized subnet or a collapsed site. Show it first, then reveal it.
  function selectFromDetails(id: string) {
    const entity = scene.entities.get(id);
    if (!entity) return;
    setHovered(null);
    setFocused(null);
    setSelected(id);
    canvas.current?.focus({ preventScroll: true });
    if (scene.bounds.has(id)) { reveal(id); return; }
    const site = scene.collapsedSite.get(id);
    if (site) setSiteChoices((current) => ({ ...current, [site]: true }));
    if (entity.kind === "host") {
      const zone = [...scene.model.zones.values()].find(({ hosts }) => hosts.some((member) => member.id === id));
      if (zone) setZoneDetail((current) => ({ ...current, [zone.id]: "hosts" }));
    }
    setPendingReveal(id);
  }
  useEffect(() => {
    if (!pendingReveal) return;
    if (scene.bounds.has(pendingReveal)) reveal(pendingReveal);
    setPendingReveal(null);
    // Reveal only once the expanded subnet or site is part of the scene.
  }, [scene, pendingReveal]);

  function toggleSelection(id: string) {
    setSelected((current) => current === id ? null : id);
  }

  async function askAbout(entity?: DiagramEntity) {
    if (!onAsk || !revision || !viewport.current || asking) return;
    setAsking(true);
    setAskError("");
    try {
      const image = await captureNetworkView(viewport.current).catch(() => null);
      await onAsk({
        revision, topology: graph, image, firewall_scopes_visible: showScopes && scopes.length > 0,
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
      data-family={family} data-placement={placed.device.placement} data-related={active === placed.device.id}
      {...interactive(placed.device.id, sensorLabel(placed.device))}>
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
      data-compact={compact || undefined} data-public={!!host.public_address || undefined} {...interactive(host.id, hostLabel(host))}>
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
        {...interactive(model.id, zoneLabel(model))}>
        {segmentScopes?.map((scope, index) => <rect key={scope.id} className="diagram-scope-highlight" x={-4 - index * 4} y={-4 - index * 4}
          width={zone.width + 8 + index * 8} height={zone.height + 8 + index * 8} rx={12 + index * 2} style={{ color: scope.color }} strokeDasharray={scope.dash}>
          <title>{scope.label}</title></rect>)}
        <rect className="diagram-zone-box" width={zone.width} height={zone.height} />
        <text x={12} y={20} className="diagram-zone-name" aria-hidden="true">{model.name}</text>
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
        {(description || (expanded && context)) && <p className="muted diagram-context">{description || context}</p>}
        {hasNodes && scene.model.inferredLinks && <p className="diagram-notice" title="Add authored routing for exact links and paths.">
          <strong>Segment-based model:</strong> dashed links are inferred from firewall interfaces and monitored segments.
        </p>}
      </div>
      <div className="diagram-controls">
        {actions}
        {onAsk && revision && hasNodes && <button type="button" className="button-quiet" disabled={asking}
          onClick={() => void askAbout()}>Ask about this diagram</button>}
        {expanded
          ? <button ref={restoreButton} type="button" className="button-quiet icon-only" aria-label="Exit expanded view" title="Exit expanded view" onClick={() => resizeDiagram(false)}><Minimize size={16} aria-hidden="true" /></button>
          : hasNodes && <button ref={expandButton} type="button" className="button-quiet icon-only" aria-label="Expand diagram" title="Expand diagram" onClick={() => resizeDiagram(true)}><Expand size={16} aria-hidden="true" /></button>}
      </div>
    </div>
    {askError && <p role="alert">{askError}</p>}
    {graph.segments.length === 0 && <p className="muted">No network segments are declared.</p>}
    {hasNodes ? <div className="diagram-body">
      <div ref={trackCanvas} className="diagram-canvas" role="group" tabIndex={0}
        aria-label="Network map, use arrow keys to pan and the wheel to zoom when focused" onKeyDown={panByKeyboard}>
        <svg ref={viewport} className="diagram-viewport" data-dragging={dragging}
          onPointerDown={startDrag} onPointerMove={moveDrag} onPointerUp={stopDrag}
          onPointerCancel={stopDrag} onLostPointerCapture={stopDrag}>
          <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
            {scene.sites.map((site) => {
              const toggle = () => setSiteChoices((current) => ({ ...current, [site.id]: site.collapsed }));
              return site.collapsed
                ? <g key={site.id} className="diagram-node diagram-site-card" role="button" tabIndex={0} aria-label={`Expand site ${site.label}`}
                  transform={`translate(${site.x} ${site.y})`} onClick={toggle} onKeyDown={(event) => activateByKey(event, toggle)}>
                  <rect className="diagram-site-box" width={site.width} height={site.height} />
                  <text x={16} y={26} className="diagram-site-title">{site.label}</text>
                  <text x={16} y={48} className="diagram-zone-os">{site.summary!.zones} subnets · {site.summary!.hosts} hosts</text>
                  <text x={16} y={66} className="diagram-zone-os">{site.summary!.devices.slice(0, 3).join(", ")}{site.summary!.devices.length > 3 ? ` +${site.summary!.devices.length - 3}` : ""}</text>
                  <text x={16} y={88} className="diagram-site-expand">Expand site ▾</text>
                </g>
                : <g key={site.id} className="diagram-site" transform={`translate(${site.x} ${site.y})`}>
                  <rect className="diagram-site-frame" width={site.width} height={site.height} />
                  <g className="diagram-node diagram-site-label" role="button" tabIndex={0} aria-label={`Collapse site ${site.label}`}
                    onClick={toggle} onKeyDown={(event) => activateByKey(event, toggle)}>
                    <text x={16} y={18}>{`SITE · ${site.label}`.toUpperCase()}</text>
                  </g>
                </g>;
            })}
            <g aria-hidden="true" className="diagram-edges">{scene.wires.map((wire) =>
              <path key={wire.key} d={wire.path} data-style={wire.style} data-link-kind={wire.linkKind} data-highlighted={highlighted(wire.entities)} />)}
            </g>
            {scene.zones.flatMap(zoneNodes)}
            {scene.internets.map(({ internet, x, y }) => <g key={internet.id} className="diagram-node diagram-internet" transform={`translate(${x} ${y})`}
              data-inferred={internet.inferred || undefined} {...interactive(internet.id, internet.inferred ? `${internet.name} (inferred)` : internet.name)}>
              <rect className="diagram-node-box" x={-32} y={-24} width={64} height={48} rx={10} />
              <Cloud x={-24} y={-22} size={48} aria-hidden="true" />
              <text x={34} y={-2} className="diagram-device-name" aria-hidden="true">{internet.name}</text>
              {internet.inferred && <text x={34} y={12} className="diagram-device-subtitle" aria-hidden="true">inferred from public addresses</text>}
            </g>)}
            {scene.equipment.map(({ equipment, x, y, labelSide }) => <g key={equipment.id} className="diagram-node diagram-device" transform={`translate(${x} ${y})`}
              data-kind={equipment.kind} {...interactive(equipment.id, equipmentLabel(equipment))}>
              <rect className="diagram-device-box" x={-24} y={-24} width={48} height={48} rx={11} />
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
        <DiagramKey scene={scene} showScopes={showScopes} scopes={scopes} segments={graph.segments} />
        <div className="diagram-zoom" role="group" aria-label="Diagram view">
          <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoom(1.25)}><ZoomIn size={16} aria-hidden="true" /></button>
          <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoom(0.8)}><ZoomOut size={16} aria-hidden="true" /></button>
          <button type="button" aria-label="Fit to view" title="Fit to view" onClick={() => setCamera("fit")}><Maximize size={16} aria-hidden="true" /></button>
        </div>
      </div>
      {pinned && <DiagramInspector entity={pinned} scene={scene} graph={graph}
        askAction={onAsk && revision && <button type="button" className="button-quiet" disabled={asking}
          onClick={() => void askAbout(pinned)}>Ask about this</button>}
        onSelect={selectFromDetails} onClose={() => { setSelected(null); canvas.current?.focus(); }} />}
    </div> : (graph.segments.length > 0 || graph.devices.length > 0 || graph.hosts.length > 0) && <p className="muted">No diagram items in the selected layers.</p>}
    {graph.findings.length > 0 && <details className="diagram-findings">
      <summary>{graph.findings.length} diagram {graph.findings.length === 1 ? "finding" : "findings"}</summary>
      <ul>{graph.findings.map(({ entity_id, message }) => <li key={JSON.stringify([entity_id, message])}>{message}</li>)}</ul>
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

