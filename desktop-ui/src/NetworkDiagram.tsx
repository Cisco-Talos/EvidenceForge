import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import { Apple, BrickWallFire, ChevronLeft, ChevronRight, ChevronUp, Expand, Grid2X2, Maximize, Minimize, Monitor, Network, Server, X, ZoomIn, ZoomOut } from "lucide-react";
import type { NetworkChatContext, TopologyGraph } from "./api";
import { captureNetworkView } from "./captureNetworkView";
import { Modal } from "./Modal";
import {
  chooseInitialBranches, indexDiagramHosts, indexInlineHosts, INLINE_HOST_LIMIT, layoutNetworkDiagram,
  type Branch, type DiagramAssociation, type DiagramDevice, type DiagramEntity, type DiagramHost, type DiagramLayers, type DiagramNode, type SensorEntry,
} from "./networkDiagramLayout";

const DEVICE_LABELS: Record<DiagramDevice["kind"], string> = {
  network: "Network sensor", ids: "IDS sensor", firewall: "Firewall",
};
const EXPOSURE_LABELS = { internal: "Internal", external: "External", both: "Internal and external" };
const OS_LABELS: Record<string, string> = { windows: "Windows", linux: "Linux", macos: "macOS" };
const EQUIPMENT_LABELS = { firewall: "Firewall", network: "Network appliance", router: "Router", switch: "Switch" };
const LAYER_LABELS = { sensors: "Sensors", firewalls: "Firewalls", hosts: "Hosts" };
const PAGE_SIZE = 12;
const INITIAL_SIZE = { width: 720, height: 320 };
type Camera = { x: number; y: number; scale: number };
type Drag = { pointer: number; x: number; y: number; camera: Camera };

function nodeLabel(entity: DiagramEntity): string {
  if (entity.kind === "segment") return entity.segment.name;
  if (entity.kind === "device") return entity.device.hostname;
  if (entity.kind === "host") return entity.host.hostname;
  return "Unassigned hosts";
}

function abbreviatedLabel(value: string, limit: number, keepSuffix = false): string {
  const characters = [...value];
  if (characters.length <= limit) return value;
  const suffix = keepSuffix ? Math.min(4, Math.floor((limit - 1) / 2)) : 0;
  return characters.slice(0, limit - suffix - 1).join("") + "…" + characters.slice(characters.length - suffix).join("");
}

function HostIcon({ family, size, x, y }: { family: string; size: number; x?: number; y?: number }) {
  if (family === "linux") return <svg width={size} height={size} x={x} y={y} viewBox="0 0 24 24"
    fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M8 10V7a4 4 0 0 1 8 0v3l2.5 4.5v3l2 2.5H14l-2-1-2 1H3.5l2-2.5v-3L8 10Z" />
    <path d="m10 8 2 1 2-1M9 13c0-3 6-3 6 0v3a3 3 0 0 1-6 0Z" />
  </svg>;
  const Icon = family === "macos" ? Apple : family === "windows" ? Grid2X2 : Monitor;
  return <Icon size={size} x={x} y={y} aria-hidden="true" />;
}

function RouterIcon({ x, y }: { x: number; y: number }) {
  return <svg width={44} height={44} x={x} y={y} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="1.55" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <ellipse cx="12" cy="8.5" rx="10.5" ry="5.25" />
    <path d="M1.5 8.5v7C1.5 18.4 6.2 21 12 21s10.5-2.6 10.5-5.5v-7M7 7h3L7 5.5M17 7h-3l3-1.5M7 10h3l-3 1.5m10-1.5h-3l3 1.5" />
  </svg>;
}

function HostFacts({ host }: { host: DiagramHost }) {
  return <dl className="diagram-facts">
    <dt>IP address</dt><dd><code>{host.ip}</code></dd>
    <dt>Operating system</dt><dd>{host.os}</dd>
    {!!host.primary_users?.length && <>
      <dt>{host.primary_users.length === 1 ? "Primary user" : "Primary users"}</dt>
      <dd>{host.primary_users.join(", ")}</dd>
    </>}
    {!!host.roles?.length && <><dt>Roles</dt><dd>{host.roles.join(", ")}</dd></>}
  </dl>;
}

function activateByKey(event: KeyboardEvent<SVGGElement>, action: () => void) {
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  action();
}

function HostGroup({ hosts }: { hosts: DiagramHost[] }) {
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
      const osLabel = OS_LABELS[host.os_family] || "Other OS";
      const expanded = expandedHost === host.id;
      return <li key={host.id}>
        <button type="button" className="diagram-host" aria-expanded={expanded}
          aria-label={`${host.hostname} ${osLabel}`} title={`${host.ip} · ${host.os}`} aria-description={`${host.ip}, ${host.os}`}
          onClick={() => setExpandedHost(expanded ? null : host.id)}>
          <HostIcon family={host.os_family} size={16} /><strong>{host.hostname}</strong><span>{osLabel}</span>
        </button>
        {expanded && <HostFacts host={host} />}
      </li>;
    })}</ul>
  </div>;
}

function DiagramInspector({ entity, graph, hosts, associations, extraSensorIds, onSelect, onClose, askAction }: {
  entity: DiagramEntity; graph: TopologyGraph; hosts: DiagramHost[];
  associations: DiagramAssociation[];
  extraSensorIds: readonly string[];
  onSelect: (id: string) => void; onClose: () => void;
  askAction?: ReactNode;
}) {
  const { kind, id } = entity;
  const inspector = useRef<HTMLElement>(null);
  const findings = graph.findings.filter((finding) => finding.entity_id === id);
  const additional = associations.filter(({ device }) => extraSensorIds.includes(device.id));
  const otherAssociations = associations.filter(({ device }) => !extraSensorIds.includes(device.id));
  useEffect(() => {
    if (extraSensorIds.length && inspector.current) inspector.current.scrollTop = 0;
  }, [extraSensorIds]);
  const associationList = (entries: DiagramAssociation[]) => <ul className="diagram-associations">
    {entries.map(({ device, interface_name, monitored }) => <li key={device.id}>
      <button type="button" onClick={() => onSelect(device.id)}>{device.hostname}</button>
      {interface_name !== null && <span>Interface {interface_name}</span>}
      {monitored && <span>{device.kind === "firewall" ? "Monitored by firewall" : device.placement.toUpperCase()}</span>}
    </li>)}
  </ul>;
  return <aside ref={inspector} className="diagram-inspector" aria-label="Network diagram details">
    <header className="diagram-details-heading">
      <h4>{nodeLabel(entity)}</h4>
      {askAction}
      <button type="button" className="icon-button" aria-label="Close details" onClick={onClose}><X size={16} aria-hidden="true" /></button>
    </header>
    {additional.length > 0 && <section className="diagram-attached-devices" aria-label="Additional sensors">
      <h5>Additional sensors</h5>
      {associationList(additional)}
    </section>}
    {kind === "host" && <HostFacts host={entity.host} />}
    {kind === "segment" && <>
      <dl className="diagram-facts">
        <dt>Address range</dt><dd><code>{entity.segment.cidr}</code></dd>
        <dt>Exposure</dt><dd>{EXPOSURE_LABELS[entity.segment.exposure]}</dd>
      </dl>
      {entity.segment.description && <p>{entity.segment.description}</p>}
    </>}
    {kind === "device" && <>
      <dl className="diagram-facts">
        <dt>Type</dt><dd>{DEVICE_LABELS[entity.device.kind]}</dd>
        {entity.device.hostname !== entity.device.name && <><dt>Name</dt><dd>{entity.device.name}</dd></>}
        <dt>{entity.device.kind === "firewall" ? "Monitoring placement" : "Placement"}</dt><dd>{entity.device.placement.toUpperCase()}</dd>
        <dt>Direction</dt><dd>{entity.device.direction}</dd>
        {entity.device.log_formats.length > 0 && <><dt>Log formats</dt><dd>{entity.device.log_formats.join(", ")}</dd></>}
        {entity.device.default_interface !== null && <><dt>Default interface</dt><dd>{entity.device.default_interface}</dd></>}
      </dl>
      {entity.device.description && <p>{entity.device.description}</p>}
      {entity.host && <HostFacts host={entity.host} />}
      {entity.device.associations.length > 0 && <ul className="diagram-associations">
        {entity.device.associations.map((association) => <li key={association.segment_id}>
          <button type="button" onClick={() => onSelect(association.segment_id)}>{graph.segments.find((segment) => segment.id === association.segment_id)?.name}</button>
          {association.interface_name !== null && <span>Interface {association.interface_name}</span>}
          {association.monitored && <span>Monitored</span>}
        </li>)}
      </ul>}
    </>}
    {kind === "unassigned" && <p>These hosts have no segment match in this environment.</p>}
    {hosts.length > 0 && <HostGroup key={id} hosts={hosts} />}
    {otherAssociations.length > 0 && <div className="diagram-attached-devices">
      <h5>Segment associations</h5>
      {associationList(otherAssociations)}
    </div>}
    {findings.length > 0 && <ul className="diagram-findings">
      {findings.map((finding) => <li key={finding.message}>{finding.message}</li>)}
    </ul>}
  </aside>;
}

function BranchControls({ branch, active, selected, onPreview, onSelect, onToggle, onPage, onRevealSensors }: {
  branch: Branch; active?: string; selected: string | null;
  onPreview: (id: string | null) => void; onSelect: (id: string) => void; onToggle: () => void;
  onPage: (page: number) => void; onRevealSensors: (ids: string[]) => void;
}) {
  const { node, hosts, expanded, hostPage, railX, railY, hostToggleY, sensors, sensorStart, sensorEnd, side, vertical } = branch;
  const alongVertical = vertical || !!side;
  const markerPitch = alongVertical ? 26 : 34;
  const availableSlots = Math.max(1, Math.floor((sensorEnd - sensorStart) / markerPitch) + 1);
  const visibleCount = sensors.length > availableSlots ? availableSlots - 1 : sensors.length;
  const activeSensor = sensors.find(({ device }) => device.id === active);
  const visibleSensors = sensors.slice(0, visibleCount);
  if (visibleCount && activeSensor && !visibleSensors.includes(activeSensor)) visibleSensors[visibleCount - 1] = activeSensor;
  const hiddenSensors = sensors.filter((entry) => !visibleSensors.includes(entry));
  const showAdditional = () => onRevealSensors(hiddenSensors.map(({ device }) => device.id));
  const start = hostPage * INLINE_HOST_LIMIT + 1;
  const end = Math.min(start + INLINE_HOST_LIMIT - 1, hosts.length);
  const paged = hosts.length > INLINE_HOST_LIMIT;
  const range = start === end ? String(start) : `${start}–${end}`;
  const hostCaption = expanded
    ? (paged ? `${range} of ${hosts.length} hosts` : "Collapse hosts")
    : `${hosts.length} ${hosts.length === 1 ? "host" : "hosts"}`;
  const markerDirection = side === "left" ? -1 : 1;
  const markerCount = visibleSensors.length + Number(hiddenSensors.length > 0);
  const trackPosition = (index: number) => (sensorStart + sensorEnd) / 2 + (index - (markerCount - 1) / 2) * markerPitch;
  const markerX = (index: number) => alongVertical ? railX + 32 * markerDirection
    : trackPosition(index);
  const markerY = (index: number) => alongVertical ? trackPosition(index) : railY - 28;
  const controlX = node.x + node.width / 2;
  return <>
    {visibleSensors.map(({ device, mark }, index) => {
      const x = markerX(index);
      const y = markerY(index);
      const tap = device.placement === "tap";
      const connector = alongVertical
        ? tap ? `M ${x - 10 * markerDirection} ${y} H ${railX}`
          : `M ${x - 12 * markerDirection} ${y} H ${railX + 9 * markerDirection} V ${y + 6} H ${railX}`
        : tap ? `M ${x} ${y + 10} V ${railY}` : `M ${x} ${y + 12} V ${railY - 9} H ${x + 7} V ${railY}`;
      return <g key={device.id} className="diagram-node diagram-marker" role="button" tabIndex={0}
        data-placement={device.placement} data-active={device.id === active}
        aria-label={`${device.hostname} ${device.placement.toUpperCase()} on ${nodeLabel(node)}`}
        aria-pressed={device.id === selected}
        onMouseEnter={() => onPreview(device.id)} onMouseLeave={() => onPreview(null)}
        onFocus={() => onPreview(device.id)} onBlur={() => onPreview(null)}
        onClick={() => onSelect(device.id)} onKeyDown={(event) => activateByKey(event, () => onSelect(device.id))}>
        <path className="diagram-sensor-stem" d={connector} strokeDasharray={tap ? undefined : "4 3"} />
        {tap ? <circle className="diagram-sensor-badge" cx={x} cy={y} r={10} />
          : <polygon className="diagram-sensor-badge" points={`${x},${y - 12} ${x + 12},${y} ${x},${y + 12} ${x - 12},${y}`} />}
        <text x={x} y={y + 3.5} textAnchor="middle" aria-hidden="true">{mark}</text>
      </g>;
    })}
    {hiddenSensors.length > 0 && <g className="diagram-node diagram-overflow" role="button" tabIndex={0}
      aria-label={`Show ${hiddenSensors.length} more sensors on ${nodeLabel(node)}`}
      onClick={showAdditional} onKeyDown={(event) => activateByKey(event, showAdditional)}>
      <rect x={markerX(visibleSensors.length) - 15} y={markerY(visibleSensors.length) - 9} width={30} height={18} className="diagram-node-box" />
      <text x={markerX(visibleSensors.length)} y={markerY(visibleSensors.length) + 4} textAnchor="middle">+{hiddenSensors.length}</text>
    </g>}
    {hosts.length > 0 && <g className="diagram-node diagram-host-toggle" role="button" tabIndex={0}
      transform={`translate(${controlX} ${expanded ? hostToggleY : railY + 27})`}
      aria-expanded={expanded} aria-label={`${expanded ? "Collapse" : "Expand"} ${nodeLabel(node)} hosts`}
      onClick={onToggle} onKeyDown={(event) => activateByKey(event, onToggle)}>
      {expanded ? <>
        <rect x={-61} y={paged ? -16 : -11} width={122} height={paged ? 32 : 22} className="diagram-node-box" />
        <text x={-7} y={4} textAnchor="middle" aria-live="polite">{hostCaption}</text>
        <ChevronUp size={13} x={45} y={-7} aria-hidden="true" />
      </> : <>
        <rect x={-50} y={-15} width={100} height={46} className="diagram-node-box" />
        <Server size={28} x={-14} y={-14} aria-hidden="true" />
        <text y={26} textAnchor="middle">{hostCaption}</text>
      </>}
    </g>}
    {expanded && paged && [
      { offset: -1, label: "Previous", Icon: ChevronLeft, disabled: hostPage === 0 },
      { offset: 1, label: "Next", Icon: ChevronRight, disabled: end === hosts.length },
    ].map(({ offset, label, Icon, disabled }) => {
      const change = () => { if (!disabled) onPage(hostPage + offset); };
      return <g key={label} className="diagram-node diagram-host-page" role="button" tabIndex={disabled ? -1 : 0}
        aria-label={`${label} hosts on ${nodeLabel(node)}`} aria-disabled={disabled}
        transform={`translate(${controlX + offset * 105} ${hostToggleY})`}
        onClick={change} onKeyDown={(event) => activateByKey(event, change)}>
        <rect x={-40} y={-16} width={80} height={32} className="diagram-node-box" />
        <Icon size={16} x={offset < 0 ? -34 : 14} y={-8} aria-hidden="true" />
        <text x={offset < 0 ? 7 : -8} y={4} textAnchor="middle" aria-hidden="true">{label}</text>
      </g>;
    })}
  </>;
}

function CoverageKey({ placement }: { placement: DiagramDevice["placement"] }) {
  const tap = placement === "tap";
  return <span>
    <svg className="diagram-coverage-symbol" width="31" height="18" viewBox="0 0 31 18" aria-hidden="true">
      <path d="M 13 9 H 29" strokeDasharray={tap ? undefined : "4 3"} />
      {tap ? <circle cx="8" cy="9" r="5" /> : <polygon points="8,2 15,9 8,16 1,9" />}
    </svg>
    {placement.toUpperCase()} coverage
  </span>;
}

function SensorKey({ sensors, active, selected, onPreview, onSelect }: {
  sensors: SensorEntry[]; active?: string; selected: string | null;
  onPreview: (id: string | null) => void; onSelect: (id: string) => void;
}) {
  if (sensors.length === 0) return null;
  const entries = <ul aria-label="Diagram sensor key">{sensors.map(({ device, mark }) => <li key={device.id}>
    <button type="button" aria-label={`${DEVICE_LABELS[device.kind]} ${device.hostname}, ${device.placement.toUpperCase()}`}
      aria-pressed={device.id === selected} data-active={device.id === active}
      onMouseEnter={() => onPreview(device.id)} onMouseLeave={() => onPreview(null)}
      onFocus={() => onPreview(device.id)} onBlur={() => onPreview(null)} onClick={() => onSelect(device.id)}>
      <span className="diagram-key-mark" data-placement={device.placement}><span>{mark}</span></span>
      <span>{device.hostname}</span><small>{device.placement.toUpperCase()}</small>
    </button>
  </li>)}</ul>;
  return sensors.length <= 4 ? <div className="diagram-sensor-key">{entries}</div>
    : <details className="diagram-sensor-key"><summary>Sensor key ({sensors.length})</summary>{entries}</details>;
}

export function NetworkDiagram({ graph, context, description, actions, revision, onAsk }: {
  graph: TopologyGraph; context?: string; description?: string; actions?: ReactNode;
  revision?: string; onAsk?: (context: NetworkChatContext) => Promise<void>;
}) {
  const title = useId();
  const viewport = useRef<SVGSVGElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const expandButton = useRef<HTMLButtonElement>(null);
  const restoreButton = useRef<HTMLButtonElement>(null);
  const drag = useRef<Drag | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [asking, setAsking] = useState(false);
  const [askError, setAskError] = useState("");
  const [dragging, setDragging] = useState(false);
  const [layers, setLayers] = useState<DiagramLayers>({ sensors: true, firewalls: true, hosts: true });
  const [size, setSize] = useState(INITIAL_SIZE);
  const [layoutSize, setLayoutSize] = useState(INITIAL_SIZE);
  const [camera, setCamera] = useState<Camera | "fit" | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [extraSensorIds, setExtraSensorIds] = useState<string[]>([]);
  const [hovered, setHovered] = useState<string | null>(null);
  const [focused, setFocused] = useState<string | null>(null);
  const [branchChoices, setBranchChoices] = useState<Record<string, boolean>>({});
  const [hostPages, setHostPages] = useState<Record<string, number>>({});
  const groups = useMemo(() => indexDiagramHosts(graph.hosts), [graph.hosts]);
  const inlineGroups = useMemo(() => indexInlineHosts(graph, groups), [graph, groups]);
  const expandedBranches = useMemo(() => {
    const automatic = chooseInitialBranches(inlineGroups, layoutSize);
    for (const [id, value] of Object.entries(branchChoices)) {
      if (value) automatic.add(id);
      else automatic.delete(id);
    }
    return automatic;
  }, [inlineGroups, layoutSize, branchChoices]);
  const scene = useMemo(() => layoutNetworkDiagram(graph, layers, groups, expandedBranches, hostPages),
    [graph, layers, groups, expandedBranches, hostPages]);
  const hasNodes = scene.nodes.length > 0 || scene.sensors.length > 0;
  const scale = Math.min(1.05, size.width / scene.width, size.height / scene.height);
  const centered = (value: number): Camera => ({
    x: (size.width - scene.width * value) / 2,
    y: (size.height - scene.height * value) / 2,
    scale: value,
  });
  const fit = centered(scale);
  const readable = centered(Math.max(0.55, scale));
  const view = camera === "fit" ? fit : camera ?? { ...readable, x: Math.max(0, readable.x), y: Math.max(0, readable.y) };
  const previewId = [hovered, focused].find((id) => id && scene.entities.has(id));
  const pinned = selected ? scene.entities.get(selected) : undefined;
  const preview = previewId ? scene.entities.get(previewId) : undefined;
  const active = preview?.id ?? pinned?.id;
  const hasSensors = graph.devices.some((device) => device.kind !== "firewall");
  const hasFirewalls = graph.devices.some((device) => device.kind === "firewall");
  const layerAvailability: DiagramLayers = { sensors: hasSensors, firewalls: hasFirewalls, hosts: graph.hosts.length > 0 };

  useEffect(() => {
    const svg = viewport.current;
    if (!svg || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (!width || !height) return;
      setSize({ width, height });
      const fullWidth = body.current?.clientWidth || width;
      setLayoutSize((previous) => previous.width === fullWidth && previous.height === height ? previous : { width: fullWidth, height });
    });
    observer.observe(svg);
    return () => observer.disconnect();
  }, [hasNodes, expanded]);

  function resizeDiagram(value: boolean) {
    setHovered(null);
    setFocused(null);
    setCamera(null);
    setExpanded(value);
  }

  function zoom(factor: number) {
    const nextScale = Math.min(3, Math.max(Math.min(0.25, scale), view.scale * factor));
    const ratio = nextScale / view.scale;
    const centerX = size.width / 2;
    const centerY = size.height / 2;
    setCamera({
      x: centerX + (view.x - centerX) * ratio,
      y: centerY + (view.y - centerY) * ratio,
      scale: nextScale,
    });
  }

  function startDrag(event: PointerEvent<SVGSVGElement>) {
    if (event.button !== 0) return;
    event.preventDefault();
    if ((event.target as Element).closest(".diagram-node")) return;
    event.currentTarget.focus();
    event.currentTarget.setPointerCapture(event.pointerId);
    drag.current = { pointer: event.pointerId, x: event.clientX, y: event.clientY, camera: view };
    setDragging(true);
  }

  function moveDrag(event: PointerEvent<SVGSVGElement>) {
    const start = drag.current;
    if (start?.pointer !== event.pointerId) return;
    setCamera({
      x: start.camera.x + event.clientX - start.x,
      y: start.camera.y + event.clientY - start.y,
      scale: start.camera.scale,
    });
  }

  function stopDrag(event: PointerEvent<SVGSVGElement>) {
    if (drag.current?.pointer !== event.pointerId) return;
    drag.current = null;
    setDragging(false);
  }

  function panByKeyboard(event: KeyboardEvent<SVGSVGElement>) {
    if (event.key === "Escape") {
      setSelected(null);
      setExtraSensorIds([]);
      return;
    }
    if (event.currentTarget !== event.target) return;
    const offset = { ArrowLeft: [48, 0], ArrowRight: [-48, 0], ArrowUp: [0, 48], ArrowDown: [0, -48] }[event.key];
    if (!offset) return;
    event.preventDefault();
    setCamera({ ...view, x: view.x + offset[0], y: view.y + offset[1] });
  }

  function revealNode(node: DiagramNode) {
    const left = node.x * view.scale + view.x;
    const top = node.y * view.scale + view.y;
    const right = left + node.width * view.scale;
    const bottom = top + node.height * view.scale;
    if (left >= 4 && right <= size.width - 4 && top >= 4 && bottom <= size.height - 4) return;
    setCamera({
      ...view,
      x: size.width / 2 - (node.x + node.width / 2) * view.scale,
      y: size.height / 2 - (node.y + node.height / 2) * view.scale,
    });
  }

  function selectFromDetails(id: string) {
    if (!scene.entities.has(id)) return;
    setHovered(null);
    setFocused(null);
    setSelected(id);
    setExtraSensorIds([]);
    viewport.current?.focus();
    const node = scene.nodesById.get(id);
    if (node) revealNode(node);
  }

  function toggleSelection(id: string) {
    setSelected((current) => current === id ? null : id);
    setExtraSensorIds([]);
  }

  async function askAbout(entity?: DiagramEntity) {
    if (!onAsk || !revision || !viewport.current || asking) return;
    setAsking(true);
    setAskError("");
    try {
      const image = await captureNetworkView(viewport.current).catch(() => null);
      await onAsk({
        revision, topology: graph, image, selected_id: entity?.id, selection_label: entity && nodeLabel(entity),
        visible_layers: (Object.keys(layers) as (keyof DiagramLayers)[]).filter((layer) => layers[layer] && layerAvailability[layer]),
        expanded_subnet_ids: scene.branches.filter((branch) => branch.expanded).map(({ node }) => node.id),
        sensor_key: Object.fromEntries(scene.sensors.map(({ mark, device }) => [mark, device.id])),
      });
      setExpanded(false);
    } catch (error) {
      setAskError(String(error));
    } finally {
      setAsking(false);
    }
  }

  const diagram = <section className="network-diagram" aria-labelledby={title}>
    <header className="diagram-titlebar">
      <div><h3 id={title}>Network diagram</h3>{(description || (expanded && context)) && <p className="muted">{description || context}</p>}</div>
      <div className="diagram-controls">
        {actions}
        {onAsk && revision && hasNodes && <button type="button" className="button-quiet" disabled={asking}
          onClick={() => void askAbout()}>Ask about this diagram</button>}
        {expanded
          ? <button ref={restoreButton} type="button" className="button-quiet" onClick={() => resizeDiagram(false)}><Minimize size={16} aria-hidden="true" /> Exit expanded view</button>
          : hasNodes && <button ref={expandButton} type="button" className="button-quiet" onClick={() => resizeDiagram(true)}><Expand size={16} aria-hidden="true" /> Expand diagram</button>}
      </div>
    </header>
    {askError && <p role="alert">{askError}</p>}
    {graph.segments.length === 0 && <p className="muted">No network segments are declared.</p>}
    {(graph.segments.length > 0 || graph.devices.length > 0 || graph.hosts.length > 0) && <>
      <div className="diagram-toolbar">
        <div className="diagram-controls" role="group" aria-label="Diagram layers">
          {(Object.keys(LAYER_LABELS) as (keyof DiagramLayers)[]).map((key) => <button key={key} type="button" className="button-quiet"
            disabled={!layerAvailability[key]} title={layerAvailability[key] ? undefined : `No ${LAYER_LABELS[key].toLowerCase()} in this environment`}
            aria-pressed={layers[key] && layerAvailability[key]} onClick={() => {
              setLayers({ ...layers, [key]: !layers[key] });
              setHovered(null);
              setFocused(null);
              setExtraSensorIds([]);
              setCamera(null);
            }}>{LAYER_LABELS[key]}</button>)}
        </div>
        <div className="diagram-controls" role="group" aria-label="Diagram view">
          <button type="button" className="button-quiet" aria-label="Zoom out" disabled={!hasNodes} onClick={() => zoom(0.8)}><ZoomOut size={16} /></button>
          <button type="button" className="button-quiet" aria-label="Zoom in" disabled={!hasNodes} onClick={() => zoom(1.25)}><ZoomIn size={16} /></button>
          <button type="button" className="button-quiet" disabled={!hasNodes} onClick={() => setCamera("fit")}><Maximize size={16} aria-hidden="true" /> Fit to view</button>
        </div>
      </div>
      {hasNodes ? <>
        <div ref={body} className="diagram-body">
          <div className="diagram-canvas">
            <svg ref={viewport} className="diagram-viewport" data-dragging={dragging} tabIndex={0}
              role="group" aria-label="Network map, use arrow keys to pan" onKeyDown={panByKeyboard}
              onPointerDown={startDrag} onPointerMove={moveDrag} onPointerUp={stopDrag}
              onPointerCancel={stopDrag} onLostPointerCapture={stopDrag}>
              <g transform={`translate(${view.x} ${view.y}) scale(${view.scale})`}>
                <g aria-hidden="true" className="diagram-edges">{scene.wires.map((wire) =>
                  <path key={wire.key} d={wire.path} data-kind={wire.kind} data-highlighted={!!active && wire.entities.includes(active)} />)}
                </g>
                <g aria-hidden="true" className="diagram-interface-labels">
                  {scene.labels.map((label) => <text key={label.key} x={label.x} y={label.y}>
                    {abbreviatedLabel(label.text, Math.floor(label.width / 7))}<title>{label.text}</title>
                  </text>)}
                </g>
                {scene.nodes.map((node) => {
                  const { kind, id, x, y, width, height } = node;
                  const label = nodeLabel(node);
                  const endpoint = kind === "host" && !node.equipment;
                  const labelLimit = endpoint ? Math.floor((width - 4) / 6.7) : Math.floor((width - 12) / 9);
                  const osFamily = kind === "host" ? node.host.os_family : "";
                  const EquipmentIcon = node.equipment === "firewall" ? BrickWallFire : Network;
                  const routerSymbol = node.equipment === "router" || node.equipment === "network";
                  const accessibleLabel = kind === "segment" ? `Segment ${label}, ${node.segment.cidr}`
                    : kind === "device" ? `Firewall ${label}`
                    : kind === "host" ? `${label} ${node.equipment ? EQUIPMENT_LABELS[node.equipment] : OS_LABELS[osFamily] || "Other OS"}` : label;
                  return <g key={node.key} className="diagram-node" transform={`translate(${x} ${y})`} role="button"
                    tabIndex={0} aria-label={accessibleLabel} aria-pressed={selected === id}
                    data-kind={kind} data-equipment={node.equipment} data-active={active === id} data-family={osFamily || undefined}
                    onMouseEnter={() => setHovered(id)} onMouseLeave={() => setHovered(null)}
                    onFocus={() => { setFocused(id); revealNode(node); }} onBlur={() => setFocused(null)}
                    onClick={(event) => {
                      toggleSelection(id);
                      event.currentTarget.focus({ preventScroll: true });
                    }} onKeyDown={(event) => activateByKey(event, () => toggleSelection(id))}>
                    <rect className="diagram-node-box" width={width} height={height} />
                    {routerSymbol ? <RouterIcon x={width / 2 - 22} y={12} />
                      : node.equipment && <EquipmentIcon x={width / 2 - 22} y={12} size={44} aria-hidden="true" />}
                    {endpoint && <HostIcon family={osFamily} x={width / 2 - 13} y={0} size={26} />}
                    <text x={width / 2} y={node.equipment ? 69 : kind === "host" ? 39 : 16} textAnchor="middle"
                      className="diagram-node-label" aria-hidden="true">
                      {abbreviatedLabel(label, labelLimit, endpoint)}
                    </text>
                    {kind === "segment" && <text x={width / 2} y={36} textAnchor="middle"
                      className="diagram-node-subtitle" aria-hidden="true">{node.segment.cidr}</text>}
                    <title>{kind === "host" ? `${label} · ${node.host.os}` : accessibleLabel}</title>
                  </g>;
                })}
                {scene.branches.map((branch) => <BranchControls
                  key={branch.node.id} branch={branch} active={active} selected={selected}
                  onPreview={setHovered} onSelect={toggleSelection}
                  onPage={(page) => setHostPages((current) => ({ ...current, [branch.node.id]: page }))}
                  onRevealSensors={(ids) => {
                    setSelected(branch.node.id);
                    setHovered(null);
                    setFocused(null);
                    setExtraSensorIds(ids);
                  }}
                  onToggle={() => setBranchChoices((current) => ({ ...current, [branch.node.id]: !branch.expanded }))} />)}
              </g>
            </svg>
            {preview && preview.id !== pinned?.id && <div className="diagram-preview">
              <strong>{nodeLabel(preview)}</strong>
              {preview.kind === "segment" && <code>{preview.segment.cidr}</code>}
              {preview.kind === "device" && <span>{DEVICE_LABELS[preview.device.kind]} · {preview.device.placement.toUpperCase()}</span>}
              {preview.kind === "host" && <span>{preview.host.ip} · {preview.host.os}</span>}
            </div>}
          </div>
          {pinned && <DiagramInspector entity={pinned} graph={graph}
            hosts={layers.hosts ? groups.get(pinned.id) ?? [] : []}
            associations={(scene.associations.get(pinned.id) ?? []).filter(({ device }) => scene.entities.has(device.id))}
            extraSensorIds={extraSensorIds}
            askAction={onAsk && revision && <button type="button" className="button-quiet" disabled={asking}
              onClick={() => void askAbout(pinned)}>Ask about this</button>}
            onSelect={selectFromDetails} onClose={() => { setSelected(null); setExtraSensorIds([]); viewport.current?.focus(); }} />}
        </div>
        <div className="diagram-legend" aria-label="Diagram key">
          {layers.firewalls && hasFirewalls && <span><i aria-hidden="true" />Firewall interface</span>}
          {scene.wires.some(({ kind }) => kind === "membership") && <span><i className="diagram-membership-key" aria-hidden="true" />Device subnet membership</span>}
          {scene.sensors.some(({ device }) => device.placement === "tap") && <CoverageKey placement="tap" />}
          {scene.sensors.some(({ device }) => device.placement === "span") && <CoverageKey placement="span" />}
          <SensorKey sensors={scene.sensors} active={active} selected={selected}
            onPreview={setHovered} onSelect={toggleSelection} />
        </div>
      </> : <p className="muted">No diagram items in the selected layers.</p>}
    </>}
    {graph.findings.length > 0 && <details className="diagram-findings">
      <summary>{graph.findings.length} diagram {graph.findings.length === 1 ? "finding" : "findings"}</summary>
      <ul>{graph.findings.map(({ entity_id, message }) => <li key={JSON.stringify([entity_id, message])}>{message}</li>)}</ul>
    </details>}
  </section>;
  return expanded ? <Modal title="Expanded network diagram" hideTitle size="full" className="network-diagram-dialog"
    onClose={() => resizeDiagram(false)}
    onOpenAutoFocus={(event) => { event.preventDefault(); restoreButton.current?.focus(); }}
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
