# Talus Enterprises

A fictional 350-person robotics company designing and manufacturing the Talus
Protective Automaton (TPA). This standalone organization draft represents the
company with 44 named staff, 12 automation workload accounts, and 85 systems. Its stable name is talus-enterprises;
the user-selected domain is talus.lab.

## Sites and routing

The HQ and manufacturing cores route their respective internal subnets. At HQ,
the Internet firewall terminates the guest and DMZ subnets on separate interfaces.
Each core has a routed handoff to its local VPN concentrator. The private WAN
circuit joins the concentrators. EvidenceForge models forwarding across this
link without generating IPsec encapsulation. Manufacturing Internet traffic
backhauls through the HQ firewall.

The manufacturing guest subnet has a local firewall gateway. Both guest subnets
can initiate connections to the Internet on ports 53, 80, 443, and 123 and to the
HQ DMZ on port 443. Forwarding defaults to deny. Replies to allowed flows follow
the return route. The HQ edge maintains the portal's public HTTPS VIP and the
portal can reach its internal backend on port 8069.
The modeled policies apply to forwarded traffic. Access to the firewall's own
interface addresses is outside the forwarding policy model.

## Monitoring

Zeek and IDS TAPs monitor the HQ core-to-firewall transit and the HQ
concentrator's LAN-side link. The WAN circuit is unmonitored. Each guest-facing
firewall link has a Zeek TAP. Engineering and prototype retain their subnet
uplink Zeek and IDS collectors, and the other internal subnet uplinks retain
connection-only Zeek. The DMZ uses SPAN for eligible same-subnet traffic. Both
firewalls emit ASA evidence, and the manufacturing log collector has a modeled
TLS forwarding connection to HQ.

Same-subnet traffic generally stays off the routed uplinks. Link-local DHCP is
generally invisible to TAPs. TLS content remains opaque, while the support
proxy's cleartext backend can expose HTTP.

## Users, identity, and work hours

All staff use first.last usernames and matching @talus.lab addresses.
Leaders/key personnel have mythology-inspired full names and system names.
Department groups, release approvers/publishers, lab operators, and support
publishers are explicit.

HQ works weekdays 09:00–17:00; manufacturing 07:00–16:00, with lunch 12:00–13:00.
Manufacturing has one represented daytime shift. Ambient volume is restrained
for the staff sample; application cadences model recurring engineering work
and programming/calibration bursts.

Separate named administrative principals and service accounts are declared.
The public group model does not encode the administrative principals' complete
privileged authorization. Ordinary staff are not members of Domain Admins.

## Software and behavior

Real products: GitLab/registries, VS Code/Git/GCC/Make/Docker/pytest, ROS 2 Jazzy,
Gazebo, PyTorch, MLflow, Solid Edge 2024, PADS Professional VX.2.14, Odoo,
NI TestStand 2024, Foxglove, and Microsoft 365.

The technology industry is pinned to exact 1.0.0 and its locked digest.
Its engineering-toolchain and engineering-share exports are reused.
Organization applications own audiences, named connections, process profiles,
cadences, and robotics-specific storage vocabulary.

| Custom software | Role | Platform |
| --- | --- | --- |
| CRETE | Robot controls/autonomy/perception/diagnostics; local bench and simulation instances | Linux development systems and robot computers |
| HEPHAESTUS | Approved programming/calibration integrating with NI TestStand | Windows manufacturing/calibration stations |
| ARGO | Simulation regression and physical integration/acceptance tests | Linux engineering, CI/simulation, and test systems |

Definitions model supported process/network evidence. They do not execute
software, implement firmware, or add vendor-native log formats. Binary versions
and PE metadata are modeled installation identities, not extracted installer
measurements. No vendor binaries or executable hooks are included.

Normal work includes source/artifact access, model tracking, explicit GPU/CI worker connections,
simulation results, CAD/PCB revisions, manufacturing ERP, calibration bursts,
support exchanges, and storage activity. Robot DDS is generic UDP transport,
not decoded ROS content. HTTPS transfers use synthetic body-size profiles.

## Customer-contained deployments and support

Customer-owned robots and fleet servers are outside Talus's host inventory.
Routine operation and fleet management stay at customer premises.

Customers initiate HTTPS sessions to support.talus.lab for tickets, diagnostic
uploads, and authorized approved-release downloads. A DMZ nginx entry point
connects to a dedicated Odoo Helpdesk/Documents backend in HQ shared services,
separate from manufacturing ERP. Staff retrieve diagnostic bundles and approved
release copies; Foxglove browser activity represents recording visualization.
No continuous customer fleet telemetry is assumed.

## Storage and email

Windows HQ shares hold engineering, hardware, business, and approved-release
documents. Linux Samba dataset/recording storage uses ext4 but advertises NTFS
over SMB. Manufacturing has Windows procedure/acceptance shares and a local
release cache. Windows drives and Linux mounts use per-user credentials;
Linux clients explicitly declare cifs-utils capability.

Microsoft 365 email/collaboration is external SaaS. No on-prem Exchange or native
SMTP topology is fabricated. External products use reserved simulation domains/IPs;
product names identify real software rather than live network targets.

## Scope and lifecycle

All six catalogs and both organization model files are authored. Scenario identity,
dates, seed, output formats, attack storylines, exercise collection overrides,
and generation/evaluation/runtime policy remain scenario-owned.
Generation stays deterministic in eforge.

This editable Schema 3 draft retains its original draft ID and publisher metadata.
No release version is allocated and nothing is published.

## Product references

- [GitLab registry](https://docs.gitlab.com/user/packages/package_registry/)
- [ROS/Gazebo](https://index.ros.org/p/ros_gz_sim/)
- [MLflow](https://www.mlflow.org/docs/latest/tracking/)
- [PyTorch](https://pytorch.org/get-started/locally/)
- [Solid Edge](https://blogs.sw.siemens.com/solidedge/First-Steps-to-Automation-Part-2/)
- [PADS Professional](https://www.siemens.com/en-gb/products/pcb/pads/professional/)
- [Odoo](https://www.odoo.com/documentation/master/applications/inventory_and_mrp.html)
- [Odoo Helpdesk](https://www.odoo.com/documentation/19.0/applications/services/helpdesk.html)
- [Odoo Documents](https://www.odoo.com/documentation/19.0/applications/productivity/documents.html)
- [NI TestStand](https://knowledge.ni.com/KnowledgeArticleDetails?id=kA03q000000ozLmCAI&l=en-US)
- [Foxglove](https://docs.foxglove.dev/docs/visualization)

## Network inventory

| Segment | CIDR | Purpose |
| --- | --- | --- |
| hq-corporate | 10.40.10.0/24 | Corporate workstations |
| hq-engineering | 10.40.20.0/24 | Engineering access subnet across several switches |
| hq-ai-compute | 10.40.30.0/24 | GPU training and simulation workers |
| hq-shared-services | 10.40.40.0/24 | Identity, source control, model tracking, and engineering services |
| hq-prototype | 10.40.50.0/24 | Prototype robots and lab benches |
| hq-dmz | 10.40.60.0/24 | Customer support HTTPS entry point |
| hq-management | 10.40.90.0/24 | Administrative workstations, jump host, and infrastructure management |
| hq-guest | 10.40.100.0/24 | Guest access |
| hq-edge-transit | 10.40.254.0/30 | HQ central router to Internet firewall, routed link |
| mfg-operations | 10.50.10.0/24 | Planning, procurement, materials, and supervision |
| mfg-production | 10.50.20.0/24 | Assembly and programming |
| mfg-quality | 10.50.30.0/24 | Calibration and robot acceptance testing |
| mfg-local-services | 10.50.40.0/24 | Production ERP and approved release staging |
| mfg-management | 10.50.90.0/24 | Manufacturing management and jump host |
| mfg-guest | 10.50.100.0/24 | Manufacturing guest access |
| site-transit | 10.60.0.0/30 | Private leased line joining the two VPN concentrators; WAN interface addresses |
| hq-vpn-lan | 10.40.253.0/30 | Routed link between HQ core and VPN concentrator |
| mfg-vpn-lan | 10.50.254.0/30 | Routed link between manufacturing core and VPN concentrator |
| mfg-guest-transit | 10.50.253.0/30 | Routed link between manufacturing core and guest firewall |

## Application workflows

| Export | Purpose |
| --- | --- |
| productivity | Email, collaboration, and business documents. |
| software-development | GitLab development and approved artifact access. |
| ml-training | PyTorch training and experiment tracking. |
| model-review | Model and experiment review. |
| simulation | Gazebo scene development and ARGO simulation runs. |
| robot-development | ROS 2 and CRETE local bench/simulation development. |
| argo-validation | ARGO integration and acceptance test execution. |
| mechanical-design | Solid Edge assemblies and design revisions. |
| pcb-design | PADS Professional electronics revisions. |
| design-change-control | Odoo engineering changes, BOMs, and design release. |
| manufacturing-operations | Odoo production, inventory, procurement, and quality. |
| hephaestus-programming | HEPHAESTUS programs approved releases and records calibration. |
| support-diagnostics | Odoo customer tickets, diagnostic bundle retrieval, and approved support releases. |
| engineering-storage | Engineering documents, datasets, and diagnostic recordings. |
| manufacturing-storage | Procedures and acceptance records. |
| administration | Infrastructure administration through approved management paths. |
| foxglove-visualization | Foxglove in the browser for local MCAP replay and internal lab diagnostic analysis. |
| dataset-storage | AI, software, and verification access to authorized datasets and MCAP recordings. |
| ci-worker | GitLab build and artifact automation workload account. |
| training-worker | GPU training and model-tracking automation workload account. |
| simulation-worker | ARGO and Gazebo simulation automation workload account. |
| release-cache-worker | Approved-release cache synchronization workload account. |
| support-proxy-worker | Customer support reverse proxy workload workload account. |
| log-collector-worker | Local log collector and forwarding automation workload account. |
| robot-runtime-worker | Internal prototype and acceptance CRETE runtime workload account. |

## Staff and primary workstations

| Name | Username | Role | OS | Workstation | Subnet |
| --- | --- | --- | --- | --- | --- |
| Atlas Mercer | atlas.mercer | CEO | Windows | ATLAS-WS01 | hq-corporate |
| Hera Ward | hera.ward | COO | Windows | HERA-WS01 | hq-corporate |
| Rhea Brooks | rhea.brooks | CFO | Windows | RHEA-WS01 | hq-corporate |
| Ariadne Bell | ariadne.bell | Product director | Windows | ARIADNE-WS01 | hq-corporate |
| Hannah Price | hannah.price | HR and business administration | Windows | HQ-BIZ-01 | hq-corporate |
| Marcus Bell | marcus.bell | Sales and customer accounts | Windows | HQ-BIZ-02 | hq-corporate |
| Athena Chen | athena.chen | CTO | Windows | ATHENA-WS01 | hq-engineering |
| Hector Morgan | hector.morgan | Lead systems engineer | Windows | HECTOR-WS01 | hq-engineering |
| Iris Patel | iris.patel | Lead controls engineer | Linux | IRIS-WS01 | hq-engineering |
| Phoebe Marin | phoebe.marin | Head of AI and autonomy | Linux | PHOEBE-WS01 | hq-engineering |
| Elias Reed | elias.reed | Computer vision engineer | Linux | HQ-AI-01 | hq-engineering |
| Priya Shah | priya.shah | Autonomy engineer | Linux | HQ-AI-02 | hq-engineering |
| Jonah Park | jonah.park | ML infrastructure engineer | Linux | HQ-AI-03 | hq-engineering |
| Sofia Vega | sofia.vega | Simulation and data engineer | Linux | HQ-AI-04 | hq-engineering |
| Perseus Clarke | perseus.clarke | Head of software | Linux | PERSEUS-WS01 | hq-engineering |
| Leila Haddad | leila.haddad | Robotics middleware engineer | Linux | HQ-SWE-01 | hq-engineering |
| Daniel Kim | daniel.kim | Embedded software engineer | Linux | HQ-SWE-02 | hq-engineering |
| Clara Jensen | clara.jensen | Fleet software engineer | Linux | HQ-SWE-03 | hq-engineering |
| Ravi Mehta | ravi.mehta | Build and release engineer | Linux | HQ-SWE-04 | hq-engineering |
| Daedalus Voss | daedalus.voss | Head of hardware engineering | Windows | DAEDALUS-WS01 | hq-engineering |
| Amara Okafor | amara.okafor | Mechanical engineer | Windows | HQ-HW-01 | hq-engineering |
| Lucas Silva | lucas.silva | Electrical engineer | Windows | HQ-HW-02 | hq-engineering |
| Nina Patel | nina.patel | PCB engineer | Windows | HQ-HW-03 | hq-engineering |
| Grace Liu | grace.liu | Hardware bring-up engineer | Linux | HQ-HW-04 | hq-engineering |
| Felix Hart | felix.hart | Engineering configuration specialist | Windows | HQ-HW-05 | hq-engineering |
| Hephaestus Hayes | hephaestus.hayes | Manufacturing director | Windows | HEPHAESTUS-WS01 | mfg-operations |
| Rosa Delgado | rosa.delgado | Production planner | Windows | MFG-OPS-01 | mfg-operations |
| Ben Carter | ben.carter | Assembly supervisor | Windows | MFG-PROD-01 | mfg-production |
| Aisha Rahman | aisha.rahman | Manufacturing engineer | Windows | MFG-PROD-02 | mfg-production |
| Mateo Ruiz | mateo.ruiz | Procurement specialist | Windows | MFG-OPS-02 | mfg-operations |
| Erin Walsh | erin.walsh | Materials coordinator | Windows | MFG-OPS-03 | mfg-operations |
| Owen Park | owen.park | Production technician | Windows | MFG-PROD-03 | mfg-production |
| Themis Scott | themis.scott | Head of quality and safety | Windows | THEMIS-WS01 | mfg-quality |
| Noah Evans | noah.evans | System verification engineer | Linux | MFG-QA-01 | mfg-quality |
| Tara Singh | tara.singh | Calibration and quality engineer | Windows | MFG-QA-02 | mfg-quality |
| Leo Fischer | leo.fischer | Functional safety engineer | Windows | HQ-QA-01 | hq-engineering |
| Hermes Ross | hermes.ross | Field service manager | Windows | HERMES-WS01 | hq-corporate |
| Keira Adams | keira.adams | Field service engineer | Windows | HQ-FIELD-01 | hq-corporate |
| Samir Nasser | samir.nasser | Technical support engineer | Windows | HQ-FIELD-02 | hq-corporate |
| Argus Blake | argus.blake | IT and security manager | Windows | ARGUS-WS01 | hq-management |
| Olivia Grant | olivia.grant | Identity and endpoint administrator | Windows | HQ-IT-01 | hq-management |
| Ethan Cole | ethan.cole | Linux and network administrator | Linux | HQ-IT-02 | hq-management |
| Chloe Martin | chloe.martin | OT systems administrator | Windows | MFG-IT-01 | mfg-management |
| Cassandra Hale | cassandra.hale | Security analyst | Linux | CASSANDRA-WS01 | hq-management |

## Automation workload representation

Eforge schedules application cadences and internal affinities from active accounts.
Twelve functional workload accounts therefore represent CI, training, simulation,
release caching, the support proxy, log collection, and internal CRETE runtimes.
They are functional account records rather than additional staff; their logical names use
first.last and their Linux account names/UIDs are explicit local identities.
Their 24-hour personas use the public parsed-hours field. Runtime scheduling uses
persistent account-session texture; this is not an exact systemd/cron lifecycle
simulation. No arbitrary jobs, hooks, or engine-owned effect plans are authored.

| Workload account | System | Function |
| --- | --- | --- |
| build.runner01 | HQ-CI-01 | GitLab Runner 01 account |
| build.runner02 | HQ-CI-02 | GitLab Runner 02 account |
| training.worker01 | HQ-GPU-01 | GPU Training 01 account |
| training.worker02 | HQ-GPU-02 | GPU Training 02 account |
| argo.runner | HQ-SIM-01 | ARGO Simulation account |
| release.sync | MFG-STAGE-01 | Release Cache account |
| logs.forwarder | MFG-LOG-01 | Manufacturing Log Collector account |
| support.proxy | HQ-PORTAL-01 | Customer Support Proxy account |
| crete.prototype01 | HQ-TPA-01 | CRETE Prototype 01 account |
| crete.prototype02 | HQ-TPA-02 | CRETE Prototype 02 account |
| crete.acceptance01 | MFG-TPA-01 | CRETE Acceptance 01 account |
| crete.acceptance02 | MFG-TPA-02 | CRETE Acceptance 02 account |

- [GitLab Runner commands](https://docs.gitlab.com/runner/commands/)
- [nginx command-line parameters](https://nginx.org/en/docs/switches.html)

Functional accounts live in the public users list to participate in scheduling;
the separate service_accounts list contains additional actor-only principals.
These lists are disjoint. Parsed automation hours explicitly supply start/end,
hours, and no lunch or peak windows.

Linux services use native unit/capability names such as gitlab-runner, smbd,
crete, and nginx. ROS 2, CUDA, PyTorch, ARGO, and Windows TestStand are software
components rather than fictitious OS service names. GPU/simulation jobs can use
the already selected GitLab Runner infrastructure. Proxy frontend/backend traffic
is independently shaped; no one-to-one reverse-proxy request correlation is claimed.
Host output selection remains consumer-owned; the proof requests broad host telemetry
for verification rather than establishing blanket real-world endpoint-agent coverage.
