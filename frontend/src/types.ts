export interface Annotation {
  status: string;
  tags: string[];
}
export interface Host {
  id: number;
  ip: string;
  first_seen: string;
  last_seen: string;
}
export interface HostRow {
  id: number;
  ip: string;
  hostnames: string[];
  open_count: number;
  status: string;
  tags: string[];
  open_services: [number, string | null][];
  change: string;
  triaged: boolean;
}
export interface Service {
  service_id: number;
  port: number;
  proto: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  last_seen: string;
  annotation: Annotation | null;
  manual: boolean;
  overrides: TimelineOverrides;
}
export interface LinkedHost {
  host_id: number;
  ip: string;
}
export interface LinkedService {
  service_id: number;
  host_id: number;
  ip: string;
  port: number;
  proto: string;
  name: string | null;
}
export interface Credential {
  id: number;
  kind: string;
  username: string;
  secret: string;
  notes: string;
  created_at: string;
  hosts: LinkedHost[];
  services: LinkedService[];
  pickable_services: LinkedService[];
}
export type HostCredential = Pick<Credential, "id" | "kind" | "username" | "secret" | "notes"> & {
  hosts: Pick<LinkedHost, "host_id">[];
  services: Omit<LinkedService, "ip">[];
};
export interface Note {
  id: number;
  title: string;
  body_md: string;
  updated_at: string;
}
export interface Scan {
  id: number;
  filename: string;
  tool: string;
  imported_at: string;
  host_count: number;
}
export interface TimelineState {
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
}
export interface TimelineOverrides extends Omit<TimelineState, "state"> {
  state: string | null;
}
export interface TimelineChange {
  port: number;
  proto: string;
  kind: "added" | "changed" | "removed";
  before: TimelineState | null;
  after: TimelineState | null;
  before_overrides?: TimelineOverrides | null;
  after_overrides?: TimelineOverrides | null;
}
export interface TimelineEntry {
  id: string;
  source: "scan" | "manual";
  scan_id: number | null;
  filename: string;
  tool: string;
  occurred_at: string;
  time_source: "scan" | "import" | "manual";
  first_seen: boolean;
  coverage_known: boolean;
  changes: TimelineChange[];
  not_reported: { port: number; proto: string }[];
}
export interface HostTimeline {
  entries: TimelineEntry[];
  total: number;
  page: number;
  pages: number;
  show_unchanged: boolean;
  latest_change: TimelineEntry | null;
}
export interface Operation {
  id: number;
  started_at: string | null;
  ended_at: string | null;
  source: string;
  destination: string;
  tool: string;
  user_context: string;
  command: string;
  output: string;
  description: string;
  comments: string;
  tags: string[];
  attachment_name: string | null;
  created_at: string;
  updated_at: string;
}
export interface Engagement {
  id: string;
  name: string;
  description: string;
  created_at: string;
}
export type EngagementOption = Pick<Engagement, "id" | "name">;
export type ServiceOption = Pick<Service, "service_id" | "port" | "proto" | "service_name">;

export interface BootstrapData {
  engagement?: EngagementOption;
  engagements: EngagementOption[];
}

export interface PageData extends BootstrapData {
  catalog?: Engagement[];
  rows?: HostRow[];
  total?: number;
  matched?: number;
  page?: number;
  pages?: number;
  per?: string;
  q?: string;
  port?: string;
  tag?: string;
  status?: string;
  change?: string;
  sort?: string;
  direction?: string;
  statuses?: string[];
  states?: string[];
  kinds?: string[];
  host?: Host;
  hostnames?: [number, string][];
  host_ann?: Annotation | null;
  host_notes?: Note[];
  host_credentials?: HostCredential[];
  host_timeline?: HostTimeline;
  services?: Service[];
  svc_total?: number;
  f_port?: string;
  f_state?: string;
  f_service?: string;
  f_status?: string;
  credentials?: Credential[];
  scans?: Scan[];
  tools?: string[];
  a?: number | null;
  b?: number | null;
  result?: {
    scan_a: Pick<Scan, "id" | "filename">;
    scan_b: Pick<Scan, "id" | "filename">;
    entries: {
      ip: string;
      port: number;
      proto: string;
      kind: string;
      before: string | null;
      after: string | null;
    }[];
  } | null;
  operations?: Operation[];
  results?: {
    hosts: HostRow[];
    notes: {
      href: string;
      where: string;
      title: string;
      preview: string;
    }[];
    credentials: Pick<Credential, "id" | "kind" | "username" | "hosts">[];
  };
}
