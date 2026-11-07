import { QueryLink, ScopedLink } from "../common";
import { lazy, Suspense, useEffect, useState, type ComponentProps } from "react";
import { Tabs } from "@base-ui/react/tabs";
import { ListFilter, Network, RotateCcw } from "lucide-react";
import { Secret } from "@/components/secret";
import { CredentialFields } from "@/components/credential-fields";
import { HostTimeline, TimelineTime, timelineSummary, timelineUrl } from "@/components/host-timeline";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Empty,
  Field,
  Filters,
  Modal,
  MutationForm,
  Pager,
  SelectField,
  usePage,
} from "../common";
import type { Credential, Note, PageData, Service } from "../types";
import {
  describeHostCommand,
  initialHostView,
  isHostSection,
  reconcileHostView,
  sectionFromHash,
  transitionHostView,
  type HostCommand,
  type HostViewEvent,
} from "./host-workflow";

const MarkdownView = lazy(() =>
  import("@/components/markdown-view").then((module) => ({
    default: module.MarkdownView,
  })),
);

const MarkdownEditor = lazy(() =>
  import("@/components/markdown-editor").then((module) => ({
    default: module.MarkdownEditor,
  })),
);

function timestamp(value: string) {
  return value.replace("T", " ").slice(0, 16);
}

function HostActionForm({
  command,
  ...props
}: Omit<ComponentProps<typeof MutationForm>, "action" | "confirm" | "onSuccess"> & { command: HostCommand }) {
  const { navigate } = usePage();
  const { action, confirm, outcome } = describeHostCommand(command);
  return (
    <MutationForm
      {...props}
      action={action}
      confirm={confirm}
      onSuccess={outcome.type === "return-to-inventory" ? () => navigate(outcome.href) : undefined}
    />
  );
}

function ServiceContext({ data }: { data: PageData }) {
  return (
    <>
      <input type="hidden" name="sort" value={data.sort ?? "port"} />
      <input type="hidden" name="dir" value={data.direction ?? "asc"} />
      <input type="hidden" name="page" value={data.page ?? 1} />
      <input type="hidden" name="per" value={data.per ?? "25"} />
      <input type="hidden" name="f_port" value={data.f_port ?? ""} />
      <input type="hidden" name="f_state" value={data.f_state ?? ""} />
      <input type="hidden" name="f_service" value={data.f_service ?? ""} />
      <input type="hidden" name="f_status" value={data.f_status ?? ""} />
    </>
  );
}

function ServiceDetail({
  service,
  data,
}: {
  service: Service;
  data: PageData;
}) {
  const annotation = service.annotation;
  return (
    <Modal
      title={`Service ${service.port}/${service.proto}`}
      trigger={
        <Button
          variant="outline"
          size="sm"
          aria-label={`Edit service ${service.port}/${service.proto}`}
        >
          Edit service
        </Button>
      }
    >
      <div className="stack">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {service.manual && <Badge variant="secondary">Manual</Badge>}
          <span className="muted">
            Last seen: {service.last_seen || "Not seen in a scan"}
          </span>
        </div>
        <HostActionForm
          command={{ type: "save-service-overrides", serviceId: service.service_id }}
          className="stack"
        >
          <ServiceContext data={data} />
          <div className="form-grid">
            <SelectField
              label="State"
              name="state"
              defaultValue={service.overrides.state ?? ""}
              options={data.states ?? []}
              empty="Use latest scan value"
            />
            <Field
              label="Service name"
              name="service_name"
              defaultValue={service.overrides.service_name ?? ""}
            />
            <Field
              label="Product"
              name="product"
              defaultValue={service.overrides.product ?? ""}
            />
            <Field
              label="Version"
              name="version"
              defaultValue={service.overrides.version ?? ""}
            />
            <SelectField
              label="Triage status"
              name="status"
              defaultValue={annotation?.status ?? "new"}
              options={data.statuses ?? []}
            />
            <Field
              label="Tags"
              name="tags"
              defaultValue={annotation?.tags.join(", ") ?? ""}
              placeholder="comma, separated"
            />
          </div>
          <p className="muted text-sm">
            Manual values survive future scans. Leave a field empty to use its
            latest scan value instead.
          </p>
          <div className="actions">
            <Button type="submit">Save service</Button>
          </div>
        </HostActionForm>
        <div className="flex flex-wrap gap-3 border-t pt-4">
          <HostActionForm
            command={{ type: "reset-service-overrides", serviceId: service.service_id }}
          >
            <ServiceContext data={data} />
            <input type="hidden" name="state" value="" />
            <input type="hidden" name="service_name" value="" />
            <input type="hidden" name="product" value="" />
            <input type="hidden" name="version" value="" />
            <input
              type="hidden"
              name="status"
              value={annotation?.status ?? "new"}
            />
            <input
              type="hidden"
              name="tags"
              value={annotation?.tags.join(", ") ?? ""}
            />
            <Button type="submit" variant="outline">
              Reset scan overrides
            </Button>
          </HostActionForm>
          <HostActionForm
            command={{ type: "delete-service", serviceId: service.service_id, label: `${service.port}/${service.proto}` }}
          >
            <ServiceContext data={data} />
            <Button type="submit" variant="destructive">
              Delete service
            </Button>
          </HostActionForm>
        </div>
      </div>
    </Modal>
  );
}

function CredentialDetail({
  credential,
  data,
  hostId,
}: {
  credential: Credential;
  data: PageData;
  hostId: number;
}) {
  const services = credential.services.filter(
    (service) => service.host_id === hostId,
  );
  return (
    <article>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">{credential.kind}</Badge>
            {credential.hosts.some((host) => host.host_id === hostId) && (
              <Badge variant="secondary">Host-wide</Badge>
            )}
            {services.map((service) => (
              <Badge key={service.service_id} variant="secondary">
                {service.port}/{service.proto}
                {service.name ? ` ${service.name}` : ""}
              </Badge>
            ))}
          </div>
          <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-x-4 gap-y-1 text-sm">
            <div className="min-w-0">
              <dt className="muted">Username</dt>
              <dd className="mono min-w-0 break-all py-1">
                {credential.username || "—"}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="muted">Secret</dt>
              <dd className="min-w-0">
                <Secret key={credential.secret} value={credential.secret} />
              </dd>
            </div>
            {credential.notes && (
              <>
                <dt className="muted col-span-full">Notes</dt>
                <dd className="col-span-full whitespace-pre-wrap break-words">
                  {credential.notes}
                </dd>
              </>
            )}
          </dl>
        </div>
        <Modal
          title="Edit linked credential"
          trigger={
            <Button
              variant="outline"
              size="sm"
              aria-label={`Edit ${credential.kind} credential${credential.username ? ` for ${credential.username}` : ""}`}
            >
              Edit
            </Button>
          }
        >
          <div className="stack">
            <p className="muted text-sm">
              Changes apply everywhere this credential is linked.
            </p>
            <HostActionForm
              command={{ type: "save-linked-credential", credentialId: credential.id }}
              className="stack"
            >
              <input type="hidden" name="host_id" value={hostId} />
              <CredentialFields credential={credential} kinds={data.kinds ?? []} />
              <Button type="submit">Save credential</Button>
            </HostActionForm>
            <HostActionForm
              command={{ type: "delete-linked-credential-everywhere", credentialId: credential.id }}
            >
              <input type="hidden" name="host_id" value={hostId} />
              <Button type="submit" variant="destructive">
                Delete credential everywhere
              </Button>
            </HostActionForm>
          </div>
        </Modal>
      </div>
    </article>
  );
}

function NoteDetail({ note }: { note: Note }) {
  return (
    <article>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="break-words font-medium">{note.title}</h3>
          <p className="muted text-xs">
            Updated{" "}
            <time dateTime={note.updated_at}>{timestamp(note.updated_at)}</time>
          </p>
        </div>
        <Modal
          title="Edit note"
          protectChanges
          className="sm:max-w-5xl"
          trigger={
            <Button
              variant="outline"
              size="sm"
              aria-label={`Edit note ${note.title}`}
            >
              Edit
            </Button>
          }
        >
          <div className="stack">
            <HostActionForm command={{ type: "save-note", noteId: note.id }} className="stack" encType="application/x-www-form-urlencoded">
              <Field
                label="Title"
                name="title"
                defaultValue={note.title}
                required
              />
              <MarkdownEditor defaultValue={note.body_md} />
              <Button type="submit">Save note</Button>
            </HostActionForm>
            <HostActionForm
              command={{ type: "delete-note", noteId: note.id, label: note.title }}
            >
              <Button type="submit" variant="destructive">
                Delete note
              </Button>
            </HostActionForm>
          </div>
        </Modal>
      </div>
      <Suspense fallback={<p role="status" className="muted text-sm">Loading note…</p>}>
        <MarkdownView source={note.body_md} />
      </Suspense>
    </article>
  );
}

function ManageHost({ data }: { data: PageData }) {
  const host = data.host!;
  return (
    <Modal
      title="Manage host"
      trigger={<Button variant="outline">Manage host</Button>}
    >
      <div className="space-y-6">
        <dl className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
          <div>
            <dt className="muted">First observed</dt>
            <dd className="mono">
              <time dateTime={host.first_seen}>
                {timestamp(host.first_seen)}
              </time>
            </dd>
          </div>
          <div>
            <dt className="muted">Last observed</dt>
            <dd className="mono">
              <time dateTime={host.last_seen}>{timestamp(host.last_seen)}</time>
            </dd>
          </div>
        </dl>
        <HostActionForm command={{ type: "rename-host", hostId: host.id }}>
          <Field label="IP address" name="ip" defaultValue={host.ip} required />
          <div>
            <Button type="submit" variant="outline">
              Rename host
            </Button>
          </div>
        </HostActionForm>
        <section className="space-y-3 border-t pt-4">
          <h3 className="font-semibold">Hostnames</h3>
          <ul className="flex flex-wrap gap-2" aria-label="Linked hostnames">
            {(data.hostnames ?? []).map(([id, name]) => (
              <li
                key={id}
                className="flex items-center gap-2 rounded-md border py-1 pl-3 pr-1"
              >
                <span className="mono break-all text-sm">{name}</span>
                <HostActionForm
                  command={{ type: "hide-hostname", hostId: host.id, hostnameId: id, label: name }}
                >
                  <Button
                    type="submit"
                    variant="ghost"
                    size="sm"
                    aria-label={`Remove hostname ${name}`}
                  >
                    ×
                  </Button>
                </HostActionForm>
              </li>
            ))}
          </ul>
          {!data.hostnames?.length && (
            <p className="muted text-sm">No hostnames yet.</p>
          )}
          <HostActionForm
            command={{ type: "add-hostname", hostId: host.id }}
            className="flex flex-wrap items-end gap-3"
          >
            <Field
              label="New hostname"
              name="name"
              required
              placeholder="host.example.com"
            />
            <Button type="submit" variant="outline">
              Add hostname
            </Button>
          </HostActionForm>
        </section>
        <section className="space-y-3 border-t pt-4">
          <h3 className="font-semibold">Delete host</h3>
          <p className="text-sm">
            This permanently deletes this host, its services, notes, triage, and
            credential links. Credentials themselves are kept.
          </p>
          <HostActionForm
            command={{ type: "delete-host", hostId: host.id, label: host.ip }}
          >
            <div>
              <Button type="submit" variant="destructive">
                Permanently delete host
              </Button>
            </div>
          </HostActionForm>
        </section>
      </div>
    </Modal>
  );
}

function HostTriage({ data }: { data: PageData }) {
  return (
    <Modal
      title="Host triage"
      trigger={<Button variant="outline">Host triage</Button>}
    >
      <HostActionForm command={{ type: "save-host-triage" }}>
        <input type="hidden" name="host_id" value={data.host!.id} />
        <div className="form-grid">
          <SelectField
            label="Status"
            name="status"
            defaultValue={data.host_ann?.status ?? "new"}
            options={data.statuses ?? []}
          />
          <Field
            label="Tags"
            name="tags"
            defaultValue={data.host_ann?.tags.join(", ") ?? ""}
            placeholder="comma, separated"
          />
        </div>
        <div>
          <Button type="submit">Save host triage</Button>
        </div>
      </HostActionForm>
    </Modal>
  );
}

function AddService({ data }: { data: PageData }) {
  return (
    <Modal title="Add service" trigger={<Button>Add service</Button>}>
      <HostActionForm command={{ type: "create-or-update-service", hostId: data.host!.id }}>
        <ServiceContext data={data} />
        <div className="form-grid">
          <Field
            label="Port"
            name="port"
            type="number"
            min={0}
            max={65535}
            required
          />
          <Field label="Protocol" name="proto" defaultValue="tcp" required />
          <SelectField
            label="State"
            name="state"
            defaultValue="open"
            options={data.states ?? []}
          />
          <Field label="Service name" name="service_name" placeholder="ssh" />
          <Field label="Product" name="product" />
          <Field label="Version" name="version" />
        </div>
        <p className="muted text-sm">
          Manual values are kept across scans. Adding an existing port/protocol
          updates that service.
        </p>
        <div>
          <Button type="submit">Add service</Button>
        </div>
      </HostActionForm>
    </Modal>
  );
}

function AddNote({ hostId }: { hostId: number }) {
  return (
    <Modal title="Add note" trigger={<Button>Add note</Button>} protectChanges className="sm:max-w-5xl">
      <HostActionForm command={{ type: "create-note" }} encType="application/x-www-form-urlencoded">
        <input type="hidden" name="host_id" value={hostId} />
        <Field label="Title" name="title" required placeholder="Note title" />
        <MarkdownEditor />
        <div>
          <Button type="submit">Add note</Button>
        </div>
      </HostActionForm>
    </Modal>
  );
}

function ServiceFilters({ data }: { data: PageData }) {
  const filtered = Boolean(
    data.f_port || data.f_state || data.f_service || data.f_status,
  );
  const [disclosure, setDisclosure] = useState<"expanded" | "collapsed">(filtered ? "expanded" : "collapsed");
  const expanded = disclosure === "expanded";
  const appliedQuery = JSON.stringify([
    data.f_port, data.f_state, data.f_service, data.f_status,
    data.sort ?? "port", data.direction ?? "asc", data.per ?? "25",
  ]);
  return (
    <>
      <div className="host-service-toolbar">
        <p className="muted text-xs">
          {(data.services ?? []).length} shown · {data.svc_total ?? 0}{" "}
          {filtered ? "matching" : "total"} services
        </p>
        <Button
          variant="outline"
          size="sm"
          aria-expanded={expanded}
          aria-controls="host-service-filters"
          onClick={() => setDisclosure((current) => current === "expanded" ? "collapsed" : "expanded")}
        >
          <ListFilter />
          Filter and sort{filtered ? " · Filters active" : ""}
        </Button>
        <AddService data={data} />
      </div>
      <div
        id="host-service-filters"
        className="host-service-filters"
        hidden={!expanded}
      >
        <Filters key={appliedQuery}>
          <Field
            label="Port filter"
            name="f_port"
            type="search"
            defaultValue={data.f_port ?? ""}
            placeholder="Port contains…"
          />
          <SelectField
            label="State filter"
            name="f_state"
            defaultValue={data.f_state ?? ""}
            options={data.states ?? []}
            empty="All states"
          />
          <Field
            label="Service filter"
            name="f_service"
            type="search"
            defaultValue={data.f_service ?? ""}
            placeholder="Name, product, version…"
          />
          <SelectField
            label="Triage filter"
            name="f_status"
            defaultValue={data.f_status ?? ""}
            options={data.statuses ?? []}
            empty="All statuses"
          />
          <SelectField
            label="Sort by"
            name="sort"
            defaultValue={data.sort ?? "port"}
            options={[
              { value: "port", label: "Port" },
              { value: "state", label: "State" },
              { value: "service", label: "Service" },
              { value: "status", label: "Triage" },
            ]}
          />
          <SelectField
            label="Order"
            name="dir"
            defaultValue={data.direction ?? "asc"}
            options={[
              { value: "asc", label: "Ascending" },
              { value: "desc", label: "Descending" },
            ]}
          />
          <input type="hidden" name="per" value={data.per ?? "25"} />
          <input type="hidden" name="page" value="1" />
          <Button type="submit" variant="outline">
            <ListFilter />
            Apply
          </Button>
          <Button
            variant="outline"
            render={
              <ScopedLink href={`/hosts/${data.host!.id}?per=${encodeURIComponent(data.per ?? "25")}`} />
            }
          >
            <RotateCcw />
            Reset
          </Button>
        </Filters>
      </div>
    </>
  );
}

export function HostPage({ data }: { data: PageData }) {
  const [storedView, setView] = useState(() => initialHostView(data, sectionFromHash(location.hash)));
  const view = reconcileHostView(storedView, data);
  if (view !== storedView) setView(view);
  const send = (event: HostViewEvent) => setView((current) => transitionHostView(current, event, data));
  useEffect(() => {
    const sync = () => {
      const section = sectionFromHash(location.hash);
      if (location.hash !== `#${section}`) {
        history.replaceState(history.state, "", `${location.pathname}${location.search}#${section}`);
      }
      setView((current) => transitionHostView(current, { type: "section-changed", section }, data));
    };
    sync();
    window.addEventListener("hashchange", sync);
    window.addEventListener("popstate", sync);
    return () => {
      window.removeEventListener("hashchange", sync);
      window.removeEventListener("popstate", sync);
    };
  }, [data]);
  const host = data.host;
  if (!host)
    return (
      <Empty>
        Host not found. <ScopedLink href="/">Return to hosts</ScopedLink>.
      </Empty>
    );
  const services = data.services ?? [];
  const notes = data.host_notes ?? [];
  const credentials = data.host_credentials ?? [];
  const service = services.find((item) => item.service_id === view.serviceId);
  const note = notes.find((item) => item.id === view.noteId);
  const credential = credentials.find((item) => item.id === view.credentialId);
  const associatedCredentials = service
    ? credentials.filter((item) =>
        item.services.some((link) => link.service_id === service.service_id),
      )
    : [];
  const filtered = Boolean(
    data.f_port || data.f_state || data.f_service || data.f_status,
  );
  return (
    <div className="host-workbench-page" key={host.id}>
      <header className="space-y-2 border-b pb-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <ScopedLink href="/" className="muted text-xs hover:underline">
            ← Host inventory
          </ScopedLink>
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Network className="size-4 muted" aria-hidden="true" />
          <h1 className="sr-only">Host {host.ip}</h1>
          <span className="mono break-all text-[13px] font-semibold">
            {host.ip}
          </span>
          <Badge variant="secondary">{data.host_ann?.status ?? "new"}</Badge>
          {!!data.hostnames?.length && (
            <p className="mono break-all text-xs muted">
              {data.hostnames.map(([, name]) => name).join(" · ")}
            </p>
          )}
          {data.host_ann?.tags.map((tag) => (
            <Badge key={tag} variant="outline">
              {tag}
            </Badge>
          ))}
          <div className="actions ml-auto">
            <HostTriage data={data} />
            <ManageHost data={data} />
          </div>
        </div>
      </header>
        {data.host_timeline?.latest_change && (
          <p className="flex min-w-0 flex-none flex-wrap items-baseline gap-x-2 gap-y-1 text-xs">
            <span className="muted">Latest change</span>
            <span><TimelineTime entry={data.host_timeline.latest_change} /></span>
            <QueryLink href={timelineUrl(1, false)} className="min-w-0 break-words underline underline-offset-4">
              {timelineSummary(data.host_timeline.latest_change)} — View timeline
            </QueryLink>
          </p>
        )}
      <Tabs.Root
        value={view.section}
        onValueChange={(value) => {
          if (!isHostSection(value)) return;
          send({ type: "section-changed", section: value });
          location.hash = value;
        }}
        className="host-workbench-tabs"
      >
        <Tabs.List aria-label="Host workbench sections" className="host-tabs">
          <Tabs.Tab value="services">
            Services <span className="mono muted">{data.svc_total ?? 0}</span>
          </Tabs.Tab>
          <Tabs.Tab value="notes">
            Host notes <span className="mono muted">{notes.length}</span>
          </Tabs.Tab>
          <Tabs.Tab value="credentials">
            Credentials <span className="mono muted">{credentials.length}</span>
          </Tabs.Tab>
          <Tabs.Tab value="timeline">Timeline</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="timeline">
          <HostTimeline timeline={data.host_timeline} />
        </Tabs.Panel>
        <Tabs.Panel value="services">
          <ServiceFilters
            key={host.id}
            data={data}
          />
          <div className="host-inspector">
            <div className="host-item-list" aria-label="Select a service">
              {services.map((item) => (
                <button
                  key={item.service_id}
                  type="button"
                  aria-pressed={item.service_id === service?.service_id}
                  onClick={() => send({ type: "service-selected", id: item.service_id })}
                  className="host-item-choice host-service-choice"
                >
                  <span className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                    <strong className="mono">
                      {item.port}/{item.proto}
                    </strong>
                    {item.service_name && <span>{item.service_name}</span>}
                    <span className="muted text-xs">{item.state}</span>
                  </span>
                  {(item.product ||
                    item.version ||
                    item.annotation?.status) && (
                    <span className="mt-1 flex flex-wrap items-baseline gap-x-2 text-xs">
                      {(item.product || item.version) && (
                        <span className="mono muted">
                          {[item.product, item.version]
                            .filter(Boolean)
                            .join(" ")}
                        </span>
                      )}
                      {item.annotation?.status && (
                        <span>{item.annotation.status}</span>
                      )}
                    </span>
                  )}
                </button>
              ))}
            </div>
            <div className="host-item-detail" aria-live="polite">
              {service ? (
                <div className="space-y-3 text-[13px]" key={service.service_id}>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="mono text-base font-semibold">
                        {service.port}/{service.proto}
                      </h2>
                      {service.service_name && (
                        <span>{service.service_name}</span>
                      )}
                      <Badge variant="outline">{service.state}</Badge>
                      {service.annotation?.status && (
                        <Badge variant="secondary">
                          {service.annotation.status}
                        </Badge>
                      )}
                      {service.manual && (
                        <Badge variant="outline">Manual override</Badge>
                      )}
                    </div>
                    <ServiceDetail service={service} data={data} />
                  </div>
                  {(service.product ||
                    service.version ||
                    service.last_seen) && (
                    <dl className="flex flex-wrap gap-x-6 gap-y-2">
                      {(service.product || service.version) && (
                        <div>
                          <dt className="muted text-xs">Product / version</dt>
                          <dd className="mono break-words">
                            {[service.product, service.version]
                              .filter(Boolean)
                              .join(" ")}
                          </dd>
                        </div>
                      )}
                      {service.last_seen && (
                        <div>
                          <dt className="muted text-xs">Last observed</dt>
                          <dd className="mono">
                            {timestamp(service.last_seen)}
                          </dd>
                        </div>
                      )}
                    </dl>
                  )}
                  {!!service.annotation?.tags.length && (
                    <div className="flex flex-wrap gap-1">
                      {service.annotation.tags.map((tag) => (
                        <Badge key={tag} variant="outline">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                  {!!associatedCredentials.length && (
                    <section className="border-t pt-3">
                      <h3 className="mb-1 text-xs font-semibold">
                        Linked credentials
                      </h3>
                      {associatedCredentials.map((item) => (
                        <button
                          type="button"
                          key={item.id}
                          onClick={() => {
                            send({ type: "linked-credential-opened", id: item.id });
                            location.hash = "credentials";
                          }}
                          className="block break-all text-left text-sm underline underline-offset-4"
                        >
                          <span className="mono">
                            {item.username || "No username"}
                          </span>{" "}
                          · {item.kind}
                        </button>
                      ))}
                    </section>
                  )}
                </div>
              ) : (
                <Empty>
                  {filtered
                    ? "No services match these filters."
                    : "No services yet. Add one or ingest a scan."}
                </Empty>
              )}
            </div>
          </div>
          <Pager data={data} total={data.svc_total ?? 0} />
        </Tabs.Panel>
        <Tabs.Panel value="notes">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="muted text-sm">{notes.length} host notes</p>
            <AddNote hostId={host.id} />
          </div>
          <div className="host-inspector">
            <div className="host-item-list" aria-label="Select a host note">
              {notes.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  aria-pressed={item.id === note?.id}
                  onClick={() => send({ type: "note-selected", id: item.id })}
                  className="host-item-choice"
                >
                  <span className="block font-medium">{item.title}</span>
                  <span className="mono muted mt-2 block text-xs">
                    Updated {timestamp(item.updated_at)}
                  </span>
                </button>
              ))}
            </div>
            <div className="host-item-detail" aria-live="polite">
              {note ? (
                <NoteDetail key={note.id} note={note} />
              ) : (
                <Empty>
                  No host notes yet. Add a note to capture findings and next
                  steps.
                </Empty>
              )}
            </div>
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="credentials">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="muted text-sm">
              {credentials.length} linked credentials
            </p>
            <ScopedLink href="/credentials"
            className="text-sm font-medium underline underline-offset-4">
              Add credentials / manage links →
            </ScopedLink>
          </div>
          <div className="host-inspector">
            <div
              className="host-item-list"
              aria-label="Select a linked credential"
            >
              {credentials.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  aria-pressed={item.id === credential?.id}
                  onClick={() => send({ type: "credential-selected", id: item.id })}
                  className="host-item-choice"
                >
                  <span className="mono block font-medium">
                    {item.username || "No username"}
                  </span>
                  <span className="muted mt-2 block text-xs">
                    {item.kind} · Credential #{item.id}
                  </span>
                </button>
              ))}
            </div>
            <div className="host-item-detail" aria-live="polite">
              {credential ? (
                <CredentialDetail
                  key={credential.id}
                  credential={credential}
                  data={data}
                  hostId={host.id}
                />
              ) : (
                <Empty>
                  No credentials linked yet.{" "}
                  <ScopedLink href="/credentials" className="underline">
                    Add a credential and link it to this host or a service
                  </ScopedLink>
                  .
                </Empty>
              )}
              <p className="muted mt-4 text-xs">
                Links indicate association, not verified access.
              </p>
            </div>
          </div>
        </Tabs.Panel>
      </Tabs.Root>
    </div>
  );
}
