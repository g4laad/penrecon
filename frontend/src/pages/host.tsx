import { useEffect, useState } from "react";
import { Tabs } from "@base-ui/react/tabs";
import { ListFilter, Network, RotateCcw } from "lucide-react";
import { Secret } from "@/components/secret";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
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

function timestamp(value: string) {
  return value.replace("T", " ").slice(0, 16);
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
        <MutationForm
          action={`/services/${service.service_id}/edit`}
          className="stack"
        >
          <ServiceContext data={data} />
          <div className="form-grid">
            <SelectField
              label="State"
              name="state"
              defaultValue={
                (data.states ?? []).includes(service.state) ? service.state : ""
              }
              options={data.states ?? []}
              empty="Use latest scan value"
            />
            <Field
              label="Service name"
              name="service_name"
              defaultValue={service.service_name ?? ""}
            />
            <Field
              label="Product"
              name="product"
              defaultValue={service.product ?? ""}
            />
            <Field
              label="Version"
              name="version"
              defaultValue={service.version ?? ""}
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
        </MutationForm>
        <div className="flex flex-wrap gap-3 border-t pt-4">
          <MutationForm
            action={`/services/${service.service_id}/edit`}
            confirm="Reset all manual service values to the latest scan? Triage status and tags will be kept."
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
          </MutationForm>
          <MutationForm
            action={`/services/${service.service_id}/delete`}
            confirm={`Delete ${service.port}/${service.proto} and its associated data? A future scan that sees it will re-add it.`}
          >
            <ServiceContext data={data} />
            <Button type="submit" variant="destructive">
              Delete service
            </Button>
          </MutationForm>
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
                <Secret value={credential.secret} />
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
            <MutationForm
              action={`/credentials/${credential.id}/edit`}
              className="stack"
            >
              <input type="hidden" name="host_id" value={hostId} />
              <SelectField
                label="Kind"
                name="kind"
                defaultValue={credential.kind}
                options={data.kinds ?? []}
              />
              <Field
                label="Username"
                name="username"
                defaultValue={credential.username}
              />
              <Field
                label="Secret"
                name="secret"
                defaultValue={credential.secret}
              />
              <Field
                label="Notes"
                name="notes"
                defaultValue={credential.notes}
              />
              <Button type="submit">Save credential</Button>
            </MutationForm>
            <MutationForm
              action={`/credentials/${credential.id}/delete`}
              confirm="Delete this credential and all its host and service links? This cannot be undone."
            >
              <input type="hidden" name="host_id" value={hostId} />
              <Button type="submit" variant="destructive">
                Delete credential everywhere
              </Button>
            </MutationForm>
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
            <MutationForm action={`/notes/${note.id}/edit`} className="stack">
              <Field
                label="Title"
                name="title"
                defaultValue={note.title}
                required
              />
              <Field label="Note (Markdown)" name="body_md">
                <Textarea
                  name="body_md"
                  aria-label="Note (Markdown)"
                  defaultValue={note.body_md}
                  rows={10}
                />
              </Field>
              <Button type="submit">Save note</Button>
            </MutationForm>
            <MutationForm
              action={`/notes/${note.id}/delete`}
              confirm={`Delete note “${note.title}”? This cannot be undone.`}
            >
              <Button type="submit" variant="destructive">
                Delete note
              </Button>
            </MutationForm>
          </div>
        </Modal>
      </div>
      <p className="whitespace-pre-wrap break-words text-sm">
        {note.body_md || <span className="muted">No note body.</span>}
      </p>
    </article>
  );
}

function ManageHost({ data }: { data: PageData }) {
  const { navigate } = usePage();
  const host = data.host!;
  const path = `/hosts/${host.id}`;
  return (
    <Modal
      title="Manage host"
      trigger={<Button variant="outline">Manage host</Button>}
    >
      <div className="space-y-6">
        <MutationForm action={`${path}/edit`}>
          <Field label="IP address" name="ip" defaultValue={host.ip} required />
          <div>
            <Button type="submit" variant="outline">
              Rename host
            </Button>
          </div>
        </MutationForm>
        <section className="space-y-3 border-t pt-4">
          <h3 className="font-semibold">Hostnames</h3>
          <ul className="flex flex-wrap gap-2" aria-label="Linked hostnames">
            {(data.hostnames ?? []).map(([id, name]) => (
              <li
                key={id}
                className="flex items-center gap-2 rounded-md border py-1 pl-3 pr-1"
              >
                <span className="mono break-all text-sm">{name}</span>
                <MutationForm
                  action={`${path}/hostnames/${id}/delete`}
                  confirm={`Remove hostname ${name} from this host? It will stay hidden on future scans.`}
                >
                  <Button
                    type="submit"
                    variant="ghost"
                    size="sm"
                    aria-label={`Remove hostname ${name}`}
                  >
                    ×
                  </Button>
                </MutationForm>
              </li>
            ))}
          </ul>
          {!data.hostnames?.length && (
            <p className="muted text-sm">No hostnames yet.</p>
          )}
          <MutationForm
            action={`${path}/hostnames`}
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
          </MutationForm>
        </section>
        <section className="space-y-3 border-t pt-4">
          <h3 className="font-semibold">Delete host</h3>
          <p className="text-sm">
            This permanently deletes this host, its services, notes, triage, and
            credential links. Credentials themselves are kept.
          </p>
          <MutationForm
            action={`${path}/delete`}
            confirm={`Permanently delete host ${host.ip} and all its services and notes? This cannot be undone.`}
            onSuccess={() => navigate("/")}
          >
            <div>
              <Button type="submit" variant="destructive">
                Permanently delete host
              </Button>
            </div>
          </MutationForm>
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
      <MutationForm action="/annotation">
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
      </MutationForm>
    </Modal>
  );
}

function AddService({ data }: { data: PageData }) {
  return (
    <Modal title="Add service" trigger={<Button>Add service</Button>}>
      <MutationForm action={`/hosts/${data.host!.id}/services`}>
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
      </MutationForm>
    </Modal>
  );
}

function AddNote({ hostId }: { hostId: number }) {
  return (
    <Modal title="Add note" trigger={<Button>Add note</Button>}>
      <MutationForm action="/notes">
        <input type="hidden" name="host_id" value={hostId} />
        <Field label="Title" name="title" required placeholder="Note title" />
        <Field label="Note (Markdown)" name="body_md">
          <Textarea
            name="body_md"
            aria-label="Note (Markdown)"
            rows={8}
            placeholder="Findings, next steps…"
          />
        </Field>
        <div>
          <Button type="submit">Add note</Button>
        </div>
      </MutationForm>
    </Modal>
  );
}

function ServiceFilters({ data }: { data: PageData }) {
  const filtered = Boolean(
    data.f_port || data.f_state || data.f_service || data.f_status,
  );
  return (
    <details className="host-service-filters" open={filtered || undefined}>
      <summary className="cursor-pointer text-sm font-medium">
        Filter and sort services{filtered ? " · Filters active" : ""}
      </summary>
      <div className="pt-4">
        <Filters>
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
          <Button type="submit" variant="outline">
            <ListFilter />
            Apply
          </Button>
          <Button
            variant="outline"
            render={
              <a
                href={`/hosts/${data.host!.id}?per=${encodeURIComponent(data.per ?? "25")}`}
              />
            }
          >
            <RotateCcw />
            Reset
          </Button>
        </Filters>
      </div>
    </details>
  );
}

type HostSection = "services" | "notes" | "credentials";
function currentSection(): HostSection {
  const hash = location.hash.slice(1);
  return hash === "notes" || hash === "credentials" ? hash : "services";
}

export function HostPage({ data }: { data: PageData }) {
  const [section, setSection] = useState<HostSection>(currentSection);
  const [serviceId, setServiceId] = useState<number>();
  const [noteId, setNoteId] = useState<number>();
  const [credentialId, setCredentialId] = useState<number>();
  useEffect(() => {
    const sync = () => setSection(currentSection());
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  const host = data.host;
  if (!host)
    return (
      <Empty>
        Host not found. <a href="/">Return to hosts</a>.
      </Empty>
    );
  const services = data.services ?? [];
  const notes = data.host_notes ?? [];
  const credentials = data.host_credentials ?? [];
  const service =
    services.find((item) => item.service_id === serviceId) ?? services[0];
  const note = notes.find((item) => item.id === noteId) ?? notes[0];
  const credential =
    credentials.find((item) => item.id === credentialId) ?? credentials[0];
  const associatedCredentials = service
    ? credentials.filter((item) =>
        item.services.some((link) => link.service_id === service.service_id),
      )
    : [];
  const filtered = Boolean(
    data.f_port || data.f_state || data.f_service || data.f_status,
  );
  return (
    <div className="host-workbench-page">
      <header className="space-y-4 border-b pb-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <a href="/" className="muted text-sm hover:underline">
            ← Host inventory
          </a>
          <div className="actions">
            <HostTriage data={data} />
            <ManageHost data={data} />
          </div>
        </div>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <Network className="size-5 muted" aria-hidden="true" />
              <h1 className="mono break-all text-2xl font-semibold tracking-tight">
                {host.ip}
              </h1>
              <Badge variant="secondary">
                {data.host_ann?.status ?? "new"}
              </Badge>
            </div>
            <p className="mono break-all text-sm muted">
              {data.hostnames?.map(([, name]) => name).join(" · ") ||
                "No linked hostnames"}
            </p>
            {!!data.host_ann?.tags.length && (
              <div className="flex flex-wrap gap-1">
                {data.host_ann.tags.map((tag) => (
                  <Badge key={tag} variant="outline">
                    {tag}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <dl className="flex flex-wrap gap-x-8 gap-y-2 text-xs">
            <div>
              <dt className="muted mb-1">First observed</dt>
              <dd className="mono">
                <time dateTime={host.first_seen}>
                  {timestamp(host.first_seen)}
                </time>
              </dd>
            </div>
            <div>
              <dt className="muted mb-1">Last observed</dt>
              <dd className="mono">
                <time dateTime={host.last_seen}>
                  {timestamp(host.last_seen)}
                </time>
              </dd>
            </div>
          </dl>
        </div>
      </header>
      <Tabs.Root
        value={section}
        onValueChange={(value) => {
          const next = value as HostSection;
          setSection(next);
          location.hash = next;
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
        </Tabs.List>
        <Tabs.Panel value="services">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="muted text-sm">
              {services.length} shown · {data.svc_total ?? 0}{" "}
              {filtered ? "matching" : "total"} services
            </p>
            <AddService data={data} />
          </div>
          <ServiceFilters data={data} />
          <div className="host-inspector">
            <div className="host-item-list" aria-label="Select a service">
              {services.map((item) => (
                <button
                  key={item.service_id}
                  type="button"
                  aria-pressed={item.service_id === service?.service_id}
                  onClick={() => setServiceId(item.service_id)}
                  className="host-item-choice"
                >
                  <span className="flex items-center justify-between gap-2">
                    <strong className="mono">
                      {item.port}/{item.proto}
                    </strong>
                    <span className="muted text-xs">{item.state}</span>
                  </span>
                  <span className="mt-2 block font-medium">
                    {item.service_name || "Unidentified service"}
                  </span>
                  <span className="muted mt-1 block text-xs">
                    {item.annotation?.status ?? "No triage recorded"}
                  </span>
                </button>
              ))}
            </div>
            <div className="host-item-detail" aria-live="polite">
              {service ? (
                <div className="space-y-5" key={service.service_id}>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="muted mb-2 text-xs">Selected service</p>
                      <h2 className="mono text-xl font-semibold">
                        {service.port}/{service.proto}
                      </h2>
                      <p className="mt-1 font-medium">
                        {service.service_name || "Unidentified service"}
                      </p>
                    </div>
                    <ServiceDetail service={service} data={data} />
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant="outline">{service.state}</Badge>
                    <Badge variant="secondary">
                      {service.annotation?.status ?? "No triage recorded"}
                    </Badge>
                    {service.manual && (
                      <Badge variant="outline">Manual override</Badge>
                    )}
                  </div>
                  <dl className="space-y-4 text-sm">
                    <div>
                      <dt className="muted text-xs">Product / version</dt>
                      <dd className="mono mt-1 break-words">
                        {[service.product, service.version]
                          .filter(Boolean)
                          .join(" ") || "Not identified"}
                      </dd>
                    </div>
                    <div>
                      <dt className="muted text-xs">Last observed</dt>
                      <dd className="mono mt-1">
                        {service.last_seen
                          ? timestamp(service.last_seen)
                          : "Not scanned"}
                      </dd>
                    </div>
                  </dl>
                  {!!service.annotation?.tags.length && (
                    <div className="flex flex-wrap gap-1">
                      {service.annotation.tags.map((tag) => (
                        <Badge key={tag} variant="outline">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  )}
                  <section className="border-t pt-4">
                    <h3 className="mb-2 text-xs font-semibold">
                      Credentials associated with this service
                    </h3>
                    {associatedCredentials.map((item) => (
                      <button
                        type="button"
                        key={item.id}
                        onClick={() => {
                          setCredentialId(item.id);
                          setSection("credentials");
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
                    {!associatedCredentials.length && (
                      <p className="muted text-sm">
                        No direct service links. Host-wide credentials are in
                        the Credentials tab.
                      </p>
                    )}
                    <p className="muted mt-2 text-xs">
                      Links indicate association, not verified access.
                    </p>
                  </section>
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
                  onClick={() => setNoteId(item.id)}
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
            <a
              href="/credentials"
              className="text-sm font-medium underline underline-offset-4"
            >
              Add credentials / manage links →
            </a>
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
                  onClick={() => setCredentialId(item.id)}
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
                  key={`${credential.id}-${credential.secret}`}
                  credential={credential}
                  data={data}
                  hostId={host.id}
                />
              ) : (
                <Empty>
                  No credentials linked yet.{" "}
                  <a href="/credentials" className="underline">
                    Add a credential and link it to this host or a service
                  </a>
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
