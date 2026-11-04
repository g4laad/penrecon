import { Secret } from "@/components/secret";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Empty,
  Field,
  Filters,
  Modal,
  MutationForm,
  PageHeader,
  Pager,
  Section,
  SelectField,
  SortLink,
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
          Details
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
    <article className="rounded-md border p-4">
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
    <article className="rounded-md border p-4">
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

export function HostPage({ data }: { data: PageData }) {
  const { navigate } = usePage();
  const host = data.host;
  if (!host)
    return (
      <Empty>
        Host not found. <a href="/">Return to hosts</a>.
      </Empty>
    );
  const services = data.services ?? [];
  const credentials = data.host_credentials ?? [];
  const notes = data.host_notes ?? [];
  const filtered = Boolean(
    data.f_port || data.f_state || data.f_service || data.f_status,
  );
  const path = `/hosts/${host.id}`;
  const sortState = (column: string): "ascending" | "descending" | "none" =>
    data.sort === column
      ? data.direction === "desc"
        ? "descending"
        : "ascending"
      : "none";

  return (
    <div className="stack">
      <a href="/" className="text-sm underline underline-offset-4">
        ← Hosts
      </a>
      <PageHeader
        title={host.ip}
        description="Host detail, evidence, and triage"
      >
        {data.host_ann && (
          <Badge variant="secondary">{data.host_ann.status}</Badge>
        )}
        <Modal
          title="Rename host IP"
          trigger={<Button variant="outline">Rename IP</Button>}
        >
          <MutationForm action={`${path}/edit`} className="stack">
            <Field
              label="IP address"
              name="ip"
              defaultValue={host.ip}
              required
            />
            <Button type="submit">Rename host</Button>
          </MutationForm>
        </Modal>
        <Modal
          title={`Delete host ${host.ip}?`}
          trigger={<Button variant="destructive">Delete host</Button>}
        >
          <div className="stack">
            <p className="text-sm">
              This permanently deletes this host, its services, notes, triage,
              and credential links. Credentials themselves are kept.
            </p>
            <MutationForm
              action={`${path}/delete`}
              confirm={`Permanently delete host ${host.ip} and all its services and notes? This cannot be undone.`}
              onSuccess={() => navigate("/")}
            >
              <Button type="submit" variant="destructive">
                Permanently delete host
              </Button>
            </MutationForm>
          </div>
        </Modal>
      </PageHeader>

      <dl className="flex flex-wrap gap-x-10 gap-y-3 rounded-md border bg-muted/30 px-4 py-3 text-sm">
        <div>
          <dt className="muted text-xs">First seen</dt>
          <dd className="mono">
            <time dateTime={host.first_seen}>{timestamp(host.first_seen)}</time>
          </dd>
        </div>
        <div>
          <dt className="muted text-xs">Last seen</dt>
          <dd className="mono">
            <time dateTime={host.last_seen}>{timestamp(host.last_seen)}</time>
          </dd>
        </div>
      </dl>

      <Section title="Hostnames">
        <div className="stack">
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
        </div>
      </Section>

      <nav
        aria-label="On this host"
        className="flex flex-wrap gap-x-6 gap-y-2 border-b pb-3 text-sm font-medium"
      >
        <a href="#services" className="underline-offset-4 hover:underline">
          Services ({data.svc_total ?? 0})
        </a>
        <a href="#credentials" className="underline-offset-4 hover:underline">
          Credentials ({credentials.length})
        </a>
        <a href="#notes" className="underline-offset-4 hover:underline">
          Notes ({notes.length})
        </a>
        <a href="#triage" className="underline-offset-4 hover:underline">
          Triage
        </a>
      </nav>

      <Section
        id="services"
        title={`Services (${data.svc_total ?? 0})`}
        action={
          <Modal title="Add service" trigger={<Button>Add service</Button>}>
            <MutationForm action={`${path}/services`} className="stack">
              <ServiceContext data={data} />
              <div className="form-grid">
                <Field label="Port" name="port">
                  <Input
                    type="number"
                    name="port"
                    aria-label="Port"
                    min={0}
                    max={65535}
                    required
                  />
                </Field>
                <Field
                  label="Protocol"
                  name="proto"
                  defaultValue="tcp"
                  required
                />
                <SelectField
                  label="State"
                  name="state"
                  defaultValue="open"
                  options={data.states ?? []}
                />
                <Field
                  label="Service name"
                  name="service_name"
                  placeholder="ssh"
                />
                <Field label="Product" name="product" />
                <Field label="Version" name="version" />
              </div>
              <p className="muted text-sm">
                Manual values are kept across scans. Adding an existing
                port/protocol updates that service.
              </p>
              <Button type="submit">Add service</Button>
            </MutationForm>
          </Modal>
        }
      >
        <div className="stack">
          <Filters>
            <input type="hidden" name="sort" value={data.sort ?? "port"} />
            <input type="hidden" name="dir" value={data.direction ?? "asc"} />
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
              label="Rows per page"
              name="per"
              defaultValue={data.per ?? "25"}
              options={["10", "25", "50", "all"]}
            />
            <Button type="submit" variant="outline">
              Apply filters
            </Button>
            {filtered && (
              <a
                className="self-end py-2 text-sm underline underline-offset-4"
                href={`${path}?per=${encodeURIComponent(data.per ?? "25")}`}
              >
                Clear filters
              </a>
            )}
          </Filters>
          <Table className="data-table">
            <TableHeader>
              <TableRow>
                <TableHead aria-sort={sortState("port")}>
                  <SortLink column="port">Port</SortLink>
                </TableHead>
                <TableHead aria-sort={sortState("state")}>
                  <SortLink column="state">State</SortLink>
                </TableHead>
                <TableHead aria-sort={sortState("service")}>
                  <SortLink column="service">
                    Service / product / version
                  </SortLink>
                </TableHead>
                <TableHead aria-sort={sortState("status")}>
                  <SortLink column="status">Triage</SortLink>
                </TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((service) => (
                <TableRow key={service.service_id}>
                  <TableCell className="mono whitespace-nowrap">
                    {service.port}/{service.proto}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{service.state}</Badge>
                  </TableCell>
                  <TableCell className="min-w-48 whitespace-normal">
                    <div className="space-y-1">
                      <p className="font-medium">
                        {service.service_name || "—"}
                      </p>
                      {(service.product || service.version) && (
                        <p className="mono muted text-xs">
                          {[service.product, service.version]
                            .filter(Boolean)
                            .join(" ")}
                        </p>
                      )}
                      <div className="flex flex-wrap gap-1">
                        {service.manual && (
                          <Badge variant="secondary">Manual</Badge>
                        )}
                        {service.annotation?.tags.map((tag) => (
                          <Badge key={tag} variant="outline">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    {service.annotation ? (
                      <Badge variant="secondary">
                        {service.annotation.status}
                      </Badge>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </TableCell>
                  <TableCell className="mono whitespace-nowrap text-xs">
                    {service.last_seen || (
                      <span className="muted">Not scanned</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <ServiceDetail service={service} data={data} />
                  </TableCell>
                </TableRow>
              ))}
              {!services.length && (
                <TableRow>
                  <TableCell colSpan={6}>
                    <Empty>
                      {filtered
                        ? "No services match these filters."
                        : "No services yet. Add one or ingest a scan."}
                    </Empty>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <Pager
            data={{
              page: data.page ?? 1,
              pages: data.pages ?? 1,
              per: data.per ?? "25",
            }}
            total={data.svc_total ?? 0}
          />
        </div>
      </Section>

      <Section
        id="credentials"
        title={`Credentials (${credentials.length})`}
        action={
          <a
            href="/credentials"
            className="text-sm font-medium underline underline-offset-4"
          >
            Add credentials / manage links →
          </a>
        }
      >
        <div className="stack">
          {credentials.map((credential) => (
            <CredentialDetail
              key={credential.id}
              credential={credential}
              data={data}
              hostId={host.id}
            />
          ))}
          {!credentials.length && (
            <Empty>
              No credentials linked yet.{" "}
              <a href="/credentials" className="underline">
                Add a credential and link it to this host or a service
              </a>
              .
            </Empty>
          )}
        </div>
      </Section>

      <Section
        id="notes"
        title={`Notes (${notes.length})`}
        action={
          <Modal title="Add note" trigger={<Button>Add note</Button>}>
            <MutationForm action="/notes" className="stack">
              <input type="hidden" name="host_id" value={host.id} />
              <Field
                label="Title"
                name="title"
                required
                placeholder="Note title"
              />
              <Field label="Note (Markdown)" name="body_md">
                <Textarea
                  name="body_md"
                  aria-label="Note (Markdown)"
                  rows={8}
                  placeholder="Findings, next steps…"
                />
              </Field>
              <Button type="submit">Add note</Button>
            </MutationForm>
          </Modal>
        }
      >
        <div className="stack">
          {notes.map((note) => (
            <NoteDetail key={note.id} note={note} />
          ))}
          {!notes.length && <Empty>No notes yet.</Empty>}
        </div>
      </Section>

      <Section id="triage" title="Host triage">
        <MutationForm action="/annotation" className="stack">
          <input type="hidden" name="host_id" value={host.id} />
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
          <div className="actions">
            <Button type="submit">Save host triage</Button>
          </div>
        </MutationForm>
      </Section>
    </div>
  );
}
