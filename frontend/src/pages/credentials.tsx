import { useEffect, useState } from "react";
import { Search, Unlink } from "lucide-react";
import { Secret } from "@/components/secret";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import {
  Empty,
  Field,
  Modal,
  MutationForm,
  PageHeader,
  SelectField,
} from "../common";
import type { PageData } from "../types";
import { CredentialCreateForm } from "./credential-create";

type Credential = NonNullable<PageData["credentials"]>[number];
type Host = NonNullable<PageData["hosts"]>[number];

function CredentialFields({
  credential,
  kinds,
}: {
  credential?: Credential;
  kinds: string[];
}) {
  return (
    <div className="form-grid">
      <SelectField
        label="Kind"
        name="kind"
        defaultValue={credential?.kind ?? "password"}
        options={kinds}
      />
      <Field
        label="Username"
        name="username"
        defaultValue={credential?.username}
        placeholder="admin"
      />
      <div className="col-span-full">
        <Field label="Secret" name="secret">
          <Textarea
            name="secret"
            defaultValue={credential?.secret}
            autoComplete="off"
            spellCheck={false}
            className="mono"
            rows={3}
            placeholder="Password, hash, private key, or token"
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Notes" name="notes">
          <Textarea
            name="notes"
            defaultValue={credential?.notes}
            rows={3}
            placeholder="Where and how this credential was found"
          />
        </Field>
      </div>
      <p className="muted col-span-full text-xs">
        Provide a username, a secret, or both. Credentials and their links are
        never changed by scan imports.
      </p>
    </div>
  );
}

function CredentialLinks({
  credential,
  hosts,
}: {
  credential: Credential;
  hosts: Host[];
}) {
  const availableHosts = hosts.filter(
    (host) => !credential.hosts.some((link) => link.host_id === host.id),
  );
  return (
    <div className="grid items-start gap-4 md:grid-cols-2">
      <div className="stack gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide">
          Linked hosts
        </h3>
        <div className="flex flex-wrap gap-2">
          {credential.hosts.map((host) => (
            <div
              key={host.host_id}
              className="actions rounded-md border px-2 py-1"
            >
              <a
                href={`/hosts/${host.host_id}`}
                className="mono text-sm underline underline-offset-4"
              >
                {host.ip}
              </a>
              <MutationForm
                action={`/credentials/${credential.id}/unlink/host/${host.host_id}`}
                confirm={`Unlink host ${host.ip} from this credential?`}
              >
                <Button
                  type="submit"
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Unlink host ${host.ip}`}
                  title={`Unlink host ${host.ip}`}
                >
                  <Unlink aria-hidden="true" />
                </Button>
              </MutationForm>
            </div>
          ))}
          {!credential.hosts.length && (
            <span className="muted text-sm">No linked hosts.</span>
          )}
        </div>
        {availableHosts.length > 0 && (
          <MutationForm
            action={`/credentials/${credential.id}/link/host`}
            className="flex flex-wrap items-end gap-2"
          >
            <SelectField
              label="Link host"
              name="host_id"
              empty="Select a host…"
              options={availableHosts.map((host) => ({
                value: String(host.id),
                label: host.ip,
              }))}
            />
            <Button type="submit" variant="outline" size="sm">
              Link host
            </Button>
          </MutationForm>
        )}
      </div>
      <div className="stack gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide">
          Linked services
        </h3>
        <div className="flex flex-wrap gap-2">
          {credential.services.map((service) => (
            <div
              key={service.service_id}
              className="actions rounded-md border px-2 py-1"
            >
              <a
                href={`/hosts/${service.host_id}`}
                className="mono text-sm underline underline-offset-4"
              >
                {service.ip}:{service.port}/{service.proto}
                {service.name ? ` ${service.name}` : ""}
              </a>
              <MutationForm
                action={`/credentials/${credential.id}/unlink/service/${service.service_id}`}
                confirm={`Unlink ${service.ip}:${service.port}/${service.proto} from this credential?`}
              >
                <Button
                  type="submit"
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Unlink service ${service.ip}:${service.port}/${service.proto}`}
                  title={`Unlink service ${service.ip}:${service.port}/${service.proto}`}
                >
                  <Unlink aria-hidden="true" />
                </Button>
              </MutationForm>
            </div>
          ))}
          {!credential.services.length && (
            <span className="muted text-sm">No linked services.</span>
          )}
        </div>
        {!credential.hosts.length ? (
          <p className="muted text-xs">Link a host to pick its services.</p>
        ) : credential.pickable_services.length > 0 ? (
          <MutationForm
            action={`/credentials/${credential.id}/link/service`}
            className="flex flex-wrap items-end gap-2"
          >
            <SelectField
              label="Link service"
              name="service_id"
              empty="Select a service…"
              options={credential.pickable_services.map((service) => ({
                value: String(service.service_id),
                label: `${service.ip}:${service.port}/${service.proto}${service.name ? ` ${service.name}` : ""}`,
              }))}
            />
            <Button type="submit" variant="outline" size="sm">
              Link service
            </Button>
          </MutationForm>
        ) : (
          <p className="muted text-xs">
            No additional services available on linked hosts.
          </p>
        )}
      </div>
    </div>
  );
}

function CredentialDetail({
  credential,
  kinds,
  hosts,
}: {
  credential: Credential;
  kinds: string[];
  hosts: Host[];
}) {
  return (
    <article className="credential-detail" aria-labelledby="credential-title">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b pb-4">
        <div className="min-w-0">
          <p className="credential-label mb-2">Credential detail</p>
          <h2 id="credential-title" className="mono break-all text-lg font-semibold">
            {credential.username || "No username"}
          </h2>
        </div>
        <div className="actions">
          <Badge variant="secondary">{credential.kind}</Badge>
          <Modal
            title="Edit credential"
            trigger={<Button type="button" variant="outline" size="sm">Edit credential</Button>}
          >
            <MutationForm action={`/credentials/${credential.id}/edit`}>
              <CredentialFields credential={credential} kinds={kinds} />
              <div className="actions mt-4 justify-end">
                <Button type="submit">Save credential</Button>
              </div>
            </MutationForm>
          </Modal>
        </div>
      </header>
      <section className="stack gap-2" aria-labelledby="credential-secret">
        <h3 id="credential-secret" className="credential-label">Secret</h3>
        <div className="rounded-md border bg-muted/30 p-3">
          <Secret key={credential.secret} value={credential.secret} />
        </div>
      </section>
      <section className="stack gap-3" aria-labelledby="credential-scope">
        <h3 id="credential-scope" className="credential-label">Scope</h3>
        <CredentialLinks credential={credential} hosts={hosts} />
        <p className="muted text-xs">
          Associations only; links do not establish that access was verified.
        </p>
      </section>
      <section aria-labelledby="credential-notes">
        <h3 id="credential-notes" className="credential-label mb-2">Discovery notes</h3>
        <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
          {credential.notes || <span className="muted">No discovery notes recorded.</span>}
        </p>
      </section>
      <footer className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
        <p className="muted text-xs">Added <time className="mono">{credential.created_at}</time></p>
        <MutationForm
          action={`/credentials/${credential.id}/delete`}
          confirm={`Delete credential ${credential.username || "(no username)"} and all its links? This cannot be undone.`}
        >
          <Button type="submit" variant="ghost" size="sm" className="text-destructive">
            Delete credential
          </Button>
        </MutationForm>
      </footer>
    </article>
  );
}

export function CredentialsPage({ data }: { data: PageData }) {
  const [url, setUrl] = useState(() => location.href);
  useEffect(() => {
    const sync = () => setUrl(location.href);
    window.addEventListener("popstate", sync);
    window.addEventListener("hashchange", sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("hashchange", sync);
    };
  }, []);
  const currentUrl = new URL(url);
  const query = currentUrl.searchParams.get("filter") ?? "";
  const kind = currentUrl.searchParams.get("kind") ?? "";
  const scope = currentUrl.searchParams.get("scope") ?? "";
  const all = data.credentials ?? [];
  const kinds = data.kinds ?? [];
  const hosts = data.hosts ?? [];
  const credentials = all.filter((credential) => {
    const linked = Boolean(credential.hosts.length || credential.services.length);
    const text = [
      credential.username, credential.kind, credential.notes,
      ...credential.hosts.map((host) => host.ip),
      ...credential.services.map((service) =>
        `${service.ip}:${service.port}/${service.proto} ${service.name ?? ""}`),
    ].join(" ").toLowerCase();
    return (!kind || credential.kind === kind)
      && (!scope || (scope === "linked" ? linked : !linked))
      && text.includes(query.toLowerCase());
  });
  const selected = credentials.find((credential) =>
    currentUrl.hash === `#credential-${credential.id}`) ?? credentials[0];
  function filter(values: Record<string, string>) {
    const next = new URL(location.href);
    for (const [key, value] of Object.entries(values)) {
      if (value) next.searchParams.set(key, value);
      else next.searchParams.delete(key);
    }
    next.hash = "";
    history.replaceState(null, "", next);
    setUrl(next.href);
  }
  return (
    <div className="credential-workbench-page">
      <PageHeader
        title="Credentials"
        description="Find an identity. Inspect its secret, discovery notes, and target associations."
      >
        <Modal title="Add credential" trigger={<Button type="button">Add credential</Button>}>
          <CredentialCreateForm kinds={kinds} hosts={hosts} />
        </Modal>
      </PageHeader>
      <div className="credential-filters" role="search" aria-label="Filter credentials">
        <label className="relative min-w-0">
          <Search size={15} className="pointer-events-none absolute top-2.5 left-3 text-muted-foreground" aria-hidden="true" />
          <span className="sr-only">Filter credentials</span>
          <Input type="search" className="pl-9" placeholder="Filter username, notes, IP or service…"
            value={query} onChange={(event) => filter({ filter: event.target.value })} />
        </label>
        <NativeSelect aria-label="Credential kind" value={kind}
          onChange={(event) => filter({ kind: event.target.value })}>
          <option value="">All kinds</option>
          {kinds.map((value) => <option key={value} value={value}>{value}</option>)}
        </NativeSelect>
        <NativeSelect aria-label="Credential scope" value={scope}
          onChange={(event) => filter({ scope: event.target.value })}>
          <option value="">All associations</option>
          <option value="linked">Linked</option>
          <option value="unlinked">Unlinked</option>
        </NativeSelect>
        <span className="muted text-xs" role="status">{credentials.length} of {all.length} credentials</span>
      </div>
      {selected ? (
        <div className="credential-workbench rounded-lg border bg-card">
          <section className="credential-list" aria-label="Credential list">
            <h2 className="credential-label border-b bg-muted/40 px-4 py-3">Identity / scope</h2>
            {credentials.map((credential) => (
              <a key={credential.id} href={`?${currentUrl.searchParams}#credential-${credential.id}`}
                aria-current={credential.id === selected.id ? "true" : undefined}
                className="credential-choice"
                onClick={(event) => {
                  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
                  event.preventDefault();
                  const next = new URL(location.href);
                  next.hash = `credential-${credential.id}`;
                  history.pushState(null, "", next);
                  setUrl(next.href);
                }}>
                <span className="flex items-center justify-between gap-2">
                  <span className="mono truncate font-semibold">{credential.username || "No username"}</span>
                  <Badge variant="outline">{credential.kind}</Badge>
                </span>
                <span className="muted mt-2 block text-xs">
                  {credential.hosts.length} hosts · {credential.services.length} services
                  {!credential.hosts.length && !credential.services.length ? " · Unlinked" : ""}
                </span>
                <span className="muted mt-2 block truncate text-xs">{credential.notes || "No discovery notes"}</span>
              </a>
            ))}
          </section>
          <CredentialDetail key={selected.id} credential={selected} kinds={kinds} hosts={hosts} />
        </div>
      ) : (
        <Empty>
          {all.length ? <>
            <p>No credentials match these filters.</p>
            <Button type="button" variant="outline" className="mt-3"
              onClick={() => filter({ filter: "", kind: "", scope: "" })}>Clear filters</Button>
          </> : "No credentials yet. Add one as you find it."}
        </Empty>
      )}
    </div>
  );
}
