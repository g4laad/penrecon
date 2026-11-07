import { ScopedLink } from "../common";
import { useEffect, useState } from "react";
import { Search, Unlink } from "lucide-react";
import { Secret } from "@/components/secret";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { CredentialFields } from "@/components/credential-fields";
import {
  Empty,
  Field,
  Modal,
  MutationForm,
  PageHeader,
} from "../common";
import type { PageData } from "../types";
import { CredentialCreateForm } from "./credential-create";
import { credentialDraftValidity, resolveCredentialScope, resolveCredentialSelection } from "./credential-workflow";
import { useHostOptions, type HostOptions } from "./credential-host-options";

type Credential = NonNullable<PageData["credentials"]>[number];

type AssociationPicker =
  | { status: "available"; options: { value: string; label: string }[] }
  | { status: "blocked"; message: string };

function LinkAssociationForm({ credentialId, target, picker }: {
  credentialId: number;
  target: "host" | "service";
  picker: AssociationPicker;
}) {
  const [selected, setSelected] = useState("");
  if (picker.status === "blocked") return <p className="muted text-xs">{picker.message}</p>;
  const resolution = !selected ? "unselected" : picker.options.some((option) => option.value === selected) ? "selected" : "unavailable";
  const label = target === "host" ? "Link host" : "Link service";
  return <MutationForm action={`/credentials/${credentialId}/link/${target}`} className="flex flex-wrap items-end gap-2" canSubmit={resolution === "selected"}>
    <Field label={label}>
      <NativeSelect name={`${target}_id`} value={selected} required onChange={(event) => setSelected(event.target.value)}>
        <option value="">Select a {target}…</option>
        {resolution === "unavailable" && <option value={selected} disabled>Selected {target} is no longer available</option>}
        {picker.options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </NativeSelect>
    </Field>
    <Button type="submit" variant="outline" size="sm" disabled={resolution !== "selected"}>{label}</Button>
    {resolution === "unavailable" && <p role="status" className="muted w-full text-xs">Choose another {target} before linking.</p>}
  </MutationForm>;
}
function CredentialLinks({
  credential,
  hostOptions,
}: {
  credential: Credential;
  hostOptions: HostOptions;
}) {
  const hosts = hostOptions.hosts;
  const availableHosts = hosts.filter(
    (host) => !credential.hosts.some((link) => link.host_id === host.id),
  );
  const pickableServices = credential.pickable_services.filter((service) =>
    credential.hosts.some((host) => host.host_id === service.host_id) &&
    !credential.services.some((linked) => linked.service_id === service.service_id),
  );
  const hostPicker: AssociationPicker = availableHosts.length
    ? { status: "available", options: availableHosts.map((host) => ({ value: String(host.id), label: host.ip })) }
    : { status: "blocked", message: hosts.length ? "All hosts are already linked." : "Add a host before linking it to this credential." };
  const servicePicker: AssociationPicker = !credential.hosts.length
    ? { status: "blocked", message: "Link a host to pick its services." }
    : pickableServices.length
      ? { status: "available", options: pickableServices.map((service) => ({ value: String(service.service_id), label: `${service.ip}:${service.port}/${service.proto}${service.name ? ` ${service.name}` : ""}` })) }
      : { status: "blocked", message: "No additional services available on linked hosts." };
  return (
    <div className="grid items-start gap-3 md:grid-cols-2">
      <div className="stack gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide">
          Linked hosts
        </h3>
        <div className="flex flex-wrap gap-1.5">
          {credential.hosts.map((host) => (
            <div
              key={host.host_id}
              className="actions min-w-0 max-w-full rounded-md border px-2 py-0.5"
            >
              <ScopedLink href={`/hosts/${host.host_id}`}
              className="mono min-w-0 break-all text-[13px] underline underline-offset-4">{host.ip}</ScopedLink>
              <MutationForm
                action={`/credentials/${credential.id}/unlink/host/${host.host_id}`}
                confirm={`Unlink host ${host.ip} and its service links from this credential?`}
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
            <span className="muted text-xs">No linked hosts.</span>
          )}
        </div>
        <p role="status" className="muted text-xs">{hostOptions.status === "idle" || hostOptions.status === "loading" ? "Loading hosts…" : ""}</p>
        {hostOptions.status === "error" && <div className="grid gap-2">
          <p role="alert" className="text-xs text-destructive">Unable to load hosts. Retry to link a host.</p>
          <Button type="button" variant="outline" size="sm" onClick={hostOptions.load}>Retry hosts</Button>
        </div>}
        {hostOptions.status === "ready" && <LinkAssociationForm credentialId={credential.id} target="host" picker={hostPicker} />}
      </div>
      <div className="stack gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide">
          Linked services
        </h3>
        <div className="flex flex-wrap gap-1.5">
          {credential.services.map((service) => (
            <div
              key={service.service_id}
              className="actions min-w-0 max-w-full rounded-md border px-2 py-0.5"
            >
              <ScopedLink href={`/hosts/${service.host_id}`}
              className="mono min-w-0 break-all text-[13px] underline underline-offset-4">{service.ip}:{service.port}/{service.proto}
              {service.name ? ` ${service.name}` : ""}</ScopedLink>
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
            <span className="muted text-xs">No linked services.</span>
          )}
        </div>
        <LinkAssociationForm credentialId={credential.id} target="service" picker={servicePicker} />
      </div>
    </div>
  );
}
function CredentialEditForm({ credential, kinds }: { credential: Credential; kinds: string[] }) {
  const [draft, setDraft] = useState({ username: credential.username, secret: credential.secret });
  const validity = credentialDraftValidity(draft.username, draft.secret);
  return <MutationForm action={`/credentials/${credential.id}/edit`} canSubmit={validity === "valid"}>
    <div onChange={(event) => {
      const field = event.target;
      if ((field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) && (field.name === "username" || field.name === "secret")) {
        setDraft((current) => ({ ...current, [field.name]: field.value }));
      }
    }}>
      <CredentialFields credential={credential} kinds={kinds} />
    </div>
    <div className="actions mt-4 justify-end"><Button type="submit" disabled={validity !== "valid"}>Save credential</Button></div>
  </MutationForm>;
}

function CredentialDetail({
  credential,
  kinds,
  hostOptions,
}: {
  credential: Credential;
  kinds: string[];
  hostOptions: HostOptions;
}) {
  return (
    <article className="credential-detail" aria-labelledby="credential-title">
      <header className="flex flex-wrap items-start justify-between gap-2 border-b pb-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h2
            id="credential-title"
            className="mono break-all text-[13px] font-semibold"
          >
            {credential.username || "No username"}
          </h2>
          <Badge variant="secondary">{credential.kind}</Badge>
        </div>
        <div className="actions">
          <Modal
            title="Edit credential"
            protectChanges="Discard unsaved credential changes?"
            trigger={
              <Button type="button" variant="outline" size="sm">
                Edit credential
              </Button>
            }
          >
            <CredentialEditForm credential={credential} kinds={kinds} />
          </Modal>
        </div>
      </header>
      <section className="stack gap-2" aria-labelledby="credential-secret">
        <h3 id="credential-secret" className="credential-label text-xs">
          Secret
        </h3>
        <div className="rounded-md border bg-muted/30 p-2 text-[13px]">
          <Secret key={credential.secret} value={credential.secret} />
        </div>
      </section>
      <section className="stack gap-2" aria-labelledby="credential-scope">
        <h3 id="credential-scope" className="credential-label text-xs">
          Scope
        </h3>
        <CredentialLinks credential={credential} hostOptions={hostOptions} />
        <p className="muted text-xs">
          Associations only; links do not establish that access was verified.
        </p>
      </section>
      {credential.notes && (
        <section aria-labelledby="credential-notes">
          <h3 id="credential-notes" className="credential-label mb-1 text-xs">
            Discovery notes
          </h3>
          <p className="whitespace-pre-wrap break-words text-[13px]">
            {credential.notes}
          </p>
        </section>
      )}
      <footer className="flex flex-wrap items-center justify-between gap-2 border-t pt-2">
        <p className="muted text-xs">
          Added <time className="mono">{credential.created_at}</time>
        </p>
        <MutationForm
          action={`/credentials/${credential.id}/delete`}
          confirm={`Delete credential ${credential.username || "(no username)"} and all its links? This cannot be undone.`}
        >
          <Button
            type="submit"
            variant="ghost"
            size="sm"
            className="text-destructive"
          >
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
  const resolvedScope = resolveCredentialScope(scope);
  const all = data.credentials ?? [];
  const kinds = data.kinds ?? [];
  const credentials = all.filter((credential) => {
    const linked = Boolean(
      credential.hosts.length || credential.services.length,
    );
    const text = [
      credential.username,
      credential.kind,
      credential.notes,
      ...credential.hosts.map((host) => host.ip),
      ...credential.services.map(
        (service) =>
          `${service.ip}:${service.port}/${service.proto} ${service.name ?? ""}`,
      ),
    ]
      .join(" ")
      .toLowerCase();
    return (
      (!kind || credential.kind === kind) &&
      (resolvedScope === "all" || (resolvedScope === "linked" && linked) || (resolvedScope === "unlinked" && !linked)) &&
      text.includes(query.toLowerCase())
    );
  });
  const selection = resolveCredentialSelection(currentUrl.hash, all, credentials);
  const selected = selection.status === "selected" ? selection.credential : undefined;
  const hostOptions = useHostOptions(Boolean(selected));
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
      <PageHeader title="Credentials">
        <Modal
          title="Add credential"
          protectChanges="Discard unsaved credential changes?"
          trigger={<Button type="button">Add credential</Button>}
        >
          <CredentialCreateForm kinds={kinds} hostOptions={hostOptions} />
        </Modal>
      </PageHeader>
      <div
        className="credential-filters"
        role="search"
        aria-label="Filter credentials"
      >
        <label className="relative min-w-0">
          <Search
            size={15}
            className="pointer-events-none absolute top-2.5 left-3 text-muted-foreground"
            aria-hidden="true"
          />
          <span className="sr-only">Filter credentials</span>
          <Input
            type="search"
            className="pl-9"
            placeholder="Filter username, notes, IP or service…"
            value={query}
            onChange={(event) => filter({ filter: event.target.value })}
          />
        </label>
        <NativeSelect
          aria-label="Credential kind"
          value={kind}
          onChange={(event) => filter({ kind: event.target.value })}
        >
          <option value="">All kinds</option>
          {kind && !kinds.includes(kind) && <option value={kind}>{kind}</option>}
          {kinds.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect
          aria-label="Credential scope"
          value={scope}
          onChange={(event) => filter({ scope: event.target.value })}
        >
          <option value="">All associations</option>
          <option value="linked">Linked</option>
          <option value="unlinked">Unlinked</option>
          {resolvedScope === "invalid" && <option value={scope} disabled>Unknown scope: {scope}</option>}
        </NativeSelect>
        <span className="muted text-xs" role="status">
          {credentials.length} of {all.length} credentials
        </span>
      </div>
      {resolvedScope === "invalid" && <div role="alert" className="flex flex-wrap items-center gap-2 text-sm">
        <p>Unknown association filter. Choose a scope or clear this filter.</p>
        <Button type="button" variant="outline" size="sm" onClick={() => filter({ scope: "" })}>Clear scope filter</Button>
      </div>}
      {credentials.length > 0 || selection.status === "unavailable" ? (
        <div className="credential-workbench rounded-lg border bg-card">
          <section className="credential-list" aria-label="Credential list">
            <h2 className="credential-label border-b bg-muted/40 px-2.5 py-2 text-xs">
              Identity / scope
            </h2>
            {credentials.map((credential) => (
              <ScopedLink key={credential.id}
              href={`?${currentUrl.searchParams}#credential-${credential.id}`}
              aria-current={
                credential.id === selected?.id ? "true" : undefined
              }
              className="credential-choice"
              onClick={(event) => {
                if (
                  event.button !== 0 ||
                  event.metaKey ||
                  event.ctrlKey ||
                  event.shiftKey ||
                  event.altKey
                )
                  return;
                event.preventDefault();
                const next = new URL(location.href);
                next.hash = `credential-${credential.id}`;
                history.pushState(null, "", next);
                setUrl(next.href);
              }}><span className="flex items-center justify-between gap-2">
                <span className="mono truncate text-[13px] font-semibold">
                  {credential.username || "No username"}
                </span>
                <Badge variant="outline">{credential.kind}</Badge>
              </span>
              <span className="muted mt-1 block text-xs">
                {[
                  credential.hosts.length
                    ? `${credential.hosts.length} hosts`
                    : "",
                  credential.services.length
                    ? `${credential.services.length} services`
                    : "",
                ]
                  .filter(Boolean)
                  .join(" · ") || "Unlinked"}
              </span>
              {credential.notes && (
                <span className="muted mt-1 block truncate text-xs">
                  {credential.notes}
                </span>
              )}</ScopedLink>
            ))}
          </section>
          {selected ? <CredentialDetail
            key={selected.id}
            credential={selected}
            kinds={kinds}
            hostOptions={hostOptions}
          /> : <Empty>
            <p>{selection.status === "unavailable" && selection.reason === "filtered" ? "This credential is hidden by the current filters." : "The requested credential is unavailable. It may have been deleted."}</p>
            <div className="actions mt-3 justify-center">
              <Button type="button" variant="outline" onClick={() => filter({})}>Clear selection</Button>
              {selection.status === "unavailable" && selection.reason === "filtered" && <Button type="button" variant="outline" onClick={() => filter({ filter: "", kind: "", scope: "" })}>Clear filters</Button>}
            </div>
          </Empty>}
        </div>
      ) : (
        <Empty>
          {all.length ? (
            <>
              <p>No credentials match these filters.</p>
              <Button
                type="button"
                variant="outline"
                className="mt-3"
                onClick={() => filter({ filter: "", kind: "", scope: "" })}
              >
                Clear filters
              </Button>
            </>
          ) : (
            "No credentials yet."
          )}
        </Empty>
      )}
    </div>
  );
}
