import { useEffect, useMemo, useReducer, useRef, useState, type Dispatch } from "react";
import { CredentialSecretInput } from "@/components/credential-secret-input";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { Field, MutationForm, engagementUrl } from "../common";
import type { Host, ServiceOption } from "../types";
import { associationReadiness, credentialDraftValidity, initialAssociations, transitionAssociations, type AssociationEvent, type CredentialTarget } from "./credential-workflow";
import type { HostOptions } from "./credential-host-options";
import { apiUrl } from "../lib/api";

const HOSTS_PER_PAGE = 50;

function HostServices({ host, target, dispatch }: {
  host: Pick<Host, "id" | "ip">;
  target: CredentialTarget;
  dispatch: Dispatch<AssociationEvent>;
}) {
  const activeRequest = useRef<{ controller: AbortController; request: symbol } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    const request = Symbol("host-services");
    const attempt = target.attempt;
    activeRequest.current = { controller, request };
    dispatch({ type: "started", hostId: host.id, attempt, request });
    void (async () => {
      try {
        const response = await fetch(apiUrl(engagementUrl(`/options/hosts/${host.id}/services`)), {
          headers: { Accept: "application/json" }, signal: controller.signal,
        });
        if (!response.ok) throw new Error("Unable to load services.");
        const options = await response.json() as { services: ServiceOption[] };
        if (!controller.signal.aborted) {
          dispatch({ type: "loaded", hostId: host.id, attempt, request, services: options.services });
        }
      } catch {
        if (!controller.signal.aborted) dispatch({ type: "failed", hostId: host.id, attempt, request });
      }
    })();
    return () => {
      controller.abort();
      dispatch({ type: "aborted", hostId: host.id, attempt, request });
    };
  }, [host.id, target.attempt, dispatch]);
  function cancel() {
    const active = activeRequest.current;
    if (!active) return;
    active.controller.abort();
    dispatch({ type: "aborted", hostId: host.id, attempt: target.attempt, request: active.request });
  }
  const load = target.load;
  return <div className="grid gap-2 border-t bg-muted/20 py-2 pr-3 pl-9">
    {load.status === "loading" && <><p role="status" className="text-xs text-muted-foreground">Loading services…</p><Button type="button" variant="outline" size="sm" onClick={cancel}>Cancel loading</Button></>}
    {(load.status === "error" || load.status === "aborted") && <div className="grid gap-2"><p role="alert" className="text-xs text-destructive">{load.status === "error" ? "Unable to load services." : "Service loading was cancelled."} Retry or deselect this host before saving.</p><Button type="button" variant="outline" size="sm" onClick={() => dispatch({ type: "retry", hostId: host.id })}>Retry services</Button></div>}
    {load.status === "ready" && !load.services.length && <p className="text-xs text-muted-foreground">No services recorded. The host can still be linked.</p>}
    {load.status === "ready" && load.services.map((service) => <label key={service.service_id} className="flex cursor-pointer items-center gap-2 text-xs">
      <input type="checkbox" className="size-4 accent-primary" value={service.service_id} checked={target.selected.includes(service.service_id)} onChange={() => dispatch({ type: "toggle-service", hostId: host.id, serviceId: service.service_id })} />
      <span className="mono">{service.port}/{service.proto}</span><span className="text-muted-foreground">{service.service_name}</span>
    </label>)}
  </div>;
}

export function CredentialCreateForm({ hostOptions, kinds }: { hostOptions: HostOptions; kinds: string[] }) {
  const hosts = hostOptions.hosts;
  const [kind, setKind] = useState(() => kinds.includes("password") ? "password" : kinds[0] ?? "");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [query, setQuery] = useState("");
  const [disclosure, setDisclosure] = useState<"unopened" | "open" | "closed">("unopened");
  const [hostPage, setHostPage] = useState(1);
  const [associations, dispatch] = useReducer(transitionAssociations, initialAssociations);
  const availableHostIds = useMemo(() => new Set(hosts.map((host) => host.id)), [hosts]);
  useEffect(() => dispatch({ type: "retain-hosts", hostIds: availableHostIds }), [availableHostIds]);
  // A removed host stops participating immediately, before effect cleanup.
  const targets = Object.fromEntries(Object.entries(associations.targets).filter(([id]) => availableHostIds.has(Number(id))));
  const hostIds = Object.keys(targets).map(Number);
  const serviceCount = Object.values(targets).reduce((count, target) => count + target.selected.length, 0);
  const validity = credentialDraftValidity(username, secret);
  const readiness = associationReadiness(Object.values(targets));
  const canSubmit = validity === "valid" && readiness === "ready";
  const matchingHosts = useMemo(
    () => disclosure !== "unopened" ? hosts.filter((host) => host.ip.includes(query.trim())) : [],
    [disclosure, hosts, query],
  );
  const selectedHosts = hosts.filter((host) => host.id in targets);
  const hostPages = Math.max(1, Math.ceil(matchingHosts.length / HOSTS_PER_PAGE));
  const currentHostPage = Math.min(hostPage, hostPages);
  const visibleHosts = matchingHosts.slice((currentHostPage - 1) * HOSTS_PER_PAGE, currentHostPage * HOSTS_PER_PAGE);
  const visibleHostIds = new Set(visibleHosts.map((host) => host.id));
  // Selected rows stay mounted through filtering, paging, and disclosure closing.
  const renderedHosts = [...visibleHosts, ...selectedHosts.filter((host) => !visibleHostIds.has(host.id))];
  return <MutationForm action="/credentials" canSubmit={canSubmit}>
    {hostIds.map((id) => <input key={`host-${id}`} type="hidden" name="host_ids" value={id} />)}
    {Object.values(targets).flatMap((target) => target.selected.map((id) => <input key={`service-${id}`} type="hidden" name="service_ids" value={id} />))}
    <p className="text-sm text-muted-foreground">Capture quickly. Expand associations when you know the scope.</p>
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="Credential kind"><NativeSelect className="w-full" name="kind" value={kind} onChange={(event) => setKind(event.target.value)}>
        {kinds.map((value) => <option key={value}>{value}</option>)}
      </NativeSelect></Field>
      <Field label="Username / identity" name="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="admin, DOMAIN\\user, or email" autoComplete="off" />
    </div>
    <CredentialSecretInput key={kind} kind={kind} value={secret} onChange={setSecret} />
    <Field label="Discovery notes (optional)"><Textarea name="notes" rows={3} placeholder="Where was it found? What context should you keep?" /></Field>
    <details className="rounded-md border p-3" onToggle={(event) => {
      setDisclosure(event.currentTarget.open ? "open" : "closed");
      if (event.currentTarget.open) hostOptions.load();
    }}>
      <summary className="cursor-pointer text-sm font-semibold">Target associations · {hostIds.length} hosts / {serviceCount} services</summary>
      {disclosure !== "unopened" && <section className="grid gap-3 pt-4" aria-label="Target associations">
        <div><h3 className="text-sm font-semibold">Link targets <span className="font-normal text-muted-foreground">· optional</span></h3><p className="mt-1 text-xs text-muted-foreground">Choose hosts, then specific services. Links record scope, not verified access.</p></div>
        <p role="status" className="text-xs text-muted-foreground">{hostOptions.status === "idle" || hostOptions.status === "loading" ? "Loading hosts… You can still save an unlinked credential." : ""}</p>
        {hostOptions.status === "error" && <div className="grid gap-2">
          <p role="alert" className="text-xs text-destructive">Unable to load hosts. Retry or save an unlinked credential.</p>
          <Button type="button" variant="outline" size="sm" onClick={hostOptions.load}>Retry hosts</Button>
        </div>}
        <Input type="search" aria-label="Search target hosts" placeholder="Search hosts by IP…" value={query} onChange={(event) => { setQuery(event.target.value); setHostPage(1); }} />
        <div className="max-h-56 overflow-y-auto rounded-md border">
          {renderedHosts.map((host) => <div key={host.id} hidden={!visibleHostIds.has(host.id)} className="border-b last:border-b-0">
            <label className="flex min-w-0 cursor-pointer items-center gap-3 p-3 text-sm hover:bg-muted/40"><input type="checkbox" className="size-4 shrink-0 accent-primary" value={host.id} checked={host.id in targets} onChange={() => dispatch({ type: "toggle-host", hostId: host.id })} /><span className="mono min-w-0 break-all">{host.ip}</span></label>
            {host.id in targets && <HostServices host={host} target={targets[host.id]} dispatch={dispatch} />}
          </div>)}
          {hostOptions.status === "ready" && !hosts.length && <p className="p-3 text-sm text-muted-foreground">No hosts yet. You can save an unlinked credential.</p>}
          {hosts.length > 0 && !matchingHosts.length && <p className="p-3 text-sm text-muted-foreground">No matching hosts. Existing selections are kept.</p>}
        </div>
        {matchingHosts.length > HOSTS_PER_PAGE && <nav aria-label="Target host pagination" className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-muted-foreground" aria-live="polite">{matchingHosts.length} hosts · Page {currentHostPage} of {hostPages}</span>
          <div className="flex gap-2">
            <Button type="button" variant="outline" size="sm" aria-label="Previous host page" disabled={currentHostPage <= 1} onClick={() => setHostPage(currentHostPage - 1)}>Previous</Button>
            <Button type="button" variant="outline" size="sm" aria-label="Next host page" disabled={currentHostPage >= hostPages} onClick={() => setHostPage(currentHostPage + 1)}>Next</Button>
          </div>
        </nav>}
        <p className="text-xs text-muted-foreground" role="status">{hostIds.length} hosts · {serviceCount} services selected. {hostIds.length ? "Unchecking a host also clears its services." : "Unlinked is OK."}</p>
      </section>}
    </details>
    {validity === "empty" && <p className="text-xs text-muted-foreground">Provide a username, a secret, or both.</p>}
    {readiness !== "ready" && <div className="grid gap-2">
      <p role="status" className="text-xs text-muted-foreground">{readiness === "loading" ? "Waiting for selected hosts’ services. Open associations to cancel loading or deselect a host." : "Some selected hosts need attention. Open associations to retry loading or deselect a host."}</p>
      {selectedHosts.filter((host) => targets[host.id].load.status !== "ready").map((host) => <div key={host.id} className="flex flex-wrap items-center gap-2 text-xs">
        <span className="mono">{host.ip}</span>
        {(targets[host.id].load.status === "error" || targets[host.id].load.status === "aborted") && <Button type="button" variant="outline" size="sm" onClick={() => dispatch({ type: "retry", hostId: host.id })}>Retry services</Button>}
        <Button type="button" variant="outline" size="sm" onClick={() => dispatch({ type: "toggle-host", hostId: host.id })}>Deselect host</Button>
      </div>)}
    </div>}
    <p className="text-xs text-muted-foreground">Credentials and their links are never changed by scan imports.</p>
    <div className="actions justify-end border-t pt-4"><Button type="submit">Add credential</Button></div>
  </MutationForm>;
}
