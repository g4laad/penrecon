import { useCallback, useEffect, useId, useState, type CSSProperties } from "react";
import { Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { NativeSelect } from "@/components/ui/native-select";
import { Field, MutationForm } from "../common";
import type { Host, PageData, Service } from "../types";

function HostServices({ host, selected, onSelect, onReady }: {
  host: Host;
  selected: number[];
  onSelect: (hostId: number, serviceId: number) => void;
  onReady: (hostId: number, ready: boolean) => void;
}) {
  const [services, setServices] = useState<Service[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    onReady(host.id, false);
    void (async () => {
      try {
        const response = await fetch(`/hosts/${host.id}?per=all`, {
          headers: { Accept: "application/json" }, signal: controller.signal,
        });
        if (!response.ok) throw new Error("Unable to load services.");
        const page = await response.json() as PageData;
        if (controller.signal.aborted) return;
        setServices(page.services ?? []);
        setLoading(false);
        onReady(host.id, true);
      } catch {
        if (!controller.signal.aborted) {
          setLoading(false);
          setError("Unable to load services. Retry or deselect this host before saving.");
        }
      }
    })();
    return () => controller.abort();
  }, [host.id, attempt, onReady]);
  return <div className="grid gap-2 border-t bg-muted/20 py-2 pr-3 pl-9">
    {loading && <p role="status" className="text-xs text-muted-foreground">Loading services…</p>}
    {error && <div className="grid gap-2"><p role="alert" className="text-xs text-destructive">{error}</p><Button type="button" variant="outline" size="sm" onClick={() => setAttempt((value) => value + 1)}>Retry services</Button></div>}
    {!loading && !error && !services.length && <p className="text-xs text-muted-foreground">No services recorded. The host can still be linked.</p>}
    {!loading && !error && services.map((service) => <label key={service.service_id} className="flex cursor-pointer items-center gap-2 text-xs">
      <input type="checkbox" className="size-4 accent-primary" name="service_ids" value={service.service_id} checked={selected.includes(service.service_id)} onChange={() => onSelect(host.id, service.service_id)} />
      <span className="mono">{service.port}/{service.proto}</span><span className="text-muted-foreground">{service.service_name}</span>
    </label>)}
  </div>;
}

export function CredentialCreateForm({ hosts, kinds }: { hosts: Host[]; kinds: string[] }) {
  const [kind, setKind] = useState("password");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [reveal, setReveal] = useState(false);
  const [query, setQuery] = useState("");
  const [targets, setTargets] = useState<Record<number, number[]>>({});
  const [ready, setReady] = useState<Record<number, boolean>>({});
  const secretId = useId();
  const hintId = useId();
  const hostIds = Object.keys(targets).map(Number);
  const serviceCount = Object.values(targets).reduce((count, ids) => count + ids.length, 0);
  const valid = Boolean(username.trim() || secret.trim());
  const loading = hostIds.some((id) => !ready[id]);
  const onReady = useCallback((id: number, value: boolean) => {
    setReady((current) => ({ ...current, [id]: value }));
  }, []);
  const onSelect = useCallback((hostId: number, serviceId: number) => {
    setTargets((current) => {
      const selected = current[hostId];
      if (!selected) return current;
      return { ...current, [hostId]: selected.includes(serviceId) ? selected.filter((id) => id !== serviceId) : [...selected, serviceId] };
    });
  }, []);
  function toggleHost(id: number) {
    setReady((current) => ({ ...current, [id]: false }));
    setTargets((current) => {
      const next = { ...current };
      if (id in next) delete next[id];
      else next[id] = [];
      return next;
    });
  }
  const label = kind === "key" ? "Private key" : kind === "hash" ? "Hash" : kind === "token" ? "Token" : "Secret";
  return <MutationForm action="/credentials">
    <p className="text-sm text-muted-foreground">Capture quickly. Expand associations when you know the scope.</p>
    <div className="grid gap-4 sm:grid-cols-2">
      <Field label="Credential kind"><NativeSelect className="w-full" name="kind" value={kind} onChange={(event) => { setKind(event.target.value); setReveal(false); }}>
        {kinds.map((value) => <option key={value}>{value}</option>)}
      </NativeSelect></Field>
      <Field label="Username / identity" name="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="admin, DOMAIN\\user, or email" autoComplete="off" />
    </div>
    <div className="grid gap-1.5">
      <div className="flex items-center justify-between gap-2"><label htmlFor={secretId} className="text-sm font-medium">{label}</label>
        <Button type="button" size="sm" variant="ghost" aria-pressed={reveal} onClick={() => setReveal(!reveal)}>{reveal ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}{reveal ? "Hide" : "Reveal"}</Button></div>
      {kind === "key" || kind === "other" ? <Textarea id={secretId} name="secret" className="mono" rows={kind === "key" ? 5 : 3} value={secret} onChange={(event) => setSecret(event.target.value)} autoComplete="off" spellCheck={false} aria-describedby={hintId} style={!reveal ? { WebkitTextSecurity: "disc" } as CSSProperties : undefined} placeholder={kind === "key" ? "Paste private key" : "Paste or enter secret"} /> :
        <Input id={secretId} name="secret" className="mono" type={reveal ? "text" : "password"} value={secret} onChange={(event) => setSecret(event.target.value)} autoComplete="new-password" spellCheck={false} aria-describedby={hintId} placeholder={kind === "hash" ? "Paste hash" : kind === "token" ? "Paste token" : "Paste or enter secret"} />}
      <p id={hintId} className="text-xs text-muted-foreground">Username or secret required; either can stand alone.</p>
    </div>
    <Field label="Discovery notes (optional)"><Textarea name="notes" rows={3} placeholder="Where was it found? What context should you keep?" /></Field>
    <details className="rounded-md border p-3">
      <summary className="cursor-pointer text-sm font-semibold">Target associations · {hostIds.length} hosts / {serviceCount} services</summary>
      <section className="grid gap-3 pt-4" aria-label="Target associations">
        <div><h3 className="text-sm font-semibold">Link targets <span className="font-normal text-muted-foreground">· optional</span></h3><p className="mt-1 text-xs text-muted-foreground">Choose hosts, then specific services. Links record scope, not verified access.</p></div>
        <Input type="search" aria-label="Search target hosts" placeholder="Search hosts by IP…" value={query} onChange={(event) => setQuery(event.target.value)} />
        <div className="max-h-56 overflow-y-auto rounded-md border">
          {hosts.map((host) => <div key={host.id} hidden={!host.ip.includes(query.trim())} className="border-b last:border-b-0">
            <label className="flex cursor-pointer items-center gap-3 p-3 text-sm hover:bg-muted/40"><input type="checkbox" className="size-4 accent-primary" name="host_ids" value={host.id} checked={host.id in targets} onChange={() => toggleHost(host.id)} /><span className="mono">{host.ip}</span></label>
            {host.id in targets && <HostServices host={host} selected={targets[host.id]} onSelect={onSelect} onReady={onReady} />}
          </div>)}
          {!hosts.length && <p className="p-3 text-sm text-muted-foreground">No hosts yet. You can save an unlinked credential.</p>}
          {hosts.length > 0 && !hosts.some((host) => host.ip.includes(query.trim())) && <p className="p-3 text-sm text-muted-foreground">No matching hosts. Existing selections are kept.</p>}
        </div>
        <p className="text-xs text-muted-foreground" role="status">{hostIds.length} hosts · {serviceCount} services selected. {hostIds.length ? "Unchecking a host also clears its services." : "Unlinked is OK."}</p>
      </section>
    </details>
    <p className="text-xs text-muted-foreground">Credentials and their links are never changed by scan imports.</p>
    <div className="actions justify-end border-t pt-4"><Button type="submit" disabled={!valid || loading}>Add credential</Button></div>
  </MutationForm>;
}
