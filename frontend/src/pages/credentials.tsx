import { useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
  Modal,
  MutationForm,
  PageHeader,
  SelectField,
} from "../common";
import type { PageData } from "../types";

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

function Secret({ value }: { value: string }) {
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState("");
  if (!value)
    return <span className="muted flex min-h-7 items-center">No secret</span>;
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setStatus("Secret copied.");
    } catch {
      setVisible(true);
      setStatus(
        "Clipboard unavailable. Select the revealed secret to copy it.",
      );
    }
  }
  return (
    <div className="stack gap-1">
      <div className="flex min-h-7 items-start gap-2">
        <span className="mono block min-w-0 max-w-80 select-text whitespace-pre-wrap break-all py-1">
          {visible ? value : "••••••••••••"}
        </span>
        <div className="flex shrink-0 items-center">
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={() => setVisible(!visible)}
            aria-label={visible ? "Hide secret" : "Reveal secret"}
            title={visible ? "Hide secret" : "Reveal secret"}
            aria-pressed={visible}
          >
            {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={copy}
            aria-label="Copy secret"
            title="Copy secret"
          >
            <Copy aria-hidden="true" />
          </Button>
        </div>
      </div>
      <span role="status" className="muted text-xs">
        {status}
      </span>
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
    <div className="grid gap-4 md:grid-cols-2">
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
                  size="sm"
                  aria-label={`Unlink host ${host.ip}`}
                >
                  Unlink
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
                  size="sm"
                  aria-label={`Unlink service ${service.ip}:${service.port}/${service.proto}`}
                >
                  Unlink
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

function CredentialRow({
  credential,
  kinds,
  hosts,
}: {
  credential: Credential;
  kinds: string[];
  hosts: Host[];
}) {
  return (
    <>
      <TableRow id={`credential-${credential.id}`}>
        <TableCell className="align-top">
          <div className="flex min-h-7 items-center">
            <Badge variant="secondary">{credential.kind}</Badge>
          </div>
          <div className="muted mt-2 text-xs">#{credential.id}</div>
        </TableCell>
        <TableCell className="mono align-top break-all">
          <div className="min-h-7 py-1">
            {credential.username || <span className="muted">No username</span>}
          </div>
        </TableCell>
        <TableCell className="align-top">
          <Secret value={credential.secret} />
        </TableCell>
        <TableCell className="max-w-sm whitespace-pre-wrap align-top break-words">
          <div className="min-h-7 py-1">
            {credential.notes || <span className="muted">—</span>}
          </div>
        </TableCell>
        <TableCell className="mono whitespace-nowrap align-top text-xs">
          <div className="flex min-h-7 items-center">{credential.created_at}</div>
        </TableCell>
        <TableCell className="align-top">
          <div className="actions">
            <Modal
              title={`Edit credential #${credential.id}`}
              trigger={
                <Button type="button" variant="outline" size="sm">
                  Edit
                </Button>
              }
            >
              <MutationForm action={`/credentials/${credential.id}/edit`}>
                <CredentialFields credential={credential} kinds={kinds} />
                <div className="actions mt-4 justify-end">
                  <Button type="submit">Save credential</Button>
                </div>
              </MutationForm>
            </Modal>
            <MutationForm
              action={`/credentials/${credential.id}/delete`}
              confirm={`Delete credential #${credential.id} and all its links? This cannot be undone.`}
            >
              <Button type="submit" variant="destructive" size="sm">
                Delete
              </Button>
            </MutationForm>
          </div>
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell colSpan={6} className="bg-muted/25 pb-4">
          <CredentialLinks credential={credential} hosts={hosts} />
        </TableCell>
      </TableRow>
    </>
  );
}

export function CredentialsPage({ data }: { data: PageData }) {
  const credentials = data.credentials ?? [];
  const kinds = data.kinds ?? [];
  const hosts = data.hosts ?? [];
  return (
    <div className="stack">
      <PageHeader
        title="Credentials"
        description="Found secrets and their host and service associations."
      >
        <Modal
          title="Add credential"
          trigger={<Button type="button">Add credential</Button>}
        >
          <MutationForm action="/credentials">
            <CredentialFields kinds={kinds} />
            <div className="actions mt-4 justify-end">
              <Button type="submit">Add credential</Button>
            </div>
          </MutationForm>
        </Modal>
      </PageHeader>
      <p className="muted text-sm">
        {credentials.length} credential{credentials.length === 1 ? "" : "s"}
      </p>
      {credentials.length ? (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <Table className="data-table">
            <TableHeader>
              <TableRow>
                <TableHead>Kind</TableHead>
                <TableHead>Username</TableHead>
                <TableHead>Secret</TableHead>
                <TableHead>Notes</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {credentials.map((credential) => (
                <CredentialRow
                  key={credential.id}
                  credential={credential}
                  kinds={kinds}
                  hosts={hosts}
                />
              ))}
            </TableBody>
          </Table>
        </div>
      ) : (
        <Empty>No credentials yet. Add one as you find it.</Empty>
      )}
    </div>
  );
}
