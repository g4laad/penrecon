import { useId, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
  SelectField,
} from "../common";
import type { Operation, PageData } from "../types";

function OperationFields({ operation }: { operation?: Operation }) {
  const attachmentId = useId();
  const removeId = useId();
  const attachmentInput = useRef<HTMLInputElement>(null);
  const [removeAttachment, setRemoveAttachment] = useState(false);
  return (
    <div className="form-grid">
      <Field
        label="Started"
        name="started_at"
        type="datetime-local"
        defaultValue={operation?.started_at?.slice(0, 16) ?? ""}
      />
      <Field
        label="Ended"
        name="ended_at"
        type="datetime-local"
        defaultValue={operation?.ended_at?.slice(0, 16) ?? ""}
      />
      <Field
        label="Source"
        name="source"
        defaultValue={operation?.source}
        placeholder="Operator host or IP"
      />
      <Field
        label="Destination"
        name="destination"
        defaultValue={operation?.destination}
        placeholder="Target host, IP, or range"
      />
      <Field
        label="Tool"
        name="tool"
        defaultValue={operation?.tool}
        placeholder="nmap"
      />
      <Field
        label="User context"
        name="user_context"
        defaultValue={operation?.user_context}
        placeholder="root, domain\\user, relay"
      />
      <div className="col-span-full">
        <Field label="Command" name="command" required>
          <Textarea
            name="command"
            defaultValue={operation?.command}
            required
            spellCheck={false}
            rows={3}
            className="mono"
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Output" name="output">
          <Textarea
            name="output"
            defaultValue={operation?.output}
            spellCheck={false}
            rows={7}
            className="mono"
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Description" name="description">
          <Textarea
            name="description"
            defaultValue={operation?.description}
            rows={3}
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Comments" name="comments">
          <Textarea
            name="comments"
            defaultValue={operation?.comments}
            rows={3}
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field
          label="Tags"
          name="tags"
          defaultValue={operation?.tags.join(", ")}
          placeholder="comma, separated"
        />
      </div>
      {operation?.attachment_name && (
        <div className="stack col-span-full gap-2 rounded-md border bg-muted/30 p-3">
          <span className="text-sm font-medium">Current attachment</span>
          <a
            href={`/operations/${operation.id}/attachment`}
            className="break-all text-sm underline underline-offset-4"
            download
          >
            {operation.attachment_name}
          </a>
          <label htmlFor={removeId} className="flex items-center gap-2 text-sm">
            <input
              id={removeId}
              type="checkbox"
              name="remove_attachment"
              value="true"
              checked={removeAttachment}
              className="size-4 accent-primary"
              onChange={(event) => {
                const checked = event.target.checked;
                if (
                  checked &&
                  !window.confirm(
                    `Remove attachment ${operation.attachment_name}? The file will be deleted when you save.`,
                  )
                )
                  return;
                setRemoveAttachment(checked);
                if (checked && attachmentInput.current)
                  attachmentInput.current.value = "";
              }}
            />
            Remove attachment when saving
          </label>
        </div>
      )}
      <div className="stack col-span-full gap-2">
        <label htmlFor={attachmentId} className="text-sm font-medium">
          {operation?.attachment_name ? "Replacement attachment" : "Attachment"}
        </label>
        <Input
          id={attachmentId}
          ref={attachmentInput}
          type="file"
          name="attachment"
          disabled={removeAttachment}
          onChange={(event) => {
            if (
              event.currentTarget.files?.length &&
              operation?.attachment_name &&
              !window.confirm(
                `Replace attachment ${operation.attachment_name}? The current file will be deleted when you save.`,
              )
            ) {
              event.currentTarget.value = "";
            }
          }}
        />
        {operation?.attachment_name && (
          <p className="muted text-xs">
            {removeAttachment
              ? "Attachment removal selected. Uncheck removal to upload a replacement instead."
              : "Uploading a replacement deletes the current attachment when saved."}
          </p>
        )}
      </div>
    </div>
  );
}

function OperationEditor({ operation }: { operation: Operation }) {
  return (
    <div className="stack">
      <MutationForm action={`/operations/${operation.id}/edit`}>
        <OperationFields operation={operation} />
        <div className="actions mt-4 justify-end">
          <Button type="submit">Save operation</Button>
        </div>
      </MutationForm>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
        <p className="muted text-xs">
          Created {operation.created_at.replace("T", " ").slice(0, 16)}
          <br />
          Updated {operation.updated_at.replace("T", " ").slice(0, 16)}
        </p>
        <MutationForm
          action={`/operations/${operation.id}/delete`}
          confirm={`Delete operation #${operation.id} and its attachment? This cannot be undone.`}
        >
          <Button type="submit" variant="destructive">
            Delete operation
          </Button>
        </MutationForm>
      </div>
    </div>
  );
}

function OperationRow({ operation }: { operation: Operation }) {
  return (
    <TableRow>
      <TableCell className="mono whitespace-nowrap align-top text-xs">
        {operation.started_at ? (
          <time dateTime={operation.started_at}>
            {operation.started_at.replace("T", " ").slice(0, 16)}
          </time>
        ) : (
          <span className="muted">No start time</span>
        )}
        <span className="muted my-1 block">to</span>
        {operation.ended_at ? (
          <time dateTime={operation.ended_at}>
            {operation.ended_at.replace("T", " ").slice(0, 16)}
          </time>
        ) : (
          <span className="muted">No end time</span>
        )}
      </TableCell>
      <TableCell className="mono max-w-56 align-top break-words">
        <div>{operation.source || "—"}</div>
        <div className="muted" aria-label="to">
          →
        </div>
        <div>{operation.destination || "—"}</div>
      </TableCell>
      <TableCell className="mono align-top">
        {operation.tool || <span className="muted">—</span>}
      </TableCell>
      <TableCell className="mono max-w-40 align-top break-words">
        {operation.user_context || <span className="muted">—</span>}
      </TableCell>
      <TableCell className="min-w-56 max-w-md align-top">
        <pre
          className="mono line-clamp-4 whitespace-pre-wrap break-all text-sm"
          title={operation.command}
        >
          {operation.command}
        </pre>
        {operation.description && (
          <p className="muted mt-2 line-clamp-2 whitespace-pre-wrap text-xs">
            {operation.description}
          </p>
        )}
        <div className="muted mt-2 flex flex-wrap gap-x-3 text-xs">
          {operation.output && <span>Output recorded</span>}
          {operation.comments && <span>Comments recorded</span>}
        </div>
      </TableCell>
      <TableCell className="max-w-48 align-top">
        <div className="flex flex-wrap gap-1">
          {operation.tags.length ? (
            operation.tags.map((tag, index) => (
              <Badge key={`${tag}-${index}`} variant="secondary">
                {tag}
              </Badge>
            ))
          ) : (
            <span className="muted">—</span>
          )}
        </div>
      </TableCell>
      <TableCell className="max-w-48 align-top">
        {operation.attachment_name ? (
          <a
            href={`/operations/${operation.id}/attachment`}
            className="break-all text-sm underline underline-offset-4"
            download
          >
            {operation.attachment_name}
          </a>
        ) : (
          <span className="muted">—</span>
        )}
      </TableCell>
      <TableCell className="align-top">
        <Modal
          title={`Operation #${operation.id}`}
          trigger={
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-label={`View or edit operation ${operation.id}`}
            >
              View / edit
            </Button>
          }
        >
          <OperationEditor operation={operation} />
        </Modal>
      </TableCell>
    </TableRow>
  );
}

export function OperationsPage({ data }: { data: PageData }) {
  const operations = data.operations ?? [];
  return (
    <div className="stack">
      <PageHeader
        title="Operation log"
        description="A searchable timeline of commands, context, output, and evidence."
      >
        <Modal
          title="Add operation"
          trigger={<Button type="button">Add operation</Button>}
        >
          <MutationForm action="/operations">
            <OperationFields />
            <div className="actions mt-4 justify-end">
              <Button type="submit">Add operation</Button>
            </div>
          </MutationForm>
        </Modal>
      </PageHeader>
      <Filters>
        <div className="min-w-64 flex-1">
          <Field
            label="Search operations"
            name="q"
            type="search"
            defaultValue={data.q}
            placeholder="Command, endpoint, tool, tag, attachment"
          />
        </div>
        <input type="hidden" name="page" value="1" />
        <SelectField
          label="Rows per page"
          name="per"
          defaultValue={data.per ?? "25"}
          options={(data.per_page_choices ?? ["10", "25", "50", "all"]).map(
            (value) => ({ value, label: value === "all" ? "All" : value }),
          )}
        />
        <Button type="submit">Search</Button>
        {data.q && (
          <a
            href="/operations"
            className="self-end pb-2 text-sm underline underline-offset-4"
          >
            Clear search
          </a>
        )}
      </Filters>
      <p className="muted text-sm" role="status">
        {data.total ?? operations.length} matched operation
        {(data.total ?? operations.length) === 1 ? "" : "s"}
      </p>
      {operations.length ? (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <Table className="data-table">
            <TableHeader>
              <TableRow>
                <TableHead>Start / end</TableHead>
                <TableHead>Source → destination</TableHead>
                <TableHead>Tool</TableHead>
                <TableHead>User context</TableHead>
                <TableHead>Command</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>Attachment</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {operations.map((operation) => (
                <OperationRow key={operation.id} operation={operation} />
              ))}
            </TableBody>
          </Table>
        </div>
      ) : (
        <Empty>
          {data.q ? (
            <>No operations match “{data.q}”.</>
          ) : (
            "No operations recorded yet. Add the command or action that started your timeline."
          )}
        </Empty>
      )}
      <Pager
        data={{
          page: data.page ?? 1,
          pages: data.pages ?? 1,
          per: data.per ?? "25",
        }}
        total={data.total}
      />
    </div>
  );
}
