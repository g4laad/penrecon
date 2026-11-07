import {
  createContext,
  Component,
  useContext,
  useId,
  useState,
  useEffect,
  useRef,
  useCallback,
  isValidElement,
  Fragment,
  Suspense,
  type ReactNode,
  type InputHTMLAttributes,
  type ComponentProps,
} from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  NativeSelect,
  NativeSelectOption,
} from "@/components/ui/native-select";
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import type { PageData } from "./types";

/** Scope domain URLs to this tab's explicit engagement URL, never global state. */
export function engagementUrl(url: string): string {
  if (!url.startsWith("/") || url.startsWith("//") ||
      /^\/(?:e|engagements)(?:\/|[?#]|$)/.test(url)) return url;
  const match = location.pathname.match(/^\/e\/([^/]+)(?:\/|$)/);
  if (!match) throw new Error("Domain navigation requires an engagement");
  return `/e/${match[1]}${url}`;
}

export function ScopedLink({ href, ...props }: ComponentProps<"a">) {
  return <a {...props} href={href === undefined ? undefined : engagementUrl(href)} />;
}

export const PageContext = createContext<{
  data: PageData;
  refresh: () => Promise<void>;
  navigate: (url: string) => void;
  updateQuery: (url: string) => void;
  queryPending: boolean;
  notify: (message: string) => void;
} | null>(null);
const CloseModal = createContext<{ close: () => void; committed: () => void } | null>(null);
const FieldErrors = createContext<Record<string, string>>({});
export function usePage() {
  const value = useContext(PageContext);
  if (!value) throw new Error("Missing page context");
  return value;
}

/** Keep ordinary link behavior for modified clicks and other destinations. */
export function QueryLink({ href, onClick, ...props }: ComponentProps<"a">) {
  const { updateQuery } = usePage();
  return <a {...props} href={href} onClick={(event) => {
    onClick?.(event);
    if (event.defaultPrevented || event.button !== 0 || event.metaKey ||
        event.ctrlKey || event.shiftKey || event.altKey || props.download !== undefined ||
        (props.target && props.target !== "_self") || !href) return;
    const target = new URL(href, location.href);
    if (target.origin !== location.origin || target.pathname !== location.pathname) return;
    event.preventDefault();
    updateQuery(target.href);
  }} />;
}
export function Field({
  label,
  children,
  ...props
}: {
  label: string;
  children?: ReactNode;
} & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  const errors = useContext(FieldErrors);
  const error = props.name ? errors[props.name] : undefined;
  const errorId = `${id}-error`;
  return (
    <div data-slot="field" className="grid min-w-0 gap-1.5 text-sm font-medium">
      <label className="grid min-w-0 gap-1.5" htmlFor={children ? undefined : id}>
        <span>{label}</span>
        {children ?? <Input
          id={id}
          {...props}
          aria-invalid={error ? true : props["aria-invalid"]}
          aria-describedby={[props["aria-describedby"], error ? errorId : undefined].filter(Boolean).join(" ") || undefined}
        />}
      </label>
      {error && <span id={errorId} className="text-sm font-normal text-destructive">{error}</span>}
    </div>
  );
}
export function SelectField({
  label,
  name,
  defaultValue,
  options,
  empty,
  required = false,
}: {
  label: string;
  name: string;
  defaultValue?: string | number;
  options: (string | { value: string; label: string })[];
  empty?: string;
  required?: boolean;
}) {
  return (
    <Field label={label}>
      <NativeSelect name={name} defaultValue={defaultValue} required={required} className="w-full">
        {empty !== undefined && (
          <NativeSelectOption value="">{empty}</NativeSelectOption>
        )}
        {options.map((option) => {
          const o =
            typeof option === "string"
              ? { value: option, label: option }
              : option;
          return (
            <NativeSelectOption key={o.value} value={o.value}>
              {o.label}
            </NativeSelectOption>
          );
        })}
      </NativeSelect>
    </Field>
  );
}
/** Lazy-load failures are recoverable navigation states, not a blank application. */
export class WorkflowBoundary extends Component<{ children: ReactNode }, { phase: "ready" | "failed" }> {
  state: { phase: "ready" | "failed" } = { phase: "ready" };

  static getDerivedStateFromError() {
    return { phase: "failed" as const };
  }

  render() {
    if (this.state.phase === "failed") {
      return <div role="alert" className="stack">
        <p>Unable to load this view. Reload the page to try again.</p>
        <Button type="button" variant="outline" onClick={() => location.reload()}>Reload page</Button>
      </div>;
    }
    return this.props.children;
  }
}

export function Modal({
  title,
  trigger,
  children,
  protectChanges = true,
  className,
}: {
  title: string;
  trigger: ReactNode;
  children: ReactNode;
  protectChanges?: boolean | string;
  className?: string;
}) {
  const [phase, setPhase] = useState<"closed" | "clean" | "dirty" | "committed">("closed");
  const open = phase !== "closed";
  const content = useRef<HTMLDivElement>(null);
  const initialForms = useRef<string[]>([]);
  const snapshot = useCallback((root: HTMLDivElement) =>
    Array.from(root.querySelectorAll("form"), (form) =>
      JSON.stringify({
        fields: Array.from(new FormData(form).entries(), ([name, value]) => [
          name,
          value instanceof File
            ? value.name ? [value.name, value.size, value.type, value.lastModified] : null
            : value,
        ]),
        // Incomplete controlled drafts may intentionally serialize no server
        // value, but still contain work that must be protected on dismissal.
        drafts: Array.from(form.querySelectorAll("[data-draft-value]"), (element) => element.getAttribute("data-draft-value")),
      }),
    ), []);
  const hasChanges = useCallback(() => content.current
    ? JSON.stringify(snapshot(content.current)) !== JSON.stringify(initialForms.current)
    : false, [snapshot]);
  const trackDraft = () => queueMicrotask(() => {
    const next = hasChanges() ? "dirty" : "clean";
    setPhase((current) => current === "closed" || current === "committed" ? current : next);
  });
  useEffect(() => {
    if (!protectChanges || !open || phase === "committed") return;
    const warn = (event: BeforeUnloadEvent) => {
      if (!hasChanges()) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [open, phase, protectChanges, hasChanges]);
  const captureContent = useCallback((node: HTMLDivElement | null) => {
    content.current = node;
    if (node && protectChanges) {
      initialForms.current = snapshot(node);
    }
  }, [protectChanges, snapshot]);
  return (
    <Dialog open={open} onOpenChange={(nextOpen) => {
      if (!nextOpen) {
        if (content.current?.querySelector('form[aria-busy="true"]')) return;
        if (protectChanges && phase !== "committed" && hasChanges() && !window.confirm(typeof protectChanges === "string" ? protectChanges : "Discard unsaved changes?")) return;
      }
      setPhase(nextOpen ? "clean" : "closed");
    }}>
      <DialogTrigger
        render={
          isValidElement(trigger) && trigger.type !== Fragment ? (
            trigger
          ) : (
            <Button variant="outline">{trigger}</Button>
          )
        }
      />
      <DialogContent className={`max-h-[90dvh] overflow-y-auto ${className ?? "sm:max-w-2xl"}`}>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription className="sr-only">{title} form</DialogDescription>
        <CloseModal.Provider value={{
          close: () => setPhase("closed"),
          committed: () => setPhase("committed"),
        }}>
          <WorkflowBoundary>
          <Suspense fallback={<p role="status" className="muted text-sm">Loading form…</p>}>
          <div
            ref={captureContent}
            className="contents"
            onInput={protectChanges ? trackDraft : undefined}
            onChange={protectChanges ? trackDraft : undefined}
          >
            {children}
          </div>
          </Suspense>
          </WorkflowBoundary>
        </CloseModal.Provider>
      </DialogContent>
    </Dialog>
  );
}
type MutationOutcome = {
  ok: true;
  redirect_to?: string;
  committed?: boolean;
  cleanup_pending?: boolean;
  detail?: string;
};

type MutationState =
  | { phase: "idle" | "saved" }
  | { phase: "submitting" | "checking-unconfirmed" }
  | { phase: "rejected"; message: string; fields: Record<string, string> }
  | { phase: "unconfirmed"; message: string }
  | { phase: "reconciling"; outcome: MutationOutcome }
  | { phase: "committed-refresh-failed"; outcome: MutationOutcome };

const saveRecoveryMessage =
  "Save could not be confirmed. Check the current data before deciding whether to submit again.";

export function MutationForm({
  action,
  children,
  confirm: confirmation,
  className = "stack",
  encType = "multipart/form-data",
  canSubmit = true,
}: {
  action: string;
  children: ReactNode;
  confirm?: string;
  className?: string;
  encType?: "multipart/form-data" | "application/x-www-form-urlencoded";
  canSubmit?: boolean;
}) {
  const { refresh, navigate, notify } = usePage();
  const modal = useContext(CloseModal);
  const [state, setState] = useState<MutationState>({ phase: "idle" });
  // Own the active operation synchronously, including two submits in one event turn.
  const operation = useRef<symbol | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const busy = state.phase === "submitting" || state.phase === "reconciling" || state.phase === "checking-unconfirmed";
  const editable = state.phase === "idle" || state.phase === "saved" || state.phase === "rejected";
  const fieldErrors = state.phase === "rejected" ? state.fields : {};
  useEffect(() => {
    if (state.phase === "rejected") {
      formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
    }
  }, [state]);

  async function reconcile(outcome: MutationOutcome) {
    setState({ phase: "reconciling", outcome });
    try {
      if (outcome.redirect_to && new URL(outcome.redirect_to, location.href).pathname !== location.pathname) {
        navigate(outcome.redirect_to);
      } else {
        await refresh();
        formRef.current?.reset();
      }
      setState({ phase: "saved" });
      modal?.close();
    } catch {
      // The POST already succeeded. Recovery must never submit it again.
      setState({ phase: "committed-refresh-failed", outcome });
    }
  }

  async function recover() {
    if (operation.current) return;
    operation.current = Symbol("recovery");
    try {
      if (state.phase === "committed-refresh-failed") await reconcile(state.outcome);
      else if (state.phase === "unconfirmed") {
        setState({ phase: "checking-unconfirmed" });
        try {
          await refresh();
          setState({ phase: "unconfirmed", message: "Current data loaded. Check whether your change was saved before submitting again." });
        } catch {
          setState({ phase: "unconfirmed", message: "Unable to load current data. Check that the local server is running, then check again." });
        }
      }
    } finally {
      operation.current = null;
    }
  }

  return (
    <form
      ref={formRef}
      action={engagementUrl(action)}
      method="post"
      encType={encType}
      className={className}
      data-mutation-state={state.phase}
      aria-busy={busy}
      onSubmit={async (event) => {
        event.preventDefault();
        if (operation.current || !editable) return;
        if (!canSubmit) {
          setState({ phase: "rejected", message: "Complete the required fields and wait for selected targets to load before saving.", fields: {} });
          return;
        }
        if (confirmation && !window.confirm(confirmation)) return;
        const body = new FormData(event.currentTarget);
        operation.current = Symbol("submission");
        setState({ phase: "submitting" });
        try {
          let response: Response;
          try {
            response = await fetch(engagementUrl(action), {
              method: "POST",
              redirect: "error",
              // URL encoding preserves exact Markdown newlines.
              body: encType === "application/x-www-form-urlencoded"
                ? new URLSearchParams(Array.from(body, ([key, value]) => [key, String(value)]))
                : body,
              headers: { Accept: "application/json" },
            });
          } catch {
            setState({ phase: "unconfirmed", message: saveRecoveryMessage });
            return;
          }
          if (!response.ok) {
            let message = response.status >= 500 ? saveRecoveryMessage : `Unable to save (${response.status}). Check the form and try again.`;
            let fields: Record<string, string> = {};
            try {
              const parsed = await response.json() as { detail?: unknown; field_errors?: unknown };
              if (typeof parsed.detail === "string") message = parsed.detail;
              if (parsed.field_errors && typeof parsed.field_errors === "object") {
                fields = Object.fromEntries(Object.entries(parsed.field_errors).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
              }
            } catch { /* Keep actionable fallback for unstructured responses. */ }
            setState(response.status >= 500
              ? { phase: "unconfirmed", message: saveRecoveryMessage }
              : { phase: "rejected", message, fields });
            return;
          }
          let outcome: MutationOutcome;
          try {
            outcome = await response.json() as MutationOutcome;
            if (outcome.ok !== true) throw new Error("Missing mutation confirmation");
          } catch {
            setState({ phase: "unconfirmed", message: saveRecoveryMessage });
            return;
          }
          if (outcome.committed === true && outcome.cleanup_pending === true && typeof outcome.detail === "string") {
            notify(outcome.detail);
          }
          modal?.committed();
          await reconcile(outcome);
        } finally {
          operation.current = null;
        }
      }}
    >
      <FieldErrors.Provider value={fieldErrors}>
        <fieldset disabled={!editable} className="contents">
          {children}
        </fieldset>
      </FieldErrors.Provider>
      <p role="status" className={busy ? "muted text-sm" : "sr-only"}>
        {state.phase === "submitting" ? "Saving…" : state.phase === "reconciling" ? "Saved. Updating view…" : state.phase === "checking-unconfirmed" ? "Checking current data…" : ""}
      </p>
      {state.phase === "rejected" && <p role="alert" className="text-sm text-destructive">
        {Object.keys(state.fields).length ? "Correct the highlighted fields and submit again." : state.message}
      </p>}
      {state.phase === "committed-refresh-failed" && <div role="alert" className="stack text-sm">
        <p>Saved, but the view could not be updated. Refresh the view without submitting again.</p>
        <Button type="button" variant="outline" onClick={() => void recover()}>Refresh view</Button>
      </div>}
      {state.phase === "unconfirmed" && <div role="alert" className="stack text-sm">
        <p>{state.message}</p>
        <div className="actions">
          <Button type="button" variant="outline" onClick={() => void recover()}>Check current data</Button>
          <Button type="button" variant="outline" onClick={() => {
            if (window.confirm("The earlier request may have saved. Submitting again could duplicate it. Return to editing?")) {
              setState({ phase: "idle" });
            }
          }}>Return to editing</Button>
        </div>
      </div>}
    </form>
  );
}
export function PageHeader({
  title,
  description,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <header className={children ? "mb-2 flex justify-end" : "sr-only"}>
      <div className="sr-only">
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children && <div className="actions">{children}</div>}
    </header>
  );
}
export function Section({
  title,
  children,
  action,
  id,
}: {
  title: ReactNode;
  children: ReactNode;
  action?: ReactNode;
  id?: string;
}) {
  return (
    <section id={id} className="page-section">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
export function Filters({ children }: { children: ReactNode }) {
  return (
    <form
      method="get"
      className="mb-3 flex flex-wrap items-end gap-2"
      role="search"
    >
      {children}
    </form>
  );
}
export function SortLink({
  column,
  children,
}: {
  column: string;
  children: ReactNode;
}) {
  const { data } = usePage();
  const params = new URLSearchParams(location.search);
  params.set("sort", column);
  params.set(
    "dir",
    data.sort === column && data.direction === "asc" ? "desc" : "asc",
  );
  params.set("page", "1");
  return (
    <a
      className="inline-flex items-center gap-1 hover:text-foreground"
      href={"?" + params.toString()}
    >
      {children}
      <span aria-hidden="true">
        {data.sort === column ? (data.direction === "desc" ? "↓" : "↑") : "↕"}
      </span>
    </a>
  );
}
export function Pager({
  data,
  total,
}: {
  data: Pick<PageData, "page" | "pages" | "per">;
  total?: number;
}) {
  const page = data.page ?? 1;
  const pages = data.pages ?? 1;
  function url(n: number) {
    const p = new URLSearchParams(location.search);
    p.set("page", String(n));
    return "?" + p.toString();
  }
  return (
    <nav
      aria-label="Pagination"
      className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs"
    >
      <span className="muted" aria-live="polite">
        {total !== undefined ? `${total} results · ` : ""}Page {page} of {pages}
      </span>
      <div className="flex flex-wrap items-end gap-2">
        <form method="get" className="flex flex-wrap items-end gap-2">
          {Array.from(new URLSearchParams(location.search))
            .filter(([key]) => key !== "per" && key !== "page")
            .map(([key, value], index) => (
              <input key={index} type="hidden" name={key} value={value} />
            ))}
          <SelectField
            label="Rows"
            name="per"
            defaultValue={data.per ?? "10"}
            options={["10", "25", "50", "all"]}
          />
          <Field
            label="Page"
            name="page"
            type="number"
            min={1}
            max={pages}
            defaultValue={page}
            className="w-20"
          />
          <Button type="submit" variant="outline">
            Go
          </Button>
        </form>
        <Button
          variant="outline"
          disabled={page <= 1}
          render={<a href={url(page - 1)} aria-label="Previous page" />}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          disabled={page >= pages}
          render={<a href={url(page + 1)} aria-label="Next page" />}
        >
          Next
        </Button>
      </div>
    </nav>
  );
}
