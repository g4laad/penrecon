import {
  createContext,
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
} | null>(null);
const CloseModal = createContext<(() => void) | null>(null);
const FieldErrors = createContext<Record<string, string>>({});
export function usePage() {
  const value = useContext(PageContext);
  if (!value) throw new Error("Missing page context");
  return value;
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
export function Modal({
  title,
  trigger,
  children,
  protectChanges = false,
  className,
}: {
  title: string;
  trigger: ReactNode;
  children: ReactNode;
  protectChanges?: boolean | string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [dirty, setDirty] = useState(false);
  const content = useRef<HTMLDivElement>(null);
  const initialForms = useRef<string[]>([]);
  const snapshot = (root: HTMLDivElement) =>
    Array.from(root.querySelectorAll("form"), (form) =>
      JSON.stringify(Array.from(new FormData(form).entries())),
    );
  useEffect(() => {
    if (!protectChanges || !dirty) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty, protectChanges]);
  const captureContent = useCallback((node: HTMLDivElement | null) => {
    content.current = node;
    if (node && protectChanges) {
      initialForms.current = Array.from(node.querySelectorAll("form"), (form) =>
        JSON.stringify(Array.from(new FormData(form).entries())),
      );
    }
  }, [protectChanges]);
  return (
    <Dialog open={open} onOpenChange={(nextOpen) => {
      if (!nextOpen && protectChanges) {
        if (content.current?.querySelector("fieldset:disabled")) return;
        if (dirty && !window.confirm(typeof protectChanges === "string" ? protectChanges : "Discard unsaved note changes?")) return;
      }
      setDirty(false);
      setOpen(nextOpen);
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
        <CloseModal.Provider value={() => { setDirty(false); setOpen(false); }}>
          <Suspense fallback={<p role="status" className="muted text-sm">Loading form…</p>}>
          <div
            ref={captureContent}
            className="contents"
            onInput={protectChanges ? () => {
              if (content.current) {
                setDirty(JSON.stringify(snapshot(content.current)) !== JSON.stringify(initialForms.current));
              }
            } : undefined}
          >
            {children}
          </div>
          </Suspense>
        </CloseModal.Provider>
      </DialogContent>
    </Dialog>
  );
}
const saveRecoveryMessage =
  "Save could not be confirmed. Check that the local penrecon server is running and your connection is available before trying again.";

export function MutationForm({
  action,
  children,
  onSuccess,
  confirm: confirmation,
  className = "stack",
  encType = "multipart/form-data",
}: {
  action: string;
  children: ReactNode;
  onSuccess?: (response: Response) => void | Promise<void>;
  confirm?: string;
  className?: string;
  encType?: "multipart/form-data" | "application/x-www-form-urlencoded";
}) {
  const { refresh, navigate } = usePage();
  const close = useContext(CloseModal);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const formRef = useRef<HTMLFormElement>(null);
  useEffect(() => {
    if (!busy && Object.keys(fieldErrors).length) {
      formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
    }
  }, [busy, fieldErrors]);
  return (
    <form
      ref={formRef}
      action={engagementUrl(action)}
      method="post"
      encType={encType}
      className={className}
      onSubmit={async (event) => {
        event.preventDefault();
        if (busy || (confirmation && !window.confirm(confirmation))) return;
        const form = event.currentTarget;
        const body = new FormData(form);
        setBusy(true);
        setError("");
        setFieldErrors({});
        try {
          const response = await fetch(engagementUrl(action), {
            method: "POST",
            // Multipart serialization normalizes newlines to CRLF. Text-only
            // Markdown forms use URL encoding to preserve their exact source.
            body: encType === "application/x-www-form-urlencoded"
              ? new URLSearchParams(Array.from(body, ([key, value]) => [key, String(value)]))
              : body,
            headers: { Accept: "application/json" },
          });
          if (!response.ok) {
            const text = await response.text();
            let message = saveRecoveryMessage;
            try {
              const parsed = JSON.parse(text) as { detail?: unknown; field_errors?: Record<string, string> };
              setFieldErrors(parsed.field_errors ?? {});
              message =
                typeof parsed.detail === "string"
                  ? parsed.detail
                  : saveRecoveryMessage;
            } catch {
              // Unstructured server responses do not provide recovery instructions.
              message = saveRecoveryMessage;
            }
            throw new Error(message);
          }
          if (onSuccess) await onSuccess(response);
          else if (
            response.redirected &&
            new URL(response.url).pathname !== location.pathname
          )
            navigate(response.url);
          else {
            await refresh();
            form.reset();
          }
          close?.();
        } catch (reason) {
          setError(reason instanceof TypeError || !(reason instanceof Error)
            ? saveRecoveryMessage
            : reason.message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <FieldErrors.Provider value={fieldErrors}>
        <fieldset disabled={busy} className="contents">
          {children}
        </fieldset>
      </FieldErrors.Provider>
      {busy && (
        <p role="status" className="muted text-sm">
          Saving…
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {Object.keys(fieldErrors).length ? "Correct the highlighted fields and submit again." : error}
        </p>
      )}
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
