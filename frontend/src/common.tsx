import {
  createContext,
  useContext,
  useId,
  useState,
  isValidElement,
  Fragment,
  type ReactNode,
  type InputHTMLAttributes,
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

export const PageContext = createContext<{
  data: PageData;
  refresh: () => Promise<void>;
  navigate: (url: string) => void;
} | null>(null);
const CloseModal = createContext<(() => void) | null>(null);
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
  return (
    <label
      className="grid min-w-0 gap-1.5 text-sm font-medium"
      htmlFor={children ? undefined : id}
    >
      <span>{label}</span>
      {children ?? <Input id={id} {...props} />}
    </label>
  );
}
export function SelectField({
  label,
  name,
  defaultValue,
  options,
  empty,
}: {
  label: string;
  name: string;
  defaultValue?: string | number;
  options: (string | { value: string; label: string })[];
  empty?: string;
}) {
  return (
    <Field label={label}>
      <NativeSelect name={name} defaultValue={defaultValue} className="w-full">
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
}: {
  title: string;
  trigger: ReactNode;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          isValidElement(trigger) && trigger.type !== Fragment ? (
            trigger
          ) : (
            <Button variant="outline">{trigger}</Button>
          )
        }
      />
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription className="sr-only">{title} form</DialogDescription>
        <CloseModal.Provider value={() => setOpen(false)}>
          {children}
        </CloseModal.Provider>
      </DialogContent>
    </Dialog>
  );
}
export function MutationForm({
  action,
  children,
  onSuccess,
  confirm: confirmation,
  className = "stack",
}: {
  action: string;
  children: ReactNode;
  onSuccess?: (response: Response) => void | Promise<void>;
  confirm?: string;
  className?: string;
}) {
  const { refresh, navigate } = usePage();
  const close = useContext(CloseModal);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <form
      action={action}
      method="post"
      encType="multipart/form-data"
      className={className}
      onSubmit={async (event) => {
        event.preventDefault();
        if (busy || (confirmation && !window.confirm(confirmation))) return;
        const form = event.currentTarget;
        const body = new FormData(form);
        setBusy(true);
        setError("");
        try {
          const response = await fetch(action, {
            method: "POST",
            body,
            headers: { Accept: "application/json" },
          });
          if (!response.ok) {
            const text = await response.text();
            let message = text;
            try {
              const parsed = JSON.parse(text) as { detail?: unknown };
              message =
                typeof parsed.detail === "string"
                  ? parsed.detail
                  : JSON.stringify(parsed.detail ?? parsed);
            } catch {
              message =
                new DOMParser().parseFromString(text, "text/html").body
                  .textContent || text;
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
          setError(reason instanceof Error ? reason.message : "Request failed");
        } finally {
          setBusy(false);
        }
      }}
    >
      <fieldset disabled={busy} className="contents">
        {children}
      </fieldset>
      {busy && (
        <p role="status" className="muted text-sm">
          Saving…
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
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
