import { useEffect, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { engagementUrl } from "../common";

type DetailState<T> = {
  url: string;
  revision: object;
  attempt: number;
} & ({ status: "ready"; value: T } | { status: "error" });

/** A refreshed list invalidates its detail, even when selection stays unchanged. */
export function SelectedDetail<T>({ url, revision, label, children }: {
  url: string;
  revision: object;
  label: string;
  children: (value: T) => ReactNode;
}) {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<DetailState<T> | null>(null);
  const current = state?.url === url && state.revision === revision && state.attempt === attempt
    ? state : null;
  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(engagementUrl(url), {
          headers: { Accept: "application/json" },
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Unable to load ${label}.`);
        const value = await response.json() as T;
        if (!controller.signal.aborted) setState({ url, revision, attempt, status: "ready", value });
      } catch {
        if (!controller.signal.aborted) setState({ url, revision, attempt, status: "error" });
      }
    })();
    return () => controller.abort();
  }, [url, revision, attempt, label]);
  return <div className="contents">
    <p role="status" className={current ? "sr-only" : "muted p-3 text-sm"}>
      {!current ? `Loading ${label}…` : ""}
    </p>
    {current?.status === "error" && <div className="stack p-3">
      <p role="alert" className="text-sm text-destructive">Unable to load {label}. Retry to load the current details.</p>
      <Button type="button" variant="outline" size="sm" onClick={() => setAttempt((value) => value + 1)}>Retry {label}</Button>
    </div>}
    {current?.status === "ready" && children(current.value)}
  </div>;
}
