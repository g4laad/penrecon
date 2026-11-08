import { useCallback, useEffect, useState } from "react";
import { engagementUrl } from "../common";
import type { Host } from "../types";
import { apiUrl } from "../lib/api";

type HostOption = Pick<Host, "id" | "ip">;

export interface HostOptions {
  status: "idle" | "loading" | "ready" | "error";
  hosts: HostOption[];
  load: () => void;
}

export function useHostOptions(active: boolean): HostOptions {
  const [state, setState] = useState<Omit<HostOptions, "load">>({ status: "idle", hosts: [] });
  const load = useCallback(() => {
    setState((current) => current.status === "idle" || current.status === "error"
      ? { ...current, status: "loading" }
      : current);
  }, []);
  useEffect(() => {
    if (active) load();
  }, [active, load]);
  useEffect(() => {
    if (state.status !== "loading") return;
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(apiUrl(engagementUrl("/options/hosts")), {
          headers: { Accept: "application/json" }, signal: controller.signal,
        });
        if (!response.ok) throw new Error("Unable to load hosts.");
        const options = await response.json() as { hosts: HostOption[] };
        if (!controller.signal.aborted) setState({ status: "ready", hosts: options.hosts });
      } catch {
        if (!controller.signal.aborted) setState((current) => ({ ...current, status: "error" }));
      }
    })();
    return () => controller.abort();
  }, [state.status]);
  return { ...state, load };
}
