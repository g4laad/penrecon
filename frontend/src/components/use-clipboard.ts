import { useLayoutEffect, useRef, useState } from "react";

type ClipboardStatus = "idle" | "pending" | "copied" | "error";
type ClipboardResult = "copied" | "error" | "superseded";
type ClipboardRequest = { identity: unknown; request: number; status: ClipboardStatus };

// Only the latest request for the current content may publish a result. A
// superseded failure must not reveal a different secret or replace newer copy feedback.
export function useClipboard(identity: unknown) {
  const owner = useRef(0);
  const currentIdentity = useRef(identity);
  const [state, setState] = useState<ClipboardRequest>({ identity, request: 0, status: "idle" });
  useLayoutEffect(() => {
    currentIdentity.current = identity;
    return () => { owner.current += 1; };
  }, [identity]);

  async function copy(text: string): Promise<ClipboardResult> {
    const request = ++owner.current;
    setState({ identity, request, status: "pending" });
    let result: "copied" | "error";
    try {
      await navigator.clipboard.writeText(text);
      result = "copied";
    } catch {
      result = "error";
    }
    if (owner.current !== request || currentIdentity.current !== identity) return "superseded";
    setState((current) => current.request === request
      ? { identity, request, status: result }
      : current);
    return result;
  }
  const status: ClipboardStatus = state.identity === identity ? state.status : "idle";
  return { status, copy };
}
