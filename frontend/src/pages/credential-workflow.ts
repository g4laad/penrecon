import type { Credential, Service } from "../types";

export type DraftValidity = "empty" | "valid";
export function credentialDraftValidity(username: string, secret: string): DraftValidity {
  return username.trim() || secret.trim() ? "valid" : "empty";
}

export type ServiceLoad =
  | { status: "loading"; request: symbol | null }
  | { status: "ready"; services: Service[] }
  | { status: "error" }
  | { status: "aborted" };

export interface CredentialTarget {
  attempt: number;
  selected: number[];
  load: ServiceLoad;
}
interface AssociationState {
  targets: Record<number, CredentialTarget>;
  nextAttempt: number;
}
export const initialAssociations: AssociationState = { targets: {}, nextAttempt: 0 };
export type AssociationEvent =
  | { type: "toggle-host"; hostId: number }
  | { type: "retain-hosts"; hostIds: Set<number> }
  | { type: "toggle-service"; hostId: number; serviceId: number }
  | { type: "retry"; hostId: number }
  | { type: "started"; hostId: number; attempt: number; request: symbol }
  | { type: "loaded"; hostId: number; attempt: number; request: symbol; services: Service[] }
  | { type: "failed" | "aborted"; hostId: number; attempt: number; request: symbol };

export function transitionAssociations(state: AssociationState, event: AssociationEvent): AssociationState {
  if (event.type === "retain-hosts") {
    const ids = Object.keys(state.targets).map(Number);
    if (ids.every((id) => event.hostIds.has(id))) return state;
    return { ...state, targets: Object.fromEntries(ids.filter((id) => event.hostIds.has(id)).map((id) => [id, state.targets[id]])) };
  }
  const target = state.targets[event.hostId];
  if (event.type === "toggle-host") {
    const targets = { ...state.targets };
    if (target) {
      delete targets[event.hostId];
      return { ...state, targets };
    }
    const attempt = state.nextAttempt + 1;
    targets[event.hostId] = { attempt, selected: [], load: { status: "loading", request: null } };
    return { targets, nextAttempt: attempt };
  }
  if (!target) return state;
  let next: CredentialTarget;
  if (event.type === "toggle-service") {
    if (target.load.status !== "ready" || !target.load.services.some((service) => service.service_id === event.serviceId)) return state;
    next = { ...target, selected: target.selected.includes(event.serviceId) ? target.selected.filter((id) => id !== event.serviceId) : [...target.selected, event.serviceId] };
  } else if (event.type === "retry") {
    if (target.load.status !== "error" && target.load.status !== "aborted") return state;
    const attempt = state.nextAttempt + 1;
    return { targets: { ...state.targets, [event.hostId]: { ...target, attempt, load: { status: "loading", request: null } } }, nextAttempt: attempt };
  } else {
    if (event.attempt !== target.attempt) return state;
    if (event.type === "started") {
      // Effect replay may restart an aborted attempt; a new token owns its result.
      if (target.load.status !== "loading" && target.load.status !== "aborted") return state;
      next = { ...target, load: { status: "loading", request: event.request } };
    } else {
      if (target.load.status !== "loading" || target.load.request !== event.request) return state;
      next = event.type === "loaded"
        ? { ...target, selected: target.selected.filter((id) => event.services.some((service) => service.service_id === id)), load: { status: "ready", services: event.services } }
        : { ...target, load: { status: event.type === "failed" ? "error" : "aborted" } };
    }
  }
  return { ...state, targets: { ...state.targets, [event.hostId]: next } };
}

export type AssociationReadiness = "ready" | "loading" | "blocked";
export function associationReadiness(targets: CredentialTarget[]): AssociationReadiness {
  if (targets.some((target) => target.load.status === "error" || target.load.status === "aborted")) return "blocked";
  return targets.some((target) => target.load.status === "loading") ? "loading" : "ready";
}

export type CredentialScope = "all" | "linked" | "unlinked" | "invalid";
export function resolveCredentialScope(value: string): CredentialScope {
  return !value ? "all" : value === "linked" || value === "unlinked" ? value : "invalid";
}

export type CredentialSelection =
  | { status: "selected"; credential: Credential }
  | { status: "empty" }
  | { status: "unavailable"; reason: "invalid" | "missing" | "filtered" };
export function resolveCredentialSelection(hash: string, all: Credential[], visible: Credential[]): CredentialSelection {
  if (!hash) return visible[0] ? { status: "selected", credential: visible[0] } : { status: "empty" };
  if (!/^#credential-\d+$/.test(hash)) return { status: "unavailable", reason: "invalid" };
  const credential = all.find((item) => hash === `#credential-${item.id}`);
  if (!credential) return { status: "unavailable", reason: "missing" };
  return visible.some((item) => item.id === credential.id)
    ? { status: "selected", credential }
    : { status: "unavailable", reason: "filtered" };
}
