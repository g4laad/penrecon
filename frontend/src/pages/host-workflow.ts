import type { PageData } from "../types";

export type HostSection = "services" | "notes" | "credentials" | "timeline";

export function isHostSection(value: unknown): value is HostSection {
  return value === "services" || value === "notes" || value === "credentials" || value === "timeline";
}

export function sectionFromHash(hash: string): HostSection {
  const section = hash.slice(1);
  return isHostSection(section) ? section : "services";
}

export type HostViewState = {
  hostId: number | undefined;
  section: HostSection;
  serviceId: number | undefined;
  noteId: number | undefined;
  credentialId: number | undefined;
};

export function initialHostView(data: PageData, section: HostSection): HostViewState {
  return {
    hostId: data.host?.id,
    section,
    serviceId: data.services?.[0]?.service_id,
    noteId: data.host_notes?.[0]?.id,
    credentialId: data.host_credentials?.[0]?.id,
  };
}

// Persist the fallback identity, not the missing identity: removed selections must
// not spring back if a later filter, page, or refresh includes the old item again.
export function reconcileHostView(state: HostViewState, data: PageData): HostViewState {
  if (state.hostId !== data.host?.id) return initialHostView(data, sectionFromHash(location.hash));
  const serviceId = data.services?.some((item) => item.service_id === state.serviceId)
    ? state.serviceId : data.services?.[0]?.service_id;
  const noteId = data.host_notes?.some((item) => item.id === state.noteId)
    ? state.noteId : data.host_notes?.[0]?.id;
  const credentialId = data.host_credentials?.some((item) => item.id === state.credentialId)
    ? state.credentialId : data.host_credentials?.[0]?.id;
  if (serviceId === state.serviceId && noteId === state.noteId && credentialId === state.credentialId) return state;
  return { ...state, serviceId, noteId, credentialId };
}

export type HostViewEvent =
  | { type: "section-changed"; section: HostSection }
  | { type: "service-selected"; id: number }
  | { type: "note-selected"; id: number }
  | { type: "credential-selected"; id: number }
  | { type: "linked-credential-opened"; id: number };

export function transitionHostView(state: HostViewState, event: HostViewEvent, data: PageData): HostViewState {
  const current = reconcileHostView(state, data);
  switch (event.type) {
    case "section-changed": return current.section === event.section ? current : { ...current, section: event.section };
    case "service-selected": return data.services?.some((item) => item.service_id === event.id) ? { ...current, serviceId: event.id } : current;
    case "note-selected": return data.host_notes?.some((item) => item.id === event.id) ? { ...current, noteId: event.id } : current;
    case "credential-selected": return data.host_credentials?.some((item) => item.id === event.id) ? { ...current, credentialId: event.id } : current;
    case "linked-credential-opened": return data.host_credentials?.some((item) => item.id === event.id) ? { ...current, credentialId: event.id, section: "credentials" } : current;
  }
}

export type HostCommand =
  | { type: "save-service-overrides" | "reset-service-overrides"; serviceId: number }
  | { type: "delete-service"; serviceId: number; label: string }
  | { type: "create-or-update-service" | "rename-host" | "add-hostname"; hostId: number }
  | { type: "delete-host"; hostId: number; label: string }
  | { type: "hide-hostname"; hostId: number; hostnameId: number; label: string }
  | { type: "save-host-triage" }
  | { type: "create-note" }
  | { type: "save-note"; noteId: number }
  | { type: "delete-note"; noteId: number; label: string }
  | { type: "save-linked-credential" | "delete-linked-credential-everywhere"; credentialId: number };

type HostCommandDescription = { action: string; confirm?: string };

export function describeHostCommand(command: HostCommand): HostCommandDescription {
  switch (command.type) {
    case "save-service-overrides": return { action: `/services/${command.serviceId}/edit` };
    case "reset-service-overrides": return { action: `/services/${command.serviceId}/edit`, confirm: "Reset all saved manual service values to the latest scan? Saved triage status and tags will be kept. Unsaved edits in this dialog will not be applied." };
    case "delete-service": return { action: `/services/${command.serviceId}/delete`, confirm: `Delete ${command.label} and its associated data? A future scan that sees it will re-add it.` };
    case "create-or-update-service": return { action: `/hosts/${command.hostId}/services` };
    case "rename-host": return { action: `/hosts/${command.hostId}/edit` };
    case "add-hostname": return { action: `/hosts/${command.hostId}/hostnames` };
    case "hide-hostname": return { action: `/hosts/${command.hostId}/hostnames/${command.hostnameId}/delete`, confirm: `Remove hostname ${command.label} from this host? It will stay hidden on future scans.` };
    case "delete-host": return { action: `/hosts/${command.hostId}/delete`, confirm: `Permanently delete host ${command.label} and all its services and notes? This cannot be undone.` };
    case "save-host-triage": return { action: "/annotation" };
    case "create-note": return { action: "/notes" };
    case "save-note": return { action: `/notes/${command.noteId}/edit` };
    case "delete-note": return { action: `/notes/${command.noteId}/delete`, confirm: `Delete note “${command.label}”? This cannot be undone.` };
    case "save-linked-credential": return { action: `/credentials/${command.credentialId}/edit` };
    case "delete-linked-credential-everywhere": return { action: `/credentials/${command.credentialId}/delete`, confirm: "Delete this credential and all its host and service links? This cannot be undone." };
  }
}
