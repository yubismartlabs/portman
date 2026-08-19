import type { Listener } from "./types";

export type ListenerFilter = "all" | "localhost";
export type ListenerSort = "port" | "name";

export function listenerAddress(listener: Listener) { return listener.bindings.map((binding) => binding.address).join(", "); }

export function filterAndSortListeners(listeners: Listener[], query: string, filter: ListenerFilter, sort: ListenerSort) {
  const normalized = query.toLowerCase();
  return listeners.filter((listener) => {
    const haystack = `${listener.processName} ${listener.command} ${listener.owner} ${listener.port} ${listenerAddress(listener)}`.toLowerCase();
    return haystack.includes(normalized) && (filter === "all" || listener.bindings.some((binding) => binding.isLocalhost));
  }).sort((a, b) => sort === "port" ? a.port - b.port || a.pid - b.pid : a.processName.localeCompare(b.processName));
}
