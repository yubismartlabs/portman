import { describe, expect, it } from "vitest";
import { filterAndSortListeners, listenerHttpUrl } from "./listeners";
import type { Listener } from "./types";

const records: Listener[] = [
  { id: "2:5173", pid: 2, processName: "vite", command: "vite --host", owner: "501", port: 5173, bindings: [{ address: "*", isLocalhost: false }], binaryTrust: "trusted", isProtected: false, canStop: true },
  { id: "1:3000", pid: 1, processName: "next", command: "next dev", owner: "501", port: 3000, bindings: [{ address: "127.0.0.1", isLocalhost: true }], binaryTrust: "unsigned", isProtected: false, canStop: true },
];

describe("filterAndSortListeners", () => {
  it("limits to localhost bindings and sorts by port", () => expect(filterAndSortListeners(records, "", "localhost", "port").map((item) => item.port)).toEqual([3000]));
  it("searches command/process data and sorts by name", () => expect(filterAndSortListeners(records, "host", "all", "name").map((item) => item.processName)).toEqual(["vite"]));
  it("builds browser-safe URLs for wildcard and IPv6 listeners", () => {
    expect(listenerHttpUrl(records[0])).toBe("http://127.0.0.1:5173");
    expect(listenerHttpUrl({ ...records[1], bindings: [{ address: "::1", isLocalhost: true }] })).toBe("http://[::1]:3000");
  });
});
