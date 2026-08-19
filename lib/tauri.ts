import { invoke } from "@tauri-apps/api/core";
import type { Listener, ProcessMetrics, RemoteConnection, SandboxStatus, StopResult } from "./types";

const inTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const portmanApi = {
  list: () => inTauri() ? invoke<Listener[]>("list_listeners") : Promise.resolve<Listener[]>([]),
  stop: (pid: number) => invoke<StopResult>("stop_listener", { pid }),
  forceStop: (pid: number) => invoke<StopResult>("force_stop_listener", { pid }),
  metrics: (pid: number) => invoke<ProcessMetrics>("process_metrics", { pid }),
  outboundConnections: (pid: number) => invoke<RemoteConnection[]>("outbound_connections", { pid }),
  sandboxStatus: () => inTauri()
    ? invoke<SandboxStatus>("process_sandbox_status")
    : Promise.resolve<SandboxStatus>({ environment: "Browser preview", level: "process", details: "The web preview runs within the browser security sandbox.", indicators: ["Browser context"] }),
  open: (listener: Listener) => inTauri()
    ? invoke<string>("open_listener", { listener })
    : Promise.resolve(window.open(`http://127.0.0.1:${listener.port}`, "_blank")).then(() => ""),
};
