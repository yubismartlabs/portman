import { invoke } from "@tauri-apps/api/core";
import type { ExecutableInspection, InstanceAnomaly, Listener, ProcessMetrics, ProcessThread, RemoteConnection, SandboxStatus, StopResult, StopRisk } from "./types";

const inTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const portmanApi = {
  list: () => inTauri() ? invoke<Listener[]>("list_listeners") : Promise.resolve<Listener[]>([]),
  stop: (pid: number) => invoke<StopResult>("stop_listener", { pid }),
  forceStop: (pid: number) => invoke<StopResult>("force_stop_listener", { pid }),
  metrics: (pid: number) => invoke<ProcessMetrics>("process_metrics", { pid }),
  threads: (pid: number) => inTauri() ? invoke<ProcessThread[]>("process_threads", { pid }) : Promise.resolve<ProcessThread[]>([]),
  inspectExecutable: (path: string) => invoke<ExecutableInspection>("inspect_executable", { path }),
  anomalies: (pids: number[]) => inTauri() ? invoke<InstanceAnomaly[]>("instance_anomalies", { pids }) : Promise.resolve<InstanceAnomaly[]>([]),
  stopRisk: (pid: number) => inTauri() ? invoke<StopRisk>("stop_risk", { pid }) : Promise.resolve<StopRisk>({ level: "low", score: 0, blocked: false, reasons: [], consequence: "", previousStops: 0 }),
  outboundConnections: (pid: number) => invoke<RemoteConnection[]>("outbound_connections", { pid }),
  sandboxStatus: () => inTauri()
    ? invoke<SandboxStatus>("process_sandbox_status")
    : Promise.resolve<SandboxStatus>({ environment: "Browser preview", level: "process", details: "The web preview runs within the browser security sandbox.", indicators: ["Browser context"] }),
  open: (listener: Listener) => inTauri()
    ? invoke<string>("open_listener", { listener })
    : Promise.resolve(window.open(`http://127.0.0.1:${listener.port}`, "_blank")).then(() => ""),
};
