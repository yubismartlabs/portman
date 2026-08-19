import { invoke } from "@tauri-apps/api/core";
import type { ExecutableInspection, ExecutionWatcherStatus, InstanceAnomaly, Listener, MemoryGuardStatus, ProcessMetrics, ProcessThread, QuarantineEntry, RemoteConnection, SandboxStatus, StopResult, StopRisk, SystemPosture } from "./types";

const inTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
let previewMemoryGuard = false;
let previewWatcher = { enabled: false, autoPause: false };

export const portmanApi = {
  isNative: inTauri,
  list: () => inTauri() ? invoke<Listener[]>("list_listeners") : Promise.resolve<Listener[]>([]),
  stop: (pid: number) => invoke<StopResult>("stop_listener", { pid }),
  forceStop: (pid: number) => invoke<StopResult>("force_stop_listener", { pid }),
  metrics: (pid: number) => invoke<ProcessMetrics>("process_metrics", { pid }),
  threads: (pid: number) => inTauri() ? invoke<ProcessThread[]>("process_threads", { pid }) : Promise.resolve<ProcessThread[]>([]),
  inspectExecutable: (path: string) => invoke<ExecutableInspection>("inspect_executable", { path }),
  anomalies: (pids: number[]) => inTauri() ? invoke<InstanceAnomaly[]>("instance_anomalies", { pids }) : Promise.resolve<InstanceAnomaly[]>([]),
  stopRisk: (pid: number) => inTauri() ? invoke<StopRisk>("stop_risk", { pid }) : Promise.resolve<StopRisk>({ level: "low", score: 0, blocked: false, reasons: [], consequence: "", previousStops: 0 }),
  memoryGuard: () => inTauri() ? invoke<MemoryGuardStatus>("memory_guard_status") : Promise.resolve<MemoryGuardStatus>({ enabled: false, thresholdPercent: 95 }),
  setMemoryGuard: (enabled: boolean) => {
    if (inTauri()) return invoke<MemoryGuardStatus>("set_memory_guard", { enabled });
    previewMemoryGuard = enabled;
    return Promise.resolve<MemoryGuardStatus>({ enabled: previewMemoryGuard, thresholdPercent: 95 });
  },
  executionWatcher: () => inTauri() ? invoke<ExecutionWatcherStatus>("execution_watcher_status") : Promise.resolve<ExecutionWatcherStatus>({ enabled: false, autoPause: false, platformMode: "Browser preview" }),
  setExecutionWatcher: (enabled: boolean, autoPause: boolean) => {
    if (inTauri()) return invoke<ExecutionWatcherStatus>("set_execution_watcher", { enabled, autoPause });
    previewWatcher = { enabled, autoPause };
    return Promise.resolve<ExecutionWatcherStatus>({ ...previewWatcher, platformMode: "Browser preview" });
  },
  quarantined: () => inTauri() ? invoke<QuarantineEntry[]>("quarantined_processes") : Promise.resolve<QuarantineEntry[]>([]),
  resumeQuarantined: (pid: number) => invoke<StopResult>("resume_quarantined", { pid }),
  posture: () => inTauri() ? invoke<SystemPosture>("system_posture") : Promise.resolve<SystemPosture>({ score: 0, platform: "Browser preview", checks: [] }),
  applyPostureFix: (id: string) => invoke<string>("apply_posture_fix", { id }),
  resume: (pid: number) => invoke<StopResult>("resume_listener", { pid }),
  outboundConnections: (pid: number) => invoke<RemoteConnection[]>("outbound_connections", { pid }),
  sandboxStatus: () => inTauri()
    ? invoke<SandboxStatus>("process_sandbox_status")
    : Promise.resolve<SandboxStatus>({ environment: "Browser preview", level: "process", details: "The web preview runs within the browser security sandbox.", indicators: ["Browser context"] }),
  open: (listener: Listener) => inTauri()
    ? invoke<string>("open_listener", { pid: listener.pid, port: listener.port })
    : Promise.resolve(window.open(`http://127.0.0.1:${listener.port}`, "_blank")).then(() => `http://127.0.0.1:${listener.port}`),
};
