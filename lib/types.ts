export type Binding = { address: string; isLocalhost: boolean };
export type BinaryTrust = "trusted" | "signed" | "unsigned" | "unknown";
export type Listener = {
  id: string;
  pid: number;
  processName: string;
  command: string;
  owner: string;
  port: number;
  bindings: Binding[];
  binaryTrust: BinaryTrust;
  isProtected: boolean;
  canStop: boolean;
};

export type StopResult = { stopped: boolean; requiresForce: boolean; message: string };

export type ProcessMetrics = {
  cpuPercent: number;
  memoryBytes: number;
  readBytesPerSec: number;
  writeBytesPerSec: number;
};

export type ProcessThread = { id: number; name: string; cpuPercent: number };

export type ExecutableInstance = { pid: number; path: string; state: string; ports: number[] };
export type ExecutableInspection = { name: string; path: string; isExecutable: boolean; instances: ExecutableInstance[] };

export type InstanceAnomaly = { pid: number; score: number; baselineSamples: number; isAnomalous: boolean; summary: string; cpuPercent: number; memoryBytes: number; outboundConnections: number; novelRemoteConnections: number };
export type StopRisk = { level: "low" | "medium" | "critical"; score: number; blocked: boolean; reasons: string[]; consequence: string; previousStops: number };
export type MemoryGuardStatus = { enabled: boolean; thresholdPercent: number };
export type MemoryGuardAlert = { pid: number; processName: string; memoryBytes: number; totalMemoryBytes: number; utilizationPercent: number };
export type ExecutionWatcherStatus = { enabled: boolean; autoPause: boolean; platformMode: string };
export type QuarantineEntry = { id: number; pid: number; processName: string; path: string; sha256: string; reasons: string[]; detectedAt: number; state: "detected" | "paused" | "resumed"; canResume: boolean };

export type GeoLocation = { city: string; country: string; latitude: number; longitude: number };
export type RemoteConnection = { remoteIp: string; remotePort: number; location: GeoLocation | null };

export type IsolationLevel = "none" | "process" | "container" | "virtualized";
export type SandboxStatus = {
  environment: string;
  level: IsolationLevel;
  details: string;
  indicators: string[];
};
