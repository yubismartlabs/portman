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

export type GeoLocation = { city: string; country: string; latitude: number; longitude: number };
export type RemoteConnection = { remoteIp: string; remotePort: number; location: GeoLocation | null };

export type IsolationLevel = "none" | "process" | "container" | "virtualized";
export type SandboxStatus = {
  environment: string;
  level: IsolationLevel;
  details: string;
  indicators: string[];
};
