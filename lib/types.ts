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
