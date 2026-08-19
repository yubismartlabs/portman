"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import * as ContextMenu from "@radix-ui/react-context-menu";
import { Activity, ArrowUpDown, ChevronDown, CircleStop, Copy, ExternalLink, Globe2, Grid2X2, List, Loader2, LockKeyhole, RefreshCw, Search, Server, ShieldAlert, ShieldCheck, TerminalSquare, X } from "lucide-react";
import type { BinaryTrust, ExecutableInspection, Listener, ProcessMetrics, ProcessThread, RemoteConnection, SandboxStatus } from "@/lib/types";
import { filterAndSortListeners, listenerAddress } from "@/lib/listeners";
import { portmanApi } from "@/lib/tauri";
import { Button, Modal } from "@/components/ui";

type Filter = "all" | "localhost";
type Sort = "port" | "name";
type ViewMode = "list" | "grid";
const truncate = (value: string, max = 56) => value.length > max ? `${value.slice(0, max)}…` : value;
const statusLabel = (listener: Listener) => listener.isProtected ? "Protected" : "Running";
const trustLabel = (trust: BinaryTrust) => ({ trusted: "Trusted binary", signed: "Signed but untrusted binary", unsigned: "Unsigned binary", unknown: "Signature unavailable" })[trust];
function serviceKind(listener: Listener) { const text = `${listener.processName} ${listener.command}`.toLowerCase(); if (/(next|vite|node|bun|deno)/.test(text)) return "JavaScript service"; if (/(python|uvicorn|gunicorn|flask|django)/.test(text)) return "Python service"; if (/(postgres|mysql|redis|mongo)/.test(text)) return "Data service"; if (/(nginx|apache|caddy)/.test(text)) return "Web server"; return "Local service"; }

export function PortMan() {
  const [listeners, setListeners] = useState<Listener[]>([]);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [sort, setSort] = useState<Sort>("port");
  const [viewMode, setViewMode] = useState<ViewMode>("list");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [stopping, setStopping] = useState<Listener | null>(null);
  const [force, setForce] = useState<Listener | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [metrics, setMetrics] = useState<ProcessMetrics | null>(null);
  const [metricHistory, setMetricHistory] = useState<ProcessMetrics[]>([]);
  const [connections, setConnections] = useState<RemoteConnection[]>([]);
  const [sandboxStatus, setSandboxStatus] = useState<SandboxStatus | null>(null);
  const [droppedExecutable, setDroppedExecutable] = useState<ExecutableInspection | null>(null);
  const [dropError, setDropError] = useState("");

  const refresh = useCallback(async () => {
    setError("");
    try { setListeners(await portmanApi.list()); setLastUpdated(new Date()); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not scan local listeners."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { portmanApi.sandboxStatus().then(setSandboxStatus).catch(() => setSandboxStatus(null)); }, []);
  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    let unlisten: (() => void) | undefined;
    listen<Listener[]>("server-list-updated", (event) => { setListeners(event.payload); setLastUpdated(new Date()); }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);
  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    let unlistenScan: (() => void) | undefined; let unlistenAction: (() => void) | undefined;
    listen("shortcut-scan", () => { refresh(); setNotice("PortMan opened and listener scan refreshed."); }).then((fn) => { unlistenScan = fn; });
    listen<string>("shortcut-action", (event) => { setNotice(event.payload); refresh(); }).then((fn) => { unlistenAction = fn; });
    return () => { unlistenScan?.(); unlistenAction?.(); };
  }, [refresh]);
  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    let unlisten: (() => void) | undefined;
    getCurrentWebview().onDragDropEvent((event) => {
      if (event.payload.type !== "drop") return;
      const [path] = event.payload.paths;
      if (!path) return;
      setDropError("");
      portmanApi.inspectExecutable(path).then(setDroppedExecutable).catch((cause) => setDropError(cause instanceof Error ? cause.message : "Could not inspect the dropped file."));
    }).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);

  const visible = useMemo(() => filterAndSortListeners(listeners, query, filter, sort), [listeners, query, filter, sort]);
  const selected = listeners.find((listener) => listener.id === selectedId) ?? null;
  const manageable = listeners.filter((listener) => listener.canStop).length;

  useEffect(() => {
    if (!selected || !("__TAURI_INTERNALS__" in window)) { setMetrics(null); setMetricHistory([]); return; }
    let active = true;
    const sample = async () => {
      try {
        const next = await portmanApi.metrics(selected.pid);
        if (!active) return;
        setMetrics(next);
        setMetricHistory((history) => [...history, next].slice(-45));
      } catch { if (active) setMetrics(null); }
    };
    setMetrics(null); setMetricHistory([]); sample();
    const interval = window.setInterval(sample, 1000);
    return () => { active = false; window.clearInterval(interval); };
  }, [selected?.pid]);

  useEffect(() => {
    if (!selected || !("__TAURI_INTERNALS__" in window)) { setConnections([]); return; }
    let active = true;
    const refreshConnections = async () => { try { const next = await portmanApi.outboundConnections(selected.pid); if (active) setConnections(next); } catch { if (active) setConnections([]); } };
    refreshConnections(); const interval = window.setInterval(refreshConnections, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [selected?.pid]);

  async function terminate(listener: Listener, isForce = false) {
    setBusy(true); setNotice("");
    try {
      const result = isForce ? await portmanApi.forceStop(listener.pid) : await portmanApi.stop(listener.pid);
      setStopping(null); setForce(null);
      if (result.requiresForce) { setForce(listener); return; }
      setNotice(result.message); await refresh();
    } catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not stop the process."); }
    finally { setBusy(false); }
  }

  return <main className="desktop-shell">
    <header className="topbar"><div className="window-title" data-tauri-drag-region><Server size={15}/><b>Local listeners</b><span>{listeners.length} active</span></div><div className="title-drag-region" data-tauri-drag-region/><div className="title-search"><Search size={14}/><input aria-label="Search listeners" placeholder="Search processes, ports, or addresses" value={query} onChange={(event) => setQuery(event.target.value)}/>{query && <button onClick={() => setQuery("")}><X size={13}/></button>}</div><div className="topbar-actions"><span className="updated">{lastUpdated ? `Last scan ${lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "Connecting…"}</span><Button variant="ghost" onClick={refresh}><RefreshCw size={15}/> Refresh</Button></div></header>
    <div className="desktop-body">
    <aside className="app-sidebar">
      <div className="brand"><div className="brand-mark"><Activity size={19}/></div><div><b>PortMan</b><span>LOCAL SERVER MANAGER</span></div></div>
      <div className="sidebar-summary"><p>ACTIVE LISTENERS</p><b>{listeners.length}</b><span>{manageable} manageable by you</span></div>
      <div className="sidebar-section"><p>SCOPE</p><button className={filter === "all" ? "sidebar-filter active" : "sidebar-filter"} onClick={() => setFilter("all")}><i/>All interfaces</button><button className={filter === "localhost" ? "sidebar-filter active" : "sidebar-filter"} onClick={() => setFilter("localhost")}><i/>Localhost only</button></div>
      <div className="sidebar-spacer" />
      <div className="scanner-card"><span className="pulse"/><div><b>Scanner active</b><p>TCP · refreshes every second</p></div></div>
      {sandboxStatus && <div className={`isolation-card ${sandboxStatus.level}`} title={`${sandboxStatus.details}${sandboxStatus.indicators.length ? ` Indicators: ${sandboxStatus.indicators.join(", ")}` : ""}`}><ShieldCheck size={15}/><div><b>{sandboxStatus.environment}</b><p>Isolation: {sandboxStatus.level}</p></div></div>}
    </aside>
    <section className="workspace">
      <div className="workspace-content">
        {error && <div className="alert alert-error"><ShieldAlert size={17}/><span>{error}</span><Button className="ml-auto" variant="ghost" onClick={refresh}>Retry</Button></div>}
        {notice && <div className="alert"><Activity size={17}/><span>{notice}</span><button className="ml-auto" onClick={() => setNotice("")}><X size={15}/></button></div>}
        <section className={`main-panes ${selected ? "with-inspector" : ""}`}>
          <div className="listeners-pane">
            <div className="pane-title"><div><h2>Listener inventory</h2><p>{visible.length} of {listeners.length} shown</p></div><div className="pane-actions"><div className="view-toggle"><button className={viewMode === "list" ? "selected" : ""} aria-label="List view" onClick={() => setViewMode("list")}><List size={15}/></button><button className={viewMode === "grid" ? "selected" : ""} aria-label="Grid view" onClick={() => setViewMode("grid")}><Grid2X2 size={14}/></button></div><button className="icon-button" title="Toggle sort" onClick={() => setSort(sort === "port" ? "name" : "port")}><ArrowUpDown size={16}/></button></div></div>
            {viewMode === "list" && <div className="table-head"><span>Process</span><span>PID</span><span>Port</span><span>Address</span><span>Owner</span><span>Status</span></div>}
            <div className={viewMode === "grid" ? "listener-grid" : "listener-list"}>{loading ? <Empty icon={<Loader2 className="animate-spin"/>} title="Scanning local listeners" text="This only takes a moment."/> : visible.length === 0 ? <Empty icon={<Globe2/>} title="No matching listeners" text="Adjust filters or start a local server."/> : visible.map((listener) => <ListenerMenu key={listener.id} listener={listener} onStop={setStopping}>{viewMode === "grid" ? <ListenerTile listener={listener} selected={selected?.id === listener.id} onSelect={() => setSelectedId(listener.id)} /> : <button className={`listener-row ${selected?.id === listener.id ? "selected" : ""}`} onClick={() => setSelectedId(listener.id)}><span className="process-cell"><span className="process-icon"><TerminalSquare size={15}/></span><span><b>{listener.processName}<TrustMark trust={listener.binaryTrust}/></b><small title={listener.command}>{serviceKind(listener)} · {truncate(listener.command)}</small></span></span><span className="pid-cell">{listener.pid}</span><span className="port-cell">:{listener.port}</span><span className="binding-cell" title={listenerAddress(listener)}>{listenerAddress(listener)}</span><span className="owner-cell">{listener.owner}</span><span className={listener.isProtected ? "status protected" : "status"}><i/>{statusLabel(listener)}</span></button>}</ListenerMenu>)}</div>
          </div>
          {selected && <Inspector listener={selected} metrics={metrics} history={metricHistory} connections={connections} onClose={() => setSelectedId(null)} onStop={setStopping} />}
        </section>
      </div>
      <footer className="statusbar"><span><i className="pulse"/> Native scanner online</span><span>⌃⌥P: Show & scan</span><span>⌃⌥⇧K: Quit frontmost app</span><span>{sandboxStatus ? `Isolation: ${sandboxStatus.level}` : "Checking isolation…"}</span><span>Current user processes can be stopped</span></footer>
    </section>
    <Confirm listener={stopping} ports={listeners.filter((item) => item.pid === stopping?.pid).map((item) => item.port)} force={false} busy={busy} onClose={() => setStopping(null)} onConfirm={() => stopping && terminate(stopping)} />
    <Confirm listener={force} ports={listeners.filter((item) => item.pid === force?.pid).map((item) => item.port)} force busy={busy} onClose={() => setForce(null)} onConfirm={() => force && terminate(force, true)} />
    <ExecutableModal inspection={droppedExecutable} error={dropError} onClose={() => { setDroppedExecutable(null); setDropError(""); }} />
    </div>
  </main>;
}

function Empty({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) { return <div className="empty"><span>{icon}</span><b>{title}</b><p>{text}</p></div>; }
function ExecutableModal({ inspection, error, onClose }: { inspection: ExecutableInspection | null; error: string; onClose: () => void }) { const open = !!inspection || !!error; return <Modal open={open} onOpenChange={(value) => !value && onClose()} title="Dropped executable inspection">{error ? <p className="text-sm text-rose-300">{error}</p> : inspection && <div className="executable-inspection"><p className="section-label">EXECUTABLE</p><b>{inspection.name}</b><code>{inspection.path}</code>{!inspection.isExecutable ? <p className="drop-result">This file is not marked as executable.</p> : inspection.instances.length === 0 ? <p className="drop-result">No running instance found.</p> : <><p className="drop-result">{inspection.instances.length} running {inspection.instances.length === 1 ? "instance" : "instances"} found</p>{inspection.instances.map((instance) => <div className="executable-instance" key={instance.pid}><span><b>PID {instance.pid}</b><small>{instance.state}</small></span><code>{instance.path}</code><em>{instance.ports.length ? instance.ports.map((port) => `:${port}`).join(", ") : "No listening port"}</em></div>)}</>}</div>}</Modal>; }
function ListenerMenu({ listener, onStop, children }: { listener: Listener; onStop: (listener: Listener) => void; children: React.ReactNode }) {
  const primary = listener.bindings[0]?.address ?? "127.0.0.1";
  return <ContextMenu.Root><ContextMenu.Trigger asChild>{children}</ContextMenu.Trigger><ContextMenu.Portal><ContextMenu.Content className="context-menu"><ContextMenu.Label>Port {listener.port} · {listener.processName}</ContextMenu.Label><ContextMenu.Item onSelect={() => portmanApi.open(listener)}><ExternalLink size={14}/> Open in browser</ContextMenu.Item><ContextMenu.Item onSelect={() => navigator.clipboard.writeText(`http://${primary}:${listener.port}`)}><Copy size={14}/> Copy URL</ContextMenu.Item><ContextMenu.Item onSelect={() => navigator.clipboard.writeText(String(listener.port))}><Copy size={14}/> Copy port</ContextMenu.Item><ContextMenu.Separator/><ContextMenu.Item className="danger-item" disabled={!listener.canStop} onSelect={() => onStop(listener)}><CircleStop size={14}/> {listener.canStop ? "Stop process" : "Protected process"}</ContextMenu.Item></ContextMenu.Content></ContextMenu.Portal></ContextMenu.Root>;
}
function ListenerTile({ listener, selected, onSelect }: { listener: Listener; selected: boolean; onSelect: () => void }) { return <button className={`listener-tile ${selected ? "selected" : ""}`} onClick={onSelect}><div className="tile-head"><span className="process-icon"><TerminalSquare size={15}/></span><span className="tile-flags"><TrustMark trust={listener.binaryTrust}/><span className={listener.isProtected ? "status protected" : "status"}><i/>{statusLabel(listener)}</span></span></div><h3 className="tile-title" title={listener.processName}>{listener.processName}</h3><small title={listener.command}>{serviceKind(listener)} · {truncate(listener.command, 42)}</small><div className="tile-port">:{listener.port}</div><div className="tile-details"><span title={listenerAddress(listener)}>{listenerAddress(listener)}</span><span>PID {listener.pid} · {listener.owner}</span></div></button>; }
function Inspector({ listener, metrics, history, connections, onClose, onStop }: { listener: Listener; metrics: ProcessMetrics | null; history: ProcessMetrics[]; connections: RemoteConnection[]; onClose: () => void; onStop: (listener: Listener) => void }) {
  const primary = listener.bindings[0]?.address ?? "127.0.0.1";
  return <aside className="inspector"><div className="inspector-head"><div><p className="eyebrow">INSPECTOR</p><h2>{listener.processName}</h2><span className={listener.isProtected ? "status protected" : "status"}><i/>{statusLabel(listener)}</span></div><div className="inspector-top-actions"><span className="pid">PID {listener.pid}</span><button aria-label="Close inspector" onClick={onClose}><X size={14}/></button></div></div><div className="inspector-command"><p>COMMAND</p><code>{listener.command}</code></div><div className="inspector-section"><p className="section-label">CONNECTION</p><Info label="Detected" value={serviceKind(listener)}/><Info label="Binary" value={trustLabel(listener.binaryTrust)}/><Info label="Port" value={`:${listener.port}`}/><Info label="Bindings" value={listenerAddress(listener)}/><Info label="Owner" value={listener.owner}/></div><MetricsPanel metrics={metrics} history={history}/><ThreadList pid={listener.pid}/><ConnectionsMap connections={connections}/><div className="inspector-actions"><Button variant="ghost" onClick={() => navigator.clipboard.writeText(`http://${primary}:${listener.port}`)}><Copy size={15}/> Copy URL</Button><Button variant="ghost" onClick={() => portmanApi.open(listener)}><ExternalLink size={15}/> Open</Button>{listener.canStop ? <Button variant="danger" className="w-full" onClick={() => onStop(listener)}><CircleStop size={15}/> Stop process</Button> : <div className="protected-note"><LockKeyhole size={14}/> This process belongs to another user.</div>}</div></aside>;
}
function TrustMark({ trust }: { trust: BinaryTrust }) { return <span className={`trust-mark ${trust}`} title={trustLabel(trust)}>{trust === "trusted" ? <ShieldCheck size={13}/> : <ShieldAlert size={13}/>}</span>; }
function MetricsPanel({ metrics, history }: { metrics: ProcessMetrics | null; history: ProcessMetrics[] }) { const readWrite = metrics ? metrics.readBytesPerSec + metrics.writeBytesPerSec : 0; return <div className="metrics-panel"><p className="section-label">LIVE METRICS <span>1s</span></p><MetricGraph label="CPU" value={metrics ? `${metrics.cpuPercent.toFixed(1)}%` : "—"} points={history.map((item) => item.cpuPercent)} tone="cpu"/><MetricGraph label="Memory" value={metrics ? formatBytes(metrics.memoryBytes) : "—"} points={history.map((item) => item.memoryBytes)} tone="memory"/><MetricGraph label="Disk I/O" value={metrics ? `${formatBytes(readWrite)}/s` : "—"} points={history.map((item) => item.readBytesPerSec + item.writeBytesPerSec)} tone="disk"/></div>; }
function ThreadList({ pid }: { pid: number }) {
  const [expanded, setExpanded] = useState(false); const [threads, setThreads] = useState<ProcessThread[]>([]); const [error, setError] = useState("");
  useEffect(() => { if (!expanded) return; let active = true; const refresh = async () => { try { const next = await portmanApi.threads(pid); if (active) { setThreads(next); setError(""); } } catch { if (active) setError("Thread details are unavailable."); } }; refresh(); const timer = window.setInterval(refresh, 1000); return () => { active = false; window.clearInterval(timer); }; }, [expanded, pid]);
  return <section className="thread-list"><button className="thread-toggle" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded}><span><b>OS THREADS</b><small>{expanded ? `${threads.length} live · 1s` : "Expand individual CPU usage"}</small></span><ChevronDown size={15}/></button>{expanded && <div className="thread-table">{error ? <p className="thread-empty">{error}</p> : threads.length === 0 ? <p className="thread-empty">Loading threads…</p> : <>{threads.slice(0, 80).map((thread) => <div className="thread-row" key={thread.id}><span title={thread.name}>{thread.name}</span><code>TID {thread.id}</code><b>{thread.cpuPercent.toFixed(1)}%</b></div>)}{threads.length > 80 && <p className="thread-empty">Showing the 80 busiest of {threads.length} threads.</p>}</>}</div>}</section>;
}
function MetricGraph({ label, value, points, tone }: { label: string; value: string; points: number[]; tone: string }) { const max = Math.max(...points, 1); const chart = points.length < 2 ? "0,24 100,24" : points.map((point, index) => `${(index / (points.length - 1)) * 100},${24 - (point / max) * 20}`).join(" "); return <div className={`metric-graph ${tone}`}><div><span>{label}</span><b>{value}</b></div><svg viewBox="0 0 100 24" preserveAspectRatio="none" aria-label={`${label} history`}><polyline points={chart}/></svg></div>; }
function ConnectionsMap({ connections }: { connections: RemoteConnection[] }) { const located = connections.filter((connection) => connection.location); return <div className="connections-map"><p className="section-label">OUTBOUND GEO <span>{connections.length} live</span></p>{connections.length === 0 ? <p className="map-empty">No public outbound TCP connections.</p> : <><svg viewBox="0 0 180 90" aria-label="Remote connection locations"><path d="M0 22H180M0 45H180M0 68H180M45 0V90M90 0V90M135 0V90"/>{located.map((connection) => { const point = connection.location!; return <circle key={`${connection.remoteIp}:${connection.remotePort}`} cx={(point.longitude + 180) / 2} cy={(90 - point.latitude) / 2} r="3"/>; })}</svg><div className="connection-places">{connections.slice(0, 3).map((connection) => <span key={`${connection.remoteIp}:${connection.remotePort}`}>{connection.location ? `${connection.location.city}, ${connection.location.country}` : connection.remoteIp}</span>)}</div></>}</div>; }
function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`; if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`; return `${(value / 1024 ** 3).toFixed(1)} GB`; }
function Info({ label, value }: { label: string; value: string }) { return <div className="info-row"><span>{label}</span><b title={value}>{value}</b></div>; }
function Confirm({ listener, ports, force, busy, onClose, onConfirm }: { listener: Listener | null; ports: number[]; force: boolean; busy: boolean; onClose: () => void; onConfirm: () => void }) {
  return <Modal open={!!listener} onOpenChange={(value) => !value && onClose()} title={force ? "Force stop server?" : "Stop server?"}>{listener && <div><p className="text-sm leading-6 text-slate-300">{force ? "The process did not exit gracefully. Force Stop immediately terminates it and can lose in-flight work." : "PortMan will ask this process to exit gracefully. Any service on these ports will become unavailable."}</p><div className="my-4 rounded-lg border border-slate-700 bg-black/20 p-3"><b className="text-sm">{listener.processName} <span className="font-mono text-slate-400">(PID {listener.pid})</span></b><p className="mt-1 font-mono text-xs text-slate-400">Ports affected: {ports.map((port) => `:${port}`).join(", ")}</p></div><div className="flex justify-end gap-2"><Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button><Button variant="danger" onClick={onConfirm} disabled={busy}>{busy && <Loader2 className="animate-spin" size={15}/>} {force ? "Force Stop" : "Stop server"}</Button></div></div>}</Modal>;
}
