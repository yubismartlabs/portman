"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { relaunch } from "@tauri-apps/plugin-process";
import { check } from "@tauri-apps/plugin-updater";
import * as ContextMenu from "@radix-ui/react-context-menu";
import { Activity, ArrowUpDown, ChevronDown, CircleStop, Copy, ExternalLink, Globe2, Grid2X2, List, Loader2, LockKeyhole, RefreshCw, Search, Server, ShieldAlert, ShieldCheck, SlidersHorizontal, TerminalSquare, X } from "lucide-react";
import type { BinaryTrust, ExecutableInspection, ExecutionWatcherStatus, InstanceAnomaly, Listener, MemoryGuardAlert, MemoryGuardStatus, PostureCheck, ProcessMetrics, ProcessThread, QuarantineEntry, RemoteConnection, SandboxStatus, StopRisk, SystemPosture } from "@/lib/types";
import { filterAndSortListeners, listenerAddress, listenerHttpUrl } from "@/lib/listeners";
import { portmanApi } from "@/lib/tauri";
import { Button, Modal } from "@/components/ui";

type Filter = "all" | "localhost";
type Sort = "port" | "name";
type ViewMode = "list" | "grid";
type WorkspaceTab = "listeners" | "quarantine" | "posture" | "controls";
type AvailableUpdate = { version: string; body?: string | null };
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
  const [anomalies, setAnomalies] = useState<Record<number, InstanceAnomaly>>({});
  const [memoryGuard, setMemoryGuard] = useState<MemoryGuardStatus | null>(null);
  const [memoryAlert, setMemoryAlert] = useState<MemoryGuardAlert | null>(null);
  const [watcher, setWatcher] = useState<ExecutionWatcherStatus | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineEntry[]>([]);
  const [workspaceTab, setWorkspaceTab] = useState<WorkspaceTab>("listeners");
  const [posture, setPosture] = useState<SystemPosture | null>(null);
  const [fixing, setFixing] = useState<PostureCheck | null>(null);
  const [controlUpdating, setControlUpdating] = useState<"memory" | "watcher" | null>(null);
  const [nativeRuntime, setNativeRuntime] = useState(false);
  const [availableUpdate, setAvailableUpdate] = useState<AvailableUpdate | null>(null);
  const [installingUpdate, setInstallingUpdate] = useState(false);

  const refresh = useCallback(async () => {
    setError("");
    try { setListeners(await portmanApi.list()); setLastUpdated(new Date()); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not scan local listeners."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { setNativeRuntime(portmanApi.isNative()); }, []);
  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return;
    let active = true;
    check().then((update) => {
      if (active && update) setAvailableUpdate({ version: update.version, body: update.body });
    }).catch(() => { /* An unreachable update endpoint must not interrupt local server management. */ });
    return () => { active = false; };
  }, []);
  useEffect(() => { portmanApi.sandboxStatus().then(setSandboxStatus).catch(() => setSandboxStatus(null)); }, []);
  useEffect(() => { portmanApi.memoryGuard().then(setMemoryGuard).catch(() => setMemoryGuard(null)); }, []);
  useEffect(() => { portmanApi.executionWatcher().then(setWatcher).catch(() => setWatcher(null)); portmanApi.quarantined().then(setQuarantine).catch(() => setQuarantine([])); }, []);
  useEffect(() => { portmanApi.posture().then(setPosture).catch(() => setPosture(null)); }, []);
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
    listen<WorkspaceTab>("menu-navigate", (event) => setWorkspaceTab(event.payload)).then((fn) => { unlisten = fn; });
    return () => unlisten?.();
  }, []);
  useEffect(() => { if (!("__TAURI_INTERNALS__" in window)) return; let unlisten: (() => void) | undefined; listen<MemoryGuardAlert>("memory-guard-alert", (event) => setMemoryAlert(event.payload)).then((fn) => { unlisten = fn; }); return () => unlisten?.(); }, []);
  useEffect(() => { if (!("__TAURI_INTERNALS__" in window)) return; let unlisten: (() => void) | undefined; listen<QuarantineEntry>("execution-quarantined", (event) => { setQuarantine((entries) => [event.payload, ...entries]); setWorkspaceTab("quarantine"); setNotice(`${event.payload.processName} was added to quarantine.`); }).then((fn) => { unlisten = fn; }); return () => unlisten?.(); }, []);
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
  const selectedPid = selected?.pid;
  const manageable = listeners.filter((listener) => listener.canStop).length;

  useEffect(() => {
    if (!selectedPid || !("__TAURI_INTERNALS__" in window)) { setMetrics(null); setMetricHistory([]); return; }
    let active = true;
    const sample = async () => {
      try {
        const next = await portmanApi.metrics(selectedPid);
        if (!active) return;
        setMetrics(next);
        setMetricHistory((history) => [...history, next].slice(-45));
      } catch { if (active) setMetrics(null); }
    };
    setMetrics(null); setMetricHistory([]); sample();
    const interval = window.setInterval(sample, 1000);
    return () => { active = false; window.clearInterval(interval); };
  }, [selectedPid]);

  useEffect(() => {
    if (!selectedPid || !("__TAURI_INTERNALS__" in window)) { setConnections([]); return; }
    let active = true;
    const refreshConnections = async () => { try { const next = await portmanApi.outboundConnections(selectedPid); if (active) setConnections(next); } catch { if (active) setConnections([]); } };
    refreshConnections(); const interval = window.setInterval(refreshConnections, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [selectedPid]);

  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window) || listeners.length === 0) { setAnomalies({}); return; }
    let active = true;
    const sample = async () => { try { const values = await portmanApi.anomalies([...new Set(listeners.map((listener) => listener.pid))]); if (active) setAnomalies(Object.fromEntries(values.map((value) => [value.pid, value]))); } catch { /* The detector must never interrupt listener inspection. */ } };
    sample(); const timer = window.setInterval(sample, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [listeners]);

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

  const refreshPosture = useCallback(async () => {
    try { setPosture(await portmanApi.posture()); }
    catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not refresh system posture."); }
  }, []);

  const updateMemoryGuard = useCallback(async (enabled: boolean) => {
    setControlUpdating("memory");
    try {
      const next = await portmanApi.setMemoryGuard(enabled);
      setMemoryGuard(next);
      setNotice(enabled ? `Memory guard armed at ${next.thresholdPercent}%.` : "Memory guard disabled.");
    } catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not update memory guard."); }
    finally { setControlUpdating(null); }
  }, []);

  const updateExecutionWatcher = useCallback(async (enabled: boolean, autoPause: boolean) => {
    setControlUpdating("watcher");
    try {
      const next = await portmanApi.setExecutionWatcher(enabled, autoPause);
      setWatcher(next);
      setNotice(!enabled ? "Execution watcher disabled." : autoPause ? "Execution watcher will pause suspicious launches." : "Execution watcher will flag suspicious launches for review.");
    } catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not update execution watcher."); }
    finally { setControlUpdating(null); }
  }, []);

  const openListener = useCallback(async (listener: Listener) => {
    try { setNotice(`Opened ${await portmanApi.open(listener)}.`); }
    catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not open the listener."); }
  }, []);

  const copyText = useCallback(async (value: string, label: string) => {
    try { await navigator.clipboard.writeText(value); setNotice(`${label} copied to the clipboard.`); }
    catch { setNotice("Clipboard access was unavailable. Copy the value manually."); }
  }, []);

  const resumeMemoryGuard = useCallback(async () => {
    if (!memoryAlert) return;
    try {
      const result = await portmanApi.resume(memoryAlert.pid);
      setNotice(result.message);
      setMemoryAlert(null);
      await refresh();
    } catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not resume the process."); }
  }, [memoryAlert, refresh]);

  const installUpdate = useCallback(async () => {
    if (!availableUpdate) return;
    setInstallingUpdate(true);
    try {
      const update = await check();
      if (!update) {
        setAvailableUpdate(null);
        setNotice("PortMan is already up to date.");
        return;
      }
      await update.downloadAndInstall();
      await relaunch();
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : "Could not install the PortMan update.");
    } finally {
      setInstallingUpdate(false);
    }
  }, [availableUpdate]);

  return <main className="desktop-shell">
    <header className="topbar"><div className="window-title" data-tauri-drag-region><Server size={15}/><b>Local listeners</b><span>{listeners.length} active</span></div><div className="title-drag-region" data-tauri-drag-region/><div className="title-search"><Search size={14}/><input aria-label="Search listeners" placeholder="Search processes, ports, or addresses" value={query} onChange={(event) => setQuery(event.target.value)}/>{query && <button onClick={() => setQuery("")}><X size={13}/></button>}</div><div className="topbar-actions"><span className="updated">{lastUpdated ? `Last scan ${lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "Connecting…"}</span><Button variant="ghost" onClick={refresh}><RefreshCw size={15}/> Refresh</Button></div></header>
    <div className="desktop-body">
    <aside className="app-sidebar">
      <div className="brand"><div className="brand-mark"><Activity size={19}/></div><div><b>PortMan</b><span>LOCAL SERVER MANAGER</span></div></div>
      <div className="sidebar-activity"><span className="pulse"/><span><b>{listeners.length} active</b><small>{manageable} manageable</small></span></div>
      <nav className="sidebar-nav" aria-label="Workspace"><button className={workspaceTab === "listeners" ? "sidebar-filter active" : "sidebar-filter"} onClick={() => setWorkspaceTab("listeners")}><i/>Listener inventory</button><button className={workspaceTab === "quarantine" ? "sidebar-filter active" : "sidebar-filter"} onClick={() => setWorkspaceTab("quarantine")}><ShieldAlert size={12}/><span>Quarantine</span>{quarantine.filter((entry) => entry.state !== "resumed").length > 0 && <em>{quarantine.filter((entry) => entry.state !== "resumed").length}</em>}</button><button className={workspaceTab === "posture" ? "sidebar-filter active" : "sidebar-filter"} onClick={() => setWorkspaceTab("posture")}><ShieldCheck size={12}/>System posture</button><button className={workspaceTab === "controls" ? "sidebar-filter active" : "sidebar-filter"} onClick={() => setWorkspaceTab("controls")}><SlidersHorizontal size={12}/>Protection controls</button></nav>
      <div className="sidebar-scope" aria-label="Listener scope"><span>Scope</span><div><button className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>All</button><button className={filter === "localhost" ? "active" : ""} onClick={() => setFilter("localhost")}>Local</button></div></div>
      <div className="sidebar-spacer" />
      <div className="scanner-line"><span className="pulse"/>{nativeRuntime ? "Scanner online" : "Browser preview"}</div>
    </aside>
    <section className="workspace">
      <div className="workspace-content">
        {error && <div className="alert alert-error"><ShieldAlert size={17}/><span>{error}</span><Button className="ml-auto" variant="ghost" onClick={refresh}>Retry</Button></div>}
        {notice && <div className="alert"><Activity size={17}/><span>{notice}</span><button className="ml-auto" onClick={() => setNotice("")}><X size={15}/></button></div>}
        {workspaceTab === "quarantine" ? <QuarantinePanel entries={quarantine} watcher={watcher} onResume={async (pid) => { try { const result = await portmanApi.resumeQuarantined(pid); setNotice(result.message); setQuarantine((entries) => entries.map((entry) => entry.pid === pid && entry.state === "paused" ? { ...entry, state: "resumed", canResume: false } : entry)); } catch (cause) { setNotice(cause instanceof Error ? cause.message : "Could not resume the process."); } }} /> : workspaceTab === "posture" ? <PosturePanel posture={posture} onRefresh={refreshPosture} onFix={setFixing} /> : workspaceTab === "controls" ? <ProtectionControls memoryGuard={memoryGuard} watcher={watcher} updating={controlUpdating} onMemoryGuardChange={updateMemoryGuard} onWatcherChange={updateExecutionWatcher} /> : <section className={`main-panes ${selected ? "with-inspector" : ""}`}>
          <div className="listeners-pane">
            <div className="pane-title"><div><h2>Listener inventory</h2><p>{visible.length} of {listeners.length} shown</p></div><div className="pane-actions"><div className="view-toggle"><button className={viewMode === "list" ? "selected" : ""} aria-label="List view" onClick={() => setViewMode("list")}><List size={15}/></button><button className={viewMode === "grid" ? "selected" : ""} aria-label="Grid view" onClick={() => setViewMode("grid")}><Grid2X2 size={14}/></button></div><button className="icon-button" title="Toggle sort" onClick={() => setSort(sort === "port" ? "name" : "port")}><ArrowUpDown size={16}/></button></div></div>
            {viewMode === "list" && <div className="table-head"><span>Process</span><span>PID</span><span>Port</span><span>Address</span><span>Owner</span><span>Status</span></div>}
            <div className={viewMode === "grid" ? "listener-grid" : "listener-list"}>{loading ? <Empty icon={<Loader2 className="animate-spin"/>} title="Scanning local listeners" text="This only takes a moment."/> : visible.length === 0 ? <Empty icon={<Globe2/>} title="No matching listeners" text="Adjust filters or start a local server."/> : visible.map((listener) => <ListenerMenu key={listener.id} listener={listener} onStop={setStopping} onOpen={openListener} onCopy={copyText}>{viewMode === "grid" ? <ListenerTile listener={listener} selected={selected?.id === listener.id} onSelect={() => setSelectedId(listener.id)} /> : <button className={`listener-row ${selected?.id === listener.id ? "selected" : ""}`} onClick={() => setSelectedId(listener.id)}><span className="process-cell"><span className="process-icon"><TerminalSquare size={15}/></span><span><b>{listener.processName}<TrustMark trust={listener.binaryTrust}/></b><small title={listener.command}>{serviceKind(listener)} · {truncate(listener.command)}</small></span></span><span className="pid-cell">{listener.pid}</span><span className="port-cell">:{listener.port}</span><span className="binding-cell" title={listenerAddress(listener)}>{listenerAddress(listener)}</span><span className="owner-cell">{listener.owner}</span><span className={listener.isProtected ? "status protected" : "status"}><i/>{statusLabel(listener)}</span></button>}</ListenerMenu>)}</div>
          </div>
          {selected && <Inspector listener={selected} metrics={metrics} history={metricHistory} connections={connections} anomaly={anomalies[selected.pid]} onClose={() => setSelectedId(null)} onStop={setStopping} onOpen={openListener} onCopy={copyText} />}
        </section>}
      </div>
      <footer className="statusbar"><span><i className="pulse"/> {nativeRuntime ? "Native scanner online" : "Browser preview"}</span><span>⌃⌥P: Show & scan</span><span>⌃⌥⇧K: Quit frontmost app</span><span>{sandboxStatus ? `Isolation: ${sandboxStatus.level}` : "Checking isolation…"}</span><span>{nativeRuntime ? "Current user processes can be stopped" : "Native actions require the desktop app"}</span></footer>
    </section>
    <Confirm listener={stopping} ports={listeners.filter((item) => item.pid === stopping?.pid).map((item) => item.port)} force={false} busy={busy} onClose={() => setStopping(null)} onConfirm={() => stopping && terminate(stopping)} />
    <Confirm listener={force} ports={listeners.filter((item) => item.pid === force?.pid).map((item) => item.port)} force busy={busy} onClose={() => setForce(null)} onConfirm={() => force && terminate(force, true)} />
    <ExecutableModal inspection={droppedExecutable} error={dropError} onClose={() => { setDroppedExecutable(null); setDropError(""); }} />
    <MemoryGuardModal alert={memoryAlert} onClose={() => setMemoryAlert(null)} onResume={resumeMemoryGuard} />
    <PostureFixModal check={fixing} onClose={() => setFixing(null)} onConfirm={async () => { if (!fixing) return; try { setNotice(await portmanApi.applyPostureFix(fixing.id)); setFixing(null); setPosture(await portmanApi.posture()); } catch (cause) { setNotice(cause instanceof Error ? cause.message : "The setting could not be changed."); } }} />
    <UpdateModal update={availableUpdate} installing={installingUpdate} onClose={() => setAvailableUpdate(null)} onInstall={installUpdate} />
    </div>
  </main>;
}

function QuarantinePanel({ entries, watcher, onResume }: { entries: QuarantineEntry[]; watcher: ExecutionWatcherStatus | null; onResume: (pid: number) => void }) { return <section className="quarantine-pane"><div className="pane-title"><div><h2>Quarantine</h2><p>Suspicious executable launches retained for review</p></div><ShieldAlert size={19}/></div><div className="quarantine-mode"><ShieldCheck size={15}/><span>{watcher?.platformMode ?? "Loading execution watcher…"}</span></div>{entries.length === 0 ? <Empty icon={<ShieldCheck/>} title="No quarantined executions" text="New executable processes are scanned as they appear. Auto-pause is optional."/> : <div className="quarantine-list">{entries.map((entry) => <article className={`quarantine-entry ${entry.state}`} key={entry.id}><div><div className="quarantine-entry-head"><b>{entry.processName}</b><span>{entry.state}</span></div><p>PID {entry.pid} · {new Date(entry.detectedAt * 1000).toLocaleString()}</p><code title={entry.path}>{entry.path}</code><small>SHA-256 {entry.sha256}</small><ul>{entry.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></div>{entry.canResume && <Button variant="ghost" onClick={() => onResume(entry.pid)}>Resume</Button>}</article>)}</div>}</section>; }
function PosturePanel({ posture, onRefresh, onFix }: { posture: SystemPosture | null; onRefresh: () => Promise<void>; onFix: (check: PostureCheck) => void }) { return <section className="posture-pane"><div className="pane-title"><div><h2>System posture</h2><p>Host protections and exposure checks</p></div><Button variant="ghost" onClick={() => void onRefresh()}><RefreshCw size={14}/> Refresh</Button></div>{!posture ? <Empty icon={<Loader2 className="animate-spin"/>} title="Assessing system protections" text="Reading local security settings."/> : <><div className="posture-score"><div><span>{posture.score}</span><small>/100</small></div><section><b>{posture.score >= 90 ? "Strong protection" : posture.score >= 70 ? "Needs attention" : "Protection gaps found"}</b><p>{posture.platform} · Failed checks reduce the score by 25; warnings by 10.</p></section></div><div className="posture-checks">{posture.checks.map((check) => <article key={check.id} className={`posture-check ${check.status}`}><span className="posture-icon">{check.status === "pass" ? <ShieldCheck size={18}/> : <ShieldAlert size={18}/>}</span><div><div className="posture-check-heading"><b>{check.title}</b><em>{check.status}</em></div><p>{check.summary}</p><small>{check.remediation}</small></div>{check.canFix && <Button variant="ghost" onClick={() => onFix(check)}>Fix</Button>}</article>)}</div></>}</section>; }
function ProtectionControls({ memoryGuard, watcher, updating, onMemoryGuardChange, onWatcherChange }: { memoryGuard: MemoryGuardStatus | null; watcher: ExecutionWatcherStatus | null; updating: "memory" | "watcher" | null; onMemoryGuardChange: (enabled: boolean) => Promise<void>; onWatcherChange: (enabled: boolean, autoPause: boolean) => Promise<void> }) { return <section className="controls-pane"><div className="pane-title"><div><h2>Protection controls</h2><p>Configure local safeguards and review how they act.</p></div><SlidersHorizontal size={19}/></div><div className="control-cards"><article className="control-card"><div className="control-card-heading"><span><ShieldAlert size={18}/></span><div><b>Memory guard</b><p>Pauses the heaviest manageable listener when system memory reaches its threshold.</p></div></div><div className="control-card-footer"><small>{memoryGuard ? memoryGuard.enabled ? `Armed at ${memoryGuard.thresholdPercent}% memory use` : "Disabled" : "Checking availability…"}</small><Button variant={memoryGuard?.enabled ? "ghost" : "default"} disabled={!memoryGuard || updating === "memory"} onClick={() => void onMemoryGuardChange(!memoryGuard?.enabled)}>{updating === "memory" && <Loader2 className="animate-spin" size={14}/>} {memoryGuard?.enabled ? "Disable" : "Enable"}</Button></div></article><article className="control-card"><div className="control-card-heading"><span><ShieldCheck size={18}/></span><div><b>Execution watcher</b><p>Reviews newly launched executables against local signals and the bundled signature list.</p></div></div><div className="control-card-footer"><small>{watcher ? watcher.enabled ? watcher.autoPause ? "Monitoring and auto-pausing suspicious launches" : "Monitoring; suspicious launches remain available for review" : "Disabled" : "Checking availability…"}</small><Button variant={watcher?.enabled ? "ghost" : "default"} disabled={!watcher || updating === "watcher"} onClick={() => watcher && void onWatcherChange(!watcher.enabled, watcher.autoPause)}>{updating === "watcher" && <Loader2 className="animate-spin" size={14}/>} {watcher?.enabled ? "Disable" : "Enable"}</Button></div>{watcher?.enabled && <label className="control-checkbox"><input type="checkbox" checked={watcher.autoPause} disabled={updating === "watcher"} onChange={(event) => void onWatcherChange(watcher.enabled, event.target.checked)} /> <span>Pause suspicious launches automatically</span></label>}</article><article className="control-card control-note"><div className="control-card-heading"><span><ShieldCheck size={18}/></span><div><b>Review queue</b><p>Paused executions can be resumed only after PortMan confirms the process and its recorded file hash still match.</p></div></div><small>Use the Quarantine workspace to inspect executable paths, hashes, detection reasons, and available resume actions.</small></article></div></section>; }
function UpdateModal({ update, installing, onClose, onInstall }: { update: AvailableUpdate | null; installing: boolean; onClose: () => void; onInstall: () => void }) { return <Modal open={!!update} onOpenChange={(open) => !open && onClose()} title="Update available">{update && <div><p className="text-sm leading-6 text-slate-300">PortMan {update.version} is ready. Install it now to restart with the latest version.</p>{update.body && <div className="my-4 max-h-36 overflow-auto rounded-lg border border-slate-700 bg-black/20 p-3 text-xs leading-5 text-slate-300 whitespace-pre-wrap">{update.body}</div>}<div className="mt-5 flex justify-end gap-2"><Button variant="ghost" onClick={onClose} disabled={installing}>Later</Button><Button variant="default" onClick={onInstall} disabled={installing}>{installing && <Loader2 className="animate-spin" size={15}/>} Install &amp; restart</Button></div></div>}</Modal>; }
function PostureFixModal({ check, onClose, onConfirm }: { check: PostureCheck | null; onClose: () => void; onConfirm: () => void }) { return <Modal open={!!check} onOpenChange={(open) => !open && onClose()} title={`Enable ${check?.title ?? "protection"}?`}>{check && <div><p className="text-sm leading-6 text-slate-300">PortMan will request macOS administrator authorization to apply this setting. It will run only the built-in remediation for {check.title}.</p><div className="my-4 rounded-lg border border-slate-700 bg-black/20 p-3 text-xs text-slate-300">{check.remediation}</div><div className="flex justify-end gap-2"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="danger" onClick={onConfirm}>Request authorization</Button></div></div>}</Modal>; }

function Empty({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) { return <div className="empty"><span>{icon}</span><b>{title}</b><p>{text}</p></div>; }
function ExecutableModal({ inspection, error, onClose }: { inspection: ExecutableInspection | null; error: string; onClose: () => void }) { const open = !!inspection || !!error; return <Modal open={open} onOpenChange={(value) => !value && onClose()} title="Dropped executable inspection">{error ? <p className="text-sm text-rose-300">{error}</p> : inspection && <div className="executable-inspection"><p className="section-label">EXECUTABLE</p><b>{inspection.name}</b><code>{inspection.path}</code>{!inspection.isExecutable ? <p className="drop-result">This file is not marked as executable.</p> : inspection.instances.length === 0 ? <p className="drop-result">No running instance found.</p> : <><p className="drop-result">{inspection.instances.length} running {inspection.instances.length === 1 ? "instance" : "instances"} found</p>{inspection.instances.map((instance) => <div className="executable-instance" key={instance.pid}><span><b>PID {instance.pid}</b><small>{instance.state}</small></span><code>{instance.path}</code><em>{instance.ports.length ? instance.ports.map((port) => `:${port}`).join(", ") : "No listening port"}</em></div>)}</>}</div>}</Modal>; }
function MemoryGuardModal({ alert, onClose, onResume }: { alert: MemoryGuardAlert | null; onClose: () => void; onResume: () => void }) { return <Modal open={!!alert} onOpenChange={(value) => !value && onClose()} title="Memory guard activated">{alert && <div><p className="text-sm leading-6 text-slate-300">System memory reached {alert.utilizationPercent.toFixed(1)}%. PortMan paused the lowest-priority heavy local instance before the system became unresponsive.</p><div className="my-4 rounded-lg border border-rose-900/70 bg-rose-950/30 p-3"><b className="text-sm">{alert.processName} <span className="font-mono text-slate-400">(PID {alert.pid})</span></b><p className="mt-1 text-xs text-slate-400">Paused memory: {formatBytes(alert.memoryBytes)} · System total: {formatBytes(alert.totalMemoryBytes)}</p></div><div className="flex justify-end gap-2"><Button variant="ghost" onClick={onClose}>Keep paused</Button><Button variant="danger" onClick={onResume}>Resume instance</Button></div></div>}</Modal>; }
function ListenerMenu({ listener, onStop, onOpen, onCopy, children }: { listener: Listener; onStop: (listener: Listener) => void; onOpen: (listener: Listener) => Promise<void>; onCopy: (value: string, label: string) => Promise<void>; children: React.ReactNode }) {
  return <ContextMenu.Root><ContextMenu.Trigger asChild>{children}</ContextMenu.Trigger><ContextMenu.Portal><ContextMenu.Content className="context-menu"><ContextMenu.Label>Port {listener.port} · {listener.processName}</ContextMenu.Label><ContextMenu.Item onSelect={() => void onOpen(listener)}><ExternalLink size={14}/> Open in browser</ContextMenu.Item><ContextMenu.Item onSelect={() => void onCopy(listenerHttpUrl(listener), "URL")}><Copy size={14}/> Copy URL</ContextMenu.Item><ContextMenu.Item onSelect={() => void onCopy(String(listener.port), "Port")}><Copy size={14}/> Copy port</ContextMenu.Item><ContextMenu.Separator/><ContextMenu.Item className="danger-item" disabled={!listener.canStop} onSelect={() => onStop(listener)}><CircleStop size={14}/> {listener.canStop ? "Stop process" : "Protected process"}</ContextMenu.Item></ContextMenu.Content></ContextMenu.Portal></ContextMenu.Root>;
}
function ListenerTile({ listener, selected, onSelect }: { listener: Listener; selected: boolean; onSelect: () => void }) { return <button className={`listener-tile ${selected ? "selected" : ""}`} onClick={onSelect}><div className="tile-head"><span className="process-icon"><TerminalSquare size={15}/></span><span className="tile-flags"><TrustMark trust={listener.binaryTrust}/><span className={listener.isProtected ? "status protected" : "status"}><i/>{statusLabel(listener)}</span></span></div><h3 className="tile-title" title={listener.processName}>{listener.processName}</h3><small title={listener.command}>{serviceKind(listener)} · {truncate(listener.command, 42)}</small><div className="tile-port">:{listener.port}</div><div className="tile-details"><span title={listenerAddress(listener)}>{listenerAddress(listener)}</span><span>PID {listener.pid} · {listener.owner}</span></div></button>; }
function Inspector({ listener, metrics, history, connections, anomaly, onClose, onStop, onOpen, onCopy }: { listener: Listener; metrics: ProcessMetrics | null; history: ProcessMetrics[]; connections: RemoteConnection[]; anomaly?: InstanceAnomaly; onClose: () => void; onStop: (listener: Listener) => void; onOpen: (listener: Listener) => Promise<void>; onCopy: (value: string, label: string) => Promise<void> }) {
  return <aside className="inspector"><div className="inspector-head"><div><p className="eyebrow">INSPECTOR</p><h2>{listener.processName}</h2><span className={listener.isProtected ? "status protected" : "status"}><i/>{statusLabel(listener)}</span></div><div className="inspector-top-actions"><span className="pid">PID {listener.pid}</span><button aria-label="Close inspector" onClick={onClose}><X size={14}/></button></div></div><div className="inspector-command"><p>COMMAND</p><code>{listener.command}</code></div><div className="inspector-section"><p className="section-label">CONNECTION</p><Info label="Detected" value={serviceKind(listener)}/><Info label="Binary" value={trustLabel(listener.binaryTrust)}/><Info label="Port" value={`:${listener.port}`}/><Info label="Bindings" value={listenerAddress(listener)}/><Info label="Owner" value={listener.owner}/></div><MetricsPanel metrics={metrics} history={history}/><AnomalyPanel anomaly={anomaly} onForceStop={() => onStop(listener)} canStop={listener.canStop}/><ThreadList pid={listener.pid}/><ConnectionsMap connections={connections}/><div className="inspector-actions"><Button variant="ghost" onClick={() => void onCopy(listenerHttpUrl(listener), "URL")}><Copy size={15}/> Copy URL</Button><Button variant="ghost" onClick={() => void onOpen(listener)}><ExternalLink size={15}/> Open</Button>{listener.canStop ? <Button variant="danger" className="w-full" onClick={() => onStop(listener)}><CircleStop size={15}/> Stop process</Button> : <div className="protected-note"><LockKeyhole size={14}/> This process belongs to another user.</div>}</div></aside>;
}
function TrustMark({ trust }: { trust: BinaryTrust }) { return <span className={`trust-mark ${trust}`} title={trustLabel(trust)}>{trust === "trusted" ? <ShieldCheck size={13}/> : <ShieldAlert size={13}/>}</span>; }
function MetricsPanel({ metrics, history }: { metrics: ProcessMetrics | null; history: ProcessMetrics[] }) { const readWrite = metrics ? metrics.readBytesPerSec + metrics.writeBytesPerSec : 0; return <div className="metrics-panel"><p className="section-label">LIVE METRICS <span>1s</span></p><MetricGraph label="CPU" value={metrics ? `${metrics.cpuPercent.toFixed(1)}%` : "—"} points={history.map((item) => item.cpuPercent)} tone="cpu"/><MetricGraph label="Memory" value={metrics ? formatBytes(metrics.memoryBytes) : "—"} points={history.map((item) => item.memoryBytes)} tone="memory"/><MetricGraph label="Disk I/O" value={metrics ? `${formatBytes(readWrite)}/s` : "—"} points={history.map((item) => item.readBytesPerSec + item.writeBytesPerSec)} tone="disk"/></div>; }
function AnomalyPanel({ anomaly, canStop, onForceStop }: { anomaly?: InstanceAnomaly; canStop: boolean; onForceStop: () => void }) { if (!anomaly) return null; return <section className={anomaly.isAnomalous ? "anomaly-panel alerting" : "anomaly-panel"}><p className="section-label">LOCAL AI BEHAVIOR <span>{anomaly.baselineSamples < 12 ? "learning" : `${anomaly.score.toFixed(1)} score`}</span></p><p>{anomaly.summary}</p><div><span>CPU {anomaly.cpuPercent.toFixed(1)}%</span><span>{formatBytes(anomaly.memoryBytes)}</span><span>{anomaly.outboundConnections} public connections</span></div>{anomaly.isAnomalous && canStop && <Button variant="danger" onClick={onForceStop}><CircleStop size={14}/> Review & force stop</Button>}</section>; }
function ThreadList({ pid }: { pid: number }) {
  const [expanded, setExpanded] = useState(false); const [threads, setThreads] = useState<ProcessThread[]>([]); const [error, setError] = useState("");
  useEffect(() => { if (!expanded) return; let active = true; const refresh = async () => { try { const next = await portmanApi.threads(pid); if (active) { setThreads(next); setError(""); } } catch { if (active) setError("Thread details are unavailable."); } }; refresh(); const timer = window.setInterval(refresh, 1000); return () => { active = false; window.clearInterval(timer); }; }, [expanded, pid]);
  return <section className="thread-list"><button className="thread-toggle" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded}><span><b>OS THREADS</b><small>{expanded ? `${threads.length} live · 1s` : "Expand individual CPU usage"}</small></span><ChevronDown size={15}/></button>{expanded && <div className="thread-table">{error ? <p className="thread-empty">{error}</p> : threads.length === 0 ? <p className="thread-empty">Loading threads…</p> : <>{threads.slice(0, 80).map((thread) => <div className="thread-row" key={thread.id}><span title={thread.name}>{thread.name}</span><code>TID {thread.id}</code><b>{thread.cpuPercent.toFixed(1)}%</b></div>)}{threads.length > 80 && <p className="thread-empty">Showing the 80 busiest of {threads.length} threads.</p>}</>}</div>}</section>;
}
function MetricGraph({ label, value, points, tone }: { label: string; value: string; points: number[]; tone: string }) { const max = Math.max(...points, 1); const chart = points.length < 2 ? "0,24 100,24" : points.map((point, index) => `${(index / (points.length - 1)) * 100},${24 - (point / max) * 20}`).join(" "); return <div className={`metric-graph ${tone}`}><div><span>{label}</span><b>{value}</b></div><svg viewBox="0 0 100 24" preserveAspectRatio="none" aria-label={`${label} history`}><polyline points={chart}/></svg></div>; }
function ConnectionsMap({ connections }: { connections: RemoteConnection[] }) { const located = connections.filter((connection) => connection.location); const countries = [...new Map(located.map((connection) => [connection.location!.country, located.filter((item) => item.location?.country === connection.location!.country).length])).entries()]; return <div className="connections-map"><p className="section-label">OFFLINE OUTBOUND GEO <span>{connections.length} live</span></p>{connections.length === 0 ? <p className="map-empty">No public outbound TCP connections.</p> : <><svg viewBox="0 0 180 90" aria-label="Remote connection locations"><path d="M0 22H180M0 45H180M0 68H180M45 0V90M90 0V90M135 0V90"/>{located.map((connection) => { const point = connection.location!; return <circle key={`${connection.remoteIp}:${connection.remotePort}`} cx={(point.longitude + 180) / 2} cy={(90 - point.latitude) / 2} r="3"/>; })}</svg>{countries.length === 0 ? <p className="map-empty">Set PORTMAN_GEOIP_DB to a local MaxMind City database to resolve countries. Raw IPs remain local.</p> : <div className="country-list">{countries.map(([country, count]) => <div key={country}><span>{country} <small>{count} connection{count === 1 ? "" : "s"}</small></span><button disabled title="Country blocking requires an administrator-approved firewall policy and CIDR feed.">Policy needed</button></div>)}</div>}<div className="connection-places">{connections.slice(0, 3).map((connection) => <span key={`${connection.remoteIp}:${connection.remotePort}`}>{connection.location ? `${connection.location.city}, ${connection.location.country}` : connection.remoteIp}</span>)}</div></>}</div>; }
function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`; if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`; return `${(value / 1024 ** 3).toFixed(1)} GB`; }
function Info({ label, value }: { label: string; value: string }) { return <div className="info-row"><span>{label}</span><b title={value}>{value}</b></div>; }
function Confirm({ listener, ports, force, busy, onClose, onConfirm }: { listener: Listener | null; ports: number[]; force: boolean; busy: boolean; onClose: () => void; onConfirm: () => void }) {
  const [risk, setRisk] = useState<StopRisk | null>(null);
  const listenerPid = listener?.pid;
  useEffect(() => { if (!listenerPid) { setRisk(null); return; } setRisk(null); portmanApi.stopRisk(listenerPid).then(setRisk).catch(() => setRisk(null)); }, [listenerPid]);
  return <Modal open={!!listener} onOpenChange={(value) => !value && onClose()} title={risk?.blocked ? "Stop blocked: critical system process" : force ? "Force stop server?" : "Stop server?"}>{listener && <div><p className="text-sm leading-6 text-slate-300">{risk?.blocked ? risk.consequence : force ? "The process did not exit gracefully. Force Stop immediately terminates it and can lose in-flight work." : "PortMan will ask this process to exit gracefully. Any service on these ports will become unavailable."}</p><div className="my-4 rounded-lg border border-slate-700 bg-black/20 p-3"><b className="text-sm">{listener.processName} <span className="font-mono text-slate-400">(PID {listener.pid})</span></b><p className="mt-1 font-mono text-xs text-slate-400">Ports affected: {ports.map((port) => `:${port}`).join(", ")}</p></div>{risk && <div className={`stop-risk ${risk.level}`}><b>{risk.level.toUpperCase()} RISK · {risk.score}/100</b><p>{risk.reasons.length ? risk.reasons.join(" ") : risk.consequence}</p></div>}<div className="flex justify-end gap-2"><Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button><Button variant="danger" onClick={onConfirm} disabled={busy || risk?.blocked}>{busy && <Loader2 className="animate-spin" size={15}/>} {risk?.blocked ? "Action blocked" : force ? "Force Stop" : "Stop server"}</Button></div></div>}</Modal>;
}
