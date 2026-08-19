use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet, HashMap, HashSet}, fs::File, io::{BufReader, Read}, path::Path, process::Command, sync::{Mutex, OnceLock}, thread, time::{Duration, SystemTime, UNIX_EPOCH}};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Binding { pub address: String, pub is_localhost: bool }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BinaryTrust { Trusted, Signed, Unsigned, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
  pub id: String,
  pub pid: u32,
  pub process_name: String,
  pub command: String,
  pub owner: String,
  pub port: u16,
  pub bindings: Vec<Binding>,
  pub binary_trust: BinaryTrust,
  pub is_protected: bool,
  pub can_stop: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopResult { pub stopped: bool, pub requires_force: bool, pub message: String }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessMetrics {
  pub cpu_percent: f32,
  pub memory_bytes: u64,
  pub read_bytes_per_sec: u64,
  pub write_bytes_per_sec: u64,
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessThread { pub id: u32, pub name: String, pub cpu_percent: f32 }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutableInstance { pub pid: u32, pub path: String, pub state: String, pub ports: Vec<u16> }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutableInspection { pub name: String, pub path: String, pub is_executable: bool, pub instances: Vec<ExecutableInstance> }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceAnomaly { pub pid: u32, pub score: f64, pub baseline_samples: u32, pub is_anomalous: bool, pub summary: String, pub cpu_percent: f32, pub memory_bytes: u64, pub outbound_connections: usize, pub novel_remote_connections: usize }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopRisk { pub level: String, pub score: u8, pub blocked: bool, pub reasons: Vec<String>, pub consequence: String, pub previous_stops: u32 }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryGuardStatus { pub enabled: bool, pub threshold_percent: u8 }
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryGuardAlert { pub pid: u32, pub process_name: String, pub memory_bytes: u64, pub total_memory_bytes: u64, pub utilization_percent: f32 }

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionWatcherStatus { pub enabled: bool, pub auto_pause: bool, pub platform_mode: String }

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineEntry { pub id: u64, pub pid: u32, pub process_name: String, pub path: String, pub sha256: String, pub reasons: Vec<String>, pub detected_at: u64, pub state: String, pub can_resume: bool }

struct MetricsState(Mutex<System>);
struct StopHistoryState(Mutex<HashMap<String, u32>>);
struct MemoryGuardState(Mutex<MemoryGuardConfig>);
struct ExecutionWatcherState(Mutex<ExecutionWatcherConfig>);
struct MemoryGuardConfig { enabled: bool, paused_pids: std::collections::BTreeSet<u32> }
struct ExecutionWatcherConfig { enabled: bool, auto_pause: bool, seen_pids: HashSet<u32>, quarantined: Vec<QuarantineEntry>, next_id: u64, blocked_hashes: HashSet<String> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureDatabase { blocked_sha256: Vec<String> }
static BINARY_TRUST_CACHE: OnceLock<Mutex<HashMap<String, BinaryTrust>>> = OnceLock::new();
static GEO_CACHE: OnceLock<Mutex<HashMap<String, Option<GeoLocation>>>> = OnceLock::new();
static ANOMALY_CACHE: OnceLock<Mutex<HashMap<String, ProcessBaseline>>> = OnceLock::new();

#[derive(Default)]
struct RunningStats { samples: u32, mean: f64, m2: f64 }
impl RunningStats {
  fn deviation(&self, value: f64) -> f64 { if self.samples < 4 { 0.0 } else { let variance = (self.m2 / (self.samples - 1) as f64).max(0.0001); (value - self.mean) / variance.sqrt() } }
  fn observe(&mut self, value: f64) { self.samples += 1; let delta = value - self.mean; self.mean += delta / self.samples as f64; self.m2 += delta * (value - self.mean); }
}
#[derive(Default)]
struct ProcessBaseline { cpu: RunningStats, memory: RunningStats, connections: RunningStats, novel_connections: RunningStats, remotes: std::collections::BTreeSet<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoLocation { pub city: String, pub country: String, pub latitude: f64, pub longitude: f64 }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteConnection { pub remote_ip: String, pub remote_port: u16, pub location: Option<GeoLocation> }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxStatus { pub environment: String, pub level: String, pub details: String, pub indicators: Vec<String> }

#[derive(Deserialize)]
struct GeoResponse { success: bool, country: Option<String>, city: Option<String>, latitude: Option<f64>, longitude: Option<f64> }

#[derive(Default)]
struct ProcessRecord { pid: u32, name: String, owner: String, bindings: Vec<(String, u16)> }

fn current_uid() -> Result<String, String> {
  let output = Command::new("id").arg("-u").output().map_err(|e| format!("Unable to read current user: {e}"))?;
  Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_for(pid: u32) -> String {
  Command::new("ps").args(["-p", &pid.to_string(), "-o", "command="]).output()
    .ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "Command unavailable".to_string())
}

fn process_state(state: &str) -> String {
  match state.chars().next() { Some('R') => "Running", Some('S') | Some('I') => "Sleeping", Some('T') => "Stopped", Some('U') => "Uninterruptible wait", Some('Z') => "Zombie", _ => "Unknown" }.into()
}

fn inspect_executable_path(path: &str) -> Result<ExecutableInspection, String> {
  let input = Path::new(path);
  let metadata = input.metadata().map_err(|_| "The dropped file is no longer available.".to_string())?;
  let canonical = input.canonicalize().map_err(|_| "Could not resolve the dropped file path.".to_string())?;
  #[cfg(unix)]
  let is_executable = metadata.is_file() && (metadata.permissions().mode() & 0o111 != 0);
  #[cfg(not(unix))]
  let is_executable = metadata.is_file();
  let target = canonical.to_string_lossy().to_string();
  if !is_executable { return Ok(ExecutableInspection { name: canonical.file_name().and_then(|value| value.to_str()).unwrap_or("Dropped file").into(), path: target, is_executable, instances: Vec::new() }); }
  let listeners = scan_listeners().unwrap_or_default();
  let output = Command::new("ps").args(["-axo", "pid=,state=,comm="]).output().map_err(|e| format!("Could not inspect running processes: {e}"))?;
  let mut instances = Vec::new();
  for line in String::from_utf8_lossy(&output.stdout).lines() {
    let mut fields = line.split_whitespace();
    let Some(pid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else { continue; };
    let state = fields.next().unwrap_or_default();
    let process_path = fields.collect::<Vec<_>>().join(" ");
    if process_path.is_empty() { continue; }
    let matches = Path::new(&process_path).canonicalize().ok().is_some_and(|value| value == canonical);
    if matches { let mut ports: Vec<u16> = listeners.iter().filter(|listener| listener.pid == pid).map(|listener| listener.port).collect(); ports.sort_unstable(); ports.dedup(); instances.push(ExecutableInstance { pid, path: process_path, state: process_state(state), ports }); }
  }
  instances.sort_by_key(|instance| instance.pid);
  Ok(ExecutableInspection { name: canonical.file_name().and_then(|value| value.to_str()).unwrap_or("Executable").into(), path: target, is_executable, instances })
}

#[tauri::command]
fn inspect_executable(path: String) -> Result<ExecutableInspection, String> { inspect_executable_path(&path) }

fn executable_for(pid: u32) -> Option<String> {
  let output = Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output().ok()?;
  let executable = String::from_utf8_lossy(&output.stdout).trim().to_string();
  (!executable.is_empty() && Path::new(&executable).exists()).then_some(executable)
}

struct SystemBinaryProfile { names: &'static [&'static str], vector: &'static [&'static str], consequence: &'static str }
const CRITICAL_BINARIES: &[SystemBinaryProfile] = &[
  SystemBinaryProfile { names: &["windowserver"], vector: &["window", "display", "compositor", "system"], consequence: "Stopping WindowServer ends the macOS graphical session and can immediately log you out." },
  SystemBinaryProfile { names: &["launchd"], vector: &["launch", "service", "system", "init"], consequence: "Stopping launchd destabilizes core system service management and can force a restart." },
  SystemBinaryProfile { names: &["kernel_task"], vector: &["kernel", "system", "task"], consequence: "Stopping kernel_task can destabilize macOS and may force a system restart." },
  SystemBinaryProfile { names: &["loginwindow"], vector: &["login", "window", "session", "system"], consequence: "Stopping loginwindow ends the active user session and logs you out." },
  SystemBinaryProfile { names: &["lsass.exe", "csrss.exe", "wininit.exe", "services.exe"], vector: &["windows", "security", "session", "system"], consequence: "Stopping this Windows system process causes Windows to terminate the session or restart." },
];

fn binary_tokens(value: &str) -> Vec<String> { value.to_ascii_lowercase().split(|character: char| !character.is_ascii_alphanumeric()).filter(|token| !token.is_empty()).map(str::to_string).collect() }
fn vector_similarity(tokens: &[String], vector: &[&str]) -> f64 { let shared = vector.iter().filter(|feature| tokens.iter().any(|token| token == **feature)).count() as f64; if tokens.is_empty() { 0.0 } else { shared / ((tokens.len() * vector.len()) as f64).sqrt() } }

fn stop_risk_for_pid(pid: u32, history: &StopHistoryState) -> Result<StopRisk, String> {
  let executable = executable_for(pid).unwrap_or_else(|| command_for(pid));
  let name = Path::new(&executable).file_name().and_then(|value| value.to_str()).unwrap_or(&executable).to_ascii_lowercase();
  let tokens = binary_tokens(&format!("{name} {executable}"));
  let previous_stops = history.0.lock().ok().and_then(|values| values.get(&executable).copied()).unwrap_or(0);
  for profile in CRITICAL_BINARIES {
    if profile.names.iter().any(|known| name == *known) || vector_similarity(&tokens, profile.vector) > 0.82 { return Ok(StopRisk { level: "critical".into(), score: 100, blocked: true, reasons: vec![format!("Matches protected system binary profile: {name}")], consequence: "PortMan blocked this action. ".to_string() + profile.consequence, previous_stops }); }
  }
  let listener_count = scan_listeners().unwrap_or_default().iter().filter(|listener| listener.pid == pid).count();
  let mut score: u8 = if listener_count > 0 { 45 } else { 10 }; let mut reasons = Vec::new();
  if listener_count > 0 { reasons.push(format!("This instance is serving {listener_count} local listener(s).")); }
  if previous_stops > 0 { score = score.saturating_sub(10); reasons.push(format!("You previously stopped this executable {previous_stops} time(s) in this session.")); }
  Ok(StopRisk { level: if score >= 35 { "medium" } else { "low" }.into(), score, blocked: false, reasons, consequence: if listener_count > 0 { "Stopping it interrupts its local service and connected clients.".into() } else { "No protected system impact was detected.".into() }, previous_stops })
}

#[tauri::command]
fn stop_risk(pid: u32, history: State<StopHistoryState>) -> Result<StopRisk, String> { stop_risk_for_pid(pid, &history) }

fn record_stop(pid: u32, history: &StopHistoryState) { let executable = executable_for(pid).unwrap_or_else(|| command_for(pid)); if let Ok(mut values) = history.0.lock() { *values.entry(executable).or_default() += 1; } }

fn binary_trust(path: &str) -> BinaryTrust {
  let cache = BINARY_TRUST_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
  if let Ok(values) = cache.lock() { if let Some(value) = values.get(path) { return value.clone(); } }
  let signed = Command::new("/usr/bin/codesign").args(["--verify", "--deep", "--strict", path]).status().map(|status| status.success()).unwrap_or(false);
  let value = if !signed { BinaryTrust::Unsigned } else {
    let trusted = Command::new("/usr/sbin/spctl").args(["--assess", "--type", "execute", path]).status().map(|status| status.success()).unwrap_or(false);
    if trusted { BinaryTrust::Trusted } else { BinaryTrust::Signed }
  };
  if let Ok(mut values) = cache.lock() { values.insert(path.to_string(), value.clone()); }
  value
}

fn parse_binding(value: &str) -> Option<(String, u16)> {
  let colon = value.rfind(':')?;
  let address = value[..colon].trim_matches(['[', ']']).to_string();
  let port = value[colon + 1..].parse::<u16>().ok()?;
  Some((address, port))
}

fn parse_lsof(raw: &str, current_uid: &str) -> Vec<Listener> {
  let mut processes: BTreeMap<u32, ProcessRecord> = BTreeMap::new();
  let mut pid: Option<u32> = None;
  for line in raw.lines() {
    if line.len() < 2 { continue; }
    let (field, value) = line.split_at(1);
    match field {
      "p" => { pid = value.parse::<u32>().ok(); if let Some(id) = pid { processes.entry(id).or_insert_with(|| ProcessRecord { pid: id, ..Default::default() }); } }
      "c" => if let Some(id) = pid { processes.entry(id).or_default().name = value.to_string(); }
      "u" => if let Some(id) = pid { processes.entry(id).or_default().owner = value.to_string(); }
      "n" => if let (Some(id), Some(binding)) = (pid, parse_binding(value)) { processes.entry(id).or_default().bindings.push(binding); }
      _ => {}
    }
  }
  let mut grouped: BTreeMap<(u32, u16), Listener> = BTreeMap::new();
  for record in processes.into_values() {
    let executable = executable_for(record.pid);
    let trust = executable.as_deref().map(binary_trust).unwrap_or(BinaryTrust::Unknown);
    let command = command_for(record.pid);
    for (address, port) in record.bindings {
      let owner_matches = record.owner == current_uid;
      let listener = grouped.entry((record.pid, port)).or_insert_with(|| Listener {
        id: format!("{}:{port}", record.pid), pid: record.pid, process_name: record.name.clone(), command: command.clone(), owner: record.owner.clone(), port,
        bindings: Vec::new(), binary_trust: trust.clone(), is_protected: !owner_matches, can_stop: owner_matches,
      });
      let is_localhost = matches!(address.as_str(), "127.0.0.1" | "::1" | "localhost");
      if !listener.bindings.iter().any(|b| b.address == address) { listener.bindings.push(Binding { address, is_localhost }); }
    }
  }
  grouped.into_values().collect()
}

fn scan_listeners() -> Result<Vec<Listener>, String> {
  let output = Command::new("/usr/sbin/lsof").args(["-nP", "-iTCP", "-sTCP:LISTEN", "-FpcuLnf"]).output().map_err(|e| format!("Could not run lsof: {e}"))?;
  if !output.status.success() && !output.stdout.is_empty() { return Err(String::from_utf8_lossy(&output.stderr).trim().to_string()); }
  let uid = current_uid()?;
  Ok(parse_lsof(&String::from_utf8_lossy(&output.stdout), &uid))
}

fn env_present(name: &str) -> bool { std::env::var_os(name).is_some_and(|value| !value.is_empty()) }

fn sandbox_status() -> SandboxStatus {
  let mut indicators = Vec::new();
  if env_present("APP_SANDBOX_CONTAINER_ID") { indicators.push("APP_SANDBOX_CONTAINER_ID".into()); }
  if std::env::var("HOME").ok().is_some_and(|home| home.contains("/Library/Containers/")) { indicators.push("App container home directory".into()); }
  if !indicators.is_empty() { return SandboxStatus { environment: "macOS App Sandbox".into(), level: "process".into(), details: "The process is isolated by macOS App Sandbox entitlements.".into(), indicators }; }

  if env_present("SNAP") { return SandboxStatus { environment: "Snap sandbox".into(), level: "process".into(), details: "The process is confined by Snap.".into(), indicators: vec!["SNAP".into()] }; }
  if env_present("FLATPAK_ID") { return SandboxStatus { environment: "Flatpak sandbox".into(), level: "process".into(), details: "The process is confined by Flatpak.".into(), indicators: vec!["FLATPAK_ID".into()] }; }
  if env_present("WSL_INTEROP") || env_present("WSL_DISTRO_NAME") { return SandboxStatus { environment: "Windows Subsystem for Linux".into(), level: "virtualized".into(), details: "The process runs in a WSL virtualized Linux environment.".into(), indicators: vec!["WSL environment variable".into()] }; }
  if Path::new("/.dockerenv").exists() { return SandboxStatus { environment: "Docker container".into(), level: "container".into(), details: "The process runs inside a Docker container.".into(), indicators: vec!["/.dockerenv".into()] }; }
  if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
    let value = cgroup.to_ascii_lowercase();
    if ["docker", "containerd", "kubepods", "podman", "lxc"].iter().any(|marker| value.contains(marker)) {
      return SandboxStatus { environment: "Linux container".into(), level: "container".into(), details: "The process is running in a Linux container environment.".into(), indicators: vec!["/proc/1/cgroup".into()] };
    }
  }
  SandboxStatus { environment: "No known sandbox detected".into(), level: "none".into(), details: "No Docker, WSL, Snap, Flatpak, or macOS App Sandbox markers were found.".into(), indicators: vec![] }
}

#[tauri::command]
fn process_sandbox_status() -> SandboxStatus { sandbox_status() }

fn owned_process(pid: u32) -> Result<(), String> {
  let listeners = scan_listeners()?;
  let listener = listeners.iter().find(|item| item.pid == pid).ok_or_else(|| "This process is no longer listening.".to_string())?;
  if !listener.can_stop { return Err("Protected processes cannot be stopped by PortMan.".to_string()); }
  Ok(())
}

fn process_exists(pid: u32) -> bool { Command::new("kill").args(["-0", &pid.to_string()]).status().map(|s| s.success()).unwrap_or(false) }

fn signal(pid: u32, signal: &str) -> Result<(), String> {
  let status = Command::new("kill").args([signal, &pid.to_string()]).status().map_err(|e| format!("Could not signal process: {e}"))?;
  if status.success() { Ok(()) } else { Err("macOS refused to signal this process.".to_string()) }
}

fn frontmost_process_id() -> Result<u32, String> {
  #[cfg(target_os = "macos")]
  let output = Command::new("/usr/bin/osascript").args(["-e", "tell application \"System Events\" to get unix id of first application process whose frontmost is true"]).output().map_err(|e| format!("Could not inspect the frontmost application: {e}"))?;
  #[cfg(not(target_os = "macos"))]
  return Err("Killing the frontmost window is currently available on macOS only.".into());
  #[cfg(target_os = "macos")]
  if !output.status.success() { return Err("PortMan needs macOS Accessibility permission to identify the frontmost application.".into()); }
  #[cfg(target_os = "macos")]
  String::from_utf8_lossy(&output.stdout).trim().parse().map_err(|_| "Could not determine the frontmost application process.".into())
}

fn focus_and_scan(app: &AppHandle) {
  if let Some(window) = app.get_webview_window("main") { let _ = window.show(); let _ = window.set_focus(); }
  let _ = app.emit("shortcut-scan", ());
}

fn kill_frontmost_process(app: &AppHandle) {
  let result = frontmost_process_id().and_then(|pid| {
    if pid == std::process::id() { return Err("PortMan will not terminate itself.".into()); }
    signal(pid, "-TERM").map(|_| format!("Sent a quit signal to frontmost process {pid}."))
  });
  let _ = app.emit("shortcut-action", result.unwrap_or_else(|error| error));
}

#[tauri::command]
fn list_listeners() -> Result<Vec<Listener>, String> { scan_listeners() }

#[tauri::command]
fn stop_listener(pid: u32, history: State<StopHistoryState>) -> Result<StopResult, String> {
  owned_process(pid)?; let risk = stop_risk_for_pid(pid, &history)?; if risk.blocked { return Err(risk.consequence); } signal(pid, "-TERM")?;
  for _ in 0..50 { if !process_exists(pid) { record_stop(pid, &history); return Ok(StopResult { stopped: true, requires_force: false, message: "Server stopped gracefully.".into() }); } thread::sleep(Duration::from_millis(100)); }
  Ok(StopResult { stopped: false, requires_force: true, message: "The server is still running. You may Force Stop it.".into() })
}

#[tauri::command]
fn force_stop_listener(pid: u32, history: State<StopHistoryState>) -> Result<StopResult, String> {
  owned_process(pid)?; let risk = stop_risk_for_pid(pid, &history)?; if risk.blocked { return Err(risk.consequence); } signal(pid, "-KILL")?; record_stop(pid, &history);
  Ok(StopResult { stopped: true, requires_force: false, message: "Server force-stopped.".into() })
}

#[tauri::command]
fn resume_listener(pid: u32, guard: State<MemoryGuardState>) -> Result<StopResult, String> {
  owned_process(pid)?; signal(pid, "-CONT")?;
  if let Ok(mut config) = guard.0.lock() { config.paused_pids.remove(&pid); }
  Ok(StopResult { stopped: false, requires_force: false, message: "Server resumed after memory protection.".into() })
}
#[tauri::command]
fn memory_guard_status(guard: State<MemoryGuardState>) -> Result<MemoryGuardStatus, String> { let config = guard.0.lock().map_err(|_| "Memory guard is unavailable.".to_string())?; Ok(MemoryGuardStatus { enabled: config.enabled, threshold_percent: 95 }) }
#[tauri::command]
fn set_memory_guard(enabled: bool, guard: State<MemoryGuardState>) -> Result<MemoryGuardStatus, String> { let mut config = guard.0.lock().map_err(|_| "Memory guard is unavailable.".to_string())?; config.enabled = enabled; Ok(MemoryGuardStatus { enabled, threshold_percent: 95 }) }
fn process_nice(pid: u32) -> i32 { Command::new("ps").args(["-p", &pid.to_string(), "-o", "nice="]).output().ok().and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse().ok()).unwrap_or(0) }
fn check_memory_guard(app: &AppHandle) {
  let guard = app.state::<MemoryGuardState>(); let Ok(mut config) = guard.0.lock() else { return; }; if !config.enabled { return; }
  let mut system = System::new(); system.refresh_memory(); let total = system.total_memory(); let used = system.used_memory();
  if total == 0 || used.saturating_mul(100) < total.saturating_mul(95) { return; }
  let listeners = match scan_listeners() { Ok(value) => value, Err(_) => return }; let mut processes = System::new(); processes.refresh_processes(ProcessesToUpdate::All, true);
  let candidate = listeners.iter().filter(|listener| listener.can_stop && !config.paused_pids.contains(&listener.pid)).filter_map(|listener| processes.process(Pid::from_u32(listener.pid)).map(|process| (listener, process.memory(), process_nice(listener.pid)))).max_by_key(|(_, memory, nice)| (*nice, *memory));
  if let Some((listener, memory, _)) = candidate { if signal(listener.pid, "-STOP").is_ok() { config.paused_pids.insert(listener.pid); let _ = app.emit("memory-guard-alert", MemoryGuardAlert { pid: listener.pid, process_name: listener.process_name.clone(), memory_bytes: memory, total_memory_bytes: total, utilization_percent: used as f32 / total as f32 * 100.0 }); } }
}

#[tauri::command]
fn process_metrics(pid: u32, state: State<MetricsState>) -> Result<ProcessMetrics, String> {
  let process_pid = Pid::from_u32(pid);
  let mut system = state.0.lock().map_err(|_| "Metrics sampler is unavailable.".to_string())?;
  system.refresh_processes(ProcessesToUpdate::Some(&[process_pid]), true);
  let process = system.process(process_pid).ok_or_else(|| "This process is no longer running.".to_string())?;
  let disk = process.disk_usage();
  Ok(ProcessMetrics {
    cpu_percent: process.cpu_usage(), memory_bytes: process.memory(),
    read_bytes_per_sec: disk.read_bytes, write_bytes_per_sec: disk.written_bytes,
  })
}

fn public_remote_addresses(pid: u32) -> Vec<String> {
  let output = Command::new("/usr/sbin/lsof").args(["-nP", "-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:ESTABLISHED", "-Fn"]).output().ok();
  let mut remotes = BTreeMap::new();
  if let Some(output) = output { for line in String::from_utf8_lossy(&output.stdout).lines() { if let Some((ip, port)) = line.strip_prefix('n').and_then(|value| value.split("->").nth(1)).and_then(parse_socket) { if !is_private_host(&ip) { remotes.insert(format!("{ip}:{port}"), ()); } } } }
  remotes.into_keys().collect()
}

#[tauri::command]
fn instance_anomalies(pids: Vec<u32>, state: State<MetricsState>) -> Result<Vec<InstanceAnomaly>, String> {
  let process_ids: Vec<Pid> = pids.iter().copied().map(Pid::from_u32).collect();
  let mut system = state.0.lock().map_err(|_| "Metrics sampler is unavailable.".to_string())?;
  system.refresh_processes(ProcessesToUpdate::Some(&process_ids), true);
  let cache = ANOMALY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
  let mut baselines = cache.lock().map_err(|_| "Anomaly model is unavailable.".to_string())?;
  let mut results = Vec::new();
  for pid in pids {
    let Some(process) = system.process(Pid::from_u32(pid)) else { continue; };
    let remotes = public_remote_addresses(pid);
    let key = executable_for(pid).unwrap_or_else(|| command_for(pid));
    let baseline = baselines.entry(key).or_default();
    let cpu = process.cpu_usage() as f64; let memory = process.memory() as f64 / (1024.0 * 1024.0); let connections = remotes.len() as f64;
    let novel = remotes.iter().filter(|remote| !baseline.remotes.contains(*remote)).count() as f64;
    let deviations = [("CPU", baseline.cpu.deviation(cpu)), ("memory", baseline.memory.deviation(memory)), ("outbound connections", baseline.connections.deviation(connections)), ("new remote connections", baseline.novel_connections.deviation(novel))];
    let score = deviations.iter().map(|(_, value)| value.powi(2)).sum::<f64>().sqrt();
    let samples = baseline.cpu.samples;
    let is_anomalous = samples >= 12 && score >= 4.0;
    let strongest = deviations.iter().max_by(|a, b| a.1.abs().total_cmp(&b.1.abs())).map(|(label, _)| *label).unwrap_or("activity");
    let summary = if samples < 12 { format!("Learning normal behavior ({samples}/12 samples).") } else if is_anomalous { format!("Unusual {strongest} compared with this executable's learned baseline. Review or force stop it.") } else { "Activity is within this executable's learned baseline.".into() };
    baseline.cpu.observe(cpu); baseline.memory.observe(memory); baseline.connections.observe(connections); baseline.novel_connections.observe(novel);
    for remote in remotes { if baseline.remotes.len() < 256 { baseline.remotes.insert(remote); } }
    results.push(InstanceAnomaly { pid, score, baseline_samples: samples, is_anomalous, summary, cpu_percent: process.cpu_usage(), memory_bytes: process.memory(), outbound_connections: connections as usize, novel_remote_connections: novel as usize });
  }
  Ok(results)
}

fn parse_process_threads(raw: &str) -> Vec<ProcessThread> {
  let mut threads: Vec<ProcessThread> = raw.lines().filter_map(|line| {
    let mut fields = line.split_whitespace();
    let id = fields.next()?.parse().ok()?;
    let cpu_percent = fields.next()?.parse().ok()?;
    let name = fields.collect::<Vec<_>>().join(" ");
    Some(ProcessThread { id, cpu_percent, name: if name.is_empty() { "Thread".into() } else { name } })
  }).collect();
  threads.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent).then_with(|| a.id.cmp(&b.id)));
  threads
}

#[tauri::command]
fn process_threads(pid: u32) -> Result<Vec<ProcessThread>, String> {
  #[cfg(target_os = "macos")]
  let args = ["-M", "-p", &pid.to_string(), "-o", "tid=,pcpu=,comm="];
  #[cfg(not(target_os = "macos"))]
  let args = ["-L", "-p", &pid.to_string(), "-o", "lwp=,pcpu=,comm="];
  let output = Command::new("ps").args(args).output().map_err(|e| format!("Could not inspect process threads: {e}"))?;
  if !output.status.success() { return Err("The process is no longer running or its threads cannot be inspected.".into()); }
  Ok(parse_process_threads(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_socket(value: &str) -> Option<(String, u16)> {
  let endpoint = value.trim().trim_matches(['[', ']']);
  let separator = endpoint.rfind(':')?;
  Some((endpoint[..separator].trim_matches(['[', ']']).to_string(), endpoint[separator + 1..].parse().ok()?))
}

fn is_private_host(ip: &str) -> bool {
  if matches!(ip, "localhost" | "::1" | "::" | "0.0.0.0") || ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("169.254.") || ip.starts_with("fc") || ip.starts_with("fd") || ip.starts_with("fe80:") { return true; }
  let octets: Vec<u8> = ip.split('.').filter_map(|part| part.parse().ok()).collect();
  octets.len() == 4 && octets[0] == 172 && (16..=31).contains(&octets[1])
}

fn lookup_geo(ip: &str) -> Option<GeoLocation> {
  let cache = GEO_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
  if let Ok(values) = cache.lock() { if let Some(value) = values.get(ip) { return value.clone(); } }
  let output = Command::new("/usr/bin/curl").args(["-sS", "--max-time", "3", &format!("https://ipwho.is/{ip}")]).output().ok();
  let location = output.and_then(|data| serde_json::from_slice::<GeoResponse>(&data.stdout).ok()).and_then(|response| {
    if response.success { Some(GeoLocation { city: response.city.unwrap_or_else(|| "Unknown city".into()), country: response.country.unwrap_or_else(|| "Unknown country".into()), latitude: response.latitude?, longitude: response.longitude? }) } else { None }
  });
  if let Ok(mut values) = cache.lock() { values.insert(ip.to_string(), location.clone()); }
  location
}

#[tauri::command]
fn outbound_connections(pid: u32) -> Result<Vec<RemoteConnection>, String> {
  let output = Command::new("/usr/sbin/lsof").args(["-nP", "-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:ESTABLISHED", "-Fn"]).output().map_err(|e| format!("Could not inspect connections: {e}"))?;
  let mut endpoints = BTreeMap::new();
  for line in String::from_utf8_lossy(&output.stdout).lines() {
    if let Some(remote) = line.strip_prefix('n').and_then(|value| value.split("->").nth(1)).and_then(parse_socket) {
      if !is_private_host(&remote.0) { endpoints.insert(remote, ()); }
    }
  }
  Ok(endpoints.into_keys().take(12).map(|(remote_ip, remote_port)| RemoteConnection { location: lookup_geo(&remote_ip), remote_ip, remote_port }).collect())
}

#[tauri::command]
fn open_listener(listener: Listener) -> Result<String, String> {
  let raw = listener.bindings.first().map(|b| b.address.as_str()).unwrap_or("127.0.0.1");
  let host = match raw { "*" | "0.0.0.0" => "127.0.0.1".to_string(), "::" => "[::1]".to_string(), value if value.contains(':') => format!("[{value}]"), value => value.to_string() };
  let url = format!("http://{host}:{}", listener.port);
  let status = Command::new("open").arg(&url).status().map_err(|e| format!("Could not open browser: {e}"))?;
  if status.success() { Ok(url) } else { Err("macOS could not open this address.".into()) }
}

fn sha256_file(path: &Path) -> Result<String, String> {
  let file = File::open(path).map_err(|e| format!("Could not read executable for hashing: {e}"))?;
  let mut reader = BufReader::new(file); let mut hasher = Sha256::new(); let mut buffer = [0_u8; 64 * 1024];
  loop { let read = reader.read(&mut buffer).map_err(|e| format!("Could not hash executable: {e}"))?; if read == 0 { break; } hasher.update(&buffer[..read]); }
  Ok(format!("{:x}", hasher.finalize()))
}

fn local_blocked_hashes() -> HashSet<String> {
  serde_json::from_str::<SignatureDatabase>(include_str!("../signatures.json")).map(|database| database.blocked_sha256).unwrap_or_default().into_iter().chain(std::env::var("PORTMAN_BLOCKED_SHA256").unwrap_or_default().split(',').map(str::to_string)).map(|hash| hash.trim().to_ascii_lowercase()).filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).collect()
}

fn is_untrusted_launch_location(path: &str) -> bool {
  let normalized = path.replace('\\', "/").to_ascii_lowercase();
  normalized.contains("/downloads/") || normalized.contains("/tmp/") || normalized.contains("/private/var/folders/") || normalized.contains("/appdata/local/temp/")
}

fn should_ignore_executable(path: &Path) -> bool {
  let value = path.to_string_lossy();
  value.starts_with("/System/") || value.starts_with("/usr/") || value.starts_with("/bin/") || value.starts_with("/sbin/") || value.starts_with("/Library/Apple/")
}

fn process_owned_by_current_user(pid: u32) -> bool {
  let Ok(current) = current_uid() else { return false; };
  Command::new("ps").args(["-p", &pid.to_string(), "-o", "uid="]).output().ok().is_some_and(|output| String::from_utf8_lossy(&output.stdout).trim() == current)
}

fn inspect_new_process(pid: u32, process_name: String, path: &Path, blocked_hashes: &HashSet<String>) -> Option<QuarantineEntry> {
  if should_ignore_executable(path) || !path.is_file() { return None; }
  let path_text = path.to_string_lossy().to_string(); let hash = sha256_file(path).ok()?; let mut reasons = Vec::new();
  if blocked_hashes.contains(&hash) { reasons.push("SHA-256 matches PortMan's local blocked-signature database.".into()); }
  let trust = binary_trust(&path_text);
  if is_untrusted_launch_location(&path_text) && matches!(trust, BinaryTrust::Unsigned | BinaryTrust::Unknown) {
    reasons.push("Unsigned executable launched from a temporary or Downloads location.".into());
  }
  let name = process_name.to_ascii_lowercase();
  if is_untrusted_launch_location(&path_text) && matches!(trust, BinaryTrust::Unsigned | BinaryTrust::Unknown) && ["crack", "keygen", "payload", "miner"].iter().any(|word| name.contains(word)) {
    reasons.push("Executable name matches a high-risk local rule.".into());
  }
  (!reasons.is_empty()).then(|| QuarantineEntry { id: 0, pid, process_name, path: path_text, sha256: hash, reasons, detected_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(), state: "detected".into(), can_resume: false })
}

fn check_execution_watcher(app: &AppHandle, initialized: &mut bool) {
  let watcher = app.state::<ExecutionWatcherState>(); let mut system = System::new(); system.refresh_processes(ProcessesToUpdate::All, true);
  let pids: HashSet<u32> = system.processes().keys().map(|pid| pid.as_u32()).collect();
  let Ok(mut config) = watcher.0.lock() else { return; };
  if !*initialized { config.seen_pids = pids; *initialized = true; return; }
  let new_pids: Vec<u32> = pids.difference(&config.seen_pids).copied().collect(); config.seen_pids = pids;
  if !config.enabled { return; }
  for pid in new_pids {
    let Some(process) = system.process(Pid::from_u32(pid)) else { continue; };
    let Some(path) = process.exe() else { continue; };
    let Some(mut entry) = inspect_new_process(pid, process.name().to_string_lossy().to_string(), path, &config.blocked_hashes) else { continue; };
    entry.id = config.next_id; config.next_id += 1;
    if config.auto_pause && process_owned_by_current_user(pid) && pid != std::process::id() {
      if signal(pid, "-STOP").is_ok() { entry.state = "paused".into(); entry.can_resume = true; }
    }
    config.quarantined.push(entry.clone()); let _ = app.emit("execution-quarantined", entry);
  }
}

#[tauri::command]
fn execution_watcher_status(watcher: State<ExecutionWatcherState>) -> Result<ExecutionWatcherStatus, String> {
  let config = watcher.0.lock().map_err(|_| "Execution watcher is unavailable.".to_string())?;
  Ok(ExecutionWatcherStatus { enabled: config.enabled, auto_pause: config.auto_pause, platform_mode: if cfg!(target_os = "macos") { "Process monitoring; Endpoint Security requires a separately entitled system extension.".into() } else { "Process polling monitor".into() } })
}

#[tauri::command]
fn set_execution_watcher(enabled: bool, auto_pause: bool, watcher: State<ExecutionWatcherState>) -> Result<ExecutionWatcherStatus, String> {
  let mut config = watcher.0.lock().map_err(|_| "Execution watcher is unavailable.".to_string())?; config.enabled = enabled; config.auto_pause = auto_pause;
  Ok(ExecutionWatcherStatus { enabled, auto_pause, platform_mode: if cfg!(target_os = "macos") { "Process monitoring; Endpoint Security requires a separately entitled system extension.".into() } else { "Process polling monitor".into() } })
}

#[tauri::command]
fn quarantined_processes(watcher: State<ExecutionWatcherState>) -> Result<Vec<QuarantineEntry>, String> {
  let config = watcher.0.lock().map_err(|_| "Quarantine is unavailable.".to_string())?; Ok(config.quarantined.clone())
}

#[tauri::command]
fn resume_quarantined(pid: u32, watcher: State<ExecutionWatcherState>) -> Result<StopResult, String> {
  if !process_owned_by_current_user(pid) { return Err("Only your own quarantined processes can be resumed.".into()); }
  signal(pid, "-CONT")?;
  let mut config = watcher.0.lock().map_err(|_| "Quarantine is unavailable.".to_string())?;
  if let Some(entry) = config.quarantined.iter_mut().rev().find(|entry| entry.pid == pid && entry.state == "paused") { entry.state = "resumed".into(); entry.can_resume = false; }
  Ok(StopResult { stopped: false, requires_force: false, message: "Quarantined process resumed.".into() })
}

fn start_watcher(app: AppHandle) {
  std::thread::spawn(move || {
    let mut last: Vec<Listener> = Vec::new();
    let mut execution_watcher_initialized = false;
    loop {
      if let Ok(next) = scan_listeners() { if next != last { let _ = app.emit("server-list-updated", &next); last = next; } }
      check_memory_guard(&app);
      check_execution_watcher(&app, &mut execution_watcher_initialized);
      thread::sleep(Duration::from_secs(1));
    }
  });
}

pub fn run() {
  let show_portman = Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyP);
  let kill_frontmost = Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SHIFT), Code::KeyK);
  let blocked_hashes = local_blocked_hashes();
  tauri::Builder::default().manage(MetricsState(Mutex::new(System::new()))).manage(StopHistoryState(Mutex::new(HashMap::new()))).manage(MemoryGuardState(Mutex::new(MemoryGuardConfig { enabled: false, paused_pids: BTreeSet::new() }))).manage(ExecutionWatcherState(Mutex::new(ExecutionWatcherConfig { enabled: true, auto_pause: false, seen_pids: HashSet::new(), quarantined: Vec::new(), next_id: 1, blocked_hashes }))).plugin(tauri_plugin_opener::init()).setup(move |app| {
    let show_portman = show_portman; let kill_frontmost = kill_frontmost;
    app.handle().plugin(tauri_plugin_global_shortcut::Builder::new().with_handler(move |app, shortcut, event| {
      if event.state() != ShortcutState::Pressed { return; }
      if shortcut == &show_portman { focus_and_scan(app); }
      if shortcut == &kill_frontmost { kill_frontmost_process(app); }
    }).build())?;
    use tauri_plugin_global_shortcut::GlobalShortcutExt;
    app.global_shortcut().register(show_portman)?;
    app.global_shortcut().register(kill_frontmost)?;
    start_watcher(app.handle().clone()); Ok(())
  })
    .invoke_handler(tauri::generate_handler![list_listeners, stop_listener, force_stop_listener, resume_listener, stop_risk, memory_guard_status, set_memory_guard, execution_watcher_status, set_execution_watcher, quarantined_processes, resume_quarantined, process_metrics, process_threads, inspect_executable, instance_anomalies, outbound_connections, open_listener, process_sandbox_status])
    .run(tauri::generate_context!()).expect("error while running PortMan");
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test] fn parses_and_groups_lsof_records() {
    let raw = "p123\ncnode\nu501\nn127.0.0.1:3000\nn*:3000\np456\ncrootd\nu0\nn*:80\n";
    let listeners = parse_lsof(raw, "501");
    assert_eq!(listeners.len(), 2); assert_eq!(listeners[0].bindings.len(), 2); assert!(listeners[0].can_stop); assert!(listeners[1].is_protected); assert_eq!(listeners[0].binary_trust, BinaryTrust::Unknown);
  }
  #[test] fn recognizes_local_bindings() { assert_eq!(parse_binding("[::1]:8080"), Some(("::1".into(), 8080))); }
  #[test] fn parses_threads_and_sorts_by_cpu() {
    let threads = parse_process_threads("101 0.2 worker\n99 12.5 server main\n");
    assert_eq!(threads, vec![ProcessThread { id: 99, name: "server main".into(), cpu_percent: 12.5 }, ProcessThread { id: 101, name: "worker".into(), cpu_percent: 0.2 }]);
  }
  #[test] fn identifies_untrusted_launch_locations() { assert!(is_untrusted_launch_location("/Users/test/Downloads/tool")); assert!(is_untrusted_launch_location("C:\\Users\\test\\AppData\\Local\\Temp\\tool.exe")); assert!(!is_untrusted_launch_location("/Applications/Safari.app")); }
}
