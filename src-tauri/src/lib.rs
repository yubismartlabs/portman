use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, HashMap}, path::Path, process::Command, sync::{Mutex, OnceLock}, thread, time::Duration};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tauri::{AppHandle, Emitter, State};

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

struct MetricsState(Mutex<System>);
static BINARY_TRUST_CACHE: OnceLock<Mutex<HashMap<String, BinaryTrust>>> = OnceLock::new();
static GEO_CACHE: OnceLock<Mutex<HashMap<String, Option<GeoLocation>>>> = OnceLock::new();

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

fn executable_for(pid: u32) -> Option<String> {
  let output = Command::new("ps").args(["-p", &pid.to_string(), "-o", "comm="]).output().ok()?;
  let executable = String::from_utf8_lossy(&output.stdout).trim().to_string();
  (!executable.is_empty() && Path::new(&executable).exists()).then_some(executable)
}

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

#[tauri::command]
fn list_listeners() -> Result<Vec<Listener>, String> { scan_listeners() }

#[tauri::command]
fn stop_listener(pid: u32) -> Result<StopResult, String> {
  owned_process(pid)?; signal(pid, "-TERM")?;
  for _ in 0..50 { if !process_exists(pid) { return Ok(StopResult { stopped: true, requires_force: false, message: "Server stopped gracefully.".into() }); } thread::sleep(Duration::from_millis(100)); }
  Ok(StopResult { stopped: false, requires_force: true, message: "The server is still running. You may Force Stop it.".into() })
}

#[tauri::command]
fn force_stop_listener(pid: u32) -> Result<StopResult, String> {
  owned_process(pid)?; signal(pid, "-KILL")?;
  Ok(StopResult { stopped: true, requires_force: false, message: "Server force-stopped.".into() })
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

fn start_watcher(app: AppHandle) {
  std::thread::spawn(move || {
    let mut last: Vec<Listener> = Vec::new();
    loop {
      if let Ok(next) = scan_listeners() { if next != last { let _ = app.emit("server-list-updated", &next); last = next; } }
      thread::sleep(Duration::from_secs(1));
    }
  });
}

pub fn run() {
  tauri::Builder::default().manage(MetricsState(Mutex::new(System::new()))).plugin(tauri_plugin_opener::init()).setup(|app| { start_watcher(app.handle().clone()); Ok(()) })
    .invoke_handler(tauri::generate_handler![list_listeners, stop_listener, force_stop_listener, process_metrics, process_threads, outbound_connections, open_listener, process_sandbox_status])
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
}
