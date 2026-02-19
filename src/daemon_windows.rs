//! Process daemonization and IPC for background operation on Windows.

use crate::config::{Config, TelemetryConfig};

use anyhow::Context as _;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithHttpConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, STILL_ACTIVE};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, GetExitCodeProcess, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt as _;

const DAEMON_CHILD_ENV: &str = "SPACEBOT_DAEMON_CHILD";
const PIPE_CONNECT_ATTEMPTS: usize = 30;
const PIPE_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Commands sent from CLI client to the running daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum IpcCommand {
    Shutdown,
    Status,
}

/// Responses from the daemon back to the CLI client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok,
    Status { pid: u32, uptime_seconds: u64 },
    Error { message: String },
}

/// Paths for daemon runtime files, all derived from the instance directory.
pub struct DaemonPaths {
    pub pid_file: PathBuf,
    pub socket: PathBuf,
    pub log_dir: PathBuf,
}

impl DaemonPaths {
    pub fn new(instance_dir: &std::path::Path) -> Self {
        Self {
            pid_file: instance_dir.join("spacebot.pid"),
            socket: instance_dir.join("spacebot.pipe"),
            log_dir: instance_dir.join("logs"),
        }
    }

    pub fn from_default() -> Self {
        Self::new(&Config::default_instance_dir())
    }
}

/// Check whether a daemon is already running by testing PID file liveness.
pub fn is_running(paths: &DaemonPaths) -> Option<u32> {
    let pid = read_pid_file(&paths.pid_file)?;

    if !is_process_alive(pid) {
        cleanup_stale_files(paths);
        return None;
    }

    // If the process is alive, treat it as running.
    Some(pid)
}

/// Daemonize the current process by spawning a detached child process.
pub fn daemonize(paths: &DaemonPaths) -> anyhow::Result<()> {
    if std::env::var(DAEMON_CHILD_ENV).as_deref() == Ok("1") {
        write_pid_file(paths, std::process::id())?;
        return Ok(());
    }

    std::fs::create_dir_all(&paths.log_dir).with_context(|| {
        format!(
            "failed to create log directory: {}",
            paths.log_dir.display()
        )
    })?;

    let stdout = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_dir.join("spacebot.out"))
        .context("failed to open stdout log")?;

    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_dir.join("spacebot.err"))
        .context("failed to open stderr log")?;

    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let mut command = Command::new(executable);

    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    command.args(args);
    command.env(DAEMON_CHILD_ENV, "1");
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::from(stderr));
    command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);

    let child = command
        .spawn()
        .context("failed to spawn detached daemon process")?;

    write_pid_file(paths, child.id())?;

    // Match Unix daemonization behavior: parent exits after successfully
    // launching the detached child.
    std::process::exit(0);
}

/// Initialize tracing for background (daemon) mode.
///
/// Returns an `SdkTracerProvider` if OTLP export is configured. The caller must
/// hold onto it for the process lifetime and call `.shutdown()` before exit so
/// the batch exporter flushes buffered spans.
pub fn init_background_tracing(
    paths: &DaemonPaths,
    debug: bool,
    telemetry: &TelemetryConfig,
) -> Option<SdkTracerProvider> {
    let file_appender = tracing_appender::rolling::daily(&paths.log_dir, "spacebot.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Leak the guard so the non-blocking writer lives for the entire process.
    // The process owns this — it's cleaned up on exit.
    std::mem::forget(guard);

    let filter = build_env_filter(debug);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false);

    match build_otlp_provider(telemetry) {
        Some(provider) => {
            let tracer = provider.tracer("spacebot");
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
            Some(provider)
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
            None
        }
    }
}

/// Initialize tracing for foreground (terminal) mode.
///
/// Returns an `SdkTracerProvider` if OTLP export is configured.
pub fn init_foreground_tracing(
    debug: bool,
    telemetry: &TelemetryConfig,
) -> Option<SdkTracerProvider> {
    let filter = build_env_filter(debug);
    let fmt_layer = tracing_subscriber::fmt::layer();

    match build_otlp_provider(telemetry) {
        Some(provider) => {
            let tracer = provider.tracer("spacebot");
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
            Some(provider)
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
            None
        }
    }
}

fn build_env_filter(debug: bool) -> tracing_subscriber::EnvFilter {
    if debug {
        tracing_subscriber::EnvFilter::new("debug")
    } else {
        tracing_subscriber::EnvFilter::new("info")
    }
}

/// Build an OTLP `SdkTracerProvider` when an endpoint is configured.
///
/// Returns `None` if neither the config field nor the `OTEL_EXPORTER_OTLP_ENDPOINT`
/// environment variable is set, allowing the OTel layer to be omitted entirely.
fn build_otlp_provider(telemetry: &TelemetryConfig) -> Option<SdkTracerProvider> {
    use opentelemetry_otlp::WithExportConfig as _;

    let endpoint = telemetry.otlp_endpoint.as_deref()?;

    // The HTTP/protobuf endpoint path is /v1/traces by default. Append it only
    // when the caller provided a bare host:port so both forms work.
    let endpoint = if endpoint.ends_with("/v1/traces") {
        endpoint.to_owned()
    } else {
        format!("{}/v1/traces", endpoint.trim_end_matches('/'))
    };

    let mut exporter_builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint);
    if !telemetry.otlp_headers.is_empty() {
        exporter_builder = exporter_builder.with_headers(telemetry.otlp_headers.clone());
    }
    let exporter = exporter_builder
        .build()
        .map_err(|error| eprintln!("failed to build OTLP exporter: {error}"))
        .ok()?;

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(telemetry.service_name.clone())
        .build();

    let sampler: opentelemetry_sdk::trace::Sampler =
        if (telemetry.sample_rate - 1.0).abs() < f64::EPSILON {
            opentelemetry_sdk::trace::Sampler::AlwaysOn
        } else {
            opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
                opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(telemetry.sample_rate),
            ))
        };

    // Use the async-runtime-aware BatchSpanProcessor so the export future is
    // driven by tokio::spawn rather than a plain OS thread using
    // futures_executor::block_on. The sync variant panics because reqwest
    // calls tokio::time::sleep internally, which requires an active Tokio
    // runtime on the calling thread — something the plain thread never has.
    let batch_processor =
        opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor::builder(
            exporter,
            opentelemetry_sdk::runtime::Tokio,
        )
        .build();

    let provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    Some(provider)
}

/// Start the IPC server. Returns a shutdown receiver that the main event
/// loop should select on.
pub async fn start_ipc_server(
    paths: &DaemonPaths,
) -> anyhow::Result<(watch::Receiver<bool>, tokio::task::JoinHandle<()>)> {
    if let Some(parent) = paths.pid_file.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create instance directory: {}", parent.display())
        })?;
    }

    write_pid_file(paths, std::process::id())?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let start_time = Instant::now();
    let pipe_name = pipe_name(paths);

    let handle = tokio::task::spawn_blocking({
        let mut shutdown_rx = shutdown_rx.clone();
        let shutdown_tx = shutdown_tx.clone();

        move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(%error, "failed to create IPC runtime");
                    return;
                }
            };

            runtime.block_on(async move {
                let mut first_pipe_instance = true;

                loop {
                    if *shutdown_rx.borrow() {
                        break;
                    }

                    let mut server_options = ServerOptions::new();
                    if first_pipe_instance {
                        server_options.first_pipe_instance(true);
                    }

                    let server = match server_options.create(&pipe_name) {
                        Ok(server) => server,
                        Err(error) => {
                            tracing::warn!(%error, pipe = %pipe_name, "failed to create IPC named pipe server");
                            tokio::time::sleep(Duration::from_millis(250)).await;
                            first_pipe_instance = false;
                            continue;
                        }
                    };

                    first_pipe_instance = false;

                    tokio::select! {
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        result = server.connect() => {
                            match result {
                                Ok(()) => {
                                    if let Err(error) =
                                        handle_ipc_connection(server, &shutdown_tx, start_time.elapsed()).await
                                    {
                                        tracing::warn!(%error, "IPC connection handler failed");
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(%error, "failed to accept IPC connection");
                                }
                            }
                        }
                    }
                }
            });
        }
    });

    Ok((shutdown_rx, handle))
}

/// Handle a single IPC client connection.
async fn handle_ipc_connection(
    stream: NamedPipeServer,
    shutdown_tx: &watch::Sender<bool>,
    uptime: Duration,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let command: IpcCommand = serde_json::from_str(line.trim())
        .with_context(|| format!("invalid IPC command: {line}"))?;

    let response = match command {
        IpcCommand::Shutdown => {
            tracing::info!("shutdown requested via IPC");
            shutdown_tx.send(true).ok();
            IpcResponse::Ok
        }
        IpcCommand::Status => IpcResponse::Status {
            pid: std::process::id(),
            uptime_seconds: uptime.as_secs(),
        },
    };

    let mut response_bytes = serde_json::to_vec(&response)?;
    response_bytes.push(b'\n');
    writer.write_all(&response_bytes).await?;
    writer.flush().await?;

    Ok(())
}

/// Send a command to the running daemon and return the response.
pub async fn send_command(paths: &DaemonPaths, command: IpcCommand) -> anyhow::Result<IpcResponse> {
    let pipe_name = pipe_name(paths);
    let mut stream = connect_pipe_with_retry(&pipe_name)
        .await
        .with_context(|| "failed to connect to spacebot daemon. is it running?")?;

    let mut command_bytes = serde_json::to_vec(&command)?;
    command_bytes.push(b'\n');
    stream.write_all(&command_bytes).await?;
    stream.flush().await?;

    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let response: IpcResponse = serde_json::from_str(line.trim())
        .with_context(|| format!("invalid IPC response: {line}"))?;

    Ok(response)
}

/// Clean up PID and socket files on shutdown.
pub fn cleanup(paths: &DaemonPaths) {
    if let Err(error) = std::fs::remove_file(&paths.pid_file) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(%error, "failed to remove PID file");
        }
    }
    if let Err(error) = std::fs::remove_file(&paths.socket) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(%error, "failed to remove socket file");
        }
    }
}

fn read_pid_file(path: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

fn is_process_alive(pid: u32) -> bool {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }

        let mut exit_code = 0_u32;
        let ok = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);

        ok != 0 && exit_code == STILL_ACTIVE as u32
    }
}

fn cleanup_stale_files(paths: &DaemonPaths) {
    let _ = std::fs::remove_file(&paths.pid_file);
    let _ = std::fs::remove_file(&paths.socket);
}

/// Wait for the daemon process to exit after sending a shutdown command.
/// Polls the PID with a short interval, times out after 10 seconds.
pub fn wait_for_exit(pid: u32) -> bool {
    for _ in 0..100 {
        if !is_process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

async fn connect_pipe_with_retry(pipe_name: &str) -> std::io::Result<NamedPipeClient> {
    for attempt in 0..PIPE_CONNECT_ATTEMPTS {
        match ClientOptions::new().open(pipe_name) {
            Ok(client) => return Ok(client),
            Err(error) => {
                let is_pipe_busy = error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32);
                let waiting_for_server =
                    is_pipe_busy || error.kind() == std::io::ErrorKind::NotFound;

                if waiting_for_server && attempt + 1 < PIPE_CONNECT_ATTEMPTS {
                    tokio::time::sleep(PIPE_CONNECT_RETRY_DELAY).await;
                    continue;
                }

                return Err(error);
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out connecting to daemon pipe",
    ))
}

fn pipe_name(paths: &DaemonPaths) -> String {
    let key = paths.socket.to_string_lossy();
    let hash = stable_hash(key.as_bytes());
    format!(r"\\.\pipe\spacebot-{hash:016x}")
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn write_pid_file(paths: &DaemonPaths, pid: u32) -> anyhow::Result<()> {
    if let Some(parent) = paths.pid_file.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create PID file directory: {}", parent.display())
        })?;
    }

    std::fs::write(&paths.pid_file, pid.to_string())
        .with_context(|| format!("failed to write PID file: {}", paths.pid_file.display()))
}
