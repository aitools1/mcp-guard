use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mcp_guard_core::config::{
    build_guard_config, default_config_candidates, global_config_path, resolve_config_path,
    scan_config_files, GuardConfig,
};
use mcp_guard_core::events::{Event, EventLog};
use mcp_guard_core::proxy::{Proxy, RemoteProxy};
use mcp_guard_core::sandbox::SandboxConfig;

#[derive(Parser)]
#[command(name = "mcp-guard", version, about = "MCP stdio proxy, sandbox and secret filter")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan agent MCP configs (OpenCode, Claude, Cursor) and write mcp-guard.toml
    Import {
        /// Output file (default: ~/.mcp-guard/mcp-guard.toml)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Project directory to scan project-local configs from
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Run a proxied MCP server on stdio (plug this into agent configs instead of the raw command)
    Run {
        /// Server name from mcp-guard.toml
        server: String,
        /// Path to mcp-guard.toml (default: ./mcp-guard.toml or ~/.mcp-guard/mcp-guard.toml)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List configured servers and their security policy
    List {
        /// Path to mcp-guard.toml (default: ./mcp-guard.toml or ~/.mcp-guard/mcp-guard.toml)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Open the TUI dashboard
    Ui {
        /// Path to mcp-guard.toml (default: ./mcp-guard.toml or ~/.mcp-guard/mcp-guard.toml)
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Diagnostics go to stderr only; stdout is reserved for JSON-RPC in `run`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Import { output, dir } => import(output, dir),
        Commands::Run { server, config } => {
            let config_path = resolve_config_path(config.as_deref())
                .context("config not found: run 'mcp-guard import' or pass --config")?;
            run(server, config_path).await
        }
        Commands::List { config } => {
            let config_path = resolve_config_path(config.as_deref())
                .context("config not found: run 'mcp-guard import' or pass --config")?;
            list(config_path)
        }
        Commands::Ui { config } => {
            let config_path = resolve_config_path(config.as_deref())
                .context("config not found: run 'mcp-guard import' or pass --config")?;
            tui::run_tui(config_path)
        }
    }
}

fn import(output: Option<PathBuf>, dir: Option<PathBuf>) -> Result<()> {
    let project_dir = match dir {
        Some(d) => d,
        None => std::env::current_dir().context("cannot determine current directory")?,
    };

    let candidates = default_config_candidates(&project_dir);
    let hits = scan_config_files(&candidates);

    if hits.is_empty() {
        eprintln!("No agent MCP configs found. Scanned locations:");
        for (_, path) in &candidates {
            eprintln!("  - {}", path.display());
        }
        return Ok(());
    }

    let default_output = global_config_path()
        .context("cannot determine global config directory")?;
    let output_path = output.unwrap_or(default_output);

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create config directory")?;
    }

    eprintln!(
        "Found {} agent config(s):",
        hits.len()
    );
    for h in &hits {
        let names = h
            .servers
            .iter()
            .map(|s| {
                if s.command.is_empty() {
                    format!("{} (remote)", s.name)
                } else {
                    s.name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "  [{}] {} -> {} server(s): {names}",
            h.source,
            h.path.display(),
            h.servers.len()
        );
    }

    let cfg = build_guard_config(&hits, &project_dir);
    let toml_out = cfg.to_toml_string()?;
    std::fs::write(&output_path, toml_out)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    eprintln!(
        "Wrote {} server(s) to {}",
        cfg.server.len(),
        output_path.display()
    );
    Ok(())
}

/// Opens the event log. `$MCP_GUARD_EVENTS` overrides the default location
/// (empty string disables logging). Failures are non-fatal: the proxy still
/// works, telemetry just stops.
fn open_events() -> Option<Arc<EventLog>> {
    let path = EventLog::resolve_path()?;
    let log = EventLog::open(&path).ok()?;
    eprintln!("events: {}", path.display());
    Some(Arc::new(log))
}

async fn run(server_name: String, config_path: PathBuf) -> Result<()> {
    let cfg: GuardConfig =
        GuardConfig::from_file(config_path.to_str().context("config path is not valid UTF-8")?)
            .with_context(|| format!("failed to load config {}", config_path.display()))?;

    let srv = cfg
        .server
        .get(&server_name)
        .with_context(|| format!("server '{server_name}' not found in {}", config_path.display()))?
        .clone();

    let events = open_events();

    match srv {
        mcp_guard_core::config::ServerConfig::Stdio {
            command,
            args,
            allowed_dir,
            allow_env,
            disabled_tools,
        } => {
            let sandbox = SandboxConfig {
                allowed_dir: allowed_dir.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                }),
                allow_env,
            };

            eprintln!(
                "mcp-guard: proxying '{}' -> {} {}",
                server_name, command, args.join(" ")
            );
            eprintln!(
                "sandbox: dir={}, allow_env={:?}",
                sandbox.allowed_dir.display(),
                sandbox.allow_env
            );
            if !disabled_tools.is_empty() {
                eprintln!("disabled tools: {:?}", disabled_tools);
            }

            let proxy = Proxy::spawn(
                &server_name,
                &command,
                &args,
                &sandbox,
                disabled_tools,
                events.clone(),
            )?;

            if let Some(log) = &events {
                log.record(&Event::ServerStarted {
                    ts_ms: mcp_guard_core::events::now_ms(),
                    server: server_name.clone(),
                    proxy_pid: std::process::id(),
                    child_pid: proxy.child_pid(),
                });
            }

            proxy.run().await?;

            if let Some(log) = &events {
                log.record(&Event::ServerStopped {
                    ts_ms: mcp_guard_core::events::now_ms(),
                    server: server_name.clone(),
                });
            }
            eprintln!("mcp-guard: proxy for '{server_name}' terminated");
            Ok(())
        }
        mcp_guard_core::config::ServerConfig::Remote {
            url,
            headers,
            disabled_tools,
        } => {
            eprintln!(
                "mcp-guard: proxying '{}' -> remote {}",
                server_name, url
            );
            if !disabled_tools.is_empty() {
                eprintln!("disabled tools: {:?}", disabled_tools);
            }
            if !headers.is_empty() {
                eprintln!("headers: {:?}", headers);
            }

            // Run remote proxy
            let proxy = RemoteProxy::spawn(
                &server_name,
                &url,
                &headers,
                disabled_tools,
                events.clone(),
            )?;

            if let Some(log) = &events {
                log.record(&Event::ServerStarted {
                    ts_ms: mcp_guard_core::events::now_ms(),
                    server: server_name.clone(),
                    proxy_pid: std::process::id(),
                    child_pid: 0, // No child process for remote
                });
            }

            proxy.run().await?;

            if let Some(log) = &events {
                log.record(&Event::ServerStopped {
                    ts_ms: mcp_guard_core::events::now_ms(),
                    server: server_name.clone(),
                });
            }
            eprintln!("mcp-guard: proxy for '{server_name}' terminated");
            Ok(())
        }
    }
}

fn list(config_path: PathBuf) -> Result<()> {
    let cfg: GuardConfig =
        GuardConfig::from_file(config_path.to_str().context("config path is not valid UTF-8")?)
            .with_context(|| format!("failed to load config {}", config_path.display()))?;

    if cfg.server.is_empty() {
        eprintln!("No servers configured in {}", config_path.display());
        return Ok(());
    }

    println!("{:<20} {:<12} POLICY", "SERVER", "TYPE");
    for (name, srv) in &cfg.server {
        match srv {
            mcp_guard_core::config::ServerConfig::Stdio {
                command,
                args,
                allowed_dir,
                allow_env,
                disabled_tools,
            } => {
                let cmd = format!("{} {}", command, args.join(" "));
                let dir = allowed_dir
                    .as_ref()
                    .map(|d| d.display().to_string())
                    .unwrap_or_else(|| "(inherited)".into());
                println!("{name:<20} {{'stdio':<12}} dir={dir}");
                println!(
                    "  cmd={cmd} allow_env={:?} disabled_tools={:?}",
                    allow_env, disabled_tools
                );
            }
            mcp_guard_core::config::ServerConfig::Remote {
                url,
                headers,
                disabled_tools,
            } => {
                println!("{name:<20} {{'remote':<12}} url={url}");
                println!(
                    "  headers={:?} disabled_tools={:?}",
                    headers, disabled_tools
                );
            }
        }
    }
    Ok(())
}

mod tui;
