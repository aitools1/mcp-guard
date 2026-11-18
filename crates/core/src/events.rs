use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Unix time in milliseconds (event timestamp).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Ok,
    Blocked,
}

/// Telemetry events written as JSONL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    ServerStarted {
        ts_ms: u64,
        server: String,
        proxy_pid: u32,
        child_pid: u32,
    },
    ServerStopped {
        ts_ms: u64,
        server: String,
    },
    ToolsListed {
        ts_ms: u64,
        server: String,
        tools: usize,
        est_tokens: usize,
        #[serde(default)]
        names: Vec<String>,
    },
    ToolCalled {
        ts_ms: u64,
        server: String,
        tool: String,
        latency_ms: u64,
        status: CallStatus,
    },
    SecretRedacted {
        ts_ms: u64,
        server: String,
        secret_type: String,
    },
}

impl Event {
    /// Short human label for TUI display.
    pub fn label(&self) -> String {
        match self {
            Event::ServerStarted { server, .. } => format!("{server} started"),
            Event::ServerStopped { server, .. } => format!("{server} stopped"),
            Event::ToolsListed {
                server, tools, ..
            } => format!("{server}: {tools} tools listed"),
            Event::ToolCalled {
                server,
                tool,
                latency_ms,
                status,
                ..
            } => match status {
                CallStatus::Ok => format!("{server}/{tool} ok ({latency_ms} ms)"),
                CallStatus::Blocked => format!("{server}/{tool} BLOCKED"),
            },
            Event::SecretRedacted {
                server,
                secret_type,
                ..
            } => format!("{server}: SECRET {secret_type} redacted"),
        }
    }
}

/// Append-only JSONL event log. Thread-safe, never blocks, never fails the
/// main stdio proxy path (record errors are swallowed by design).
pub struct EventLog {
    file: Mutex<File>,
}

impl EventLog {
    /// Opens (creating if needed) the JSONL file at `path`.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Default location: `~/.mcp-guard/events.jsonl`.
    pub fn default_path() -> Option<PathBuf> {
        let home = crate::config::home_dir()?;
        Some(home.join(".mcp-guard").join("events.jsonl"))
    }

    /// Resolves the effective log path: `$MCP_GUARD_EVENTS` override
    /// (empty string disables), else the default location.
    pub fn resolve_path() -> Option<PathBuf> {
        match std::env::var("MCP_GUARD_EVENTS") {
            Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
            _ => Self::default_path(),
        }
    }

    /// Appends one event. Best-effort: a poisoned lock or I/O error is skipped.
    pub fn record(&self, ev: &Event) {
        if let Ok(json) = serde_json::to_string(ev) {
            if let Ok(mut file) = self.file.lock() {
                let _ = writeln!(file, "{json}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let ev = Event::SecretRedacted {
            ts_ms: 42,
            server: "mock".into(),
            secret_type: "OPENAI".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"event\":\"secret_redacted\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn test_record_and_read() {
        let dir = std::env::temp_dir().join("mcp-guard-events-test");
        let _ = std::fs::create_dir_all(&dir).ok();
        let path = dir.join("events.jsonl");
        let log = EventLog::open(&path).unwrap();
        log.record(&Event::ServerStarted {
            ts_ms: 1,
            server: "s".into(),
            proxy_pid: 100,
            child_pid: 101,
        });
        log.record(&Event::ToolCalled {
            ts_ms: 2,
            server: "s".into(),
            tool: "echo".into(),
            latency_ms: 12,
            status: CallStatus::Ok,
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("server_started"));
        let parsed: Event = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed, Event::ToolCalled {
            ts_ms: 2,
            server: "s".into(),
            tool: "echo".into(),
            latency_ms: 12,
            status: CallStatus::Ok,
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
