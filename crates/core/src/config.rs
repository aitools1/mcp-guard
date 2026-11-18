use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::error::{GuardError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerConfig {
    /// Local stdio MCP server
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        allowed_dir: Option<PathBuf>,
        #[serde(default)]
        allow_env: Vec<String>,
        #[serde(default)]
        disabled_tools: Vec<String>,
    },
    /// Remote MCP server (Streamable HTTP / SSE)
    Remote {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        disabled_tools: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default)]
    pub server: HashMap<String, ServerConfig>,
}

impl GuardConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(GuardError::Io)?;
        let config: GuardConfig = toml::from_str(&content)
            .map_err(|e| GuardError::Config(e.to_string()))?;
        Ok(config)
    }

    /// Serializes the whole config to TOML text (for `mcp-guard import`).
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| GuardError::Config(e.to_string()))
    }
}

/// One MCP server definition read from an agent's config file.
#[derive(Debug, Clone, Default)]
pub struct AgentServerDef {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    /// Env variable names the agent config declares for this server.
    pub env: Vec<String>,
    /// Set for remote (http/sse) servers, which a stdio proxy cannot run.
    pub url: Option<String>,
    /// Headers for remote servers.
    pub headers: HashMap<String, String>,
}

/// A discovered agent config file with the MCP servers inside it.
#[derive(Debug, Clone)]
pub struct AgentConfigHit {
    pub source: String,
    pub path: PathBuf,
    pub servers: Vec<AgentServerDef>,
}

fn is_mcp_guard_command(command: &str) -> bool {
    let file_name = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);
    file_name.eq_ignore_ascii_case("mcp-guard") || file_name.eq_ignore_ascii_case("mcp-guard.exe")
}

/// Extracts MCP server definitions from an agent config JSON value.
/// Handles the `mcpServers` map (Claude/Cursor/OpenCode) and OpenCode's `mcp`
/// map where `command` is an array (first element is the binary).
/// Skips servers already wrapped by `mcp-guard` so re-importing never overwrites
/// the real upstream definition.
pub fn parse_mcp_servers(root: &Value) -> Vec<AgentServerDef> {
    let mut out = Vec::new();
    let map = root
        .get("mcpServers")
        .or_else(|| root.get("mcp").and_then(|m| m.get("servers")))
        .or_else(|| root.get("mcp"))
        .cloned()
        .unwrap_or(Value::Null);
    for (name, def) in map.as_object().cloned().unwrap_or_default() {
        let mut command = String::new();
        let mut args: Vec<String> = Vec::new();

        if let Some(c) = def.get("command").and_then(|c| c.as_str()) {
            command = c.to_string();
        } else if let Some(arr) = def.get("command").and_then(|c| c.as_array()) {
            if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                command = first.to_string();
                args = arr
                    .iter()
                    .skip(1)
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
        }

        if let Some(a) = def.get("args").and_then(|a| a.as_array()) {
            args = a.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        }

        let env = def
            .get("env")
            .and_then(|e| e.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        let url = def.get("url").and_then(|u| u.as_str()).map(String::from);
        let headers = def
            .get("headers")
            .and_then(|h| h.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        if is_mcp_guard_command(&command) {
            continue;
        }

        if !command.is_empty() || url.is_some() {
            out.push(AgentServerDef {
                name,
                command,
                args,
                env,
                url,
                headers,
            });
        }
    }
    out
}

/// Candidate agent config locations on this OS.
pub fn default_config_candidates(project_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<(String, PathBuf)> = Vec::new();
    if let Some(home) = home_dir() {
        // OpenCode (user)
        v.push((
            "opencode".into(),
            home.join(".config/opencode/opencode.json"),
        ));
        // Claude Desktop
        if let Ok(appdata) = std::env::var("APPDATA") {
            v.push((
                "claude-desktop".into(),
                PathBuf::from(appdata).join("Claude/claude_desktop_config.json"),
            ));
        }
        if cfg!(target_os = "macos") {
            v.push((
                "claude-desktop".into(),
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
            ));
        } else if cfg!(target_os = "linux") {
            v.push((
                "claude-desktop".into(),
                home.join(".config/Claude/claude_desktop_config.json"),
            ));
        }
        // Claude Code (user + project)
        v.push(("claude-code".into(), home.join(".claude.json")));
        v.push(("claude-code".into(), project_dir.join(".mcp.json")));
        // Cursor (user + project)
        v.push(("cursor".into(), home.join(".cursor/mcp.json")));
        v.push(("cursor".into(), project_dir.join(".cursor/mcp.json")));
    }
    // OpenCode (project-local)
    v.push(("opencode".into(), project_dir.join("opencode.json")));
    v
}

/// Reads all candidate files that exist and parse as JSON with MCP servers.
pub fn scan_config_files(candidates: &[(String, PathBuf)]) -> Vec<AgentConfigHit> {
    candidates
        .iter()
        .filter_map(|(source, path)| {
            let content = std::fs::read_to_string(path).ok()?;
            let json: Value = serde_json::from_str(&content).ok()?;
            let servers = parse_mcp_servers(&json);
            if servers.is_empty() {
                return None;
            }
            Some(AgentConfigHit {
                source: source.clone(),
                path: path.clone(),
                servers,
            })
        })
        .collect()
}

/// Builds a GuardConfig from scanned hits, first-found server name wins.
/// Safe defaults: `allow_env` = PATH/HOME + env keys declared by the agent,
/// `allowed_dir` = the working directory.
pub fn build_guard_config(hits: &[AgentConfigHit], workdir: &Path) -> GuardConfig {
    let mut servers: HashMap<String, ServerConfig> = HashMap::new();
    for hit in hits {
        for s in &hit.servers {
            if servers.contains_key(&s.name) {
                warn!(server = %s.name, source = %hit.source, "duplicate server name, keeping first definition");
                continue;
            }
            let mut allow_env = vec!["PATH".to_string(), "HOME".to_string()];
            for e in &s.env {
                if !allow_env.iter().any(|x| x == e) {
                    allow_env.push(e.clone());
                }
            }
            let cfg = if let Some(url) = &s.url {
                // Remote server
                ServerConfig::Remote {
                    url: url.clone(),
                    headers: s.headers.clone(),
                    disabled_tools: Vec::new(),
                }
            } else if !s.command.is_empty() {
                // Local stdio server
                ServerConfig::Stdio {
                    command: s.command.clone(),
                    args: s.args.clone(),
                    allowed_dir: Some(workdir.to_path_buf()),
                    allow_env,
                    disabled_tools: Vec::new(),
                }
            } else {
                warn!(
                    server = %s.name,
                    source = %hit.source,
                    "no command or url, skipping"
                );
                continue;
            };
            servers.insert(s.name.clone(), cfg);
        }
    }
    GuardConfig { server: servers }
}

/// User home directory (USERPROFILE on Windows, HOME elsewhere).
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var).ok().map(PathBuf::from)
}

/// Returns the default global config directory (~/.mcp-guard).
pub fn global_config_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".mcp-guard"))
}

/// Returns the default global config file path (~/.mcp-guard/mcp-guard.toml).
pub fn global_config_path() -> Option<PathBuf> {
    global_config_dir().map(|d| d.join("mcp-guard.toml"))
}

/// Resolves the effective config path:
/// - If `path` is provided and exists, use it.
/// - Else if `./mcp-guard.toml` exists, use it.
/// - Else use the global config path (~/.mcp-guard/mcp-guard.toml).
pub fn resolve_config_path(path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = path {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // Check local
    let local = PathBuf::from("mcp-guard.toml");
    if local.exists() {
        return Some(local);
    }
    // Fall back to global
    global_config_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
[server.test]
type = "stdio"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
allowed_dir = "/tmp"
allow_env = ["PATH", "HOME", "CUSTOM_VAR"]
disabled_tools = ["write_file"]
"#;
        let config_path = std::env::temp_dir().join("test_guard_config.toml");
        fs::write(&config_path, toml_str).unwrap();
        let config = GuardConfig::from_file(config_path.to_str().unwrap()).unwrap();
        assert!(config.server.contains_key("test"));
        let srv = &config.server["test"];
        match srv {
            ServerConfig::Stdio { command, args, allowed_dir, allow_env, disabled_tools, .. } => {
                assert_eq!(command, "npx");
                assert_eq!(args.len(), 3);
                assert_eq!(allowed_dir.as_ref().unwrap().as_os_str(), "/tmp");
                assert!(allow_env.contains(&"CUSTOM_VAR".to_string()));
                assert!(disabled_tools.contains(&"write_file".to_string()));
            }
            ServerConfig::Remote { .. } => panic!("expected stdio"),
        }
        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn test_parse_mcp_servers_claude_style() {
        let json_str = r#"{
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
                    "env": {"HOME": "/home/user"}
                },
                "gh": {
                    "command": "docker",
                    "args": ["run", "-i", "mcp/github"],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "unused"}
                }
            }
        }"#;
        let root: Value = serde_json::from_str(json_str).unwrap();
        let servers = parse_mcp_servers(&root);
        assert_eq!(servers.len(), 2);
        let fs_srv = servers.iter().find(|s| s.name == "fs").unwrap();
        assert_eq!(fs_srv.command, "npx");
        assert_eq!(fs_srv.args.len(), 3);
        assert!(fs_srv.env.contains(&"HOME".to_string()));
        let gh = servers.iter().find(|s| s.name == "gh").unwrap();
        assert!(gh.env.contains(&"GITHUB_PERSONAL_ACCESS_TOKEN".to_string()));
    }

    #[test]
    fn test_parse_mcp_servers_opencode_array_style() {
        let json_str = r#"{
            "mcp": {
                "ctx7": {
                    "type": "local",
                    "command": ["npx", "-y", "@upstash/context7-mcp"]
                }
            }
        }"#;
        let root: Value = serde_json::from_str(json_str).unwrap();
        let servers = parse_mcp_servers(&root);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].command, "npx");
        assert_eq!(servers[0].args, vec!["-y", "@upstash/context7-mcp"]);
    }

    #[test]
    fn test_parse_mcp_servers_opencode_nested_v2() {
        let json_str = r#"{
            "mcp": {
                "servers": {
                    "ctx7": {
                        "type": "local",
                        "command": ["npx", "-y", "@upstash/context7-mcp"],
                        "env": {"API_KEY": "x"}
                    }
                }
            }
        }"#;
        let root: Value = serde_json::from_str(json_str).unwrap();
        let servers = parse_mcp_servers(&root);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].command, "npx");
        assert_eq!(servers[0].args, vec!["-y", "@upstash/context7-mcp"]);
        assert!(servers[0].env.contains(&"API_KEY".to_string()));
    }

    #[test]
    fn test_parse_mcp_servers_opencode_remote_style() {
        let json_str = r#"{
            "mcp": {
                "servers": {
                    "ctx7": {
                        "type": "remote",
                        "url": "https://mcp.context7.com/mcp",
                        "headers": {"Authorization": "Bearer secret"}
                    }
                }
            }
        }"#;
        let root: Value = serde_json::from_str(json_str).unwrap();
        let servers = parse_mcp_servers(&root);
        assert_eq!(servers.len(), 1);
        let srv = &servers[0];
        assert_eq!(srv.name, "ctx7");
        assert!(srv.command.is_empty());
        assert_eq!(srv.url.as_deref(), Some("https://mcp.context7.com/mcp"));
    }

    #[test]
    fn test_build_and_scan_roundtrip() {
        // Simulate an opencode.json and .cursor/mcp.json on disk.
        let dir = std::env::temp_dir().join("mcp-guard-scan-test");
        let _ = fs::create_dir_all(dir.join(".cursor")).ok();
        let opencode_json = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","fs-srv"],"env":{"PATH":"x"}}}}"#;
        let cursor_json = r#"{"mcpServers":{"gh":{"command":"docker","args":["run","-i","mcp/github"]}}}"#;
        fs::write(dir.join("opencode.json"), opencode_json).unwrap();
        fs::write(dir.join(".cursor/mcp.json"), cursor_json).unwrap();

        let candidates: Vec<(String, PathBuf)> = vec![
            ("opencode".into(), dir.join("opencode.json")),
            ("cursor".into(), dir.join(".cursor/mcp.json")),
            ("claude-code".into(), dir.join(".mcp.json")), // does not exist
        ];
        let hits = scan_config_files(&candidates);
        assert_eq!(hits.len(), 2);

        let cfg = build_guard_config(&hits, &dir);
        assert_eq!(cfg.server.len(), 2);
        let fs_srv = &cfg.server["fs"];
        match fs_srv {
            ServerConfig::Stdio { command, args, allowed_dir, allow_env, .. } => {
                assert_eq!(command, "npx");
                assert_eq!(args.len(), 2);
                assert_eq!(allowed_dir.as_ref().unwrap(), &dir);
                assert!(allow_env.contains(&"PATH".to_string()));
            }
            ServerConfig::Remote { .. } => panic!("expected stdio"),
        }
        // Env keys declared by the agent must land in allow_env.
        let gh = &cfg.server["gh"];
        match gh {
            ServerConfig::Stdio { allow_env, .. } => {
                assert_eq!(allow_env.as_slice(), &["PATH".to_string(), "HOME".to_string()][..]);
            }
            ServerConfig::Remote { .. } => panic!("expected stdio"),
        }

        let toml_out = cfg.to_toml_string().unwrap();
        assert!(toml_out.contains("[server.fs]"));
        assert!(toml_out.contains("[server.gh]"));
        assert!(toml_out.contains("allow_env = [\"PATH\", \"HOME\"]"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_mcp_servers_skips_mcp_guard() {
        let json_str = r#"{
            "mcp": {
                "servers": {
                    "context7": { "type": "local", "command": ["mcp-guard", "run", "context7"] },
                    "mslearn": { "type": "local", "command": ["mcp-guard.exe", "run", "mslearn"] },
                    "github": { "type": "local", "command": ["/home/user/.cargo/bin/mcp-guard.exe", "run", "github"] },
                    "fs": { "type": "local", "command": ["npx", "-y", "fs-srv"] }
                }
            }
        }"#;
        let root: Value = serde_json::from_str(json_str).unwrap();
        let servers = parse_mcp_servers(&root);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "fs");
    }
}
