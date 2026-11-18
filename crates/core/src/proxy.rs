use std::collections::HashMap;
use std::marker::Unpin;
use std::path::PathBuf;
use std::time::Instant;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tracing::{error, info, warn};

use crate::error::{GuardError, Result};
use crate::events::{Event, EventLog};
use crate::redaction::{detected_secret_types, redact_json};
use crate::sandbox::{configure_command, SandboxConfig};
use crate::telemetry::estimate_tokens;

struct PendingCall {
    method: String,
    tool: Option<String>,
    at: Instant,
}

/// Spawns a sandboxed MCP child process and proxies JSON-RPC 2.0 between the
/// parent's stdin/stdout and the child.
pub struct Proxy {
    child: Child,
    server_name: String,
    disabled_tools: Vec<String>,
    events: Option<std::sync::Arc<EventLog>>,
}

impl Proxy {
    pub fn spawn(
        server_name: &str,
        command: &str,
        args: &[String],
        sandbox: &SandboxConfig,
        disabled_tools: Vec<String>,
        events: Option<std::sync::Arc<EventLog>>,
    ) -> Result<Self> {
        let mut cmd = Command::new(command);
        configure_command(&mut cmd, sandbox, args)?;
        let child = cmd.spawn()?;
        info!(server = %server_name, command = %command, "MCP child process spawned");
        Ok(Self {
            child,
            server_name: server_name.to_string(),
            disabled_tools,
            events,
        })
    }

    /// PID of the spawned MCP child (0 if already reaped).
    pub fn child_pid(&self) -> u32 {
        self.child.id().unwrap_or(0)
    }

    /// Runs the stdio proxy loop until client stdin closes, the child exits,
    /// or an I/O error occurs.
    pub async fn run(self) -> Result<()> {
        let server_name = self.server_name.clone();
        let disabled = self.disabled_tools.clone();
        let events = self.events.clone();
        let mut child = self.child;
        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| GuardError::Proxy("Failed to open child stdin".to_string()))?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| GuardError::Proxy("Failed to open child stdout".to_string()))?;
        let child_stderr = child.stderr.take();

        // Forward child stderr to tracing (parent stderr), never stdout.
        if let Some(stderr) = child_stderr {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                loop {
                    match reader.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            let trimmed = line.trim_end();
                            if !trimmed.is_empty() {
                                warn!(target: "mcp-child", "{}", trimmed);
                            }
                            line.clear();
                        }
                        Err(e) => {
                            error!("Error reading child stderr: {e}");
                            break;
                        }
                    }
                }
            });
        }

        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        let mut stdout_writer = tokio::io::stdout();
        let mut server_reader = BufReader::new(child_stdout);
        let mut child_writer = child_stdin;

        let mut pending: HashMap<Value, PendingCall> = HashMap::new();
        let mut client_buf = String::new();
        let mut server_buf = String::new();

        loop {
            tokio::select! {
                n = stdin_reader.read_line(&mut client_buf) => {
                    match n {
                        Ok(0) => {
                            info!("Client stdin closed, terminating proxy");
                            break;
                        }
                        Ok(_) => {
                            if !forward_client_line(&server_name, &disabled, events.as_deref(), &client_buf, &mut child_writer, &mut stdout_writer, &mut pending).await {
                                break;
                            }
                            client_buf.clear();
                        }
                        Err(e) => {
                            error!("Error reading client stdin: {e}");
                            break;
                        }
                    }
                }
                n = server_reader.read_line(&mut server_buf) => {
                    match n {
                        Ok(0) => {
                            info!("Child stdout closed");
                            break;
                        }
                        Ok(_) => {
                            if !forward_server_line(&server_name, &disabled, events.as_deref(), &server_buf, &mut stdout_writer, &mut pending).await {
                                break;
                            }
                            server_buf.clear();
                        }
                        Err(e) => {
                            error!("Error reading child stdout: {e}");
                            break;
                        }
                    }
                }
                _ = child.wait() => {
                    info!("Child process exited, terminating proxy");
                    break;
                }
            }
        }

        // Safety net: terminate any still-alive child so it does not outlive
        // the proxy (stdout close already ended the loop normally).
        let _ = child.kill().await;
        Ok(())
    }
}

/// Forwards one client request line to the child. Returns false on I/O error.
async fn forward_client_line(
    server_name: &str,
    disabled: &[String],
    events: Option<&EventLog>,
    buf: &str,
    child_writer: &mut ChildStdin,
    stdout_writer: &mut (impl AsyncWriteExt + Unpin),
    pending: &mut HashMap<Value, PendingCall>,
) -> bool {
    let line = buf
        .trim_start_matches('\u{feff}')
        .trim_end_matches(&['\r', '\n'][..]);
    if line.is_empty() {
        return true;
    }

    match serde_json::from_str::<Value>(line) {
        Ok(mut val) => {
            // Block calls to disabled tools at the proxy level.
            if let Some(tool) = disabled_tool_name(&val, disabled) {
                let id = val.get("id").cloned().unwrap_or(Value::Null);
                let resp = rpc_error_response(&id, &tool);
                if let Err(e) = write_json_line(stdout_writer, &resp).await {
                    error!("Failed to write blocked-tool error to client: {e}");
                    return false;
                }
                warn!(server = %server_name, tool = %tool, "Blocked tools/call (disabled tool)");
                if let Some(log) = events {
                    log.record(&Event::ToolCalled {
                        ts_ms: crate::events::now_ms(),
                        server: server_name.to_string(),
                        tool,
                        latency_ms: 0,
                        status: crate::events::CallStatus::Blocked,
                    });
                }
                return true;
            }

            // Track outgoing requests by id so responses can be matched later.
            if let (Some(id), Some(method)) = (val.get("id"), val.get("method")) {
                let method_s = method.as_str().unwrap_or("").to_string();
                // Capture the tool name at request time (responses carry no `params`).
                let tool = if method_s == "tools/call" {
                    val.pointer("/params/name")
                        .and_then(|n| n.as_str())
                        .map(String::from)
                } else {
                    None
                };
                pending.insert(
                    id.clone(),
                    PendingCall {
                        method: method_s,
                        tool,
                        at: Instant::now(),
                    },
                );
            }

            // Redact args before they leave the process boundary.
            redact_json(&mut val);
            if let Err(e) = write_json_line(child_writer, &val).await {
                error!("Failed to write request to child stdin: {e}");
                return false;
            }
            true
        }
        // Not JSON: pass through untouched.
        Err(_) => {
            if let Err(e) = child_writer.write_all(buf.as_bytes()).await {
                error!("Failed to passthrough client line: {e}");
                return false;
            }
            let _ = child_writer.flush().await;
            true
        }
    }
}

/// Forwards one server response line to the client. Returns false on I/O error.
async fn forward_server_line(
    server_name: &str,
    disabled: &[String],
    events: Option<&EventLog>,
    buf: &str,
    stdout_writer: &mut (impl AsyncWriteExt + Unpin),
    pending: &mut HashMap<Value, PendingCall>,
) -> bool {
    let line = buf
        .trim_start_matches('\u{feff}')
        .trim_end_matches(&['\r', '\n'][..]);
    if line.is_empty() {
        return true;
    }

    match serde_json::from_str::<Value>(line) {
        Ok(mut val) => {
            if let Some(id) = val.get("id").cloned() {
                if val.get("error").is_none() {
                    if let Some(meta) = pending.remove(&id) {
                        let latency_ms: u64 = meta.at.elapsed().as_millis() as u64;
                        if meta.method == "tools/list" {
                            // Strip disabled tools so the LLM never sees them.
                            filter_disabled_tools(&mut val, disabled);
                            let (tools, names) = match val.pointer("/result/tools") {
                                Some(t) => {
                                    let arr = t.as_array();
                                    match arr {
                                        Some(a) => (
                                            a.len(),
                                            a.iter()
                                                .filter_map(|x| {
                                                    x.get("name")
                                                        .and_then(|n| n.as_str())
                                                        .map(String::from)
                                                })
                                                .collect(),
                                        ),
                                        None => (0, Vec::new()),
                                    }
                                }
                                None => (0, Vec::new()),
                            };
                            let est_tokens = val.get("result").map(estimate_tokens).unwrap_or(0);
                            info!(
                                server = %server_name,
                                latency_ms, tools_tokens = est_tokens,
                                "tools/list response forwarded"
                            );
                            if let Some(log) = events {
                                log.record(&Event::ToolsListed {
                                    ts_ms: crate::events::now_ms(),
                                    server: server_name.to_string(),
                                    tools,
                                    est_tokens,
                                    names,
                                });
                            }
                        } else if meta.method == "tools/call" {
                            let tool = meta.tool.unwrap_or_else(|| "unknown".to_string());
                            info!(server = %server_name, tool = %tool, latency_ms, "tools/call completed");
                            if let Some(log) = events {
                                log.record(&Event::ToolCalled {
                                    ts_ms: crate::events::now_ms(),
                                    server: server_name.to_string(),
                                    tool,
                                    latency_ms,
                                    status: crate::events::CallStatus::Ok,
                                });
                            }
                        }
                    }
                }
            }

            // Telemetry: which secret types were redacted in this response.
            if let Some(log) = events {
                for secret_type in detected_secret_types(line) {
                    log.record(&Event::SecretRedacted {
                        ts_ms: crate::events::now_ms(),
                        server: server_name.to_string(),
                        secret_type,
                    });
                }
            }

            // Redact all server responses before they reach the client.
            redact_json(&mut val);
            if let Err(e) = write_json_line(stdout_writer, &val).await {
                error!("Failed to write response to client stdout: {e}");
                return false;
            }
            true
        }
        Err(_) => {
            if let Err(e) = stdout_writer.write_all(buf.as_bytes()).await {
                error!("Failed to passthrough child line: {e}");
                return false;
            }
            let _ = stdout_writer.flush().await;
            true
        }
    }
}

/// Returns the tool name if this request is a `tools/call` for a disabled tool.
pub fn disabled_tool_name(req: &Value, disabled: &[String]) -> Option<String> {
    if req.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
        let name = req
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())?;
        if disabled.iter().any(|d| d == name) {
            return Some(name.to_string());
        }
    }
    None
}

/// Removes disabled tools from a `tools/list` response's `result.tools` array.
pub fn filter_disabled_tools(val: &mut Value, disabled: &[String]) {
    if let Some(tools) = val
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    {
        tools.retain(|t| {
            let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
            !disabled.iter().any(|d| d == name)
        });
    }
}

/// Builds a JSON-RPC error response for a blocked tool call.
pub fn rpc_error_response(id: &Value, tool: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32601,
            "message": format!("tool '{tool}' is disabled by mcp-guard policy")
        }
    })
}

async fn write_json_line(
    writer: &mut (impl AsyncWriteExt + Unpin),
    val: &Value,
) -> std::result::Result<(), std::io::Error> {
    let serialized =
        serde_json::to_string(val).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writer.write_all(serialized.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

fn expand_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.clone(), expand_value(v)))
        .collect()
}

/// Expands `{file:~/.config/token.txt}` and `{env:VAR}` placeholders in a header
/// value. A missing file or variable leaves the placeholder intact (fail loud,
/// not silently with an empty credential).
fn expand_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let Some(end) = tail.find('}') else {
            out.push_str(tail);
            return out;
        };
        let placeholder = &tail[1..end];
        let replacement = if let Some(path) = placeholder.strip_prefix("file:") {
            let resolved: Option<PathBuf> = if let Some(rel) = path.strip_prefix("~/") {
                crate::config::home_dir().map(|h| h.join(rel))
            } else {
                Some(PathBuf::from(path))
            };
            match resolved.map(|p| {
                let content = std::fs::read_to_string(&p);
                (p, content)
            }) {
                Some((_, Ok(content))) => content.trim().to_string(),
                Some((p, Err(_))) => {
                    warn!(path = %p.display(), "header token file not found");
                    tail[..=end].to_string()
                }
                None => {
                    warn!(path = %path, "cannot resolve home directory for token file");
                    tail[..=end].to_string()
                }
            }
        } else if let Some(var) = placeholder.strip_prefix("env:") {
            std::env::var(var).unwrap_or_else(|_| {
                warn!(var = %var, "header env variable not set");
                tail[..=end].to_string()
            })
        } else {
            tail[..=end].to_string()
        };
        out.push_str(&replacement);
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Remote MCP proxy: bridges stdio JSON-RPC to HTTP/SSE remote MCP server.
pub struct RemoteProxy {
    server_name: String,
    url: String,
    headers: HashMap<String, String>,
    disabled_tools: Vec<String>,
    events: Option<std::sync::Arc<EventLog>>,
    client: reqwest::Client,
    session_id: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl RemoteProxy {
    pub fn spawn(
        server_name: &str,
        url: &str,
        headers: &HashMap<String, String>,
        disabled_tools: Vec<String>,
        events: Option<std::sync::Arc<EventLog>>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| GuardError::Proxy(format!("Failed to create HTTP client: {e}")))?;
        
        info!(server = %server_name, url = %url, "Remote MCP proxy created");
        Ok(Self {
            server_name: server_name.to_string(),
            url: url.to_string(),
            headers: expand_headers(headers),
            disabled_tools,
            events,
            client,
            session_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    pub async fn run(self) -> Result<()> {
        let server_name = self.server_name.clone();
        let disabled = self.disabled_tools.clone();
        let events = self.events.clone();
        let url = self.url.clone();
        let headers = self.headers.clone();
        let client = self.client.clone();
        let session_id = self.session_id.clone();

        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        let mut stdout_writer = tokio::io::stdout();
        let mut client_buf = String::new();
        let mut pending: HashMap<Value, PendingCall> = HashMap::new();

        // Send initialize request to establish session
        let init_request = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mcp-guard", "version": "0.1.0" }
            }
        });
        if let Err(e) = Self::send_remote_request(&client, &url, &headers, &session_id, &init_request).await {
            error!("Failed to initialize remote session: {e}");
        }

        loop {
            tokio::select! {
                n = stdin_reader.read_line(&mut client_buf) => {
                    match n {
                        Ok(0) => {
                            info!("Client stdin closed, terminating remote proxy");
                            break;
                        }
                        Ok(_) => {
                            if !Self::forward_client_line_remote(
                                &server_name, &disabled, events.as_deref(), &client_buf, 
                                &mut stdout_writer, &mut pending, &client, &url, &headers, &session_id
                            ).await {
                                break;
                            }
                            client_buf.clear();
                        }
                        Err(e) => {
                            error!("Error reading client stdin: {e}");
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_client_line_remote(
        server_name: &str,
        disabled: &[String],
        events: Option<&EventLog>,
        buf: &str,
        stdout_writer: &mut (impl AsyncWriteExt + Unpin),
        pending: &mut HashMap<Value, PendingCall>,
        client: &reqwest::Client,
        url: &str,
        headers: &HashMap<String, String>,
        session_id: &std::sync::Mutex<Option<String>>,
    ) -> bool {
        let line = buf
        .trim_start_matches('\u{feff}')
        .trim_end_matches(&['\r', '\n'][..]);
        if line.is_empty() {
            return true;
        }

        match serde_json::from_str::<Value>(line) {
            Ok(mut val) => {
                // Block calls to disabled tools at the proxy level.
                if let Some(tool) = disabled_tool_name(&val, disabled) {
                    let id = val.get("id").cloned().unwrap_or(Value::Null);
                    let resp = rpc_error_response(&id, &tool);
                    if let Err(e) = write_json_line(stdout_writer, &resp).await {
                        error!("Failed to write blocked-tool error to client: {e}");
                        return false;
                    }
                    warn!(server = %server_name, tool = %tool, "Blocked tools/call (disabled tool)");
                    if let Some(log) = events {
                        log.record(&Event::ToolCalled {
                            ts_ms: crate::events::now_ms(),
                            server: server_name.to_string(),
                            tool,
                            latency_ms: 0,
                            status: crate::events::CallStatus::Blocked,
                        });
                    }
                    return true;
                }

                // Track outgoing requests by id so responses can be matched later.
                if let (Some(id), Some(method)) = (val.get("id"), val.get("method")) {
                    let method_s = method.as_str().unwrap_or("").to_string();
                    let tool = if method_s == "tools/call" {
                        val.pointer("/params/name")
                            .and_then(|n| n.as_str())
                            .map(String::from)
                    } else {
                        None
                    };
                    pending.insert(
                        id.clone(),
                        PendingCall {
                            method: method_s,
                            tool,
                            at: Instant::now(),
                        },
                    );
                }

                // Redact args before they leave the process boundary (outgoing).
                redact_json(&mut val);

                // Send to remote server
                let mut response = match Self::send_remote_request(client, url, headers, session_id, &val).await {
                    Ok(Some(resp)) => resp,
                    Ok(None) => return true,
                    Err(e) => {
                        error!("Remote request failed: {e}");
                        // Send error response to client
                        let id = val.get("id").cloned().unwrap_or(Value::Null);
                        let err_resp = rpc_error_response(&id, &format!("remote error: {e}"));
                        if let Err(e) = write_json_line(stdout_writer, &err_resp).await {
                            error!("Failed to write remote error to client: {e}");
                            return false;
                        }
                        return true;
                    }
                };

                // Handle response
                if let Some(id) = response.get("id").cloned() {
                    if response.get("error").is_none() {
                        if let Some(meta) = pending.remove(&id) {
                            let latency_ms: u64 = meta.at.elapsed().as_millis() as u64;
                            if meta.method == "tools/list" {
                                // Strip disabled tools so the LLM never sees them.
                                filter_disabled_tools(&mut response, disabled);
                                let (tools, names) = match response.pointer("/result/tools") {
                                    Some(t) => {
                                        let arr = t.as_array();
                                        match arr {
                                            Some(a) => (
                                                a.len(),
                                                a.iter()
                                                    .filter_map(|x| {
                                                        x.get("name")
                                                            .and_then(|n| n.as_str())
                                                            .map(String::from)
                                                    })
                                                    .collect(),
                                            ),
                                            None => (0, Vec::new()),
                                        }
                                    }
                                    None => (0, Vec::new()),
                                };
                                let est_tokens = response.get("result").map(estimate_tokens).unwrap_or(0);
                                info!(
                                    server = %server_name,
                                    latency_ms, tools_tokens = est_tokens,
                                    "tools/list response forwarded"
                                );
                                if let Some(log) = events {
                                    log.record(&Event::ToolsListed {
                                        ts_ms: crate::events::now_ms(),
                                        server: server_name.to_string(),
                                        tools,
                                        est_tokens,
                                        names,
                                    });
                                }
                            } else if meta.method == "tools/call" {
                                let tool = meta.tool.unwrap_or_else(|| "unknown".to_string());
                                info!(server = %server_name, tool = %tool, latency_ms, "tools/call completed");
                                if let Some(log) = events {
                                    log.record(&Event::ToolCalled {
                                        ts_ms: crate::events::now_ms(),
                                        server: server_name.to_string(),
                                        tool,
                                        latency_ms,
                                        status: crate::events::CallStatus::Ok,
                                    });
                                }
                            }
                        }
                    }
                }

                // Telemetry: which secret types were redacted in this response.
                if let Some(log) = events {
                    let response_str = serde_json::to_string(&response).unwrap_or_default();
                    for secret_type in detected_secret_types(&response_str) {
                        log.record(&Event::SecretRedacted {
                            ts_ms: crate::events::now_ms(),
                            server: server_name.to_string(),
                            secret_type,
                        });
                    }
                }

                // Redact all server responses before they reach the client.
                redact_json(&mut response);
                if let Err(e) = write_json_line(stdout_writer, &response).await {
                    error!("Failed to write response to client stdout: {e}");
                    return false;
                }
                true
            }
            // Not JSON: pass through untouched.
            Err(_) => {
                if let Err(e) = stdout_writer.write_all(buf.as_bytes()).await {
                    error!("Failed to passthrough client line: {e}");
                    return false;
                }
                let _ = stdout_writer.flush().await;
                true
            }
        }
    }

    async fn send_remote_request(
        client: &reqwest::Client,
        url: &str,
        headers: &HashMap<String, String>,
        session_id: &std::sync::Mutex<Option<String>>,
        request: &Value,
    ) -> Result<Option<Value>> {
        let mut req = client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
            .json(request);
        
        // Add custom headers
        for (k, v) in headers {
            req = req.header(k, v);
        }
        
        // Add session ID if we have one
        if let Ok(guard) = session_id.lock() {
            if let Some(sid) = guard.as_ref() {
                req = req.header("Mcp-Session-Id", sid);
            }
        }

        let response = req
            .send()
            .await
            .map_err(|e| GuardError::Proxy(format!("HTTP request failed: {e}")))?;

        // Capture session ID from response headers
        if let Some(sid) = response.headers().get("Mcp-Session-Id") {
            if let Ok(sid_str) = sid.to_str() {
                if let Ok(mut guard) = session_id.lock() {
                    *guard = Some(sid_str.to_string());
                }
            }
        }

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| GuardError::Proxy(format!("Failed to read response: {e}")))?;

        let is_notification = request.get("id").is_none();
        parse_remote_response(status, &text, is_notification)
    }

    pub fn child_pid(&self) -> u32 {
        0 // No child process for remote
    }
}

fn parse_remote_response(
    status: reqwest::StatusCode,
    text: &str,
    is_notification: bool,
) -> Result<Option<Value>> {
    if !status.is_success() {
        return Err(GuardError::Proxy(format!("Remote server returned {}: {}", status, text)));
    }

    if text.trim().is_empty()
        && (status == reqwest::StatusCode::ACCEPTED
            || status == reqwest::StatusCode::NO_CONTENT
            || is_notification)
    {
        return Ok(None);
    }

    // Handle both JSON and SSE responses
    let response_value: Value = if text.lines().any(|l| l.trim_start().starts_with("data:")) {
        // SSE format - extract JSON from data lines
        let mut last_json: Option<Value> = None;
        for line in text.lines() {
            if let Some(data) = line.trim_start().strip_prefix("data:") {
                let data = data.trim();
                if data == "[DONE]" {
                    break;
                }
                if let Ok(json_val) = serde_json::from_str::<Value>(data) {
                    last_json = Some(json_val);
                }
            }
        }
        last_json.ok_or_else(|| GuardError::Proxy("No valid JSON in SSE response".to_string()))?
    } else {
        serde_json::from_str(text)
            .map_err(|e| GuardError::Proxy(format!("Failed to parse JSON response: {e}")))?
    };

    Ok(Some(response_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_disabled_tool_name() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {}}
        });
        let disabled = vec!["write_file".to_string(), "delete_file".to_string()];
        assert_eq!(
            disabled_tool_name(&req, &disabled).as_deref(),
            Some("write_file")
        );

        let ok_req = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}});
        assert_eq!(disabled_tool_name(&ok_req, &disabled), None);

        let not_a_call = json!({"jsonrpc":"2.0","id":3,"method":"tools/list"});
        assert_eq!(disabled_tool_name(&not_a_call, &disabled), None);
    }

    #[test]
    fn test_filter_disabled_tools() {
        let mut resp = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [
                {"name": "read_file", "description": "read"},
                {"name": "write_file", "description": "write"},
                {"name": "list_dir", "description": "list"}
            ]}
        });
        let disabled = vec!["write_file".to_string()];
        filter_disabled_tools(&mut resp, &disabled);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["read_file", "list_dir"]);
    }

    #[test]
    fn test_rpc_error_response() {
        let resp = rpc_error_response(&json!(7), "write_file");
        assert_eq!(resp["id"], json!(7));
        assert_eq!(resp["error"]["code"], json!(-32601));
        assert!(resp["error"]["message"].as_str().unwrap().contains("write_file"));
    }

    #[test]
    fn test_expand_value() {
        let dir = tempfile_dir();
        let token_path = dir.join("token.txt");
        std::fs::write(&token_path, "gho_secret123\n").unwrap();
        let value = format!("Bearer {{file:{}}}", token_path.display());
        assert_eq!(expand_value(&value), "Bearer gho_secret123");

        std::env::set_var("MCP_GUARD_TEST_HDR", "abc");
        assert_eq!(expand_value("{env:MCP_GUARD_TEST_HDR}"), "abc");
        std::env::remove_var("MCP_GUARD_TEST_HDR");

        // Unknown placeholders and missing files stay literal.
        assert_eq!(expand_value("plain"), "plain");
        assert_eq!(expand_value("{file:/definitely/not/here}"), "{file:/definitely/not/here}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp-guard-expand-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_parse_remote_response_empty_202_204() {
        assert_eq!(
            parse_remote_response(reqwest::StatusCode::ACCEPTED, "", false).unwrap(),
            None
        );
        assert_eq!(
            parse_remote_response(reqwest::StatusCode::NO_CONTENT, "   \n", true).unwrap(),
            None
        );
        assert_eq!(
            parse_remote_response(reqwest::StatusCode::OK, "", true).unwrap(),
            None
        );
        assert!(parse_remote_response(reqwest::StatusCode::OK, "", false).is_err());

        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        assert_eq!(
            parse_remote_response(reqwest::StatusCode::OK, sse, false).unwrap(),
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
        );
    }
}
