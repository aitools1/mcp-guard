//! Live end-to-end test: real `mcp-guard` binary proxying a real mock MCP
//! child over piped stdio. Verifies disabled-tools filtering, secret
//! redaction, blocked-call error responses and event telemetry.

#![allow(clippy::unwrap_used)]

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn bin_path(target: &str, is_example: bool) -> String {
    // Test exe lives in <workspace>/target/debug/deps/, binaries in
    // <workspace>/target/debug/ — derive the real location from current_exe().
    if let Ok(exe) = std::env::current_exe() {
        if let Some(debug) = exe.parent().and_then(|p| p.parent()) {
            let candidate = if is_example {
                debug.join("examples").join(format!("{target}{}", std::env::consts::EXE_SUFFIX))
            } else {
                debug.join(format!("{target}{}", std::env::consts::EXE_SUFFIX))
            };
            if candidate.exists() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    let env_name = target.replace('-', "_");
    std::env::var(format!("CARGO_BIN_EXE_{env_name}")).unwrap_or_else(|_| {
        if is_example {
            format!("target/debug/examples/{target}{}", std::env::consts::EXE_SUFFIX)
        } else {
            format!("target/debug/{target}{}", std::env::consts::EXE_SUFFIX)
        }
    })
}

fn json_line(v: &serde_json::Value) -> String {
    let mut s = serde_json::to_string(v).unwrap();
    s.push('\n');
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn live_proxy_filters_redacts_and_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let events_path = dir.path().join("events.jsonl");

    let mock_bin = bin_path("mock-mcp-server", true);
    let mcp_guard = bin_path("mcp-guard", false);

    let config_path = dir.path().join("mcp-guard.toml");
    // Escape backslashes for TOML basic strings (Windows paths).
    let mock_toml = mock_bin.replace('\\', "\\\\");
    let dir_toml = dir.path().display().to_string().replace('\\', "\\\\");
    let cfg_toml = format!(
        r#"[server.mock]
type = "stdio"
command = "{mock_toml}"
args = []
allow_env = []
allowed_dir = "{dir_toml}"
disabled_tools = ["danger"]
"#
    );
    std::fs::write(&config_path, &cfg_toml).unwrap();

    let mut child = tokio::process::Command::new(mcp_guard)
        .arg("run")
        .arg("mock")
        .arg("--config")
        .arg(&config_path)
        .env("MCP_GUARD_EVENTS", &events_path)
        .env_remove("RUST_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Drain child stderr so the pipe never fills up. Capture it for debugging.
    let stderr_capture: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let stderr_capture_clone = stderr_capture.clone();
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut buf = String::new();
        while reader.read_line(&mut buf).await.unwrap_or(0) > 0 {
            stderr_capture_clone.lock().unwrap().push(buf.clone());
            buf.clear();
        }
    });

    // Send all requests; each JSON-RPC response will arrive on stdout.
    async fn send_requests(stdin: &mut tokio::process::ChildStdin) {
        stdin
            .write_all(json_line(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).as_bytes())
            .await
            .unwrap();
        stdin
            .write_all(
                json_line(&json!({
                    "jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"danger"}
                }))
                .as_bytes(),
            )
            .await
            .unwrap();
        stdin
            .write_all(
                json_line(&json!({
                    "jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"leak","arguments":{}}
                }))
                .as_bytes(),
            )
            .await
            .unwrap();
        stdin
            .write_all(
                json_line(&json!({
                    "jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}
                ))
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    send_requests(&mut stdin).await;

    // Read responses until we have all 4 expected responses (1, 2, 3, 4).
    let read_all = {
        let mut reader = BufReader::new(stdout);
        async move {
            let mut lines: Vec<String> = Vec::new();
            let mut responses_received = 0;
            loop {
                let mut line = String::new();
                let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line))
                    .await
                    .unwrap_or_else(|_| panic!("reading response timed out"))
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                let trimmed = line.trim_end();
                if trimmed.is_empty() {
                    continue;
                }
                lines.push(trimmed.to_string());
                responses_received += 1;
                if responses_received >= 4 {
                    break;
                }
            }
            lines
        }
    };
    let lines = read_all.await;

    // Now close stdin -> proxy exits after terminating the child.
    drop(stdin);

    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .unwrap_or_else(|_| panic!("mcp-guard did not exit"))
        .unwrap();
    let stderr_output = stderr_capture.lock().unwrap().join("\n");
    if !status.success() {
        eprintln!("=== mcp-guard stderr ===\n{}=== end stderr ===", stderr_output);
    }
    assert!(status.success(), "mcp-guard run should exit cleanly (stderr: {})", stderr_output);
    let _ = stderr_task.await;

    assert_eq!(lines.len(), 4, "expected 4 responses, got: {lines:?}");
    let by_id: std::collections::HashMap<i64, &str> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            (v["id"].as_i64().unwrap(), l.as_str())
        })
        .collect();

    // --- tools/list: `danger` filtered out ---
    let list: serde_json::Value = serde_json::from_str(by_id[&1]).unwrap();
    let tool_names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(!tool_names.contains(&"danger"), "disabled tool leaked: {tool_names:?}");
    assert!(tool_names.contains(&"echo") && tool_names.contains(&"leak"));

    // --- tools/call danger: blocked with JSON-RPC error -32601 ---
    let blocked: serde_json::Value = serde_json::from_str(by_id[&2]).unwrap();
    assert_eq!(blocked["error"]["code"], json!(-32601));
    assert!(blocked["error"]["message"]
        .as_str()
        .unwrap()
        .contains("danger"));

    // --- tools/call leak: secrets redacted ---
    let leak: serde_json::Value = serde_json::from_str(by_id[&3]).unwrap();
    let leak_text = leak["result"]["content"][0]["text"].as_str().unwrap();
    assert!(leak_text.contains("[REDACTED:OPENAI]"), "OpenAI key not redacted: {leak_text}");
    assert!(leak_text.contains("[REDACTED:BEARER]"), "Bearer not redacted: {leak_text}");
    assert!(
        !leak_text.contains("sk-abcdefghijklmnopqrstuvwxyz"),
        "raw secret leaked"
    );

    // --- tools/call echo: happy path ---
    let echo: serde_json::Value = serde_json::from_str(by_id[&4]).unwrap();
    assert_eq!(echo["result"]["content"][0]["text"], "echo:hi");

    // --- telemetry events were written ---
    let events_raw = std::fs::read_to_string(&events_path).unwrap();
    let event_lines: Vec<&str> = events_raw.lines().collect();
    let has_server_started = event_lines.iter().any(|l| l.contains("server_started"));
    let has_blocked_call = event_lines
        .iter()
        .any(|l| l.contains("tool_called") && l.contains("danger") && l.contains("blocked"));
    let has_secret = event_lines.iter().any(|l| l.contains("secret_redacted"));
    assert!(has_server_started, "missing server_started event:\n{events_raw}");
    assert!(
        has_blocked_call,
        "missing blocked tool_called event:\n{events_raw}"
    );
    assert!(has_secret, "missing secret_redacted event:\n{events_raw}");

    let _ = dir;
}
