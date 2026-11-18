//! Test/dev fixture: a tiny MCP-ish JSON-RPC server on stdio.
//!
//! Not part of the product surface; used by `crates/cli/tests/live_proxy.rs`
//! and handy for manual proxy smoke tests (`[server.mock] command = "mock-mcp-server"`).
//!
//! Tools: `echo` (ok), `leak` (response contains a fake OpenAI key + Bearer
//! token to exercise redaction), `danger` (normally disabled in test config).

use std::io::{self, Write};

use serde_json::{json, Value};

fn main() {
    let mut line = String::new();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    eprintln!("[mock-mcp] started, waiting on stdin");

    let mut request_count = 0;
    loop {
        line.clear();
        let n = stdin.read_line(&mut line).unwrap_or(0);
        if n == 0 {
            break;
        }
        // Strip BOM if present (UTF-8 BOM = \u{feff})
        if line.starts_with('\u{feff}') {
            line = line.trim_start_matches('\u{feff}').to_string();
        }
        if line.trim().is_empty() {
            continue;
        }
        request_count += 1;
        eprintln!("[mock-mcp] request #{}: {:?}", request_count, line.trim_end());
        let req: Value = match serde_json::from_str(line.trim_end()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[mock-mcp] bad JSON: {e}");
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let resp = match method {
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "echo back arguments",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": { "type": "string", "description": "text to echo" }
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "leak",
                            "description": "returns fake credentials (redaction fixture)",
                            "inputSchema": { "type": "object", "properties": {} }
                        },
                        {
                            "name": "danger",
                            "description": "always disabled in tests",
                            "inputSchema": { "type": "object", "properties": {} }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let tool = req
                    .pointer("/params/name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                match tool {
                    "echo" => {
                        let text = req
                            .pointer("/params/arguments/text")
                            .and_then(|t| t.as_str())
                            .unwrap_or("");
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{ "type": "text", "text": format!("echo:{text}") }]
                            }
                        })
                    }
                    "leak" => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": "key=sk-abcdefghijklmnopqrstuvwxyz0123456789 Bearer abcdefghijklmnopqrstuvwxyz"
                            }]
                        }
                    }),
                    _ => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [{ "type": "text", "text": "ok" }] }
                    }),
                }
            }
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": { "name": "mock-mcp", "version": "0.1.0" }
                }
            }),
            _ => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        };

        eprintln!("[mock-mcp] handled {method}");
        let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap());
        let _ = out.flush();
    }

    eprintln!("[mock-mcp] stdin closed, exiting");
}
