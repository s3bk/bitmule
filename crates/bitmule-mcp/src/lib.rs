//! An MCP server for agents: send files and receive them over bitmule.
//!
//! Speaks JSON-RPC 2.0 (the Model Context Protocol) with one JSON message per
//! line, on stdin/stdout (`main.rs`); [`Server::handle`] is the whole protocol,
//! one message in, at most one message out.
//!
//! Tools:
//! - `bitmule_send`: share files or folders; returns the share URL at once and
//!   keeps sending in the background until the receivers are done.
//! - `bitmule_send_status`: how far a send is, or why it failed.
//! - `bitmule_receive`: fetch what a share URL points to, into a directory;
//!   returns when it is complete.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use bitmule::{Client, TransportMode};
use serde_json::{Value, json};

/// MCP revisions this server understands, newest first.
const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

#[derive(Clone)]
pub struct Server {
    inner: Arc<Inner>,
}

struct Inner {
    /// Relay to use unless a call names another.
    server: String,
    /// Where `bitmule_receive` puts files unless a call names a directory.
    downloads: PathBuf,
    /// Servers without TLS are refused unless this is set (by whoever runs
    /// the MCP server, not by the agent that calls it).
    allow_insecure: bool,
    sends: Mutex<HashMap<String, SendState>>,
}

#[derive(Clone, Default)]
struct SendState {
    share_url: String,
    state: &'static str, // sending | done | failed
    bytes: u64,
    total: u64,
    error: Option<String>,
}

impl Server {
    pub fn new(server: impl Into<String>, downloads: impl Into<PathBuf>) -> Self {
        Server { inner: Arc::new(Inner { server: server.into(), downloads: downloads.into(), allow_insecure: false, sends: Mutex::default() }) }
    }

    /// Allow relays without TLS (`http://`). Off by default; the agent's
    /// `server` argument cannot turn it on.
    pub fn allow_insecure(self, allow: bool) -> Self {
        let inner = &*self.inner;
        Server { inner: Arc::new(Inner { server: inner.server.clone(), downloads: inner.downloads.clone(), allow_insecure: allow, sends: Mutex::default() }) }
    }

    /// Answer one JSON-RPC message. Notifications (no `id`) get no answer.
    pub async fn handle(&self, message: Value) -> Option<Value> {
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let Some(id) = id else { return None };

        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools() })),
            "tools/call" => Ok(self.call(&params).await),
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
        let version = PROTOCOL_VERSIONS.iter().find(|v| **v == asked).unwrap_or(&PROTOCOL_VERSIONS[0]);
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "bitmule", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Send files with bitmule_send (give the share URL to whoever should receive them), \
                             fetch a share URL with bitmule_receive. Transfers are end-to-end encrypted.",
        })
    }

    /// `tools/call`: tool failures are results with `isError`, as MCP wants,
    /// not protocol errors.
    async fn call(&self, params: &Value) -> Value {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        let outcome = match name {
            "bitmule_send" => self.send(&args).await,
            "bitmule_send_status" => self.status(&args),
            "bitmule_receive" => self.receive(&args).await,
            _ => Err(format!("unknown tool {name:?}")),
        };
        match outcome {
            Ok(value) => json!({ "content": [{ "type": "text", "text": value.to_string() }], "structuredContent": value, "isError": false }),
            Err(message) => json!({ "content": [{ "type": "text", "text": message }], "isError": true }),
        }
    }

    fn client(&self, args: &Value) -> Client {
        Client::new(args.get("server").and_then(Value::as_str).unwrap_or(&self.inner.server)).allow_insecure(self.inner.allow_insecure)
    }

    async fn send(&self, args: &Value) -> Result<Value, String> {
        let paths: Vec<PathBuf> = args
            .get("paths")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(PathBuf::from).collect())
            .unwrap_or_default();
        if paths.is_empty() {
            return Err("`paths` must list at least one file or directory".into());
        }
        let mode = mode_of(args)?;
        let name = args.get("name").and_then(Value::as_str);

        let id = {
            let mut sends = self.inner.sends.lock().unwrap();
            let id = format!("send-{}", sends.len() + 1);
            sends.insert(id.clone(), SendState { state: "sending", ..Default::default() });
            id
        };
        let progress = {
            let (server, id) = (self.clone(), id.clone());
            move |bytes, total| {
                if let Some(state) = server.inner.sends.lock().unwrap().get_mut(&id) {
                    state.bytes = bytes;
                    state.total = total;
                }
            }
        };

        let client = self.client(args);
        let mut builder = match (name, paths.len()) {
            (Some(name), 1) => client.send_with_name(&paths[0], name),
            _ => client.send(&paths[0]),
        };
        for path in &paths[1..] {
            builder = builder.send(path);
        }
        let handle = match builder.mode(mode).on_progress(progress).start().await {
            Ok(handle) => handle,
            Err(e) => {
                self.finish(&id, Err(e.to_string()));
                return Err(e.to_string());
            }
        };
        let share_url = handle.share_url().to_string();
        let summary = json!({
            "transfer_id": id,
            "share_url": share_url,
            "name": handle.display_name(),
            "bytes": handle.total_bytes(),
            "note": "sending continues in the background; give share_url to the receiver, bitmule_send_status shows progress",
        });
        if let Some(state) = self.inner.sends.lock().unwrap().get_mut(&id) {
            state.share_url = share_url;
            state.total = handle.total_bytes();
        }
        let server = self.clone();
        tokio::spawn(async move {
            let result = handle.wait().await.map_err(|e| e.to_string());
            server.finish(&id, result);
        });
        Ok(summary)
    }

    fn finish(&self, id: &str, result: Result<(), String>) {
        if let Some(state) = self.inner.sends.lock().unwrap().get_mut(id) {
            match result {
                Ok(()) => {
                    state.state = "done";
                    state.bytes = state.total;
                }
                Err(e) => {
                    state.state = "failed";
                    state.error = Some(e);
                }
            }
        }
    }

    fn status(&self, args: &Value) -> Result<Value, String> {
        let id = args.get("transfer_id").and_then(Value::as_str).ok_or("`transfer_id` is required")?;
        let sends = self.inner.sends.lock().unwrap();
        let state = sends.get(id).ok_or_else(|| format!("no transfer {id:?}"))?;
        Ok(json!({
            "transfer_id": id,
            "state": state.state,
            "share_url": state.share_url,
            "bytes_received": state.bytes,
            "bytes_total": state.total,
            "error": state.error,
        }))
    }

    async fn receive(&self, args: &Value) -> Result<Value, String> {
        let url = args.get("url").and_then(Value::as_str).ok_or("`url` is required")?;
        let dest = args.get("dest").and_then(Value::as_str).map(PathBuf::from).unwrap_or_else(|| self.inner.downloads.clone());
        let outcome = self
            .client(args)
            .recv(url)
            .dest(&dest)
            .mode(mode_of(args)?)
            .start()
            .await
            .map_err(|e| e.to_string())?;
        let files: Vec<Value> = outcome
            .files()
            .map(|f| json!({ "name": f.name(), "path": f.path().to_string_lossy(), "bytes": f.size() }))
            .collect();
        Ok(json!({ "dest": outcome.dest().to_string_lossy(), "files": files }))
    }
}

fn mode_of(args: &Value) -> Result<TransportMode, String> {
    match args.get("mode").and_then(Value::as_str) {
        None | Some("auto") => Ok(TransportMode::Auto),
        Some("relay") => Ok(TransportMode::Relay),
        Some("webrtc") => Ok(TransportMode::Webrtc),
        Some(other) => Err(format!("`mode` is auto, relay or webrtc, not {other:?}")),
    }
}

fn tools() -> Value {
    let server = json!({ "type": "string", "description": "Relay URL, if not the default" });
    let mode = json!({ "type": "string", "enum": ["auto", "relay", "webrtc"], "description": "Transport; auto (default) uses a direct connection when possible and the relay otherwise" });
    json!([
        {
            "name": "bitmule_send",
            "title": "Send files with bitmule",
            "description": "Share files or folders end-to-end encrypted. Returns a share URL right away; the transfer \
                            runs in the background until the receiver(s) that connect have everything. Several paths, \
                            or a folder, are sent as one bundle that the receiver unpacks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": { "type": "array", "items": { "type": "string" }, "minItems": 1, "description": "Files or directories on this machine" },
                    "name": { "type": "string", "description": "Name the receiver saves a single file (or folder) under" },
                    "server": server,
                    "mode": mode,
                },
                "required": ["paths"],
            },
        },
        {
            "name": "bitmule_send_status",
            "title": "Progress of a bitmule send",
            "description": "State of a send started with bitmule_send: sending, done or failed, with bytes the receiver has.",
            "inputSchema": {
                "type": "object",
                "properties": { "transfer_id": { "type": "string" } },
                "required": ["transfer_id"],
            },
        },
        {
            "name": "bitmule_receive",
            "title": "Receive files with bitmule",
            "description": "Fetch what a bitmule share URL points to into a directory and return the files. Waits \
                            until the transfer is complete; a bundle is unpacked into a folder.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "The share URL (https://…/#…)" },
                    "dest": { "type": "string", "description": "Directory to save into; default: the server's download directory" },
                    "server": server,
                    "mode": mode,
                },
                "required": ["url"],
            },
        },
    ])
}
