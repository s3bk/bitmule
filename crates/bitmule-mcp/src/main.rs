//! `bitmule-mcp`: the MCP server on stdin/stdout, one JSON message per line.
//!
//! Environment: `BITMULE_SERVER` (relay, default https://bitmule.qdat.net) and
//! `BITMULE_DOWNLOADS` (where received files go, default the working directory).

use std::sync::Arc;

use bitmule_mcp::Server;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let relay = std::env::var("BITMULE_SERVER").unwrap_or_else(|_| "https://bitmule.qdat.net".into());
    let downloads = std::env::var_os("BITMULE_DOWNLOADS").map(std::path::PathBuf::from).unwrap_or_else(|| ".".into());
    let server = Server::new(relay, downloads);

    // answers go out whole and one at a time, however many calls are in flight
    let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let server = server.clone();
        let stdout = stdout.clone();
        tokio::spawn(async move {
            let answer = match serde_json::from_str::<Value>(&line) {
                Ok(message) => server.handle(message).await,
                Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("parse error: {e}") } })),
            };
            if let Some(answer) = answer {
                let mut out = stdout.lock().await;
                let _ = out.write_all(format!("{answer}\n").as_bytes()).await;
                let _ = out.flush().await;
            }
        });
    }
    Ok(())
}
