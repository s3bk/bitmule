use std::sync::Arc;

use bitmule_mcp::Server;
use bitmule_server::{AppState, router};
use serde_json::{Value, json};

async fn relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(AppState::new()));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

async fn call(server: &Server, tool: &str, arguments: Value) -> Value {
    let answer = server.handle(request(1, "tools/call", json!({ "name": tool, "arguments": arguments }))).await.unwrap();
    assert_eq!(answer["id"], 1);
    answer["result"].clone()
}

/// The tool's JSON result, expecting success.
fn ok(result: &Value) -> Value {
    assert_eq!(result["isError"], false, "tool failed: {result}");
    result["structuredContent"].clone()
}

#[tokio::test]
async fn initialize_and_list_tools() {
    let server = Server::new("http://127.0.0.1:1", ".");
    let answer = server.handle(request(7, "initialize", json!({ "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }))).await.unwrap();
    assert_eq!(answer["id"], 7);
    assert_eq!(answer["result"]["protocolVersion"], "2025-03-26");
    assert!(answer["result"]["capabilities"]["tools"].is_object());
    assert_eq!(answer["result"]["serverInfo"]["name"], "bitmule");

    // a revision it does not know: it names the one it speaks
    let answer = server.handle(request(8, "initialize", json!({ "protocolVersion": "1999-01-01" }))).await.unwrap();
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");

    let answer = server.handle(request(9, "tools/list", json!({}))).await.unwrap();
    let tools = answer["result"]["tools"].as_array().unwrap();
    let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["bitmule_send", "bitmule_send_status", "bitmule_receive"]);
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["description"].as_str().unwrap().len() > 20);
        assert!(tool["inputSchema"]["required"].as_array().is_some());
    }
}

#[tokio::test]
async fn notifications_get_no_answer_and_unknown_methods_an_error() {
    let server = Server::new("http://127.0.0.1:1", ".");
    assert!(server.handle(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).await.is_none());
    assert_eq!(server.handle(request(1, "ping", json!({}))).await.unwrap()["result"], json!({}));
    let answer = server.handle(request(2, "no/such/method", json!({}))).await.unwrap();
    assert_eq!(answer["error"]["code"], -32601);
    assert_eq!(answer["id"], 2);
}

#[tokio::test]
async fn send_then_receive_through_the_tools() {
    let relay = relay().await;
    let src = tempfile::tempdir().unwrap();
    let downloads = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..2_500_000u32).map(|i| i.wrapping_mul(2654435761) as u8).collect();
    std::fs::write(src.path().join("report.bin"), &data).unwrap();

    let sender = Server::new(&relay, ".");
    let sent = ok(&call(&sender, "bitmule_send", json!({ "paths": [src.path().join("report.bin")], "mode": "relay" })).await);
    let url = sent["share_url"].as_str().unwrap().to_string();
    let id = sent["transfer_id"].as_str().unwrap().to_string();
    assert_eq!(sent["name"], "report.bin");
    assert_eq!(sent["bytes"], data.len());
    assert!(url.starts_with(&relay), "{url}");

    // another agent, its own server and download directory
    let receiver = Server::new(&relay, downloads.path());
    let got = ok(&call(&receiver, "bitmule_receive", json!({ "url": url, "mode": "relay" })).await);
    let files = got["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["name"], "report.bin");
    assert_eq!(files[0]["bytes"], data.len());
    assert_eq!(std::fs::read(files[0]["path"].as_str().unwrap()).unwrap(), data);
    assert!(files[0]["path"].as_str().unwrap().starts_with(downloads.path().to_str().unwrap()));

    // the sender's status ends at done
    let mut state = Value::Null;
    for _ in 0..50 {
        state = ok(&call(&sender, "bitmule_send_status", json!({ "transfer_id": id })).await);
        if state["state"] != "sending" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(state["state"], "done", "{state}");
    assert_eq!(state["bytes_received"], data.len());
    assert_eq!(state["share_url"], url);
}

#[tokio::test]
async fn a_folder_goes_as_a_bundle_to_a_chosen_directory() {
    let relay = relay().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(src.path().join("notes/old")).unwrap();
    std::fs::write(src.path().join("notes/a.txt"), b"a").unwrap();
    std::fs::write(src.path().join("notes/old/b.txt"), b"b").unwrap();

    let sender = Server::new(&relay, ".");
    let sent = ok(&call(&sender, "bitmule_send", json!({ "paths": [src.path().join("notes")], "name": "memos", "mode": "relay" })).await);
    let receiver = Server::new(&relay, ".");
    let got = ok(&call(&receiver, "bitmule_receive", json!({ "url": sent["share_url"], "dest": dest.path(), "mode": "relay" })).await);
    let mut paths: Vec<String> = got["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap().strip_prefix(dest.path().to_str().unwrap()).unwrap().trim_start_matches('/').split('/').skip(1).collect::<Vec<_>>().join("/"))
        .collect();
    paths.sort();
    // the name the sender gave is the folder inside the bundle
    assert_eq!(paths, ["memos/a.txt", "memos/old/b.txt"]);
}

#[tokio::test]
async fn failures_are_tool_errors_not_protocol_errors() {
    let relay = relay().await;
    let server = Server::new(&relay, ".");
    for (tool, arguments) in [
        ("bitmule_send", json!({})),
        ("bitmule_send", json!({ "paths": [] })),
        ("bitmule_send", json!({ "paths": ["/definitely/not/here"] })),
        ("bitmule_send", json!({ "paths": ["."], "mode": "carrier-pigeon" })),
        ("bitmule_send_status", json!({})),
        ("bitmule_send_status", json!({ "transfer_id": "send-999" })),
        ("bitmule_receive", json!({})),
        ("bitmule_receive", json!({ "url": "https://example.net/#garbage" })),
        ("bitmule_nonsense", json!({})),
    ] {
        let result = call(&server, tool, arguments.clone()).await;
        assert_eq!(result["isError"], true, "{tool} {arguments}: {result}");
        assert!(!result["content"][0]["text"].as_str().unwrap().is_empty());
    }
}

/// The binary on real pipes, one JSON message per line.
#[tokio::test]
async fn the_binary_speaks_mcp_on_stdio() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_bitmule-mcp"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    for (message, expect_answer) in [
        (request(1, "initialize", json!({ "protocolVersion": "2025-06-18" })), true),
        (json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }), false),
        (request(2, "tools/list", json!({})), true),
    ] {
        stdin.write_all(format!("{message}\n").as_bytes()).await.unwrap();
        if expect_answer {
            let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await.unwrap().unwrap().unwrap();
            let answer: Value = serde_json::from_str(&line).unwrap();
            assert!(answer["result"].is_object(), "{answer}");
        }
    }
    // garbage in: a parse error out, and the server carries on
    stdin.write_all(b"this is not json\n").await.unwrap();
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await.unwrap().unwrap().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["error"]["code"], -32700);
    stdin.write_all(format!("{}\n", request(3, "ping", json!({}))).as_bytes()).await.unwrap();
    let line = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await.unwrap().unwrap().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], 3);
}
