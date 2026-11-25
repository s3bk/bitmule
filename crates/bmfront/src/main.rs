//! bmfront — put the relay and the app under one hostname.
//!
//! bitmule.net serves the account app on 127.0.0.1:8441. The relay (signaling
//! `/ws/*`, the proof of work `/pow`, the chunk relay `/session/*`) wants the
//! same origin, because the browser's live mode calls those paths relative to
//! wherever the app was loaded from. The webserver in front (artisan) proxies a
//! whole host to one port and has no path routing, so this sits between them:
//!
//!   bitmule.net ── artisan ──▶ 127.0.0.1:8440 ─┬─ /pow, /ws/*, /session/* → 8443 relay
//!                                              └─ everything else        → 8441 app
//!
//! One request per upstream connection. The request head is rewritten to say
//! `Connection: close`, so an upstream answers exactly one request and closes;
//! that is what makes a keep-alive client connection safe to split across two
//! backends. WebSocket upgrades are tunneled untouched, both directions.
//!
//! Standard library only: this runs on a small box next to the two servers it
//! fronts, and a dependency tree is not worth it.

use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const MAX_HEAD: usize = 64 * 1024;
const BUF: usize = 64 * 1024;

/// Where a request goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Backend {
    App,
    Relay,
}

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    app: SocketAddr,
    relay: SocketAddr,
    /// Path prefixes that belong to the relay.
    prefixes: Vec<String>,
    verbose: bool,
}

impl Config {
    fn from_args() -> Result<Self, String> {
        let mut cfg = Config {
            listen: "127.0.0.1:8440".parse().unwrap(),
            app: "127.0.0.1:8441".parse().unwrap(),
            relay: "127.0.0.1:8443".parse().unwrap(),
            prefixes: vec!["/pow".into(), "/ws/".into(), "/session/".into()],
            verbose: env::var("BMFRONT_LOG").map(|v| v != "0").unwrap_or(false),
        };
        let mut it = env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--listen" => cfg.listen = next(&mut it, &arg)?.parse().map_err(|e| format!("--listen: {e}"))?,
                "--app" => cfg.app = next(&mut it, &arg)?.parse().map_err(|e| format!("--app: {e}"))?,
                "--relay" => cfg.relay = next(&mut it, &arg)?.parse().map_err(|e| format!("--relay: {e}"))?,
                "--prefix" => cfg.prefixes.push(next(&mut it, &arg)?),
                "--verbose" => cfg.verbose = true,
                "-h" | "--help" => {
                    return Err("usage: bmfront [--listen ADDR] [--app ADDR] [--relay ADDR] \
                                [--prefix PATH]... [--verbose]"
                        .into())
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(cfg)
    }

    fn backend_for(&self, path: &str) -> Backend {
        // A prefix matches either exactly (/pow) or as the start of a path
        // segment (/pow/, /pow?x=1, /ws/...); /powder and /sessionish are not
        // the relay's.
        for p in &self.prefixes {
            if path == p {
                return Backend::Relay;
            }
            if p.ends_with('/') {
                if path.starts_with(p.as_str()) {
                    return Backend::Relay;
                }
            } else if let Some(rest) = path.strip_prefix(p.as_str()) {
                if rest.starts_with('/') || rest.starts_with('?') {
                    return Backend::Relay;
                }
            }
        }
        Backend::App
    }
}

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn main() -> ExitCode {
    let cfg = match Config::from_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bmfront: {e}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bmfront: cannot bind {}: {e}", cfg.listen);
            return ExitCode::FAILURE;
        }
    };
    println!(
        "bmfront: {} → app {} (everything else), relay {} ({})",
        cfg.listen,
        cfg.app,
        cfg.relay,
        cfg.prefixes.join(" ")
    );
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    let peer = s.peer_addr().ok();
                    if let Err(e) = serve(s, &cfg) {
                        if cfg.verbose {
                            eprintln!("bmfront: {peer:?}: {e}");
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("bmfront: accept: {e}");
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    ExitCode::SUCCESS
}

/// Read one request head from `client`, leaving whatever followed it in `rest`.
/// `Ok(None)` means the client went away before sending anything.
fn read_head(client: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(end) = find_head_end(buf) {
            let head = buf[..end].to_vec();
            buf.drain(..end);
            return Ok(Some(head));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "half a head"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

fn serve(mut client: TcpStream, cfg: &Config) -> io::Result<()> {
    client.set_nodelay(true).ok();
    // A little patience for a slow client, then give up: the socket is public.
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = Vec::new();
    let head = match read_head(&mut client, &mut buf)? {
        Some(h) => h,
        None => return Ok(()),
    };
    let text = String::from_utf8_lossy(&head).to_string();

    let request_line = text.lines().next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    // Only the path decides; a query string is not a route.
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    let backend = cfg.backend_for(&path);
    let upstream_addr = match backend {
        Backend::App => cfg.app,
        Backend::Relay => cfg.relay,
    };

    let upgrade = header(&text, "upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        || header(&text, "connection")
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false);

    if cfg.verbose {
        eprintln!(
            "bmfront: {method} {target} {version} → {backend:?} ({upstream_addr}){}",
            if upgrade { " [upgrade]" } else { "" }
        );
    }

    let mut upstream = match TcpStream::connect_timeout(&upstream_addr, Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => {
            // Say so in HTTP rather than dropping the connection unexplained.
            let body = format!("{backend:?} backend {upstream_addr} is not running\n");
            let resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-type: text/plain\r\n\
                 content-length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = client.write_all(resp.as_bytes());
            return Err(io::Error::new(e.kind(), format!("connect {upstream_addr}: {e}")));
        }
    };
    upstream.set_nodelay(true).ok();

    // The head goes up, minus the client's connection-management headers: the
    // upstream answers one request and closes unless this is an upgrade.
    let out_head = if upgrade {
        head.clone()
    } else {
        rewrite_head(&head, &version)
    };
    upstream.write_all(&out_head)?;
    if !buf.is_empty() {
        upstream.write_all(&buf)?;
    }
    upstream.flush()?;
    client.set_read_timeout(None)?;

    tunnel(client, upstream)
}

/// Drop `Connection`, `Keep-Alive`, `Proxy-Connection` and `Upgrade`, and ask
/// the upstream to close after it has answered.
fn rewrite_head(head: &[u8], version: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = String::with_capacity(text.len() + 32);
    let mut first = true;
    for line in text.split("\r\n") {
        if first {
            out.push_str(line);
            out.push_str("\r\n");
            first = false;
            continue;
        }
        if line.is_empty() {
            break;
        }
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    let _ = version; // HTTP/1.0 and 1.1 both take it the same way
    out.push_str("connection: close\r\n\r\n");
    out.into_bytes()
}

/// Copy both directions until each side has finished; then close both.
fn tunnel(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut c_read = client.try_clone()?;
    let mut u_write = upstream.try_clone()?;
    let up = thread::spawn(move || {
        let mut buf = [0u8; BUF];
        loop {
            match c_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if u_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = u_write.shutdown(Shutdown::Write);
    });

    let mut u_read = upstream;
    let mut c_write = client;
    let mut buf = [0u8; BUF];
    loop {
        match u_read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if c_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = c_write.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            app: "127.0.0.1:8441".parse().unwrap(),
            relay: "127.0.0.1:8443".parse().unwrap(),
            prefixes: vec!["/pow".into(), "/ws/".into(), "/session/".into()],
            verbose: false,
        }
    }

    #[test]
    fn routes_relay_paths() {
        let c = cfg();
        assert_eq!(c.backend_for("/pow"), Backend::Relay);
        assert_eq!(c.backend_for("/pow?x=1"), Backend::Relay);
        assert_eq!(c.backend_for("/powder"), Backend::App);
        assert_eq!(c.backend_for("/ws/create"), Backend::Relay);
        assert_eq!(c.backend_for("/ws/join"), Backend::Relay);
        assert_eq!(c.backend_for("/ws"), Backend::App);
        assert_eq!(c.backend_for("/session/abc/def"), Backend::Relay);
        assert_eq!(c.backend_for("/session"), Backend::App);
    }

    #[test]
    fn keeps_app_paths_on_the_app() {
        let c = cfg();
        for p in [
            "/",
            "/app",
            "/app.js",
            "/v1/shares",
            "/v1/pub/abc",
            "/wasm/bitmule_client_wasm.js",
            "/favicon.ico",
            "/sessionish",
        ] {
            assert_eq!(c.backend_for(p), Backend::App, "{p}");
        }
    }

    #[test]
    fn rewrites_connection_headers() {
        let head = b"GET /pow HTTP/1.1\r\nHost: bitmule.net\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nAccept: */*\r\n\r\n";
        let out = String::from_utf8(rewrite_head(head, "HTTP/1.1")).unwrap();
        assert!(out.starts_with("GET /pow HTTP/1.1\r\n"));
        assert_eq!(out.matches("onnection:").count(), 1, "{out}");
        assert!(out.contains("connection: close\r\n"));
        assert!(!out.to_ascii_lowercase().contains("keep-alive:"));
        assert!(out.contains("Host: bitmule.net\r\n"));
        assert!(out.contains("Accept: */*\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn finds_head_end() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn reads_headers_case_insensitively() {
        let head = "GET /ws/create HTTP/1.1\r\nhost: bitmule.net\r\nUpgrade: WebSocket\r\n\r\n";
        assert_eq!(header(head, "upgrade"), Some("WebSocket"));
        assert_eq!(header(head, "HOST"), Some("bitmule.net"));
        assert_eq!(header(head, "nope"), None);
    }
}
