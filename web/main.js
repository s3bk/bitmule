// bitmule landing-page SPA.
//
// Sender flow (this cut):
//   1. User drops or picks files.
//   2. Client generates a fresh session id.
//   3. Client opens a signaling WebSocket to /ws/<hex> as role=sender.
//   4. Client renders the share link the receiver will paste, and stays
//      connected on the socket, waiting for a receiver to join the same
//      session.
//   5. Anything that arrives on the socket while we're waiting flips the
//      state to "receiver joined" — the actual chunk pipeline lands in
//      the follow-up cut.

const CONFIG = {
  server:
    (window.BITMULE_SERVER && String(window.BITMULE_SERVER)) ||
    (location.protocol === "file:"
      ? "http://localhost:8443"
      : `${location.protocol}//${location.host}`),
  wasmModulePath: "./wasm/pkg/bitmule_client_wasm.js",
};

const els = {
  dropzone: document.getElementById("dropzone"),
  pickBtn: document.getElementById("pick-btn"),
  fileInput: document.getElementById("file-input"),
  queue: document.getElementById("queue"),
  wasmStatus: document.getElementById("wasm-status"),
  serverStatus: document.getElementById("server-status"),
  session: document.getElementById("session"),
  sessionLink: document.getElementById("session-link"),
  sessionState: document.getElementById("session-state"),
  copyBtn: document.getElementById("copy-link"),
  cancelBtn: document.getElementById("cancel-session"),
};

function setStatus(el, state, text) {
  el.textContent = text;
  el.classList.remove("pending", "ok", "err");
  el.classList.add(state);
}

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KiB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MiB`;
  return `${(mb / 1024).toFixed(2)} GiB`;
}

function clearQueue() {
  els.queue.textContent = "";
}

function renderQueue(files) {
  clearQueue();
  for (const f of files) {
    const row = document.createElement("div");
    row.className = "queue-item";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = f.webkitRelativePath || f.name;
    const size = document.createElement("span");
    size.className = "size";
    size.textContent = fmtSize(f.size);
    row.append(name, size);
    els.queue.appendChild(row);
  }
}

// ---- session state ------------------------------------------------------

// Holds the currently-live send session. Only one at a time in this cut.
let activeSession = null;

function newSessionIdHex() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function serverToWs(url) {
  return url.replace(/^http/, "ws").replace(/\/$/, "");
}

function serverHttpBase(url) {
  return url.replace(/\/$/, "");
}

function showSessionPanel(link) {
  els.dropzone.hidden = true;
  els.session.hidden = false;
  els.sessionLink.value = link;
  els.sessionState.textContent = "waiting for receiver…";
  els.sessionState.classList.remove("transferring");
}

function hideSessionPanel() {
  els.session.hidden = true;
  els.dropzone.hidden = false;
  clearQueue();
  els.sessionLink.value = "";
}

async function startSendSession(files) {
  // If a previous session is still open, close it. The user picked new
  // files; that supersedes the prior session.
  if (activeSession) {
    activeSession.close();
    activeSession = null;
  }

  renderQueue(files);

  const sessionHex = newSessionIdHex();
  const link = `${serverHttpBase(CONFIG.server)}/r/${sessionHex}`;

  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    els.sessionState.textContent = `couldn't open socket: ${err.message}`;
    return;
  }

  const session = {
    sessionHex,
    link,
    ws,
    files,
    close() {
      try {
        ws.close();
      } catch {}
    },
  };
  activeSession = session;
  showSessionPanel(link);

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "hello", role: "sender" }));
  });

  ws.addEventListener("message", (ev) => {
    // Any frame from the server on this socket means a receiver has
    // joined the room and their frame was relayed to us. The real
    // pipeline (SDP exchange, KEX, chunk stream) attaches here in a
    // follow-up. For now: flip the visible state so the user knows the
    // other side showed up.
    if (activeSession !== session) return;
    els.sessionState.textContent = "receiver joined — transfer stub (not yet wired)";
    els.sessionState.classList.add("transferring");
    console.info("relay frame from receiver:", ev.data);
  });

  ws.addEventListener("close", () => {
    if (activeSession !== session) return;
    if (!els.sessionState.classList.contains("transferring")) {
      els.sessionState.textContent = "socket closed — cancel to send another";
    }
  });

  ws.addEventListener("error", () => {
    if (activeSession !== session) return;
    els.sessionState.textContent = "server unreachable";
  });
}

// ---- drop-zone wiring ---------------------------------------------------

els.pickBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  els.fileInput.click();
});

els.dropzone.addEventListener("click", () => {
  els.fileInput.click();
});

els.dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    els.fileInput.click();
  }
});

els.fileInput.addEventListener("change", (e) => {
  if (e.target.files && e.target.files.length) {
    startSendSession(Array.from(e.target.files));
    e.target.value = "";
  }
});

["dragenter", "dragover"].forEach((ev) => {
  els.dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    els.dropzone.classList.add("dragover");
  });
});
["dragleave", "drop"].forEach((ev) => {
  els.dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    e.stopPropagation();
    els.dropzone.classList.remove("dragover");
  });
});
els.dropzone.addEventListener("drop", (e) => {
  const files = e.dataTransfer?.files;
  if (files && files.length) startSendSession(Array.from(files));
});

// ---- session panel buttons ---------------------------------------------

els.copyBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(els.sessionLink.value);
    const prev = els.copyBtn.textContent;
    els.copyBtn.textContent = "Copied";
    setTimeout(() => (els.copyBtn.textContent = prev), 1200);
  } catch {
    els.sessionLink.select();
  }
});

els.cancelBtn.addEventListener("click", () => {
  if (activeSession) {
    activeSession.close();
    activeSession = null;
  }
  hideSessionPanel();
});

// ---- background: wasm load ---------------------------------------------

(async () => {
  try {
    const mod = await import(CONFIG.wasmModulePath);
    if (typeof mod.default === "function") {
      await mod.default();
    }
    const version =
      typeof mod.version === "function" ? mod.version() : "loaded";
    setStatus(els.wasmStatus, "ok", `v${version}`);
    window.bitmule = mod;
  } catch (err) {
    setStatus(els.wasmStatus, "err", "not built");
    console.info("bitmule-client-wasm not loaded:", err?.message || err);
  }
})();

// ---- background: reachability probe ------------------------------------

// Fire-and-forget HEAD probe against the server root so the status row
// reflects reachability without holding a socket idle. The real per-session
// WS opens on file selection.
(async () => {
  try {
    // Any non-network-error response — even 404 — means the server host is
    // up and reachable. axum routes /session/... but not /, so an unrouted
    // GET returns 404 by design.
    const resp = await fetch(serverHttpBase(CONFIG.server) + "/", {
      method: "GET",
      cache: "no-store",
    });
    setStatus(els.serverStatus, "ok", `reachable (${resp.status})`);
  } catch (err) {
    setStatus(els.serverStatus, "err", "unreachable");
  }
})();
