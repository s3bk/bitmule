// bitmule landing-page SPA.
//
// Single page, two modes:
//   - Send:    URL has no hash. Drop-zone + share-link flow.
//   - Receive: URL hash is a valid 64-hex session id. Connects as
//              receiver against that session.
//
// Switching modes is a route change: navigate to `#` to send, navigate
// to `#<hex>` to receive. Live `hashchange` events flip the mode
// without a reload.

const CONFIG = {
  server:
    (window.BITMULE_SERVER && String(window.BITMULE_SERVER)) ||
    (location.protocol === "file:"
      ? "http://localhost:8443"
      : `${location.protocol}//${location.host}`),
  wasmModulePath: "./wasm/pkg/bitmule_client_wasm.js",
};

// ---- shared helpers -----------------------------------------------------

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

function serverToWs(url) {
  return url.replace(/^http/, "ws").replace(/\/$/, "");
}

function serverHttpBase(url) {
  return url.replace(/\/$/, "");
}

function isHex64(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

function randomHex32() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- element refs (both modes) -----------------------------------------

const els = {
  tagline: document.getElementById("tagline"),
  sendMode: document.getElementById("send-mode"),
  recvMode: document.getElementById("receive-mode"),

  // send
  dropzone: document.getElementById("dropzone"),
  pickBtn: document.getElementById("pick-btn"),
  fileInput: document.getElementById("file-input"),
  queue: document.getElementById("queue"),
  session: document.getElementById("session"),
  sessionLink: document.getElementById("session-link"),
  sessionQr: document.getElementById("session-qr"),
  sessionState: document.getElementById("session-state"),
  copyBtn: document.getElementById("copy-link"),
  cancelBtn: document.getElementById("cancel-session"),

  // receive
  recvState: document.getElementById("recv-state"),
  recvSessionId: document.getElementById("recv-session-id"),
  recvServerStatus: document.getElementById("recv-server-status"),
  recvCancel: document.getElementById("recv-cancel"),

  // global status
  wasmStatus: document.getElementById("wasm-status"),
  serverStatus: document.getElementById("server-status"),
};

// ---- QR ----------------------------------------------------------------

function renderQr(text) {
  if (typeof window.qrcode !== "function") {
    els.sessionQr.textContent = "";
    return;
  }
  try {
    const qr = window.qrcode(0, "L");
    qr.addData(text);
    qr.make();
    els.sessionQr.innerHTML = qr.createSvgTag({
      cellSize: 5,
      margin: 2,
      scalable: true,
    });
  } catch (err) {
    els.sessionQr.textContent = "";
    console.warn("qr render failed:", err);
  }
}

// ---- send mode ---------------------------------------------------------

let sendSession = null;

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

function showSessionPanel(link) {
  els.dropzone.hidden = true;
  els.session.hidden = false;
  els.sessionLink.value = link;
  renderQr(link);
  els.sessionState.textContent = "waiting for receiver…";
  els.sessionState.classList.remove("transferring");
}

function hideSessionPanel() {
  els.session.hidden = true;
  els.dropzone.hidden = false;
  clearQueue();
  els.sessionLink.value = "";
  els.sessionQr.innerHTML = "";
}

function closeSendSession() {
  if (sendSession) {
    try {
      sendSession.ws.close();
    } catch {}
    sendSession = null;
  }
}

function startSendSession(files) {
  closeSendSession();
  renderQueue(files);

  const sessionHex = randomHex32();
  // Same-page share link: navigate to the app root with the session in
  // the hash. Receiver reads the hash on load and flips into receive
  // mode without any URL rewriting or extra route.
  const link = `${serverHttpBase(CONFIG.server)}/#${sessionHex}`;

  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    els.sessionState.textContent = `couldn't open socket: ${err.message}`;
    return;
  }

  const session = { sessionHex, link, ws, files };
  sendSession = session;
  showSessionPanel(link);

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "hello", role: "sender" }));
  });
  ws.addEventListener("message", (ev) => {
    if (sendSession !== session) return;
    els.sessionState.textContent =
      "receiver joined — transfer stub (not yet wired)";
    els.sessionState.classList.add("transferring");
    console.info("relay frame from receiver:", ev.data);
  });
  ws.addEventListener("close", () => {
    if (sendSession !== session) return;
    if (!els.sessionState.classList.contains("transferring")) {
      els.sessionState.textContent = "socket closed — cancel to send another";
    }
  });
  ws.addEventListener("error", () => {
    if (sendSession !== session) return;
    els.sessionState.textContent = "server unreachable";
  });
}

// send-mode DOM wiring
function wireSendMode() {
  els.pickBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    els.fileInput.click();
  });
  els.dropzone.addEventListener("click", () => els.fileInput.click());
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
    closeSendSession();
    hideSessionPanel();
  });
}

// ---- receive mode ------------------------------------------------------

let recvSession = null;

function closeRecvSession() {
  if (recvSession) {
    try {
      recvSession.ws.close();
    } catch {}
    recvSession = null;
  }
}

function startRecvSession(sessionHex) {
  closeRecvSession();

  els.recvSessionId.textContent = sessionHex.slice(0, 8) + "…";
  setStatus(els.recvServerStatus, "pending", "connecting…");
  els.recvState.textContent = "connecting…";
  els.recvState.classList.remove("transferring");

  const receiverId = randomHex32();
  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    setStatus(els.recvServerStatus, "err", "url invalid");
    els.recvState.textContent = `couldn't open socket: ${err.message}`;
    return;
  }

  const session = { sessionHex, receiverId, ws };
  recvSession = session;

  ws.addEventListener("open", () => {
    setStatus(els.recvServerStatus, "ok", "connected");
    ws.send(
      JSON.stringify({
        type: "hello",
        role: "receiver",
        receiver_id: receiverId,
      })
    );
    ws.send(
      JSON.stringify({ type: "peer_hello", receiver_id: receiverId })
    );
    els.recvState.textContent =
      "connected — waiting for sender to start transfer";
    els.recvState.classList.add("transferring");
  });
  ws.addEventListener("message", (ev) => {
    if (recvSession !== session) return;
    console.info("relay frame from sender:", ev.data);
  });
  ws.addEventListener("close", () => {
    if (recvSession !== session) return;
    setStatus(els.recvServerStatus, "err", "closed");
    if (!els.recvState.classList.contains("transferring")) {
      els.recvState.textContent = "socket closed";
    }
  });
  ws.addEventListener("error", () => {
    if (recvSession !== session) return;
    setStatus(els.recvServerStatus, "err", "unreachable");
    els.recvState.textContent = "server unreachable";
  });
}

function wireRecvMode() {
  els.recvCancel.addEventListener("click", () => {
    closeRecvSession();
    history.replaceState(null, "", location.pathname + location.search);
    applyRoute();
  });
}

// ---- routing -----------------------------------------------------------

function currentSessionHex() {
  const h = location.hash.replace(/^#/, "");
  return isHex64(h) ? h : null;
}

function applyRoute() {
  const hex = currentSessionHex();
  if (hex) {
    // Receive mode
    closeSendSession();
    hideSessionPanel();
    els.sendMode.hidden = true;
    els.recvMode.hidden = false;
    els.tagline.textContent = "receiving";
    startRecvSession(hex);
  } else {
    // Send mode
    closeRecvSession();
    els.recvMode.hidden = true;
    els.sendMode.hidden = false;
    els.tagline.textContent = "drop files to send";
  }
}

// ---- background: wasm load --------------------------------------------

(async () => {
  try {
    const mod = await import(CONFIG.wasmModulePath);
    if (typeof mod.default === "function") await mod.default();
    const version =
      typeof mod.version === "function" ? mod.version() : "loaded";
    setStatus(els.wasmStatus, "ok", `v${version}`);
    window.bitmule = mod;
  } catch (err) {
    setStatus(els.wasmStatus, "err", "not built");
    console.info("bitmule-client-wasm not loaded:", err?.message || err);
  }
})();

// ---- background: reachability probe -----------------------------------

(async () => {
  try {
    const resp = await fetch(serverHttpBase(CONFIG.server) + "/", {
      method: "GET",
      cache: "no-store",
    });
    setStatus(els.serverStatus, "ok", `reachable (${resp.status})`);
  } catch {
    setStatus(els.serverStatus, "err", "unreachable");
  }
})();

// ---- boot --------------------------------------------------------------

wireSendMode();
wireRecvMode();
window.addEventListener("hashchange", applyRoute);
applyRoute();
