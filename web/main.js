// bitmule landing-page SPA.
//
// Responsibilities today:
//   - Drop-zone + file picker that accept any files.
//   - Load the bitmule-client-wasm module in the background.
//   - Open a signaling WebSocket to the server in the background.
//
// Follow-up cuts wire the file queue into an actual upload flow (via
// wasm + WebRTC + relay fallback). For now the drop just enqueues the
// picked files into a visible list so the UI is honest about what
// exists and what doesn't yet.

const CONFIG = {
  // Server root. Change to your deployed bitmule-server address.
  // Same-origin default in production; localhost during dev.
  server:
    (window.BITMULE_SERVER && String(window.BITMULE_SERVER)) ||
    (location.protocol === "file:"
      ? "http://localhost:8443"
      : `${location.protocol}//${location.host}`),
  // Optional path where the wasm-pack --target web bundle lives.
  // Missing bundle is not an error; the SPA still functions.
  wasmModulePath: "./wasm/pkg/bitmule_client_wasm.js",
};

const els = {
  dropzone: document.getElementById("dropzone"),
  pickBtn: document.getElementById("pick-btn"),
  fileInput: document.getElementById("file-input"),
  queue: document.getElementById("queue"),
  wasmStatus: document.getElementById("wasm-status"),
  serverStatus: document.getElementById("server-status"),
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

function enqueueFiles(fileList) {
  for (const f of fileList) {
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
    enqueueFiles(e.target.files);
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
  if (files && files.length) enqueueFiles(files);
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
    // No wasm bundle yet, or import failed. UI still works.
    setStatus(els.wasmStatus, "err", "not built");
    console.info("bitmule-client-wasm not loaded:", err?.message || err);
  }
})();

// ---- background: signaling socket --------------------------------------

(function connectSignaling() {
  // For the pre-transfer "server is up" probe, open a ws with a random
  // session id and role=sender. The server accepts, we send a hello, and
  // that's proof-of-life. Real sessions get their own sockets later.
  const httpBase = CONFIG.server.replace(/^http/, "ws");
  // Random 32-byte hex session id, browser-crypto.
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const sessionHex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const url = `${httpBase.replace(/\/$/, "")}/ws/${sessionHex}`;

  let ws;
  try {
    ws = new WebSocket(url);
  } catch (err) {
    setStatus(els.serverStatus, "err", "url invalid");
    return;
  }
  ws.addEventListener("open", () => {
    setStatus(els.serverStatus, "ok", "connected");
    ws.send(JSON.stringify({ type: "hello", role: "sender" }));
  });
  ws.addEventListener("error", () => {
    setStatus(els.serverStatus, "err", "unreachable");
  });
  ws.addEventListener("close", (ev) => {
    if (ev.wasClean && els.serverStatus.classList.contains("ok")) {
      // Kept OK — the probe closed cleanly after saying hello.
      return;
    }
    if (!els.serverStatus.classList.contains("ok")) {
      setStatus(els.serverStatus, "err", "unreachable");
    }
  });
})();
