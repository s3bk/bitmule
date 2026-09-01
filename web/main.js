// bitmule landing-page SPA.
//
// Single page, two modes:
//   - Send:    URL has no hash. Drop-zone + share-link flow.
//   - Receive: URL hash is a valid 64-hex session id. Connects as
//              receiver against that session.
//
// Both modes open the signaling WebSocket to the server, then negotiate
// a direct WebRTC data channel with the other peer. Chunk transfer will
// ride the data channel; this cut only proves the connection opens.

const CONFIG = {
  server:
    (window.BITMULE_SERVER && String(window.BITMULE_SERVER)) ||
    (location.protocol === "file:"
      ? "http://localhost:8443"
      : `${location.protocol}//${location.host}`),
  wasmModulePath: "./wasm/pkg/bitmule_client_wasm.js",
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
  ],
  // 16 KiB is the SCTP-safe universal message size (Firefox cap). Chrome
  // allows larger but 16 KiB gives us portable behaviour with no
  // fragmentation risk.
  chunkBytes: 16 * 1024,
  // Backpressure watermarks on RTCDataChannel.bufferedAmount.
  bufferedHighWater: 4 * 1024 * 1024,
  bufferedLowWater: 1 * 1024 * 1024,
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
  recvDownload: document.getElementById("recv-download"),

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

// ---- WebRTC signaling adapter ------------------------------------------
//
// Shared by both roles. Wraps an RTCPeerConnection and speaks four frame
// types over the caller-supplied WS:
//   {type:"sdp", kind:"offer"|"answer", sdp}
//   {type:"ice", candidate}    // candidate is RTCIceCandidateInit or null
// The caller is responsible for routing incoming ws messages into
// `handleFrame(frame)` and for closing the peer connection on cancel.

function createPeer({ role, ws, onOpen, onMessage, onState }) {
  const pc = new RTCPeerConnection({ iceServers: CONFIG.iceServers });
  let dc = null;

  function bindDataChannel(channel) {
    dc = channel;
    dc.binaryType = "arraybuffer";
    dc.addEventListener("open", () => onOpen && onOpen(dc));
    dc.addEventListener("message", (ev) => onMessage && onMessage(ev.data));
    dc.addEventListener("close", () => onState && onState("dc-closed"));
    dc.addEventListener("error", (e) =>
      console.warn("data channel error:", e)
    );
  }

  if (role === "sender") {
    bindDataChannel(pc.createDataChannel("bitmule", { ordered: true }));
  } else {
    pc.addEventListener("datachannel", (ev) => bindDataChannel(ev.channel));
  }

  pc.addEventListener("icecandidate", (ev) => {
    // ev.candidate === null signals end-of-candidates; forward that too so
    // the peer can stop waiting.
    try {
      ws.send(
        JSON.stringify({ type: "ice", candidate: ev.candidate })
      );
    } catch {}
  });

  pc.addEventListener("connectionstatechange", () => {
    onState && onState(`pc:${pc.connectionState}`);
  });

  async function startOffer() {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    ws.send(
      JSON.stringify({ type: "sdp", kind: "offer", sdp: offer.sdp })
    );
  }

  async function handleFrame(frame) {
    if (!frame || typeof frame !== "object") return;
    if (frame.type === "sdp") {
      const desc = { type: frame.kind, sdp: frame.sdp };
      await pc.setRemoteDescription(desc);
      if (frame.kind === "offer") {
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        ws.send(
          JSON.stringify({
            type: "sdp",
            kind: "answer",
            sdp: answer.sdp,
          })
        );
      }
    } else if (frame.type === "ice") {
      try {
        // null candidate = end-of-candidates from the peer; ignore.
        if (frame.candidate) await pc.addIceCandidate(frame.candidate);
      } catch (e) {
        console.warn("addIceCandidate failed:", e);
      }
    }
  }

  function close() {
    try {
      if (dc) dc.close();
    } catch {}
    try {
      pc.close();
    } catch {}
  }

  return { pc, get dc() { return dc; }, startOffer, handleFrame, close };
}

// ---- chunk transfer over the data channel ------------------------------
//
// Wire framing:
//   text frame:   JSON control message
//       {type:"meta", name, size, chunkBytes, totalChunks}
//       {type:"done"}
//   binary frame: raw ciphertext-equivalent bytes (no encryption in this
//                 cut — step 1 is transfer correctness; K_session wrap
//                 lands with the identity-key layer)
//
// Sender streams the file via File.stream() and writes each chunkBytes
// slice with dc.send(). Backpressure: when bufferedAmount rises above
// CONFIG.bufferedHighWater, pause and await 'bufferedamountlow' with a
// low-watermark threshold of CONFIG.bufferedLowWater.

async function sendFileOverDC(dc, file, { onProgress } = {}) {
  const meta = {
    type: "meta",
    name: file.webkitRelativePath || file.name || "file.bin",
    size: file.size,
    chunkBytes: CONFIG.chunkBytes,
    totalChunks: Math.ceil(file.size / CONFIG.chunkBytes),
  };
  dc.send(JSON.stringify(meta));

  dc.bufferedAmountLowThreshold = CONFIG.bufferedLowWater;

  const reader = file.stream().getReader();
  let carry = new Uint8Array(0);
  let sent = 0;

  const flushChunk = async (chunk) => {
    if (dc.bufferedAmount > CONFIG.bufferedHighWater) {
      await new Promise((resolve) => {
        const handler = () => {
          dc.removeEventListener("bufferedamountlow", handler);
          resolve();
        };
        dc.addEventListener("bufferedamountlow", handler);
      });
    }
    dc.send(chunk);
    sent += chunk.byteLength;
    onProgress && onProgress(sent, file.size);
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    // Merge with any carry-over, then slice into chunkBytes segments.
    let buf;
    if (carry.length === 0) {
      buf = value;
    } else {
      buf = new Uint8Array(carry.length + value.length);
      buf.set(carry, 0);
      buf.set(value, carry.length);
    }
    let offset = 0;
    while (offset + CONFIG.chunkBytes <= buf.length) {
      await flushChunk(buf.subarray(offset, offset + CONFIG.chunkBytes));
      offset += CONFIG.chunkBytes;
    }
    carry = buf.subarray(offset);
  }
  // Tail
  if (carry.length > 0) {
    await flushChunk(carry);
  }

  dc.send(JSON.stringify({ type: "done" }));
}

// Receiver-side accumulator. One outbound Blob per file.
function makeReceiver({ onProgress, onFile }) {
  let meta = null;
  let chunks = [];
  let received = 0;

  return function onMessage(data) {
    if (typeof data === "string") {
      let frame;
      try {
        frame = JSON.parse(data);
      } catch {
        return;
      }
      if (frame.type === "meta") {
        meta = frame;
        chunks = [];
        received = 0;
      } else if (frame.type === "done") {
        if (!meta) return;
        const blob = new Blob(chunks, { type: "application/octet-stream" });
        onFile && onFile(meta.name, blob, meta.size);
        meta = null;
        chunks = [];
        received = 0;
      }
      return;
    }
    // Binary frame — ArrayBuffer per DC.binaryType = "arraybuffer".
    if (data instanceof ArrayBuffer) {
      chunks.push(data);
      received += data.byteLength;
      if (meta) onProgress && onProgress(received, meta.size, meta.name);
    }
  };
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
  // Reset the cancel button back to "Cancel" — it becomes "Send another"
  // when a transfer completes successfully.
  els.cancelBtn.textContent = "Cancel";
  els.cancelBtn.classList.remove("done");
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
      sendSession.peer && sendSession.peer.close();
    } catch {}
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
  const link = `${serverHttpBase(CONFIG.server)}/#${sessionHex}`;

  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    els.sessionState.textContent = `couldn't open socket: ${err.message}`;
    return;
  }

  const session = { sessionHex, link, ws, files, peer: null };
  sendSession = session;
  showSessionPanel(link);

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "hello", role: "sender" }));
  });

  ws.addEventListener("message", async (ev) => {
    if (sendSession !== session) return;
    let frame;
    try {
      frame = JSON.parse(ev.data);
    } catch {
      return;
    }

    // The receiver's peer_hello is the trigger to spin up WebRTC and
    // send an SDP offer. Subsequent sdp/ice frames flow through the peer.
    if (frame.type === "peer_hello") {
      els.sessionState.textContent =
        "receiver joined — negotiating direct connection…";
      els.sessionState.classList.add("transferring");
      if (!session.peer) {
        session.peer = createPeer({
          role: "sender",
          ws,
          onOpen: async (dc) => {
            const file = session.files && session.files[0];
            if (!file) {
              els.sessionState.textContent = "direct channel open (no file queued)";
              return;
            }
            els.sessionState.textContent = `sending ${file.name}: 0%`;
            try {
              await sendFileOverDC(dc, file, {
                onProgress: (sent, total) => {
                  if (sendSession !== session) return;
                  const pct = total > 0 ? Math.floor((sent / total) * 100) : 0;
                  els.sessionState.textContent =
                    `sending ${file.name}: ${pct}% (${fmtSize(sent)} / ${fmtSize(total)})`;
                },
              });
              els.sessionState.textContent = `sent ${file.name} (${fmtSize(file.size)})`;
              // Flip the cancel button into a "Send another" affordance —
              // same click handler tears the session down and returns
              // the drop-zone.
              els.cancelBtn.textContent = "Send another";
              els.cancelBtn.classList.add("done");
            } catch (err) {
              els.sessionState.textContent = `send failed: ${err.message}`;
            }
          },
          onMessage: (data) => {
            console.info("dc message from receiver:", data);
          },
          onState: (s) => {
            console.info("sender pc state:", s);
          },
        });
        try {
          await session.peer.startOffer();
        } catch (e) {
          els.sessionState.textContent = `offer failed: ${e.message}`;
        }
      }
      return;
    }

    if (session.peer && (frame.type === "sdp" || frame.type === "ice")) {
      try {
        await session.peer.handleFrame(frame);
      } catch (e) {
        console.warn("sender handleFrame:", e);
      }
    }
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
      recvSession.peer && recvSession.peer.close();
    } catch {}
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

  // Receiver preps its peer connection immediately so the SDP offer can
  // be answered as soon as it arrives.
  const session = { sessionHex, receiverId, ws, peer: null };
  recvSession = session;
  const recvOnMessage = makeReceiver({
    onProgress: (received, total, name) => {
      if (recvSession !== session) return;
      const pct = total > 0 ? Math.floor((received / total) * 100) : 0;
      els.recvState.textContent =
        `receiving ${name}: ${pct}% (${fmtSize(received)} / ${fmtSize(total)})`;
    },
    onFile: (name, blob, size) => {
      if (recvSession !== session) return;
      els.recvState.textContent = `received ${name} (${fmtSize(size)})`;
      const url = URL.createObjectURL(blob);
      els.recvDownload.hidden = false;
      els.recvDownload.innerHTML = "";
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.textContent = `Download ${name}`;
      a.className = "pick-btn download-link";
      els.recvDownload.appendChild(a);
      // Try to auto-trigger the download (browsers may block if no
      // user-gesture recency; the visible button always works).
      a.click();
    },
  });

  session.peer = createPeer({
    role: "receiver",
    ws,
    onOpen: () => {
      els.recvState.textContent =
        "direct channel open — ready to receive";
      els.recvState.classList.add("transferring");
    },
    onMessage: recvOnMessage,
    onState: (s) => {
      console.info("receiver pc state:", s);
    },
  });

  ws.addEventListener("open", () => {
    setStatus(els.recvServerStatus, "ok", "connected");
    ws.send(
      JSON.stringify({
        type: "hello",
        role: "receiver",
        receiver_id: receiverId,
      })
    );
    // The peer_hello triggers the sender to spin up its RTC + send offer.
    ws.send(
      JSON.stringify({ type: "peer_hello", receiver_id: receiverId })
    );
    els.recvState.textContent =
      "connected — waiting for sender to negotiate direct channel";
  });

  ws.addEventListener("message", async (ev) => {
    if (recvSession !== session) return;
    let frame;
    try {
      frame = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (frame.type === "sdp" || frame.type === "ice") {
      try {
        await session.peer.handleFrame(frame);
      } catch (e) {
        console.warn("recv handleFrame:", e);
      }
    }
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
    closeSendSession();
    hideSessionPanel();
    els.sendMode.hidden = true;
    els.recvMode.hidden = false;
    els.tagline.textContent = "receiving";
    startRecvSession(hex);
  } else {
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
