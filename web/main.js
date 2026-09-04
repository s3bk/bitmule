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
  // fragmentation risk. Used ONLY for the WebRTC data-channel path.
  chunkBytes: 16 * 1024,
  // Relay chunks are 1 MiB because each chunk is a separate HTTP PUT
  // and 16 KiB × N adds crippling round-trip overhead. Receiver adapts
  // to whatever the sender declares in meta_relay.chunkBytes.
  relayChunkBytes: 1024 * 1024,
  // Backpressure watermarks on RTCDataChannel.bufferedAmount.
  bufferedHighWater: 4 * 1024 * 1024,
  bufferedLowWater: 1 * 1024 * 1024,
  // How long the sender waits for a WebRTC data channel to open before
  // falling back to the server-relay upload path.
  webrtcTimeoutMs: 3000,
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

// M2b: URL fragment is either a legacy 64-char hex session id or an
// 86-char base64url ShareLink (share_key || signature) for the modern
// send-initiated flow. Returns null if neither shape matches. On
// modern URLs, `shareKey` + `signature` come back parsed via the
// wasm module — falls back to null if wasm not loaded yet.
function parseSessionFragment(rawHash) {
  const h = (rawHash || "").replace(/^#/, "");
  if (!h) return null;
  if (isHex64(h)) {
    return { kind: "hex", sessionHex: h, shareKey: null, signature: null };
  }
  // Send-initiated ShareLink shape: base64url chars decoding to 64 bytes
  // = 32-byte share_key || 32-byte signature. 86 chars unpadded, 88
  // with padding — accept either shape and let wasm's from_b64_url do
  // the length check. Non-b64url chars fall through as "unrecognised".
  if (/^[A-Za-z0-9_\-=]{80,100}$/.test(h)) {
    if (!window.bitmule || !window.bitmule.ShareLink) {
      // Wasm not loaded yet — return a "pending" marker so the caller
      // can decide whether to defer or fall through. The post-wasm
      // applyRoute re-run will pick this up on the next tick.
      console.info("parseSessionFragment: b64url-shaped hash but wasm not loaded yet — deferring");
      return { kind: "sharelink-pending", sessionHex: null, shareKey: null, signature: null };
    }
    try {
      const link = window.bitmule.ShareLink.fromB64Url(h);
      const signature = link.signature;
      const shareKey = link.takeShareKey();
      const sessionHex = shareKey.sessionIdHex();
      console.info("parseSessionFragment: ShareLink parsed, session", sessionHex);
      return { kind: "sharelink", sessionHex, shareKey, signature };
    } catch (e) {
      console.warn("parseSessionFragment: ShareLink parse failed:", e, "fragment:", h);
      return null;
    }
  }
  console.warn("parseSessionFragment: hash didn't match either shape:", h);
  return null;
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
  requestMode: document.getElementById("request-mode"),
  invitedSendMode: document.getElementById("invited-send-mode"),

  // send
  dropzone: document.getElementById("dropzone"),
  pickBtn: document.getElementById("pick-btn"),
  fileInput: document.getElementById("file-input"),
  queue: document.getElementById("queue"),
  session: document.getElementById("session"),
  sessionLink: document.getElementById("session-link"),
  sessionQr: document.getElementById("session-qr"),
  sessionState: document.getElementById("session-state"),
  stopAfterFirst: document.getElementById("stop-after-first"),
  sessionActiveCount: document.getElementById("session-active-count"),
  sessionTotalCount: document.getElementById("session-total-count"),
  peerProgressList: document.getElementById("peer-progress-list"),

  // F00 options menu
  optMultiSend: document.getElementById("opt-multi-send"),
  optUpnp: document.getElementById("opt-upnp"),
  optClipboardWatch: document.getElementById("opt-clipboard-watch"),
  optAutoDownload: document.getElementById("opt-auto-download"),

  // F02 clipboard fetch queue
  fetchQueue: document.getElementById("fetch-queue"),
  fetchQueueList: document.getElementById("fetch-queue-list"),
  copyBtn: document.getElementById("copy-link"),
  cancelBtn: document.getElementById("cancel-session"),
  requestFilesBtn: document.getElementById("request-files-btn"),

  // receive
  recvState: document.getElementById("recv-state"),
  recvSessionId: document.getElementById("recv-session-id"),
  recvServerStatus: document.getElementById("recv-server-status"),
  recvCancel: document.getElementById("recv-cancel"),
  recvDownload: document.getElementById("recv-download"),

  // request (I'm receiver, waiting for sender at /send#<hex>)
  requestLink: document.getElementById("request-link"),
  requestQr: document.getElementById("request-qr"),
  requestState: document.getElementById("request-state"),
  requestDownload: document.getElementById("request-download"),
  copyRequestLink: document.getElementById("copy-request-link"),
  requestCancel: document.getElementById("request-cancel"),

  // invited send (path=/send + hash — someone is waiting for my files)
  invitedDropzone: document.getElementById("invited-dropzone"),
  invitedPickBtn: document.getElementById("invited-pick-btn"),
  invitedFileInput: document.getElementById("invited-file-input"),
  invitedQueue: document.getElementById("invited-queue"),
  invitedSession: document.getElementById("invited-session"),
  invitedSessionState: document.getElementById("invited-session-state"),
  invitedCancel: document.getElementById("invited-cancel"),

  // global status
  wasmStatus: document.getElementById("wasm-status"),
  serverStatus: document.getElementById("server-status"),
};

// ---- QR ----------------------------------------------------------------

function renderQrInto(el, text) {
  if (typeof window.qrcode !== "function") {
    el.textContent = "";
    return;
  }
  try {
    const qr = window.qrcode(0, "L");
    qr.addData(text);
    qr.make();
    el.innerHTML = qr.createSvgTag({
      cellSize: 5,
      margin: 2,
      scalable: true,
    });
  } catch (err) {
    el.textContent = "";
    console.warn("qr render failed:", err);
  }
}

function renderQr(text) { renderQrInto(els.sessionQr, text); }

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

  // Debug output for the DTLS/ICE cross-side diagnosis (2026-09-02, Seb).
  // Every ICE state, DTLS state, and signaling state gets logged with
  // enough context to correlate against the native side's log lines.
  const dbg = (...args) => console.log(`[bitmule ${role}]`, ...args);
  pc.addEventListener("iceconnectionstatechange", () =>
    dbg("iceConnectionState =>", pc.iceConnectionState));
  pc.addEventListener("icegatheringstatechange", () =>
    dbg("iceGatheringState =>", pc.iceGatheringState));
  pc.addEventListener("signalingstatechange", () =>
    dbg("signalingState =>", pc.signalingState));
  pc.addEventListener("icecandidateerror", (e) =>
    dbg("iceCandidateError:", e.errorCode, e.errorText, "url:", e.url));

  function bindDataChannel(channel) {
    dc = channel;
    dc.binaryType = "arraybuffer";
    dbg("bound data channel, initial state =", dc.readyState);
    dc.addEventListener("open", () => { dbg("dc open"); onOpen && onOpen(dc); });
    dc.addEventListener("message", (ev) => onMessage && onMessage(ev.data));
    dc.addEventListener("close", () => { dbg("dc close"); onState && onState("dc-closed"); });
    dc.addEventListener("error", (e) => {
      dbg("dc error:", e);
      console.warn("data channel error:", e);
    });
  }

  if (role === "sender") {
    bindDataChannel(pc.createDataChannel("bitmule", { ordered: true }));
  } else {
    pc.addEventListener("datachannel", (ev) => {
      dbg("ondatachannel fired, label =", ev.channel.label);
      bindDataChannel(ev.channel);
    });
  }

  pc.addEventListener("icecandidate", (ev) => {
    if (ev.candidate) {
      dbg("local ICE candidate:", ev.candidate.candidate);
    } else {
      dbg("local ICE end-of-candidates");
    }
    try {
      ws.send(
        JSON.stringify({ type: "ice", candidate: ev.candidate })
      );
    } catch {}
  });

  pc.addEventListener("connectionstatechange", () => {
    dbg("connectionState =>", pc.connectionState);
    onState && onState(`pc:${pc.connectionState}`);
  });

  async function startOffer() {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    dbg(`local SDP (offer):\n${offer.sdp}`);
    ws.send(
      JSON.stringify({ type: "sdp", kind: "offer", sdp: offer.sdp })
    );
  }

  async function handleFrame(frame) {
    if (!frame || typeof frame !== "object") return;
    if (frame.type === "sdp") {
      dbg(`remote SDP (${frame.kind}):\n${frame.sdp}`);
      const desc = { type: frame.kind, sdp: frame.sdp };
      try {
        await pc.setRemoteDescription(desc);
        dbg("setRemoteDescription OK");
      } catch (e) {
        dbg("setRemoteDescription FAILED:", e);
        throw e;
      }
      if (frame.kind === "offer") {
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        dbg(`local SDP (answer):\n${answer.sdp}`);
        ws.send(
          JSON.stringify({
            type: "sdp",
            kind: "answer",
            sdp: answer.sdp,
          })
        );
      }
    } else if (frame.type === "ice") {
      if (frame.candidate) {
        dbg("remote ICE candidate:", frame.candidate.candidate);
      } else {
        dbg("remote ICE end-of-candidates");
      }
      try {
        if (frame.candidate) await pc.addIceCandidate(frame.candidate);
      } catch (e) {
        dbg("addIceCandidate FAILED:", e);
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

async function sendFileOverDC(dc, file, { onProgress, interruptAt } = {}) {
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
    // Debug interruption hook: if configured, bail out (before send) the
    // moment the transfer would cross the interrupt threshold. Simulates
    // a network drop mid-transfer without needing actual network faults.
    if (typeof interruptAt === "number" && sent >= interruptAt) {
      throw new Error(`debug-interrupt at ${sent} bytes (threshold ${Math.floor(interruptAt)})`);
    }
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

// ---- server-relay send path (fallback when WebRTC doesn't come up) ------
//
// Sender uploads each chunk via HTTP PUT to /session/:sess/chunk/:idx and
// notifies the receiver over the signaling WS with a {type:"chunk_relay",
// idx} frame per uploaded chunk. Finally sends {type:"relay_done"} so the
// receiver knows to finalize. Meta ships as a {type:"meta_relay", ...}
// WS frame before the first chunk_relay so the receiver knows shape +
// name.

async function sendFileOverRelay(session, ws, file, { onProgress, progressState } = {}) {
  const chunkBytes = CONFIG.relayChunkBytes;
  const totalChunks = Math.ceil(file.size / chunkBytes);
  const meta = {
    type: "meta_relay",
    name: file.webkitRelativePath || file.name || "file.bin",
    size: file.size,
    chunkBytes,
    totalChunks,
  };
  try { ws.send(JSON.stringify(meta)); } catch {}
  if (progressState) {
    progressState.meta = meta;
    progressState.sentIdxs = [];
    progressState.done = false;
  }

  const sessionHex = session;
  const httpBase = serverHttpBase(CONFIG.server);
  let sent = 0;
  for (let idx = 0; idx < totalChunks; idx++) {
    const start = idx * chunkBytes;
    const end = Math.min(start + chunkBytes, file.size);
    const slice = file.slice(start, end);
    const url = `${httpBase}/session/${sessionHex}/chunk/${idx}`;
    const resp = await fetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(end - start),
      },
      body: slice,
    });
    if (!resp.ok) {
      throw new Error(`relay PUT ${idx} → ${resp.status}`);
    }
    try {
      ws.send(JSON.stringify({ type: "chunk_relay", idx }));
    } catch {}
    if (progressState) progressState.sentIdxs.push(idx);
    sent += end - start;
    onProgress && onProgress(sent, file.size);
  }
  try { ws.send(JSON.stringify({ type: "relay_done" })); } catch {}
  if (progressState) progressState.done = true;
}

// Re-emit the meta/chunk/done frames a sender already sent during a
// prior relay run. Called when the server notifies of a fresh receiver
// join so the newcomer catches up on what was already uploaded.
function resendRelayProgress(ws, progressState) {
  if (!progressState || !progressState.meta) return;
  try { ws.send(JSON.stringify(progressState.meta)); } catch {}
  for (const idx of progressState.sentIdxs) {
    try { ws.send(JSON.stringify({ type: "chunk_relay", idx })); } catch {}
  }
  if (progressState.done) {
    try { ws.send(JSON.stringify({ type: "relay_done" })); } catch {}
  }
}

// Receiver side for the relay path. Fetches chunks GET
// /session/:sess/chunk/:idx as `chunk_relay` frames arrive over WS, and
// on `relay_done` assembles the Blob (order guaranteed by the
// sender-side sequential PUT + monotonic idx).
function makeRelayReceiver(session, { onProgress, onFile }) {
  let meta = null;
  // Dense array of ArrayBuffers keyed by chunk index. Initialized to a
  // fixed-length array of nulls once meta arrives, so completeness is a
  // simple `.every(x !== null)` and Blob assembly is order-preserving.
  let chunks = null;
  let filled = 0;
  let received = 0;
  let done = false;
  const httpBase = serverHttpBase(CONFIG.server);
  const sessionHex = session;
  const inflight = new Set();

  async function fetchAndPlace(idx) {
    if (!chunks) return;
    if (chunks[idx] !== null) return;
    if (inflight.has(idx)) return;
    inflight.add(idx);
    try {
      const resp = await fetch(`${httpBase}/session/${sessionHex}/chunk/${idx}`);
      if (!resp.ok) throw new Error(`GET chunk ${idx} → ${resp.status}`);
      const buf = await resp.arrayBuffer();
      if (chunks[idx] === null) {
        chunks[idx] = buf;
        filled += 1;
        received += buf.byteLength;
        if (meta) onProgress && onProgress(received, meta.size, meta.name);
      }
      maybeFinalize();
    } catch (e) {
      console.warn("relay fetch:", e);
    } finally {
      inflight.delete(idx);
    }
  }

  function maybeFinalize() {
    if (!meta || done || !chunks) return;
    if (filled !== meta.totalChunks) return;
    done = true;
    const blob = new Blob(chunks, { type: "application/octet-stream" });
    onFile && onFile(meta.name, blob, meta.size);
  }

  return {
    onWsFrame(frame) {
      if (!frame || typeof frame !== "object") return;
      if (frame.type === "meta_relay") {
        meta = frame;
        chunks = new Array(frame.totalChunks).fill(null);
        filled = 0;
        received = 0;
      } else if (frame.type === "chunk_relay") {
        if (typeof frame.idx === "number") fetchAndPlace(frame.idx);
      } else if (frame.type === "relay_done") {
        (async () => {
          if (!meta || !chunks) return;
          for (let i = 0; i < meta.totalChunks; i++) {
            if (chunks[i] === null) await fetchAndPlace(i);
          }
          maybeFinalize();
        })();
      }
    },
  };
}

// ---- hex helpers (KEX / KeyWrap / meta_enc wire) ---------------------

function hexEncode(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < arr.length; i++) s += arr[i].toString(16).padStart(2, "0");
  return s;
}

function hexDecode(s) {
  if (typeof s !== "string" || s.length % 2 !== 0) return null;
  const n = s.length / 2;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const b = parseInt(s.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) return null;
    out[i] = b;
  }
  return out;
}

// Receiver-side accumulator. One outbound Blob per file.
//
// M2b: `keys` (optional) enables the modern AEAD wire — pass
// `{ metaKey, bulkKey, sessionIdBytes, dc }` and the receiver will:
//   - decrypt `meta_enc` under metaKey with sessionIdBytes as AAD
//   - decrypt each binary chunk under bulkKey using idx-derived nonce
//   - emit `request_ranges [0, total_chunks)` on `dc` after meta lands
//   - emit `recv_done` on `dc` after all chunks received
//   - accept `done_ack` alongside legacy `done` as end signal
// Without `keys`, falls back to the pre-AEAD plaintext wire.
function makeReceiver({ onProgress, onFile, keys } = {}) {
  let meta = null;
  let chunks = [];
  let received = 0;
  let recvIdx = 0;
  let requestSent = false;
  let recvDoneSent = false;

  const finalize = () => {
    if (!meta) return;
    const blob = new Blob(chunks, { type: "application/octet-stream" });
    onFile && onFile(meta.name, blob, meta.size);
    meta = null;
    chunks = [];
    received = 0;
    recvIdx = 0;
    requestSent = false;
    recvDoneSent = false;
  };

  const maybeSendRequestRanges = () => {
    if (!keys || !keys.dc || requestSent || !meta) return;
    // total_chunks derived from meta.size + chunkBytes so we ask for
    // exactly the range the sender needs to serve.
    const chunkBytes = meta.chunkBytes || 16 * 1024;
    const totalChunks = meta.size === 0
      ? 0
      : Math.ceil(meta.size / chunkBytes);
    if (totalChunks > 0) {
      const frame = JSON.stringify({
        type: "request_ranges",
        ranges: [{ start: 0, end: totalChunks }],
      });
      try { keys.dc.send(frame); } catch (e) {
        console.warn("request_ranges send failed:", e);
      }
    }
    requestSent = true;
  };

  const maybeSendRecvDone = () => {
    if (!keys || !keys.dc || recvDoneSent || !meta) return;
    const chunkBytes = meta.chunkBytes || 16 * 1024;
    const totalChunks = meta.size === 0
      ? 0
      : Math.ceil(meta.size / chunkBytes);
    if (recvIdx >= totalChunks) {
      try { keys.dc.send(JSON.stringify({ type: "recv_done" })); }
      catch (e) { console.warn("recv_done send failed:", e); }
      recvDoneSent = true;
    }
  };

  return function onMessage(data) {
    if (typeof data === "string") {
      let frame;
      try { frame = JSON.parse(data); } catch { return; }

      if (frame.type === "meta") {
        // Legacy plaintext meta — pre-AEAD wire.
        meta = frame;
        chunks = [];
        received = 0;
        recvIdx = 0;
        return;
      }
      if (frame.type === "meta_enc") {
        if (!keys || !keys.metaKey) {
          console.warn("meta_enc arrived but receiver has no metaKey");
          return;
        }
        const nonce = hexDecode(frame.nonce_hex);
        const ct = hexDecode(frame.ct_hex);
        if (!nonce || !ct) { console.warn("meta_enc: bad hex"); return; }
        let plain;
        try {
          plain = keys.metaKey.decryptMeta(keys.sessionIdBytes, nonce, ct);
        } catch (e) { console.warn("meta_enc decrypt:", e); return; }
        try {
          meta = JSON.parse(new TextDecoder().decode(plain));
        } catch (e) { console.warn("meta_enc JSON parse:", e); return; }
        // Normalize `chunkBytes` casing — native emits camelCase.
        if (meta.chunkBytes == null && meta.chunk_bytes != null) {
          meta.chunkBytes = meta.chunk_bytes;
        }
        chunks = [];
        received = 0;
        recvIdx = 0;
        maybeSendRequestRanges();
        return;
      }
      if (frame.type === "done" || frame.type === "done_ack") {
        finalize();
        return;
      }
      return;
    }
    // Binary frame — ArrayBuffer per DC.binaryType = "arraybuffer".
    if (data instanceof ArrayBuffer) {
      if (keys && keys.bulkKey) {
        let plain;
        try {
          plain = keys.bulkKey.decryptChunk(BigInt(recvIdx), new Uint8Array(data));
        } catch (e) {
          console.warn(`decryptChunk idx=${recvIdx} failed:`, e);
          return;
        }
        chunks.push(plain);
        received += plain.byteLength;
        recvIdx += 1;
      } else {
        chunks.push(data);
        received += data.byteLength;
      }
      if (meta) onProgress && onProgress(received, meta.size, meta.name);
      maybeSendRecvDone();
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

async function startSendSession(files) {
  closeSendSession();
  renderQueue(files);

  // AEAD-only send flow (per Seb 2026-09-04 "no plaintext path"):
  // mint ShareKey + BulkKey, stream-hash the file with BulkKey for the
  // URL commitment, build a ShareLink (base64url) URL. Same shape as
  // the CLI `bitmule send` URL.
  if (!window.bitmule || !window.bitmule.ShareKey) {
    els.sessionState.textContent = "wasm not loaded — refresh and retry";
    return;
  }
  const file = files && files[0];
  if (!file) return;

  els.sessionState.textContent = "computing file commitment…";
  const shareKey = new window.bitmule.ShareKey();
  const bulkKey = new window.bitmule.BulkKey();
  const sessionHexRaw = shareKey.sessionIdHex();
  const sessionIdBytes = hexDecode(sessionHexRaw);
  // Stream-hash the file via CommitmentHasher (SHA256 || bulk_key).
  // Load-and-hash in 64 KiB slices so a 5 GB file doesn't need to fit
  // in memory. Actual send below will re-stream from the same File.
  const hasher = new window.bitmule.CommitmentHasher();
  const HASH_CHUNK = 64 * 1024;
  for (let off = 0; off < file.size; off += HASH_CHUNK) {
    const slice = await file.slice(off, off + HASH_CHUNK).arrayBuffer();
    hasher.update(new Uint8Array(slice));
  }
  const signature = hasher.finalize(bulkKey);
  const link = `${serverHttpBase(CONFIG.server)}/#${b64UrlEncode(
    concatBytes(hexDecode(shareKey.toHex()), signature)
  )}`;

  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHexRaw}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    els.sessionState.textContent = `couldn't open socket: ${err.message}`;
    return;
  }

  const session = {
    sessionHex: sessionHexRaw, link, ws, files, peer: null,
    // Modern crypto material — cheap to share across all peer tasks.
    shareKey, bulkKey, sessionIdBytes,
    // Multipeer state: map from receiver_id (envelope from_receiver_id)
    // to per-peer { pc, dc, ephemeral, wrapKey, metaKey, chunkIdx,
    // metaSent, complete }.
    peers: new Map(),
    activeCount: 0,
    totalCount: 0,
  };
  sendSession = session;
  showSessionPanel(link);
  updateSendCounters();

  // Send-side WebRTC-first, relay-fallback. Symmetric to the recv
  // side: NO timeout, NO fallback until we have positive evidence
  // WebRTC failed AND a receiver is present on the WS.
  //
  // Signals we watch:
  //   - `peer_hello` from server → receiverPresent = true.
  //   - createPeer's onState "failed" AFTER receiverPresent AND
  //     !dcOpen → arm relay upload.
  //
  // No armFallbackTimer, no CONFIG.webrtcTimeoutMs auto-trip.
  session.receiverPresent = false;
  session.dcOpen = false;
  session.relayStarted = false;
  session.relayProgress = { meta: null, sentIdxs: [], done: false };

  const startRelayUpload = async (reason) => {
    if (sendSession !== session) return;
    if (session.dcOpen || session.relayStarted) return;
    const file = session.files && session.files[0];
    if (!file) return;
    session.relayStarted = true;
    // Short low-drama arm text; sendFileOverRelay's onProgress
    // replaces it with per-chunk progress as soon as bytes move.
    els.sessionState.textContent = "using relay fallback…";
    els.sessionState.classList.add("transferring");
    try {
      await sendFileOverRelay(session.sessionHex, ws, file, {
        onProgress: (sent, total) => {
          if (sendSession !== session) return;
          const pct = total > 0 ? Math.floor((sent / total) * 100) : 0;
          els.sessionState.textContent =
            `sending via relay ${file.name}: ${pct}% (${fmtSize(sent)} / ${fmtSize(total)})`;
        },
        progressState: session.relayProgress,
      });
      els.sessionState.textContent = `sent (via relay) ${file.name} (${fmtSize(file.size)})`;
      document.body.dataset.transferStatus = 'complete';
      els.cancelBtn.textContent = "Send another";
      els.cancelBtn.classList.add("done");
    } catch (err) {
      els.sessionState.textContent = `relay send failed: ${err.message}`;
    }
  };

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "hello", role: "sender", wire_version: 2 }));
    // Idle text — waits for a receiver. No fallback timer.
    els.sessionState.textContent = "waiting for receiver…";
  });

  ws.addEventListener("message", async (ev) => {
    if (sendSession !== session) return;
    let frame;
    try {
      frame = JSON.parse(ev.data);
    } catch {
      return;
    }

    // Server-side notification that a new receiver joined mid-session.
    // If we've already started a relay upload, catch the newcomer up by
    // re-emitting the meta + all chunk indices already uploaded.
    if (frame.type === "peer_joined" && frame.role === "receiver") {
      if (session.relayStarted) {
        resendRelayProgress(ws, session.relayProgress);
      }
      return;
    }

    // Multipeer AEAD send: each receiver's peer_hello spawns its own
    // per-peer state (fresh RTCPeerConnection + fresh Ephemeral +
    // eventual wrapKey/metaKey/DC). Frames sdp / ice / kex_pub carry
    // envelope from_receiver_id — route them to the right per-peer
    // entry. The server sends peer_hello with role:"receiver" AND
    // from_receiver_id at the envelope level after the M2b patches.
    const fromId = frame.from_receiver_id || frame.receiver_id || null;
    if (frame.type === "peer_hello" && frame.role !== "sender") {
      session.receiverPresent = true;
      if (fromId && !session.peers.has(fromId)) {
        startPeerForReceiver(session, fromId);
      }
      return;
    }
    // Server-emitted peer_left when a receiver's WS drops. Prune the
    // per-peer state so the UI counter + peers map stays accurate
    // without waiting on ICE-failed / DC-close timeouts.
    if (frame.type === "peer_left" && frame.role === "receiver" && fromId) {
      const peer = session.peers.get(fromId);
      if (peer) {
        console.info(`peer_left: ${fromId.slice(0,8)}… — pruning`);
        if (!peer.complete) {
          session.activeCount = Math.max(0, session.activeCount - 1);
        }
        try { peer.wrpc.close(); } catch {}
        session.peers.delete(fromId);
        removePeerProgressRow(fromId);
        updateSendCounters();
        if (session.activeCount === 0) {
          els.sessionState.textContent = "waiting for receiver…";
        }
      }
      return;
    }
    if (frame.type === "sdp" || frame.type === "ice" || frame.type === "kex_pub") {
      const peer = fromId ? session.peers.get(fromId) : null;
      if (!peer) return;
      try {
        if (frame.type === "kex_pub") {
          await peer.handleKexPub(frame);
        } else {
          await peer.wrpc.handleFrame(frame);
        }
      } catch (e) {
        console.warn(`sender handleFrame for ${fromId}:`, e);
      }
      return;
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

// Concatenate two byte arrays (Uint8Array or ArrayBuffer) into one.
function concatBytes(a, b) {
  const aa = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
  const out = new Uint8Array(aa.length + bb.length);
  out.set(aa, 0);
  out.set(bb, aa.length);
  return out;
}

// Base64url (no padding) encode a byte array — matches
// bitmule_crypto::ShareLink::to_b64_url on the native side.
function b64UrlEncode(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function updateSendCounters() {
  if (!sendSession) return;
  if (els.sessionActiveCount) els.sessionActiveCount.textContent = String(sendSession.activeCount);
  if (els.sessionTotalCount) els.sessionTotalCount.textContent = String(sendSession.totalCount);
}

// F01: per-peer progress rendering. One <li> per peer, keyed by
// receiver_id. Reads live from session.peers state; the sender's
// chunk-loop bumps peer.bytesSent + peer.bytesTotal on each write.
function upsertPeerProgressRow(peer, statusText) {
  if (!els.peerProgressList) return;
  const id = "peer-row-" + peer.receiverId;
  let row = document.getElementById(id);
  if (!row) {
    row = document.createElement("li");
    row.id = id;
    row.className = "peer-progress-row";
    row.innerHTML = `
      <span class="peer-progress-id"></span>
      <span class="peer-progress-bar"><span class="peer-progress-bar-fill"></span></span>
      <span class="peer-progress-status"></span>
    `;
    row.querySelector(".peer-progress-id").textContent = peer.receiverId.slice(0, 8) + "…";
    els.peerProgressList.appendChild(row);
  }
  const total = peer.bytesTotal || 0;
  const sent = peer.bytesSent || 0;
  const pct = total > 0 ? Math.min(100, Math.floor((sent / total) * 100)) : 0;
  row.querySelector(".peer-progress-bar-fill").style.width = pct + "%";
  const st = statusText != null
    ? statusText
    : (total > 0 ? `${pct}% (${fmtSize(sent)} / ${fmtSize(total)})` : "connecting…");
  row.querySelector(".peer-progress-status").textContent = st;
}

function removePeerProgressRow(receiverId) {
  const row = document.getElementById("peer-row-" + receiverId);
  if (row) row.remove();
}

// Spawn a per-receiver peer task. Called on peer_hello with a fresh
// from_receiver_id. Owns its own RTCPeerConnection + Ephemeral + DC.
// Handles the full modern wire: KEX over WS → key_wrap → meta_enc
// → AEAD chunks → recv_done/done_ack.
function startPeerForReceiver(session, receiverId) {
  session.totalCount++;
  session.activeCount++;
  updateSendCounters();
  els.sessionState.textContent = `receiver joined (${receiverId.slice(0,8)}…) — negotiating`;
  els.sessionState.classList.add("transferring");

  const peer = {
    receiverId,
    wrapKey: null,
    metaKey: null,
    chunkIdx: 0,
    metaSent: false,
    complete: false,
    dc: null,
    bytesSent: 0,
    bytesTotal: (session.files && session.files[0]) ? session.files[0].size : 0,
  };
  upsertPeerProgressRow(peer, "connecting…");

  // Fresh ephemeral X25519 keypair for THIS peer's KEX.
  peer.ephemeral = new window.bitmule.Ephemeral();

  peer.wrpc = createPeer({
    role: "sender",
    ws: session.ws,
    onOpen: async (dc) => {
      peer.dc = dc;
      // If KEX hasn't completed yet, defer meta_enc until it does.
      if (peer.wrapKey && peer.metaKey && !peer.metaSent) {
        await sendMetaAndChunksForPeer(session, peer);
      }
    },
    onMessage: (data) => {
      // Receiver's DC messages arrive here. In the AEAD wire, they're
      // JSON control frames: `request_ranges`, `recv_done`. We ignore
      // request_ranges (we already stream the whole file); we care
      // about recv_done → send done_ack + close.
      if (typeof data !== "string") return;
      let f;
      try { f = JSON.parse(data); } catch { return; }
      if (f.type === "recv_done") {
        try { peer.dc && peer.dc.send(JSON.stringify({ type: "done_ack" })); }
        catch (e) { console.warn("done_ack send failed:", e); }
        peer.complete = true;
        upsertPeerProgressRow(peer, "✓ complete");
        setTimeout(() => removePeerProgressRow(peer.receiverId), 4000);
        session.activeCount = Math.max(0, session.activeCount - 1);
        updateSendCounters();
        try { peer.wrpc.close(); } catch {}
        session.peers.delete(peer.receiverId);
        // Stop-after-first toggle: if on, tear down the whole session
        // once the first peer completes (mirrors CLI Complete mode).
        if (els.stopAfterFirst && els.stopAfterFirst.checked) {
          els.sessionState.textContent = "delivered to first receiver — session closed (stop-after-first on)";
          closeSendSession();
        } else {
          els.sessionState.textContent =
            `delivered to ${session.totalCount - session.activeCount} · active ${session.activeCount}`;
        }
      }
    },
    onState: (s) => {
      if (s === "pc:failed") {
        console.warn(`peer ${peer.receiverId.slice(0,8)}… failed`);
        if (!peer.complete) {
          session.activeCount = Math.max(0, session.activeCount - 1);
          updateSendCounters();
          session.peers.delete(peer.receiverId);
        }
      }
    },
  });

  // Ship our own KexPub immediately, concurrent with SDP exchange.
  const pubBytes = peer.ephemeral.publicBytes();
  const macBytes = session.shareKey.macEphemeralPub(pubBytes);
  wsSendFromSender(session.ws, {
    type: "kex_pub",
    pub_hex: hexEncode(pubBytes),
    mac_hex: hexEncode(macBytes),
  }, receiverId);

  // Handler for the receiver's KexPub arriving via WS. Verifies MAC,
  // derives wrap_key + meta_key, wraps bulk_key + ships key_wrap.
  peer.handleKexPub = async (frame) => {
    if (peer.wrapKey) return; // idempotent
    const peerPub = hexDecode(frame.pub_hex);
    const peerMac = hexDecode(frame.mac_hex);
    if (!peerPub || !peerMac) { console.warn("kex_pub: bad hex"); return; }
    const expectedMac = session.shareKey.macEphemeralPub(peerPub);
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= (expectedMac[i] ^ peerMac[i]);
    if (diff !== 0) {
      console.warn(`kex_pub MAC verify failed for peer ${peer.receiverId.slice(0,8)}`);
      return;
    }
    const sk = peer.ephemeral.deriveSharedSecret(peerPub);
    peer.wrapKey = sk.wrapKey(session.sessionIdBytes);
    peer.metaKey = sk.metaKey(session.sessionIdBytes);
    // Wrap the shared bulk_key under this peer's wrap_key + ship
    // key_wrap over WS so the receiver can decrypt subsequent chunks.
    const wrapped = peer.wrapKey.wrapBulkKey(session.bulkKey);
    wsSendFromSender(session.ws, {
      type: "key_wrap",
      nonce_hex: hexEncode(wrapped.nonce),
      enc_b_hex: hexEncode(wrapped.ct),
    }, peer.receiverId);
    // If DC opened before KEX finished, fire meta_enc + chunks now.
    if (peer.dc && !peer.metaSent) {
      await sendMetaAndChunksForPeer(session, peer);
    }
  };

  // Kick off the SDP offer. createPeer's startOffer handles createOffer
  // + setLocalDescription + ws.send. Offer/answer + ICE will flow
  // through wrpc.handleFrame, and DC-open fires onOpen above.
  peer.wrpc.startOffer().catch((e) => {
    console.warn(`startOffer for ${peer.receiverId.slice(0,8)} failed:`, e);
  });

  session.peers.set(receiverId, peer);
}

// Send a sender-originated frame with envelope `to_receiver_id`
// so the server's per-peer router dispatches it correctly.
function wsSendFromSender(ws, obj, toReceiverId) {
  const withEnv = Object.assign({}, obj, { to_receiver_id: toReceiverId });
  try { ws.send(JSON.stringify(withEnv)); } catch (e) {
    console.warn("ws send failed:", e);
  }
}

// Per-peer meta_enc + AEAD chunk stream. Requires peer.dc open and
// peer.metaKey/bulkKey ready. Idempotent via peer.metaSent flag.
async function sendMetaAndChunksForPeer(session, peer) {
  if (peer.metaSent) return;
  const file = session.files && session.files[0];
  if (!file || !peer.dc) return;
  const chunkBytes = 16 * 1024;
  const totalChunks = file.size === 0 ? 0 : Math.ceil(file.size / chunkBytes);
  // Build MetaFrame JSON, AEAD-encrypt via metaKey with sessionIdBytes AAD.
  const metaPlain = JSON.stringify({
    type: "meta", name: file.name, size: file.size,
    chunkBytes, totalChunks,
  });
  const metaEnc = peer.metaKey.encryptMeta(
    session.sessionIdBytes,
    new TextEncoder().encode(metaPlain),
  );
  peer.dc.send(JSON.stringify({
    type: "meta_enc",
    nonce_hex: hexEncode(metaEnc.nonce),
    ct_hex: hexEncode(metaEnc.ct),
  }));
  peer.metaSent = true;

  // Stream file: slice → encryptChunk(idx, plain) → dc.send(binary).
  // Simple backpressure via bufferedAmount vs 4 MiB high-water.
  const HIGH = 4 * 1024 * 1024;
  const LOW  = 1 * 1024 * 1024;
  const awaitDrain = () => new Promise((resolve) => {
    const check = () => {
      if (peer.dc.bufferedAmount <= LOW) { peer.dc.removeEventListener("bufferedamountlow", check); resolve(); }
    };
    peer.dc.bufferedAmountLowThreshold = LOW;
    peer.dc.addEventListener("bufferedamountlow", check);
  });

  let offset = 0;
  let idx = 0;
  while (offset < file.size) {
    if (session.peers.get(peer.receiverId) !== peer) return; // torn down
    const end = Math.min(offset + chunkBytes, file.size);
    const plain = new Uint8Array(await file.slice(offset, end).arrayBuffer());
    const ct = session.bulkKey.encryptChunk(BigInt(idx), plain);
    while (peer.dc.bufferedAmount > HIGH) await awaitDrain();
    peer.dc.send(ct);
    offset = end;
    idx++;
    // Live progress in the shared session-state line (single-peer
    // view; per-peer progress would need extra UI). Coalesces via
    // the counters block for the multipeer story.
    peer.bytesSent = offset;
    if (idx % 8 === 0) {
      upsertPeerProgressRow(peer);
      const pct = Math.floor((offset / file.size) * 100);
      els.sessionState.textContent =
        `sending to ${peer.receiverId.slice(0,8)}… ${pct}% (${fmtSize(offset)} / ${fmtSize(file.size)})`;
    }
  }
  peer.chunkIdx = idx;
  peer.bytesSent = file.size;
  upsertPeerProgressRow(peer, "delivered, awaiting ack");
  // Chunks done. Receiver will send recv_done on its side once it's
  // decrypted everything, and our onMessage handler above ships
  // done_ack + closes the peer.
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

function startRecvSession(sessionHex, fragment) {
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
  //
  // M2b crypto state — populated only for modern ShareLink URLs when
  // window.bitmule is loaded. Handshake progression:
  //   1. On WS open: send Hello + PeerHello + our own KexPub with MAC.
  //   2. On WS `kex_pub` from sender: verify MAC, derive wrap+meta keys.
  //   3. On WS `key_wrap` from sender: unwrap bulk_key.
  //   4. Once bulkKey + metaKey are ready + DC is open, hand them to
  //      makeReceiver via the `keys` opt so it can decrypt meta_enc +
  //      chunks and emit request_ranges / recv_done on the DC.
  const crypto = (fragment && fragment.kind === "sharelink" && window.bitmule)
    ? {
        shareKey: fragment.shareKey,
        sessionIdBytes: hexDecode(sessionHex),
        ephemeral: new window.bitmule.Ephemeral(),
        wrapKey: null,
        metaKey: null,
        bulkKey: null,
        ownKexPubSent: false,
      }
    : null;

  const session = { sessionHex, receiverId, ws, peer: null, crypto };
  recvSession = session;

  const commonProgress = (received, total, name) => {
    if (recvSession !== session) return;
    const pct = total > 0 ? Math.floor((received / total) * 100) : 0;
    els.recvState.textContent =
      `receiving ${name}: ${pct}% (${fmtSize(received)} / ${fmtSize(total)})`;
  };
  const commonOnFile = (name, blob, size, via) => {
    if (recvSession !== session) return;
    const suffix = via ? ` (via ${via})` : "";
    els.recvState.textContent = `received ${name} (${fmtSize(size)})${suffix}`;
    document.body.dataset.transferStatus = 'complete';
    const url = URL.createObjectURL(blob);
    els.recvDownload.hidden = false;
    els.recvDownload.innerHTML = "";
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.textContent = `Download ${name}`;
    a.className = "pick-btn download-link";
    els.recvDownload.appendChild(a);
    a.click();
  };

  // Keys handed to makeReceiver once KEX + KeyWrap complete. The
  // receiver's onMessage is bound to a mutable holder so it can pick
  // up the keys the moment they land without re-plumbing everything.
  const keysHolder = { metaKey: null, bulkKey: null, sessionIdBytes: null, dc: null };
  const recvOnMessage = makeReceiver({
    onProgress: commonProgress,
    onFile: (n, b, s) => commonOnFile(n, b, s, "WebRTC"),
    keys: crypto ? keysHolder : undefined,
  });

  // Relay-path receiver is created eagerly (cheap) but STAYS SILENT
  // until we decide WebRTC has failed to open. Prevents the receiver
  // from double-consuming a transfer that WebRTC would have handled
  // and cuts unnecessary GETs against the relay server.
  //
  // WebRTC "opened" = onOpen fired. WebRTC "failed" = either the
  // 8s wall-clock timer expires without DC-open, or pc's ICE state
  // transitions to a terminal failure. Only in the failed branch do
  // we start piping relay frames to relayRecv.
  const relayRecv = makeRelayReceiver(sessionHex, {
    onProgress: commonProgress,
    onFile: (n, b, s) => commonOnFile(n, b, s, "relay"),
  });
  session.webrtcOk = false;
  session.webrtcFailed = false;
  session.relayArmed = false; // starts false; flipped when we commit to relay
  // Pre-arm buffer for relay frames — captures meta_relay + any
  // chunk_relay notifications the sender broadcasts before we've
  // committed to the relay path. Replayed on arm so the receiver
  // has the full picture; capped to avoid unbounded growth if the
  // sender streams thousands of chunks pre-arm.
  session.relayPrearmBuffer = [];
  const RELAY_PREARM_CAP = 4096;
  const armRelay = (reason) => {
    if (session.relayArmed || recvSession !== session) return;
    session.relayArmed = true;
    session.webrtcFailed = true;
    console.info(`relay armed (${reason}) — replaying ${session.relayPrearmBuffer.length} buffered frames`);
    // Short, low-drama arm message. commonProgress will replace it
    // with "receiving X: N%" as soon as the first relay chunk lands,
    // so the fallback moment reads as a transient state, not a stuck
    // error page.
    els.recvState.textContent = "using relay fallback…";
    for (const buffered of session.relayPrearmBuffer) {
      try { relayRecv.onWsFrame(buffered); }
      catch (e) { console.warn("relay replay failed:", e); }
    }
    session.relayPrearmBuffer = null;
  };
  // NO timeout. Arm only when we have positive evidence WebRTC failed
  // AND a sender is present on the WS session. Signals we watch:
  //   - server peer_hello with role:"sender" → sender exists.
  //   - ICE connection state transitions to `failed` after WebRTC
  //     negotiation actually started (per W3C spec, `failed` is the
  //     terminal ICE state — no retry from here).
  //   - `disconnected` alone is NOT a failure (ICE can recover). We
  //     don't arm on it; wait for `failed` proper.
  session.senderPresent = false;

  session.peer = createPeer({
    role: "receiver",
    ws,
    onOpen: (dc) => {
      session.webrtcOk = true;
      els.recvState.textContent =
        "direct channel open — ready to receive";
      els.recvState.classList.add("transferring");
      keysHolder.dc = dc;
    },
    onMessage: recvOnMessage,
    onState: (s) => {
      console.info("receiver pc state:", s);
      // ICE `failed` = terminal per spec, retry impossible. Arm relay
      // ONLY if a sender is actually present (otherwise we're just
      // sitting on an empty session with nothing to fail over to).
      // Once webrtcOk is true, ignore state changes — we're mid-transfer.
      if (!session.webrtcOk && session.senderPresent && s === "failed") {
        armRelay(`ICE state: ${s}`);
      }
    },
  });

  ws.addEventListener("open", () => {
    setStatus(els.recvServerStatus, "ok", "connected");
    ws.send(
      JSON.stringify({
        type: "hello",
        role: "receiver",
        receiver_id: receiverId,
        wire_version: 2,
      })
    );
    // The peer_hello triggers the sender to spin up its RTC + send offer.
    ws.send(
      JSON.stringify({ type: "peer_hello", receiver_id: receiverId, wire_version: 2 })
    );
    // M2b: on modern URLs, ship our KexPub immediately — same
    // concurrent-with-SDP flow the native client uses.
    if (crypto) {
      keysHolder.sessionIdBytes = crypto.sessionIdBytes;
      try {
        const pubBytes = crypto.ephemeral.publicBytes();
        const macBytes = crypto.shareKey.macEphemeralPub(pubBytes);
        ws.send(JSON.stringify({
          type: "kex_pub",
          pub_hex: hexEncode(pubBytes),
          mac_hex: hexEncode(macBytes),
        }));
        crypto.ownKexPubSent = true;
      } catch (e) {
        console.warn("KEX pub send failed:", e);
      }
    }
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
    // Server relays this to us when a sender registers on the same
    // session. Marks "peer connected on WS" — the precondition for
    // arming the relay fallback later if ICE ends up in `failed`.
    if (frame.type === "peer_hello" && frame.role === "sender") {
      session.senderPresent = true;
      console.info("sender present on ws session — WebRTC negotiation window open");
    }
    // Server-emitted peer_left when the sender's WS drops. Reflect
    // it in the UI so the receiver doesn't sit at "waiting for
    // sender to negotiate…" forever after the sender has gone away.
    if (frame.type === "peer_left" && frame.role === "sender") {
      session.senderPresent = false;
      console.info("sender left the session");
      if (!recvSession || recvSession !== session) return;
      els.recvState.textContent = "sender disconnected — session idle";
      return;
    }
    if (frame.type === "sdp" || frame.type === "ice") {
      try {
        await session.peer.handleFrame(frame);
      } catch (e) {
        console.warn("recv handleFrame:", e);
      }
      return;
    }
    if (frame.type === "kex_pub" && crypto && !crypto.wrapKey) {
      // Verify sender's ephemeral pub with MAC-under-A, then derive
      // shared secret + wrap/meta keys. Ephemeral.deriveSharedSecret
      // consumes self so the private zeroizes after.
      const peerPub = hexDecode(frame.pub_hex);
      const peerMac = hexDecode(frame.mac_hex);
      if (!peerPub || !peerMac) { console.warn("kex_pub: bad hex"); return; }
      const expectedMac = crypto.shareKey.macEphemeralPub(peerPub);
      // Constant-time-ish compare (JS length is fixed 32 here).
      let diff = 0;
      for (let i = 0; i < 32; i++) diff |= (expectedMac[i] ^ peerMac[i]);
      if (diff !== 0) {
        console.warn("kex_pub: MAC verify failed — sender doesn't know share key");
        return;
      }
      try {
        const sk = crypto.ephemeral.deriveSharedSecret(peerPub);
        crypto.wrapKey = sk.wrapKey(crypto.sessionIdBytes);
        crypto.metaKey = sk.metaKey(crypto.sessionIdBytes);
        keysHolder.metaKey = crypto.metaKey;
      } catch (e) {
        console.warn("KEX derive failed:", e);
      }
      return;
    }
    if (frame.type === "key_wrap" && crypto && crypto.wrapKey && !crypto.bulkKey) {
      const nonce = hexDecode(frame.nonce_hex);
      const ct = hexDecode(frame.enc_b_hex);
      if (!nonce || !ct) { console.warn("key_wrap: bad hex"); return; }
      try {
        crypto.bulkKey = crypto.wrapKey.unwrapBulkKey(nonce, ct);
        keysHolder.bulkKey = crypto.bulkKey;
      } catch (e) {
        console.warn("key_wrap unwrap failed:", e);
      }
      return;
    }
    // Relay-path fallback frames from the sender. Gated on
    // session.relayArmed — until WebRTC has explicitly failed (or the
    // 8s no-open timeout elapsed), we buffer these instead of piping
    // to keep the receiver from double-processing a transfer the
    // direct channel will handle. On arm, the buffer replays into
    // relayRecv so meta_relay + chunk_relay notifications from before
    // the arm decision aren't lost.
    if (frame.type === "meta_relay" || frame.type === "chunk_relay" || frame.type === "relay_done") {
      if (session.relayArmed) {
        relayRecv.onWsFrame(frame);
      } else if (session.relayPrearmBuffer && session.relayPrearmBuffer.length < RELAY_PREARM_CAP) {
        session.relayPrearmBuffer.push(frame);
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
    history.replaceState(null, "", "/");
    applyRoute();
  });
}

// ---- request-files mode (in-page, no URL nav) ---------------------------
//
// User clicks "Request files instead" on the landing page. We generate a
// fresh session id and act as the RECEIVER (same WS role, same DC ondatachannel
// wiring). We render a link `<origin>/send#<hex>` for them to send to the
// person supposed to send files; that person opens the link, lands in
// invited-send mode, and pushes files to us.

let requestSession = null;

function closeRequestSession() {
  if (requestSession) {
    try { requestSession.peer && requestSession.peer.close(); } catch {}
    try { requestSession.ws.close(); } catch {}
    requestSession = null;
  }
}

function startRequestSession() {
  closeRequestSession();
  const sessionHex = randomHex32();
  const link = `${serverHttpBase(CONFIG.server)}/send#${sessionHex}`;

  els.requestLink.value = link;
  renderQrInto(els.requestQr, link);
  els.requestState.textContent = "waiting for sender to open the link…";
  els.requestState.classList.remove("transferring");
  els.requestDownload.hidden = true;
  els.requestDownload.innerHTML = "";

  const receiverId = randomHex32();
  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try { ws = new WebSocket(wsUrl); }
  catch (err) { els.requestState.textContent = `couldn't open socket: ${err.message}`; return; }

  const session = { sessionHex, receiverId, ws, peer: null };
  requestSession = session;

  const commonReqProgress = (received, total, name) => {
    if (requestSession !== session) return;
    const pct = total > 0 ? Math.floor((received / total) * 100) : 0;
    els.requestState.textContent =
      `receiving ${name}: ${pct}% (${fmtSize(received)} / ${fmtSize(total)})`;
  };
  const commonReqOnFile = (name, blob, size, via) => {
    if (requestSession !== session) return;
    const suffix = via ? ` (via ${via})` : "";
    els.requestState.textContent = `received ${name} (${fmtSize(size)})${suffix}`;
    document.body.dataset.transferStatus = 'complete';
    const url = URL.createObjectURL(blob);
    els.requestDownload.hidden = false;
    els.requestDownload.innerHTML = "";
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.textContent = `Download ${name}`;
    a.className = "pick-btn download-link";
    els.requestDownload.appendChild(a);
    a.click();
  };
  const recvOnMessage = makeReceiver({
    onProgress: commonReqProgress,
    onFile: (n, b, s) => commonReqOnFile(n, b, s, "WebRTC"),
  });
  const relayRecv = makeRelayReceiver(sessionHex, {
    onProgress: commonReqProgress,
    onFile: (n, b, s) => commonReqOnFile(n, b, s, "relay"),
  });

  session.peer = createPeer({
    role: "receiver",
    ws,
    onOpen: () => {
      els.requestState.textContent = "direct channel open — ready to receive";
      els.requestState.classList.add("transferring");
    },
    onMessage: recvOnMessage,
    onState: (s) => { console.info("request pc state:", s); },
  });

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "hello", role: "receiver", receiver_id: receiverId, wire_version: 2 }));
    ws.send(JSON.stringify({ type: "peer_hello", receiver_id: receiverId, wire_version: 2 }));
  });

  ws.addEventListener("message", async (ev) => {
    if (requestSession !== session) return;
    let frame;
    try { frame = JSON.parse(ev.data); } catch { return; }
    if (frame.type === "peer_joined" && frame.role === "sender") {
      // The invited sender just connected. Re-emit peer_hello so they
      // pick up on the offer trigger (our earlier peer_hello was sent
      // before they existed and got dropped by the relay).
      try {
        ws.send(JSON.stringify({ type: "peer_hello", receiver_id: receiverId, wire_version: 2 }));
      } catch {}
      return;
    }
    if ((frame.type === "sdp" || frame.type === "ice") && session.peer) {
      try { await session.peer.handleFrame(frame); }
      catch (e) { console.warn("request handleFrame:", e); }
      return;
    }
    if (frame.type === "meta_relay" || frame.type === "chunk_relay" || frame.type === "relay_done") {
      relayRecv.onWsFrame(frame);
    }
  });

  ws.addEventListener("close", () => {
    if (requestSession !== session) return;
    if (!els.requestState.classList.contains("transferring")) {
      els.requestState.textContent = "socket closed";
    }
  });
  ws.addEventListener("error", () => {
    if (requestSession !== session) return;
    els.requestState.textContent = "server unreachable";
  });
}

function wireRequestMode() {
  els.requestFilesBtn.addEventListener("click", () => {
    // Flip in-page from send-mode to request-mode. Doesn't change URL —
    // the shareable URL is embedded in the request panel.
    els.sendMode.hidden = true;
    els.requestMode.hidden = false;
    els.tagline.textContent = "requesting files";
    startRequestSession();
  });
  els.copyRequestLink.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(els.requestLink.value);
      const prev = els.copyRequestLink.textContent;
      els.copyRequestLink.textContent = "Copied";
      setTimeout(() => (els.copyRequestLink.textContent = prev), 1200);
    } catch { els.requestLink.select(); }
  });
  els.requestCancel.addEventListener("click", () => {
    closeRequestSession();
    els.requestMode.hidden = true;
    els.sendMode.hidden = false;
    els.tagline.textContent = "drop files to send";
  });
}

// ---- invited-send mode (URL /send#<hex>) --------------------------------
//
// Someone opened this page via a request-files link. We act as the sender,
// but the session hex is pre-set from the URL (not generated). File pick
// triggers the offer.

let invitedSession = null;

function closeInvitedSession() {
  if (invitedSession) {
    try { invitedSession.peer && invitedSession.peer.close(); } catch {}
    try { invitedSession.ws.close(); } catch {}
    invitedSession = null;
  }
}

function startInvitedSendSession(sessionHex, files) {
  closeInvitedSession();

  els.invitedDropzone.hidden = true;
  els.invitedSession.hidden = false;
  els.invitedSessionState.textContent = "connecting to receiver…";
  els.invitedSessionState.classList.remove("transferring");
  renderQueueInto(els.invitedQueue, files);

  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try { ws = new WebSocket(wsUrl); }
  catch (err) { els.invitedSessionState.textContent = `couldn't open socket: ${err.message}`; return; }

  const session = {
    sessionHex, ws, files, peer: null,
    relayStarted: false, dcOpen: false, fallbackTimer: null,
    relayProgress: { meta: null, sentIdxs: [], done: false },
  };
  invitedSession = session;

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ type: "hello", role: "sender", wire_version: 2 }));
    // Fallback: if the receiver's DC doesn't open within the timeout,
    // upload the file via server relay so the request-mode receiver on
    // the other end can pick it up. Same timer + progressState + resend
    // pattern as the primary send-mode flow.
    session.fallbackTimer = setTimeout(async () => {
      if (invitedSession !== session) return;
      if (session.dcOpen || session.relayStarted) return;
      const file = session.files && session.files[0];
      if (!file) return;
      session.relayStarted = true;
      els.invitedSessionState.textContent =
        `WebRTC not open after ${CONFIG.webrtcTimeoutMs}ms — falling back to server relay…`;
      els.invitedSessionState.classList.add("transferring");
      try {
        await sendFileOverRelay(session.sessionHex, ws, file, {
          onProgress: (sent, total) => {
            if (invitedSession !== session) return;
            const pct = total > 0 ? Math.floor((sent / total) * 100) : 0;
            els.invitedSessionState.textContent =
              `sending via relay ${file.name}: ${pct}% (${fmtSize(sent)} / ${fmtSize(total)})`;
          },
          progressState: session.relayProgress,
        });
        els.invitedSessionState.textContent = `sent (via relay) ${file.name} (${fmtSize(file.size)})`;
        document.body.dataset.transferStatus = 'complete';
        els.invitedCancel.textContent = "Send another";
        els.invitedCancel.classList.add("done");
      } catch (err) {
        els.invitedSessionState.textContent = `relay send failed: ${err.message}`;
      }
    }, CONFIG.webrtcTimeoutMs);
  });

  ws.addEventListener("message", async (ev) => {
    if (invitedSession !== session) return;
    let frame;
    try { frame = JSON.parse(ev.data); } catch { return; }
    if (frame.type === "peer_joined" && frame.role === "receiver") {
      if (session.relayStarted) resendRelayProgress(ws, session.relayProgress);
      return;
    }
    if (frame.type === "peer_hello") {
      els.invitedSessionState.textContent = "receiver joined — negotiating direct connection…";
      els.invitedSessionState.classList.add("transferring");
      if (!session.peer) {
        session.peer = createPeer({
          role: "sender",
          ws,
          onOpen: async (dc) => {
            session.dcOpen = true;
            if (session.fallbackTimer) {
              clearTimeout(session.fallbackTimer);
              session.fallbackTimer = null;
            }
            if (session.relayStarted) {
              console.info("invited DC opened after relay-upload started; skipping DC stream");
              return;
            }
            const file = session.files && session.files[0];
            if (!file) return;
            els.invitedSessionState.textContent = `sending ${file.name}: 0%`;
            try {
              await sendFileOverDC(dc, file, {
                onProgress: (sent, total) => {
                  if (invitedSession !== session) return;
                  const pct = total > 0 ? Math.floor((sent / total) * 100) : 0;
                  els.invitedSessionState.textContent =
                    `sending ${file.name}: ${pct}% (${fmtSize(sent)} / ${fmtSize(total)})`;
                },
              });
              els.invitedSessionState.textContent = `sent ${file.name} (${fmtSize(file.size)})`;
              document.body.dataset.transferStatus = 'complete';
              els.invitedCancel.textContent = "Send another";
              els.invitedCancel.classList.add("done");
            } catch (err) {
              els.invitedSessionState.textContent = `send failed: ${err.message}`;
            }
          },
          onMessage: (data) => { console.info("invited dc msg:", data); },
          onState: (s) => { console.info("invited sender pc state:", s); },
        });
        try { await session.peer.startOffer(); }
        catch (e) { els.invitedSessionState.textContent = `offer failed: ${e.message}`; }
      }
      return;
    }
    if (session.peer && (frame.type === "sdp" || frame.type === "ice")) {
      try { await session.peer.handleFrame(frame); }
      catch (e) { console.warn("invited handleFrame:", e); }
    }
  });

  ws.addEventListener("close", () => {
    if (invitedSession !== session) return;
    if (!els.invitedSessionState.classList.contains("transferring")) {
      els.invitedSessionState.textContent = "socket closed";
    }
  });
  ws.addEventListener("error", () => {
    if (invitedSession !== session) return;
    els.invitedSessionState.textContent = "server unreachable";
  });
}

function renderQueueInto(el, files) {
  el.textContent = "";
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
    el.appendChild(row);
  }
}

function wireInvitedSendMode() {
  els.invitedPickBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    els.invitedFileInput.click();
  });
  els.invitedDropzone.addEventListener("click", () => els.invitedFileInput.click());
  els.invitedDropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      els.invitedFileInput.click();
    }
  });
  els.invitedFileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length) {
      const hex = currentSessionHex();
      if (!hex) return;
      startInvitedSendSession(hex, Array.from(e.target.files));
      e.target.value = "";
    }
  });
  ["dragenter", "dragover"].forEach((ev) => {
    els.invitedDropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      els.invitedDropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((ev) => {
    els.invitedDropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      els.invitedDropzone.classList.remove("dragover");
    });
  });
  els.invitedDropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer?.files;
    if (files && files.length) {
      const hex = currentSessionHex();
      if (!hex) return;
      startInvitedSendSession(hex, Array.from(files));
    }
  });
  els.invitedCancel.addEventListener("click", () => {
    closeInvitedSession();
    els.invitedSession.hidden = true;
    els.invitedDropzone.hidden = false;
    els.invitedQueue.textContent = "";
  });
}

// ---- routing -----------------------------------------------------------

function currentSessionHex() {
  const h = location.hash.replace(/^#/, "");
  return isHex64(h) ? h : null;
}

// Prefers the modern ShareLink shape; falls back to legacy 64-hex.
function currentSessionFragment() {
  return parseSessionFragment(location.hash);
}

function applyRoute() {
  const fragment = currentSessionFragment();
  const hex = fragment ? fragment.sessionHex : null;
  const isSendPath = location.pathname === "/send" || location.pathname === "/send/";

  // Self-download guard: if the fragment matches a session THIS tab is
  // currently serving (as sender OR as request-files receiver-with-URL),
  // don't switch modes. Otherwise the user clicking / pasting their
  // own share URL would tear down the active send and immediately try
  // to download from themselves. No-op the route.
  if (hex) {
    if (sendSession && sendSession.sessionHex === hex) {
      console.info("applyRoute: hash matches active send session — leaving as-is");
      return;
    }
    if (requestSession && requestSession.sessionHex === hex) {
      console.info("applyRoute: hash matches active request session — leaving as-is");
      return;
    }
  }

  // Reset everything
  closeSendSession();
  closeRecvSession();
  closeInvitedSession();
  closeRequestSession();
  hideSessionPanel();
  els.sendMode.hidden = true;
  els.recvMode.hidden = true;
  els.requestMode.hidden = true;
  els.invitedSendMode.hidden = true;
  els.invitedSession.hidden = true;
  els.invitedDropzone.hidden = false;

  if (isSendPath && hex) {
    // Invited-sender mode
    els.invitedSendMode.hidden = false;
    els.tagline.textContent = "someone is waiting for files";
  } else if (hex) {
    // Receive mode
    els.recvMode.hidden = false;
    els.tagline.textContent = "receiving";
    startRecvSession(hex, fragment);
  } else {
    // Landing / send mode
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
    // Re-run routing now that ShareLink parsing is available — if the
    // page loaded with a modern (base64url) hash before wasm was ready,
    // `applyRoute()` treated it as no session and rendered the landing.
    // With `window.bitmule` set, `parseSessionFragment` can now decode
    // the ShareLink; re-apply so we land in receive mode.
    try { applyRoute(); }
    catch (e) { console.warn("post-wasm applyRoute:", e); }
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

// Consume ?debug=interrupt at boot: strip it from the URL and set a
// localStorage flag. The sender reads + clears the flag on next send, so
// the interrupt fires exactly once per URL visit and never on the resume
// that follows.
(function armDebugInterrupt() {
  const params = new URLSearchParams(location.search);
  if (params.get("debug") === "interrupt") {
    try { localStorage.setItem("bitmule.debug.interrupt", "1"); } catch {}
    params.delete("debug");
    const q = params.toString();
    const cleaned = location.pathname + (q ? "?" + q : "") + location.hash;
    history.replaceState(null, "", cleaned);
    console.info("debug=interrupt armed via localStorage; URL cleaned");
  }
})();

wireSendMode();
wireRecvMode();
wireRequestMode();
wireInvitedSendMode();
wireOptions();
window.addEventListener("hashchange", applyRoute);
window.addEventListener("popstate", applyRoute);
applyRoute();

// ---- F00: options menu + persistence -----------------------------------

const OPTIONS_KEY = "bitmule.options.v1";

function loadOptions() {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(OPTIONS_KEY) || "{}"); } catch {}
  const defaults = { multiSend: true, upnp: false, clipboardWatch: false, autoDownload: false };
  return Object.assign(defaults, saved);
}

function saveOptions(opts) {
  try { localStorage.setItem(OPTIONS_KEY, JSON.stringify(opts)); } catch {}
}

function getOptions() {
  // Read live from the DOM inputs so a mid-session toggle applies
  // without re-loading. Falls back to the persisted snapshot if the
  // DOM inputs aren't wired yet.
  if (!els.optMultiSend) return loadOptions();
  return {
    multiSend: !!els.optMultiSend.checked,
    upnp: !!els.optUpnp.checked,
    clipboardWatch: !!els.optClipboardWatch.checked,
    autoDownload: !!els.optAutoDownload.checked,
  };
}

function wireOptions() {
  const opts = loadOptions();
  if (els.optMultiSend) els.optMultiSend.checked = opts.multiSend;
  if (els.optUpnp) els.optUpnp.checked = opts.upnp;
  if (els.optClipboardWatch) els.optClipboardWatch.checked = opts.clipboardWatch;
  if (els.optAutoDownload) els.optAutoDownload.checked = opts.autoDownload;
  // "multi-send by default" flips the stop-after-first default:
  // multi-send on → stop-after-first off, and vice versa.
  if (els.stopAfterFirst) els.stopAfterFirst.checked = !opts.multiSend;

  const persist = () => {
    saveOptions(getOptions());
    // If clipboard-watch flipped, start / stop the poller.
    if (els.optClipboardWatch && els.optClipboardWatch.checked) startClipboardWatcher();
    else stopClipboardWatcher();
  };
  for (const el of [els.optMultiSend, els.optUpnp, els.optClipboardWatch, els.optAutoDownload]) {
    if (el) el.addEventListener("change", persist);
  }
  // Reflect multi-send back onto the stop-after-first checkbox each
  // time it changes, so the two controls stay coherent.
  if (els.optMultiSend && els.stopAfterFirst) {
    els.optMultiSend.addEventListener("change", () => {
      els.stopAfterFirst.checked = !els.optMultiSend.checked;
    });
  }
  if (opts.clipboardWatch) startClipboardWatcher();
}

// ---- F02: clipboard watcher + fetch queue ------------------------------

let clipboardWatchTimer = null;
let lastClipboardText = "";
const fetchQueueLinks = new Map(); // url → { status: "pending"|"downloading"|"done" }

// Prefix check for clipboard-detected links. Per Seb 2026-09-04: only
// accept URLs starting with `https://bitmule.qdat.net/#`. Anything
// else — different origin, http (not https), missing hash — is
// ignored to keep the queue from filling with random hash-shaped URLs.
// parseSessionFragment does the definitive validation on the fragment
// itself; this is just a fast prefilter on the URL.
function isValidBitmuleUrl(text) {
  if (typeof text !== "string") return false;
  const trimmed = text.trim();
  return trimmed.startsWith("https://bitmule.qdat.net/#")
    && trimmed.length > "https://bitmule.qdat.net/#".length;
}

function isOurOwnLink(url) {
  // Ignore any URL for a session THIS tab is currently serving —
  // matches the same-tab self-download guard in applyRoute.
  if (!url) return false;
  const hash = (new URL(url)).hash.replace(/^#/, "");
  const parsed = parseSessionFragment("#" + hash);
  const hex = parsed && parsed.sessionHex;
  if (!hex) return false;
  if (sendSession && sendSession.sessionHex === hex) return true;
  if (requestSession && requestSession.sessionHex === hex) return true;
  return false;
}

function renderFetchQueue() {
  if (!els.fetchQueueList) return;
  els.fetchQueueList.innerHTML = "";
  if (fetchQueueLinks.size === 0) {
    els.fetchQueue.hidden = true;
    return;
  }
  els.fetchQueue.hidden = false;
  for (const [url, state] of fetchQueueLinks) {
    const li = document.createElement("li");
    li.className = "fetch-queue-item";
    const label = document.createElement("span");
    label.className = "fetch-queue-url";
    label.textContent = url;
    li.appendChild(label);
    if (state.status === "pending") {
      const btn = document.createElement("button");
      btn.className = "pick-btn";
      btn.textContent = "Download";
      btn.addEventListener("click", () => triggerFetchDownload(url));
      li.appendChild(btn);
    } else {
      const s = document.createElement("span");
      s.className = "fetch-queue-status";
      s.textContent = state.status;
      li.appendChild(s);
    }
    els.fetchQueueList.appendChild(li);
  }
}

function triggerFetchDownload(url) {
  const state = fetchQueueLinks.get(url);
  if (!state) return;
  state.status = "downloading";
  renderFetchQueue();
  // Route via applyRoute: navigate the tab to the URL. If the user
  // wants multiple concurrent downloads they can open the queue links
  // in new tabs; for now single-tab receive is the simplest surface.
  // For same-origin URLs, use history + hashchange; for cross-origin,
  // open a new tab.
  try {
    const u = new URL(url);
    if (u.origin === location.origin) {
      history.pushState(null, "", u.pathname + u.search + u.hash);
      applyRoute();
    } else {
      window.open(url, "_blank", "noopener,noreferrer");
    }
    state.status = "done";
  } catch (e) {
    console.warn("triggerFetchDownload:", e);
    state.status = "error";
  }
  renderFetchQueue();
}

async function pollClipboardOnce() {
  if (!navigator.clipboard || !navigator.clipboard.readText) return;
  let text;
  try { text = await navigator.clipboard.readText(); }
  catch { return; /* permission denied or not focused */ }
  if (text === lastClipboardText) return;
  lastClipboardText = text;
  if (!isValidBitmuleUrl(text)) return;
  const url = text.trim();
  if (isOurOwnLink(url)) return;
  if (fetchQueueLinks.has(url)) return;
  fetchQueueLinks.set(url, { status: "pending" });
  renderFetchQueue();
  const opts = getOptions();
  if (opts.autoDownload) triggerFetchDownload(url);
}

function startClipboardWatcher() {
  if (clipboardWatchTimer) return;
  clipboardWatchTimer = setInterval(pollClipboardOnce, 1500);
  console.info("clipboard watcher: on");
}
function stopClipboardWatcher() {
  if (!clipboardWatchTimer) return;
  clearInterval(clipboardWatchTimer);
  clipboardWatchTimer = null;
  console.info("clipboard watcher: off");
}
