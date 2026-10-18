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

import * as v2 from "./v2.js";

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

// The URL fragment is either an 86-char base64url share link (share key and
// signature, for a receiver) or a 64-char hex request key (`/send#`, for a
// sender answering a request). Returns null if neither shape matches.
// Parsing a share link needs the wasm module on this thread; until it is
// loaded the result is "sharelink-pending" and the route is applied again
// when it is.
function parseSessionFragment(rawHash) {
  const h = (rawHash || "").replace(/^#/, "");
  if (!h) return null;
  if (isHex64(h)) {
    return { kind: "hex", sessionHex: h, link: null };
  }
  if (/^[A-Za-z0-9_\-=]{80,100}$/.test(h)) {
    if (!window.bitmule || !window.bitmule.ShareLink) {
      return { kind: "sharelink-pending", sessionHex: null, link: null };
    }
    try {
      const link = window.bitmule.ShareLink.fromB64Url(h);
      return { kind: "sharelink", sessionHex: link.sessionIdHex(), link: h };
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
  debugLog: document.getElementById("debug-log"),

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

// On-screen debug log for iOS Safari, which has no accessible console
// without a Mac tether. Keeps the last N lines in a <pre> the user can
// expand from the "Debug log" details block; also mirrors to
// console.log so desktop DevTools shows the same stream.
const DLOG_MAX_LINES = 200;
const dlogBuf = [];
function dlog(...parts) {
  const ts = new Date().toISOString().slice(11, 23);
  const line = `${ts}  ${parts.map((p) =>
    typeof p === "string" ? p : (() => { try { return JSON.stringify(p); } catch { return String(p); } })()
  ).join(" ")}`;
  dlogBuf.push(line);
  if (dlogBuf.length > DLOG_MAX_LINES) dlogBuf.splice(0, dlogBuf.length - DLOG_MAX_LINES);
  if (els.debugLog) {
    els.debugLog.textContent = dlogBuf.join("\n");
    els.debugLog.scrollTop = els.debugLog.scrollHeight;
  }
  try { console.log("[dlog]", ...parts); } catch {}
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
  if (link) renderQr(link);
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

// ---- v2 transfers ------------------------------------------------------
//
// The protocol runs in a worker (v2-worker.js, wasm); v2.js starts it and
// handles WebRTC. This file is UI: it prepares what to send, shows state,
// and offers the received file.

// Several files (or a directory) go as one store-mode zip; a single file as it is.
async function prepareBlob(files, setState) {
  const needBundle = files.length > 1 || (files.length === 1 && !!files[0].webkitRelativePath);
  if (!needBundle) return { blob: files[0], kind: "single", name: files[0].name };
  setState(`bundling ${files.length} file(s) into a zip…`);
  const { blob } = await buildStoreZip(Array.from(files));
  return { blob, kind: "zip", name: "bitmule-files.zip" };
}

function shareUrl(link) {
  return `${serverHttpBase(CONFIG.server)}/#${link}`;
}

function sessionHexOfLink(link) {
  try { return window.bitmule.ShareLink.fromB64Url(link).sessionIdHex(); } catch { return null; }
}

// Offer a received file: a download link (clicked at once), or the bundle
// dialog for zips.
function offerFile(container, file, kind) {
  container.hidden = false;
  container.innerHTML = "";
  if (kind === "zip") {
    presentBundleDialog(file.name, file, container);
    return;
  }
  const url = URL.createObjectURL(file);
  const a = document.createElement("a");
  a.href = url;
  a.download = file.name;
  a.textContent = `Download ${file.name}`;
  a.className = "pick-btn download-link";
  container.appendChild(a);
  a.click();
}

// Receive `link` and report into the elements of `ui`: { state, download }.
function receiveLink(link, ui, isCurrent) {
  return v2.startReceive({
    server: CONFIG.server,
    link,
    on: {
      state: (text) => { if (isCurrent()) ui.state.textContent = text; },
      progress: ({ bytes, total, via }) => {
        if (!isCurrent()) return;
        const pct = total > 0 ? Math.floor((bytes / total) * 100) : 100;
        ui.state.textContent = `receiving (${via}): ${pct}% (${fmtSize(bytes)} / ${fmtSize(total)})`;
        ui.state.classList.add("transferring");
      },
      done: (d) => {
        if (!isCurrent()) return;
        const how = d.directBytes && d.relayBytes ? "relay + direct" : d.directBytes ? "direct" : "relay";
        ui.state.textContent = `received ${d.file.name} (${fmtSize(d.size)}, via ${how})`;
        document.body.dataset.transferStatus = "complete";
        offerFile(ui.download, d.file, d.kind);
      },
      error: (message) => { if (isCurrent()) ui.state.textContent = `failed: ${message}`; },
    },
  });
}

// ---- send mode (state and session panel above) -------------------------

function closeSendSession() {
  if (sendSession) {
    sendSession.job && sendSession.job.cancel();
    sendSession = null;
  }
}

async function startSendSession(files) {
  closeSendSession();
  renderQueue(files);
  if (!files || !files.length) return;

  const session = { job: null, sessionHex: null, seen: new Set() };
  sendSession = session;
  const current = () => sendSession === session;

  showSessionPanel("");
  els.sessionState.textContent = "preparing…";
  let prepared;
  try {
    prepared = await prepareBlob(files, (t) => { if (current()) els.sessionState.textContent = t; });
  } catch (e) {
    if (current()) els.sessionState.textContent = `could not prepare the files: ${e.message || e}`;
    return;
  }
  if (!current()) return;

  session.job = v2.startSend({
    server: CONFIG.server,
    blob: prepared.blob,
    kind: prepared.kind,
    name: prepared.name,
    on: {
      state: (text) => { if (current()) els.sessionState.textContent = text; },
      link: (link) => {
        if (!current()) return;
        session.sessionHex = sessionHexOfLink(link);
        const url = shareUrl(link);
        els.sessionLink.value = url;
        renderQr(url);
      },
      peers: (peers) => {
        if (!current()) return;
        const ids = new Set(peers.map((p) => p.id));
        for (const p of peers) {
          session.seen.add(p.id);
          upsertPeerProgressRow({ receiverId: p.id, bytesSent: p.bytes, bytesTotal: p.total }, p.bytes > 0 ? null : (p.state === "direct" ? "sending (direct)" : p.state));
        }
        for (const id of session.seen) if (!ids.has(id)) removePeerProgressRow(id);
        session.active = peers.length;
        session.total = session.seen.size;
        updateSendCounters();
        if (peers.length) els.sessionState.classList.add("transferring");
      },
      done: ({ receivers }) => {
        if (!current()) return;
        els.sessionState.textContent = `sent (${receivers} receiver${receivers === 1 ? "" : "s"})`;
        document.body.dataset.transferStatus = "complete";
        els.cancelBtn.textContent = "Send another";
        els.cancelBtn.classList.add("done");
      },
      error: (message) => { if (current()) els.sessionState.textContent = `failed: ${message}`; },
    },
  });
}

// ---- receive mode ------------------------------------------------------

let recvSession = null;

function closeRecvSession() {
  if (recvSession) {
    recvSession.job && recvSession.job.cancel();
    recvSession = null;
  }
}

function startRecvSession(sessionHex, fragment) {
  closeRecvSession();
  els.recvSessionId.textContent = sessionHex.slice(0, 8) + "…";
  setStatus(els.recvServerStatus, "pending", "connecting…");
  els.recvState.textContent = "connecting…";
  els.recvState.classList.remove("transferring");
  els.recvDownload.hidden = true;
  const session = { sessionHex, job: null };
  recvSession = session;
  session.job = receiveLink(fragment.link, { state: els.recvState, download: els.recvDownload }, () => recvSession === session);
  setStatus(els.recvServerStatus, "ok", CONFIG.server.replace(/^https?:\/\//, ""));
}

// ---- request-files mode (in-page, no URL nav) ---------------------------
//
// "Request files instead": we make a rendezvous session and show a
// `/send#<key>` link. Whoever opens it sends us a share link through the
// encrypted channel, and we receive that as any other.

let requestSession = null;

function closeRequestSession() {
  if (requestSession) {
    requestSession.job && requestSession.job.cancel();
    requestSession = null;
  }
}

function startRequestSession() {
  closeRequestSession();
  els.requestLink.value = "";
  els.requestQr.innerHTML = "";
  els.requestState.textContent = "connecting…";
  els.requestState.classList.remove("transferring");
  els.requestDownload.hidden = true;
  els.requestDownload.innerHTML = "";

  const session = { sessionHex: null, job: null };
  requestSession = session;
  const current = () => requestSession === session;
  session.job = v2.startRequest({
    server: CONFIG.server,
    on: {
      state: (text) => { if (current()) els.requestState.textContent = text; },
      requestKey: (key) => {
        if (!current()) return;
        session.sessionHex = key;
        const link = `${serverHttpBase(CONFIG.server)}/send#${key}`;
        els.requestLink.value = link;
        renderQrInto(els.requestQr, link);
        els.requestState.textContent = "waiting for sender to open the link…";
      },
      shareLink: (link) => {
        if (!current()) return;
        els.requestState.textContent = "sender found — connecting…";
        session.job = receiveLink(link, { state: els.requestState, download: els.requestDownload }, current);
      },
      error: (message) => { if (current()) els.requestState.textContent = `failed: ${message}`; },
    },
  });
}

// ---- invited-send mode (URL /send#<key>) --------------------------------
//
// Someone opened this page through a request link: they are waiting for our
// files. We make a transfer of our own and hand them its link.

let invitedSession = null;

function closeInvitedSession() {
  if (invitedSession) {
    invitedSession.job && invitedSession.job.cancel();
    invitedSession = null;
  }
}

async function startInvitedSendSession(requestKey, files) {
  closeInvitedSession();
  els.invitedDropzone.hidden = true;
  els.invitedSession.hidden = false;
  els.invitedSessionState.textContent = "preparing…";
  els.invitedSessionState.classList.remove("transferring");
  renderQueueInto(els.invitedQueue, files);

  const session = { job: null };
  invitedSession = session;
  const current = () => invitedSession === session;
  let prepared;
  try {
    prepared = await prepareBlob(files, (t) => { if (current()) els.invitedSessionState.textContent = t; });
  } catch (e) {
    if (current()) els.invitedSessionState.textContent = `could not prepare the files: ${e.message || e}`;
    return;
  }
  if (!current()) return;

  session.job = v2.startSend({
    server: CONFIG.server,
    blob: prepared.blob,
    kind: prepared.kind,
    name: prepared.name,
    requestKey,
    on: {
      state: (text) => { if (current()) els.invitedSessionState.textContent = text; },
      peers: (peers) => {
        if (current() && peers.length) els.invitedSessionState.classList.add("transferring");
      },
      done: () => {
        if (!current()) return;
        els.invitedSessionState.textContent = "sent";
        document.body.dataset.transferStatus = "complete";
        els.invitedCancel.textContent = "Send another";
        els.invitedCancel.classList.add("done");
      },
      error: (message) => { if (current()) els.invitedSessionState.textContent = `failed: ${message}`; },
    },
  });
}

function updateSendCounters() {
  if (!sendSession) return;
  if (els.sessionActiveCount) els.sessionActiveCount.textContent = String(sendSession.active || 0);
  if (els.sessionTotalCount) els.sessionTotalCount.textContent = String(sendSession.total || 0);
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
  els.dropzone.addEventListener("drop", async (e) => {
    if (!e.dataTransfer) return;
    const files = await flattenDroppedItems(e.dataTransfer);
    if (files.length) startSendSession(files);
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

function wireRecvMode() {
  els.recvCancel.addEventListener("click", () => {
    closeRecvSession();
    history.replaceState(null, "", "/");
    applyRoute();
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
  els.invitedDropzone.addEventListener("drop", async (e) => {
    if (!e.dataTransfer) return;
    const files = await flattenDroppedItems(e.dataTransfer);
    if (files.length) {
      const hex = currentSessionHex();
      if (!hex) return;
      startInvitedSendSession(hex, files);
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
  } else if (fragment && fragment.kind === "sharelink") {
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

// ============================================================
// F5 — drag-drop folder walker.
//
// `DataTransfer.files` on a folder-drop hands back a File whose
// `.arrayBuffer()` throws NotFoundError — the entry is a directory
// pseudo-file, not a real file. To handle a folder drop we have
// to walk via `DataTransferItem.webkitGetAsEntry()` and resolve
// each FileSystemFileEntry through `.file(cb)`. We tag each
// resulting File with `webkitRelativePath` (via a Proxy since the
// property is normally read-only on File) so the zip writer
// preserves the drop-root name at the top of the archive.
// ============================================================

async function readDirEntries(dirReader) {
  // readEntries only returns a batch at a time (typically ~100);
  // keep reading until it returns empty.
  const all = [];
  while (true) {
    const batch = await new Promise((resolve, reject) =>
      dirReader.readEntries(resolve, reject));
    if (!batch.length) return all;
    all.push(...batch);
  }
}

async function walkEntry(entry, prefix, out) {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) =>
      entry.file(resolve, reject));
    const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
    // File's webkitRelativePath is read-only in the platform. Wrap
    // in a Proxy so downstream code reading .webkitRelativePath
    // sees our path without touching the real prototype.
    out.push(new Proxy(file, {
      get(target, prop) {
        if (prop === "webkitRelativePath") return relPath;
        const v = target[prop];
        return typeof v === "function" ? v.bind(target) : v;
      }
    }));
    return;
  }
  if (entry.isDirectory) {
    const reader = entry.createReader();
    const children = await readDirEntries(reader);
    const nextPrefix = prefix ? `${prefix}/${entry.name}` : entry.name;
    for (const child of children) await walkEntry(child, nextPrefix, out);
  }
}

// Flatten a drop event's dataTransfer.items into a flat Array<File>.
// Handles a mix of file + folder drops. Folders expand recursively
// and every descendant file's webkitRelativePath preserves the tree
// shape (with the drop-root dir name at the top).
async function flattenDroppedItems(dataTransfer) {
  const items = dataTransfer.items;
  if (!items || !items.length) {
    // Fallback: no items list — use the raw files (single-file drops).
    return Array.from(dataTransfer.files || []);
  }
  const entries = [];
  for (const item of items) {
    if (item.kind !== "file") continue;
    // Prefer webkitGetAsEntry (returns FileSystemEntry supporting
    // directory walk); fall back to getAsFile() if the browser
    // doesn't implement the entry API.
    const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
    if (entry) {
      entries.push(entry);
    } else {
      const f = item.getAsFile();
      if (f) entries.push({ __rawFile: f });
    }
  }
  const out = [];
  for (const entry of entries) {
    if (entry.__rawFile) { out.push(entry.__rawFile); continue; }
    await walkEntry(entry, "", out);
  }
  return out;
}

// ============================================================
// F5 — store-mode ZIP writer + reader.
//
// The wire's `container: "zip-store"` meta flag says "the payload
// is a level-0 zip of the sender's picked files; the receiver may
// unpack it." We handwrite the writer + reader here rather than
// pull a library because store-mode is only ~80 lines of JS and
// avoids a vendored dep. Deflate isn't needed — bitmule already
// zstd-encrypts on the wire, so layering compression here would
// waste CPU on ciphertext.
// ============================================================

// CRC32 IEEE polynomial (0xEDB88320 reversed). Precompute once.
const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32Bytes(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC32_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// Build a store-mode (compression method 0) zip Blob from an array
// of Files. Filenames land under each File's `webkitRelativePath`
// when available (so a `webkitdirectory` dir pick preserves tree
// shape), else just the file name. Returns { blob, displayName }.
async function buildStoreZip(files) {
  const encoder = new TextEncoder();
  const parts = [];            // Blob parts for the zip (LFH + data ... + CD ... + EOCD)
  const cdEntries = [];        // { nameBytes, crc, size, headerOffset }
  let offset = 0;

  for (const file of files) {
    const rawName = (file.webkitRelativePath && file.webkitRelativePath.length)
      ? file.webkitRelativePath
      : (file.name || "file.bin");
    // Zip spec uses forward slashes; belt-and-braces normalization.
    const name = rawName.replaceAll("\\", "/");
    const nameBytes = encoder.encode(name);
    const data = new Uint8Array(await file.arrayBuffer());
    const crc = crc32Bytes(data);
    const size = data.length;

    // Local File Header — 30 bytes fixed + name + no extra.
    const lfh = new Uint8Array(30 + nameBytes.length);
    const dv = new DataView(lfh.buffer);
    dv.setUint32(0, 0x04034b50, true);   // signature
    dv.setUint16(4, 20, true);           // version needed
    dv.setUint16(6, 0, true);            // general purpose flags
    dv.setUint16(8, 0, true);            // compression method (Stored)
    dv.setUint16(10, 0, true);           // mod time (unused)
    dv.setUint16(12, 0, true);           // mod date (unused)
    dv.setUint32(14, crc, true);
    dv.setUint32(18, size, true);        // compressed size == uncompressed for Stored
    dv.setUint32(22, size, true);
    dv.setUint16(26, nameBytes.length, true);
    dv.setUint16(28, 0, true);           // extra length
    lfh.set(nameBytes, 30);

    parts.push(lfh, data);
    cdEntries.push({ nameBytes, crc, size, headerOffset: offset });
    offset += lfh.length + data.length;
  }

  // Central Directory — 46 bytes fixed per entry + name.
  const cdStart = offset;
  for (const e of cdEntries) {
    const cd = new Uint8Array(46 + e.nameBytes.length);
    const dv = new DataView(cd.buffer);
    dv.setUint32(0, 0x02014b50, true);
    dv.setUint16(4, 20, true);           // version made by
    dv.setUint16(6, 20, true);           // version needed
    dv.setUint16(8, 0, true);            // flags
    dv.setUint16(10, 0, true);           // method
    dv.setUint16(12, 0, true);
    dv.setUint16(14, 0, true);
    dv.setUint32(16, e.crc, true);
    dv.setUint32(20, e.size, true);
    dv.setUint32(24, e.size, true);
    dv.setUint16(28, e.nameBytes.length, true);
    dv.setUint16(30, 0, true);           // extra length
    dv.setUint16(32, 0, true);           // comment length
    dv.setUint16(34, 0, true);           // disk number
    dv.setUint16(36, 0, true);           // internal attrs
    dv.setUint32(38, 0, true);           // external attrs
    dv.setUint32(42, e.headerOffset, true);
    cd.set(e.nameBytes, 46);
    parts.push(cd);
    offset += cd.length;
  }
  const cdSize = offset - cdStart;

  // End of Central Directory record.
  const eocd = new Uint8Array(22);
  const dv = new DataView(eocd.buffer);
  dv.setUint32(0, 0x06054b50, true);
  dv.setUint16(4, 0, true);              // disk num
  dv.setUint16(6, 0, true);              // disk with cd
  dv.setUint16(8, cdEntries.length, true);
  dv.setUint16(10, cdEntries.length, true);
  dv.setUint32(12, cdSize, true);
  dv.setUint32(16, cdStart, true);
  dv.setUint16(20, 0, true);             // comment length
  parts.push(eocd);

  const blob = new Blob(parts, { type: "application/zip" });
  // Pick a display name: single-dir pick uses the tree root; else
  // first stem + "and N more". Falls back to "bundle.zip".
  let displayName = "bundle.zip";
  const first = files[0];
  if (files.length === 1) {
    const base = (first.name || "bundle").replace(/\.[^.]+$/, "");
    displayName = `${base}.zip`;
  } else if (files.length > 1 && first && first.webkitRelativePath) {
    const root = first.webkitRelativePath.split("/")[0];
    if (root) displayName = `${root}.zip`;
  }
  if (displayName === "bundle.zip" && files.length > 1) {
    const stem = (files[0].name || "bundle").replace(/\.[^.]+$/, "");
    displayName = `${stem}-and-${files.length - 1}-more.zip`;
  }
  return { blob, displayName };
}

// Parse a store-mode zip Blob and return an array of entries.
// Each entry: { name, blob, size, crcOk }. Only method=0 (Stored)
// is supported — the sender-side builder emits Stored exclusively.
// Reads the entries of a zip: stored, deflated, or zstd compressed (what the
// CLI's zips use; the zstd decoder is in the wasm module).
async function parseZip(zipBlob) {
  const totalSize = zipBlob.size;
  // Read the last 22..(22+65k) bytes to find the EOCD signature.
  // Zip comment can be up to 65535 bytes; we cap the search at 66 KiB.
  const tailStart = Math.max(0, totalSize - (22 + 65536));
  const tailBuf = await zipBlob.slice(tailStart, totalSize).arrayBuffer();
  const tail = new Uint8Array(tailBuf);
  let eocdOffset = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail[i] === 0x50 && tail[i+1] === 0x4b && tail[i+2] === 0x05 && tail[i+3] === 0x06) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) throw new Error("EOCD not found — not a valid zip");
  const eocdDv = new DataView(tail.buffer, tail.byteOffset + eocdOffset);
  let cdEntries = eocdDv.getUint16(10, true);
  let cdSize = eocdDv.getUint32(12, true);
  let cdOffset = eocdDv.getUint32(16, true);
  // ZIP64 (what the CLI writes): the real values are in the zip64 end of
  // central directory record, found through the locator just before the EOCD.
  if (cdEntries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const locatorAt = tailStart + eocdOffset - 20;
    const locator = new DataView(await zipBlob.slice(locatorAt, locatorAt + 20).arrayBuffer());
    if (locatorAt < 0 || locator.getUint32(0, true) !== 0x07064b50) throw new Error("zip64 locator not found");
    const recordAt = Number(locator.getBigUint64(8, true));
    const record = new DataView(await zipBlob.slice(recordAt, recordAt + 56).arrayBuffer());
    if (record.getUint32(0, true) !== 0x06064b50) throw new Error("zip64 end of central directory not found");
    cdEntries = Number(record.getBigUint64(32, true));
    cdSize = Number(record.getBigUint64(40, true));
    cdOffset = Number(record.getBigUint64(48, true));
  }

  const cdBuf = await zipBlob.slice(cdOffset, cdOffset + cdSize).arrayBuffer();
  const cd = new Uint8Array(cdBuf);
  const decoder = new TextDecoder();

  const entries = [];
  let p = 0;
  for (let i = 0; i < cdEntries; i++) {
    const dv = new DataView(cd.buffer, cd.byteOffset + p);
    if (dv.getUint32(0, true) !== 0x02014b50) throw new Error(`bad CD entry #${i}`);
    const method = dv.getUint16(10, true);
    const declaredCrc = dv.getUint32(16, true);
    let compSize = dv.getUint32(20, true);
    let uncompSize = dv.getUint32(24, true);
    const nameLen = dv.getUint16(28, true);
    const extraLen = dv.getUint16(30, true);
    const commentLen = dv.getUint16(32, true);
    let headerOffset = dv.getUint32(42, true);
    const name = decoder.decode(cd.subarray(p + 46, p + 46 + nameLen));
    // ZIP64 extra field (id 1): holds, in this order, the values that did not fit in 32 bits
    for (let e = p + 46 + nameLen, end = e + extraLen; e + 4 <= end;) {
      const id = dv.getUint16(e - p, true);
      const size = dv.getUint16(e - p + 2, true);
      if (id === 1) {
        let at = e - p + 4;
        const next = () => { const v = Number(dv.getBigUint64(at, true)); at += 8; return v; };
        if (uncompSize === 0xffffffff) uncompSize = next();
        if (compSize === 0xffffffff) compSize = next();
        if (headerOffset === 0xffffffff) headerOffset = next();
      }
      e += 4 + size;
    }
    p += 46 + nameLen + extraLen + commentLen;

    if (method !== 0 && method !== 8 && method !== 93) {
      throw new Error(`entry ${name}: compression method ${method} is not supported (stored, deflate and zstd are)`);
    }
    if (method === 93 && !(window.bitmule && window.bitmule.zstdDecompress)) {
      throw new Error(`entry ${name}: zstd needs the wasm module, which is not loaded`);
    }
    // Read the LFH to find the actual data start (LFH's own name+extra
    // may differ from CD's).
    const lfhFixedBuf = await zipBlob.slice(headerOffset, headerOffset + 30).arrayBuffer();
    const lfhDv = new DataView(lfhFixedBuf);
    if (lfhDv.getUint32(0, true) !== 0x04034b50) throw new Error(`entry ${name}: bad LFH`);
    const lfhNameLen = lfhDv.getUint16(26, true);
    const lfhExtraLen = lfhDv.getUint16(28, true);
    const dataStart = headerOffset + 30 + lfhNameLen + lfhExtraLen;
    const dataEnd = dataStart + compSize;
    // Skip directory entries (name ends with "/" and size 0).
    if (uncompSize === 0 && name.endsWith("/")) continue;
    let entryBlob = zipBlob.slice(dataStart, dataEnd);
    if (method === 93) {
      entryBlob = new Blob([window.bitmule.zstdDecompress(new Uint8Array(await entryBlob.arrayBuffer()))]);
    } else if (method === 8) {
      entryBlob = await new Response(entryBlob.stream().pipeThrough(new DecompressionStream("deflate-raw"))).blob();
    }
    // Best-effort CRC check for entries small enough to buffer.
    let crcOk = true;
    if (uncompSize <= 4 * 1024 * 1024) {
      const bytes = new Uint8Array(await entryBlob.arrayBuffer());
      crcOk = crc32Bytes(bytes) === declaredCrc;
    }
    entries.push({ name, blob: entryBlob, size: uncompSize, crcOk });
  }
  return entries;
}

// Trigger a browser download for a Blob under a specific name.
function downloadBlobAs(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on next tick — some browsers race the click otherwise.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Render the F5 receiver dialog for a container="zip-store" bundle.
// Two actions:
//   - "Download bundle" downloads the raw zip as-is
//   - "Extract & save individually" parses the zip client-side and
//     drops per-entry download links into a list the user can grab.
async function presentBundleDialog(name, blob, containerEl) {
  containerEl.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.className = "bundle-dialog";

  const heading = document.createElement("p");
  heading.className = "bundle-heading";
  heading.textContent = `Received ${name} — how would you like it?`;
  wrap.appendChild(heading);

  const row = document.createElement("div");
  row.className = "bundle-actions";
  const dlZipBtn = document.createElement("button");
  dlZipBtn.className = "pick-btn";
  dlZipBtn.type = "button";
  dlZipBtn.textContent = "Download bundle";
  dlZipBtn.addEventListener("click", () => downloadBlobAs(blob, name));

  const extractBtn = document.createElement("button");
  extractBtn.className = "pick-btn secondary";
  extractBtn.type = "button";
  extractBtn.textContent = "Extract & save individually";

  const list = document.createElement("div");
  list.className = "bundle-list";
  list.hidden = true;

  extractBtn.addEventListener("click", async () => {
    extractBtn.disabled = true;
    extractBtn.textContent = "Extracting…";
    try {
      const entries = await parseZip(blob);
      list.innerHTML = "";
      for (const entry of entries) {
        const link = document.createElement("a");
        link.className = "download-link";
        link.href = URL.createObjectURL(entry.blob);
        link.download = entry.name.split("/").pop() || entry.name;
        link.textContent = `${entry.name}${entry.crcOk ? "" : " (CRC mismatch)"} — ${fmtSize(entry.size)}`;
        list.appendChild(link);
      }
      list.hidden = false;
      extractBtn.textContent = `Extracted ${entries.length} file(s)`;
    } catch (e) {
      extractBtn.disabled = false;
      extractBtn.textContent = "Extract failed — retry";
      const err = document.createElement("p");
      err.className = "bundle-error";
      err.textContent = `unpack: ${e.message}`;
      wrap.appendChild(err);
    }
  });

  row.appendChild(dlZipBtn);
  row.appendChild(extractBtn);
  wrap.appendChild(row);
  wrap.appendChild(list);
  containerEl.hidden = false;
  containerEl.appendChild(wrap);
}