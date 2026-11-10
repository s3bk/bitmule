// bitmule v2 transfer worker.
//
// One job per worker, and the worker is shared: the page reaches it through a
// `SharedWorker` named after the transfer, so a reload — or that tab closed and
// another opened — finds the same job still running instead of starting over.
// A shared worker ends when the last page holding it goes away; what it was
// doing is a journal in OPFS (opfs.js), and the worker that comes next picks it
// up from there.
//
// The protocol lives in the wasm module (the Rust the CLI uses); this file does
// the I/O around it: the signaling websocket, the relay's HTTP streams, reading
// and storing the file. Everything heavy (proof of work, fountain coding,
// hashing) runs here, off the UI thread.
//
// WebRTC stays on the page (RTCPeerConnection is not in workers everywhere):
// the page reports the data channel's events and this worker tells it what to
// send. Messages, page -> worker:
//   {type: "start", job: "send" | "receive" | "request", jobId, server, caps, ...}
//   {type: "resume", jobId}     take the job back: from here, or from the journal
//   {type: "cancel"}
//   {type: "rtcSignal", peer, message}      SDP produced by the page's peer connection
//   {type: "dcOpen" | "dcClosed", peer}
//   {type: "dcMessage", peer, data}         one data channel message (ArrayBuffer)
//   {type: "dcDrained", peer, bytes}        bytes the page has handed to the channel so far
// worker -> page:
//   {type: "hello", job, id}    on connect: what this worker is holding, if anything
//   {type: "state", text}   {type: "link", link}   {type: "requestKey", key}
//   {type: "shareLink", link}  {type: "peers", peers}
//   {type: "progress", bytes, total, via}
//   {type: "rtcStart", peer, role}   {type: "rtcSignal", peer, message}   {type: "rtcClose", peer}
//   {type: "dcSend", peer, data}
//   {type: "done", ...}   {type: "error", message}

import { Journal, Spool, Store, RECV_PREFIX } from "./opfs.js";

// Loaded once, lazily: a worker that only has a journal to hand back does not
// need the protocol, and a build without the wasm bundle still starts instead
// of failing at import time.
let wasm = null;
let wasmError = null;
const READY = import("./wasm/pkg/bitmule_client_wasm.js")
  .then((module) => module.default().then(() => module))
  .then((module) => { wasm = module; return module; })
  .catch((err) => { wasmError = err; return null; });

/// The protocol, or an error explaining why there is none.
async function protocol() {
  await READY;
  if (!wasm) {
    const why = (wasmError && (wasmError.message || wasmError)) || "not built";
    throw new Error(`the wasm bundle is not available (${why})`);
  }
  return wasm;
}

// What the data channel and the relay carry per message / request.
const PIECE = 16 * 1024;
const DC_WINDOW = 8 * 1024 * 1024;
const UPLOAD_BATCH = 4 * 1024 * 1024;
const HASH_SLICE = 4 * 1024 * 1024;
const WS_FLUSH_MS = 4000;

// The page watching this job. A reload replaces it; posting to nobody is fine.
let port = null;
const post = (message, transfer) => { if (port) port.postMessage(message, transfer || []); };
const state = (text) => post({ type: "state", text });

const httpBase = (server) => server.replace(/\/$/, "");
const wsBase = (server) => httpBase(server).replace(/^http/, "ws");

class Cancelled extends Error {}

// ---- what a resumed job needs to know ------------------------------------

/// The blocks already on disk, as a bitstring: one bit per block, 1 = held.
function encodeHave(have, blocks) {
  const bytes = new Uint8Array(Math.ceil(blocks / 8));
  for (const b of have) if (b >= 0 && b < blocks) bytes[b >> 3] |= 1 << (b & 7);
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

function decodeHave(text, blocks) {
  const have = new Set();
  if (!text) return have;
  let bin;
  try { bin = atob(text); } catch { return have; }
  for (let i = 0; i < bin.length; i++) {
    const byte = bin.charCodeAt(i);
    if (!byte) continue;
    for (let bit = 0; bit < 8; bit++) {
      const b = i * 8 + bit;
      if (byte & (1 << bit) && b < blocks) have.add(b);
    }
  }
  return have;
}

/// The bytes the held blocks hold, so progress does not jump back on a resume.
function heldBytes(have, blockSize, size) {
  let bytes = 0;
  for (const b of have) bytes += Math.min(blockSize, size - b * blockSize);
  return bytes;
}

// ---- websocket + session -----------------------------------------------

/// Proof of work, in slices so a cancel gets through.
async function solvePow(session, magic, difficulty, isCancelled) {
  const STEP = 100_000;
  for (let start = 0; ; start += STEP) {
    if (isCancelled()) throw new Cancelled();
    const nonce = session.powStep(magic, difficulty, start, STEP);
    if (nonce !== undefined) return nonce;
    await new Promise((r) => setTimeout(r, 0));
  }
}

/// A session on the signaling server: the wasm `Session`, its websocket, and
/// the events it produces.
class Link {
  constructor(server, session, onEvent) {
    this.server = server;
    this.session = session;
    this.onEvent = onEvent;
    this.sock = null;
    this.closed = false;
    this.relayToken = null;
  }

  async open() {
    const { server, session } = this;
    const sid = session.sessionIdHex();
    let url;
    if (session.isCreator()) {
      const challenge = await (await fetch(`${httpBase(server)}/pow`)).json();
      const nonce = await solvePow(session, challenge.magic, challenge.difficulty, () => this.closed);
      url = `${wsBase(server)}/ws/create?sid=${sid}&magic=${challenge.magic}&pow=${nonce}&enablePing=1`;
    } else {
      url = `${wsBase(server)}/ws/join?sid=${sid}&enablePing=1`;
    }
    const sock = new WebSocket(url);
    sock.binaryType = "arraybuffer";
    await new Promise((resolve, reject) => {
      sock.onopen = resolve;
      sock.onerror = () => reject(new Error("could not reach the server"));
    });
    this.sock = sock;
    sock.onmessage = (e) => {
      if (typeof e.data === "string") return;
      try {
        for (const event of session.onServer(new Uint8Array(e.data))) {
          if (event.kind === "out") sock.send(event.bytes);
          else this.onEvent(event);
        }
      } catch (err) {
        this.onEvent({ kind: "error", message: String(err.message || err) });
      }
    };
    sock.onclose = () => {
      if (!this.closed) this.onEvent({ kind: "closed" });
    };
    sock.send(session.hello());
  }

  sendPeer(peer, message) {
    this.sock.send(this.session.send(peer, message));
  }

  /// Close once what was written has gone out.
  async close() {
    if (this.closed) return;
    const sock = this.sock;
    if (sock && sock.readyState === WebSocket.OPEN) {
      const until = Date.now() + WS_FLUSH_MS;
      while (sock.bufferedAmount > 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
    }
    this.closed = true;
    try { sock && sock.close(); } catch {}
  }
}

// ---- file storage --------------------------------------------------------
//
// Store and Spool live in opfs.js: the file a job is assembling, and the spool
// of bytes whose length is not known yet, are both opened by name so that a
// worker that comes later can carry on with what is already on disk.

// ---- the data channel protocol ------------------------------------------
// Get: 1 | start u64 LE | end u64 LE        Data: 2 | offset u64 LE | bytes

function encodeGet(start, end) {
  const m = new DataView(new ArrayBuffer(17));
  m.setUint8(0, 1);
  m.setBigUint64(1, BigInt(start), true);
  m.setBigUint64(9, BigInt(end), true);
  return m.buffer;
}

function decodeDc(buffer) {
  const view = new DataView(buffer);
  if (buffer.byteLength < 9) throw new Error("short data channel message");
  const tag = view.getUint8(0);
  const number = (at) => Number(view.getBigUint64(at, true));
  if (tag === 1 && buffer.byteLength === 17) return { type: "Get", start: number(1), end: number(9) };
  if (tag === 2) return { type: "Data", offset: number(1), bytes: new Uint8Array(buffer, 9) };
  throw new Error(`bad data channel message ${tag}`);
}

function dataMessage(offset, bytes) {
  const m = new Uint8Array(9 + bytes.length);
  const view = new DataView(m.buffer);
  m[0] = 2;
  view.setBigUint64(1, BigInt(offset), true);
  m.set(bytes, 9);
  return m.buffer;
}

// ---- sending -------------------------------------------------------------

async function hashBlob(transfer, blob, isCancelled) {
  for (let at = 0; at < blob.size; at += HASH_SLICE) {
    if (isCancelled()) throw new Cancelled();
    transfer.update(new Uint8Array(await blob.slice(at, at + HASH_SLICE).arrayBuffer()));
    if (at % (64 * HASH_SLICE) === 0) state(`reading ${Math.floor((at / blob.size) * 100)}%`);
  }
}

class Sender {
  constructor(opts) {
    this.kind = "send";
    this.opts = opts;
    this.blob = opts.blob;
    this.peers = new Map();
    this.completed = 0;
    this.relayAbort = null;
    this.relayStarted = false;
    this.cancelled = false;
    this.finished = false;
  }

  async run() {
    const { opts } = this;
    this.id = opts.id || crypto.randomUUID();
    // A send keeps a journal too, but only so the page can tell that a transfer
    // was in flight: the share key that is the room lives in this worker, and a
    // worker that is gone cannot put a sender back into its room. (A receive
    // can: the link is in its journal and the sender is still there.)
    this.journal = await Journal.create(this.id, {
      kind: "send",
      server: opts.server,
      name: opts.name || null,
      fileKind: opts.kind,
      size: opts.blob ? opts.blob.size : opts.size || 0,
      phase: "starting",
    });
    await protocol();
    const transfer = new wasm.Transfer(opts.kind, opts.name || undefined);
    // streaming: the data goes first, only the link is made up front; the size
    // and the checksum follow the data (the manifest comes last)
    this.streaming = !!(opts.stream || opts.streaming || opts.restartable);
    this.session = wasm.Session.create(opts.caps);
    if (this.streaming) {
      this.size = this.blob ? this.blob.size : (opts.size || 0);
      this.session.setStreamingTransfer(transfer);
    } else {
      state("reading the file…");
      await hashBlob(transfer, this.blob, () => this.cancelled);
      transfer.finish();
      this.size = this.blob.size;
      this.session.setTransfer(transfer);
    }
    this.done = new Promise((resolve, reject) => { this.finish = resolve; this.fail = reject; });
    this.link = new Link(opts.server, this.session, (e) => this.onEvent(e));
    state("connecting…");
    await this.link.open();
    return this.done;
  }

  async onEvent(event) {
    try {
      await this.handle(event);
    } catch (e) {
      this.fail(e);
    }
  }

  publishPeers() {
    post({ type: "peers", peers: [...this.peers].map(([id, p]) => ({ id, state: p.state, via: p.via, bytes: p.bytes || 0, total: this.size })) });
  }

  async handle(event) {
    const { session, link } = this;
    switch (event.kind) {
      case "created": {
        link.relayToken = event.relayToken;
        const text = session.linkB64();
        this.linkText = text;
        this.journal.set({ link: text, phase: "waiting" }).flush();
        post({ type: "link", link: text });
        state("waiting for a receiver…");
        if (this.opts.requestKey) this.deliverToRequest(text).catch((e) => this.fail(e));
        break;
      }
      case "peerJoined":
        this.peers.set(event.id, { caps: event.caps, state: "connecting", dc: null, ranges: [], serving: false, drained: 0, sent: 0 });
        this.publishPeers();
        break;
      case "peerReady": {
        const peer = this.peers.get(event.id);
        if (!peer) break;
        peer.state = "ready";
        if (this.streaming) {
          // the data starts now; the manifest follows it
          if (!(this.opts.caps & wasm.CAP_RELAY()) || !(peer.caps & wasm.CAP_RELAY())) {
            state("a receiver without the relay cannot take a streaming transfer");
            this.dropPeer(event.id);
            break;
          }
          link.sendPeer(event.id, { type: "JoinRelay" });
          this.startStreamRelay();
          if (this.checksum) this.announceTo(event.id);
        } else {
          link.sendPeer(event.id, { type: "Manifest" });
        }
        this.publishPeers();
        break;
      }
      case "message":
        await this.onMessage(event.from, event.message);
        break;
      case "peerLeft":
        this.dropPeer(event.id);
        break;
      case "text":
        state(`server: ${event.text}`);
        break;
      case "error":
        this.fail(new Error(event.message));
        break;
      case "closed":
        if (!this.finished) this.fail(new Error("connection to the server closed"));
        break;
    }
  }

  dropPeer(id) {
    const peer = this.peers.get(id);
    if (!peer) return;
    this.peers.delete(id);
    this.session.forget(id);
    post({ type: "rtcClose", peer: id });
    this.publishPeers();
    this.checkFinished();
  }

  checkFinished() {
    if (this.peers.size === 0 && this.completed > 0 && !this.finished) {
      this.finished = true;
      this.stopRelay();
      if (this.spool) this.spool.discard();
      this.journal.remove();
      this.link.close().then(() => this.finish({ type: "sent", receivers: this.completed }));
    }
  }

  /// A page came back to this job (a reload, or another tab): the peer
  /// connections it held are gone, so fall back to what this worker owns — the
  /// signaling socket and the relay — and show it where things stand.
  reattached() {
    for (const [id, peer] of this.peers) {
      if (peer.dc) {
        peer.dc = false;
        peer.ranges = [];
        peer.wake && peer.wake();
      }
      post({ type: "rtcClose", peer: id });
    }
    if (this.linkText) post({ type: "link", link: this.linkText });
    this.publishPeers();
    state(this.finished ? "transfer finished" : "page reloaded — the transfer carried on");
  }

  async onMessage(from, message) {
    const peer = this.peers.get(from);
    if (!peer) return;
    const { opts, link } = this;
    switch (message.type) {
      case "Get": {
        const whole = message.start === 0 && message.end === this.size && this.size > 0;
        if (whole) {
          const relayOffered = !!(opts.caps & wasm.CAP_RELAY()) && !!(peer.caps & wasm.CAP_RELAY());
          const rtcOffered = !!(opts.caps & wasm.CAP_WEBRTC()) && !!(peer.caps & wasm.CAP_WEBRTC());
          peer.relayOffered = relayOffered;
          if (relayOffered) {
            link.sendPeer(from, { type: "JoinRelay" });
            this.startRelay();
          }
          if (rtcOffered && !peer.rtc) {
            peer.rtc = true;
            post({ type: "rtcStart", peer: from, role: "offerer" });
          }
        } else {
          if (message.start > message.end || message.end > this.size) throw new Error("get range outside the transfer");
          const INLINE = 64 * 1024;
          for (let at = message.start; at < message.end; at += INLINE) {
            const bytes = new Uint8Array(await this.blob.slice(at, Math.min(at + INLINE, message.end)).arrayBuffer());
            link.sendPeer(from, { type: "InlineData", start: at, data: bytes });
          }
        }
        break;
      }
      case "SdpOffer":
      case "SdpAnswer":
      case "IceCandidate":
        post({ type: "rtcSignal", peer: from, message });
        break;
      case "Complete":
        this.completed++;
        this.dropPeer(from);
        break;
      case "Progress":
        peer.bytes = Math.min(message.bytes, this.size);
        this.publishPeers();
        break;
      default:
        throw new Error(`unexpected message ${message.type} from receiver`);
    }
  }

  // -- streaming: the upload starts with the first receiver, the data is hashed
  //    as the first pass reads it, and the manifest + checksum follow it --

  announceTo(id) {
    this.link.sendPeer(id, { type: "Manifest" });
    this.link.sendPeer(id, { type: "Checksum", checksum: this.checksum });
  }

  startStreamRelay() {
    if (this.relayStarted) return;
    this.relayStarted = true;
    this.relayAbort = new AbortController();
    this.relayUploadStream().catch((e) => {
      if (!this.relayAbort.signal.aborted) this.fail(e);
    });
  }

  /// A fresh stream of the data from the page (`openStream` in v2.js), once per pass.
  requestStream(pass) {
    return new Promise((resolve) => {
      this.streamWaiter = resolve;
      post({ type: "openStream", pass });
    });
  }

  /// The chunks of `reader` cut into blocks of `block` bytes, the last one shorter.
  /// `keep`: also append each block to the spool (a stream that can be read only once).
  async *cut(reader, block, keep) {
    let buf = new Uint8Array(block);
    let fill = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      let rest = value;
      while (rest.length) {
        const take = Math.min(block - fill, rest.length);
        buf.set(rest.subarray(0, take), fill);
        fill += take;
        rest = rest.subarray(take);
        if (fill === block) {
          if (keep) this.spool.append(buf);
          yield buf;
          buf = new Uint8Array(block);
          fill = 0;
        }
      }
    }
    if (fill) {
      const last = buf.subarray(0, fill);
      if (keep) this.spool.append(last);
      yield last;
    }
  }

  /// The data in blocks of the size the fountain code uses, in order. Every pass
  /// needs it again, so the source has to be restartable: a blob can be read
  /// again, `openStream` gives a new stream each time, and a stream that can
  /// be read only once is kept in a spool as it is read.
  async *blocksOf(pass, block) {
    if (this.opts.blob) {
      for (let at = 0; at < this.blob.size; at += block) {
        yield new Uint8Array(await this.blob.slice(at, Math.min(at + block, this.blob.size)).arrayBuffer());
      }
    } else if (this.opts.restartable) {
      yield* this.cut((await this.requestStream(pass)).getReader(), block, false);
    } else if (pass === 0) {
      yield* this.cut(this.opts.stream.getReader(), block, true);
    } else {
      for (let at = 0; at < this.size; at += block) yield this.spool.read(at, Math.min(block, this.size - at));
    }
  }

  async relayUploadStream() {
    const { session, link } = this;
    const url = `${httpBase(this.opts.server)}/session/${session.sessionIdHex()}/${session.ourIdHex()}?token=${link.relayToken}`;
    const signal = this.relayAbort.signal;
    const block = wasm.blockPlain();
    if (this.opts.stream && !this.opts.restartable) this.spool = await Spool.create();
    let batch = [];
    let batchBytes = 0;
    const flush = async () => {
      if (!batch.length) return;
      const body = new Blob(batch);
      batch = [];
      batchBytes = 0;
      const response = await fetch(url, { method: "POST", body, signal });
      if (!response.ok) throw new Error(`relay refused the upload: ${response.status}`);
    };
    for (let pass = 0; !signal.aborted; pass++) {
      let nr = 0;
      let offset = 0;
      for await (const data of this.blocksOf(pass, block)) {
        if (signal.aborted) return;
        if (pass === 0) session.transferUpdate(data);
        const frames = session.encodeBlock(nr, data, pass);
        batch.push(frames);
        batchBytes += frames.length;
        if (batchBytes >= UPLOAD_BATCH) await flush();
        nr++;
        offset += data.length;
      }
      await flush();
      if (pass === 0) {
        // everything has been read once: now the size and the checksum exist
        this.size = offset;
        this.checksum = session.transferFinish();
        for (const [id, peer] of this.peers) if (peer.state !== "connecting") this.announceTo(id);
        this.publishPeers();
        if (offset === 0) return;
      } else if (offset !== this.size) {
        throw new Error("the data changed between passes");
      }
    }
  }

  // -- relay: one upload for all receivers, pass after pass until stopped --

  startRelay() {
    if (this.relayStarted) return;
    this.relayStarted = true;
    this.relayAbort = new AbortController();
    this.relayUpload().catch((e) => {
      if (!this.relayAbort.signal.aborted) state(`relay upload: ${e.message || e}`);
    });
  }

  stopRelay() {
    if (this.relayAbort) this.relayAbort.abort();
  }

  async relayUpload() {
    const { session, link } = this;
    const url = `${httpBase(this.opts.server)}/session/${session.sessionIdHex()}/${session.ourIdHex()}?token=${link.relayToken}`;
    const signal = this.relayAbort.signal;
    const blocks = session.numBlocks();
    let batch = [];
    let batchBytes = 0;
    const flush = async () => {
      if (!batch.length) return;
      const body = new Blob(batch);
      batch = [];
      batchBytes = 0;
      const response = await fetch(url, { method: "POST", body, signal });
      if (!response.ok) throw new Error(`relay refused the upload: ${response.status}`);
    };
    for (let pass = 0; !signal.aborted; pass++) {
      for (let nr = 0; nr < blocks && !signal.aborted; nr++) {
        const [start, len] = session.blockSpan(nr);
        const data = new Uint8Array(await this.blob.slice(start, start + len).arrayBuffer());
        const frames = session.encodeBlock(nr, data, pass);
        batch.push(frames);
        batchBytes += frames.length;
        if (batchBytes >= UPLOAD_BATCH) await flush();
      }
      await flush();
    }
  }

  // -- data channel --

  onRtc(message) {
    const peer = this.peers.get(message.peer);
    switch (message.type) {
      case "stream":
        // the page's answer to `openStream`
        if (this.streamWaiter) {
          this.streamWaiter(message.stream);
          this.streamWaiter = null;
        }
        break;
      case "rtcSignal":
        if (peer) this.link.sendPeer(message.peer, message.message);
        break;
      case "dcOpen":
        if (peer) { peer.dc = true; peer.state = "direct"; this.publishPeers(); }
        break;
      case "dcClosed":
        if (peer) {
          peer.dc = false;
          peer.ranges = [];
          if (!peer.relayOffered) this.fail(new Error("data channel closed and there is no relay to fall back on"));
        }
        break;
      case "dcDrained":
        if (peer) { peer.drained = message.bytes; peer.wake && peer.wake(); }
        break;
      case "dcMessage": {
        if (!peer) break;
        const m = decodeDc(message.data);
        if (m.type !== "Get") throw new Error("receiver sent data");
        if (m.start > m.end || m.end > this.size) throw new Error("get range outside the transfer");
        peer.ranges.push([m.start, m.end]);
        this.serveRanges(message.peer, peer).catch((e) => this.fail(e));
        break;
      }
    }
  }

  async serveRanges(id, peer) {
    if (peer.serving) return;
    peer.serving = true;
    try {
      while (peer.ranges.length && peer.dc) {
        const [start, end] = peer.ranges.shift();
        const BLOCK = 2 * 1024 * 1024;
        for (let at = start; at < end && peer.dc; at += BLOCK) {
          const block = new Uint8Array(await this.blob.slice(at, Math.min(at + BLOCK, end)).arrayBuffer());
          for (let p = 0; p < block.length && peer.dc; p += PIECE) {
            // keep the channel's queue short: wait until the page has taken most of what was sent
            while (peer.sent - peer.drained > DC_WINDOW && peer.dc) {
              await new Promise((r) => { peer.wake = r; });
            }
            const piece = block.subarray(p, Math.min(p + PIECE, block.length));
            const message = dataMessage(at + p, piece);
            peer.sent += message.byteLength;
            post({ type: "dcSend", peer: id, data: message }, [message]);
          }
        }
      }
    } finally {
      peer.serving = false;
    }
  }

  // -- receiver-initiated: hand our link to whoever asked --

  async deliverToRequest(linkText) {
    const key = this.opts.requestKey;
    const session = wasm.Session.join(key, undefined, this.opts.caps);
    let ready = null;
    const arrived = new Promise((resolve, reject) => { ready = { resolve, reject }; });
    let sender = null;
    const rendezvous = new Link(this.opts.server, session, (event) => {
      if (event.kind === "joined") sender = event.sender;
      else if (event.kind === "peerReady") ready.resolve();
      else if (event.kind === "error") ready.reject(new Error(event.message));
      else if (event.kind === "text") ready.reject(new Error(`server refused: ${event.text}`));
      else if (event.kind === "closed") ready.reject(new Error("request link: connection closed"));
    });
    await rendezvous.open();
    await arrived;
    rendezvous.sendPeer(sender, { type: "ShareLink", link: linkText });
    await rendezvous.close();
  }

  cancel() {
    this.cancelled = true;
    this.stopRelay();
    if (this.spool) this.spool.discard();
    this.journal && this.journal.remove();
    if (this.link) this.link.close();
    if (this.fail) this.fail(new Cancelled());
  }
}

// ---- receiving -----------------------------------------------------------

function missingRanges(size, blockSize, have) {
  const ranges = [];
  const blocks = Math.ceil(size / blockSize);
  for (let b = 0; b < blocks; b++) {
    if (have.has(b)) continue;
    const start = b * blockSize;
    const end = Math.min(start + blockSize, size);
    const last = ranges[ranges.length - 1];
    if (last && last[1] === start) last[1] = end;
    else ranges.push([start, end]);
  }
  return ranges;
}

class Receiver {
  constructor(opts) {
    this.kind = "receive";
    this.opts = opts;
    this.cancelled = false;
    this.have = new Set();
    this.blocks = 0;
    this.viaRelay = 0;
    this.viaDc = 0;
    this.lastProgress = 0;
    this.streaming = false;
    this.keepJournal = false;
    // a streaming sender sends its checksum after the data
    this.checksumReady = new Promise((resolve) => { this.setChecksum = resolve; });
  }

  async run() {
    const { opts } = this;
    this.id = opts.id || crypto.randomUUID();
    this.done = new Promise((resolve, reject) => { this.finish = resolve; this.fail = reject; });
    this.journal = await Journal.create(this.id, opts.resume
      ? { ...opts.resume, kind: "receive" }
      : { kind: "receive", server: opts.server, link: opts.link, phase: "starting" });
    await protocol();
    const link = wasm.ShareLink.fromB64Url(opts.link);
    this.signature = link.signature;
    this.session = wasm.Session.join(link.shareKeyHex(), this.signature, opts.caps);
    this.link = new Link(opts.server, this.session, (e) => this.onEvent(e));
    if (opts.resume) await this.restore(opts.resume);
    state("connecting…");
    await this.link.open();
    return this.done;
  }

  /// Pick a transfer up from its journal: the file that is already on disk,
  /// the blocks that are in it, and the link that leads back to the sender.
  /// The session is joined afresh — the sender sees a receiver arrive, which
  /// it answers with its manifest, and from there we ask for what we lack.
  async restore(entry) {
    if (!entry.manifest || !entry.size || !entry.blockSize) return; // it had not got that far
    this.size = entry.size;
    this.blockSize = entry.blockSize;
    this.total = entry.size;
    this.blocks = Math.ceil(entry.size / entry.blockSize);
    this.manifest = entry.manifest;
    this.streaming = !!entry.streaming;
    this.have = decodeHave(entry.have, this.blocks);
    this.store = await Store.reopen(`${RECV_PREFIX}${this.id}.part`, entry.size);
    if (!this.store) {
      // the file is gone: start over rather than fail
      this.have = new Set();
      this.manifest = null;
      this.viaRelay = 0;
      return;
    }
    this.viaRelay = heldBytes(this.have, this.blockSize, this.size);
    if (entry.checksum) this.setChecksum(entry.checksum);
    this.restored = true;
    this.keepJournal = true;
    state(`resuming — ${this.have.size} of ${this.blocks} blocks already on disk`);
  }

  async onEvent(event) {
    try {
      await this.handle(event);
    } catch (e) {
      this.fail(e);
    }
  }

  async handle(event) {
    const { link } = this;
    switch (event.kind) {
      case "joined":
        this.sender = event.sender;
        this.senderCaps = event.senderCaps;
        link.relayToken = event.relayToken;
        state("connected — waiting for the sender…");
        break;
      case "message":
        await this.onMessage(event.message);
        break;
      case "peerLeft":
        if (!this.complete) this.fail(new Error("the sender went away"));
        break;
      case "text":
        state(`server: ${event.text}`);
        break;
      case "error":
        this.fail(new Error(event.message));
        break;
      case "closed":
        if (!this.complete) this.fail(new Error("connection to the server closed"));
        break;
    }
  }

  async onMessage(message) {
    const { opts, session, link } = this;
    switch (message.type) {
      case "Manifest": {
        if (this.manifest) {
          // a resumed job is told the manifest again, and that is also what
          // says the sender is there and ready to serve
          if (message.size !== this.size) throw new Error("the sender's file changed since this transfer started");
        } else {
          this.manifest = message;
          this.size = message.size;
          this.blockSize = message.blockSize;
          this.total = message.size;
          this.blocks = message.blockSize ? Math.ceil(this.size / message.blockSize) : 0;
          this.journal.set({ manifest: message, size: this.size, blockSize: this.blockSize }).flush();
        }
        if (this.streaming) return this.beginStreamDecode();
        this.useRelay = !!(opts.caps & wasm.CAP_RELAY()) && !!(this.senderCaps & wasm.CAP_RELAY());
        this.useRtc = !!(opts.caps & wasm.CAP_WEBRTC()) && !!(this.senderCaps & wasm.CAP_WEBRTC());
        if (!this.useRelay && !this.useRtc) throw new Error("sender and receiver have no transport in common");
        if (!this.store) this.store = await Store.create(this.size, `${RECV_PREFIX}${this.id}.part`);
        this.keepJournal = true;
        this.journal.set({ phase: "transfer", size: this.size, blockSize: this.blockSize }).flush();
        link.sendPeer(this.sender, { type: "Get", start: 0, end: this.size });
        if (this.size === 0) return this.complete_();
        state(this.restored ? "resuming the transfer…" : "starting the transfer…");
        break;
      }
      case "JoinRelay":
        // a sender that streams sends the data first and the manifest last
        if (!this.manifest) {
          this.startSpool();
          break;
        }
        if (this.useRelay) {
          this.relayOffered = true;
          this.maybeStartRelay();
        }
        break;
      case "SdpOffer":
      case "SdpAnswer":
      case "IceCandidate":
        if (!this.useRtc) break;
        if (!this.rtcStarted) {
          this.rtcStarted = true;
          post({ type: "rtcStart", peer: this.sender, role: "answerer" });
        }
        post({ type: "rtcSignal", peer: this.sender, message });
        break;
      case "Checksum":
        this.setChecksum(message.checksum);
        this.journal.set({ checksum: message.checksum }).flush();
        break;
      case "InlineData":
      case "Progress":
        break;
      default:
        throw new Error(`unexpected message ${message.type} from sender`);
    }
  }

  // -- streaming: keep the relay stream until the manifest (and so the key) arrives,
  //    then decode what was kept followed by what still comes --

  startSpool() {
    if (this.streaming) return;
    const { opts } = this;
    if (!(opts.caps & wasm.CAP_RELAY()) || !(this.senderCaps & wasm.CAP_RELAY())) {
      throw new Error("this is a streaming transfer, which goes over the relay, and one side does not use it");
    }
    this.streaming = true;
    this.spoolTask = this.spoolRelay().catch((e) => {
      if (!this.spoolStopped && !this.complete) this.fail(e);
    });
  }

  async spoolRelay() {
    const { session } = this;
    this.spool = await Spool.create();
    const url = `${httpBase(this.opts.server)}/session/${session.sessionIdHex()}/${session.ourIdHex()}?token=${this.link.relayToken}`;
    this.spoolAbort = new AbortController();
    const response = await fetch(url, { signal: this.spoolAbort.signal });
    if (!response.ok) throw new Error(`relay refused the download: ${response.status}`);
    const reader = response.body.getReader();
    try {
      for (;;) {
        let chunk;
        try {
          chunk = await reader.read();
        } catch (e) {
          if (this.spoolStopped) break; // stopped on purpose
          throw e;
        }
        if (chunk.done) break;
        this.spool.append(chunk.value);
        // no size yet: the bytes that have come, no total
        const now = Date.now();
        if (now - this.lastProgress >= 100) {
          this.lastProgress = now;
          post({ type: "progress", bytes: this.spool.length, total: 0, via: "relay" });
        }
      }
    } finally {
      try { await reader.cancel(); } catch {}
    }
  }

  async beginStreamDecode() {
    this.useRelay = true;
    this.useRtc = false;
    if (!this.store) this.store = await Store.create(this.size, `${RECV_PREFIX}${this.id}.part`);
    this.keepJournal = true;
    this.spoolStopped = true;
    if (this.spoolAbort) this.spoolAbort.abort();
    if (this.spoolTask) await this.spoolTask;
    if (this.size === 0) return this.complete_();
    this.relayOffered = true;
    state("decoding…");
    this.maybeStartRelay();
  }

  maybeStartRelay() {
    if (this.relay || this.dcActive || !this.relayOffered || this.complete) return;
    this.relay = this.relayDownload().then(
      () => { this.relay = null; this.afterRelay(); },
      (e) => {
        this.relay = null;
        if (this.dcActive || this.rtcStarted) state(`relay: ${e.message || e}`);
        else this.fail(e);
      },
    );
  }

  afterRelay() {
    if (this.complete) return;
    if (this.dcStartDue) this.startDcRequests();
  }

  progress(force) {
    const now = Date.now();
    if (!force && now - this.lastProgress < 100) return;
    this.lastProgress = now;
    const bytes = Math.min(this.viaRelay + this.viaDc, this.total);
    post({ type: "progress", bytes, total: this.total, via: this.dcActive ? "direct" : "relay" });
    // the sender shows how far we are (every quarter second is plenty)
    if (!this.complete && (force || now - (this.lastReport || 0) >= 250)) {
      this.lastReport = now;
      this.link.sendPeer(this.sender, { type: "Progress", bytes });
    }
  }

  async relayDownload() {
    const { session } = this;
    const url = `${httpBase(this.opts.server)}/session/${session.sessionIdHex()}/${session.ourIdHex()}?token=${this.link.relayToken}`;
    this.relayAbort = new AbortController();
    const response = await fetch(url, { signal: this.relayAbort.signal });
    if (!response.ok) throw new Error(`relay refused the download: ${response.status}`);
    const incoming = session.incoming();
    this.stopRelayRequested = false;
    const reader = response.body.getReader();
    this.relayBytes = 0;
    try {
      // a streaming transfer: what was kept before the key was known comes first
      if (this.spool) {
        const CHUNK = 4 * 1024 * 1024;
        for (let at = 0; at < this.spool.length; at += CHUNK) {
          const piece = this.spool.read(at, Math.min(CHUNK, this.spool.length - at));
          const complete = this.absorb(incoming.push(piece), incoming);
          this.progress(false);
          if (complete) {
            this.progress(true);
            this.saveJournal(true);
            await this.complete_();
            return;
          }
          await new Promise((r) => setTimeout(r, 0));
        }
        // what comes now is a new connection: it starts at a frame, however the kept one ended
        incoming.newStream();
      }
      while (!this.stopRelayRequested) {
        let chunk;
        try {
          chunk = await reader.read();
        } catch (e) {
          if (this.stopRelayRequested) break; // stopped on purpose
          throw e;
        }
        const { done, value } = chunk;
        if (done) break;
        const complete = this.absorb(incoming.push(value), incoming);
        this.progress(false);
        if (complete) {
          this.progress(true);
          this.saveJournal(true);
          await this.complete_();
          return;
        }
      }
    } finally {
      try { await reader.cancel(); } catch {}
      this.relayAbort = null;
    }
    if (!this.stopRelayRequested && !this.complete) throw new Error("relay stream ended before the transfer was complete");
  }

  /// Decoded blocks into the file: the ones we do not have yet are written,
  /// and the journal follows the disk, not the other way round. Says whether
  /// the file is complete (a resumed job does not need the decoder to agree —
  /// it starts from nothing while blocks are already in hand).
  absorb(blocks, incoming) {
    for (const block of blocks) {
      const b = block.offset / this.blockSize;
      if (this.have.has(b)) continue;
      this.store.write(block.offset, block.data);
      this.have.add(b);
      this.viaRelay += block.data.length;
    }
    this.saveJournal(false);
    return incoming.isComplete() || this.allHeld();
  }

  allHeld() {
    return this.blocks > 0 && this.have.size >= this.blocks;
  }

  /// Bytes first, then the record of them: the journal never claims more than
  /// the file holds. Twice a second is plenty — what is not recorded is fetched
  /// again, and every block is a fresh chance to record.
  saveJournal(force) {
    if (!this.journal) return;
    const now = Date.now();
    if (!force && now - (this.savedAt || 0) < 2000) return;
    this.savedAt = now;
    if (this.store && this.store.handle) this.store.flush();
    this.journal.set({
      have: encodeHave(this.have, this.blocks),
      blocks: this.blocks,
      streaming: this.streaming,
      phase: "transfer",
    }).flush();
  }

  /// The direct channel is gone (or has to be given up): what this worker owns
  /// — the signaling socket and the relay — takes over, from the blocks that
  /// are already on disk.
  fallBackToRelay() {
    if (!this.useRelay) {
      this.fail(new Error("the direct connection ended and the relay is not in use"));
      return;
    }
    this.dcActive = false;
    this.stopRelayRequested = true;
    if (this.relayAbort) this.relayAbort.abort();
    this.viaRelay = heldBytes(this.have, this.blockSize, this.size);
    this.viaDc = 0;
    this.relayOffered = true;
    // the sender relays for whoever asks; asking again is harmless and starts
    // it when the transfer had been going direct only
    if (this.size) this.link.sendPeer(this.sender, { type: "Get", start: 0, end: this.size });
    this.maybeStartRelay();
  }

  /// A page came back to this job (a reload, or another tab): the peer
  /// connection died with the old page, so say what is left and carry on over
  /// the relay this worker holds.
  reattached() {
    post({ type: "rtcClose", peer: this.sender });
    if (this.complete) return;
    if (this.dcActive) {
      this.fallBackToRelay();
      return;
    }
    this.progress(true);
    state("page reloaded — the transfer carried on");
  }

  // -- data channel: takes over once it opens, asking for what is missing --

  onRtc(message) {
    switch (message.type) {
      case "rtcSignal":
        this.link.sendPeer(this.sender, message.message);
        break;
      case "dcOpen":
        this.dcActive = true;
        this.dcStartDue = true;
        if (this.relay) {
          this.stopRelayRequested = true;
          if (this.relayAbort) this.relayAbort.abort();
        } else {
          this.startDcRequests();
        }
        break;
      case "dcClosed":
        this.dcStartDue = false;
        this.dcRequests = null;
        if (this.complete) break;
        // what the channel did not deliver is asked for again over the relay;
        // the blocks already on disk stay, and the journal says which
        this.fallBackToRelay();
        break;
      case "dcMessage":
        this.onDcMessage(decodeDc(message.data)).catch((e) => this.fail(e));
        break;
    }
  }

  startDcRequests() {
    this.dcStartDue = false;
    const ranges = missingRanges(this.size, this.blockSize, this.have);
    if (!ranges.length) return void this.complete_().catch((e) => this.fail(e));
    this.dcRequests = { queue: ranges, current: null, got: 0 };
    this.nextDcRange();
  }

  nextDcRange() {
    const r = this.dcRequests;
    r.current = r.queue.shift() || null;
    r.got = 0;
    if (r.current) post({ type: "dcSend", peer: this.sender, data: encodeGet(r.current[0], r.current[1]) });
  }

  async onDcMessage(m) {
    const r = this.dcRequests;
    if (m.type !== "Data" || !this.dcActive || !r || !r.current) throw new Error("unexpected data channel message");
    const [start, end] = r.current;
    const len = m.bytes.length;
    if (m.offset !== start + r.got || m.offset + len > end) throw new Error("sender sent data that was not asked for");
    this.store.write(m.offset, m.bytes);
    this.viaDc += len;
    r.got += len;
    this.progress(false);
    if (start + r.got >= end) {
      // a range is whole blocks: that is what the file now holds
      for (let at = start; at < end; at += this.blockSize) this.have.add(Math.floor(at / this.blockSize));
      this.saveJournal(true);
      this.nextDcRange();
      if (!r.current) {
        this.progress(true);
        await this.complete_();
      }
    }
  }

  // -- finished: check against the link's signature, tell the sender --

  async complete_() {
    if (this.complete) return;
    this.complete = true;
    state("checking…");
    const verifier = this.streaming ? this.session.verifier(await this.checksumReady) : this.session.verifier();
    const CHUNK = 1024 * 1024;
    for (let at = 0; at < this.size; at += CHUNK) {
      verifier.update(this.store.read(at, Math.min(CHUNK, this.size - at)));
    }
    if (!verifier.finish()) throw new Error(this.streaming ? "the data does not match the sender's checksum" : "the data does not match the share link's signature");
    if (this.spool) await this.spool.discard();
    this.link.sendPeer(this.sender, { type: "Complete" });
    const file = await this.store.file(this.manifest.name || (this.manifest.kind === "zip" ? "bitmule-files.zip" : "bitmule-download"), "application/octet-stream");
    // the transfer is over: the record goes, the file stays until the page has
    // saved it (and cleanup takes it after a day either way)
    this.keepJournal = false;
    await this.journal.remove();
    await this.link.close();
    this.finish({
      type: "done",
      file,
      size: this.size,
      kind: this.manifest.kind,
      relayBytes: this.viaRelay,
      directBytes: this.viaDc,
    });
  }

  cancel() {
    this.cancelled = true;
    this.complete = true;
    this.stopRelayRequested = true;
    if (this.relayAbort) this.relayAbort.abort();
    this.spoolStopped = true;
    if (this.spoolAbort) this.spoolAbort.abort();
    if (this.spool) this.spool.discard();
    if (this.link) this.link.close();
    if (this.store) this.store.discard();
    this.keepJournal = false;
    if (this.journal) this.journal.remove();
    if (this.fail) this.fail(new Cancelled());
  }
}

// ---- request: wait for a sender who answers our request link ---------------

class Requester {
  constructor(opts) {
    this.kind = "request";
    this.opts = opts;
  }

  async run() {
    await protocol();
    const session = wasm.Session.create(this.opts.caps);
    this.session = session;
    const done = new Promise((resolve, reject) => { this.finish = resolve; this.fail = reject; });
    this.link = new Link(this.opts.server, session, (e) => this.onEvent(e));
    state("connecting…");
    await this.link.open();
    this.key = session.shareKeyHex();
    post({ type: "requestKey", key: this.key });
    return done;
  }

  /// A page came back: what it lost is the request link, so give it again.
  reattached() {
    if (this.key) post({ type: "requestKey", key: this.key });
    state("page reloaded — still waiting for a sender");
  }

  onEvent(event) {
    try {
      switch (event.kind) {
        case "created":
          state("waiting for a sender…");
          break;
        case "message":
          if (event.message.type === "ShareLink") {
            this.link.close();
            this.finish({ type: "shareLink", link: event.message.link });
          }
          break;
        case "error":
          this.fail(new Error(event.message));
          break;
        case "closed":
          this.fail(new Error("connection to the server closed"));
          break;
      }
    } catch (e) {
      this.fail(e);
    }
  }

  onRtc() {}

  cancel() {
    if (this.link) this.link.close();
    if (this.fail) this.fail(new Cancelled());
  }
}

// ---- entry ---------------------------------------------------------------
//
// One job per worker. The page reaches this worker by name; a reload brings a
// new port to the same worker, and that is what makes a transfer survive it.

let job = null;

async function onPage(m) {
  try {
    if (m.type === "start") {
      if (job) throw new Error("this worker already runs a transfer");
      if (m.job !== "send" && m.job !== "receive" && m.job !== "request") throw new Error(`unknown job ${m.job}`);
      const Ctor = m.job === "send" ? Sender : m.job === "receive" ? Receiver : Requester;
      const current = job = new Ctor(m);
      try {
        post(await current.run());
      } finally {
        if (job === current) job = null;
      }
    } else if (m.type === "resume") {
      await resume(m);
    } else if (m.type === "cancel") {
      if (job) job.cancel();
    } else if (job) {
      job.onRtc(m);
    }
  } catch (err) {
    if (!(err instanceof Cancelled)) post({ type: "error", message: String(err.message || err) });
  }
}

/// Take a job back: the one running here, or the one its journal remembers.
async function resume(m) {
  if (job) {
    job.reattached();
    return;
  }
  const entry = m.jobId ? await Journal.read(m.jobId) : null;
  if (!entry) throw new Error("that transfer is no longer here");
  if (entry.kind === "receive") {
    const current = job = new Receiver({ ...entry, caps: m.caps || 1, resume: entry });
    try {
      post(await current.run());
    } finally {
      if (job === current) job = null;
    }
    return;
  }
  if (entry.kind === "send") {
    // the share key that is the room lived in the worker that is gone, so the
    // receivers holding that link cannot be reached again: say so plainly
    throw new Error("the sender that ran this transfer is gone; its link is dead");
  }
  throw new Error(`cannot resume a ${entry.kind}`);
}

// A page connected. It is the one that watches the job from now on: the port
// of the page that went away is closed and there is no point posting there.
function connected(p) {
  port = p;
  p.onmessage = (e) => onPage(e.data);
  if (p.start) p.start();
  p.postMessage({ type: "hello", job: job ? job.kind : null, id: job ? job.id : null });
  if (job && job.reattached) {
    try {
      job.reattached();
    } catch (e) {
      p.postMessage({ type: "error", message: String(e.message || e) });
    }
  }
}

const isDedicated = typeof DedicatedWorkerGlobalScope !== "undefined" && self instanceof DedicatedWorkerGlobalScope;
if (isDedicated) connected(self);
else self.onconnect = (event) => connected(event.ports[0]);

