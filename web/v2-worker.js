// bitmule v2 transfer worker.
//
// One job per worker: send, receive, or wait for a sender (request). The
// protocol lives in the wasm module (the Rust the CLI uses); this file does
// the I/O around it: the signaling websocket, the relay's HTTP streams,
// reading and storing the file. Everything heavy (proof of work, fountain
// coding, hashing) runs here, off the UI thread.
//
// WebRTC stays on the page (RTCPeerConnection is not in workers everywhere):
// the page reports the data channel's events and this worker tells it what to
// send. Messages, page -> worker:
//   {type: "start", job: "send" | "receive" | "request", server, caps, ...}
//   {type: "rtcSignal", peer, message}      SDP produced by the page's peer connection
//   {type: "dcOpen" | "dcClosed", peer}
//   {type: "dcMessage", peer, data}         one data channel message (ArrayBuffer)
//   {type: "dcDrained", peer, bytes}        bytes the page has handed to the channel so far
// worker -> page:
//   {type: "state", text}   {type: "link", link}   {type: "requestKey", key}
//   {type: "shareLink", link}  {type: "peers", peers}
//   {type: "progress", bytes, total, via}
//   {type: "rtcStart", peer, role}   {type: "rtcSignal", peer, message}   {type: "rtcClose", peer}
//   {type: "dcSend", peer, data}
//   {type: "done", ...}   {type: "error", message}

import init, * as wasm from "./wasm/pkg/bitmule_client_wasm.js";

const READY = init();

// What the data channel and the relay carry per message / request.
const PIECE = 16 * 1024;
const DC_WINDOW = 8 * 1024 * 1024;
const UPLOAD_BATCH = 4 * 1024 * 1024;
const HASH_SLICE = 4 * 1024 * 1024;
const WS_FLUSH_MS = 4000;

const post = (message, transfer) => self.postMessage(message, transfer || []);
const state = (text) => post({ type: "state", text });

const httpBase = (server) => server.replace(/\/$/, "");
const wsBase = (server) => httpBase(server).replace(/^http/, "ws");

class Cancelled extends Error {}

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

/// Where a received file is assembled. OPFS (a real file, not in memory)
/// where there is one, memory otherwise.
class Store {
  static async create(size) {
    const store = new Store(size);
    try {
      const root = await navigator.storage.getDirectory();
      store.name = `bitmule-recv-${crypto.randomUUID()}`;
      store.fileHandle = await root.getFileHandle(store.name, { create: true });
      store.handle = await store.fileHandle.createSyncAccessHandle();
      store.handle.truncate(size);
    } catch (e) {
      store.handle = null;
      store.memory = new Uint8Array(size);
    }
    return store;
  }

  constructor(size) {
    this.size = size;
    this.handle = null;
    this.memory = null;
  }

  write(offset, bytes) {
    if (this.handle) {
      let done = 0;
      while (done < bytes.length) {
        const n = this.handle.write(bytes.subarray(done), { at: offset + done });
        if (n === 0) throw new Error("could not write the file");
        done += n;
      }
    } else {
      this.memory.set(bytes, offset);
    }
  }

  read(offset, length) {
    if (!this.handle) return this.memory.subarray(offset, offset + length);
    const buf = new Uint8Array(length);
    this.handle.read(buf, { at: offset });
    return buf;
  }

  async file(name, type) {
    if (!this.handle) return new File([this.memory], name, { type });
    this.handle.flush();
    this.handle.close();
    this.handle = null;
    const file = await this.fileHandle.getFile();
    return new File([file], name, { type });
  }

  async discard() {
    if (this.handle) { try { this.handle.close(); } catch {} this.handle = null; }
    if (this.name) {
      try { (await navigator.storage.getDirectory()).removeEntry(this.name); } catch {}
    }
  }
}

/// Bytes kept in arrival order whose length is not known beforehand: the
/// relay stream of a streaming transfer until its manifest (and key) arrives,
/// or what a streaming sender has read of a stream it can only read once. OPFS
/// where there is one, memory otherwise.
class Spool {
  static async create() {
    const spool = new Spool();
    try {
      const root = await navigator.storage.getDirectory();
      // named so that cleanupStaleDownloads takes it too
      spool.name = `bitmule-recv-spool-${crypto.randomUUID()}`;
      const file = await root.getFileHandle(spool.name, { create: true });
      spool.handle = await file.createSyncAccessHandle();
    } catch {
      spool.handle = null;
    }
    return spool;
  }

  constructor() {
    this.length = 0;
    this.handle = null;
    this.name = null;
    this.parts = []; // memory fallback: [offset, bytes]
  }

  append(bytes) {
    if (this.handle) {
      let done = 0;
      while (done < bytes.length) {
        const n = this.handle.write(bytes.subarray(done), { at: this.length + done });
        if (n === 0) throw new Error("could not write the spool");
        done += n;
      }
    } else {
      this.parts.push([this.length, bytes.slice()]);
    }
    this.length += bytes.length;
  }

  read(at, length) {
    const out = new Uint8Array(length);
    if (this.handle) {
      this.handle.read(out, { at });
      return out;
    }
    for (const [offset, bytes] of this.parts) {
      const from = Math.max(at, offset);
      const to = Math.min(at + length, offset + bytes.length);
      if (from < to) out.set(bytes.subarray(from - offset, to - offset), from - at);
    }
    return out;
  }

  async discard() {
    if (this.handle) { try { this.handle.close(); } catch {} this.handle = null; }
    this.parts = [];
    if (this.name) {
      try { (await navigator.storage.getDirectory()).removeEntry(this.name); } catch {}
      this.name = null;
    }
  }
}

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
      this.link.close().then(() => this.finish({ type: "sent", receivers: this.completed }));
    }
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
    this.opts = opts;
    this.cancelled = false;
    this.have = new Set();
    this.viaRelay = 0;
    this.viaDc = 0;
    this.lastProgress = 0;
    this.streaming = false;
    // a streaming sender sends its checksum after the data
    this.checksumReady = new Promise((resolve) => { this.setChecksum = resolve; });
  }

  async run() {
    const { opts } = this;
    const link = wasm.ShareLink.fromB64Url(opts.link);
    this.signature = link.signature;
    this.session = wasm.Session.join(link.shareKeyHex(), this.signature, opts.caps);
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
        if (this.manifest) throw new Error("second manifest");
        this.manifest = message;
        this.size = message.size;
        this.blockSize = message.blockSize;
        this.total = message.size;
        if (this.streaming) return this.beginStreamDecode();
        this.useRelay = !!(opts.caps & wasm.CAP_RELAY()) && !!(this.senderCaps & wasm.CAP_RELAY());
        this.useRtc = !!(opts.caps & wasm.CAP_WEBRTC()) && !!(this.senderCaps & wasm.CAP_WEBRTC());
        if (!this.useRelay && !this.useRtc) throw new Error("sender and receiver have no transport in common");
        this.store = await Store.create(this.size);
        link.sendPeer(this.sender, { type: "Get", start: 0, end: this.size });
        if (this.size === 0) return this.complete_();
        state("starting the transfer…");
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
    this.store = await Store.create(this.size);
    this.spoolStopped = true;
    if (this.spoolAbort) this.spoolAbort.abort();
    await this.spoolTask;
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
          for (const block of incoming.push(piece)) {
            this.store.write(block.offset, block.data);
            this.have.add(block.offset / this.blockSize);
            this.viaRelay += block.data.length;
          }
          this.progress(false);
          if (incoming.isComplete()) break;
          await new Promise((r) => setTimeout(r, 0));
        }
        if (incoming.isComplete()) {
          this.progress(true);
          await this.complete_();
          return;
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
        for (const block of incoming.push(value)) {
          this.store.write(block.offset, block.data);
          this.have.add(block.offset / this.blockSize);
          this.viaRelay += block.data.length;
        }
        this.progress(false);
        if (incoming.isComplete()) {
          this.progress(true);
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
        this.dcActive = false;
        this.dcStartDue = false;
        this.dcRequests = null;
        if (this.complete) break;
        if (this.useRelay && this.relayOffered) {
          this.have = new Set();
          this.viaRelay = 0;
          this.viaDc = 0;
          this.maybeStartRelay();
        } else {
          this.fail(new Error("the data channel failed and the relay is not in use"));
        }
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
    if (this.fail) this.fail(new Cancelled());
  }
}

// ---- request: wait for a sender who answers our request link ---------------

class Requester {
  constructor(opts) {
    this.opts = opts;
  }

  async run() {
    const session = wasm.Session.create(this.opts.caps);
    this.session = session;
    const done = new Promise((resolve, reject) => { this.finish = resolve; this.fail = reject; });
    this.link = new Link(this.opts.server, session, (e) => this.onEvent(e));
    state("connecting…");
    await this.link.open();
    post({ type: "requestKey", key: session.shareKeyHex() });
    return done;
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

let job = null;

self.onmessage = async (e) => {
  const m = e.data;
  try {
    if (m.type === "start") {
      await READY;
      if (m.job === "send") job = new Sender(m);
      else if (m.job === "receive") job = new Receiver(m);
      else if (m.job === "request") job = new Requester(m);
      else throw new Error(`unknown job ${m.job}`);
      const result = await job.run();
      post(result);
    } else if (m.type === "cancel") {
      if (job) job.cancel();
    } else if (job) {
      job.onRtc(m);
    }
  } catch (err) {
    if (!(err instanceof Cancelled)) post({ type: "error", message: String(err.message || err) });
  }
};
