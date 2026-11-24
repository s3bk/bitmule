// bitmule v2, page side: starts a transfer worker (v2-worker.js, where the
// protocol runs) and does the one thing a worker can't everywhere, WebRTC.
//
// The worker is shared and named after the transfer, so a reload attaches to
// the transfer that is still running rather than starting a second one; and if
// the worker is gone too, the journal it left in OPFS is what a new worker
// carries on from (opfs.js).
//
//   const job = v2.startReceive({ server, link, on: { state, progress, done, error } });
//   job.cancel();
//
// Jobs:
//   startSend({ server, blob, kind: "single" | "zip", name?, requestKey?, on })
//       name defaults to blob.name; it is what the receiver saves the file as
//   startSend({ server, openStream, size?, name, on })  a streaming send, from a ReadableStream
//   startSend({ server, blob, streaming: true, on })    ... or from a blob, without the hash pass first
//       The link is there at once and the data goes first; the size, the checksum and the
//       manifest come after it. Relay only. `size` is only a hint for progress.
//       The data is read once per pass (the first pass finds the size and the hash, the next
//       ones send repair symbols for what a receiver missed), so the source has to be
//       restartable: `openStream` is a function returning a new ReadableStream (or a promise
//       of one) with the same bytes every time; a blob can be read again anyway. A `stream`
//       (one ReadableStream instance) works too, but is then kept in a temporary file as it is read.
//       on.link(link)      the share link fragment, once the session exists
//       on.peers([{id, state, via}])
//       on.done({receivers})
//   startReceive({ server, link, on })
//       on.progress({bytes, total, via})
//       on.done({file, size, kind, relayBytes, directBytes})
//   startRequest({ server, on })
//       on.requestKey(keyHex)   put it in a `/send#<key>` link for the sender
//       on.shareLink(link)      the sender answered: start a receive with this
// All jobs: on.state(text), on.error(message).

import { Journal, cleanupOlderThan } from "./opfs.js";

const CAP_RELAY = 1;
const CAP_WEBRTC = 2;

// The name a job's SharedWorker is registered under. The worker lives as long
// as a page is attached to it, and a reload attaches to the same one.
const WORKER_PREFIX = "bitmule-transfer-";

function newJobId() {
  return `job-${crypto.randomUUID()}`;
}

// A buffer's worth in the channel at most; the rest waits in the queue below.
const DC_HIGH = 4 * 1024 * 1024;
const DC_LOW = 1 * 1024 * 1024;
// Candidates are gathered before the offer or answer goes out (the CLI side
// does not trickle); don't wait forever for a slow STUN server.
const GATHER_TIMEOUT_MS = 4000;

export function webrtcAvailable() {
  return typeof RTCPeerConnection === "function";
}

function iceServers(server) {
  const servers = [{ urls: "stun:stun.l.google.com:19302" }];
  try {
    // the bitmule server runs a STUN responder next to the relay
    servers.unshift({ urls: `stun:${new URL(server).hostname}:3478` });
  } catch {}
  return servers;
}

function gathered(pc) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    const done = () => {
      if (pc.iceGatheringState === "complete") {
        pc.removeEventListener("icegatheringstatechange", done);
        resolve();
      }
    };
    pc.addEventListener("icegatheringstatechange", done);
    setTimeout(resolve, GATHER_TIMEOUT_MS);
  });
}

/// One WebRTC data channel to one peer; the worker decides what goes over it.
class Rtc {
  constructor(job, peer, role) {
    this.job = job;
    this.peer = peer;
    this.role = role;
    this.queue = [];
    this.handed = 0;
    this.channel = null;
    this.pc = new RTCPeerConnection({ iceServers: iceServers(job.server) });
    this.pc.onconnectionstatechange = () => {
      if (this.pc.connectionState === "failed" || this.pc.connectionState === "closed") this.closed();
    };
    if (role === "offerer") {
      this.wire(this.pc.createDataChannel("bitmule"));
      this.offer().catch((e) => this.job.state(`webrtc: ${e.message || e}`));
    } else {
      this.pc.ondatachannel = (e) => this.wire(e.channel);
    }
  }

  async offer() {
    await this.pc.setLocalDescription(await this.pc.createOffer());
    await gathered(this.pc);
    this.job.toWorker({ type: "rtcSignal", peer: this.peer, message: { type: "SdpOffer", sdp: this.pc.localDescription.sdp } });
  }

  async signal(message) {
    if (message.type === "SdpOffer" && this.role === "answerer") {
      await this.pc.setRemoteDescription({ type: "offer", sdp: message.sdp });
      await this.pc.setLocalDescription(await this.pc.createAnswer());
      await gathered(this.pc);
      this.job.toWorker({ type: "rtcSignal", peer: this.peer, message: { type: "SdpAnswer", sdp: this.pc.localDescription.sdp } });
    } else if (message.type === "SdpAnswer" && this.role === "offerer") {
      await this.pc.setRemoteDescription({ type: "answer", sdp: message.sdp });
    }
    // the other side does not trickle ICE candidates
  }

  wire(channel) {
    this.channel = channel;
    channel.binaryType = "arraybuffer";
    channel.bufferedAmountLowThreshold = DC_LOW;
    channel.onopen = () => this.job.toWorker({ type: "dcOpen", peer: this.peer });
    channel.onmessage = (e) => this.job.toWorker({ type: "dcMessage", peer: this.peer, data: e.data }, [e.data]);
    channel.onclose = () => this.closed();
    channel.onerror = () => this.closed();
    channel.onbufferedamountlow = () => this.flush();
  }

  send(data) {
    this.queue.push(data);
    this.flush();
  }

  flush() {
    const channel = this.channel;
    if (!channel || channel.readyState !== "open") return;
    let handed = false;
    while (this.queue.length && channel.bufferedAmount < DC_HIGH) {
      const data = this.queue.shift();
      channel.send(data);
      this.handed += data.byteLength;
      handed = true;
    }
    if (handed) this.job.toWorker({ type: "dcDrained", peer: this.peer, bytes: this.handed });
  }

  closed() {
    if (this.gone) return;
    this.gone = true;
    this.job.toWorker({ type: "dcClosed", peer: this.peer });
  }

  close() {
    this.gone = true;
    try { this.channel && this.channel.close(); } catch {}
    try { this.pc.close(); } catch {}
  }
}

/// The page's end of one job's worker.
///
/// A `SharedWorker` named after the transfer: a reload reaches the same worker,
/// which is still running the same job, instead of starting a second one. Where
/// shared workers are missing (or refuse module scripts) a dedicated worker
/// runs the job — the page then owns it, and it dies with the page.
class Channel {
  constructor(id, onmessage) {
    const url = new URL("./v2-worker.js", import.meta.url);
    let shared = null;
    try {
      if (typeof SharedWorker === "function") {
        shared = new SharedWorker(url, { type: "module", name: `${WORKER_PREFIX}${id}` });
      }
    } catch {
      shared = null;
    }
    if (shared) {
      this.shared = true;
      this.port = shared.port;
    } else {
      this.shared = false;
      this.worker = new Worker(url, { type: "module" });
      this.worker.onerror = (e) => onmessage({ type: "error", message: e.message || "the transfer worker failed" });
      this.port = this.worker;
    }
    this.port.onmessage = (e) => onmessage(e.data);
    if (this.port.start) this.port.start();
  }

  post(message, transfer) {
    this.port.postMessage(message, transfer || []);
  }

  /// Stop listening. A shared worker keeps the transfer and goes on without a
  /// page (a reload attaches to it); a dedicated one has nobody else, so it
  /// ends here.
  detach() {
    try { this.port.close && this.port.close(); } catch {}
    if (this.worker) this.worker.terminate();
  }
}

class Job {
  constructor(kind, options, extra = {}) {
    this.kind = kind;
    this.id = extra.jobId || newJobId();
    this.server = options.server;
    this.on = options.on || {};
    this.rtcs = new Map();
    this.finished = false;
    this.channel = null;
    this.caps = CAP_RELAY | (webrtcAvailable() ? CAP_WEBRTC : 0);
    // a function can't go to the worker: it asks for a new stream when it needs one
    this.openStream = extra.openStream || null;
    this.started = this.start(extra).catch((e) => this.fail(String((e && e.message) || e)));
  }

  async start(extra) {
    // A receive of the same link that did not finish is the same transfer: the
    // worker may still be running it, or its journal may be on disk. Either
    // way it is taken back rather than fetched a second time.
    if (this.kind === "receive" && extra.adopt !== false) {
      const entry = (await Journal.list()).find((e) => e.kind === "receive" && e.link === extra.link);
      if (entry) {
        this.id = entry.id;
        this.channel = new Channel(this.id, (m) => this.fromWorker(m));
        this.toWorker({ type: "resume", jobId: this.id, caps: this.caps });
        return;
      }
    }
    if (this.finished) return;
    this.channel = new Channel(this.id, (m) => this.fromWorker(m));
    if (extra.attach) {
      this.toWorker({ type: "resume", jobId: this.id, caps: this.caps });
      return;
    }
    // a ReadableStream (the data of a streaming send) is handed over, not copied
    const { attach, adopt, openStream, stream, ...rest } = extra;
    this.toWorker(
      { type: "start", job: this.kind, jobId: this.id, server: this.server, caps: this.caps, ...rest, restartable: !!openStream },
      stream ? [stream] : [],
    );
  }

  toWorker(message, transfer) {
    if (!this.finished && this.channel) this.channel.post(message, transfer);
  }

  state(text) {
    if (this.on.state) this.on.state(text);
  }

  fail(message) {
    if (this.finished) return;
    this.end();
    if (this.on.error) this.on.error(message);
  }

  end() {
    this.finished = true;
    for (const rtc of this.rtcs.values()) rtc.close();
    this.rtcs.clear();
    // the result is a message already received: stop listening, and leave a
    // shared worker to itself (it has nothing left to do and dies with the page)
    if (this.channel) this.channel.detach();
    this.channel = null;
  }

  fromWorker(m) {
    const on = this.on;
    switch (m.type) {
      case "state": return this.state(m.text);
      case "openStream": {
        // the worker needs the data again (another pass): a fresh stream, handed over
        Promise.resolve()
          .then(() => this.openStream())
          .then(
            (stream) => this.toWorker({ type: "stream", pass: m.pass, stream }, [stream]),
            (e) => this.fail(`could not open the data again: ${e && e.message || e}`),
          );
        return;
      }
      case "link": return on.link && on.link(m.link);
      case "peers": return on.peers && on.peers(m.peers);
      case "progress": return on.progress && on.progress(m);
      case "requestKey": return on.requestKey && on.requestKey(m.key);
      case "rtcStart": {
        if (!webrtcAvailable()) return;
        const rtc = new Rtc(this, m.peer, m.role);
        this.rtcs.set(m.peer, rtc);
        return;
      }
      case "rtcSignal": {
        const rtc = this.rtcs.get(m.peer);
        if (rtc) rtc.signal(m.message).catch((e) => this.state(`webrtc: ${e.message || e}`));
        return;
      }
      case "rtcClose": {
        const rtc = this.rtcs.get(m.peer);
        if (rtc) { rtc.close(); this.rtcs.delete(m.peer); }
        return;
      }
      case "uploadGate": return on.uploadGate && on.uploadGate(m);
      case "dcSend": {
        const rtc = this.rtcs.get(m.peer);
        if (rtc) rtc.send(m.data);
        return;
      }
      case "shareLink": this.end(); return on.shareLink && on.shareLink(m.link);
      case "sent": this.end(); return on.done && on.done(m);
      case "done": this.end(); return on.done && on.done(m);
      case "error": return this.fail(m.message);
    }
  }

  /// Tell the worker what the page sees of the link and what the user pressed.
  /// The worker is the side that starts an upload, so the answer has to be there.
  netPolicy({ mode = null, metered = false, consented = false } = {}) {
    this.toWorker({ type: "netPolicy", mode, metered: !!metered, consented: !!consented });
  }

  cancel() {
    if (this.finished) return;
    this.toWorker({ type: "cancel" });
    this.end();
  }
}

export function startSend({ server, blob = null, stream = null, openStream = null, size = 0, streaming = false, kind = "single", name = null, requestKey = null, mode = null, metered = false, on }) {
  return new Job("send", { server, on }, {
    blob, stream, openStream, size,
    streaming: streaming || !!stream || !!openStream,
    kind, name: name || (blob && blob.name) || null, requestKey,
    mode, metered,
  });
}

/// Receive a share link. A transfer of that link that stopped halfway is picked
/// up where it stopped, so the page does not have to know which one it is.
export function startReceive({ server, link, on, adopt = true }) {
  return new Job("receive", { server, on }, { link, adopt });
}

export function startRequest({ server, on }) {
  return new Job("request", { server, on }, {});
}

/// Transfers that are still here: running in a worker, or stopped halfway with
/// a journal on disk that says where. Newest first.
export async function pending() {
  const entries = await Journal.list();
  return entries.filter((e) => e.kind === "send" || e.kind === "receive");
}

/// Take a transfer back by id (from `pending()`), whether a worker is still
/// running it or it has to be picked up from its journal.
export function resume(id, { server, on, kind = "receive" } = {}) {
  return new Job(kind, { server, on }, { jobId: id, attach: true, adopt: false });
}

/// Drop received files and journals left behind by earlier visits (a day old:
/// nothing in use is that old).
export async function cleanupStaleDownloads() {
  await cleanupOlderThan(24 * 3600 * 1000);
}
