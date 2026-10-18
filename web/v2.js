// bitmule v2, page side: starts a transfer worker (v2-worker.js, where the
// protocol runs) and does the one thing a worker can't everywhere, WebRTC.
//
//   const job = v2.startReceive({ server, link, on: { state, progress, done, error } });
//   job.cancel();
//
// Jobs:
//   startSend({ server, blob, kind: "single" | "zip", name?, requestKey?, on })
//       name defaults to blob.name; it is what the receiver saves the file as
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

const CAP_RELAY = 1;
const CAP_WEBRTC = 2;

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

class Job {
  constructor(kind, options, extra) {
    this.server = options.server;
    this.on = options.on || {};
    this.rtcs = new Map();
    this.finished = false;
    this.worker = new Worker(new URL("./v2-worker.js", import.meta.url), { type: "module" });
    this.worker.onmessage = (e) => this.fromWorker(e.data);
    this.worker.onerror = (e) => this.fail(e.message || "the transfer worker failed");
    const caps = CAP_RELAY | (webrtcAvailable() ? CAP_WEBRTC : 0);
    this.toWorker({ type: "start", job: kind, server: this.server, caps, ...extra });
  }

  toWorker(message, transfer) {
    if (!this.finished) this.worker.postMessage(message, transfer || []);
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
    // the result is a message already received; the worker can go
    setTimeout(() => this.worker.terminate(), 100);
  }

  fromWorker(m) {
    const on = this.on;
    switch (m.type) {
      case "state": return this.state(m.text);
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

  cancel() {
    if (this.finished) return;
    this.toWorker({ type: "cancel" });
    this.end();
  }
}

export function startSend({ server, blob, kind = "single", name = null, requestKey = null, on }) {
  return new Job("send", { server, on }, { blob, kind, name: name || blob.name || null, requestKey });
}

export function startReceive({ server, link, on }) {
  return new Job("receive", { server, on }, { link });
}

export function startRequest({ server, on }) {
  return new Job("request", { server, on }, {});
}

/// Received files are assembled in OPFS; drop the ones left behind by earlier
/// visits (a day old: nothing in use is that old).
export async function cleanupStaleDownloads() {
  try {
    const root = await navigator.storage.getDirectory();
    for await (const [name, handle] of root.entries()) {
      if (!name.startsWith("bitmule-recv-") || handle.kind !== "file") continue;
      const file = await handle.getFile();
      if (Date.now() - file.lastModified > 24 * 3600 * 1000) await root.removeEntry(name);
    }
  } catch {}
}
