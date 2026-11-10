// A stand-in for v2-worker.js in the resume test.
//
// Same port protocol as the real worker — `hello` on connect, `start`, `resume`,
// `cancel` — and the same OPFS journal, but no protocol: it "downloads" a file
// of `size` bytes by writing them, so that a test can reload the page in the
// middle and watch the transfer carry on instead of starting over.
//
// Messages, page -> worker: {type:"start", jobId, size, chunk, tick, link}
//                             {type:"resume", jobId}
//                             {type:"cancel"}
// worker -> page: {type:"hello", job, id}  {type:"progress", bytes, total}
//                 {type:"state", text}  {type:"done", size}  {type:"error", message}

import { Journal, RECV_PREFIX, Store } from "../opfs.js";

let port = null;
let job = null;

const post = (message) => { if (port) port.postMessage(message); };
const state = (text) => post({ type: "state", text });

class FakeDownload {
  constructor(opts = {}) {
    this.kind = "receive";
    this.opts = opts;
    this.written = 0;
  }

  async run() {
    await this.begin(this.opts.jobId, this.opts);
    return new Promise((resolve) => { this.finish = resolve; });
  }

  async begin(id, opts) {
    this.id = id;
    this.size = opts.size;
    this.chunk = opts.chunk;
    this.tickMs = opts.tick;
    this.link = opts.link || null;
    this.journal = await Journal.create(this.id, {
      kind: "receive", link: this.link, size: this.size, written: 0, phase: "transfer",
    });
    this.store = await Store.create(this.size, `${RECV_PREFIX}${this.id}.part`);
    this.start_();
  }

  async restore(entry) {
    this.id = entry.id;
    this.size = entry.size;
    this.written = entry.written || 0;
    this.link = entry.link || null;
    this.chunk = entry.chunk || 256 * 1024;
    this.tickMs = entry.tick || 100;
    this.journal = await Journal.create(this.id, entry);
    this.store = await Store.reopen(`${RECV_PREFIX}${this.id}.part`, entry.size);
    if (!this.store) throw new Error("the partial file is gone");
    state(`resumed from the journal at ${this.written} of ${this.size}`);
    this.start_();
    this.report();
  }

  start_() {
    this.timer = setInterval(() => this.step(), this.tickMs || 100);
  }

  step() {
    if (this.stopped || this.timer === null) return;
    const n = Math.min(this.chunk, this.size - this.written);
    if (n > 0) {
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = (this.written + i) & 0xff;
      this.store.write(this.written, bytes);
      this.written += n;
    }
    this.store.flush();
    this.journal.set({ written: this.written, size: this.size, chunk: this.chunk, tick: this.tickMs }).flush();
    this.report();
    if (this.written >= this.size) this.complete();
  }

  report() {
    post({ type: "progress", bytes: this.written, total: this.size });
  }

  complete() {
    clearInterval(this.timer);
    this.timer = null;
    this.journal.remove();
    post({ type: "done", size: this.size });
  }

  /// A page came back: tell it where this is and carry on.
  reattached() {
    state("page reloaded — the transfer carried on");
    this.report();
  }

  cancel() {
    this.stopped = true;
    clearInterval(this.timer);
    this.timer = null;
    this.journal.remove();
    this.store.discard();
    post({ type: "cancelled" });
  }

  onRtc() {}
}

async function onPage(m) {
  try {
    if (m.type === "start") {
      if (job) throw new Error("this worker already runs a transfer");
      const current = job = new FakeDownload(m);
      try {
        post(await current.run());
      } finally {
        if (job === current) job = null;
      }
    } else if (m.type === "resume") {
      if (job) {
        job.reattached();
        return;
      }
      const entry = await Journal.read(m.jobId);
      if (!entry) throw new Error("no journal for " + m.jobId);
      const current = job = new FakeDownload(entry);
      await current.restore(entry);
      post(await current.run && { type: "progress", bytes: current.written, total: current.size });
    } else if (m.type === "cancel") {
      if (job) job.cancel();
    } else if (job) {
      job.onRtc(m);
    }
  } catch (err) {
    post({ type: "error", message: String((err && err.message) || err) });
  }
}

function connected(p) {
  port = p;
  p.onmessage = (e) => onPage(e.data);
  if (p.start) p.start();
  p.postMessage({ type: "hello", job: job ? job.kind : null, id: job ? job.id : null });
  if (job && job.reattached) {
    try { job.reattached(); } catch (e) { p.postMessage({ type: "error", message: String(e.message || e) }); }
  }
}

const isDedicated = typeof DedicatedWorkerGlobalScope !== "undefined" && self instanceof DedicatedWorkerGlobalScope;
if (isDedicated) connected(self);
else self.onconnect = (event) => connected(event.ports[0]);
