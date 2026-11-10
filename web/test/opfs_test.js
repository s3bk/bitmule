// The rules that make a resume safe, run in node instead of a browser.
//
//     node web/test/opfs_test.js
//
// opfs.js is the part of the web client that outlives a page: the file being
// assembled, the spool of bytes whose length is not known yet, and the journal
// that says where a transfer got to. `navigator.storage` is replaced here with
// an in-memory file system that behaves like OPFS where it matters — a sync
// access handle that reads and writes at an offset, getFile() giving what is on
// disk, entries() listing — so a "crash" is just dropping the objects and
// opening them again by name.
//
// What is checked: a journal round-trips; of its two slots the newer good one
// wins, including after one is torn; a file opened again holds what was written
// and nothing more; a spool keeps its bytes across a reopen; housekeeping drops
// what no journal claims while keeping what one does — and then the worker
// protocol itself, with `web/test/resume-worker.js` standing in for
// v2-worker.js: a page reload attaches to the transfer that is still running,
// and a worker that died is picked up by a new one from its journal.

const fs = require("node:fs");
const path = require("node:path");

// ---- an OPFS stand-in ----------------------------------------------------

const files = new Map(); // path -> { data: Uint8Array, mtime: number, open: number }

const entry = (name, create) => {
  let file = files.get(name);
  if (!file) {
    if (!create) throw new Error(`NotFoundError: ${name}`);
    file = { data: new Uint8Array(0), mtime: Date.now(), open: 0 };
    files.set(name, file);
  }
  return file;
};

class SyncHandle {
  constructor(name) {
    this.name = name;
    this.closed = false;
    entry(name, true).open++;
  }
  file() {
    if (this.closed) throw new Error("InvalidStateError: the handle is closed");
    return entry(this.name, true);
  }
  getSize() {
    return this.file().data.length;
  }
  truncate(size) {
    const file = this.file();
    const next = new Uint8Array(size);
    next.set(file.data.subarray(0, Math.min(size, file.data.length)));
    file.data = next;
  }
  write(bytes, options = {}) {
    const file = this.file();
    const at = options.at || 0;
    if (at + bytes.length > file.data.length) {
      const next = new Uint8Array(at + bytes.length);
      next.set(file.data);
      file.data = next;
    }
    file.data.set(bytes, at);
    file.mtime = Date.now();
    return bytes.length;
  }
  read(buffer, options = {}) {
    const file = this.file();
    const at = options.at || 0;
    const n = Math.max(0, Math.min(buffer.length, file.data.length - at));
    buffer.set(file.data.subarray(at, at + n));
    return n;
  }
  flush() {
    this.file().mtime = Date.now();
  }
  close() {
    if (!this.closed) entry(this.name, true).open--;
    this.closed = true;
  }
}

class FileHandle {
  constructor(name) {
    this.kind = "file";
    this.name = name;
  }
  async getFile() {
    const file = files.get(this.name);
    if (!file) throw new Error(`NotFoundError: ${this.name}`);
    // a handle is fine while a sync access handle has it open; a page reads a
    // journal a worker is writing
    return {
      name: this.name,
      lastModified: file.mtime,
      async arrayBuffer() {
        return file.data.slice().buffer;
      },
    };
  }
  async createSyncAccessHandle() {
    return new SyncHandle(this.name);
  }
}

class DirectoryHandle {
  constructor(prefix) {
    this.kind = "directory";
    this.prefix = prefix;
  }
  async getFileHandle(name, options = {}) {
    const full = this.prefix + name;
    if (!options.create && !files.has(full)) throw new Error(`NotFoundError: ${full}`);
    return new FileHandle(full);
  }
  async getDirectoryHandle(name, options = {}) {
    return new DirectoryHandle(`${this.prefix}${name}/`);
  }
  async removeEntry(name) {
    const full = this.prefix + name;
    if (!files.has(full)) throw new Error(`NotFoundError: ${full}`);
    files.delete(full);
  }
  async *entries() {
    const seen = new Set();
    for (const name of files.keys()) {
      if (!name.startsWith(this.prefix)) continue;
      const rest = name.slice(this.prefix.length);
      if (!rest || rest.includes("/")) continue;
      if (seen.has(rest)) continue;
      seen.add(rest);
      yield [rest, new FileHandle(name)];
    }
  }
}

const root = new DirectoryHandle("");

globalThis.navigator = { storage: { async getDirectory() { return root; } } };

// ---- the harness ---------------------------------------------------------

let passed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { passed++; console.log(`ok   ${name}`); })
    .catch((e) => { failures.push(name); console.log(`FAIL ${name}\n     ${e && e.message || e}`); });
}

function assert(ok, message) {
  if (!ok) throw new Error(message || "assertion failed");
}

function same(a, b, message) {
  const A = Array.from(a), B = Array.from(b);
  const equal = A.length === B.length && A.every((v, i) => v === B[i]);
  if (!equal) throw new Error(`${message}: got [${A.slice(0, 8)}…] want [${B.slice(0, 8)}…]`);
}

function pattern(n, seed) {
  const bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) bytes[i] = (i * 31 + seed) & 0xff;
  return bytes;
}

/// What resume-worker.js writes: byte i is i & 0xff, so a hole in the file is
/// a byte that does not match its offset.
function counted(n) {
  return Uint8Array.from({ length: n }, (_, i) => i & 0xff);
}

/// Nowhere to resume from: with no `navigator.storage` the module has to say so
/// rather than pretend.
function withoutOpfs() {
  delete globalThis.navigator;
}

function withOpfs() {
  globalThis.navigator = { storage: { async getDirectory() { return root; } } };
}

// ---- the worker protocol, without a browser -----------------------------
//
// resume-worker.js speaks the same port protocol as v2-worker.js — hello on
// connect, start, resume, cancel — and journals the same way, so driving it
// here is driving the part of the client that survives a reload. What a
// browser adds is the `SharedWorker` that keeps the worker alive between the
// old page and the new one; everything after that is this.

const realSetInterval = global.setInterval;
let started = [];

function fakePort() {
  const messages = [];
  return {
    messages,
    port: { postMessage: (m) => messages.push(m), start() {}, onmessage: null },
  };
}

async function until(ok, what, timeout = 5000) {
  const deadline = Date.now() + timeout;
  for (;;) {
    if (await ok()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

/// A fresh copy of the worker module: a worker that never saw the earlier one.
async function loadWorker(opfsUrl, tag) {
  const source = fs
    .readFileSync(path.join(__dirname, "resume-worker.js"), "utf8")
    .replace('"../opfs.js"', JSON.stringify(opfsUrl));
  let connect = null;
  globalThis.self = {
    set onconnect(fn) { connect = fn; },
    get onconnect() { return connect; },
  };
  await import("data:text/javascript;base64," + Buffer.from(source).toString("base64") + `#${tag}`);
  if (!connect) throw new Error("the worker did not register an onconnect handler");
  return connect;
}

const lastProgress = (messages) => {
  const progress = messages.filter((m) => m && m.type === "progress");
  return progress.length ? progress[progress.length - 1] : null;
};


async function main() {
  const source = fs.readFileSync(path.join(__dirname, "..", "opfs.js"), "utf8");
  // opfs.js is an ES module and this file is not: import it from a data URL
  const opfsUrl = "data:text/javascript;base64," + Buffer.from(source).toString("base64");
  const opfs = await import(opfsUrl);
  const { Journal, Spool, Store, cleanupOlderThan, RECV_PREFIX } = opfs;

  await test("a journal round-trips", async () => {
    await Journal.create("round", { kind: "receive", link: "BLINK", phase: "starting", written: 12 });
    const entry = await Journal.read("round");
    assert(entry, "no journal");
    assert(entry.id === "round" && entry.kind === "receive" && entry.link === "BLINK", JSON.stringify(entry));
    assert(entry.written === 12, `written ${entry.written}`);
    assert(entry.seq === 1, `seq ${entry.seq}`);
  });

  await test("the newer of the two slots wins", async () => {
    const journal = await Journal.create("slots", { kind: "receive", written: 0 });
    journal.set({ written: 64 });
    await journal.flush();
    journal.set({ written: 128 });
    await journal.flush();
    const entry = await Journal.read("slots");
    assert(entry.written === 128, `written ${entry.written}`);
    // a and b alternate, so the two writes went to b and a
    assert(entry.slot === "a", `slot ${entry.slot}`);
  });

  await test("a torn slot falls back to the other one", async () => {
    const journal = await Journal.create("torn", { kind: "receive", written: 0 });
    journal.set({ written: 64 });
    await journal.flush();
    journal.set({ written: 128 });
    await journal.flush();
    // the write that was in flight when the process died: half a record
    files.get("bitmule-jobs/torn.a.json").data = new Uint8Array([0x7b, 0x22]);
    const entry = await Journal.read("torn");
    assert(entry && entry.written === 64, `read ${entry && entry.written}`);
  });

  await test("an unreadable journal is no journal", async () => {
    const journal = await Journal.create("broken", { kind: "receive" });
    journal.set({ written: 1 });
    await journal.flush();
    for (const slot of ["a", "b"]) files.get(`bitmule-jobs/broken.${slot}.json`).data = new Uint8Array([0x00]);
    assert((await Journal.read("broken")) === null, "a broken journal was read as a record");
  });

  await test("a file reopens with what was written to it", async () => {
    const name = `${RECV_PREFIX}file.part`;
    const store = await Store.create(1000, name);
    assert(store.resumable, "no OPFS file behind the store");
    store.write(0, pattern(300, 1));
    store.flush();
    // the process dies here: nothing is closed, nothing is tidied
    const again = await Store.reopen(name, 1000);
    assert(again, "the file was not there to reopen");
    assert(again.size === 1000, `size ${again.size}`);
    same(again.read(0, 8), pattern(8, 1), "the bytes behind the resume");
    assert(again.read(300, 4).every((b) => b === 0), "the file grew by itself");
  });

  await test("a write in the middle leaves the rest alone", async () => {
    const name = `${RECV_PREFIX}blocks.part`;
    const store = await Store.create(64, name);
    store.write(0, pattern(16, 2));
    store.write(32, pattern(16, 3));
    store.flush();
    const again = await Store.reopen(name, 64);
    same(again.read(0, 16), pattern(16, 2), "first block");
    same(again.read(32, 16), pattern(16, 3), "second block");
    assert(again.read(16, 16).every((b) => b === 0), "the gap is not a gap");
  });

  await test("a file that is gone reopens to nothing", async () => {
    assert((await Store.reopen(`${RECV_PREFIX}never.part`, 10)) === null, "reopened a file that never existed");
  });

  await test("a spool keeps its bytes across a reopen", async () => {
    const spool = await Spool.create("bitmule-recv-spool-s.part");
    spool.append(pattern(5, 4));
    spool.append(pattern(3, 5));
    spool.flush();
    assert(spool.length === 8, `length ${spool.length}`);
    const again = await Spool.reopen("bitmule-recv-spool-s.part");
    assert(again && again.length === 8, `length ${again && again.length}`);
    same(again.read(3, 4), [pattern(5, 4)[3], pattern(5, 4)[4], pattern(3, 5)[0], pattern(3, 5)[1]], "the bytes across the join");
  });

  await test("listing is newest first and removing forgets", async () => {
    const old = await Journal.create("old", { kind: "receive" });
    await new Promise((r) => setTimeout(r, 5));
    const fresh = await Journal.create("fresh", { kind: "receive" });
    const listed = (await Journal.list()).map((e) => e.id);
    assert(listed.indexOf("fresh") < listed.indexOf("old"), `order ${listed}`);
    await fresh.remove();
    assert((await Journal.read("fresh")) === null, "a removed journal was still readable");
    const again = (await Journal.list()).map((e) => e.id);
    assert(again.includes("old") && !again.includes("fresh"), `after remove ${again}`);
    await old.remove();
  });

  await test("housekeeping keeps what a journal claims", async () => {
    // one orphan from a visit that left nothing behind, one live job's file
    const orphan = await root.getFileHandle(`${RECV_PREFIX}orphan.part`, { create: true });
    const handle = await orphan.createSyncAccessHandle();
    handle.write(pattern(10, 6), { at: 0 });
    handle.close();
    files.get(`${RECV_PREFIX}orphan.part`).mtime = Date.now() - 48 * 3600 * 1000;
    const live = await Journal.create("live", { kind: "receive", phase: "transfer" });
    const kept = await root.getFileHandle(`${RECV_PREFIX}live.part`, { create: true });
    const keptHandle = await kept.createSyncAccessHandle();
    keptHandle.write(pattern(10, 7), { at: 0 });
    keptHandle.close();
    files.get(`${RECV_PREFIX}live.part`).mtime = Date.now() - 48 * 3600 * 1000;
    await cleanupOlderThan(24 * 3600 * 1000);
    assert(!files.has(`${RECV_PREFIX}orphan.part`), "an orphan from an old visit was kept");
    assert(files.has(`${RECV_PREFIX}live.part`), "a file a journal claims was removed");
    await live.remove();
  });

  await test("with no OPFS nothing pretends to be resumable", async () => {
    withoutOpfs();
    try {
      const store = await Store.create(32);
      assert(!store.resumable && store.handle === null, "a store without OPFS claims to resume");
      store.write(0, pattern(32, 8));
      same(store.read(0, 4), pattern(4, 8), "the memory fallback");
      assert((await Store.reopen("anything", 32)) === null, "reopened without OPFS");
      assert((await Journal.read("mem")) === null, "a journal without OPFS");
      assert((await Journal.list()).length === 0, "journals without OPFS");
    } finally {
      withOpfs();
    }
  });

  // ---- the worker protocol ----------------------------------------------

  // a transfer is 50 bytes every few milliseconds, so a test can catch it
  // half-way and look at what is on disk
  global.setInterval = (fn, ms) => {
    const timer = realSetInterval(fn, ms);
    started.push(timer);
    return timer;
  };
  try {
    await test("a reloaded page attaches to the transfer still running", async () => {
      const connect = await loadWorker(opfsUrl, "first");
      const first = fakePort();
      connect({ ports: [first.port] });
      first.port.onmessage({
        data: { type: "start", jobId: "live", size: 1000, chunk: 50, tick: 4, link: "BLINK" },
      });
      await until(() => {
        const p = lastProgress(first.messages);
        return p && p.bytes >= 200;
      }, "the first page to see progress");
      // the page goes away and a new one connects to the worker that carried on
      const second = fakePort();
      connect({ ports: [second.port] });
      const hello = second.messages.find((m) => m && m.type === "hello");
      assert(hello && hello.job === "receive" && hello.id === "live", `the new page was told ${JSON.stringify(hello)}`);
      assert(
        second.messages.some((m) => m && m.type === "state" && /carried on/.test(m.text)),
        "the new page was not told the transfer carried on",
      );
      await until(() => second.messages.some((m) => m && m.type === "done"), "the transfer to finish");
      const done = second.messages.find((m) => m && m.type === "done");
      assert(done.size === 1000, `done said ${done.size}`);
      await until(async () => (await Journal.read("live")) === null, "the journal to be forgotten");
      const store = await Store.reopen(`${RECV_PREFIX}live.part`, 1000);
      same(store.read(0, 1000), counted(1000), "the bytes of the transfer across a reload");
    });

    await test("a worker that died is picked up from its journal", async () => {
      const connect = await loadWorker(opfsUrl, "second");
      const first = fakePort();
      connect({ ports: [first.port] });
      first.port.onmessage({
        data: { type: "start", jobId: "cut", size: 2000, chunk: 50, tick: 4, link: "BLINK" },
      });
      await until(() => {
        const p = lastProgress(first.messages);
        return p && p.bytes >= 300;
      }, "progress before the crash");
      // nothing tells the worker it is going away: its timers just stop
      for (const timer of started) clearInterval(timer);
      started = [];
      const entry = await Journal.read("cut");
      assert(entry && entry.written > 0 && entry.written < 2000, `the journal says ${entry && entry.written}`);

      const again = await loadWorker(opfsUrl, "third");
      const page = fakePort();
      again({ ports: [page.port] });
      const hello = page.messages.find((m) => m && m.type === "hello");
      assert(hello && hello.job === null, `the new worker thought it held ${JSON.stringify(hello)}`);
      page.port.onmessage({ data: { type: "resume", jobId: "cut" } });
      await until(
        () => page.messages.some((m) => m && m.type === "state" && /resumed from the journal at \d+/.test(m.text)),
        "the resume to say where it was",
      );
      const said = page.messages.find((m) => m && m.type === "state" && /resumed from the journal/.test(m.text));
      const from = Number(/at (\d+)/.exec(said.text)[1]);
      assert(from > 0 && from < 2000, `resumed at ${from}`);
      await until(() => page.messages.some((m) => m && m.type === "done"), "the resumed transfer to finish");
      await until(async () => (await Journal.read("cut")) === null, "the journal to be forgotten");
      const store = await Store.reopen(`${RECV_PREFIX}cut.part`, 2000);
      same(store.read(0, 2000), counted(2000), "the bytes after the resume");
    });
  } finally {
    global.setInterval = realSetInterval;
    for (const timer of started) clearInterval(timer);
    started = [];
  }

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) {
    console.log(failures.map((f) => `  - ${f}`).join("\n"));
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
