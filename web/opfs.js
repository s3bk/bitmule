// Where a transfer keeps its bytes and its memory.
//
// Three things live in OPFS (the origin's private file system), so that a
// transfer outlives the page that started it:
//
//   bitmule-recv-<job>.part   the received file, written in place at its offset
//   bitmule-recv-spool-<job>  bytes whose length is not known yet, append only
//   bitmule-jobs/<job>.json   the journal: what it was, how far it got
//
// The rule that makes a resume safe: bytes are written and flushed before the
// journal claims them. A journal never says more than the file holds, so the
// worst a crash can do is make us fetch a few blocks again.
//
// Every class here falls back to memory when there is no OPFS; then there is
// nothing to resume from, which the caller can see because `Store.resumable`
// and `Journal.durable` are false.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const JOBS_DIR = "bitmule-jobs";
export const RECV_PREFIX = "bitmule-recv-";
export const SPOOL_PREFIX = "bitmule-recv-spool-";

export async function opfsRoot() {
  try {
    return await navigator.storage.getDirectory();
  } catch {
    return null;
  }
}

async function jobsDir(create) {
  const root = await opfsRoot();
  if (!root) return null;
  try {
    return await root.getDirectoryHandle(JOBS_DIR, { create });
  } catch {
    return null;
  }
}

// ---- the received file ---------------------------------------------------

/// The file being assembled. OPFS where there is one (a real file, not the
/// heap), memory otherwise. Writes go straight to their offset, so a resumed
/// job rewrites only the blocks it is missing.
export class Store {
  /// A new file of `size` bytes, at `name` when one is given (a resumable job
  /// names it after itself, so the next worker can find it).
  static async create(size, name) {
    const store = new Store(size, name || `${RECV_PREFIX}${crypto.randomUUID()}.part`);
    const root = await opfsRoot();
    if (root) {
      try {
        const file = await root.getFileHandle(store.name, { create: true });
        store.handle = await file.createSyncAccessHandle();
        store.handle.truncate(size);
        store.fileHandle = file;
        store.resumable = true;
        return store;
      } catch {
        store.handle = null;
      }
    }
    store.memory = new Uint8Array(size);
    return store;
  }

  /// The file a previous job left behind. Never truncates: its length is the
  /// bytes that are already on disk.
  static async reopen(name, size) {
    const store = new Store(size, name);
    const root = await opfsRoot();
    if (root) {
      try {
        const file = await root.getFileHandle(name);
        store.handle = await file.createSyncAccessHandle();
        store.fileHandle = file;
        store.size = store.handle.getSize();
        store.resumable = true;
        return store;
      } catch {
        return null; // the file is gone: nothing to resume
      }
    }
    return null;
  }

  constructor(size, name) {
    this.size = size;
    this.name = name;
    this.handle = null;
    this.fileHandle = null;
    this.memory = null;
    this.resumable = false;
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

  /// Make what was written durable before anyone is told about it.
  flush() {
    if (this.handle) this.handle.flush();
  }

  /// The finished file, for the page to save. The OPFS handle is closed here;
  /// the entry stays until cleanup removes it.
  async file(name, type) {
    if (!this.handle) return new File([this.memory], name, { type });
    this.handle.flush();
    this.handle.close();
    this.handle = null;
    const file = await this.fileHandle.getFile();
    return new File([file], name, { type });
  }

  async discard() {
    if (this.handle) {
      try { this.handle.close(); } catch {}
      this.handle = null;
    }
    this.memory = null;
    const root = await opfsRoot();
    if (root && this.name) {
      try { await root.removeEntry(this.name); } catch {}
    }
  }
}

// ---- bytes whose length is not known yet ---------------------------------

/// Append-only bytes in arrival order: the relay stream of a streaming
/// transfer until its manifest (and key) arrives, or what a streaming sender
/// has read of a source it can only read once.
export class Spool {
  static async create(name) {
    const spool = new Spool(name || `${SPOOL_PREFIX}${crypto.randomUUID()}`);
    const root = await opfsRoot();
    if (root) {
      try {
        const file = await root.getFileHandle(spool.name, { create: true });
        spool.handle = await file.createSyncAccessHandle();
        spool.handle.truncate(0);
        spool.resumable = true;
        return spool;
      } catch {
        spool.handle = null;
      }
    }
    return spool;
  }

  /// The spool a previous job left behind.
  static async reopen(name) {
    const spool = new Spool(name);
    const root = await opfsRoot();
    if (!root) return null;
    try {
      const file = await root.getFileHandle(name);
      spool.handle = await file.createSyncAccessHandle();
      spool.resumable = true;
      spool.length = spool.handle.getSize();
      return spool;
    } catch {
      return null;
    }
  }

  constructor(name) {
    this.name = name;
    this.length = 0;
    this.handle = null;
    this.resumable = false;
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

  flush() {
    if (this.handle) this.handle.flush();
  }

  async discard() {
    if (this.handle) {
      try { this.handle.close(); } catch {}
      this.handle = null;
    }
    this.parts = [];
    this.length = 0;
    const root = await opfsRoot();
    if (root && this.name) {
      try { await root.removeEntry(this.name); } catch {}
    }
  }
}

// ---- the journal ---------------------------------------------------------

/// What a job is, so that a worker that never saw it start can carry on.
///
/// One small record per job, kept in two slots (`<id>.a.json`, `<id>.b.json`)
/// that are written alternately with a sequence number. A crash during a write
/// can tear one slot; the other still holds the last good record, and a reader
/// takes the higher sequence of the two. Nothing keeps either file open, so a
/// page can read a journal that a running worker is writing.
export class Journal {
  static async create(id, data) {
    const journal = new Journal(id, data);
    await journal.flush();
    return journal;
  }

  constructor(id, data) {
    this.id = id;
    this.seq = data.seq || 0;
    this.data = { ...data, id, created: data.created || Date.now(), updated: Date.now() };
    this.removed = false;
    // writes go out one at a time, in the order they were asked for: a flush
    // that was still in flight when the job ended cannot put the file back
    this.queue = Promise.resolve();
  }

  /// Record fields; nothing reaches the disk until flush().
  set(patch) {
    Object.assign(this.data, patch);
    this.data.updated = Date.now();
    return this;
  }

  /// Write the record. Cheap enough to call whenever the data is durable, and
  /// it never throws at the caller: a journal that cannot be written means no
  /// resume, not a failed transfer.
  flush() {
    this.queue = this.queue.then(() => this.write());
    return this.queue;
  }

  /// The job is over (done, failed or cancelled): forget it. Queued behind any
  /// write still on its way out, so what lands last is the removal.
  remove() {
    this.removed = true;
    this.queue = this.queue.then(() => this.erase());
    return this.queue;
  }

  async write() {
    if (this.removed) return;
    const dir = await jobsDir(true);
    if (!dir || this.removed) return;
    const seq = ++this.seq;
    const slot = seq % 2 ? "a" : "b";
    try {
      const file = await dir.getFileHandle(`${this.id}.${slot}.json`, { create: true });
      const handle = await file.createSyncAccessHandle();
      try {
        const bytes = enc.encode(JSON.stringify({ ...this.data, seq, slot }));
        handle.truncate(0);
        handle.write(bytes, { at: 0 });
        handle.flush();
      } finally {
        handle.close();
      }
    } catch {}
  }

  async erase() {
    const dir = await jobsDir(false);
    if (!dir) return;
    for (const slot of ["a", "b"]) {
      try { await dir.removeEntry(`${this.id}.${slot}.json`); } catch {}
    }
  }

  /// The record of a job, or null.
  static async read(id) {
    const dir = await jobsDir(false);
    return dir ? readSlots(dir, id) : null;
  }

  /// Every job a worker left behind, newest first.
  static async list() {
    const dir = await jobsDir(false);
    if (!dir) return [];
    const ids = new Set();
    try {
      for await (const [name, handle] of dir.entries()) {
        if (handle.kind !== "file") continue;
        const m = /^(.+)\.(a|b)\.json$/.exec(name);
        if (m) ids.add(m[1]);
      }
    } catch {}
    const out = [];
    for (const id of ids) {
      const entry = await readSlots(dir, id);
      if (entry) out.push(entry);
    }
    return out.sort((a, b) => (b.updated || 0) - (a.updated || 0));
  }
}

/// The newer of a job's two slots that parses.
async function readSlots(dir, id) {
  let best = null;
  for (const slot of ["a", "b"]) {
    try {
      const file = await dir.getFileHandle(`${id}.${slot}.json`);
      const entry = JSON.parse(dec.decode(await (await file.getFile()).arrayBuffer()));
      if (!best || (entry.seq || 0) > (best.seq || 0)) best = entry;
    } catch {}
  }
  return best;
}

// ---- housekeeping --------------------------------------------------------

/// Drop what earlier visits left behind: files and journals older than `age`.
/// Nothing in use is that old; what is in use is held by a live worker and its
/// mtime is being updated as it goes.
export async function cleanupOlderThan(age) {
  const root = await opfsRoot();
  if (!root) return;
  const cutoff = Date.now() - age;
  const keep = new Set((await Journal.list()).filter((j) => !j.live).map((j) => j.id));
  try {
    for await (const [name, handle] of root.entries()) {
      if (handle.kind !== "file") continue;
      if (!name.startsWith(RECV_PREFIX) && !name.startsWith(SPOOL_PREFIX)) continue;
      // a job with a journal is a transfer somebody may still resume
      let belongsToJob = false;
      for (const id of keep) if (name.includes(id)) belongsToJob = true;
      if (belongsToJob) continue;
      let file;
      try { file = await handle.getFile(); } catch { continue; } // in use
      if (file.lastModified < cutoff) {
        try { await root.removeEntry(name); } catch {}
      }
    }
    const dir = await jobsDir(false);
    if (dir) {
      for await (const [name, handle] of dir.entries()) {
        if (handle.kind !== "file") continue;
        let file;
        try { file = await handle.getFile(); } catch { continue; }
        if (file.lastModified < cutoff) {
          try { await dir.removeEntry(name); } catch {}
        }
      }
    }
  } catch {}
}
