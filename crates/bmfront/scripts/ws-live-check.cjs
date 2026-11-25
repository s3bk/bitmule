'use strict';
// ws-live-check.cjs — do what the browser's live mode does, through
// bitmule.net: GET /pow, solve it for a fresh session id, then upgrade
// /ws/create. A 101 means the relay is reachable under the app's origin and
// artisan's websocket bridge carries it.
const tls = require('tls');
const crypto = require('crypto');

const host = process.argv[2] || 'bitmule.net';
const SECRET = Buffer.from('bitmule-v1-websocket-abcde123456', 'latin1');

const get = (path) =>
  new Promise((resolve, reject) => {
    require('https')
      .get({ host, path }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString())));
      })
      .on('error', reject);
  });

function leadingZeroBits(buf) {
  let n = 0;
  for (const b of buf) {
    const lz = b === 0 ? 8 : Math.clz32(b) - 24;
    n += lz;
    if (lz !== 8) break;
  }
  return n;
}

function solve(sid, magic, difficulty) {
  // sha256(session_id[32] || nonce_le[8] || magic_le[4]), then XOR the digest
  // with the relay's SECRET; that many leading zero bits is the work.
  const msg = Buffer.alloc(44);
  sid.copy(msg, 0);
  msg.writeUInt32LE(magic >>> 0, 40);
  const t0 = Date.now();
  for (let nonce = 0; ; nonce++) {
    msg.writeBigUInt64LE(BigInt(nonce), 32);
    const h = crypto.createHash('sha256').update(msg).digest();
    for (let i = 0; i < 32; i++) h[i] ^= SECRET[i];
    if (leadingZeroBits(h) >= difficulty) {
      console.log(`solved: nonce=${nonce} in ${Date.now() - t0}ms`);
      return nonce;
    }
    if (nonce > 200_000_000) throw new Error('no solution');
  }
}

(async () => {
  const { difficulty, magic } = await get('/pow');
  console.log(`/pow through ${host}: difficulty=${difficulty} magic=${magic}`);
  const sid = crypto.randomBytes(32);
  const nonce = solve(sid, magic, difficulty);
  const path = `/ws/create?sid=${sid.toString('hex')}&magic=${magic}&pow=${nonce}`;
  const key = crypto.randomBytes(16).toString('base64');
  const s = tls.connect({ host, port: 443, servername: host }, () => {
    s.write(
      `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\n` +
        `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
  });
  let out = '';
  let done = false;
  const finish = (tag) => {
    if (done) return;
    done = true;
    console.log(tag, JSON.stringify(out.slice(0, 400)));
    s.destroy();
  };
  s.on('data', (d) => {
    out += d.toString('latin1');
    if (out.includes('\r\n\r\n')) finish('REPLY');
  });
  s.on('error', (e) => console.log('ERR', e.code || e.message));
  setTimeout(() => finish('TIMEOUT'), 15000);
})();
