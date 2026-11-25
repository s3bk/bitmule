'use strict';
// pow-url.cjs — print a solved /ws/create URL for a fresh session, so a plain
// curl can be pointed at the relay itself.
const https = require('https');
const crypto = require('crypto');
const SECRET = Buffer.from('bitmule-v1-websocket-abcde123456', 'latin1');
const host = process.argv[2] || 'bitmule.net';
const base = process.argv[3] || `https://${host}`;
const get = (p) =>
  new Promise((resolve, reject) => {
    require('https')
      .get({ host, path: p }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString())));
      })
      .on('error', reject);
  });
function lz(buf) {
  let n = 0;
  for (const b of buf) {
    const k = b === 0 ? 8 : Math.clz32(b) - 24;
    n += k;
    if (k !== 8) break;
  }
  return n;
}
(async () => {
  const { difficulty, magic } = await get('/pow');
  const sid = crypto.randomBytes(32);
  const msg = Buffer.alloc(44);
  sid.copy(msg, 0);
  msg.writeUInt32LE(magic >>> 0, 40);
  let nonce = 0;
  for (; ; nonce++) {
    msg.writeBigUInt64LE(BigInt(nonce), 32);
    const h = crypto.createHash('sha256').update(msg).digest();
    for (let i = 0; i < 32; i++) h[i] ^= SECRET[i];
    if (lz(h) >= difficulty) break;
  }
  console.log(`${base}/ws/create?sid=${sid.toString('hex')}&magic=${magic}&pow=${nonce}`);
})();
