'use strict';
// ws-check.cjs — say hello to the relay through bitmule.net and see whether the
// upgrade survives bmfront: 101 means the tunnel works, anything else means the
// request got there but not the upgrade.
const tls = require('tls');
const crypto = require('crypto');
const host = process.argv[2] || 'bitmule.net';
const path = process.argv[3] || '/ws/create';
const key = crypto.randomBytes(16).toString('base64');
const s = tls.connect({ host, port: 443, servername: host }, () => {
  s.write(
    `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\n` +
      `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
  );
});
let out = '';
let done = false;
const show = (tag) => {
  if (done) return;
  done = true;
  console.log(tag, JSON.stringify(out.slice(0, 800)));
  s.destroy();
};
s.on('data', (d) => {
  out += d.toString('latin1');
  if (out.includes('\r\n\r\n')) show('HEAD');
});
s.on('end', () => show('END'));
s.on('error', (e) => console.log('ERR', e.code || e.message));
setTimeout(() => show('TIMEOUT'), 6000);
