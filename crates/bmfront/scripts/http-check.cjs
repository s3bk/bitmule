'use strict';
// http-check.cjs — GET a handful of paths through bitmule.net and print the
// status line, content-type, length and the first bytes of each body.
const https = require('https');
const host = process.argv[2] || 'bitmule.net';
const paths = process.argv.slice(3);
if (!paths.length) paths.push('/', '/app', '/pow');
const get = (p) =>
  new Promise((resolve) => {
    const req = https.get({ host, path: p, timeout: 15000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const b = Buffer.concat(chunks);
        resolve(
          `${p} → ${res.statusCode} ${res.headers['content-type'] || '-'} ${b.length}B ` +
            JSON.stringify(b.slice(0, 80).toString('latin1').replace(/\s+/g, ' '))
        );
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => resolve(`${p} → ERR ${e.code || e.message}`));
  });
(async () => {
  for (const p of paths) console.log(await get(p));
})();
