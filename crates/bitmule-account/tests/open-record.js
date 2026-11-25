'use strict';
// open-record.js — open an account record with the browser's own crypto and
// print what came out, which is vault.js's openRecord() without the UI.
//
//   node tests/open-record.js <record.json> <password>

const { webcrypto: c } = require('crypto');
const fs = require('fs');

const b64u = (b) => Buffer.from(b).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const utf8 = (s) => new TextEncoder().encode(s);

async function main() {
  const [file, password] = process.argv.slice(2);
  const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
  const parts = ['bitmule-account-v1', rec.created, rec.label || ''];
  if (rec.plan != null) parts.push(String(rec.plan));
  parts.push(String(rec.kdf.iters), rec.kdf.salt, rec.pub);
  const aad = utf8(parts.join('|'));

  const base = await c.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveKey']);
  const key = await c.subtle.deriveKey(
    { name: 'PBKDF2', salt: unb64u(rec.kdf.salt), iterations: rec.kdf.iters, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plain = await c.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64u(rec.cipher.iv), additionalData: aad },
    key,
    unb64u(rec.ct)
  );
  const acct = JSON.parse(new TextDecoder().decode(plain));

  // the private key in the ciphertext must be the one for the public header
  const priv = await c.subtle.importKey('jwk', acct.priv, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const jwk = await c.subtle.exportKey('jwk', priv);
  const pub = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);

  const ok = b64u(pub) === rec.pub;
  console.log(
    JSON.stringify(
      {
        label: acct.label,
        plan: rec.plan,
        account_id: acct.account_id ?? null,
        public_matches: ok,
        kind: acct.kind,
      },
      null,
      2
    )
  );
  if (!ok) process.exit(2);
}

main().catch((e) => {
  console.error('did not open: ' + (e && e.message));
  process.exit(1);
});
