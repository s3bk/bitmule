'use strict';
// make-fixture.js — write an account record with the browser's own crypto, so
// the Rust side can be tested against a record it did not make.
//
//   node tests/make-fixture.js
//
// This is web/vault.js's create(), reduced to the parts that decide bytes:
// P-256 ECDH key pair exported as a JWK, PBKDF2-SHA-256 at 600000 iterations
// over a 16-byte salt, AES-256-GCM over the account JSON with the header as
// additional data.

const { webcrypto: c } = require('crypto');
const fs = require('fs');
const path = require('path');

const b64u = (b) => Buffer.from(b).toString('base64url');
const utf8 = (s) => new TextEncoder().encode(s);
const ITERS = 600000;
const PASSWORD = 'correct horse battery staple';

async function main() {
  const kp = await c.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const pub = new Uint8Array(await c.subtle.exportKey('raw', kp.publicKey));
  const priv = await c.subtle.exportKey('jwk', kp.privateKey);

  const created = '2026-11-25T20:00:00.000Z';
  const salt = Buffer.alloc(16, 7);
  const rec = {
    v: 1,
    kind: 'bitmule-account',
    created,
    label: 'browser',
    plan: 'basic',
    pub: b64u(pub),
    kdf: { alg: 'PBKDF2-SHA-256', iters: ITERS, salt: b64u(salt) },
    cipher: { alg: 'AES-256-GCM', iv: '' },
    ct: '',
  };
  const acct = {
    v: 1,
    kind: 'bitmule-account-key',
    created,
    label: rec.label,
    pub: rec.pub,
    priv,
    invites: [],
    shares: [],
  };
  const aad = utf8(
    ['bitmule-account-v1', rec.created, rec.label, rec.plan, String(ITERS), rec.kdf.salt, rec.pub].join('|')
  );

  const base = await c.subtle.importKey('raw', utf8(PASSWORD), 'PBKDF2', false, ['deriveKey']);
  const key = await c.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = Buffer.alloc(12, 3);
  const ct = await c.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    utf8(JSON.stringify(acct))
  );
  rec.cipher.iv = b64u(iv);
  rec.ct = b64u(new Uint8Array(ct));

  const out = path.join(__dirname, 'fixtures', 'browser-account.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(rec, null, 2) + '\n');
  console.log('wrote ' + out + ' (password: ' + PASSWORD + ')');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
