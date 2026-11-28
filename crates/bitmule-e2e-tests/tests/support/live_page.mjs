// The browser half of the live-site test suite: open a bitmule live link in a
// real Chromium, press "Receive in this browser", and say what happened.
//
// The Rust test in tests/live_site.rs starts the site and the sender and calls
// this script once per browser it wants. Keeping the browser here rather than
// in Rust means no webdriver: playwright-core drives the Chromium that is
// already installed, and the test only reads one JSON line.
//
//   node live_page.mjs --url <link> [--expect ok|offline] [--download <dir>]
//                      [--timeout <ms>]
//
// Written to stdout, one line: {"ok":bool,"outcome":"ok"|"offline"|"error"|
// "timeout","text":"…","saved":"<path>"|null,"name":null|"…","errors":[…]}
// Exit status is 0 when the page did what --expect asked for (default ok).
'use strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';

const require = createRequire(import.meta.url);
const core =
  process.env.BITMULE_PLAYWRIGHT || '/home/hematite/IBA/FYP/Kenna/agent/node_modules/playwright-core';
const { chromium } = require(core);

const arg = (name, fallback = null) => {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
};

const url = arg('url');
const expect = arg('expect', 'ok');
const downloadDir = arg('download');
const timeout = Number(arg('timeout', '90000'));
const chrome =
  process.env.BITMULE_CHROME ||
  path.join(process.env.HOME || '', '.cache/ms-playwright/chromium-1148/chrome-linux/chrome');

const report = { ok: false, outcome: 'error', text: '', saved: null, name: null, errors: [] };

if (!url) {
  report.errors.push('--url is required');
  console.log(JSON.stringify(report));
  process.exit(2);
}
if (!fs.existsSync(chrome)) {
  report.errors.push(`no chromium at ${chrome} (set BITMULE_CHROME)`);
  console.log(JSON.stringify(report));
  process.exit(2);
}

const browser = await chromium.launch({
  executablePath: chrome,
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
});

// One way out, so the browser is always closed and exactly one JSON line is
// printed whatever happens.
let code = 1;
try {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  page.on('pageerror', (e) => report.errors.push('pageerror: ' + String(e.message || e)));
  page.on('console', (m) => {
    if (m.type() === 'error') report.errors.push('console: ' + m.text());
  });

  await page.goto(url, { waitUntil: 'domcontentloaded' });

  const take = page.getByRole('button', { name: 'Receive in this browser' });
  if (!(await take.count())) {
    report.errors.push('no "Receive in this browser" button: the page did not offer a browser receive');
    report.text = ((await page.locator('#status').textContent().catch(() => '')) || '').trim();
    code = 1;
  } else {
    await take.first().click();

    // The page says one of three things: it is receiving, it is done ("checksum
    // holds"), or it stopped with a reason. Wait for the last two.
    const status = page.locator('#status');
    let text = '';
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      text = ((await status.textContent().catch(() => '')) || '').trim();
      if (/checksum holds/i.test(text) || /transfer stopped|is not online|cannot receive/i.test(text)) {
        break;
      }
      await page.waitForTimeout(250);
    }
    report.text = text;

    if (/checksum holds/i.test(text)) {
      report.outcome = 'ok';
      const save = page.getByRole('button', { name: /^Save / });
      report.name = ((await save.first().textContent().catch(() => '')) || '').replace(/^Save\s+/, '') || null;
      if (downloadDir) {
        const [download] = await Promise.all([
          page.waitForEvent('download', { timeout: 30000 }),
          save.first().click(),
        ]);
        const target = path.join(downloadDir, download.suggestedFilename());
        await download.saveAs(target);
        report.saved = target;
      }
    } else if (/transfer stopped|is not online/i.test(text)) {
      report.outcome = 'offline';
    } else {
      report.outcome = 'timeout';
    }
    report.ok = report.outcome === expect;
    code = report.ok ? 0 : 1;
  }
} catch (e) {
  report.errors.push(String((e && e.stack) || e));
  code = 1;
} finally {
  await browser.close().catch(() => {});
}
console.log(JSON.stringify(report));
process.exit(code);
