// The mobile-data rules, run in node instead of a browser.
//
//     node web/test/netpolicy_test.js
//
// netpolicy.js decides whether an upload may start: the page reads the link
// (`navigator.connection`) and the stored setting, the worker asks the rules,
// and the answer is one of start / ask / hold. There is no DOM in any of that,
// so the table can be checked here rather than by holding a phone in one hand.
//
// What is checked: which `Connection.type` values count as metered; that a
// browser which will not say is treated as unmetered rather than nagged at;
// the whole decision table; and the one case that matters most — a device set
// never to use mobile data stays held even when something presses "start".

const fs = require("node:fs");
const path = require("node:path");

let passed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`ok   ${name}`);
  } catch (e) {
    failures.push(name);
    console.log(`FAIL ${name}\n     ${(e && e.message) || e}`);
  }
}

function assert(ok, message) {
  if (!ok) throw new Error(message || "assertion failed");
}

function eq(got, want, what) {
  if (got !== want) throw new Error(`${what}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
}

async function main() {
  const source = fs.readFileSync(path.join(__dirname, "..", "netpolicy.js"), "utf8");
  // netpolicy.js is an ES module and this file is not: import it from a data URL
  const url = "data:text/javascript;base64," + Buffer.from(source).toString("base64");
  const { MODE_ASK, MODE_NEVER, classifyNetwork, decide, isMetered, labelOf, normalizeMode } = await import(url);

  await test("a phone's own link is metered, tethering included", async () => {
    eq(classifyNetwork({ type: "cellular" }), "cellular", "cellular");
    eq(classifyNetwork({ type: "cellular", effectiveType: "4g" }), "cellular", "cellular 4g");
    eq(classifyNetwork({ type: "bluetooth" }), "cellular", "bluetooth tethering");
    eq(classifyNetwork({ type: "wimax" }), "cellular", "wimax");
    eq(classifyNetwork({ type: "CELLULAR" }), "cellular", "case");
    assert(isMetered("cellular"), "cellular is not metered");
  });

  await test("wi-fi and a cable are not", async () => {
    eq(classifyNetwork({ type: "wifi" }), "wifi", "wifi");
    eq(classifyNetwork({ type: "ethernet" }), "ethernet", "ethernet");
    assert(!isMetered("wifi") && !isMetered("ethernet"), "a wire was called metered");
  });

  await test("a browser that will not say is unknown, not metered", async () => {
    // Firefox and Safari have no `type` at all, and iOS has no API either: a
    // prompt on every upload there would be worse than the data it saves.
    eq(classifyNetwork(null), "unknown", "no navigator.connection");
    eq(classifyNetwork({}), "unknown", "an empty connection");
    eq(classifyNetwork({ type: "unknown" }), "unknown", "type unknown");
    eq(classifyNetwork({ type: "other" }), "unknown", "type other");
    eq(classifyNetwork({ type: "something-new" }), "unknown", "a type from the future");
    eq(decide({ network: "unknown", mode: MODE_NEVER }), "start", "unknown held the upload");
  });

  await test("no link at all is offline, and not the mobile-data rule's business", async () => {
    eq(classifyNetwork({ type: "none" }), "offline", "type none");
    eq(decide({ network: "offline", mode: MODE_ASK }), "start", "offline was held");
  });

  await test("the setting has two positions and anything else is the default", async () => {
    eq(normalizeMode(MODE_NEVER), "never", "never");
    eq(normalizeMode(MODE_ASK), "ask", "ask");
    eq(normalizeMode("always"), "ask", "an unknown word");
    eq(normalizeMode(null), "ask", "nothing stored");
    eq(normalizeMode(undefined), "ask", "undefined");
  });

  await test("off mobile data an upload starts by itself, whatever the setting", async () => {
    for (const mode of [MODE_ASK, MODE_NEVER]) {
      for (const network of ["wifi", "ethernet"]) {
        eq(decide({ network, mode }), "start", `${network}/${mode}`);
      }
    }
  });

  await test("on mobile data it asks, unless it has been pressed", async () => {
    eq(decide({ network: "cellular", mode: MODE_ASK }), "ask", "unpressed");
    eq(decide({ network: "cellular", mode: MODE_ASK, consented: false }), "ask", "explicitly unpressed");
    eq(decide({ network: "cellular", mode: MODE_ASK, consented: true }), "start", "pressed");
  });

  await test("never means never, press or no press", async () => {
    eq(decide({ network: "cellular", mode: MODE_NEVER }), "hold", "unpressed");
    // the press is the page's to send, and a stale one must not get round the
    // setting: consent belongs to one transfer on one link, not to the device
    eq(decide({ network: "cellular", mode: MODE_NEVER, consented: true }), "hold", "pressed anyway");
  });

  await test("a press is about one link, not the next one", async () => {
    let mode = MODE_ASK, consented = true, network = "cellular";
    eq(decide({ network, mode, consented }), "start", "pressed on mobile data");
    // the link changes: the consent it was given for is spent with the bytes it
    // was about, so the worker asks again
    consented = false;
    network = "wifi";
    eq(decide({ network, mode, consented }), "start", "carried on over wi-fi");
    network = "cellular";
    eq(decide({ network, mode, consented }), "ask", "fell back to mobile data unpressed");
  });

  await test("the link is named the way the prompt says it", async () => {
    eq(labelOf("cellular"), "mobile data", "cellular");
    eq(labelOf("wifi"), "Wi-Fi", "wifi");
    eq(labelOf("unknown"), "Wi-Fi", "what we cannot see");
  });

  await test("a decision with nothing said is a start", async () => {
    eq(decide(), "start", "no arguments");
    eq(decide({}), "start", "an empty question");
  });

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
