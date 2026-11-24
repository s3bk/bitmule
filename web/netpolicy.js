// Who may use the mobile network for an upload.
//
// A device away from its charger is usually on somebody's data plan, and an
// upload is the one thing the page does that can spend a lot of it. The rule
// the client follows is not "no uploads on cellular" but "no upload that
// starts by itself": on a metered link the upload waits for a press that says
// how much it is, unless the device is set never to use mobile data at all — in
// which case it waits for Wi-Fi and there is no press that would start it.
//
// Everything here is pure — no DOM, no storage, no `navigator` — because both
// sides of the worker boundary have to agree on the answer, and because the
// rules are worth a test that does not need a browser
// (web/test/netpolicy_test.js). The page reads `navigator.connection` and
// passes what it finds; the worker only sees `metered`.
//
// The Network Information API is not everywhere: Chromium has
// `navigator.connection.type`, Firefox and Safari do not, and on iOS there is no
// way at all to tell Wi-Fi from cellular from inside a page. There the link
// classifies as "unknown", which is deliberately *not* treated as metered — a
// prompt on every upload on a desktop would be worse than the data it saves —
// so on an iPhone neither position of the setting can bite. That is one of the
// reasons the native client asks the operating system instead (see
// notes/hosted-uploads-spec.md, "Client behaviour on metered networks").

export const MODE_ASK = "ask";
export const MODE_NEVER = "never";

// `Connection.type` values that are a phone's data plan behind a tether.
const METERED_TYPES = new Set(["cellular", "wimax", "bluetooth"]);

/// The link, as well as a page can tell: "cellular", "wifi", "ethernet",
/// "offline", or "unknown" when the browser will not say.
export function classifyNetwork(connection) {
  const type = connection && typeof connection.type === "string" ? connection.type.toLowerCase() : "";
  if (!type) return "unknown";
  if (METERED_TYPES.has(type)) return "cellular";
  if (type === "none") return "offline";
  if (type === "wifi") return "wifi";
  if (type === "ethernet") return "ethernet";
  // "other" and "unknown" are the browser saying it does not know; anything new
  // in the spec lands here too, which is the honest answer.
  return "unknown";
}

export function isMetered(network) {
  return network === "cellular";
}

/// How the network is called in a sentence the user reads.
export function labelOf(network) {
  return isMetered(network) ? "mobile data" : "Wi-Fi";
}

/// The stored setting, whatever it holds: anything but a known word is the
/// default. "ask" is the default because it costs one press and no surprise.
export function normalizeMode(value) {
  return value === MODE_NEVER ? MODE_NEVER : MODE_ASK;
}

/// What the upload may do now:
///   "start" — begin, or carry on
///   "ask"   — wait for a press that names the size and the link
///   "hold"  — wait for another link; there is nothing to press
///
/// `consented` is the press, and it belongs to one transfer on one link: a
/// transfer that falls back to Wi-Fi and then to cellular again asks again,
/// because the amount it is about to spend is a new one.
export function decide({ network, mode, consented = false } = {}) {
  if (!isMetered(network)) return "start";
  if (normalizeMode(mode) === MODE_NEVER) return "hold";
  return consented ? "start" : "ask";
}
