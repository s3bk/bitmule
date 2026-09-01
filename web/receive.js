// bitmule receiver page.
//
// Flow:
//   1. Read session hex from location.hash (`#<64-hex>`). If absent, show
//      the paste-link fallback so a user who typed the URL by hand can
//      still enter one.
//   2. Open /ws/<hex> as role=receiver with a fresh receiver_id.
//   3. Send the receiver hello frame. The server accepts and, if the
//      sender is already in the room, our first frame relays to them —
//      which is what the sender UI waits on.
//   4. Stay connected. Actual chunk pipeline lands in the follow-up cut.

const CONFIG = {
  server:
    (window.BITMULE_SERVER && String(window.BITMULE_SERVER)) ||
    (location.protocol === "file:"
      ? "http://localhost:8443"
      : `${location.protocol}//${location.host}`),
};

const els = {
  paste: document.getElementById("paste"),
  pasteLink: document.getElementById("paste-link"),
  pasteOpen: document.getElementById("paste-open"),
  session: document.getElementById("session"),
  sessionState: document.getElementById("session-state"),
  sessionId: document.getElementById("session-id"),
  serverStatus: document.getElementById("server-status"),
  cancelBtn: document.getElementById("cancel-session"),
  queue: document.getElementById("queue"),
};

function setStatus(el, state, text) {
  el.textContent = text;
  el.classList.remove("pending", "ok", "err");
  el.classList.add(state);
}

function isHex64(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

function serverToWs(url) {
  return url.replace(/^http/, "ws").replace(/\/$/, "");
}

function newReceiverIdHex() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function extractSessionHex(input) {
  // Accept: raw 64-hex OR any URL with #<64-hex> at the tail.
  if (isHex64(input)) return input;
  try {
    const u = new URL(input);
    const hash = u.hash.replace(/^#/, "");
    if (isHex64(hash)) return hash;
  } catch {}
  // Also allow copy-pasting just the hash portion including the #.
  const stripped = input.replace(/^#/, "").trim();
  if (isHex64(stripped)) return stripped;
  return null;
}

let activeSession = null;

function showPasteFallback() {
  els.paste.hidden = false;
  els.session.hidden = true;
}

function showSessionPanel(sessionHex) {
  els.paste.hidden = true;
  els.session.hidden = false;
  els.sessionId.textContent = sessionHex.slice(0, 8) + "…";
  setStatus(els.serverStatus, "pending", "connecting…");
  els.sessionState.textContent = "connecting…";
  els.sessionState.classList.remove("transferring");
}

function connect(sessionHex) {
  if (activeSession) {
    activeSession.close();
    activeSession = null;
  }

  showSessionPanel(sessionHex);

  const receiverId = newReceiverIdHex();
  const wsUrl = `${serverToWs(CONFIG.server)}/ws/${sessionHex}`;
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    setStatus(els.serverStatus, "err", "url invalid");
    els.sessionState.textContent = `couldn't open socket: ${err.message}`;
    return;
  }

  const session = {
    sessionHex,
    receiverId,
    ws,
    close() {
      try {
        ws.close();
      } catch {}
    },
  };
  activeSession = session;

  ws.addEventListener("open", () => {
    setStatus(els.serverStatus, "ok", "connected");
    ws.send(
      JSON.stringify({
        type: "hello",
        role: "receiver",
        receiver_id: receiverId,
      })
    );
    // The server relays this to the sender; the sender's UI moves off
    // "waiting for receiver…" the moment it lands.
    ws.send(
      JSON.stringify({
        type: "peer_hello",
        receiver_id: receiverId,
      })
    );
    els.sessionState.textContent = "connected — waiting for sender to start transfer";
    els.sessionState.classList.add("transferring");
  });

  ws.addEventListener("message", (ev) => {
    if (activeSession !== session) return;
    // Any sender-relayed frame lands here. Real pipeline attaches in a
    // follow-up (SDP + KEX + chunk stream). For now, surface it so the
    // user sees the wire is alive.
    console.info("relay frame from sender:", ev.data);
  });

  ws.addEventListener("close", () => {
    if (activeSession !== session) return;
    setStatus(els.serverStatus, "err", "closed");
    if (!els.sessionState.classList.contains("transferring")) {
      els.sessionState.textContent = "socket closed";
    }
  });

  ws.addEventListener("error", () => {
    if (activeSession !== session) return;
    setStatus(els.serverStatus, "err", "unreachable");
    els.sessionState.textContent = "server unreachable";
  });
}

// ---- entry --------------------------------------------------------------

els.pasteOpen.addEventListener("click", () => {
  const hex = extractSessionHex(els.pasteLink.value.trim());
  if (!hex) {
    els.sessionState = els.sessionState || document.createElement("div");
    // No session panel yet — show inline error in the paste panel.
    const help = els.paste.querySelector(".session-state");
    if (help) {
      help.textContent = "That doesn't look like a bitmule link (need a 64-hex session).";
    }
    return;
  }
  // Push the hex into the URL so a refresh re-uses it.
  history.replaceState(null, "", "#" + hex);
  connect(hex);
});

els.cancelBtn.addEventListener("click", () => {
  if (activeSession) {
    activeSession.close();
    activeSession = null;
  }
  history.replaceState(null, "", location.pathname);
  showPasteFallback();
});

(function boot() {
  const hex = location.hash.replace(/^#/, "");
  if (isHex64(hex)) {
    connect(hex);
  } else {
    showPasteFallback();
  }
})();
