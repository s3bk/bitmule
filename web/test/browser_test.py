#!/usr/bin/env python3
"""The web client in a real Chrome (selenium) against the CLI and itself,
through a local bitmule-server that also serves web/.

    python3 web/test/browser_test.py [name-filter]

Needs selenium, a built `bitmule` and `bitmule-server` (target/release, or
BITMULE_BIN / BITMULE_SERVER_BIN). Every wait is bounded by TIMEOUT.
"""
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService

ROOT = Path(__file__).resolve().parents[2]
SERVER_BIN = os.environ.get("BITMULE_SERVER_BIN", str(ROOT / "target/release/bitmule-server"))
CLI_BIN = os.environ.get("BITMULE_BIN", str(ROOT / "target/release/bitmule"))
TIMEOUT = 10  # seconds, for every wait
BLOCK = 2 * 1024 * 1024 - 16  # fountain block payload


def _major(binary):
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10).stdout
        return re.search(r"(\d+)\.\d+\.\d+", out).group(1)
    except Exception:
        return None


def chrome_pair():
    """(chrome, chromedriver) that match: BITMULE_CHROME / BITMULE_CHROMEDRIVER, else the
    system pair if their versions agree, else a pair from selenium-manager's cache."""
    chrome, driver = os.environ.get("BITMULE_CHROME"), os.environ.get("BITMULE_CHROMEDRIVER")
    if chrome and driver:
        return chrome, driver
    system_driver = shutil.which("chromedriver")
    for c in ["/opt/google/chrome/chrome", "/usr/bin/google-chrome-stable"]:
        if system_driver and os.path.exists(c) and _major(c) and _major(c) == _major(system_driver):
            return c, system_driver
    base = Path.home() / ".cache/selenium"
    for d in sorted((base / "chromedriver/linux64").glob("*"), reverse=True):
        c = base / "chrome/linux64" / d.name / "chrome"
        if (d / "chromedriver").exists() and c.exists():
            return str(c), str(d / "chromedriver")
    return chrome, driver


def firefox_pair():
    """(firefox, geckodriver): BITMULE_FIREFOX / BITMULE_GECKODRIVER, else /opt/firefox and
    selenium-manager's cache (`selenium-manager --browser firefox`)."""
    firefox = os.environ.get("BITMULE_FIREFOX") or ("/opt/firefox/firefox" if os.path.exists("/opt/firefox/firefox") else None)
    driver = os.environ.get("BITMULE_GECKODRIVER")
    if not driver:
        found = sorted((Path.home() / ".cache/selenium/geckodriver/linux64").glob("*/geckodriver"), reverse=True)
        driver = str(found[0]) if found else None
    return firefox, driver


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Server:
    def __init__(self):
        port = random.randint(20000, 40000)
        self.url = f"http://127.0.0.1:{port}"
        self.proc = subprocess.Popen(
            [SERVER_BIN, "--bind", f"127.0.0.1:{port}", "--no-stun", "--web-dir", str(ROOT / "web")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(lambda: self._up(), "server start")

    def _up(self):
        import urllib.request
        try:
            return urllib.request.urlopen(f"{self.url}/pow", timeout=1).status == 200
        except Exception:
            return False

    def stop(self):
        self.proc.kill()


class Cli:
    """The CLI; collects its output and finds the first match of a pattern in it."""

    def __init__(self, server, *args, stdin_data=None, piece=300_000, pause=0.03):
        self.out = ""
        self.proc = subprocess.Popen([CLI_BIN, "--server", server.url, *args],
                                     stdin=subprocess.PIPE if stdin_data is not None else None,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=stdin_data is None)
        threading.Thread(target=self._read, daemon=True).start()
        if stdin_data is not None:
            threading.Thread(target=self._feed, args=(stdin_data, piece, pause), daemon=True).start()

    def _feed(self, data, piece, pause):
        """Feed stdin in pieces, as a producer that is still working."""
        try:
            for at in range(0, len(data), piece):
                self.proc.stdin.write(data[at:at + piece])
                self.proc.stdin.flush()
                time.sleep(pause)
            self.proc.stdin.close()
        except (BrokenPipeError, ValueError):
            pass

    def _read(self):
        for line in self.proc.stdout:
            self.out += line if isinstance(line, str) else line.decode("utf-8", "replace")

    def find(self, pattern, what):
        found = []
        def check():
            m = re.search(pattern, self.out)
            if m:
                found.append(m.group(1))
            return bool(found)
        wait_for(check, what, extra=lambda: f"cli output:\n{self.out}")
        return found[0]

    def wait(self):
        try:
            code = self.proc.wait(TIMEOUT)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"cli did not exit; output:\n{self.out}")
        assert code == 0, f"cli exited {code}; output:\n{self.out}"

    def kill(self):
        self.proc.kill()


def wait_for(check, what, extra=None):
    end = time.time() + TIMEOUT
    while time.time() < end:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"timeout ({TIMEOUT}s): {what}" + (f"\n{extra()}" if extra else ""))


class Page:
    """A browser (Chrome, or Firefox with BITMULE_BROWSER=firefox)."""

    def __init__(self, server, downloads=None):
        if os.environ.get("BITMULE_BROWSER", "chrome") == "firefox":
            self.driver = self._firefox(downloads)
        else:
            self.driver = self._chrome(downloads)
        self.driver.set_script_timeout(TIMEOUT)
        self.driver.set_page_load_timeout(TIMEOUT)
        self.server = server

    @staticmethod
    def _chrome(downloads):
        options = Options()
        for arg in ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                    # real host candidates, not mDNS names, so the CLI's WebRTC can reach us
                    "--disable-features=WebRtcHideLocalIpsWithMdns"]:
            options.add_argument(arg)
        if downloads:
            options.add_experimental_option("prefs", {"download.default_directory": str(downloads),
                                                      "download.prompt_for_download": False})
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
        chrome, driver = chrome_pair()
        if chrome:
            options.binary_location = chrome
        return webdriver.Chrome(options=options, service=Service(executable_path=driver) if driver else None)

    @staticmethod
    def _firefox(downloads):
        options = FirefoxOptions()
        options.add_argument("-headless")
        # real host candidates, not mDNS names, so the CLI's WebRTC can reach us
        options.set_preference("media.peerconnection.ice.obfuscate_host_addresses", False)
        options.set_preference("media.peerconnection.ice.loopback", True)
        if downloads:
            options.set_preference("browser.download.folderList", 2)
            options.set_preference("browser.download.dir", str(downloads))
            options.set_preference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream,application/zip")
        firefox, driver = firefox_pair()
        if firefox:
            options.binary_location = firefox
        return webdriver.Firefox(options=options, service=FirefoxService(executable_path=driver) if driver else None)

    def open(self, path="/test/page.html", ready="window.testReady"):
        self.driver.get(self.server.url + path)
        wait_for(lambda: self.driver.execute_script(f"return !!({ready});"), "page ready")

    def run(self, body, *args):
        """Run async JS; `args` are its `args`; returns what it returns."""
        return self.driver.execute_async_script(
            "const done = arguments[arguments.length - 1];"
            "const args = Array.from(arguments).slice(0, -1);"
            "(async () => {" + body + "})().then(done, (e) => done({error: String(e && e.stack || e)}));",
            *args)

    def eval(self, expr):
        return self.driver.execute_script(f"return {expr};")

    def wait_eval(self, expr, what):
        return wait_for(lambda: self.eval(expr), what, extra=self.console)

    def console(self):
        try:
            return "browser console:\n" + "\n".join(e["message"] for e in self.driver.get_log("browser"))
        except Exception:
            return ""

    def pick_file(self, path):
        self.driver.find_element("id", "file").send_keys(str(path))

    def close(self):
        try:
            self.driver.quit()
        except Exception:
            pass


# JS: receive a share link; resolves {sha, size, kind, relayBytes, directBytes} or {error}
RECEIVE = """
const [server, link] = args;
return await new Promise((resolve) => {
  v2.startReceive({ server, link, on: {
    done: async (d) => {
      const buf = new Uint8Array(await d.file.arrayBuffer());
      const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", buf))).map(b => b.toString(16).padStart(2, "0")).join("");
      resolve({ sha, size: d.size, kind: d.kind, relayBytes: d.relayBytes, directBytes: d.directBytes });
    },
    error: (m) => resolve({ error: m }),
  }});
});
"""

# JS: send the file picked in the page's file input; the link and the result appear in window.*
SEND = """
const [server, requestKey] = args;
const file = document.getElementById("file").files[0];
window.link = null; window.sendResult = null;
v2.startSend({ server, blob: file, kind: "single", requestKey: requestKey || null, on: {
  link: (l) => { window.link = l; },
  done: (m) => { window.sendResult = { sent: m.receivers }; },
  error: (m) => { window.sendResult = { error: m }; },
}});
return true;
"""

# JS: a streaming send of generated data, the three ways to give a source (restartable
# function, one stream, blob); the link appears in window.link, the sha256 of the data
# in window.expectedSha, how often the data was opened in window.opened
STREAM_SEND = """
const [server, size, how] = args;
const all = new Uint8Array(size);
let x = 123456789;
for (let i = 0; i < size; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; all[i] = x & 255; }
window.expectedSha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", all))).map(b => b.toString(16).padStart(2, "0")).join("");
window.opened = 0; window.link = null; window.sendResult = null;
const make = () => {
  window.opened++;
  let at = 0;
  return new ReadableStream({ pull(c) { if (at >= all.length) return c.close(); c.enqueue(all.slice(at, at + 100003)); at += 100003; } });
};
const on = {
  link: (l) => { window.link = l; },
  done: (m) => { window.sendResult = { sent: m.receivers }; },
  error: (m) => { window.sendResult = { error: m }; },
};
if (how === "restartable") v2.startSend({ server, openStream: async () => make(), size, name: "generated.bin", on });
else if (how === "once") v2.startSend({ server, stream: make(), size, name: "generated.bin", on });
else v2.startSend({ server, blob: new File([all], "generated.bin"), streaming: true, on });
return true;
"""

# JS: ask for a file; the key appears in window.reqKey, the result in window.reqResult
REQUEST_AND_RECEIVE = """
const [server] = args;
window.reqKey = null; window.reqResult = null;
v2.startRequest({ server, on: {
  requestKey: (k) => { window.reqKey = k; },
  shareLink: (link) => {
    v2.startReceive({ server, link, on: {
      done: async (d) => {
        const buf = new Uint8Array(await d.file.arrayBuffer());
        const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", buf))).map(b => b.toString(16).padStart(2, "0")).join("");
        window.reqResult = { sha, direct: d.directBytes, relay: d.relayBytes };
      },
      error: (m) => { window.reqResult = { error: m }; },
    }});
  },
  error: (m) => { window.reqResult = { error: m }; },
}});
return true;
"""

server = None
tmp = None
failures = 0


def make_file(size, name):
    data = os.urandom(size)
    path = Path(tmp) / name
    path.write_bytes(data)
    return path, data


def test_cli_to_chrome(flags, size):
    path, data = make_file(size, "in.bin")
    cli = Cli(server, "send", *flags, str(path))
    link = cli.find(r"#([A-Za-z0-9_-]{86})", "cli share link")
    page = Page(server)
    try:
        page.open()
        result = page.run(RECEIVE, server.url, link)
        assert "error" not in result, f"{result}\n{page.console()}"
        assert result["sha"] == sha256(data), "received data differs"
        if "--webrtc" in flags:
            assert result["directBytes"] > 0, f"nothing came over the data channel: {result}"
        cli.wait()
    finally:
        page.close(); cli.kill()


def test_chrome_to_cli(flags, size):
    path, data = make_file(size, "in.bin")
    out = Path(tempfile.mkdtemp(dir=tmp))
    page = Page(server)
    try:
        page.open()
        page.pick_file(path)
        page.run(SEND, server.url, None)
        link = page.wait_eval("window.link", "chrome share link")
        cli = Cli(server, "recv", *flags, "--out", str(out), f"{server.url}/#{link}")
        cli.wait()
        files = list(out.iterdir())
        assert len(files) == 1, f"files: {files}"
        assert sha256(files[0].read_bytes()) == sha256(data), "received data differs"
        sent = page.wait_eval("window.sendResult", "chrome finishing")
        assert "error" not in sent, sent
    finally:
        page.close()


def test_chrome_to_chrome_request():
    path, data = make_file(300_000, "in.bin")
    receiver, sender = Page(server), Page(server)
    try:
        receiver.open(); sender.open()
        receiver.run(REQUEST_AND_RECEIVE, server.url)
        key = receiver.wait_eval("window.reqKey", "request key")
        sender.pick_file(path)
        sender.run(SEND, server.url, key)
        result = receiver.wait_eval("window.reqResult", "receive")
        assert "error" not in result, f"{result}\n{receiver.console()}\n{sender.console()}"
        assert result["sha"] == sha256(data)
        sent = sender.wait_eval("window.sendResult", "sender finishing")
        assert "error" not in sent, sent
    finally:
        receiver.close(); sender.close()


def test_cli_stream_to_chrome(size):
    """`... | bitmule send -`: the data goes first, the manifest and checksum after it."""
    data = os.urandom(size)
    cli = Cli(server, "send", "-", "--name", "piped.bin", "--relay", stdin_data=data)
    link = cli.find(r"#([A-Za-z0-9_-]{86})", "cli share link")
    page = Page(server)
    try:
        page.open()
        result = page.run(RECEIVE, server.url, link)
        assert "error" not in result, f"{result}\n{page.console()}\ncli:\n{cli.out}"
        assert result["size"] == size and result["sha"] == sha256(data), f"received data differs: {result}"
        cli.wait()
        assert "done" in cli.out, cli.out
    finally:
        page.close(); cli.kill()


def test_chrome_stream_to_cli(how, size):
    out = Path(tempfile.mkdtemp(dir=tmp))
    page = Page(server)
    try:
        page.open()
        page.run(STREAM_SEND, server.url, size, how)
        link = page.wait_eval("window.link", "chrome share link")
        cli = Cli(server, "recv", "--relay", "--out", str(out), f"{server.url}/#{link}")
        cli.wait()
        files = list(out.iterdir())
        assert len(files) == 1, f"files: {files}"
        assert files[0].name == "generated.bin", files[0].name
        assert sha256(files[0].read_bytes()) == page.eval("window.expectedSha"), "received data differs"
        sent = page.wait_eval("window.sendResult", "chrome finishing")
        assert "error" not in sent, f"{sent}\n{page.console()}"
        if how == "restartable":
            assert page.eval("window.opened") >= 1
    finally:
        page.close()


def test_chrome_stream_to_chrome(how, size):
    sender, receiver = Page(server), Page(server)
    try:
        sender.open(); receiver.open()
        sender.run(STREAM_SEND, server.url, size, how)
        link = sender.wait_eval("window.link", "sender share link")
        result = receiver.run(RECEIVE, server.url, link)
        assert "error" not in result, f"{result}\n{receiver.console()}\n{sender.console()}"
        assert result["size"] == size and result["sha"] == sender.eval("window.expectedSha"), f"received data differs: {result}"
        sent = sender.wait_eval("window.sendResult", "sender finishing")
        assert "error" not in sent, f"{sent}\n{sender.console()}"
    finally:
        sender.close(); receiver.close()


# ---- through the real page (index.html + main.js) ----

def wait_download(directory, what):
    """The finished file in a downloads directory. Browsers write it under its
    final name or a temporary one (.crdownload, .part); take it once it is
    there and has stopped growing."""
    def check():
        files = [f for f in directory.iterdir() if not f.name.endswith((".crdownload", ".tmp", ".part"))]
        if not files:
            return None
        size = files[0].stat().st_size
        time.sleep(0.3)
        return files[0] if size > 0 and files[0].stat().st_size == size else None
    return wait_for(check, what)


def test_ui_receive(flags):
    path, data = make_file(BLOCK + 4321, "quarterly report.bin")
    downloads = Path(tempfile.mkdtemp(dir=tmp))
    cli = Cli(server, "send", *flags, str(path))
    link = cli.find(r"#([A-Za-z0-9_-]{86})", "cli share link")
    page = Page(server, downloads=downloads)
    try:
        page.open("/", ready="window.bitmule")
        page.driver.get(f"{server.url}/#{link}")
        page.wait_eval("document.body.dataset.transferStatus === 'complete'", "page reports the transfer complete")
        got = wait_download(downloads, "downloaded file")
        assert sha256(got.read_bytes()) == sha256(data), "downloaded data differs"
        assert got.name == "quarterly report.bin", f"saved as {got.name!r}"
        cli.wait()
    finally:
        page.close(); cli.kill()


def test_ui_send():
    path, data = make_file(BLOCK + 4321, "from the page.bin")
    out = Path(tempfile.mkdtemp(dir=tmp))
    page = Page(server)
    try:
        page.open("/", ready="window.bitmule")
        page.driver.find_element("id", "file-input").send_keys(str(path))
        url = page.wait_eval("document.getElementById('session-link').value", "share link in the page")
        cli = Cli(server, "recv", "--relay", "--out", str(out), url)
        cli.wait()
        files = list(out.iterdir())
        assert len(files) == 1 and sha256(files[0].read_bytes()) == sha256(data), f"received {files}"
        assert files[0].name == "from the page.bin", f"saved as {files[0].name!r}"
        page.wait_eval("document.body.dataset.transferStatus === 'complete'", "page reports the transfer complete")
    finally:
        page.close()


def test_ui_zip_from_cli():
    """Two files from the CLI arrive as a zstd zip; the page extracts them."""
    a, data_a = make_file(5000, "a.txt")
    b, data_b = make_file(BLOCK // 2, "b.bin")
    downloads = Path(tempfile.mkdtemp(dir=tmp))
    cli = Cli(server, "send", "--relay", str(a), str(b))
    link = cli.find(r"#([A-Za-z0-9_-]{86})", "cli share link")
    page = Page(server, downloads=downloads)
    try:
        page.open("/", ready="window.bitmule")
        page.driver.get(f"{server.url}/#{link}")
        page.wait_eval("document.querySelector('.bundle-dialog')", "bundle dialog")
        page.driver.find_element("css selector", ".bundle-dialog .pick-btn.secondary").click()
        wait_for(lambda: page.eval("document.querySelectorAll('.bundle-list a.download-link').length === 2"), "extracted entries",
                 extra=lambda: "dialog: " + str(page.eval("document.querySelector('.bundle-dialog').innerText")) + "\n" + page.console())
        entries = page.run("""
          const out = {};
          for (const a of document.querySelectorAll('.bundle-list a.download-link')) {
            const buf = new Uint8Array(await (await fetch(a.href)).arrayBuffer());
            const sha = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buf))).map(b => b.toString(16).padStart(2, '0')).join('');
            out[a.download] = { sha, crcOk: !a.textContent.includes('CRC mismatch') };
          }
          return out;""")
        assert set(entries) == {"a.txt", "b.bin"}, entries
        assert entries["a.txt"] == {"sha": sha256(data_a), "crcOk": True}, entries
        assert entries["b.bin"] == {"sha": sha256(data_b), "crcOk": True}, entries
        cli.wait()
    finally:
        page.close(); cli.kill()


def test_ui_request():
    path, data = make_file(70_000, "in.bin")
    downloads = Path(tempfile.mkdtemp(dir=tmp))
    page = Page(server, downloads=downloads)
    try:
        page.open("/", ready="window.bitmule")
        page.driver.find_element("id", "request-files-btn").click()
        url = page.wait_eval("document.getElementById('request-link').value", "request link in the page")
        assert "/send#" in url, url
        cli = Cli(server, "send", "--relay", "--to", url, str(path))
        got = wait_download(downloads, "downloaded file")
        assert sha256(got.read_bytes()) == sha256(data), f"downloaded data differs: {[(f.name, f.stat().st_size) for f in downloads.iterdir()]} want {len(data)} bytes"
        cli.wait()
    finally:
        page.close()


def test_ui_invited_send():
    """Someone opens a CLI request link in the page and sends a file to it."""
    path, data = make_file(70_000, "in.bin")
    out = Path(tempfile.mkdtemp(dir=tmp))
    cli = Cli(server, "recv", "--relay", "--out", str(out))
    key = cli.find(r"/send#([0-9a-f]{64})", "cli request link")
    page = Page(server)
    try:
        page.open("/", ready="window.bitmule")
        page.driver.get(f"{server.url}/send#{key}")
        page.wait_eval("!document.getElementById('invited-send-mode').hidden", "invited send mode")
        page.driver.find_element("id", "invited-file-input").send_keys(str(path))
        cli.wait()
        files = list(out.iterdir())
        assert len(files) == 1 and sha256(files[0].read_bytes()) == sha256(data), f"received {files}"
        page.wait_eval("document.body.dataset.transferStatus === 'complete'", "page reports the transfer complete")
    finally:
        page.close(); cli.kill()


TESTS = {
    "cli -> chrome, relay, 1 KB": lambda: test_cli_to_chrome(["--relay"], 1000),
    "cli -> chrome, relay, multi-block": lambda: test_cli_to_chrome(["--relay"], BLOCK * 2 + 777),
    "chrome -> cli, relay, multi-block": lambda: test_chrome_to_cli(["--relay"], BLOCK * 2 + 777),
    "cli -> chrome, webrtc, multi-block": lambda: test_cli_to_chrome(["--webrtc", "--stun", "none"], BLOCK * 2 + 777),
    "chrome -> cli, webrtc, multi-block": lambda: test_chrome_to_cli(["--webrtc", "--stun", "none"], BLOCK * 2 + 777),
    "chrome -> chrome, request link": test_chrome_to_chrome_request,
    "stream: cli -> chrome, multi-block": lambda: test_cli_stream_to_chrome(BLOCK * 2 + 4321),
    "stream: cli -> chrome, 1 byte": lambda: test_cli_stream_to_chrome(1),
    "stream: chrome (openStream) -> cli": lambda: test_chrome_stream_to_cli("restartable", BLOCK * 2 + 12345),
    "stream: chrome (one stream) -> cli": lambda: test_chrome_stream_to_cli("once", BLOCK * 2 + 12345),
    "stream: chrome (blob) -> cli": lambda: test_chrome_stream_to_cli("blob", BLOCK * 2 + 12345),
    "stream: chrome (openStream) -> chrome": lambda: test_chrome_stream_to_chrome("restartable", BLOCK * 2 + 12345),
    "stream: chrome (one stream) -> chrome": lambda: test_chrome_stream_to_chrome("once", BLOCK + 99),
    "page: receive from cli (relay)": lambda: test_ui_receive(["--relay"]),
    "page: receive from cli (webrtc)": lambda: test_ui_receive(["--webrtc", "--stun", "none"]),
    "page: send to cli": test_ui_send,
    "page: zip with zstd entries from cli": test_ui_zip_from_cli,
    "page: request files, cli sends": test_ui_request,
    "page: send to a cli request link": test_ui_invited_send,
}


def main():
    global server, tmp, failures
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    server = Server()
    tmp = tempfile.mkdtemp(prefix="bitmule-browser-")
    try:
        for name, fn in TESTS.items():
            if only not in name:
                continue
            t0 = time.time()
            try:
                fn()
                print(f"ok   {name} ({time.time() - t0:.1f}s)", flush=True)
            except BaseException:
                failures += 1
                print(f"FAIL {name}\n{traceback.format_exc()}", flush=True)
    finally:
        server.stop()
    print("all passed" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)


main()
