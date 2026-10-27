#!/usr/bin/env python3
"""Botguard signing sidecar.

Mints the X-Goog-BatchExecute-Bgr header for translate.google.com's batchexecute
RPC using a windowless (headless) Chrome. Everything else stays in Python.

Why a browser at all: the token has to be produced by Google's own botguard VM
inside a real browser realm, and the result is bound to the exact request body
(the f.req string). See the README / skill notes for the full investigation.

Endpoints
    GET  /health            -> {"ok": true, "build": "<hash>", "ua": "..."}
    POST /sign  {"f_req": "<raw f.req string>"}
                            -> {"bgr": "[...]", "token_len": 1428}
    POST /refresh           -> re-fetch the page build material

Run:
    python3 bgr_sidecar.py --port 8771 --chrome-port 9501
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import websockets

PAGE_URL = "https://translate.google.com/?sl=auto&tl=zh-CN&op=images"
PAGE = "https://translate.google.com/"
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/156.0.0.0 Safari/537.36"
)
CHROME_CANDIDATES = (
    "/usr/bin/google-chrome-stable",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)

MINT_JS = r"""(async () => {
  const arr = %s;
  if (typeof window.ridgeslice === 'undefined') { (0, eval)(%s); }
  const noop = () => {};
  const api = await new Promise((res, rej) => {
    try { window.ridgeslice.a(arr[0], (...f) => res(f), true, document.body, noop, [[], []], undefined, false, [noop, noop, noop, noop, noop]); }
    catch (e) { rej(e); }
  });
  const token = await new Promise((res) => api[0]((t) => res(String(t)), [%s, undefined, undefined, undefined]));
  return String(token);
})()"""


class BuildError(RuntimeError):
    pass


class ChromeSession:
    """A headless Chrome tab that can evaluate JS and return values."""

    def __init__(self, binary: str, port: int, ua: str, profile_dir: str):
        self.binary = binary
        self.port = port
        self.ua = ua
        self.profile_dir = profile_dir
        self.proc: subprocess.Popen | None = None
        self.ws = None
        self._id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    # ---------- lifecycle ----------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        shutil.rmtree(self.profile_dir, ignore_errors=True)
        os.makedirs(self.profile_dir, exist_ok=True)
        # chrome-headless-shell is already headless; passing --headless=new makes it
        # fall back to the old headless mode, which Google fingerprints.
        headless_shell = "headless-shell" in os.path.basename(self.binary)
        args = [self.binary]
        if not headless_shell:
            args.append("--headless=new")
        args += [
                "--no-sandbox",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-crash-reporter",
                "--disable-breakpad",
                f"--remote-debugging-port={self.port}",
                f"--user-data-dir={self.profile_dir}",
                f"--user-agent={self.ua}",
                "--window-size=1920,1040",
                "about:blank",
        ]
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await self._wait_for_port()
        await self._connect()

    async def _wait_for_port(self, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=2) as r:
                    if r.status == 200:
                        return
            except Exception:  # noqa: BLE001
                await asyncio.sleep(0.3)
        raise BuildError("chrome did not open its debugging port")

    async def _connect(self) -> None:
        targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=5).read()) or []
        page = next((t for t in targets if t["type"] == "page"), None)
        if not page:
            raise BuildError("no page target in chrome")
        self.ws = await websockets.connect(page["webSocketDebuggerUrl"], max_size=256 * 1024 * 1024)
        self._reader = asyncio.create_task(self._read())
        for cmd in ("Page.enable", "Runtime.enable"):
            await self.send(cmd)

    async def _read(self) -> None:
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(BuildError(str(msg["error"])))
                        else:
                            fut.set_result(msg.get("result", {}))
        except Exception:  # noqa: BLE001
            pass

    async def send(self, method: str, **params) -> dict:
        assert self._loop is not None
        self._id += 1
        mid = self._id
        fut = self._loop.create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        return await asyncio.wait_for(fut, timeout=120)

    async def eval(self, expr: str) -> Any:
        res = await self.send("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True, timeout=120000)
        if "exceptionDetails" in res:
            raise BuildError(json.dumps(res["exceptionDetails"])[:300])
        return res["result"].get("value")

    async def navigate(self, url: str, settle: float = 6.0) -> None:
        await self.send("Page.navigate", url=url)
        await asyncio.sleep(settle)

    async def stop(self) -> None:
        try:
            if self.ws:
                await self.ws.close()
        except Exception:  # noqa: BLE001
            pass
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Build:
    """The per-page-load botguard material: interpreter JS + program blob + ids."""

    def __init__(self, ua: str):
        self.ua = ua
        self.interpreter: str = ""
        self.arr: list = []
        self.hash: str = ""
        self.sid: str = ""
        self.bl: str = ""
        self.fetched_at: float = 0.0

    @property
    def age(self) -> float:
        return time.time() - self.fetched_at

    def refresh(self) -> None:
        req = urllib.request.Request(PAGE_URL, headers={"User-Agent": self.ua, "Accept-Language": "en-US,en;q=0.9"})
        html = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
        idx = html.find('"mnsUbf":')
        if idx < 0:
            raise BuildError("mnsUbf missing from the page (build changed or blocked)")
        start = html.index('"', idx + len('"mnsUbf":'))
        material, _ = json.JSONDecoder().raw_decode(html[start:])
        arr = json.loads("[" + (material[4:] if material.startswith("%.@.") else material))
        sid = re.search(r'FdrFJe":"(-?\d+)"', html)
        bl = re.search(r'"cfb2h":"([^"]+)"', html)
        self.arr = arr
        self.interpreter = arr[5][-1]
        self.hash = arr[2]
        self.sid = sid.group(1) if sid else ""
        self.bl = bl.group(1) if bl else ""
        self.fetched_at = time.time()


class Signer:
    def __init__(self, ua: str, chrome_binary: str, chrome_port: int, profile_dir: str, max_age: float = 900.0):
        self.ua = ua
        self.max_age = max_age
        self.build = Build(ua)
        self.chrome = ChromeSession(chrome_binary, chrome_port, ua, profile_dir)
        self.lock = asyncio.Lock()

    async def start(self) -> None:
        await asyncio.to_thread(self.build.refresh)
        await self.chrome.start()
        await self.chrome.navigate(PAGE_URL, settle=6)

    async def stop(self) -> None:
        await self.chrome.stop()

    async def sign(self, freq: str) -> dict:
        if not freq:
            raise BuildError("empty f_req")
        async with self.lock:
            if self.build.age > self.max_age:
                await asyncio.to_thread(self.build.refresh)
            js = MINT_JS % (json.dumps(self.build.arr), json.dumps(self.build.interpreter), json.dumps(freq))
            token = await self.chrome.eval(js)
            if not isinstance(token, str) or len(token) < 200:
                # material may have rotated under us; refresh once and retry
                await asyncio.to_thread(self.build.refresh)
                js = MINT_JS % (json.dumps(self.build.arr), json.dumps(self.build.interpreter), json.dumps(freq))
                token = await self.chrome.eval(js)
            if not isinstance(token, str) or len(token) < 200:
                raise BuildError(f"mint failed: {str(token)[:120]}")
            bgr = json.dumps([token, None, None, 214, 4, None, None, 0, "2"], separators=(",", ":"))
            return {"bgr": bgr, "token_len": len(token), "build": self.build.hash,
                    "sid": self.build.sid, "bl": self.build.bl}


class Handler(BaseHTTPRequestHandler):
    signer: Signer = None  # type: ignore[assignment]
    loop: asyncio.AbstractEventLoop = None  # type: ignore[assignment]

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # keep the sidecar quiet

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            b = self.signer.build
            self._json(200, {"ok": True, "build": b.hash, "age_s": round(b.age, 1), "ua": self.signer.ua})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        if self.path == "/sign":
            freq = payload.get("f_req") or payload.get("freq") or ""
            try:
                out = asyncio.run_coroutine_threadsafe(self.signer.sign(freq), self.loop).result(timeout=180)
                self._json(200, out)
            except Exception as e:  # noqa: BLE001
                self._json(502, {"error": str(e)[:300]})
        elif self.path == "/refresh":
            try:
                self.signer.build.refresh()
                self._json(200, {"ok": True, "build": self.signer.build.hash})
            except Exception as e:  # noqa: BLE001
                self._json(502, {"error": str(e)[:300]})
        else:
            self._json(404, {"error": "not found"})


class LocalSigner:
    """In-process signer: owns a browser child process and its own event loop.

    Used when the service should not run a second container (or a second HTTP hop).
    Thread-safe: call .sign() from any thread.
    """

    def __init__(self, chrome_binary: str | None = None, profile_dir: str = "/tmp/bgr-inproc",
                 ua: str = DEFAULT_UA, max_age: float = 900.0):
        self.chrome_binary = pick_chrome(chrome_binary)
        self.profile_dir = profile_dir
        self.ua = ua
        self.max_age = max_age
        self._loop: asyncio.AbstractEventLoop | None = None
        self._signer: Signer | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="bgr-signer", daemon=True)

    def start(self, timeout: float = 90.0) -> "LocalSigner":
        self._thread.start()
        if not self._ready.wait(timeout):
            raise BuildError("signer did not become ready in time")
        if self._error:
            raise BuildError(f"signer failed to start: {self._error}")
        return self

    def _run(self) -> None:
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            port = _free_port()
            self._signer = Signer(self.ua, self.chrome_binary, port, self.profile_dir, self.max_age)
            self._loop.run_until_complete(self._signer.start())
        except BaseException as e:  # noqa: BLE001
            self._error = e
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    def sign(self, freq: str, timeout: float = 180.0) -> dict:
        if not self._signer or not self._loop:
            raise BuildError("signer is not running")
        fut = asyncio.run_coroutine_threadsafe(self._signer.sign(freq), self._loop)
        return fut.result(timeout)

    def stop(self) -> None:
        if self._loop and self._signer:
            try:
                asyncio.run_coroutine_threadsafe(self._signer.stop(), self._loop).result(15)
            except Exception:  # noqa: BLE001
                pass
            self._loop.call_soon_threadsafe(self._loop.stop)


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pick_chrome(explicit: str | None) -> str:
    if explicit:
        return explicit
    for cand in CHROME_CANDIDATES:
        if os.path.exists(cand):
            return cand
    raise SystemExit("no chrome binary found; pass --chrome")


async def serve(args: argparse.Namespace) -> None:
    ua = args.ua
    signer = Signer(ua, pick_chrome(args.chrome), args.chrome_port, args.profile_dir, args.max_age)
    print(f"[sidecar] starting chrome ({signer.chrome.binary}) on :{args.chrome_port}", flush=True)
    await signer.start()
    print(f"[sidecar] build {signer.build.hash} ready; listening on :{args.port}", flush=True)

    Handler.signer = signer
    Handler.loop = asyncio.get_running_loop()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    server.shutdown()
    await signer.stop()


def main() -> None:
    ap = argparse.ArgumentParser(description="botguard signing sidecar")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8771)
    ap.add_argument("--chrome", default=None)
    ap.add_argument("--chrome-port", type=int, default=9501)
    ap.add_argument("--profile-dir", default="/tmp/bgr-chrome-profile")
    ap.add_argument("--ua", default=os.environ.get("GT_UA") or DEFAULT_UA)
    ap.add_argument("--max-age", type=float, default=900.0)
    args = ap.parse_args()
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
