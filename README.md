# google-translate — Google Translate API from a server with no browser

A tiny, dependency-free HTTP API + CLI that calls Google Translate over plain
HTTPS. No Chrome, no Playwright, no Selenium, no API key, no pip packages —
just Python 3.10+ stdlib.

Verified on this host: `curl` and the CLI both return real translations from
`translate.googleapis.com` with nothing but an HTTP GET.

## Why this works without a browser

Google's web UI calls a JSON endpoint that needs no JS challenge and no token:

```
GET https://translate.googleapis.com/translate_a/t?client=dict-chrome-ex&sl=auto&tl=zh-CN&q=hello
-> [["你好","en"]]
```

Measured behaviour (probed 2026-10, from this host):

| Variant | Result |
| --- | --- |
| `translate_a/single?client=gtx` | **429** "Sorry..." HTML page — unusable here |
| `translate_a/t?client=dict-chrome-ex`, GET | **200**, JSON |
| same endpoint, POST | **302** → `/sorry` (anti-bot) — never use POST upstream |
| 1 `q` param | `[["译文","en"]]` |
| many `q` + `sl=auto` | `[["译文1","en"],["译文2","en"], …]` |
| many `q` + explicit `sl` | `["译文1","译文2", …]` |
| unknown `tl` (e.g. `xx-YY`) | 200, source text echoed back unchanged |
| 200 `q` params / ~9 KB URL | 200 OK (batched, no per-item overhead) |
| 8 back-to-back GETs | all 200 (no throttle yet; keep it polite anyway) |
| newlines inside one `q` | **swallowed** — line structure is kept locally instead |

Because of the last row, the client splits input into lines and sends each line
as its own `q` parameter, then reassembles locally. Over-long lines are cut at
sentence boundaries (`MAX_SEGMENT_CHARS = 1400`) and re-joined.

## Files

```
gt_client.py   core client: batching, line structure, retry/backoff, throttling
gt_server.py   local HTTP API (stdlib ThreadingHTTPServer)
gt.py          CLI (same code path as the API)
selftest.py    offline tests against a fake upstream (no network, no Google calls)
Dockerfile     python:3.12-slim, non-root uid 10001, HEALTHCHECK baked in
docker-compose.yml  loopback port, read-only rootfs, cap_drop ALL, healthcheck
.env.example   GT_API_KEY / GT_PROXY / GT_ENDPOINT template
gt-server.service  systemd unit example (bare-metal alternative)
```

## Docker

```bash
cp .env.example .env          # optional: set GT_API_KEY, GT_PROXY
docker compose up -d --build
curl http://127.0.0.1:8770/health

docker compose logs -f
docker compose down
```

With podman, build in docker format or the `HEALTHCHECK` is silently dropped by
OCI output:

```bash
podman build --format docker -t gt-api:1.0 .
podman-compose up -d
podman inspect gt-api --format '{{.State.Health.Status}}'   # must say healthy
```

What the compose service pins down:

| Setting | Value | Why |
| --- | --- | --- |
| `ports` | `127.0.0.1:8770:8770` | no public exposure by default |
| `GT_HOST` | `0.0.0.0` **inside** the container | the published port cannot reach a loopback-bound process |
| `read_only` + `tmpfs /tmp` | on | the app writes nothing; proven with `touch /app/x` → read-only |
| `cap_drop` / `security_opt` | `ALL` / `no-new-privileges` | nothing needs privileges |
| `HEALTHCHECK` | `python3 -c urllib.../health` | slim image has no curl; `/health` is unauthenticated |
| `PYTHONDONTWRITEBYTECODE` | `1` | keeps `__pycache__` from breaking a read-only rootfs |

Verified here: image builds, container reaches `healthy`, real translation
through the published port, `401` without the bearer token and `200` with it,
`.env` interpolation into `GT_API_KEY` works.

## Tests

```bash
python3 selftest.py      # 17 checks, all offline against a fake upstream
```

Covers response-shape parsing (auto vs explicit `sl`), newline/blank-line
preservation, long-line splitting, batching caps (item count + encoded bytes,
including CJK), single-request batching for multi-item calls, retry after the
anti-bot HTML page, and the `RateLimited` give-up path.

## Quick start

```bash
# 1. sanity check straight from the server
python3 gt.py "hello world" -tl zh-CN
# 你好世界

# 2. start the API (default 127.0.0.1:8770)
python3 gt_server.py

# 3. call it
curl 'http://127.0.0.1:8770/translate?q=hello&tl=zh-CN'
curl -X POST http://127.0.0.1:8770/translate \
     -H 'Content-Type: application/json' \
     -d '{"text":"Line one.\nLine two.","tl":"ja"}'
```

## API

| Method | Path | Body / query | Returns |
| --- | --- | --- | --- |
| GET | `/health` | – | `{"ok":true,"auth":false}` |
| GET | `/translate` | `q` (or `text`), `sl`, `tl` | `{"text","sl","tl","detected"}` |
| POST | `/translate` | `{"text","sl","tl"}` | same |
| POST | `/translate/batch` | `{"items":["a","b"],"sl","tl"}` | `{"translations":[…],"detected":[…],"count"}` |
| GET | `/languages` | – | common language codes |

* `sl` defaults to `auto` (detection returned in `detected`), `tl` defaults to
  `GT_DEFAULT_TL` (`zh-CN`).
* Newlines and blank lines in `text` are preserved in the answer.
* Errors are JSON: `{"error":{"type":"rate_limited","message":"…"}}` with
  status `400` bad request, `401` auth, `413` too large, `404` no route,
  `429` upstream rate limit, `502` upstream failure. `429`/`502` are retryable.
* Limits: 2 MB request body, 500 items per `/translate/batch` call.

## Environment

| Var | Default | Meaning |
| --- | --- | --- |
| `GT_HOST` | `127.0.0.1` | bind address; set `0.0.0.0` to accept remote calls |
| `GT_PORT` | `8770` | listen port |
| `GT_API_KEY` | *(unset)* | if set, all routes except `/health` need `Authorization: Bearer <key>` |
| `GT_DEFAULT_TL` | `zh-CN` | target language when a request omits `tl`; also the CLI's default for `-tl` |
| `GT_PROXY` | *(unset)* | upstream proxy, e.g. `http://127.0.0.1:7890` (env `HTTPS_PROXY` is honoured when unset) |
| `GT_ENDPOINT` | Google | override the upstream URL (mirror / self-hosted gateway) |

```bash
GT_HOST=0.0.0.0 GT_API_KEY=$(openssl rand -hex 16) python3 gt_server.py
```

## CLI

```bash
python3 gt.py "hello" -tl ja                 # positional text
python3 gt.py -sl zh-CN -tl en "今天天气不错"   # explicit source
cat notes.md | python3 gt.py -tl zh-CN       # stdin, keeps line structure
python3 gt.py -f article.txt -tl zh-CN --out article.zh.txt
python3 gt.py --lines list.txt -tl zh-CN     # translate each line separately
python3 gt.py "hello" --json                 # machine-readable result
```

Exit codes: `0` ok, `2` upstream rate limited, `3` upstream error.

`-tl` defaults to `$GT_DEFAULT_TL` (falling back to `zh-CN`) — the same variable
that sets the server default, so one env var configures both the CLI and the
HTTP API. An explicit `-tl` always wins:

```bash
GT_DEFAULT_TL=ja python3 gt.py "The server is ready."          # サーバーの準備ができました。
GT_DEFAULT_TL=ja python3 gt.py "The server is ready." -tl ko   # 서버가 준비되었습니다.
```

## Throughput, measured here

| Input | Time | Upstream requests |
| --- | --- | --- |
| 201-line English file, 21 292 chars | ~5.0 s | 5 (50 lines / 6 KB each) |
| `/translate/batch` with 10 items | ~0.5 s | 1 (all items flattened into one batch) |
| single line, 3 500 chars (no punctuation) | ~1.2 s | 1 (3 segments, sentence-cut) |

`/translate/batch` and `translate_many()` flatten every item's lines and pieces
into one shared batch pipeline, so N short items cost one upstream request, not
N.

Same server deployed behind Cloudflare (curl, warm connection):

| Request | Time |
| --- | --- |
| `GET /translate` (one short sentence) | ~2.2 s |
| `POST /translate/batch`, 10 items | ~1.0 s |
| `POST /translate/batch`, 50 items | ~1.0 s (same as 10 — one upstream batch) |
| `POST /translate`, 201-line / 15.7 KB document | ~1.6 s |
| `GET /health` | ~1.2 s |

## Behind a reverse proxy or CDN

Measured against a Cloudflare-fronted deployment of exactly this server.

**The CDN's bot protection must be skipped for the API path.** With Cloudflare's
defaults, a plain Python `User-Agent` (`Python-urllib/3.x`, `python-requests/...`)
is answered with **HTTP 403 `error code: 1010`** (Browser Integrity Check) — 3/3
requests, nothing to do with this app. A WAF custom rule that skips Browser
Integrity Check and managed rules for the API prefix fixed it completely: 5/5
Python requests then returned 200.

Skipping it also removed every payload-size stall. Same deployment, before →
after:

| Request body | Before the skip rule | After the skip rule |
| --- | --- | --- |
| 100 KB | 200, 21 s | 200, 8.3 s |
| 500 KB | 200, 93 s | 200, 27 s |
| 1 MB | **524** (CDN gave up at 100 s) | 200, 48 s |
| 1.3 MB | — | 200, 55 s |
| 2.2 MB | — | 413 from the origin proxy |

So the practical ceiling is the origin nginx `client_max_body_size` (~2 MB,
which matches `MAX_BODY` in `gt_server.py`), not the CDN. Larger bodies are slow
rather than broken: the client splits them into many upstream batches. Keep one
API call to a few tens of KB and let the server-side batching do the work.

**A "random 20 s+" call is usually the caller's network, not the server.** On one
test host, the deployed hostname resolved to two Cloudflare anycast IPv4
addresses: `104.21.78.103` timed out on TCP connect (8 s socket timeout, ~21 s
until the OS gave up) while `172.67.220.56` connected in 0.05 s, and IPv6 had no
route at all. `socket.create_connection()` — what `urllib` uses — walks the
`getaddrinfo` list in order, so it sat on the dead address for 21 s on *every*
call, with any User-Agent. `curl` finished in 1–2 s because Happy Eyeballs tries
addresses in parallel. Connecting straight to the healthy address with the same
Python client and the default `User-Agent` gave 200 in 2.4–3.4 s. Confirm with
`curl -w '%{remote_ip} %{time_connect}'` before blaming the deployment; on the
client side, prefer a resolver/library with Happy Eyeballs (or pin IPv4 and
retry the next address).

## Caveats — read before relying on it

* **This is an undocumented consumer endpoint, not the paid Cloud Translation
  API.** Google can change or block it without notice, and heavy automation gets
  challenged (HTML `/sorry` page, HTTP 429) — the client then backs off
  exponentially and surfaces `429` to the caller.
* **No SLA, no quota guarantee.** For production volume use the official
  Cloud Translation API (`v2`/`v3`) with a billing account.
* **Mainland-China hosts cannot reach `translate.googleapis.com` at all** (DNS
  poisoned / TCP reset). If the server is there, put `GT_PROXY` in front of it,
  or run this API on a host that can reach Google and call it over the network.
* The client serializes upstream calls (one instance ≈ one client's
  throughput) to stay under the fraud score; parallelism buys nothing here.
* `detected` is a best-effort majority vote over the lines that had no explicit
  `sl`; when you pass `sl`, detection is empty by design.
* Long text: batching keeps requests under 6 KB encoded. Very large documents
  are many requests, so add your own queue/rate budget for bulk jobs.
* Don't expose the port publicly without `GT_API_KEY` — an open instance is a
  free quota faucet for whoever finds it.

## Running as a service

```bash
sudo cp gt-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gt-server
journalctl -u gt-server -f
```

Edit `WorkingDirectory`, `ExecStart`, `GT_API_KEY` and `GT_PROXY` in the unit
first (see `gt-server.service`).
