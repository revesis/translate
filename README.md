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
| `GT_DEFAULT_TL` | `zh-CN` | target language when the request omits `tl` |
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

## Throughput, measured here

| Input | Time | Upstream requests |
| --- | --- | --- |
| 201-line English file, 21 292 chars | ~5.0 s | 5 (50 lines / 6 KB each) |
| `/translate/batch` with 10 items | ~0.5 s | 1 (all items flattened into one batch) |
| single line, 3 500 chars (no punctuation) | ~1.2 s | 1 (3 segments, sentence-cut) |

`/translate/batch` and `translate_many()` flatten every item's lines and pieces
into one shared batch pipeline, so N short items cost one upstream request, not
N.

## Behind a reverse proxy or CDN

Measured against a Cloudflare-fronted deployment of this exact server:

* **A plain Python `User-Agent` (`Python-urllib/3.x`, `python-requests/...`) gets
  HTTP 403 `error code: 1010`** from Cloudflare's Browser Integrity Check —
  unrelated to this app. Send a normal browser `User-Agent`, or add a WAF rule
  to skip Browser Integrity Check / managed rules for the API path.
* Even with a browser UA, non-browser TLS fingerprints (OpenSSL from Python) sit
  on a slower path: ~1.5–3 s per call, with occasional 20 s+ spikes. `curl`'s
  fingerprint is treated as a normal client and stays around 1–2 s.
* Request bodies above ~100 KB stall (20 s at 100 KB, 90 s at 500 KB) and 1 MB+
  ends in Cloudflare 524; a 3 MB body is rejected by the origin proxy (413).
  Keep one API call to a few tens of KB — the upstream batching already handles
  documents far larger than that server-side.

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
