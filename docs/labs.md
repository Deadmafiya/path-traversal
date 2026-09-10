# Verification labs

The tool was verified end-to-end against five deliberately-vulnerable local
apps (`~/Documents/OWASP-top-10/path-traversal-lab/`, not part of this repo).
Each isolates one vector class. All are `127.0.0.1`, local practice only.

| App | Port | Sink | Vector class | Stage 2 verdict |
|-----|-----:|------|--------------|-----------------|
| `app.py` | 5000 | `send_file(os.path.join(FILES_DIR, request.args["file"]))` | query parameter | **confirmed** — `?file=/etc/passwd` |
| `app2.py` | 5001 | `open(os.path.join(PAGES_DIR, request.args["page"]))` | LFI via query parameter | **confirmed** — `?page=/etc/passwd` |
| `app3.py` | 5002 | raw `self.path` → `unquote` → `os.path.join(WWW_DIR, …)` | URL path itself (static-file server) | **confirmed** — synthetic `url-path-segment:*`, `..%2f…%2fetc%2fpasswd` |
| `app4.py` | 5003 | `f.save(os.path.join(UPLOADS_DIR, f.filename))` | multipart upload filename (write-side) | **likely** — server 500s on the traversal filename; round-trip 404s (file not web-served in this lab) |
| `app5.py` | 5004 | three sinks: JSON body `report`, REST path `/<path:name>`, cookie `theme` (+ `".txt"`) | API / hidden spots | **2 confirmed** (`json-body:report`, `url-path-segment:name`) + **not-vulnerable** (`cookie:theme` — suffix-constrained) |

## What each lab exercises in the tool

- **app.py** — the full happy path: crawl finds `?file=` links, the observed
  value `report.txt` becomes the baseline, the mangled control 404s, the
  `absolute` payload `/etc/passwd` returns `root:x:0:0:…`.
- **app2.py** — same shape, LFI framing; `os.path.join(dir, "/etc/passwd")`
  returns the absolute path, so the `absolute` payload confirms.
- **app3.py** — no params, no forms → Stage 1's static-path synthetic vector
  (`_add_static_path_vector`). Demonstrates the httpx path-normalisation
  constraint: `raw` `../` is skipped, `slash-enc` / `dot-slash-enc` confirm.
- **app4.py** — the write-side path: `generate_write` climb-only payloads, the
  `likely` verdict from a traversal-only 500, and the round-trip attempt.
  Confirms only if the escaped file is reachable over HTTP (it isn't here).
- **app5.py** — three injection locations with no crawlable links, driven from a
  small OpenAPI spec (`--openapi`). `json-body` sends the literal string (no
  encoding needed). `cookie:theme` is a true negative for the `/etc/passwd`
  canary because the sink appends `".txt"` — the tool says `not-vulnerable` and
  adds the suffix-constrained note on the path-segment sibling.

## Reproducing

```bash
cd ~/Documents/OWASP-top-10/path-traversal-lab
python3 app.py &   python3 app2.py &   python3 app3.py &
python3 app4.py &  python3 app5.py &

cd <this repo>
exploit-path-traversal stage2 -u http://127.0.0.1:5000 --no-ai
exploit-path-traversal stage2 -u http://127.0.0.1:5001 --no-ai
exploit-path-traversal stage2 -u http://127.0.0.1:5002 --no-ai --depth 2
exploit-path-traversal stage2 -u http://127.0.0.1:5003 --no-ai --min-relevance 0.3
exploit-path-traversal stage2 --openapi lab5.openapi.json --no-ai --min-relevance 0.3
```

(`lab5.openapi.json` describes `POST /api/export`, `GET /api/files/{name}`,
`GET /api/profile` with a `theme` cookie.)
