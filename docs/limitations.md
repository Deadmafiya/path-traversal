# Limitations

Path traversal detection is a black-box behavioural test. These are the known
blind spots — documented so results are read correctly, not as bugs.

## Why not "100 %"

- A successful read can return content the matcher never recognises (piped
  through an image processor, re-encoded, rendered into a template).
- WAFs / CDNs strip or block payloads before the vulnerable code sees them.
- The sink may require a specific extension, an OS-specific separator, or a
  null-byte trick that no longer works on modern runtimes.
- Blind traversal (file written / processed / deleted but never reflected) needs
  out-of-band or timing confirmation, which this tool does not yet have.

## Stage 1

- **Discovery is only as good as the crawl.** Authenticated routes, routes only
  reachable from JS that the regex extractor misses, GraphQL / WebSocket
  surfaces, and internal service-to-service calls are not found unless you feed a
  spec / HAR. Provide `--openapi` / `--har` / `--postman` for real coverage.
- **No auth flow.** Pass a session with `-H 'Authorization: …'` / `-b 'session=…'`;
  the tool will not log in for you.
- **Second-order / persisted vectors** are scored but Stage 2 cannot exercise
  the full store-then-trigger chain.
- Dimensions **K** (infrastructure / internal flows) and **L** (cache / temp /
  log files) are almost always populated only by the AI pass; without it they
  show as coverage gaps.

## Stage 2

- **Write-side (upload) traversal** is `confirmed` only when the escaped file is
  retrievable via one of the guessed round-trip URLs
  (`/<marker>`, `<base>/<marker>`, `/uploads/`, `/static/`, `/files/`).
  A write that lands somewhere not served over HTTP stays `likely` — a real OOB
  channel would close this.
- **Suffix-constrained sinks** — if the app appends an extension
  (`open(dir + name + ".txt")`), the `/etc/passwd` canary is unreachable.
  Null-byte-before-extension variants are tried but modern PHP/Python reject
  them, so the vector may read `inconclusive` / `not-vulnerable` with a note
  that it is traversal-shaped. Re-test manually with an extension-matching
  target file.
- **Raw `../` in a URL path is not sent** — httpx collapses dot-segments in the
  URL path before the request leaves. Path-segment vectors are tested with
  encoded separators only (`..%2f`, `%2e%2e%2f`, `....//`, `..;/`, `..%5c`,
  overlong UTF-8). A server that is only vulnerable to a *literal* `../` in the
  path (and rejects every encoded form) would be missed.
- **Payload budget** — `--max-payloads` (90) and `--depth-max` (6) bound each
  vector. Very deep directory nesting or an exotic encoding not in the table is
  out of scope; raise the limits or add to `probe/payloads.py::_ENCODINGS`.
- **Dynamic baselines** — if a page changes a lot between identical requests, the
  baseline is marked `dynamic` and the similarity thresholds loosen (0.97 → 0.9).
  A highly dynamic endpoint can push a real finding down to `inconclusive`.
- **Baseline unavailable** — if no candidate value produced a normal response,
  read-side findings without a canary hit cap at `inconclusive` (there is
  nothing to diff against). Supply `--baseline 'name=value'`.
- **No timing analysis** — blind traversal detectable only by response-time
  differences is not attempted.

## General

- Single-host, same-origin by default. Cross-host redirects are followed but not
  crawled unless in `--scope`.
- The tool sends real requests (baseline, control, payloads, round-trip reads,
  reproduction) — expect dozens to a few hundred per vector. Use `--rate` on
  fragile targets.
