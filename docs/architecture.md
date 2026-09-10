# Architecture

## Design principles

1. **No "100 %".** Traversal is inferred from response behaviour. False
   negatives are unavoidable (WAFs strip payloads, successful reads return
   re-encoded content, blind sinks never reflect). The design target is a high
   true-positive rate across encoding variants with near-zero false positives.
2. **Never classify on status code alone.** A `200` can be an error page; a
   `403`/`404` can be identical for valid and malicious input. Every verdict is
   a *difference* from a per-vector known-good baseline **and** a negative
   control.
3. **Deterministic core, thin optional AI.** Crawling, parsing, payload
   synthesis, probing and classification are deterministic and reproducible.
   The AI only refines relevance scores (Stage 1) and adjudicates ambiguous
   findings (Stage 2). If it is not configured, nothing breaks. See
   [agent.md](agent.md).
4. **Send payloads verbatim.** The HTTP layer must not re-encode or normalise a
   payload before it reaches the server. This constrains how each injection
   location is built (see [stage-2.md](stage-2.md#step-3--build-the-request-template)).
5. **Every stage writes a JSON artifact** that the next stage consumes.

## Package layout

```
exploit_path_traversal/
  cli.py             argparse; one subcommand per stage (stage1 / stage2 / report)
  config.py          Settings + AIConfig; env + .env loading, precedence
  models.py          RawRequest, InputVector  (see data-model.md)
  http_client.py     httpx.Client wrapper: TLS toggle, rate limit, 1 retry
  output.py          terminal output — bold/dim only, NO_COLOR + non-TTY aware

  crawl/
    crawler.py       same-origin BFS; forms, links, JS, robots/sitemap,
                     static-path synthetic vector, identifier harvesting
    html_parser.py   stdlib html.parser subclass: links, forms+fields, scripts
    js_parser.py     regex endpoint extraction from JavaScript

  spec/
    __init__.py      load_any(): detect + dispatch OpenAPI / HAR / Postman
    openapi.py       OpenAPI 2/3 -> RawRequest
    har.py           HAR entries -> RawRequest
    postman.py       Postman v2.x collection -> RawRequest

  vectors/
    lexicon.py       name lexicons + the A–L coverage dimension list
    scoring.py       classify(): rule-based relevance 0..1 + dimension tag
    coverage.py      matrix() / gaps() over the A–L model
    baseline.py      candidates_for(): ranked known-good value guesses
    extractor.py     from_raw(): RawRequest[] -> deduped, scored InputVector[]

  agent/
    client.py        AIClient: any OpenAI-compatible /chat/completions
    prompts.py       Stage 1 system prompt + batch builder
    classifier.py    Stage 1 refinement pass  (REVISIT seam)
    verify.py        Stage 2 finding adjudication  (REVISIT seam)

  probe/
    prepared.py      Prepared: template + one injection field -> concrete request / curl
    fingerprint.py   Fingerprint capture + body normalisation + similarity
    payloads.py      generate() read payloads, generate_write() write payloads
    baseline.py      establish() baseline + negative_control()
    differ.py        classify(): payload response vs baseline vs control -> verdict

  stages/
    stage1.py        Stage 1 orchestration (run + Stage1Report)
    stage2.py        Stage 2 orchestration (run + Stage2Options)

  report/
    writer.py        Stage 1 JSON artifact + terminal summary
    stage2_writer.py Stage 2 JSON artifact + terminal summary
    report_md.py     Stage 4 Markdown report
```

## Data flow

```
                 ┌──────────── stage1 ────────────┐
 URL ──crawl──►  │  crawl/  +  spec/              │
 specs ─import─► │        ↓                        │
                 │  RawRequest[]                   │
                 │        ↓  vectors/extractor     │
                 │  InputVector[]  (+ rule score)  │
                 │        ↓  vectors/scoring        │
                 │  + A–L coverage tag             │
                 │        ↓  agent/classifier (opt) │
                 │  + AI relevance / inferred / gaps│
                 └────────┬────────────────────────┘
                          ▼
                 stage1-vectors.json
                  { vectors[], request_templates[], harvested_values{}, coverage{} }
                          │
                 ┌────────▼──────── stage2 ────────┐
                 │  select vectors  (min-relevance)│
                 │        ↓  probe/prepared         │
                 │  Prepared request per vector    │
                 │        ↓  probe/baseline         │
                 │  baseline fingerprint + control │
                 │        ↓  probe/payloads         │
                 │  payload set (read | write)     │
                 │        ↓  probe/differ           │
                 │  verdict per payload -> best    │
                 │  + round-trip / reproduce       │
                 │        ↓  agent/verify (opt)     │
                 │  + AI adjudication              │
                 └────────┬────────────────────────┘
                          ▼
                 stage2-findings.json
                          │
                 ┌────────▼──── report ────────────┐
                 │  report_md.render()             │
                 └────────┬────────────────────────┘
                          ▼
                      report.md
```

## The HTTP client (`http_client.py`)

A single `httpx.Client` per stage run:

- `follow_redirects=True`, `max_redirects=5`
- `verify` toggled by `--insecure`
- shared `User-Agent` (`exploit-path-traversal/0.1 (authorized security testing)`),
  plus any `-H` headers and `-b` cookies
- a simple requests-per-second limiter (`--rate`): sleeps to keep at least
  `1/rate` seconds between requests
- one retry on `httpx.TransportError`; on the second failure it records
  `last_error` and returns `None`

Stage 2's `probe/fingerprint.capture()` and the round-trip reads all go through
this same client, so scope, auth, throttling and TLS behaviour are identical to
the crawl.
