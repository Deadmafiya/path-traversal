# exploit-path-traversal — design & roadmap

AI-assisted, staged path-traversal discovery and verification toolkit. Runs as
`exploit-path-traversal`. Successor to the old single-file `path-traversal`
encoding brute-forcer (now removed).

## Guiding principle

No blackbox test can be "100% accurate" for path traversal — it is a behavioral
inference over responses. The design goal is:

> **maximize true-positive detection rate across encoding / normalization
> variants while keeping false positives near zero.**

Reasons 100% is impossible (keep these in mind at every stage):

- successful traversal can return content the matcher never recognizes
  (re-encoded, image-processed, templated)
- WAFs / CDNs strip or block payloads before the vulnerable code
- sinks may need specific extensions, OS-specific separators, or tricks that no
  longer work on modern runtimes
- blind traversal (file written / processed but never reflected) needs
  out-of-band or timing confirmation, not string matching

## Stage pipeline

| Stage | Name | Status |
|------:|------|--------|
| 1 | Input-vector enumeration | **implemented** |
| 2 | Baseline-first differential probing | **implemented** |
| 3 | Tiered mechanism-attribution probing | **implemented** |
| 4 | Reporting (findings, reproduction, confidence) | **implemented** — `report.md` |

Each stage reads the previous stage's JSON artifact. Stage 1 writes
`<out>/stage1-vectors.json`.

## Cross-stage decisions (recorded ahead of the Stage 2 build)

### HTTP engine: the `httpx` client, not `curl`

Stage 2+ reuse `http_client.HttpClient`. Reasons `curl` is not used as the engine:

- **byte control** — traversal payloads must be sent without the client
  normalizing `../` or re-encoding. `curl` collapses `../` unless `--path-as-is`
  and re-encodes its own way; `httpx` sends a pre-encoded target verbatim.
- **structured diffing** — the baseline fingerprint needs status + headers +
  body bytes + timing + redirect chain + HTTP version as data, not scraped
  `-w` / `-D` output, one process-spawn per request.
- **session continuity** — scope, cookies, auth headers, rate limit and retry
  are already established in Stage 1; reuse keeps Stage 1 and Stage 2 identical.

`curl` **is** the right tool for the Stage 4 report: emit a
`curl --path-as-is ...` one-liner to reproduce each finding.

`curl -f` / `--fail` is specifically wrong for probing: it suppresses the body
and collapses everything to "was it 2xx", discarding the 403/404/500 bodies the
differential comparison depends on.

### Where baseline (known-good) values come from

Stage 2 needs a valid, in-scope value per vector to fingerprint "normal"
before sending payloads. Source order (see `vectors/baseline.py`):

1. the value actually observed for that exact parameter (crawl / spec / capture)
2. a value observed elsewhere in the run for a same-named parameter
3. conventional defaults for the parameter's semantic class
   (`locale=en`, `theme=default`, `template=default`, `image=sample.png`, ...)
4. valid IDs harvested from earlier crawl responses — **Stage 2 concern, TODO**
5. operator override — `--baseline 'file=example.txt'` — **Stage 2 flag, TODO**
6. AI fallback (hybrid agent role) — propose a plausible known-good + matched
   negative control — **Stage 2, TODO**
7. none validate → mark the vector `baseline: unavailable`, fall back to
   control-only (A/B) comparison, lower its confidence. Never guess silently.

The negative control is synthesized: take the valid value, mangle it keeping
shape/extension (`example.txt` -> `nonexistent-a9f3.txt`).

Stage 1 carries two fields forward for this (added after the first cut):

- `InputVector.request_ref` — index into `stage1-vectors.json ->
  request_templates`, the full observed request so Stage 2 replays it and
  varies only the target field (critical for POST/JSON bodies with siblings).
- `InputVector.baseline_candidates` — ranked list from sources 1–3 above.

## Stage 1 — what it does

`discover → import → extract → rule-score → AI refine → rank → report`

1. **discover** — same-origin BFS crawl from `-u` / `--seed`: links, HTML forms
   (fields + method + enctype), inline & external JS (regex endpoint
   extraction), `robots.txt`, `sitemap.xml`.
2. **import** — parse OpenAPI/Swagger (JSON or YAML), HAR, Postman v2.x into the
   same `RawRequest` shape. Auto-detected by file content.
3. **extract** — flatten every observation into `InputVector` records: URL path
   segments (incl. `/:id`, `/{id}`, `/*` wildcards), query params, JSON body
   fields (recursively, dotted paths), form fields, multipart fields + upload
   filenames, cookies, headers. Deduplicated by `(method, normalized-endpoint,
   location, name)`.
4. **rule-score** — deterministic 0..1 traversal-relevance from the lexicons in
   `vectors/lexicon.py` (strong path names, resource-selection names, id-like /
   derived names, path headers/cookies, fs-op URL verbs, source/dest fields,
   archive values, multipart filenames). Also tags each vector with a coverage
   dimension A–L (research §22) and a guessed filesystem operation.
5. **AI refine** — see below.
6. **rank + coverage** — sort by relevance; compute the A–L coverage matrix and
   list gaps (from both the rule pass and the AI).

Static-file servers (no params, no forms) get one synthetic `url-path-segment`
vector named `*` per origin — the URL path itself is the input surface.

### Data model

`InputVector` is the source-to-sink dataflow record (research §21): endpoint,
method, protocol, location, name, nested path, controllability
(direct / derived / second-order), persistence, transformations, path role,
filesystem operation, sink, coverage category, evidence, both rule and AI
relevance scores + reasons, plus `request_ref` and `baseline_candidates`.

## Stage 2 — what it does

`select → baseline → negative control → probe → classify → reproduce → adjudicate`

1. **select** — from `stage1-vectors.json`, vectors at/above `--min-relevance`
   (0.4) that have a `request_ref`. Optional `--location` / `--only <id>`.
2. **baseline** — `probe/prepared.py` rebuilds the full request from
   `request_templates[request_ref]` and injects only the target field. Try each
   `baseline_candidate` in order; accept the first that returns a normal
   response; re-send it 3x to measure natural variance (`dynamic` flag).
   `--baseline 'name=value'` forces one.
3. **negative control** — the accepted value, mangled keeping shape/extension
   (`report.txt` → `report-nx3f1a.txt`): "how the app answers a well-formed
   missing resource".
4. **probe** — `probe/payloads.py`: encoding/normalization variants
   (`../`, `..%2f`, `%2e%2e%2f`, `%252e…`, `....//`, `..;/`, `..%5c`, overlong
   UTF-8, `%00`, leading `/`, absolute) × a depth ladder (1..`--depth-max`),
   aimed at a canary (`/etc/passwd` by default; `--canary windows|both`).
   Injection is location-aware (query string built raw so payloads aren't
   re-encoded; path payloads use encoded separators because httpx collapses
   `../` in a URL path; JSON/form/cookie/header sent literally; multipart →
   the file part's filename).
   Payloads are ordered **encoding-major, depth-minor** so the first N sample
   every encoding across the depth range. Suffix-constrained sinks (baseline
   value has an extension) also get null-byte-before-extension variants.
   Multipart/write-side uses a **separate, safe payload set** (`generate_write`):
   climb-only, never absolute, benign unique filename.
5. **classify** — `probe/differ.py`, never on status alone:
   - canary signature in body → **confirmed** (~0.97)  *(read-side only — a
     reflected upload filename is not a canary)*
   - response unlike BOTH baseline and control, shaped like a file read → **likely**
   - upload/multipart: reflected escaped save path or traversal-only error → **likely**
   - == negative control → **not-vulnerable**
   - differs but ambiguous / WAF / 5xx → **inconclusive**
6. **round-trip** (write-side) — for a `likely` upload finding, try to GET the
   uploaded marker file back at a few guessed locations; if its content comes
   back → **confirmed** (the write escaped the intended dir).
7. **reproduce** — `confirmed`/`likely` re-sent 2×; a miss downgrades one level and halves confidence.
8. **adjudicate** (optional AI) — `agent/verify.py` sends baseline/control/payload
   bodies for `likely` / `inconclusive` findings; a confident `not-vulnerable`
   (≥0.8) downgrades the finding, a stronger verdict raises confidence only.

Stage 1 also harvests real identifier values (`/collection/id` in URLs/links,
`*id`/`*name` JSON fields) into `harvested_values`; Stage 2 uses them as extra
baseline candidates for id-like / second-order vectors.

## Stage 4 — Markdown report

`exploit-path-traversal report --in stage2-findings.json` renders
`report.md` (auto-loads the sibling `stage1-vectors.json` for the coverage
table): summary counts, an actionable-findings table, per-finding detail
(payload, similarity, signals, baseline + control fingerprints, AI note,
`curl --path-as-is` repro), a not-vulnerable appendix, and the A–L coverage
matrix.

Output: `stage2-findings.json` (per finding: verdict, confidence, winning
payload, baseline + control fingerprints, all probes, `curl --path-as-is`
repro) + a compact terminal summary.

### Known Stage 2 limitations (tune with real targets)

- **write-side (upload) traversal** — confirmed only when the escaped file is
  reachable via one of the guessed round-trip URLs; otherwise caps at `likely`
  (a blackbox test can't see the filesystem). A real OOB channel would close this.
- **suffix-constrained sinks** — if the app appends an extension (`theme + ".txt"`)
  the `/etc/passwd` canary won't reach; null-byte-before-extension variants are
  tried but modern runtimes reject them, so the vector may read `inconclusive`
  / `not-vulnerable` with a note that it is traversal-shaped.
- **raw `../` in a URL path** is not testable through httpx (it normalizes);
  only encoded/obfuscated separators are sent for path-segment vectors.
- payload count is capped (`--max-payloads`, default 90) and depth-limited.

## Agent role (REVISIT — flagged by the operator)

**Current (v0.1):** hybrid, thin. Deterministic code does all crawling,
parsing, extraction and the first relevance score. The AI does **one stateless,
batched refinement pass** (`agent/classifier.py`):

- re-score each vector's traversal-relevance with a reason
- propose vectors enumeration likely missed (derived, second-order, JWT claims,
  cache/temp/log filenames, internal-service fields, archive entries)
- name under-explored coverage dimensions

The AI never drives HTTP in Stage 1. If the agent env vars are absent the stage
still runs (rule-based only) and says so.

**Stage 2** keeps the same thin contract (`agent/verify.py`): deterministic
probing decides `confirmed` / `not-vulnerable` alone; the AI only adjudicates
`likely` / `inconclusive` findings and never sends requests.

**Why flagged:** the operator wants to change how much the agent decides after
getting hands-on experience — likely moving toward a tool-calling loop where the
agent chooses what to fetch / probe. Keep the seam between
`stages/stage1.py` and `agent/` clean so this can be swapped without touching
crawl / extract / scoring. Touch points:

- `agent/classifier.py` — the whole refinement contract
- `agent/prompts.py` — the Stage 1 system prompt
- `agent/client.py` — currently single `chat_json`; a loop needs tool-call
  plumbing here
- `stages/stage1.py` step 4 — where refinement is invoked

## Config

AI agent is any OpenAI-compatible `/chat/completions` endpoint. From env or
`./.env` (see `.env.example`): `EPT_AI_BASE_URL`, `EPT_AI_MODEL`,
`EPT_AI_API_KEY` (+ optional `EPT_AI_TEMPERATURE`, `EPT_AI_MAX_TOKENS`,
`EPT_AI_TIMEOUT`, `EPT_AI_BATCH_SIZE`). `OPENAI_*` names accepted as fallback.
Precedence: CLI > process env > `.env`.

## Package layout

```
exploit_path_traversal/
  cli.py            argparse; subcommand-per-stage
  config.py         env + .env loading
  models.py         RawRequest, InputVector
  http_client.py    httpx wrapper (TLS toggle, rate limit, retry)
  output.py         minimal terminal output (bold/dim only, NO_COLOR aware)
  crawl/            crawler, html_parser (stdlib), js_parser (regex)
  spec/             openapi, har, postman importers + auto-detect
  vectors/          lexicon, scoring (rule), coverage (A–L), extractor
  agent/            client, prompts, classifier   <-- REVISIT seam
  tiers/            registry, generator, attribution, selector  (Stage 3)
  stages/           stage1, stage2, stage3 orchestration
  report/           writer, stage2_writer, stage3_writer, report_md
```

## Open TODO (post-v0.1)

- [x] Stage 2: baseline-first differential probing — done (`stages/stage2.py`,
      `probe/`, `agent/verify.py`). Verified e2e against 5 local labs.
- [x] Stage 2: extension-aware canary (null-byte-before-ext variants) + note.
- [x] Stage 2: write-side round-trip confirmation (guessed served locations).
- [x] Stage 2: harvest identifier values from Stage 1 crawl → baseline candidates.
- [x] Stage 4: `report` subcommand → `report.md`.
- [x] Stage 3: tiered mechanism-attribution probing (`stages/stage3.py`,
      `tiers/`). Verified e2e against a local vulnerable server.
- [ ] Stage 2/3: real OOB channel (callback server / DNS) for blind + write-side
      cases the round-trip guesser misses.
- [ ] Stage 2/3: richer timing analysis; GraphQL / WebSocket injection.
- [ ] Stage 2/3: raw `../` in URL path (needs a transport that bypasses httpx
      path normalization).
- [ ] Auth: login flow / bearer refresh for crawling authed surface
- [ ] GraphQL introspection → argument enumeration
- [ ] WebSocket message capture input
- [ ] Revisit agent role (see above) — possibly tool-calling loop
- [ ] Tune `vectors/lexicon.py` and `vectors/scoring.py` weights against real
      targets; consider moving weights to a config file
- [ ] `--resume` from a stage artifact
